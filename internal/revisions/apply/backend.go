package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vsevo/home-gateway/internal/routing/iprule"
	routingnft "github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/internal/system/linux"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	nftArtifactName      = "50-routerd.nft"
	dnsArtifactName      = "routerd.conf"
	routeArtifactName    = "routes.json"
	snapshotManifestName = "snapshot.json"
)

var artifactNames = []string{nftArtifactName, dnsArtifactName, routeArtifactName}

type LinuxRuntime struct {
	Root                string
	FirewallIncludePath string
	DNSIncludePath      string
	Runner              linux.Runner
}

type snapshotManifest struct {
	Revision        string `json:"revision,omitempty"`
	FirewallPresent bool   `json:"firewall_present"`
	DNSPresent      bool   `json:"dns_present"`
}

type routeReconciliation struct {
	desiredRoutes [][]string
	addRules      [][]string
	deleteRules   [][]string
	deleteRoutes  [][]string
}

type nftTableInventory struct {
	Nftables []struct {
		Table *struct {
			Family  string `json:"family"`
			Name    string `json:"name"`
			Comment string `json:"comment"`
		} `json:"table,omitempty"`
	} `json:"nftables"`
}

func (runtime LinuxRuntime) Preflight(ctx context.Context, revisions []string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	candidates, err := runtime.readOwnedCandidates(revisions)
	if err != nil {
		return err
	}
	if err := runtime.verifyActiveOwnership(candidates); err != nil {
		return err
	}
	if err := runtime.verifyManagedIncludeOwnership(candidates); err != nil {
		return err
	}
	if err := runtime.verifyNFTTableOwnership(ctx, len(candidates) != 0); err != nil {
		return err
	}
	return runtime.verifyReservedRoutingOwnership(ctx, candidates)
}

func (runtime LinuxRuntime) readOwnedCandidates(revisions []string) ([]Candidate, error) {
	candidates := make([]Candidate, 0, len(revisions))
	seen := make(map[string]struct{}, len(revisions))
	for _, revision := range revisions {
		if _, exists := seen[revision]; exists {
			continue
		}
		seen[revision] = struct{}{}
		directory, err := runtime.revisionDirectory(revision)
		if err != nil {
			return nil, err
		}
		candidate := Candidate{RevisionID: revision}
		for name, target := range map[string]*[]byte{
			nftArtifactName:   &candidate.NFT,
			dnsArtifactName:   &candidate.DNS,
			routeArtifactName: &candidate.Routes,
		} {
			data, err := readRegularFile(filepath.Join(directory, name))
			if err != nil {
				return nil, fmt.Errorf("read owned revision %q artifact %s: %w", revision, name, err)
			}
			*target = data
		}
		if _, err := iprule.Parse(candidate.Routes); err != nil {
			return nil, fmt.Errorf("parse owned revision %q routes: %w", revision, err)
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func (runtime LinuxRuntime) verifyActiveOwnership(candidates []Candidate) error {
	active := filepath.Join(runtime.Root, "active")
	if _, err := os.Lstat(active); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect active ownership metadata: %w", err)
	}
	if err := requireDirectory(active); err != nil {
		return fmt.Errorf("active ownership metadata: %w", err)
	}
	for _, candidate := range candidates {
		if err := verifyArtifacts(active, candidateArtifacts(candidate)); err == nil {
			return nil
		}
	}
	if len(candidates) == 0 {
		return errors.New("unowned active routerd metadata already exists")
	}
	return errors.New("active ownership metadata differs from every journal-owned revision")
}

func (runtime LinuxRuntime) verifyManagedIncludeOwnership(candidates []Candidate) error {
	for _, include := range []struct {
		label string
		path  string
		data  func(Candidate) []byte
	}{
		{label: "firewall", path: runtime.FirewallIncludePath, data: func(candidate Candidate) []byte { return candidate.NFT }},
		{label: "dns", path: runtime.DNSIncludePath, data: func(candidate Candidate) []byte { return candidate.DNS }},
	} {
		installed, present, err := readOptionalRegularFile(include.path)
		if err != nil {
			return fmt.Errorf("inspect %s include ownership: %w", include.label, err)
		}
		if !present {
			continue
		}
		for _, candidate := range candidates {
			if bytes.Equal(installed, include.data(candidate)) {
				present = false
				break
			}
		}
		if present {
			return fmt.Errorf("%s include is not owned by a journal revision", include.label)
		}
	}
	return nil
}

func (runtime LinuxRuntime) verifyNFTTableOwnership(ctx context.Context, hasOwnedRevision bool) error {
	result, err := runtime.Runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return fmt.Errorf("inspect nft table inventory: %w", err)
	}
	tables, err := decodeNFTTableInventory(result.Stdout)
	if err != nil {
		return fmt.Errorf("decode nft table inventory: %w", err)
	}
	present := false
	for _, item := range tables.Nftables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == routingnft.TableName {
			present = true
		}
	}
	if !present {
		return nil
	}
	if !hasOwnedRevision {
		return fmt.Errorf("nft table %q exists without a journal-owned revision", routingnft.TableName)
	}
	result, err = runtime.Runner.Run(ctx, "nft", "-j", "list", "table", "inet", routingnft.TableName)
	if err != nil {
		return fmt.Errorf("inspect owned nft table: %w", err)
	}
	table, err := decodeNFTTableInventory(result.Stdout)
	if err != nil {
		return fmt.Errorf("decode owned nft table: %w", err)
	}
	owned := 0
	for _, item := range table.Nftables {
		if item.Table == nil || item.Table.Family != "inet" || item.Table.Name != routingnft.TableName {
			continue
		}
		owned++
		if item.Table.Comment != routingnft.OwnershipComment {
			return fmt.Errorf("nft table %q has an invalid ownership marker", routingnft.TableName)
		}
	}
	if owned != 1 {
		return fmt.Errorf("nft table %q ownership inventory is incomplete", routingnft.TableName)
	}
	return nil
}

func decodeNFTTableInventory(data []byte) (nftTableInventory, error) {
	var inventory nftTableInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nftTableInventory{}, err
	}
	if inventory.Nftables == nil {
		return nftTableInventory{}, errors.New("nftables array is required")
	}
	return inventory, nil
}

func (runtime LinuxRuntime) verifyReservedRoutingOwnership(ctx context.Context, candidates []Candidate) error {
	allowedRoutes := make(map[string][][]string)
	allowedRules := make(map[string][][]string)
	for _, candidate := range candidates {
		artifact, err := iprule.Parse(candidate.Routes)
		if err != nil {
			return err
		}
		for _, command := range artifact.Commands {
			target := allowedRoutes
			if command[2] == "rule" {
				target = allowedRules
			}
			key := routeStateKey(command)
			target[key] = append(target[key], command)
		}
	}

	for _, family := range []string{"-4", "-6"} {
		rules, err := runtime.Runner.Run(ctx, "ip", family, "rule", "show")
		if err != nil {
			return fmt.Errorf("inspect policy rules for %s: %w", family, err)
		}
		if err := verifyRuleOwnership(family, rules.Stdout, allowedRules); err != nil {
			return err
		}
		routes, err := runtime.Runner.Run(ctx, "ip", family, "route", "show", "table", "all")
		if err != nil {
			return fmt.Errorf("inspect route inventory for %s: %w", family, err)
		}
		if err := verifyRouteOwnership(family, routes.Stdout, allowedRoutes); err != nil {
			return err
		}
	}
	return nil
}

func verifyRuleOwnership(family string, data []byte, allowed map[string][][]string) error {
	seen := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		priority := strings.TrimSuffix(fields[0], ":")
		priorityNumber, priorityErr := strconv.ParseUint(priority, 10, 32)
		reservedPriority := priorityErr == nil && isReservedRoutingTable(uint32(priorityNumber))
		mark, reservedMark := routerdMark(fields)
		if !reservedPriority && !reservedMark {
			continue
		}
		key := family + "\x00" + priority
		seen[key]++
		matched := seen[key] == 1
		if matched {
			matched = false
			for _, command := range allowed[key] {
				if ruleLineMatches(fields, command) {
					matched = true
					break
				}
			}
		}
		if matched {
			continue
		}
		if reservedPriority {
			return fmt.Errorf("policy priority %s for %s is unowned, duplicated or drifted", priority, family)
		}
		return fmt.Errorf("policy mark %s for %s is unowned or drifted", mark, family)
	}
	return nil
}

func routerdMark(fields []string) (string, bool) {
	for index, field := range fields {
		if field != "fwmark" || index+1 >= len(fields) {
			continue
		}
		token := fields[index+1]
		parts := strings.Split(token, "/")
		if len(parts) > 2 {
			return token, false
		}
		value, err := strconv.ParseUint(parts[0], 0, 32)
		if err != nil {
			return token, false
		}
		mask := uint64(^uint32(0))
		if len(parts) == 2 {
			mask, err = strconv.ParseUint(parts[1], 0, 32)
			if err != nil {
				return token, false
			}
		}
		return token, value&mask&uint64(contracts.RouterdMarkMask) != 0
	}
	return "", false
}

func verifyRouteOwnership(family string, data []byte, allowed map[string][][]string) error {
	routes := make(map[string][]string)
	tables := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "table" || index+1 >= len(fields) {
				continue
			}
			table := fields[index+1]
			number, err := strconv.ParseUint(table, 10, 32)
			if err != nil || !isReservedRoutingTable(uint32(number)) {
				continue
			}
			key := family + "\x00" + table
			routes[key] = append(routes[key], strings.Join(fields, " "))
			tables[key] = table
			break
		}
	}
	for key, lines := range routes {
		current := []byte(strings.Join(lines, "\n") + "\n")
		matched := false
		for _, command := range allowed[key] {
			if routeOutputMatches(current, command[6:]) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("routing table %s for %s contains an unowned or drifted route", tables[key], family)
		}
	}
	return nil
}

func isReservedRoutingTable(table uint32) bool {
	return table > contracts.RouterdRoutingTableBase && table <= contracts.RouterdRoutingTableBase+255
}

func (runtime LinuxRuntime) Stage(_ context.Context, candidate Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	artifacts := candidateArtifacts(candidate)
	if _, err := os.Lstat(directory); err == nil {
		return verifyArtifacts(directory, artifacts)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	revisions := filepath.Dir(directory)
	if err := secureMkdirAll(runtime.Root, revisions); err != nil {
		return err
	}
	temporary := directory + ".next"
	if err := removeDirectory(temporary); err != nil {
		return err
	}
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return err
	}
	staged := false
	defer func() {
		if !staged {
			_ = removeDirectory(temporary)
		}
	}()
	for _, name := range artifactNames {
		if err := writeExclusive(filepath.Join(temporary, name), artifacts[name], 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
	}
	if err := os.Rename(temporary, directory); err != nil {
		return fmt.Errorf("publish staged revision: %w", err)
	}
	staged = true
	return syncDirectory(revisions)
}

func (runtime LinuxRuntime) Validate(ctx context.Context, candidate Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	if err := verifyArtifacts(directory, candidateArtifacts(candidate)); err != nil {
		return err
	}
	fragment, err := readRegularFile(filepath.Join(directory, nftArtifactName))
	if err != nil {
		return err
	}
	routes, err := readRegularFile(filepath.Join(directory, routeArtifactName))
	if err != nil {
		return err
	}
	if _, err := iprule.Parse(routes); err != nil {
		return fmt.Errorf("validate routes: %w", err)
	}
	fw4, err := runtime.Runner.Run(ctx, "fw4", "print")
	if err != nil {
		return err
	}
	complete := append([]byte(nil), fw4.Stdout...)
	installed, present, err := readOptionalRegularFile(runtime.FirewallIncludePath)
	if err != nil {
		return err
	}
	if present {
		if len(installed) == 0 || !bytes.Contains(complete, installed) {
			return errors.New("active firewall include is missing from fw4 print output")
		}
		complete = bytes.Replace(complete, installed, fragment, 1)
	} else {
		complete = append(append(complete, '\n'), fragment...)
	}
	validationDirectory := filepath.Join(runtime.Root, "validation")
	if err := secureMkdirAll(runtime.Root, validationDirectory); err != nil {
		return err
	}
	candidatePath := filepath.Join(validationDirectory, candidate.RevisionID+".nft")
	if err := replaceRegularFile(candidatePath, complete, 0o600); err != nil {
		return err
	}
	_, validationErr := runtime.Runner.Run(ctx, "nft", "-c", "-f", candidatePath)
	cleanupErr := removeManagedFile(candidatePath)
	if validationErr != nil {
		return validationErr
	}
	if cleanupErr != nil {
		return fmt.Errorf("remove temporary nft validation file: %w", cleanupErr)
	}
	if _, err := runtime.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+filepath.Join(directory, dnsArtifactName)); err != nil {
		return err
	}
	return nil
}

func (runtime LinuxRuntime) Snapshot(_ context.Context, activeRevision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	target := filepath.Join(runtime.Root, "lkg")
	temporary := target + ".next"
	if err := removeDirectory(temporary); err != nil {
		return err
	}
	manifest := snapshotManifest{Revision: activeRevision}
	if activeRevision == "" {
		for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
			if _, present, err := readOptionalRegularFile(path); err != nil {
				return err
			} else if present {
				return fmt.Errorf("unmanaged routerd include already exists at %s", path)
			}
		}
		if err := os.MkdirAll(temporary, 0o700); err != nil {
			return err
		}
		emptyRoutes, err := json.MarshalIndent(iprule.Artifact{Version: iprule.ArtifactVersion, Commands: [][]string{}}, "", "  ")
		if err != nil {
			return err
		}
		for name, data := range map[string][]byte{
			nftArtifactName:   {},
			dnsArtifactName:   {},
			routeArtifactName: append(emptyRoutes, '\n'),
		} {
			if err := writeExclusive(filepath.Join(temporary, name), data, 0o600); err != nil {
				return err
			}
		}
	} else {
		source, err := runtime.revisionDirectory(activeRevision)
		if err != nil {
			return err
		}
		if err := verifyInstalledArtifact(runtime.FirewallIncludePath, filepath.Join(source, nftArtifactName)); err != nil {
			return fmt.Errorf("firewall include drift: %w", err)
		}
		if err := verifyInstalledArtifact(runtime.DNSIncludePath, filepath.Join(source, dnsArtifactName)); err != nil {
			return fmt.Errorf("dns include drift: %w", err)
		}
		if err := copyArtifacts(source, temporary); err != nil {
			return err
		}
		manifest.FirewallPresent = true
		manifest.DNSPresent = true
	}
	if err := writeJSONFile(filepath.Join(temporary, snapshotManifestName), manifest); err != nil {
		return err
	}
	return replaceDirectory(temporary, target)
}

func (runtime LinuxRuntime) Activate(ctx context.Context, candidate Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	source, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	if err := verifyArtifacts(source, candidateArtifacts(candidate)); err != nil {
		return err
	}
	previous, err := runtime.readOptionalActiveRouteArtifact()
	if err != nil {
		return err
	}
	desired, err := readRouteArtifact(filepath.Join(source, routeArtifactName))
	if err != nil {
		return err
	}
	reconciliation, err := runtime.preflightRouteReconciliation(ctx, previous, desired)
	if err != nil {
		return err
	}
	active := filepath.Join(runtime.Root, "active")
	temporary := active + ".next"
	if err := copyArtifacts(source, temporary); err != nil {
		return err
	}
	if err := replaceDirectory(temporary, active); err != nil {
		return err
	}
	if err := runtime.executeRouteReconciliation(ctx, reconciliation); err != nil {
		return err
	}
	nftData, err := readRegularFile(filepath.Join(active, nftArtifactName))
	if err != nil {
		return err
	}
	if err := replaceRegularFile(runtime.FirewallIncludePath, nftData, 0o600); err != nil {
		return err
	}
	dnsData, err := readRegularFile(filepath.Join(active, dnsArtifactName))
	if err != nil {
		return err
	}
	return replaceRegularFile(runtime.DNSIncludePath, dnsData, 0o600)
}

func (runtime LinuxRuntime) Reload(ctx context.Context) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	if _, err := runtime.Runner.Run(ctx, "fw4", "reload"); err != nil {
		return err
	}
	_, err := runtime.Runner.Run(ctx, "/etc/init.d/dnsmasq", "reload")
	return err
}

func (runtime LinuxRuntime) PostCheck(ctx context.Context) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	active := filepath.Join(runtime.Root, "active")
	if err := runtime.verifySnapshotIncludes(active, snapshotManifest{FirewallPresent: true, DNSPresent: true}); err != nil {
		return err
	}
	artifact, err := runtime.readActiveRouteArtifact()
	if err != nil {
		return err
	}
	return runtime.verifySnapshotState(ctx, active, snapshotManifest{FirewallPresent: true, DNSPresent: true}, artifact, iprule.Artifact{})
}

func (runtime LinuxRuntime) verifySnapshotState(
	ctx context.Context,
	directory string,
	manifest snapshotManifest,
	desired iprule.Artifact,
	previous iprule.Artifact,
) error {
	if manifest.FirewallPresent {
		expected, err := readRegularFile(filepath.Join(directory, nftArtifactName))
		if err != nil {
			return fmt.Errorf("read expected nft artifact: %w", err)
		}
		if err := runtime.verifyActiveNFTTable(ctx, expected); err != nil {
			return err
		}
	} else if err := runtime.verifyNFTTableAbsent(ctx); err != nil {
		return err
	}
	return runtime.verifyRouteState(ctx, desired, previous)
}

func (runtime LinuxRuntime) verifyActiveNFTTable(ctx context.Context, expected []byte) error {
	nftResult, err := runtime.Runner.Run(ctx, "nft", "list", "table", "inet", routingnft.TableName)
	if err != nil {
		return err
	}
	if !bytes.Contains(nftResult.Stdout, []byte("table inet "+routingnft.TableName)) ||
		!bytes.Contains(nftResult.Stdout, []byte("chain prerouting")) {
		return errors.New("routerd nft table or prerouting chain is missing")
	}
	if !bytes.Contains(nftResult.Stdout, []byte(fmt.Sprintf("comment %q", routingnft.OwnershipComment))) {
		return errors.New("routerd nft table ownership marker is missing or invalid")
	}
	expectedChain, err := nftNamedBlock(expected, "chain", "prerouting")
	if err != nil {
		return fmt.Errorf("inspect expected nft artifact: %w", err)
	}
	activeChain, err := nftNamedBlock(nftResult.Stdout, "chain", "prerouting")
	if err != nil {
		return fmt.Errorf("inspect active nft table: %w", err)
	}
	if !slicesEqual(nftComparableTokens(activeChain), nftComparableTokens(expectedChain)) {
		return errors.New("routerd nft prerouting chain metadata or ordered rules are missing or drifted")
	}

	expectedSets, err := nftSetInventory(expected)
	if err != nil {
		return fmt.Errorf("inspect expected nft artifact: %w", err)
	}
	activeSets, err := nftSetInventory(nftResult.Stdout)
	if err != nil {
		return fmt.Errorf("inspect active nft table: %w", err)
	}
	if len(activeSets) != len(expectedSets) {
		return fmt.Errorf("routerd nft set inventory drifted: active=%d expected=%d", len(activeSets), len(expectedSets))
	}
	for name, expectedSet := range expectedSets {
		activeSet, found := activeSets[name]
		if !found {
			return fmt.Errorf("routerd nft set %q is missing", name)
		}
		if err := verifyNFTSetSemantics(activeSet, expectedSet); err != nil {
			return fmt.Errorf("routerd nft set %q drifted: %w", name, err)
		}
	}
	return nil
}

type nftSetSemantics struct {
	typeName string
	flags    []string
	timeout  string
	elements []string
}

func nftNamedBlock(data []byte, kind, name string) ([]string, error) {
	blocks, err := nftNamedBlocks(data, kind)
	if err != nil {
		return nil, err
	}
	block, found := blocks[name]
	if !found {
		return nil, fmt.Errorf("%s %q is missing", kind, name)
	}
	return block, nil
}

func nftNamedBlocks(data []byte, kind string) (map[string][]string, error) {
	tokens := nftDocumentTokens(string(data))
	blocks := make(map[string][]string)
	for index := 0; index+2 < len(tokens); index++ {
		if tokens[index] != kind || tokens[index+2] != "{" {
			continue
		}
		name := tokens[index+1]
		depth := 1
		end := index + 3
		for ; end < len(tokens) && depth != 0; end++ {
			switch tokens[end] {
			case "{":
				depth++
			case "}":
				depth--
			}
		}
		if depth != 0 {
			return nil, fmt.Errorf("unterminated %s %q", kind, name)
		}
		if _, duplicate := blocks[name]; duplicate {
			return nil, fmt.Errorf("duplicate %s %q", kind, name)
		}
		blocks[name] = append([]string(nil), tokens[index+3:end-1]...)
		index = end - 1
	}
	return blocks, nil
}

func nftSetInventory(data []byte) (map[string]nftSetSemantics, error) {
	blocks, err := nftNamedBlocks(data, "set")
	if err != nil {
		return nil, err
	}
	sets := make(map[string]nftSetSemantics, len(blocks))
	for name, block := range blocks {
		semantics, err := parseNFTSetSemantics(block)
		if err != nil {
			return nil, fmt.Errorf("set %q: %w", name, err)
		}
		sets[name] = semantics
	}
	return sets, nil
}

func parseNFTSetSemantics(tokens []string) (nftSetSemantics, error) {
	var result nftSetSemantics
	depth := 0
	for index := 0; index < len(tokens); index++ {
		switch tokens[index] {
		case "{":
			depth++
			continue
		case "}":
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		switch tokens[index] {
		case "type":
			if index+1 >= len(tokens) {
				return nftSetSemantics{}, errors.New("type value is missing")
			}
			result.typeName = tokens[index+1]
			index++
		case "flags":
			terminated := false
			for index++; index < len(tokens); index++ {
				if tokens[index] == ";" {
					terminated = true
					break
				}
				if tokens[index] != "{" && tokens[index] != "}" && tokens[index] != "=" {
					result.flags = append(result.flags, tokens[index])
				}
			}
			if !terminated || len(result.flags) == 0 {
				return nftSetSemantics{}, errors.New("flags declaration is invalid")
			}
		case "timeout":
			if index+1 >= len(tokens) {
				return nftSetSemantics{}, errors.New("timeout value is missing")
			}
			result.timeout = tokens[index+1]
			index++
		case "elements":
			if index+2 >= len(tokens) || tokens[index+1] != "=" || tokens[index+2] != "{" {
				return nftSetSemantics{}, errors.New("elements block is invalid")
			}
			index += 3
			elementDepth := 1
			for ; index < len(tokens) && elementDepth != 0; index++ {
				switch tokens[index] {
				case "{":
					elementDepth++
				case "}":
					elementDepth--
				default:
					if elementDepth == 1 {
						result.elements = append(result.elements, tokens[index])
					}
				}
			}
			if elementDepth != 0 {
				return nftSetSemantics{}, errors.New("elements block is unterminated")
			}
			index--
		}
	}
	if result.typeName == "" {
		return nftSetSemantics{}, errors.New("type declaration is missing")
	}
	return result, nil
}

func verifyNFTSetSemantics(active, expected nftSetSemantics) error {
	if active.typeName != expected.typeName {
		return fmt.Errorf("type=%q, want %q", active.typeName, expected.typeName)
	}
	if !sameTokenMultiset(active.flags, expected.flags) {
		return fmt.Errorf("flags=%v, want %v", active.flags, expected.flags)
	}
	if !equalNFTTimeout(active.timeout, expected.timeout) {
		return fmt.Errorf("timeout=%q, want %q", active.timeout, expected.timeout)
	}
	if containsString(expected.flags, "timeout") && len(expected.elements) == 0 {
		return nil
	}
	if !sameTokenMultiset(active.elements, expected.elements) {
		return fmt.Errorf("elements=%v, want %v", active.elements, expected.elements)
	}
	return nil
}

func equalNFTTimeout(active, expected string) bool {
	if active == expected {
		return true
	}
	if active == "" || expected == "" {
		return false
	}
	activeDuration, activeErr := time.ParseDuration(active)
	expectedDuration, expectedErr := time.ParseDuration(expected)
	return activeErr == nil && expectedErr == nil && activeDuration == expectedDuration
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func sameTokenMultiset(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, token := range left {
		counts[token]++
	}
	for _, token := range right {
		counts[token]--
		if counts[token] < 0 {
			return false
		}
	}
	return true
}

func (runtime LinuxRuntime) verifyNFTTableAbsent(ctx context.Context) error {
	result, err := runtime.Runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return err
	}
	inventory, err := decodeNFTTableInventory(result.Stdout)
	if err != nil {
		return fmt.Errorf("decode nft table inventory: %w", err)
	}
	for _, item := range inventory.Nftables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == routingnft.TableName {
			return fmt.Errorf("routerd nft table remains after restore")
		}
	}
	return nil
}

func (runtime LinuxRuntime) verifyRouteState(ctx context.Context, desired, previous iprule.Artifact) error {
	ruleOutputs := make(map[string][]byte, 2)
	for _, family := range []string{"-4", "-6"} {
		result, err := runtime.Runner.Run(ctx, "ip", family, "rule", "show")
		if err != nil {
			return err
		}
		ruleOutputs[family] = result.Stdout
	}
	seenRoutes := make(map[string]struct{})
	for _, command := range desired.Commands {
		switch command[2] {
		case "rule":
			lines := ruleLinesAtPriority(ruleOutputs[command[1]], command[5])
			if len(lines) != 1 || !ruleLineMatches(lines[0], command) {
				return fmt.Errorf("policy rule for %s priority %s mark %s lookup %s is missing or drifted", command[1], command[5], command[7], command[9])
			}
		case "route":
			key := command[1] + "\x00" + command[5]
			if _, exists := seenRoutes[key]; exists {
				continue
			}
			seenRoutes[key] = struct{}{}
			result, err := runtime.Runner.Run(ctx, "ip", command[1], "route", "show", "table", command[5])
			if err != nil {
				return err
			}
			expected := command[6:]
			if !routeOutputMatches(result.Stdout, expected) {
				return fmt.Errorf("route table %s for %s is missing or drifted from %s", command[5], command[1], strings.Join(expected, " "))
			}
		}
	}
	desiredRoutes, desiredRules := indexRouteArtifact(desired)
	for _, command := range previous.Commands {
		key := routeStateKey(command)
		switch command[2] {
		case "rule":
			if _, retained := desiredRules[key]; retained {
				continue
			}
			if lines := ruleLinesAtPriority(ruleOutputs[command[1]], command[5]); len(lines) != 0 {
				return fmt.Errorf("policy rule for %s priority %s remains after restore", command[1], command[5])
			}
		case "route":
			if _, retained := desiredRoutes[key]; retained {
				continue
			}
			result, err := runtime.Runner.Run(ctx, "ip", command[1], "route", "show", "table", command[5])
			if err != nil {
				return err
			}
			if !routeOutputEmpty(result.Stdout) {
				return fmt.Errorf("route table %s for %s remains after restore", command[5], command[1])
			}
		}
	}
	return nil
}

func (runtime LinuxRuntime) verifySnapshotIncludes(active string, manifest snapshotManifest) error {
	for _, include := range []struct {
		label   string
		path    string
		name    string
		present bool
	}{
		{label: "firewall", path: runtime.FirewallIncludePath, name: nftArtifactName, present: manifest.FirewallPresent},
		{label: "dns", path: runtime.DNSIncludePath, name: dnsArtifactName, present: manifest.DNSPresent},
	} {
		if include.present {
			if err := verifyInstalledArtifact(include.path, filepath.Join(active, include.name)); err != nil {
				return fmt.Errorf("%s include post-check: %w", include.label, err)
			}
			continue
		}
		if _, present, err := readOptionalRegularFile(include.path); err != nil {
			return fmt.Errorf("%s include post-check: %w", include.label, err)
		} else if present {
			return fmt.Errorf("%s include remains after restore", include.label)
		}
	}
	return nil
}

func (runtime LinuxRuntime) Reconcile(ctx context.Context, revision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	directory, err := runtime.revisionDirectory(revision)
	if err != nil {
		return err
	}
	candidate := Candidate{RevisionID: revision}
	for name, target := range map[string]*[]byte{
		nftArtifactName:   &candidate.NFT,
		dnsArtifactName:   &candidate.DNS,
		routeArtifactName: &candidate.Routes,
	} {
		data, err := readRegularFile(filepath.Join(directory, name))
		if err != nil {
			return fmt.Errorf("read active revision artifact %s: %w", name, err)
		}
		*target = data
	}
	active := filepath.Join(runtime.Root, "active")
	if _, err := os.Lstat(active); err == nil {
		if err := verifyArtifacts(active, candidateArtifacts(candidate)); err != nil {
			return fmt.Errorf("active ownership metadata drift: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect active ownership metadata: %w", err)
	}
	if err := runtime.Validate(ctx, candidate); err != nil {
		return fmt.Errorf("validate active revision: %w", err)
	}
	if err := runtime.Activate(ctx, candidate); err != nil {
		return fmt.Errorf("activate active revision: %w", err)
	}
	if err := runtime.Reload(ctx); err != nil {
		return fmt.Errorf("reload active revision: %w", err)
	}
	if err := runtime.PostCheck(ctx); err != nil {
		return fmt.Errorf("post-check active revision: %w", err)
	}
	return nil
}

func containsTokenSequence(data []byte, expected []string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := nftSemanticTokens(line)
		for start := 0; start+len(expected) <= len(fields); start++ {
			if slicesEqual(fields[start:start+len(expected)], expected) {
				return true
			}
		}
	}
	return false
}

func nftSemanticTokens(line string) []string {
	return nftTokens(line, " ")
}

func nftDocumentTokens(document string) []string {
	return nftTokens(document, " ; ")
}

func nftTokens(value, semicolonReplacement string) []string {
	value = strings.NewReplacer(
		"(", " ",
		")", " ",
		";", semicolonReplacement,
		",", " ",
		"{", " { ",
		"}", " } ",
		"=", " = ",
	).Replace(value)
	fields := strings.Fields(value)
	for index, field := range fields {
		if !strings.HasPrefix(field, "0x") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimPrefix(field, "0x"), 16, 64)
		if err == nil {
			fields[index] = fmt.Sprintf("0x%x", value)
		}
	}
	return fields
}

func nftComparableTokens(tokens []string) []string {
	comparable := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if token != ";" {
			comparable = append(comparable, token)
		}
	}
	return comparable
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (runtime LinuxRuntime) Restore(ctx context.Context, revision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	lkg := filepath.Join(runtime.Root, "lkg")
	manifest, err := readSnapshotManifest(filepath.Join(lkg, snapshotManifestName))
	if err != nil {
		return errors.New("last-known-good snapshot is unavailable")
	}
	if manifest.Revision != revision {
		return fmt.Errorf("last-known-good snapshot revision %q does not match requested %q", manifest.Revision, revision)
	}
	previous, err := runtime.readOptionalActiveRouteArtifact()
	if err != nil {
		return err
	}
	desired, err := readRouteArtifact(filepath.Join(lkg, routeArtifactName))
	if err != nil {
		return err
	}
	reconciliation, err := runtime.preflightRouteReconciliation(ctx, previous, desired)
	if err != nil {
		return err
	}
	active := filepath.Join(runtime.Root, "active")
	if err := copyArtifacts(lkg, active+".next"); err != nil {
		return err
	}
	if err := replaceDirectory(active+".next", active); err != nil {
		return err
	}
	if err := runtime.executeRouteReconciliation(ctx, reconciliation); err != nil {
		return err
	}
	if err := restoreManagedFile(runtime.FirewallIncludePath, filepath.Join(active, nftArtifactName), manifest.FirewallPresent); err != nil {
		return err
	}
	if err := restoreManagedFile(runtime.DNSIncludePath, filepath.Join(active, dnsArtifactName), manifest.DNSPresent); err != nil {
		return err
	}
	if err := runtime.Reload(ctx); err != nil {
		return err
	}
	if err := runtime.verifySnapshotIncludes(active, manifest); err != nil {
		return err
	}
	if err := runtime.verifySnapshotState(ctx, active, manifest, desired, previous); err != nil {
		return fmt.Errorf("restore post-check: %w", err)
	}
	return nil
}

func (runtime LinuxRuntime) readActiveRouteArtifact() (iprule.Artifact, error) {
	return readRouteArtifact(filepath.Join(runtime.Root, "active", routeArtifactName))
}

func (runtime LinuxRuntime) readOptionalActiveRouteArtifact() (iprule.Artifact, error) {
	active := filepath.Join(runtime.Root, "active")
	if _, err := os.Lstat(active); errors.Is(err, os.ErrNotExist) {
		return iprule.Artifact{Version: iprule.ArtifactVersion, Commands: [][]string{}}, nil
	} else if err != nil {
		return iprule.Artifact{}, err
	}
	if err := requireDirectory(active); err != nil {
		return iprule.Artifact{}, err
	}
	return readRouteArtifact(filepath.Join(active, routeArtifactName))
}

func readRouteArtifact(path string) (iprule.Artifact, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return iprule.Artifact{}, err
	}
	artifact, err := iprule.Parse(data)
	if err != nil {
		return iprule.Artifact{}, fmt.Errorf("parse route artifact: %w", err)
	}
	return artifact, nil
}

func (runtime LinuxRuntime) preflightRouteReconciliation(
	ctx context.Context,
	previous iprule.Artifact,
	desired iprule.Artifact,
) (routeReconciliation, error) {
	previousRoutes, previousRules := indexRouteArtifact(previous)
	desiredRoutes, desiredRules := indexRouteArtifact(desired)

	routeOutputs := make(map[string][]byte, len(previousRoutes)+len(desiredRoutes))
	for _, artifact := range []iprule.Artifact{desired, previous} {
		for _, command := range artifact.Commands {
			if command[2] != "route" {
				continue
			}
			key := routeStateKey(command)
			if _, exists := routeOutputs[key]; exists {
				continue
			}
			result, err := runtime.Runner.Run(ctx, "ip", command[1], "route", "show", "table", command[5])
			if err != nil {
				return routeReconciliation{}, fmt.Errorf("inspect route table %s for %s: %w", command[5], command[1], err)
			}
			routeOutputs[key] = append([]byte(nil), result.Stdout...)
		}
	}

	ruleOutputs := make(map[string][]byte, 2)
	for _, artifact := range []iprule.Artifact{desired, previous} {
		for _, command := range artifact.Commands {
			if command[2] != "rule" {
				continue
			}
			family := command[1]
			if _, exists := ruleOutputs[family]; exists {
				continue
			}
			result, err := runtime.Runner.Run(ctx, "ip", family, "rule", "show")
			if err != nil {
				return routeReconciliation{}, fmt.Errorf("inspect policy rules for %s: %w", family, err)
			}
			ruleOutputs[family] = append([]byte(nil), result.Stdout...)
		}
	}

	reconciliation := routeReconciliation{}
	for _, command := range desired.Commands {
		if command[2] != "route" {
			continue
		}
		key := routeStateKey(command)
		current := routeOutputs[key]
		if !routeOutputEmpty(current) {
			owned, exists := previousRoutes[key]
			if !exists || !routeOutputMatches(current, command[6:]) && !routeOutputMatches(current, owned[6:]) {
				return routeReconciliation{}, fmt.Errorf("routing table %s for %s contains an unowned or drifted route", command[5], command[1])
			}
		}
		reconciliation.desiredRoutes = append(reconciliation.desiredRoutes, cloneCommand(command))
	}
	for _, command := range desired.Commands {
		if command[2] != "rule" {
			continue
		}
		lines := ruleLinesAtPriority(ruleOutputs[command[1]], command[5])
		if len(lines) == 0 {
			reconciliation.addRules = append(reconciliation.addRules, cloneCommand(command))
			continue
		}
		owned, exists := previousRules[routeStateKey(command)]
		if !exists || len(lines) != 1 || !ruleLineMatches(lines[0], command) {
			return routeReconciliation{}, fmt.Errorf("policy priority %s for %s is unowned, duplicated or drifted", command[5], command[1])
		}
		if !commandsEqual(owned, command) {
			return routeReconciliation{}, fmt.Errorf("policy priority %s for %s requires an unsupported in-place transition", command[5], command[1])
		}
	}
	for _, command := range previous.Commands {
		if command[2] != "rule" {
			continue
		}
		key := routeStateKey(command)
		if _, retained := desiredRules[key]; retained {
			continue
		}
		lines := ruleLinesAtPriority(ruleOutputs[command[1]], command[5])
		if len(lines) == 0 {
			continue
		}
		if len(lines) != 1 || !ruleLineMatches(lines[0], command) {
			return routeReconciliation{}, fmt.Errorf("refusing to delete drifted policy priority %s for %s", command[5], command[1])
		}
		deletion := cloneCommand(command)
		deletion[3] = "del"
		reconciliation.deleteRules = append(reconciliation.deleteRules, deletion)
	}
	for _, command := range previous.Commands {
		if command[2] != "route" {
			continue
		}
		key := routeStateKey(command)
		if _, retained := desiredRoutes[key]; retained {
			continue
		}
		current := routeOutputs[key]
		if routeOutputEmpty(current) {
			continue
		}
		if !routeOutputMatches(current, command[6:]) {
			return routeReconciliation{}, fmt.Errorf("refusing to delete drifted routing table %s for %s", command[5], command[1])
		}
		deletion := cloneCommand(command)
		deletion[3] = "del"
		reconciliation.deleteRoutes = append(reconciliation.deleteRoutes, deletion)
	}
	return reconciliation, nil
}

func (runtime LinuxRuntime) executeRouteReconciliation(ctx context.Context, reconciliation routeReconciliation) error {
	for _, commands := range [][][]string{
		reconciliation.desiredRoutes,
		reconciliation.addRules,
		reconciliation.deleteRules,
		reconciliation.deleteRoutes,
	} {
		for _, command := range commands {
			if _, err := runtime.Runner.Run(ctx, command[0], command[1:]...); err != nil {
				return fmt.Errorf("execute route reconciliation argv: %w", err)
			}
		}
	}
	return nil
}

func indexRouteArtifact(artifact iprule.Artifact) (map[string][]string, map[string][]string) {
	routes := make(map[string][]string)
	rules := make(map[string][]string)
	for _, command := range artifact.Commands {
		switch command[2] {
		case "route":
			routes[routeStateKey(command)] = command
		case "rule":
			rules[routeStateKey(command)] = command
		}
	}
	return routes, rules
}

func routeStateKey(command []string) string {
	return command[1] + "\x00" + command[5]
}

func routeOutputEmpty(data []byte) bool {
	return len(strings.Fields(string(data))) == 0
}

func routeOutputMatches(data []byte, expected []string) bool {
	lines := 0
	matched := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		lines++
		for start := 0; start+len(expected) <= len(fields); start++ {
			if slicesEqual(fields[start:start+len(expected)], expected) {
				matched = true
			}
		}
	}
	return lines == 1 && matched
}

func ruleLinesAtPriority(data []byte, priority string) [][]string {
	var matches [][]string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.TrimSuffix(fields[0], ":") == priority {
			matches = append(matches, fields)
		}
	}
	return matches
}

func ruleLineMatches(fields []string, command []string) bool {
	want := []string{command[5] + ":", "from", "all", "fwmark", command[7], "lookup", command[9]}
	return slicesEqual(fields, want)
}

func cloneCommand(command []string) []string {
	return append([]string(nil), command...)
}

func commandsEqual(left, right []string) bool {
	return slicesEqual(left, right)
}

func (runtime LinuxRuntime) validateConfiguration() error {
	if runtime.Root == "" || !filepath.IsAbs(runtime.Root) {
		return errors.New("absolute runtime root is required")
	}
	if runtime.Runner == nil {
		return errors.New("linux runner is required")
	}
	for label, path := range map[string]string{
		"firewall include": runtime.FirewallIncludePath,
		"dns include":      runtime.DNSIncludePath,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("absolute clean %s path is required", label)
		}
		if filepath.Clean(path) == filepath.Clean(runtime.Root) {
			return fmt.Errorf("%s path cannot be the runtime root", label)
		}
	}
	if filepath.Clean(runtime.FirewallIncludePath) == filepath.Clean(runtime.DNSIncludePath) {
		return errors.New("firewall and dns include paths must differ")
	}
	return nil
}

func (runtime LinuxRuntime) revisionDirectory(revision string) (string, error) {
	if runtime.Root == "" || !filepath.IsAbs(runtime.Root) {
		return "", errors.New("absolute runtime root is required")
	}
	if !validRevisionID(revision) {
		return "", errors.New("invalid revision ID")
	}
	cleanRoot := filepath.Clean(runtime.Root)
	path := filepath.Join(cleanRoot, "revisions", revision)
	if filepath.Dir(filepath.Dir(path)) != cleanRoot {
		return "", errors.New("revision path escapes runtime root")
	}
	return path, nil
}

func candidateArtifacts(candidate Candidate) map[string][]byte {
	return map[string][]byte{
		nftArtifactName:   candidate.NFT,
		dnsArtifactName:   candidate.DNS,
		routeArtifactName: candidate.Routes,
	}
}

func verifyArtifacts(directory string, want map[string][]byte) error {
	if err := requireDirectory(directory); err != nil {
		return err
	}
	for _, name := range artifactNames {
		got, err := readRegularFile(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want[name]) {
			return fmt.Errorf("immutable revision artifact %s differs", name)
		}
	}
	return nil
}

func verifyInstalledArtifact(installedPath, revisionPath string) error {
	installed, present, err := readOptionalRegularFile(installedPath)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("managed include is missing")
	}
	want, err := readRegularFile(revisionPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(installed, want) {
		return errors.New("managed include differs from active revision")
	}
	return nil
}

func copyArtifacts(source, target string) error {
	if err := requireDirectory(source); err != nil {
		return errors.New("artifact source is unavailable or is a symlink")
	}
	if err := removeDirectory(target); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	for _, name := range artifactNames {
		data, err := readRegularFile(filepath.Join(source, name))
		if err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
		if err := writeExclusive(filepath.Join(target, name), data, 0o600); err != nil {
			return err
		}
	}
	return syncDirectory(target)
}

func restoreManagedFile(destination, source string, present bool) error {
	if !present {
		return removeManagedFile(destination)
	}
	data, err := readRegularFile(source)
	if err != nil {
		return err
	}
	return replaceRegularFile(destination, data, 0o600)
}

func readSnapshotManifest(path string) (snapshotManifest, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return snapshotManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest snapshotManifest
	if err := decoder.Decode(&manifest); err != nil {
		return snapshotManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return snapshotManifest{}, errors.New("snapshot manifest contains trailing JSON data")
		}
		return snapshotManifest{}, fmt.Errorf("decode snapshot manifest trailing data: %w", err)
	}
	return manifest, nil
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(path, append(data, '\n'), 0o600)
}

func secureMkdirAll(root, directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	for _, path := range []string{filepath.Clean(root), filepath.Clean(directory)} {
		if err := requireDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", path)
	}
	return nil
}

func requireAbsoluteCleanPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("absolute clean path is required: %q", path)
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	if err := requireAbsoluteCleanPath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	// #nosec G304 -- callers provide validated managed paths; the pre-open Lstat and post-open SameFile check pin the read to that regular file.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s changed while opening the managed file", path)
	}
	return io.ReadAll(file)
}

func readOptionalRegularFile(path string) ([]byte, bool, error) {
	data, err := readRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if err := requireAbsoluteCleanPath(path); err != nil {
		return err
	}
	if err := requireDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	// #nosec G304 -- path is absolute and clean, its parent is a real managed directory, and O_EXCL prevents following or replacing an existing entry.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func replaceRegularFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := requireDirectory(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed path %s is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := filepath.Join(directory, "."+filepath.Base(path)+".routerd.tmp")
	if info, err := os.Lstat(temporary); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("temporary managed path %s is unsafe", temporary)
		}
		if err := os.Remove(temporary); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusive(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		if runtime.GOOS != "windows" {
			_ = os.Remove(temporary)
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			_ = os.Remove(temporary)
			return removeErr
		}
		if retryErr := os.Rename(temporary, path); retryErr != nil {
			_ = os.Remove(temporary)
			return retryErr
		}
	}
	return syncDirectory(directory)
}

func removeManagedFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed path %s is not a regular file", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceDirectory(source, target string) error {
	if err := requireDirectory(source); err != nil {
		return err
	}
	backup := target + ".old"
	if err := removeDirectory(backup); err != nil {
		return err
	}
	targetPresent := false
	if _, err := os.Lstat(target); err == nil {
		if err := requireDirectory(target); err != nil {
			return err
		}
		if err := os.Rename(target, backup); err != nil {
			return err
		}
		targetPresent = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		if targetPresent {
			_ = os.Rename(backup, target)
		}
		return err
	}
	if targetPresent {
		if err := removeDirectory(backup); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(target))
}

func removeDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove unsafe directory %s", path)
	}
	return os.RemoveAll(path)
}

func syncDirectory(path string) error {
	if err := requireAbsoluteCleanPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", path)
	}
	// #nosec G304 -- path is absolute and clean; Lstat plus SameFile below binds the handle to the validated real directory.
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	openedInfo, err := directory.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("%s changed while opening the managed directory", path)
	}
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
