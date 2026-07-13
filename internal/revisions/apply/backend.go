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
	"strings"

	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/internal/system/linux"
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
	_, err := runtime.Runner.Run(ctx, "ubus", "call", "service", "signal", `{"name":"dnsmasq","signal":1}`)
	return err
}

func (runtime LinuxRuntime) PostCheck(ctx context.Context) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	nftResult, err := runtime.Runner.Run(ctx, "nft", "list", "table", "inet", "routerd")
	if err != nil {
		return err
	}
	if !bytes.Contains(nftResult.Stdout, []byte("table inet routerd")) ||
		!bytes.Contains(nftResult.Stdout, []byte("chain prerouting")) {
		return errors.New("routerd nft table or prerouting chain is missing")
	}
	artifact, err := runtime.readActiveRouteArtifact()
	if err != nil {
		return err
	}
	ruleOutputs := make(map[string][]byte, 2)
	for _, family := range []string{"-4", "-6"} {
		result, err := runtime.Runner.Run(ctx, "ip", family, "rule", "show")
		if err != nil {
			return err
		}
		ruleOutputs[family] = result.Stdout
	}
	seenRoutes := make(map[string]struct{})
	for _, command := range artifact.Commands {
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
			if !containsTokenSequence(result.Stdout, expected) {
				return fmt.Errorf("route table %s for %s does not contain %s", command[5], command[1], strings.Join(expected, " "))
			}
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
		fields := strings.Fields(line)
		for start := 0; start+len(expected) <= len(fields); start++ {
			if slicesEqual(fields[start:start+len(expected)], expected) {
				return true
			}
		}
	}
	return false
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
	return runtime.Reload(ctx)
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

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	return os.ReadFile(path)
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
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
