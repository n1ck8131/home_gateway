package hgctlcmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/providers/redshield"
	"github.com/vsevo/home-gateway/internal/revisions/apply"
	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

type staticCollector struct {
	inventory windowssystem.Inventory
}

func (collector staticCollector) Collect(context.Context) (windowssystem.Inventory, error) {
	return collector.inventory, nil
}

type staticInspectionBackend struct {
	redshield.Backend
	inspection tunnel.Inspection
	sourceSink *tunnel.ConfigSource
}

const (
	commandPhysicalGUID  = "11111111-1111-4111-8111-111111111111"
	commandRedShieldGUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
	commandCiscoGUID     = "22222222-2222-4222-8222-222222222222"
)

func (backend staticInspectionBackend) Inspect(_ context.Context, source tunnel.ConfigSource) (tunnel.Inspection, error) {
	if backend.sourceSink != nil {
		*backend.sourceSink = source
	}
	return backend.inspection, nil
}

func TestRunPreservesVersionCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run("hgctl", []string{"version", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var result map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["program"] != "hgctl" {
		t.Fatalf("program = %q", result["program"])
	}
}

func TestUsageShowsMandatoryFullRestorePlanHash(t *testing.T) {
	var usage bytes.Buffer
	writeUsage("hgctl", &usage)
	line := "windows canary full-restore --state-root <absolute-path> --confirm-recovery <action-token> --recovery-plan-sha256 <lowercase-sha256> --json"
	if !strings.Contains(usage.String(), line) {
		t.Fatalf("full-restore usage omitted mandatory plan hash:\n%s", usage.String())
	}
}

func TestRunRedShieldInspectJSONIsRedacted(t *testing.T) {
	privateKey := commandSyntheticKey(41)
	publicKey := commandSyntheticKey(42)
	path := writeCommandConfig(t, privateKey, publicKey)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run("hgctl", []string{"redshield", "inspect", "--config", path, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	for _, forbidden := range []string{privateKey, publicKey, path, "private_key", "public_key", "preshared"} {
		if strings.Contains(strings.ToLower(stdout.String()), strings.ToLower(forbidden)) {
			t.Fatalf("inspection JSON leaked %q: %s", forbidden, stdout.String())
		}
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
}

func TestParseReadOnlyCommandAcceptsProviderNeutralTunnelInspect(t *testing.T) {
	pin := strings.Repeat("a", 64)
	path, configSHA256, command, ok := parseReadOnlyCommand([]string{"tunnel", "inspect", "--config", "C:\\synthetic.conf", "--config-sha256", pin, "--json"})
	if !ok || command != "tunnel-inspect" || path != "C:\\synthetic.conf" || configSHA256 != pin {
		t.Fatalf("provider-neutral inspect = %q, %q, %q, %v", path, configSHA256, command, ok)
	}
}

func TestRunTunnelInspectPassesPinnedConfigSource(t *testing.T) {
	pin := strings.Repeat("b", 64)
	var source tunnel.ConfigSource
	deps := dependencies{backend: staticInspectionBackend{inspection: tunnel.Inspection{}, sourceSink: &source}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies("hgctl", []string{"tunnel", "inspect", "--config", `C:\synthetic.conf`, "--config-sha256", pin, "--json"}, &stdout, &stderr, deps)
	if code != 0 || source.Path != `C:\synthetic.conf` || source.SHA256 != pin {
		t.Fatalf("code=%d source=%#v stderr=%q", code, source, stderr.String())
	}
}

func TestRunWindowsPreflightReturnsZeroOnlyWhenReadOnlyQualified(t *testing.T) {
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportWireGuard,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/24", "fd00::2/64"},
			IPv4FullTunnel:     true,
			IPv6FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUnknown, Observed: false},
	}
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24"}},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 1},
		},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	deps := dependencies{
		backend: staticInspectionBackend{inspection: inspection},
		collect: staticCollector{inventory: inventory},
		resolve: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.5"}, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies("hgctl", []string{"windows", "preflight", "--config", `C:\synthetic.conf`, "--json"}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("ready preflight code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}
	var result struct {
		Preflight windowssystem.Preflight `json:"preflight"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Preflight.Ready || !result.Preflight.ApplyBlocked || !result.Preflight.ReadOnlyQualified {
		t.Fatalf("exit zero did not preserve P3.3 apply block: %#v", result.Preflight)
	}
}

func TestRunWindowsPreflightIsReadOnlyAndBlocksRedlinkEndpointRoute(t *testing.T) {
	path := writeCommandConfig(t, commandSyntheticKey(51), commandSyntheticKey(52))
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24"}},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32", "fd00::2/128"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", InterfaceIndex: 2, InterfaceGUID: commandRedShieldGUID, Metric: 1},
		},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	deps := dependencies{
		backend: redshield.Backend{},
		collect: staticCollector{inventory: inventory},
		resolve: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.5"}, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies("hgctl", []string{"windows", "preflight", "--config", path, "--json"}, &stdout, &stderr, deps)
	if code != 3 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var result struct {
		Preflight windowssystem.Preflight `json:"preflight"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Preflight.ApplyBlocked || result.Preflight.Ready || result.Preflight.ReadOnlyQualified {
		t.Fatalf("preflight did not block unsafe endpoint route: %#v", result.Preflight)
	}
	found := false
	for _, operation := range result.Preflight.Operations {
		if operation.Kind == windowssystem.OperationAddEndpointDirectException && operation.Destination == "203.0.113.5/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("direct endpoint exception requirement missing: %#v", result.Preflight.Operations)
	}
}

func TestRunWindowsPreflightReturnsThreeForAuthoritativeBackendDown(t *testing.T) {
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "203.0.113.5", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/32"},
			IPv4FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateDown, Observed: true},
	}
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24"}},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 1},
		},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	deps := dependencies{
		backend: staticInspectionBackend{inspection: inspection},
		collect: staticCollector{inventory: inventory},
		resolve: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.5"}, nil
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithDependencies("hgctl", []string{"windows", "preflight", "--config", `C:\synthetic.conf`, "--json"}, &stdout, &stderr, deps)
	if code != 3 {
		t.Fatalf("backend-down preflight code = %d, stderr = %q, stdout = %q", code, stderr.String(), stdout.String())
	}
}

func TestRunRejectsAnyMutatingCommand(t *testing.T) {
	for _, args := range [][]string{
		{"redshield", "start"},
		{"redshield", "stop"},
		{"windows", "apply"},
		{"redshield", "inspect", "--config", "path"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Run("hgctl", args, &stdout, &stderr); code != 2 {
			t.Fatalf("args %v returned code %d", args, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("args %v wrote stdout %q", args, stdout.String())
		}
	}
}

func TestRunWindowsCanaryPlanIsReadOnlyRedactedAndChallengeBound(t *testing.T) {
	configSHA256 := strings.Repeat("a", 64)
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/32"},
			DNS:                []string{"10.20.30.1"},
			IPv4FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUnknown, Observed: false},
	}
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true, Addresses: []string{"192.168.1.10/24"}},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 1},
		},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	deps := dependencies{
		backend: staticInspectionBackend{inspection: inspection},
		collect: staticCollector{inventory: inventory},
		resolve: func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil },
	}
	configPath := `C:\private-provider-source.conf`
	stateRoot := filepath.Join(t.TempDir(), "state")
	args := []string{"windows", "canary", "plan", "--config", configPath, "--config-sha256", configSHA256, "--state-root", stateRoot, "--revision", "p35-canary-001", "--target", "198.51.100.10", "--dns-namespace", windowssystem.CanaryDNSNamespace, "--json"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runWithDependencies("hgctl", args, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	for _, forbidden := range []string{configPath, stateRoot, "10.20.30.1", "203.0.113.5", "198.51.100.10"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("canary plan leaked %q: %s", forbidden, stdout.String())
		}
	}
	var output canaryPlanOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if !output.ReadyForLiveGate || output.LiveMutationPerformed || output.RouteCount != 2 || output.FirewallRuleCount != 2 || output.DNSRuleCount != 1 || !strings.HasPrefix(output.ConfirmationChallenge, "P35-APPLY-") {
		t.Fatalf("unexpected canary plan output: %#v", output)
	}
	var successFields map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &successFields); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"mode", "revision", "ready_for_live_gate",
		"live_mutation_performed", "route_count", "sink_count",
		"persistent_sink_ready", "firewall_rule_count", "dns_rule_count",
		"confirmation_challenge", "candidate_sha256", "candidate_identity", "confirm_timeout_seconds",
	}
	gotKeys := make([]string, 0, len(successFields))
	for key := range successFields {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if !slices.Equal(gotKeys, wantKeys) {
		t.Fatalf("success output keys = %v, want %v", gotKeys, wantKeys)
	}
	if output.BlockCode != "" || output.BlockDetails != nil {
		t.Fatalf("success output contains block data: %#v", output)
	}

	args[8] = filepath.Join(t.TempDir(), "other-state")
	stdout.Reset()
	stderr.Reset()
	if code := runWithDependencies("hgctl", args, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("second plan code = %d, stderr = %q", code, stderr.String())
	}
	var rebound canaryPlanOutput
	if err := json.Unmarshal(stdout.Bytes(), &rebound); err != nil {
		t.Fatal(err)
	}
	if rebound.ConfirmationChallenge == output.ConfirmationChallenge {
		t.Fatal("confirmation challenge was not rebound to the state root")
	}
	args[8] = stateRoot
	args[6] = strings.Repeat("b", 64)
	stdout.Reset()
	stderr.Reset()
	if code := runWithDependencies("hgctl", args, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("digest rebound plan code = %d, stderr = %q", code, stderr.String())
	}
	var digestRebound canaryPlanOutput
	if err := json.Unmarshal(stdout.Bytes(), &digestRebound); err != nil {
		t.Fatal(err)
	}
	if digestRebound.ConfirmationChallenge == output.ConfirmationChallenge {
		t.Fatal("confirmation challenge was not rebound to the config SHA-256")
	}
}

func TestRunWindowsCanaryPlanReturnsRedactedIsolationJSON(t *testing.T) {
	inspection, inventory := commandCanaryInputs()
	inventory.Adapters = append(inventory.Adapters, windowssystem.Adapter{
		Name: "Cisco", Index: 31, InterfaceGUID: commandCiscoGUID,
		Kind: windowssystem.AdapterCisco, Up: true,
	})
	inventory.Routes = append(inventory.Routes, windowssystem.Route{
		Family: windowssystem.FamilyIPv4, Destination: "10.20.30.0/24",
		NextHop: "0.0.0.0", InterfaceIndex: 31,
		InterfaceGUID: commandCiscoGUID, Metric: 1,
	})
	configPath := `C:\private-provider-source.conf`
	stateRoot := filepath.Join(t.TempDir(), "state")
	configSHA256 := strings.Repeat("a", 64)
	command := canaryPlanCommand{
		configPath: configPath, configSHA256: configSHA256, stateRoot: stateRoot,
		revision: "p35-canary-blocked", targets: []string{"198.51.100.10"},
		dnsNamespace: windowssystem.CanaryDNSNamespace,
	}
	deps := dependencies{
		backend: staticInspectionBackend{inspection: inspection},
		collect: staticCollector{inventory: inventory},
		resolve: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.5"}, nil
		},
		validateStateRoot:    func(string) error { return nil },
		validateConfigSource: func(string) error { return nil },
	}
	var stdout, stderr bytes.Buffer
	if code := runCanaryPlan(command, &stdout, &stderr, deps); code != 3 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	var output canaryPlanOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	wantBlocks := []windowssystem.CanaryIsolationBlock{{
		TargetSource: windowssystem.CanaryTargetSourceImportedDNS, ProtectedClass: windowssystem.CanaryProtectedClassCiscoPrefix,
		Family: windowssystem.FamilyIPv4, AffectedTargetCount: 1,
	}}
	if output.ReadyForLiveGate || output.LiveMutationPerformed || output.RouteCount != 0 || output.SinkCount != 0 || output.PersistentSinkReady || output.FirewallRuleCount != 0 || output.DNSRuleCount != 0 || output.BlockCode != windowssystem.CanaryIsolationBlockCode || !slices.Equal(output.BlockDetails, wantBlocks) {
		t.Fatalf("blocked plan output = %#v", output)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	wantBlockedKeys := []string{
		"mode", "revision", "ready_for_live_gate", "live_mutation_performed",
		"route_count", "sink_count", "persistent_sink_ready", "firewall_rule_count",
		"dns_rule_count", "block_code", "block_details",
	}
	gotBlockedKeys := make([]string, 0, len(fields))
	for key := range fields {
		gotBlockedKeys = append(gotBlockedKeys, key)
	}
	sort.Strings(gotBlockedKeys)
	sort.Strings(wantBlockedKeys)
	if !slices.Equal(gotBlockedKeys, wantBlockedKeys) {
		t.Fatalf("blocked output keys = %v, want %v", gotBlockedKeys, wantBlockedKeys)
	}
	for _, key := range []string{"confirmation_challenge", "confirm_timeout_seconds"} {
		if _, found := fields[key]; found {
			t.Fatalf("blocked plan unexpectedly includes %q", key)
		}
	}
	for _, forbidden := range []string{configPath, stateRoot, configSHA256, "10.20.30.1", "10.20.30.0/24", "203.0.113.5", "198.51.100.10", "Cisco", commandCiscoGUID} {
		if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("blocked plan leaked %q", forbidden)
		}
	}
}

func TestCanaryBlockedPlanOutputRejectsInvalidTypedData(t *testing.T) {
	command := canaryPlanCommand{revision: "p35-canary-blocked"}
	for _, blocked := range []*windowssystem.CanaryIsolationError{
		{Blocks: []windowssystem.CanaryIsolationBlock{{
			TargetSource: "unknown", ProtectedClass: windowssystem.CanaryProtectedClassCiscoPrefix,
			Family: windowssystem.FamilyIPv4, AffectedTargetCount: 1,
		}}},
		{Blocks: []windowssystem.CanaryIsolationBlock{{
			TargetSource: windowssystem.CanaryTargetSourceImportedDNS, ProtectedClass: windowssystem.CanaryProtectedClassCiscoPrefix,
			Family: windowssystem.FamilyIPv4, AffectedTargetCount: 0,
		}}},
	} {
		if _, ok := canaryBlockedPlanOutput(command, fmt.Errorf("wrapped: %w", blocked)); ok {
			t.Fatal("invalid typed block unexpectedly serialized")
		}
	}
}

func TestParseCanaryPlanCommandRejectsAmbiguousArguments(t *testing.T) {
	for _, args := range [][]string{
		{"windows", "canary", "plan"},
		{"windows", "canary", "plan", "--config", "a", "--config", "b", "--state-root", "c", "--revision", "r", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--json"},
		{"windows", "canary", "plan", "--config", "a", "--state-root", "c", "--revision", "r", "--target", "1.1.1.1", "--dns-namespace", ".probe.example"},
		{"windows", "canary", "plan", "--config", "a", "--state-root", "c", "--revision", "r", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--json", "extra"},
	} {
		if _, ok := parseCanaryPlanCommand(args); ok {
			t.Fatalf("ambiguous args unexpectedly parsed: %v", args)
		}
	}
}

func TestParseCanaryFullRestorePlanIsReadOnlyAndExact(t *testing.T) {
	command, ok := parseCanaryFullRestorePlanCommand([]string{"windows", "canary", "full-restore-plan", "--state-root", `C:\ProgramData\HomeGateway\p35`, "--json"})
	if !ok || command.stateRoot == "" {
		t.Fatalf("full restore plan parse = %#v, %v", command, ok)
	}
	for _, args := range [][]string{
		{"windows", "canary", "full-restore-plan", "--state-root", "state"},
		{"windows", "canary", "full-restore-plan", "--state-root", "a", "--state-root", "b", "--json"},
		{"windows", "canary", "full-restore-plan", "--state-root", "state", "--confirm-recovery", "x", "--json"},
	} {
		if _, ok := parseCanaryFullRestorePlanCommand(args); ok {
			t.Fatalf("unsafe full restore plan args parsed: %v", args)
		}
	}
}

func TestLoadCanaryJournalReadOnlyNeverRecoversAtomicReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "journal.json")
	current := []byte("{\"state\":\"idle\"}\n")
	next := []byte("{\"state\":\"restored\"}\n")
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".next", next, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := loadCanaryJournalReadOnly(path)
	if err != nil || journal.State != apply.StateIdle {
		t.Fatalf("read-only journal = %#v, %v", journal, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, current) {
		t.Fatalf("current journal changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(path + ".next"); err != nil || !bytes.Equal(got, next) {
		t.Fatalf("atomic leftover changed: %q, %v", got, err)
	}
}

func TestParseCanaryLiveCommandRequiresActionSpecificConfirmation(t *testing.T) {
	planArgs := []string{"windows", "canary", "apply", "--config", "config", "--config-sha256", strings.Repeat("a", 64), "--candidate-sha256", strings.Repeat("b", 64), "--state-root", "state", "--revision", "p35", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--confirm-live", "P35-APPLY-0011223344556677", "--json"}
	command, ok := parseCanaryLiveCommand(planArgs)
	if !ok || command.action != "apply" || command.liveConfirm == "" || len(command.plan.targets) != 1 {
		t.Fatalf("valid live command did not parse: %#v, %v", command, ok)
	}
	for _, args := range [][]string{
		{"windows", "canary", "apply", "--config", "config", "--state-root", "state", "--revision", "p35", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--json"},
		{"windows", "canary", "rollback", "--state-root", "state", "--json"},
		{"windows", "canary", "recover", "--state-root", "state", "--confirm-recovery", recoveryRecoverToken, "--target", "1.1.1.1", "--json"},
		{"windows", "canary", "status", "--state-root", "state", "--confirm-recovery", recoveryRecoverToken, "--json"},
	} {
		if _, ok := parseCanaryLiveCommand(args); ok {
			t.Fatalf("unsafe live args unexpectedly parsed: %v", args)
		}
	}
}

func TestRunCanaryStatusDoesNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCanaryLive(canaryLiveCommand{action: "status", plan: canaryPlanCommand{stateRoot: root}}, &stdout, &stderr, dependencies{
		validateStateRoot: func(string) error { return nil },
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("read-only status created state: %v", err)
	}
	var output canaryStatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.State != "idle" || output.HasActive || output.HasPending {
		t.Fatalf("status = %#v", output)
	}
}

func TestRunCanaryRecoveryDoesNotCreateAbsentStateRoot(t *testing.T) {
	for action, confirmation := range map[string]string{
		"rollback":          recoveryRollbackToken,
		"recover":           recoveryRecoverToken,
		"emergency-disable": recoveryDisableToken,
		"full-restore":      recoveryRestoreToken,
		"expire":            recoveryExpireToken,
	} {
		t.Run(action, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "absent")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			command := canaryLiveCommand{action: action, plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: confirmation}
			if action == "full-restore" {
				command.recoveryConfirm = recoveryRestoreToken + "-0123456789ABCDEF"
				command.recoveryPlanSHA256 = strings.Repeat("a", 64)
			}
			code := runCanaryLive(command, &stdout, &stderr, dependencies{
				validateStateRoot: func(string) error { return nil },
			})
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("absent recovery created state: %v", err)
			}
		})
	}
}

func TestRunCanaryApplyRejectsMismatchedCandidateChallengeBeforeMutation(t *testing.T) {
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/32"},
			DNS:                []string{"10.20.30.1"},
			IPv4FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUnknown, Observed: false},
	}
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 1},
		},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	mutationCalls := 0
	deps := dependencies{
		backend:              staticInspectionBackend{inspection: inspection},
		collect:              staticCollector{inventory: inventory},
		resolve:              func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil },
		validateStateRoot:    func(string) error { return nil },
		validateConfigSource: func(string) error { return nil },
		newMutation: func(string) (windowssystem.MutationBackend, error) {
			mutationCalls++
			return nil, fmt.Errorf("must not be called")
		},
	}
	command := canaryLiveCommand{
		action: "apply",
		plan: canaryPlanCommand{
			configPath:   `C:\private-provider-source.conf`,
			stateRoot:    filepath.Join(t.TempDir(), "state"),
			revision:     "p35-canary-001",
			targets:      []string{"198.51.100.10"},
			dnsNamespace: windowssystem.CanaryDNSNamespace,
		},
		liveConfirm: "P35-APPLY-WRONG",
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := runCanaryLive(command, &stdout, &stderr, deps); code != 2 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if mutationCalls != 0 || stdout.Len() != 0 {
		t.Fatalf("mutation backend calls = %d, stdout = %q", mutationCalls, stdout.String())
	}
}

func writeCommandConfig(t *testing.T, privateKey, publicKey string) string {
	t.Helper()
	text := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.20.30.2/32, fd00::2/128
DNS = 10.20.30.1
MTU = 1420
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.test:51820
PersistentKeepalive = 25
`, privateKey, publicKey)
	path := filepath.Join(t.TempDir(), "private-provider-source.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func commandSyntheticKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
