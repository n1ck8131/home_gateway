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
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/providers/redshield"
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
}

const (
	commandPhysicalGUID  = "11111111-1111-4111-8111-111111111111"
	commandRedShieldGUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
)

func (backend staticInspectionBackend) Inspect(context.Context, tunnel.ConfigSource) (tunnel.Inspection, error) {
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

func TestParseCanaryLiveCommandRequiresActionSpecificConfirmation(t *testing.T) {
	planArgs := []string{"windows", "canary", "apply", "--config", "config", "--config-sha256", strings.Repeat("a", 64), "--state-root", "state", "--revision", "p35", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--confirm-live", "P35-APPLY-0011223344556677", "--json"}
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
			code := runCanaryLive(canaryLiveCommand{action: action, plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: confirmation}, &stdout, &stderr, dependencies{
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
