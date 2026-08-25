package hgctlcmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
