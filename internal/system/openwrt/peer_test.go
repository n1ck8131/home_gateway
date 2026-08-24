package openwrt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

const validPeerJSON = `{
  "version": 1,
  "server_id": "primary",
  "slot": 1,
  "interface": "awg0",
  "uci_interface": "awg0",
  "uci_peer": "awg0_peer",
  "endpoint": {
    "ip": "9.9.9.9",
    "port": 51820,
    "wan_gateway": "9.9.9.1",
    "wan_device": "wan"
  },
  "private_key_ref": {
    "kind": "routerd-openwrt-peer-private-key",
    "name": "primary"
  },
  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "addresses": ["10.71.0.2/32", "fd71::2/128"],
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "awg": {
    "jc": 4,
    "jmin": 10,
    "jmax": 50,
    "s1": 142,
    "s2": 41,
    "s3": 56,
    "s4": 11,
    "h1": "684141592-1751861769",
    "h2": "1957920865-2010016669",
    "h3": "2043550980-2107134838",
    "h4": "2127672251-2132651859",
    "i1": "<r 2>",
    "i2": "<r 3>",
    "i3": "<rd 4>",
    "i4": "<rc 4>",
    "i5": "<b 0x0102>"
  },
  "persistent_keepalive": 25,
  "route_allowed_ips": 0,
  "nohostroute": 1
}`

func TestParsePeerSpecStrictValidation(t *testing.T) {
	spec, err := ParsePeerSpec([]byte(validPeerJSON))
	if err != nil {
		t.Fatal(err)
	}
	route, err := spec.ServerRoute()
	if err != nil {
		t.Fatal(err)
	}
	if route.Mark != 0x01000000 || route.Table != 10001 {
		t.Fatalf("route = %+v", route)
	}
	if got := spec.PrivateKeyRef.FilePath(); got != "/etc/routerd/secrets/routerd-openwrt-peer-private-key_primary.key" {
		t.Fatalf("secret file path = %q", got)
	}
	if spec.AWG.S3 != 56 || spec.AWG.I5 != "<b 0x0102>" {
		t.Fatalf("AWG params = %+v", spec.AWG)
	}
}

func TestOpenWrtPeerExampleMatchesContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "openwrt", "peer.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ParsePeerSpec(data)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.SanitizedExample {
		t.Fatal("peer example must remain explicitly non-deployable")
	}
	if _, err := BuildOperationPlan(spec); err == nil || !strings.Contains(err.Error(), "sanitized") {
		t.Fatalf("BuildOperationPlan() error = %v, want sanitized-example gate", err)
	}
}

func TestPeerSpecRejectsUnknownInjectionFamilyMismatchAndUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown top-level", data: strings.Replace(validPeerJSON, `"nohostroute": 1`, `"nohostroute": 1, "unexpected": true`, 1)},
		{name: "bad server ID", data: strings.Replace(validPeerJSON, `"server_id": "primary"`, `"server_id": "../primary"`, 1)},
		{name: "non canonical server ID", data: strings.Replace(validPeerJSON, `"server_id": "primary"`, `"server_id": "Primary"`, 1)},
		{name: "loopback endpoint", data: strings.Replace(validPeerJSON, `"9.9.9.9"`, `"127.0.0.1"`, 1)},
		{name: "multicast endpoint", data: strings.Replace(validPeerJSON, `"9.9.9.9"`, `"224.0.0.1"`, 1)},
		{name: "private endpoint", data: strings.Replace(validPeerJSON, `"9.9.9.9"`, `"10.0.0.10"`, 1)},
		{name: "documentation endpoint", data: strings.Replace(validPeerJSON, `"9.9.9.9"`, `"203.0.113.10"`, 1)},
		{name: "command injection endpoint", data: strings.Replace(validPeerJSON, `"9.9.9.9"`, `"9.9.9.9;reboot"`, 1)},
		{name: "bad wan device", data: strings.Replace(validPeerJSON, `"wan"`, `"-help"`, 1)},
		{name: "family mismatch", data: strings.Replace(validPeerJSON, `"9.9.9.1"`, `"2001:db8::1"`, 1)},
		{name: "non canonical allowed ips", data: strings.Replace(validPeerJSON, `["0.0.0.0/0", "::/0"]`, `["::/0", "0.0.0.0/0"]`, 1)},
		{name: "fwmark rejected as unknown", data: strings.Replace(validPeerJSON, `"route_allowed_ips": 0`, `"fwmark": "0x1", "route_allowed_ips": 0`, 1)},
		{name: "private key bytes rejected", data: strings.Replace(validPeerJSON, `"private_key_ref"`, `"private_key"`, 1)},
		{name: "secret dotdot rejected", data: strings.Replace(validPeerJSON, `"name": "primary"`, `"name": "pri..mary"`, 1)},
		{name: "AWG control rejected", data: strings.Replace(validPeerJSON, `"<r 2>"`, "\"<r\\n2>\"", 1)},
		{name: "AWG jmin above jmax", data: strings.Replace(validPeerJSON, `"jmin": 10`, `"jmin": 51`, 1)},
		{name: "AWG missing required value", data: strings.Replace(validPeerJSON, `"s4": 11`, `"s4": 0`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParsePeerSpec([]byte(test.data)); err == nil {
				t.Fatal("ParsePeerSpec() error = nil, want rejection")
			}
		})
	}
}

func TestDesiredStateBindsSystemDirectEndpointAndServerSlot(t *testing.T) {
	spec := mustPeerSpec(t)
	state, err := spec.DesiredState(time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if state.MarkMask != contracts.RouterdMarkMask || state.ActiveServerID != "primary" || len(state.Servers) != 1 {
		t.Fatalf("state = %+v", state)
	}
	entry := state.Entries[0]
	if entry.Origin != contracts.OriginSystemDirect || entry.Route != contracts.RouteClassDirect || entry.Pattern != "9.9.9.9/32" {
		t.Fatalf("endpoint direct entry = %+v", entry)
	}
}

func mustPeerSpec(t *testing.T) PeerSpec {
	t.Helper()
	spec, err := ParsePeerSpec([]byte(validPeerJSON))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
