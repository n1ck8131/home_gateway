package windows

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	testPhysicalGUID  = "11111111-1111-4111-8111-111111111111"
	testRedShieldGUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
	testCiscoGUID     = "cdefabcd-efab-4cde-8abc-cdefabcdefab"
)

type fakeSnapshotRunner struct {
	output []byte
	err    error
	calls  int
}

func (runner *fakeSnapshotRunner) Output(context.Context) ([]byte, error) {
	runner.calls++
	return runner.output, runner.err
}

func TestNativeCollectorParsesAuthoritativeStructuredSnapshot(t *testing.T) {
	runner := &fakeSnapshotRunner{output: validSnapshotJSON()}
	inventory, err := (NativeCollector{Runner: runner}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 {
		t.Fatalf("snapshot command calls = %d, want 1", runner.calls)
	}
	if !inventory.RouteSnapshotAuthoritative || !inventory.DNSPolicyObserved {
		t.Fatalf("complete strict snapshot was not authoritative: %#v", inventory)
	}
	physical := assertAdapter(t, inventory.Adapters, 12, AdapterPhysical, testPhysicalGUID, true)
	if !physical.HardwareInterface {
		t.Fatal("physical adapter did not retain the authoritative Windows hardware marker")
	}
	redShield := assertAdapter(t, inventory.Adapters, 21, AdapterRedShield, testRedShieldGUID, true)
	if !reflect.DeepEqual(redShield.Addresses, []string{"10.20.30.2/32", "fd00::2/128"}) {
		t.Fatalf("usable RedShield addresses = %#v", redShield.Addresses)
	}
	assertAdapter(t, inventory.Adapters, 31, AdapterCisco, testCiscoGUID, true)

	endpointRoute := findRoute(t, inventory.Routes, "203.0.113.5/32", 12)
	if endpointRoute.RouteMetric != 2 || endpointRoute.InterfaceMetric != 25 || endpointRoute.Metric != 27 || endpointRoute.InterfaceGUID != testPhysicalGUID {
		t.Fatalf("route metrics or identity were not joined: %#v", endpointRoute)
	}
	loopbackRoute := findRoute(t, inventory.Routes, "127.0.0.0/8", 1)
	if loopbackRoute.InterfaceGUID != "" {
		t.Fatalf("unmatched system route gained an identity: %#v", loopbackRoute)
	}
	if inventory.DNSPolicy.EffectiveNRPTRuleCount != 2 || len(inventory.DNSPolicy.ServerSets) != 2 {
		t.Fatalf("DNS/NRPT snapshot = %#v", inventory.DNSPolicy)
	}
	var physicalDNS DNSServerSet
	for _, serverSet := range inventory.DNSPolicy.ServerSets {
		if serverSet.InterfaceIndex == 12 {
			physicalDNS = serverSet
		}
	}
	if physicalDNS.InterfaceGUID != testPhysicalGUID || !reflect.DeepEqual(physicalDNS.Servers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("DNS identity or canonical servers = %#v", physicalDNS)
	}
	var systemDNS DNSServerSet
	for _, serverSet := range inventory.DNSPolicy.ServerSets {
		if serverSet.InterfaceIndex == 1 {
			systemDNS = serverSet
		}
	}
	if systemDNS.InterfaceGUID != "" || !reflect.DeepEqual(systemDNS.Servers, []string{"::1"}) {
		t.Fatalf("unmatched system DNS set was not preserved honestly: %#v", systemDNS)
	}
}

func TestStructuredSnapshotParserFailsClosed(t *testing.T) {
	valid := string(validSnapshotJSON())
	for name, data := range map[string][]byte{
		"malformed":               []byte(`not-json`),
		"incomplete":              []byte(`{"adapters":[]}`),
		"unknown root":            []byte(strings.Replace(valid, `"nrptRuleCount":2`, `"nrptRuleCount":2,"extra":true`, 1)),
		"unknown nested":          []byte(strings.Replace(valid, `"adminStatus":1`, `"adminStatus":1,"extra":true`, 1)),
		"trailing":                append(validSnapshotJSON(), []byte(` {}`)...),
		"oversized":               []byte(strings.Repeat("x", maxSnapshotBytes+1)),
		"duplicate GUID":          []byte(strings.Replace(valid, testRedShieldGUID, testPhysicalGUID, 1)),
		"zero GUID":               []byte(strings.Replace(valid, testRedShieldGUID, "00000000-0000-0000-0000-000000000000", 1)),
		"noncanonical GUID":       []byte(strings.Replace(valid, testRedShieldGUID, strings.ToUpper(testRedShieldGUID), 1)),
		"duplicate index":         []byte(strings.Replace(valid, `"interfaceIndex":21,"interfaceGuid":"`+testRedShieldGUID, `"interfaceIndex":12,"interfaceGuid":"`+testRedShieldGUID, 1)),
		"invalid admin":           []byte(strings.Replace(valid, `"adminStatus":1`, `"adminStatus":4`, 1)),
		"invalid oper":            []byte(strings.Replace(valid, `"operationalStatus":1`, `"operationalStatus":8`, 1)),
		"invalid address state":   []byte(strings.Replace(valid, `"addressState":4`, `"addressState":5`, 1)),
		"address family mismatch": []byte(strings.Replace(valid, `"addressFamily":2,"ipAddress":"192.168.1.10"`, `"addressFamily":23,"ipAddress":"192.168.1.10"`, 1)),
		"route family mismatch":   []byte(strings.Replace(valid, `"addressFamily":2,"destinationPrefix":"0.0.0.0/0"`, `"addressFamily":23,"destinationPrefix":"0.0.0.0/0"`, 1)),
		"invalid route state":     []byte(strings.Replace(valid, `"state":0`, `"state":3`, 1)),
		"metric overflow":         []byte(strings.Replace(valid, `"routeMetric":5`, `"routeMetric":4294967296`, 1)),
		"DNS family mismatch":     []byte(strings.Replace(valid, `"serverAddresses":["8.8.8.8","1.1.1.1"]`, `"serverAddresses":["2001:4860:4860::8888"]`, 1)),
		"DNS zone mismatch":       []byte(strings.Replace(valid, `"serverAddresses":["::1"]`, `"serverAddresses":["fe80::1%12"]`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInventorySnapshot(data); err == nil {
				t.Fatal("unsafe snapshot was accepted")
			}
		})
	}
}

func TestStructuredSnapshotAllowsObservedStatusEnumsButUsesOnlyUsableAddresses(t *testing.T) {
	valid := string(validSnapshotJSON())
	valid = strings.Replace(valid, `"adminStatus":1,"operationalStatus":1`, `"adminStatus":2,"operationalStatus":6`, 1)
	inventory, err := parseInventorySnapshot([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	physical := assertAdapter(t, inventory.Adapters, 12, AdapterPhysical, testPhysicalGUID, false)
	if len(physical.Addresses) != 1 || physical.Addresses[0] != "192.168.1.10/24" {
		t.Fatalf("tentative address was treated as usable: %#v", physical.Addresses)
	}
}

func TestStructuredSnapshotAcceptsMatchingWindowsIPv6Zone(t *testing.T) {
	valid := strings.Replace(
		string(validSnapshotJSON()),
		`"ipAddress":"fd00::2"`,
		`"ipAddress":"fd00::2%21"`,
		1,
	)
	inventory, err := parseInventorySnapshot([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	redShield := assertAdapter(t, inventory.Adapters, 21, AdapterRedShield, testRedShieldGUID, true)
	if !reflect.DeepEqual(redShield.Addresses, []string{"10.20.30.2/32", "fd00::2/128"}) {
		t.Fatalf("zoned IPv6 address was not normalized: %#v", redShield.Addresses)
	}

	invalid := strings.Replace(valid, `"ipAddress":"fd00::2%21"`, `"ipAddress":"fd00::2%12"`, 1)
	if _, err := parseInventorySnapshot([]byte(invalid)); err == nil {
		t.Fatal("IPv6 address with a mismatched interface zone was accepted")
	}
}

func TestStructuredSnapshotAcceptsMatchingWindowsIPv6DNSZone(t *testing.T) {
	valid := strings.Replace(
		string(validSnapshotJSON()),
		`"serverAddresses":["::1"]`,
		`"serverAddresses":["fe80::1%1"]`,
		1,
	)
	inventory, err := parseInventorySnapshot([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	var systemDNS DNSServerSet
	for _, serverSet := range inventory.DNSPolicy.ServerSets {
		if serverSet.InterfaceIndex == 1 {
			systemDNS = serverSet
		}
	}
	if !reflect.DeepEqual(systemDNS.Servers, []string{"fe80::1%1"}) {
		t.Fatalf("scoped IPv6 DNS server was not preserved: %#v", systemDNS)
	}
}

func TestStructuredSnapshotRejectsUnresolvedDefaultIdentityButAllowsSystemRoute(t *testing.T) {
	valid := string(validSnapshotJSON())
	if _, err := parseInventorySnapshot([]byte(valid)); err != nil {
		t.Fatalf("unmatched non-default system route was rejected: %v", err)
	}
	unsafe := strings.Replace(valid, `"destinationPrefix":"127.0.0.0/8"`, `"destinationPrefix":"0.0.0.0/0"`, 1)
	if _, err := parseInventorySnapshot([]byte(unsafe)); err == nil {
		t.Fatal("unresolved active default route was accepted")
	}
}

func TestStructuredSnapshotCountCaps(t *testing.T) {
	route := `{"interfaceIndex":12,"addressFamily":2,"destinationPrefix":"10.0.0.0/8","nextHop":"192.168.1.1","routeMetric":5,"interfaceMetric":25,"state":0}`
	routes := strings.Repeat(route+",", maxRoutes) + route
	data := strings.Replace(string(validSnapshotJSON()), validRoutesJSON(), routes, 1)
	if _, err := parseInventorySnapshot([]byte(data)); err == nil {
		t.Fatal("route count above cap was accepted")
	}
}

func TestTrustedInventoryCommandUsesAbsoluteSystem32SurfaceAndSanitizedEnvironment(t *testing.T) {
	windowsDirectory := filepath.Join(t.TempDir(), "Windows")
	systemDirectory := filepath.Join(windowsDirectory, "System32")
	spec, err := buildInventoryCommand(nativeInventoryPaths{
		WindowsDirectory: windowsDirectory,
		SystemDirectory:  systemDirectory,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantExecutable := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	if spec.Executable != wantExecutable || !filepath.IsAbs(spec.Executable) || spec.Directory != systemDirectory {
		t.Fatalf("untrusted executable spec: %#v", spec)
	}
	if len(spec.Arguments) < 2 || spec.Arguments[len(spec.Arguments)-1] != inventoryScript {
		t.Fatalf("fixed inventory script missing from args: %#v", spec.Arguments)
	}
	joined := strings.ToLower(strings.Join(spec.Arguments, " "))
	for _, required := range []string{"get-netadapter", "get-netipaddress", "get-netroute", "activestore", "get-dnsclientserveraddress", "get-dnsclientnrptpolicy", "convertto-json"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("trusted script lacks %q", required)
		}
	}
	for _, forbidden := range []string{"route.exe", "set-net", "remove-net", "disable-net", "enable-net", "start-service", "stop-service"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("trusted script contains mutating or PATH command %q", forbidden)
		}
	}
	for _, entry := range spec.Environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed environment entry %q", entry)
		}
		if strings.HasPrefix(parts[0], "HG_") && !filepath.IsAbs(parts[1]) {
			t.Fatalf("module manifest is not absolute: %q", entry)
		}
	}
	if len(spec.Environment) != 10 {
		t.Fatalf("unexpected inherited environment surface: %#v", spec.Environment)
	}

	if _, err := buildInventoryCommand(nativeInventoryPaths{WindowsDirectory: "relative", SystemDirectory: "relative"}); err == nil {
		t.Fatal("relative trusted paths were accepted")
	}
	if _, err := buildInventoryCommand(nativeInventoryPaths{WindowsDirectory: windowsDirectory, SystemDirectory: filepath.Dir(windowsDirectory)}); err == nil {
		t.Fatal("system directory outside Windows directory was accepted")
	}
	if _, err := buildInventoryCommand(nativeInventoryPaths{WindowsDirectory: windowsDirectory, SystemDirectory: filepath.Join(windowsDirectory, "SysWOW64")}); err == nil {
		t.Fatal("non-System32 inventory path was accepted")
	}
}

func TestBoundedInventoryBufferDoesNotGrowPastLimit(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if count, err := buffer.Write([]byte("123456")); err != nil || count != 6 {
		t.Fatalf("bounded write = %d, %v", count, err)
	}
	if string(buffer.data) != "1234" || !buffer.overflow {
		t.Fatalf("bounded buffer = %#v", buffer)
	}
}

func TestNativeCollectorDoesNotExposeRunnerErrors(t *testing.T) {
	secret := `C:\private\provider.conf`
	_, err := (NativeCollector{Runner: &fakeSnapshotRunner{err: errors.New(secret)}}).Collect(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("runner error was not safely wrapped: %v", err)
	}
}

func TestDetectAdapterKind(t *testing.T) {
	if got := DetectAdapterKind("redlink", "AmneziaWG tunnel"); got != AdapterRedShield {
		t.Fatalf("redlink kind = %q", got)
	}
	if got := DetectAdapterKind("Ethernet 2", "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter"); got != AdapterCisco {
		t.Fatalf("Cisco kind = %q", got)
	}
	if got := DetectAdapterKind("Loopback", "Software Loopback Interface"); got != AdapterLoopback {
		t.Fatalf("loopback kind = %q", got)
	}
}

func assertAdapter(t *testing.T, adapters []Adapter, index int, kind AdapterKind, guid string, up bool) Adapter {
	t.Helper()
	for _, adapter := range adapters {
		if adapter.Index == index {
			if adapter.Kind != kind || adapter.InterfaceGUID != guid || adapter.Up != up {
				t.Fatalf("adapter %d = %#v", index, adapter)
			}
			return adapter
		}
	}
	t.Fatalf("missing adapter %d", index)
	return Adapter{}
}

func findRoute(t *testing.T, routes []Route, destination string, interfaceIndex int) Route {
	t.Helper()
	for _, route := range routes {
		if route.Destination == destination && route.InterfaceIndex == interfaceIndex {
			return route
		}
	}
	t.Fatalf("missing route %s on %d", destination, interfaceIndex)
	return Route{}
}

func validSnapshotJSON() []byte {
	return []byte(`{
"adapters":[
  {"name":"Ethernet","description":"Intel Ethernet Controller","interfaceIndex":12,"interfaceGuid":"` + testPhysicalGUID + `","hardwareInterface":true,"adminStatus":1,"operationalStatus":1},
  {"name":"redlink","description":"AmneziaWG Tunnel","interfaceIndex":21,"interfaceGuid":"` + testRedShieldGUID + `","hardwareInterface":false,"adminStatus":1,"operationalStatus":1},
  {"name":"Cisco Secure Client","description":"Cisco AnyConnect Virtual Adapter","interfaceIndex":31,"interfaceGuid":"` + testCiscoGUID + `","hardwareInterface":false,"adminStatus":1,"operationalStatus":1}
],
"addresses":[
  {"interfaceIndex":12,"addressFamily":2,"ipAddress":"192.168.1.10","prefixLength":24,"addressState":4,"skipAsSource":false},
  {"interfaceIndex":12,"addressFamily":23,"ipAddress":"2001:db8:1::10","prefixLength":64,"addressState":1,"skipAsSource":false},
  {"interfaceIndex":21,"addressFamily":2,"ipAddress":"10.20.30.2","prefixLength":32,"addressState":4,"skipAsSource":false},
  {"interfaceIndex":21,"addressFamily":23,"ipAddress":"fd00::2","prefixLength":128,"addressState":3,"skipAsSource":false},
  {"interfaceIndex":1,"addressFamily":2,"ipAddress":"127.0.0.1","prefixLength":8,"addressState":4,"skipAsSource":false}
],
"routes":[` + validRoutesJSON() + `],
"dnsServers":[
  {"interfaceIndex":12,"addressFamily":2,"serverAddresses":["8.8.8.8","1.1.1.1"]},
  {"interfaceIndex":1,"addressFamily":23,"serverAddresses":["::1"]}
],
"nrptRuleCount":2
}`)
}

func validRoutesJSON() string {
	return `
  {"interfaceIndex":12,"addressFamily":2,"destinationPrefix":"0.0.0.0/0","nextHop":"192.168.1.1","routeMetric":5,"interfaceMetric":25,"state":0},
  {"interfaceIndex":12,"addressFamily":2,"destinationPrefix":"203.0.113.5/32","nextHop":"192.168.1.1","routeMetric":2,"interfaceMetric":25,"state":0},
  {"interfaceIndex":21,"addressFamily":2,"destinationPrefix":"0.0.0.0/1","nextHop":"0.0.0.0","routeMetric":0,"interfaceMetric":5,"state":0},
  {"interfaceIndex":31,"addressFamily":2,"destinationPrefix":"10.50.0.0/16","nextHop":"0.0.0.0","routeMetric":1,"interfaceMetric":1,"state":0},
  {"interfaceIndex":1,"addressFamily":2,"destinationPrefix":"127.0.0.0/8","nextHop":"0.0.0.0","routeMetric":0,"interfaceMetric":75,"state":0}
`
}
