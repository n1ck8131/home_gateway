package windows

import (
	"net"
	"testing"
)

func TestParseRoutePrintMapsIPv4AndIPv6Interfaces(t *testing.T) {
	adapters := []Adapter{
		{Name: "Ethernet", Index: 7, Addresses: []string{"192.168.50.10/24"}},
		{Name: "redlink", Index: 12, Addresses: []string{"10.0.0.2/32"}},
	}
	ipv4 := []byte(`
          0.0.0.0          0.0.0.0     192.168.50.1    192.168.50.10     25
        10.0.0.2  255.255.255.255         On-link          10.0.0.2    256
      203.0.113.5  255.255.255.255         10.0.0.1          10.0.0.2      1
`)
	ipv6 := []byte(`
 If Metric Network Destination      Gateway
  7    25 ::/0                     fe80::1
 12     1 2001:db8:abcd::/48       On-link
 12     2 2001:db8:cafe::/48
`)
	routes := ParseRoutePrint(ipv4, ipv6, adapters)

	assertParsedRoute(t, routes, FamilyIPv4, "0.0.0.0/0", 7)
	assertParsedRoute(t, routes, FamilyIPv4, "203.0.113.5/32", 12)
	assertParsedRoute(t, routes, FamilyIPv6, "::/0", 7)
	assertParsedRoute(t, routes, FamilyIPv6, "2001:db8:abcd::/48", 12)
	assertParsedRouteWithNextHop(t, routes, FamilyIPv6, "2001:db8:cafe::/48", 12, "")
}

func assertParsedRouteWithNextHop(t *testing.T, routes []Route, family AddressFamily, destination string, interfaceIndex int, nextHop string) {
	t.Helper()
	for _, route := range routes {
		if route.Family == family && route.Destination == destination && route.InterfaceIndex == interfaceIndex && route.NextHop == nextHop {
			return
		}
	}
	t.Fatalf("missing route %s %s interface %d next-hop %q in %#v", family, destination, interfaceIndex, nextHop, routes)
}

func TestDetectAdapterKindRecognizesRedlinkAndCisco(t *testing.T) {
	if got := DetectAdapterKind("redlink Netherlands", "WireGuard Tunnel", net.FlagUp); got != AdapterRedShield {
		t.Fatalf("redlink kind = %q", got)
	}
	if got := DetectAdapterKind("Ethernet 2", "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64", net.FlagUp); got != AdapterCisco {
		t.Fatalf("Cisco kind = %q", got)
	}
	if got := DetectAdapterKind("Loopback", "Software Loopback Interface", net.FlagLoopback); got != AdapterLoopback {
		t.Fatalf("loopback kind = %q", got)
	}
}

func assertParsedRoute(t *testing.T, routes []Route, family AddressFamily, destination string, interfaceIndex int) {
	t.Helper()
	for _, route := range routes {
		if route.Family == family && route.Destination == destination && route.InterfaceIndex == interfaceIndex {
			return
		}
	}
	t.Fatalf("missing route %s %s interface %d in %#v", family, destination, interfaceIndex, routes)
}
