package windows

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func ParseRoutePrint(ipv4Output, ipv6Output []byte, adapters []Adapter) []Route {
	routes := parseIPv4RoutePrint(string(ipv4Output), adapters)
	routes = append(routes, parseIPv6RoutePrint(string(ipv6Output))...)

	seen := make(map[Route]struct{}, len(routes))
	unique := routes[:0]
	for _, route := range routes {
		if _, duplicate := seen[route]; duplicate {
			continue
		}
		seen[route] = struct{}{}
		unique = append(unique, route)
	}
	sort.Slice(unique, func(left, right int) bool {
		if unique[left].Family != unique[right].Family {
			return unique[left].Family < unique[right].Family
		}
		if unique[left].Destination != unique[right].Destination {
			return unique[left].Destination < unique[right].Destination
		}
		if unique[left].Metric != unique[right].Metric {
			return unique[left].Metric < unique[right].Metric
		}
		return unique[left].InterfaceIndex < unique[right].InterfaceIndex
	})
	return unique
}

func parseIPv4RoutePrint(output string, adapters []Adapter) []Route {
	var routes []Route
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		destination, destinationErr := netip.ParseAddr(fields[0])
		mask := net.ParseIP(fields[1])
		interfaceAddress, interfaceErr := netip.ParseAddr(fields[3])
		metric, metricErr := strconv.Atoi(fields[4])
		if destinationErr != nil || !destination.Is4() || mask == nil || interfaceErr != nil || !interfaceAddress.Is4() || metricErr != nil || metric < 0 {
			continue
		}
		ones, bits := net.IPMask(mask.To4()).Size()
		if bits != 32 || ones < 0 {
			continue
		}
		prefix := netip.PrefixFrom(destination, ones).Masked()
		nextHop := ""
		if parsed, err := netip.ParseAddr(fields[2]); err == nil && parsed.Is4() {
			nextHop = parsed.String()
		}
		route := Route{
			Family:           FamilyIPv4,
			Destination:      prefix.String(),
			NextHop:          nextHop,
			InterfaceAddress: interfaceAddress.String(),
			Metric:           metric,
		}
		for _, adapter := range adapters {
			if routeUsesAdapter(route, adapter) {
				route.InterfaceIndex = adapter.Index
				break
			}
		}
		routes = append(routes, route)
	}
	return routes
}

func parseIPv6RoutePrint(output string) []Route {
	var routes []Route
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		interfaceIndex, indexErr := strconv.Atoi(fields[0])
		metric, metricErr := strconv.Atoi(fields[1])
		prefix, prefixErr := netip.ParsePrefix(fields[2])
		if indexErr != nil || interfaceIndex <= 0 || metricErr != nil || metric < 0 || prefixErr != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			continue
		}
		nextHop := ""
		if len(fields) >= 4 {
			if parsed, err := netip.ParseAddr(fields[3]); err == nil && parsed.Is6() && !parsed.Is4In6() {
				nextHop = parsed.String()
			}
		}
		routes = append(routes, Route{
			Family:         FamilyIPv6,
			Destination:    prefix.Masked().String(),
			NextHop:        nextHop,
			InterfaceIndex: interfaceIndex,
			Metric:         metric,
		})
	}
	return routes
}
