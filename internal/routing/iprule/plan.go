package iprule

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

type Server struct {
	Route     contracts.ServerRoute
	Interface string
	Available bool
}

type Inventory struct {
	Servers     []Server
	OwnedMarks  map[uint32]string
	OwnedTables map[uint32]string
}

func Render(plan contracts.PolicyPlan, inventory Inventory) ([]byte, error) {
	byID := make(map[string]Server, len(inventory.Servers))
	for _, server := range inventory.Servers {
		byID[server.Route.ServerID] = server
	}
	routes := append([]contracts.ServerRoute(nil), plan.ServerRoutes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Table < routes[j].Table })
	var output strings.Builder
	for _, route := range routes {
		if owner := inventory.OwnedMarks[route.Mark]; owner != "" && owner != "routerd" {
			return nil, fmt.Errorf("mark %#x is owned by %s", route.Mark, owner)
		}
		if owner := inventory.OwnedTables[route.Table]; owner != "" && owner != "routerd" {
			return nil, fmt.Errorf("routing table %d is owned by %s", route.Table, owner)
		}
		server, ok := byID[route.ServerID]
		if !ok {
			return nil, fmt.Errorf("missing runtime inventory for server %q", route.ServerID)
		}
		fmt.Fprintf(&output, "ip -4 rule replace priority %d fwmark %#x/%#x lookup %d\n", route.Table, route.Mark, contracts.RouterdMarkMask, route.Table)
		fmt.Fprintf(&output, "ip -6 rule replace priority %d fwmark %#x/%#x lookup %d\n", route.Table, route.Mark, contracts.RouterdMarkMask, route.Table)
		if server.Available && server.Interface != "" {
			fmt.Fprintf(&output, "ip -4 route replace table %d default dev %s\n", route.Table, server.Interface)
			fmt.Fprintf(&output, "ip -6 route replace table %d default dev %s\n", route.Table, server.Interface)
		} else {
			fmt.Fprintf(&output, "ip -4 route replace table %d blackhole default\n", route.Table)
			fmt.Fprintf(&output, "ip -6 route replace table %d blackhole default\n", route.Table)
		}
	}
	return []byte(output.String()), nil
}
