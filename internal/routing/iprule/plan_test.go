package iprule

import (
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderParityTerminalRoutesAndCollisions(t *testing.T) {
	route, _ := contracts.ServerRouteForSlot("nl", 1)
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}}
	got, err := Render(plan, Inventory{Servers: []Server{{Route: route}}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"ip -4 rule", "ip -6 rule", "ip -4 route replace table 10001 blackhole default", "ip -6 route replace table 10001 blackhole default"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	_, err = Render(plan, Inventory{Servers: []Server{{Route: route}}, OwnedTables: map[uint32]string{10001: "pbr"}})
	if err == nil {
		t.Fatal("expected table collision")
	}
}

func TestRenderIsStable(t *testing.T) {
	a, _ := contracts.ServerRouteForSlot("a", 1)
	b, _ := contracts.ServerRouteForSlot("b", 2)
	one, _ := Render(contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{b, a}}, Inventory{Servers: []Server{{Route: b}, {Route: a}}})
	two, _ := Render(contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{a, b}}, Inventory{Servers: []Server{{Route: a}, {Route: b}}})
	if string(one) != string(two) {
		t.Fatalf("unstable output\n%s\n%s", one, two)
	}
}
