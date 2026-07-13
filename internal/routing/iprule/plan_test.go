package iprule

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestRenderParityTerminalRoutesAndCollisions(t *testing.T) {
	route := mustServerRoute(t, "nl", 1)
	plan := contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}}
	got, err := Render(plan, Inventory{Servers: []Server{{Route: route}}})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "-4", "route", "replace", "table", "10001", "blackhole", "default"},
		{"ip", "-4", "rule", "add", "priority", "10001", "fwmark", "0x1000000/0xff000000", "lookup", "10001"},
		{"ip", "-6", "route", "replace", "table", "10001", "blackhole", "default"},
		{"ip", "-6", "rule", "add", "priority", "10001", "fwmark", "0x1000000/0xff000000", "lookup", "10001"},
	}
	if !reflect.DeepEqual(artifact.Commands, want) {
		t.Fatalf("commands = %#v, want %#v", artifact.Commands, want)
	}
	_, err = Render(plan, Inventory{Servers: []Server{{Route: route}}, OwnedTables: map[uint32]string{10001: "pbr"}})
	if err == nil {
		t.Fatal("expected table collision")
	}
}

func TestRenderAvailableServerUsesValidatedInterfaceArgument(t *testing.T) {
	route := mustServerRoute(t, "nl", 1)
	got, err := Render(
		contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}},
		Inventory{Servers: []Server{{Route: route, Interface: "wg-nl_1", Available: true}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(artifact.Commands[0], []string{"ip", "-4", "route", "replace", "table", "10001", "default", "dev", "wg-nl_1"}) {
		t.Fatalf("route command = %#v", artifact.Commands[0])
	}
	for _, invalid := range []string{"-help", "wg0;reboot", "interface-name-too-long"} {
		_, err := Render(
			contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}},
			Inventory{Servers: []Server{{Route: route, Interface: invalid, Available: true}}},
		)
		if err == nil {
			t.Fatalf("expected invalid interface %q to fail", invalid)
		}
	}
}

func TestParseRejectsNonCanonicalOrTamperedCommands(t *testing.T) {
	for _, data := range []string{
		`{"version":1,"commands":[["sh","-c","reboot"]]}`,
		`{"version":1,"commands":[["ip","-4","route","replace","table","10001","default","dev","-help"]]}`,
		`{"version":1,"commands":[["ip","-4","rule","replace","priority","10001","fwmark","0x1000000/0xff000000","lookup","10001"]]}`,
		`{"version":1,"commands":[["ip","-4","rule","add","priority","10001","fwmark","0x1000000/0xffffffff","lookup","10001"]]}`,
		`{"version":2,"commands":[]}`,
		`{"version":1,"commands":[],"unexpected":true}`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("Parse(%s) error = nil", data)
		}
	}
}

func TestRenderIsStable(t *testing.T) {
	a := mustServerRoute(t, "a", 1)
	b := mustServerRoute(t, "b", 2)
	one, err := Render(
		contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{b, a}},
		Inventory{Servers: []Server{{Route: b}, {Route: a}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(
		contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{a, b}},
		Inventory{Servers: []Server{{Route: a}, {Route: b}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatalf("unstable output\n%s\n%s", one, two)
	}
}

func TestRenderRejectsInventoryRouteMismatch(t *testing.T) {
	route := mustServerRoute(t, "nl", 1)
	mismatch := route
	mismatch.Table++
	_, err := Render(
		contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}},
		Inventory{Servers: []Server{{Route: mismatch}}},
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Render() error = %v, want inventory mismatch", err)
	}
}

func mustServerRoute(t *testing.T, id string, slot uint8) contracts.ServerRoute {
	t.Helper()
	route, err := contracts.ServerRouteForSlot(id, slot)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
