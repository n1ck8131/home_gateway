package openwrt

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/routing/iprule"
)

func TestBuildOperationPlanOrdersEndpointRouteBeforeUCIAndIfup(t *testing.T) {
	plan, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	got := make([][]string, len(plan.Operations))
	for index, operation := range plan.Operations {
		got[index] = operation.Argv()
	}
	wantPrefix := [][]string{
		{"ip", "-4", "route", "replace", "table", "main", "9.9.9.9/32", "via", "9.9.9.1", "dev", "wan"},
		{"uci", "set", "network.awg0=interface"},
		{"uci", "-q", "delete", "network.awg0.private_key"},
		{"uci", "-q", "delete", "network.awg0.fwmark"},
		{"uci", "-q", "delete", "network.awg0.addresses"},
		{"uci", "set", "network.awg0.proto=amneziawg"},
		{"uci", "set", "network.awg0.private_key_file=/etc/routerd/secrets/routerd-openwrt-peer-private-key_primary.key"},
		{"uci", "set", "network.awg0.nohostroute=1"},
	}
	for index, want := range wantPrefix {
		if !reflect.DeepEqual(got[index], want) {
			t.Fatalf("operation %d = %#v, want %#v", index, got[index], want)
		}
	}
	assertContainsArgv(t, got, []string{"uci", "set", "network.awg0.awg_s3=56"})
	assertContainsArgv(t, got, []string{"uci", "set", "network.awg0.awg_i5=<b 0x0102>"})
	assertContainsArgv(t, got, []string{"uci", "set", "network.awg0_peer=amneziawg_awg0"})
	assertContainsArgv(t, got, []string{"uci", "-q", "delete", "network.awg0.private_key"})
	assertContainsArgv(t, got, []string{"uci", "-q", "delete", "network.awg0.fwmark"})
	assertContainsArgv(t, got, []string{"uci", "-q", "delete", "network.awg0_peer.preshared_key"})
	assertContainsArgv(t, got, []string{"uci", "-q", "delete", "network.awg0_peer.persistent_keepalive"})
	if got[len(got)-2][0] != "uci" || got[len(got)-1][0] != "ifup" {
		t.Fatalf("last operations = %#v", got[len(got)-2:])
	}
}

func TestOperationPlanRejectsAWGFWMarkAndMainDefaultRouteChanges(t *testing.T) {
	plan, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range plan.Operations {
		argv := operation.Argv()
		if slices.Contains(argv, "fwmark") || strings.Contains(strings.Join(argv, "\x00"), ".fwmark=") {
			t.Fatalf("operation contains fwmark: %#v", argv)
		}
		if len(argv) >= 7 && argv[0] == "ip" && argv[3] == "replace" && argv[5] == "main" && argv[6] == "default" {
			t.Fatalf("operation changes main default route: %#v", argv)
		}
	}
	for _, mutate := range []func(OperationPlan) OperationPlan{
		func(plan OperationPlan) OperationPlan { plan.Operations[0].Args[5] = "default"; return plan },
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0=interface", "network.awg0=wireguard")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.proto=amneziawg", "network.awg0.proto=wireguard")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.private_key_file=/etc/routerd/secrets/routerd-openwrt-peer-private-key_primary.key", "network.awg0.private_key_file=/etc/passwd")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.nohostroute=1", "network.awg0.nohostroute=0")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.routerd_digest="+plan.Digest, "network.awg0.routerd_digest=00")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.awg_jmax=50", "network.awg0.awg_jmax=0")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0.awg_i1=<r 2>", "network.awg0.awg_i1=<r\n2>")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "network.awg0_peer.public_key=bad")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.endpoint_host=9.9.9.9", "network.awg0_peer.endpoint_host=10.0.0.1")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.endpoint_port=51820", "network.awg0_peer.endpoint_port=0")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.route_allowed_ips=0", "network.awg0_peer.route_allowed_ips=1")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.allowed_ips=0.0.0.0/0", "network.awg0_peer.allowed_ips=10.0.0.0/8")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0=interface", "network.awg0.fwmark=0x1")
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "network.awg0_peer.awg_jc=4")
		},
		func(plan OperationPlan) OperationPlan {
			plan.Operations = append(plan.Operations[:1], append([]Operation{{Name: "extra-endpoint", Program: "ip", Args: append([]string(nil), plan.Operations[0].Args...)}}, plan.Operations[1:]...)...)
			return plan
		},
		func(plan OperationPlan) OperationPlan {
			return replaceOperationArg(t, plan, "network.awg0_peer.endpoint_host=9.9.9.9", "network.awg0_peer.endpoint_host=8.8.8.8")
		},
		func(plan OperationPlan) OperationPlan {
			return moveOperationAfterArg(t, plan, "network.awg0.addresses", "network.awg0.addresses=10.71.0.2/32")
		},
		func(plan OperationPlan) OperationPlan {
			return moveOperationAfterArg(t, plan, "network.awg0.private_key", "network.awg0.private_key_file=/etc/routerd/secrets/routerd-openwrt-peer-private-key_primary.key")
		},
		func(plan OperationPlan) OperationPlan {
			return moveOperationAfterArg(t, plan, "network.awg0_peer.allowed_ips", "network.awg0_peer.allowed_ips=0.0.0.0/0")
		},
	} {
		bad := mutate(clonePlan(plan))
		if err := bad.Validate(); err == nil {
			t.Fatalf("Validate() accepted tampered plan: %#v", bad)
		}
	}
}

func TestOperationPlanRequiresStaleSecretAndMarkCleanup(t *testing.T) {
	plan, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"network.awg0.private_key",
		"network.awg0.fwmark",
		"network.awg0_peer.preshared_key",
		"network.awg0_peer.persistent_keepalive",
	} {
		t.Run(target, func(t *testing.T) {
			bad := removeOperationWithArg(t, clonePlan(plan), target)
			if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "delete stale option") {
				t.Fatalf("Validate() error = %v, want stale-option cleanup gate", err)
			}
		})
	}
}

func TestOperationPlanIsDeterministicStrictJSON(t *testing.T) {
	first, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("unstable JSON\n%s\n%s", firstJSON, secondJSON)
	}
	decoded, err := ParseOperationPlan(firstJSON)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Digest != first.Digest {
		t.Fatalf("digest = %q, want %q", decoded.Digest, first.Digest)
	}
	var withUnknown map[string]any
	if err := json.Unmarshal(firstJSON, &withUnknown); err != nil {
		t.Fatal(err)
	}
	withUnknown["unexpected"] = true
	data, err := json.Marshal(withUnknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOperationPlan(data); err == nil {
		t.Fatal("ParseOperationPlan() accepted unknown field")
	}
}

func TestRenderIPRuleArtifactKeepsFailedTunnelBlackholedAndHealthyTunnelAvailable(t *testing.T) {
	spec := mustPeerSpec(t)
	failed, err := RenderIPRuleArtifact(spec, false)
	if err != nil {
		t.Fatal(err)
	}
	failedArtifact, err := iprule.Parse(failed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(failedArtifact.Commands[0], []string{"ip", "-4", "route", "replace", "table", "10001", "blackhole", "default"}) {
		t.Fatalf("failed route = %#v", failedArtifact.Commands[0])
	}
	healthy, err := RenderIPRuleArtifact(spec, true)
	if err != nil {
		t.Fatal(err)
	}
	healthyArtifact, err := iprule.Parse(healthy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(healthyArtifact.Commands[0], []string{"ip", "-4", "route", "replace", "table", "10001", "default", "dev", "awg0"}) {
		t.Fatalf("healthy route = %#v", healthyArtifact.Commands[0])
	}
}

func assertContainsArgv(t *testing.T, got [][]string, want []string) {
	t.Helper()
	for _, argv := range got {
		if reflect.DeepEqual(argv, want) {
			return
		}
	}
	t.Fatalf("missing argv %#v in %#v", want, got)
}

func clonePlan(plan OperationPlan) OperationPlan {
	clone := OperationPlan{Version: plan.Version, Digest: plan.Digest, Operations: make([]Operation, len(plan.Operations))}
	for index, operation := range plan.Operations {
		clone.Operations[index] = Operation{
			Name:    operation.Name,
			Program: operation.Program,
			Args:    append([]string(nil), operation.Args...),
		}
	}
	return clone
}

func replaceOperationArg(t *testing.T, plan OperationPlan, old, replacement string) OperationPlan {
	t.Helper()
	for operationIndex := range plan.Operations {
		for argIndex := range plan.Operations[operationIndex].Args {
			if plan.Operations[operationIndex].Args[argIndex] == old {
				plan.Operations[operationIndex].Args[argIndex] = replacement
				return plan
			}
		}
	}
	t.Fatalf("missing operation arg %q", old)
	return plan
}

func removeOperationWithArg(t *testing.T, plan OperationPlan, target string) OperationPlan {
	t.Helper()
	for index, operation := range plan.Operations {
		if slices.Contains(operation.Args, target) {
			plan.Operations = append(plan.Operations[:index], plan.Operations[index+1:]...)
			return plan
		}
	}
	t.Fatalf("missing operation arg %q", target)
	return plan
}

func moveOperationAfterArg(t *testing.T, plan OperationPlan, movingArg, afterArg string) OperationPlan {
	t.Helper()
	movingIndex := operationIndexWithArg(t, plan, movingArg)
	operation := plan.Operations[movingIndex]
	plan.Operations = append(plan.Operations[:movingIndex], plan.Operations[movingIndex+1:]...)
	afterIndex := operationIndexWithArg(t, plan, afterArg)
	next := afterIndex + 1
	plan.Operations = append(plan.Operations[:next], append([]Operation{operation}, plan.Operations[next:]...)...)
	return plan
}

func operationIndexWithArg(t *testing.T, plan OperationPlan, target string) int {
	t.Helper()
	for index, operation := range plan.Operations {
		if slices.Contains(operation.Args, target) {
			return index
		}
	}
	t.Fatalf("missing operation arg %q", target)
	return -1
}
