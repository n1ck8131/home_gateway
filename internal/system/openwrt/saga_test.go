package openwrt

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeRuntime struct {
	failName        string
	failPolicyIndex int
	status          TunnelStatus
	snapshot        UCISnapshot
	calls           []string
	argv            [][]string
	policies        []PolicyState
	checks          []TunnelCheck
	restores        []UCISnapshot
}

func (runtime *fakeRuntime) ApplyPolicy(_ context.Context, state PolicyState) error {
	runtime.calls = append(runtime.calls, "policy")
	runtime.policies = append(runtime.policies, state)
	if runtime.failPolicyIndex != 0 && len(runtime.policies) == runtime.failPolicyIndex {
		return errors.New("policy failed")
	}
	return nil
}

func (runtime *fakeRuntime) Snapshot(_ context.Context, request SnapshotRequest) (UCISnapshot, error) {
	runtime.calls = append(runtime.calls, "snapshot")
	if runtime.snapshot.Interface == "" {
		runtime.snapshot = UCISnapshot{Interface: request.Interface, Peer: request.Peer, RecoveryID: "snapshot-1"}
	}
	return runtime.snapshot, nil
}

func (runtime *fakeRuntime) Run(_ context.Context, operation Operation) error {
	runtime.calls = append(runtime.calls, operation.Name)
	runtime.argv = append(runtime.argv, operation.Argv())
	if operation.Name == runtime.failName {
		return errors.New("failed")
	}
	return nil
}

func (runtime *fakeRuntime) Restore(_ context.Context, snapshot UCISnapshot) error {
	runtime.calls = append(runtime.calls, "restore")
	runtime.restores = append(runtime.restores, snapshot)
	return nil
}

func (runtime *fakeRuntime) CheckTunnel(_ context.Context, check TunnelCheck) (TunnelStatus, error) {
	runtime.calls = append(runtime.calls, "health")
	runtime.checks = append(runtime.checks, check)
	return runtime.status, nil
}

func TestApplyPeerPublishesFailClosedBeforeEndpointRouteAndHealthyAfterStructuredHealth(t *testing.T) {
	spec := mustPeerSpec(t)
	runtime := &fakeRuntime{status: healthyStatus()}
	result, err := ApplyPeer(context.Background(), spec, time.Unix(100, 0).UTC(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ServerAvailable {
		t.Fatal("healthy apply did not publish available result")
	}
	if len(runtime.policies) != 2 || runtime.policies[0].ServerAvailable || !runtime.policies[1].ServerAvailable {
		t.Fatalf("policies = %+v", runtime.policies)
	}
	if runtime.policies[0].DesiredState.Entries[0].Origin == "" || runtime.policies[0].DesiredState.Entries[0].Pattern != "9.9.9.9/32" {
		t.Fatalf("fail-closed policy missing system-direct endpoint: %+v", runtime.policies[0].DesiredState)
	}
	if runtime.calls[0] != "policy" || runtime.calls[1] != "snapshot" || runtime.calls[2] != "preserve-endpoint-host-route" {
		t.Fatalf("calls = %v", runtime.calls[:3])
	}
	if !reflect.DeepEqual(runtime.argv[0], []string{"ip", "-4", "route", "replace", "table", "main", "9.9.9.9/32", "via", "9.9.9.1", "dev", "wan"}) {
		t.Fatalf("first operation = %#v", runtime.argv[0])
	}
}

func TestApplyPeerRestoresPriorUCIAndRepublishesFailClosedOnFailure(t *testing.T) {
	snapshot := UCISnapshot{Interface: "awg0", Peer: "awg0_peer", CurrentDigest: "previous", RecoveryID: "snapshot-previous"}
	runtime := &fakeRuntime{failName: "ifup-peer", status: healthyStatus(), snapshot: snapshot}
	result, err := ApplyPeer(context.Background(), mustPeerSpec(t), time.Unix(100, 0).UTC(), runtime)
	if err == nil {
		t.Fatal("ApplyPeer() error = nil, want failure")
	}
	if result.ServerAvailable {
		t.Fatal("failed apply marked server available")
	}
	if len(runtime.restores) != 1 || runtime.restores[0] != snapshot {
		t.Fatalf("restores = %+v", runtime.restores)
	}
	if len(runtime.policies) < 2 || runtime.policies[len(runtime.policies)-1].ServerAvailable {
		t.Fatalf("fail-closed was not republished: %+v", runtime.policies)
	}
	for _, argv := range runtime.argv[1:] {
		if len(argv) > 0 && argv[0] == "ip" {
			t.Fatalf("endpoint route was compensated or replayed after failure: %#v", runtime.argv)
		}
	}
}

func TestApplyPeerSameSpecReplaysUCIPlanCleanupBeforeAvailability(t *testing.T) {
	plan, err := BuildOperationPlan(mustPeerSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{status: healthyStatus(), snapshot: UCISnapshot{Interface: "awg0", Peer: "awg0_peer", CurrentDigest: plan.Digest, RecoveryID: "snapshot-current"}}
	result, err := ApplyPeer(context.Background(), mustPeerSpec(t), time.Unix(100, 0).UTC(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ServerAvailable || len(runtime.argv) != len(plan.Operations) {
		t.Fatalf("same-spec result=%+v argv=%#v", result, runtime.argv)
	}
	if len(runtime.policies) != 2 || runtime.policies[0].ServerAvailable || !runtime.policies[1].ServerAvailable {
		t.Fatalf("policies = %+v", runtime.policies)
	}
	privateKeyDelete := argvIndex(t, runtime.argv, []string{"uci", "-q", "delete", "network.awg0.private_key"})
	addressDelete := argvIndex(t, runtime.argv, []string{"uci", "-q", "delete", "network.awg0.addresses"})
	addressWrite := argvIndex(t, runtime.argv, []string{"uci", "add_list", "network.awg0.addresses=10.71.0.2/32"})
	healthCall := callIndex(t, runtime.calls, "health")
	availablePolicyCall := lastCallIndex(t, runtime.calls, "policy")
	if privateKeyDelete == -1 || addressDelete == -1 || addressWrite == -1 || !(addressDelete < addressWrite) {
		t.Fatalf("cleanup ordering argv=%#v", runtime.argv)
	}
	if healthCall == -1 || availablePolicyCall == -1 || !(privateKeyDelete < healthCall && addressDelete < healthCall && healthCall < availablePolicyCall) {
		t.Fatalf("calls=%v argv=%#v", runtime.calls, runtime.argv)
	}
}

func TestApplyPeerRequiresStructuredTunnelHealthBeforeAvailable(t *testing.T) {
	tests := []struct {
		name   string
		status TunnelStatus
	}{
		{name: "interface down", status: func() TunnelStatus { s := healthyStatus(); s.InterfaceUp = false; return s }()},
		{name: "no handshake", status: func() TunnelStatus { s := healthyStatus(); s.HandshakeObserved = false; return s }()},
		{name: "stale handshake", status: func() TunnelStatus {
			s := healthyStatus()
			s.LatestHandshakeAge = MaxTunnelHandshakeAge + time.Second
			return s
		}()},
		{name: "one successful probe", status: func() TunnelStatus { s := healthyStatus(); s.ConsecutiveSuccess = 1; return s }()},
		{name: "dns failed", status: func() TunnelStatus { s := healthyStatus(); s.DNSOK = false; return s }()},
		{name: "tls failed", status: func() TunnelStatus { s := healthyStatus(); s.TLSOK = false; return s }()},
		{name: "egress equals wan", status: func() TunnelStatus { s := healthyStatus(); s.TunnelEgressIP = s.WANEgressIP; return s }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{status: test.status}
			result, err := ApplyPeer(context.Background(), mustPeerSpec(t), time.Unix(100, 0).UTC(), runtime)
			if err == nil {
				t.Fatal("ApplyPeer() error = nil, want failed health")
			}
			if result.ServerAvailable || result.IPRuleInventory.Servers[0].Available {
				t.Fatalf("failed health result = %+v", result)
			}
			if len(runtime.policies) < 2 || runtime.policies[len(runtime.policies)-1].ServerAvailable {
				t.Fatalf("fail-closed was not retained: %+v", runtime.policies)
			}
		})
	}
}

func healthyStatus() TunnelStatus {
	return TunnelStatus{
		InterfaceUp:        true,
		HandshakeObserved:  true,
		LatestHandshakeAge: time.Minute,
		ConsecutiveSuccess: 2,
		DNSOK:              true,
		TLSOK:              true,
		TunnelEgressIP:     "9.9.9.9",
		WANEgressIP:        "1.1.1.1",
	}
}

func argvIndex(t *testing.T, argv [][]string, want []string) int {
	t.Helper()
	for index, got := range argv {
		if reflect.DeepEqual(got, want) {
			return index
		}
	}
	return -1
}

func callIndex(t *testing.T, calls []string, want string) int {
	t.Helper()
	for index, got := range calls {
		if got == want {
			return index
		}
	}
	return -1
}

func lastCallIndex(t *testing.T, calls []string, want string) int {
	t.Helper()
	for index := len(calls) - 1; index >= 0; index-- {
		if calls[index] == want {
			return index
		}
	}
	return -1
}
