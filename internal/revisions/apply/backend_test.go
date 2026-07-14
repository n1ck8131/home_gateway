package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/system/linux"
)

type runnerCall struct {
	program string
	args    []string
}

type recordingRunner struct {
	calls       []runnerCall
	fw4Output   []byte
	outputs     map[string][]byte
	failProgram string
	beforeRun   func(string, []string) error
}

func (runner *recordingRunner) Run(_ context.Context, program string, args ...string) (linux.Result, error) {
	clonedArgs := append([]string(nil), args...)
	runner.calls = append(runner.calls, runnerCall{program: program, args: clonedArgs})
	if runner.beforeRun != nil {
		if err := runner.beforeRun(program, clonedArgs); err != nil {
			return linux.Result{}, err
		}
	}
	if runner.failProgram == program {
		return linux.Result{}, errors.New(program + " failed")
	}
	if output, exists := runner.outputs[commandKey(program, args)]; exists {
		return linux.Result{Stdout: append([]byte(nil), output...)}, nil
	}
	if program == "fw4" && reflect.DeepEqual(args, []string{"print"}) {
		return linux.Result{Stdout: append([]byte(nil), runner.fw4Output...)}, nil
	}
	return linux.Result{}, nil
}

func TestLinuxRuntimePostCheckRequiresExpectedNFTPolicyRulesAndRoutes(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.outputs = map[string][]byte{
		"nft list table inet routerd":  candidate.NFT,
		"ip -4 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -6 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -4 route show table 10001": []byte("blackhole default\n"),
		"ip -6 route show table 10001": []byte("blackhole default\n"),
	}
	if err := runtime.PostCheck(context.Background()); err != nil {
		t.Fatal(err)
	}

	runner.outputs["nft list table inet routerd"] = []byte(strings.Replace(string(candidate.NFT), "managed-by-routerd", "foreign", 1))
	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "ownership marker") {
		t.Fatalf("PostCheck() error = %v, want invalid ownership marker", err)
	}
	runner.outputs["nft list table inet routerd"] = candidate.NFT

	runner.outputs["nft list table inet routerd"] = []byte(strings.Replace(string(candidate.NFT), "    ct direction reply return\n", "", 1))
	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "ordered rules") {
		t.Fatalf("PostCheck() error = %v, want missing nft rule", err)
	}
	runner.outputs["nft list table inet routerd"] = candidate.NFT

	runner.outputs["ip -6 route show table 10001"] = nil
	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "route table 10001") {
		t.Fatalf("PostCheck() error = %v, want missing route", err)
	}
}

func TestLinuxRuntimePostCheckRejectsUnhookedPreroutingChain(t *testing.T) {
	runtime, runner := activeTestLinuxRuntime(t, testCandidate("revision-1"))
	candidate := testCandidate("revision-1")
	runner.outputs["nft list table inet routerd"] = []byte(strings.Replace(
		string(candidate.NFT),
		"    type filter hook prerouting priority mangle; policy accept;\n",
		"",
		1,
	))

	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "prerouting chain metadata") {
		t.Fatalf("PostCheck() error = %v, want unhooked prerouting rejection", err)
	}
}

func TestLinuxRuntimePostCheckRejectsRuleOutsidePrerouting(t *testing.T) {
	candidate := testCandidate("revision-1")
	runtime, runner := activeTestLinuxRuntime(t, candidate)
	listed := strings.Replace(string(candidate.NFT), "    ct direction reply return\n", "", 1)
	listed = strings.Replace(listed, "  chain prerouting {", "  chain decoy {\n    ct direction reply return\n  }\n  chain prerouting {", 1)
	runner.outputs["nft list table inet routerd"] = []byte(listed)

	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "ordered rules") {
		t.Fatalf("PostCheck() error = %v, want misplaced rule rejection", err)
	}
}

func TestContainsTokenSequenceNormalizesNFTListFormatting(t *testing.T) {
	expected := nftSemanticTokens("meta mark set (meta mark & 0x00ffffff) | 0x1000000 return;")
	actual := []byte("meta mark set meta mark & 0x00ffffff | 0x01000000 return\n")
	if !containsTokenSequence(actual, expected) {
		t.Fatalf("containsTokenSequence() = false, want normalized semantic match: %v", expected)
	}
}

func TestLinuxRuntimePreflightRejectsUnownedStartupResources(t *testing.T) {
	tests := []struct {
		name   string
		output map[string][]byte
		want   string
	}{
		{
			name: "nft table",
			output: map[string][]byte{
				"nft -j list tables": []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd"}}]}`),
			},
			want: "nft table",
		},
		{
			name: "reserved priority",
			output: map[string][]byte{
				"ip -4 rule show": []byte("10002: from all lookup main\n"),
			},
			want: "priority 10002",
		},
		{
			name: "reserved mark",
			output: map[string][]byte{
				"ip -6 rule show": []byte("5000: from all fwmark 0x2000000/0xff000000 lookup 200\n"),
			},
			want: "mark 0x2000000/0xff000000",
		},
		{
			name: "reserved route table",
			output: map[string][]byte{
				"ip -4 route show table all": []byte("default via 192.0.2.1 dev wan0 table 10003\n"),
			},
			want: "routing table 10003",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, runner := newTestLinuxRuntime(t)
			for command, output := range test.output {
				runner.outputs[command] = output
			}

			err := runtime.Preflight(context.Background(), nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Preflight() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLinuxRuntimePreflightAcceptsOwnedActiveRevision(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.FirewallIncludePath, candidate.NFT, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.DNSIncludePath, candidate.DNS, 0o600); err != nil {
		t.Fatal(err)
	}
	runner.outputs = expectedStartupInventoryOutputs()

	if err := runtime.Preflight(context.Background(), []string{candidate.RevisionID}); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxRuntimePreflightRejectsSpoofedOwnershipMarker(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.outputs["nft -j list tables"] = []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd"}}]}`)
	runner.outputs["nft -j list table inet routerd"] = []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd","comment":"foreign"}}]}`)

	err := runtime.Preflight(context.Background(), []string{candidate.RevisionID})
	if err == nil || !strings.Contains(err.Error(), "ownership marker") {
		t.Fatalf("Preflight() error = %v", err)
	}
}

func TestLinuxRuntimeStagesImmutableRevisionAndValidatesWithoutMutatingIt(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")

	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatalf("idempotent stage: %v", err)
	}
	changed := candidate
	changed.DNS = []byte("server=/changed.example/192.0.2.1\n")
	if err := runtime.Stage(context.Background(), changed); err == nil {
		t.Fatal("expected immutable revision mismatch")
	}

	if err := runtime.Validate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	revisionDirectory := filepath.Join(runtime.Root, "revisions", candidate.RevisionID)
	entries, err := os.ReadDir(revisionDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if got := entryNames(entries); !reflect.DeepEqual(got, artifactNames) {
		t.Fatalf("staged revision entries = %v, want %v", got, artifactNames)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("validation calls = %#v", runner.calls)
	}
	if runner.calls[0].program != "fw4" || !reflect.DeepEqual(runner.calls[0].args, []string{"print"}) {
		t.Fatalf("first validation call = %#v", runner.calls[0])
	}
	if runner.calls[1].program != "nft" || len(runner.calls[1].args) != 3 || !reflect.DeepEqual(runner.calls[1].args[:2], []string{"-c", "-f"}) {
		t.Fatalf("nft validation call = %#v", runner.calls[1])
	}
	if runner.calls[2].program != "dnsmasq" || !strings.HasPrefix(runner.calls[2].args[1], "--conf-file=") {
		t.Fatalf("dns validation call = %#v", runner.calls[2])
	}
}

func TestLinuxRuntimeRejectsFirewallPrintDrift(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	active := testCandidate("active")
	if err := runtime.Stage(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), active); err != nil {
		t.Fatal(err)
	}

	next := testCandidate("next")
	if err := runtime.Stage(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	runner.fw4Output = []byte("table inet fw4 {}\n")
	if err := runtime.Validate(context.Background(), next); err == nil || !strings.Contains(err.Error(), "active firewall include") {
		t.Fatalf("Validate() error = %v, want active include drift", err)
	}
}

func TestLinuxRuntimeActivatesRoutesBeforeIncludesAndRestoresInitialState(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	runner.beforeRun = func(program string, _ []string) error {
		if program != "ip" {
			return nil
		}
		for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("include installed before policy routes")
			}
		}
		return nil
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, runtime.FirewallIncludePath, candidate.NFT)
	assertFileEquals(t, runtime.DNSIncludePath, candidate.DNS)
	if len(runner.calls) != 8 {
		t.Fatalf("route calls = %#v", runner.calls)
	}
	for _, call := range runner.calls {
		if call.program != "ip" || call.args[0] != "-4" && call.args[0] != "-6" {
			t.Fatalf("non-canonical route execution: %#v", call)
		}
	}

	runner.beforeRun = nil
	if err := runtime.Restore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored initial include %s still exists: %v", path, err)
		}
	}
	reloadIndex := -1
	for index := 0; index+1 < len(runner.calls); index++ {
		if runner.calls[index].program == "fw4" && reflect.DeepEqual(runner.calls[index].args, []string{"reload"}) &&
			runner.calls[index+1].program == "/etc/init.d/dnsmasq" && reflect.DeepEqual(runner.calls[index+1].args, []string{"reload"}) {
			reloadIndex = index
			break
		}
	}
	if reloadIndex < 0 {
		t.Fatalf("restore reload calls are missing: %#v", runner.calls)
	}
}

func TestLinuxRuntimeReconcilesPolicyRulesWithoutUnsupportedReplace(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call.program == "ip" && len(call.args) > 2 && call.args[1] == "rule" && call.args[2] == "replace" {
			t.Fatalf("unsupported ip rule replace executed: %#v", call)
		}
	}

	runner.calls = nil
	runner.outputs = expectedKernelRouteOutputs()
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
	for _, call := range runner.calls {
		if call.program == "ip" && len(call.args) > 2 && call.args[1] == "rule" && call.args[2] == "add" {
			t.Fatalf("existing owned policy rule was added twice: %#v", call)
		}
	}
}

func TestLinuxRuntimeReconcilesActiveRevisionAfterReboot(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	runner.calls = nil
	runner.outputs = map[string][]byte{
		"nft list table inet routerd": []byte("table inet routerd {\n comment \"managed-by-routerd\"\n chain prerouting { }\n}\n"),
	}
	runner.beforeRun = func(program string, args []string) error {
		if program == "fw4" && reflect.DeepEqual(args, []string{"reload"}) {
			runner.outputs["nft list table inet routerd"] = candidate.NFT
			return nil
		}
		if program != "ip" || len(args) < 3 {
			return nil
		}
		family := args[0]
		switch {
		case args[1] == "route" && args[2] == "replace":
			runner.outputs[commandKey("ip", []string{family, "route", "show", "table", "10001"})] = []byte("blackhole default\n")
		case args[1] == "rule" && args[2] == "add":
			runner.outputs[commandKey("ip", []string{family, "rule", "show"})] = []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n")
		}
		return nil
	}

	if err := runtime.Reconcile(context.Background(), candidate.RevisionID); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, runtime.FirewallIncludePath, candidate.NFT)
	assertFileEquals(t, runtime.DNSIncludePath, candidate.DNS)

	mutations := 0
	for _, call := range runner.calls {
		if call.program == "ip" && len(call.args) > 2 &&
			(call.args[1] == "route" && call.args[2] == "replace" || call.args[1] == "rule" && call.args[2] == "add") {
			mutations++
		}
	}
	if mutations != 4 {
		t.Fatalf("kernel reconciliation mutations = %d, calls = %#v", mutations, runner.calls)
	}
}

func TestLinuxRuntimeReconcileRejectsActiveOwnershipMetadataDrift(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	activeRoutes := filepath.Join(runtime.Root, "active", routeArtifactName)
	if err := os.WriteFile(activeRoutes, []byte("{\"version\":1,\"commands\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil

	err := runtime.Reconcile(context.Background(), candidate.RevisionID)
	if err == nil || !strings.Contains(err.Error(), "active ownership metadata drift") {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner called after ownership metadata drift: %#v", runner.calls)
	}
}

func TestLinuxRuntimeRejectsUnownedPolicyPriorityCollision(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	runner.outputs = map[string][]byte{
		"ip -4 rule show": []byte("10001: from all lookup main\n"),
	}
	if err := runtime.Activate(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "priority 10001") {
		t.Fatalf("Activate() error = %v, want policy priority collision", err)
	}
	for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("include %s installed after priority collision: %v", path, err)
		}
	}
}

func TestLinuxRuntimeRejectsUnownedRouteTableCollision(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	runner.outputs = map[string][]byte{
		"ip -4 route show table 10001": []byte("default via 192.0.2.1 dev wan0\n"),
	}

	if err := runtime.Activate(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "unowned or drifted route") {
		t.Fatalf("Activate() error = %v, want route table collision", err)
	}
	for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("include %s installed after route collision: %v", path, err)
		}
	}
}

func TestLinuxRuntimeRestoreRemovesOnlyPreviouslyOwnedRulesAndRoutes(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	runner.outputs = expectedKernelRouteOutputs()
	runner.beforeRun = func(program string, args []string) error {
		if program == "/etc/init.d/dnsmasq" && reflect.DeepEqual(args, []string{"reload"}) {
			runner.outputs = emptyKernelOutputs()
		}
		return nil
	}
	if err := runtime.Restore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, call := range runner.calls {
		if call.program == "ip" && len(call.args) > 2 && (call.args[2] == "del" || call.args[2] == "delete") {
			actions = append(actions, strings.Join(call.args[1:3], " "))
		}
	}
	want := []string{"rule del", "rule del", "route del", "route del"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("rollback delete actions = %v, want %v", actions, want)
	}
}

func TestLinuxRuntimeRestorePostChecksPopulatedSnapshot(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	baseline := testCandidate("baseline")
	if err := runtime.Stage(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), baseline.RevisionID); err != nil {
		t.Fatal(err)
	}

	next := testCandidateForSlot("next", 2)
	if err := runtime.Stage(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	runner.outputs = expectedKernelRouteOutputsForSlot(1)
	if err := runtime.Activate(context.Background(), next); err != nil {
		t.Fatal(err)
	}

	runner.outputs = expectedKernelRouteOutputsForSlot(2)
	runner.beforeRun = func(program string, args []string) error {
		if program == "/etc/init.d/dnsmasq" && reflect.DeepEqual(args, []string{"reload"}) {
			runner.outputs = expectedKernelRouteOutputsForSlot(1)
			runner.outputs["nft list table inet routerd"] = baseline.NFT
		}
		return nil
	}
	if err := runtime.Restore(context.Background(), baseline.RevisionID); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, runtime.FirewallIncludePath, baseline.NFT)
	assertFileEquals(t, runtime.DNSIncludePath, baseline.DNS)
}

func TestLinuxRuntimeRestoreRejectsStaticSetDriftButAllowsDynamicElements(t *testing.T) {
	baseline := testCandidateWithSets("baseline")
	dynamicElements := strings.Replace(
		string(baseline.NFT),
		"set rd_dns_shadow4 { type ipv4_addr; flags timeout; timeout 3600s; }",
		"set rd_dns_shadow4 { type ipv4_addr; flags timeout; timeout 1h; elements = { 203.0.113.10 }; }",
		1,
	)
	dynamicElements = strings.Replace(
		dynamicElements,
		"set rd_dns_shadow6 { type ipv6_addr; flags timeout; timeout 3600s; }",
		"set rd_dns_shadow6 { type ipv6_addr; flags timeout; timeout 1h; elements = { 2001:db8::10 }; }",
		1,
	)

	tests := []struct {
		name    string
		listed  string
		wantErr string
	}{
		{name: "dynamic runtime elements", listed: dynamicElements},
		{
			name:    "rd_local4 static element drift",
			listed:  strings.Replace(string(baseline.NFT), "10.0.0.0/8", "192.168.0.0/16", 1),
			wantErr: "rd_local4",
		},
		{
			name:    "rd_local6 static element drift",
			listed:  strings.Replace(string(baseline.NFT), "fd00::/8", "2001:db8::/32", 1),
			wantErr: "rd_local6",
		},
		{
			name:    "set type drift",
			listed:  strings.Replace(string(baseline.NFT), "set rd_local4 { type ipv4_addr", "set rd_local4 { type ipv6_addr", 1),
			wantErr: "type=",
		},
		{
			name:    "set flags drift",
			listed:  strings.Replace(string(baseline.NFT), "set rd_local4 { type ipv4_addr; flags interval", "set rd_local4 { type ipv4_addr; flags timeout", 1),
			wantErr: "flags=",
		},
		{
			name:    "set timeout drift",
			listed:  strings.Replace(string(baseline.NFT), "timeout 3600s", "timeout 30m", 1),
			wantErr: "timeout=",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, runner := newTestLinuxRuntime(t)
			if err := runtime.Stage(context.Background(), baseline); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Activate(context.Background(), baseline); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Snapshot(context.Background(), baseline.RevisionID); err != nil {
				t.Fatal(err)
			}
			runner.outputs = expectedKernelRouteOutputs()
			runner.outputs["nft list table inet routerd"] = []byte(test.listed)

			err := runtime.Restore(context.Background(), baseline.RevisionID)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Restore() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestLinuxRuntimeRestoreRejectsReloadSuccessWithWrongState(t *testing.T) {
	runtime, runner := newTestLinuxRuntime(t)
	candidate := testCandidate("revision-1")
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.outputs = expectedKernelRouteOutputs()
	runner.outputs["nft -j list tables"] = []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd"}}]}`)

	err := runtime.Restore(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "restore post-check") {
		t.Fatalf("Restore() error = %v, want semantic post-check failure", err)
	}
	if !strings.Contains(err.Error(), "nft table remains") {
		t.Fatalf("Restore() error = %v, want stale nft table evidence", err)
	}
}

func TestLinuxRuntimeDetectsSnapshotDriftAndFailsBeforeInstallingIncludes(t *testing.T) {
	t.Run("active include drift", func(t *testing.T) {
		runtime, _ := newTestLinuxRuntime(t)
		candidate := testCandidate("revision-1")
		if err := runtime.Stage(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Snapshot(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Activate(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runtime.FirewallIncludePath, []byte("tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Snapshot(context.Background(), candidate.RevisionID); err == nil || !strings.Contains(err.Error(), "drift") {
			t.Fatalf("Snapshot() error = %v, want drift failure", err)
		}
	})

	t.Run("route failure", func(t *testing.T) {
		runtime, runner := newTestLinuxRuntime(t)
		candidate := testCandidate("revision-1")
		if err := runtime.Stage(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Snapshot(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		runner.failProgram = "ip"
		if err := runtime.Activate(context.Background(), candidate); err == nil {
			t.Fatal("expected route activation failure")
		}
		for _, path := range []string{runtime.FirewallIncludePath, runtime.DNSIncludePath} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("include %s installed after route failure: %v", path, err)
			}
		}
	})
}

func TestReadSnapshotManifestRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), snapshotManifestName)
	data := []byte(`{"firewall_present":false,"dns_present":false} {"revision":"unexpected"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readSnapshotManifest(path); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("readSnapshotManifest() error = %v, want trailing JSON rejection", err)
	}
}

func TestManagedFileHelpersRejectUnsafePaths(t *testing.T) {
	if _, err := readRegularFile("relative-artifact"); err == nil || !strings.Contains(err.Error(), "absolute clean path") {
		t.Fatalf("readRegularFile() error = %v, want absolute clean path rejection", err)
	}
	if err := writeExclusive("relative-artifact", []byte("unsafe"), 0o600); err == nil || !strings.Contains(err.Error(), "absolute clean path") {
		t.Fatalf("writeExclusive() error = %v, want absolute clean path rejection", err)
	}
	if err := syncDirectory("relative-directory"); err == nil || !strings.Contains(err.Error(), "absolute clean path") {
		t.Fatalf("syncDirectory() error = %v, want absolute clean path rejection", err)
	}

	directory := t.TempDir()
	if _, err := readRegularFile(directory); err == nil || !strings.Contains(err.Error(), "regular non-symlink file") {
		t.Fatalf("readRegularFile(directory) error = %v, want regular-file rejection", err)
	}
	existing := filepath.Join(directory, "existing")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(existing, []byte("replacement"), 0o600); err == nil {
		t.Fatal("writeExclusive() replaced an existing managed file")
	}
	assertFileEquals(t, existing, []byte("original"))
}

func newTestLinuxRuntime(t *testing.T) (LinuxRuntime, *recordingRunner) {
	t.Helper()
	base := t.TempDir()
	includeRoot := filepath.Join(base, "etc")
	firewallPath := filepath.Join(includeRoot, "nftables.d", nftArtifactName)
	dnsPath := filepath.Join(includeRoot, "dnsmasq.d", dnsArtifactName)
	for _, directory := range []string{filepath.Dir(firewallPath), filepath.Dir(dnsPath)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingRunner{
		fw4Output: []byte("table inet fw4 {}\n"),
		outputs: map[string][]byte{
			"nft -j list tables": []byte(`{"nftables":[]}`),
		},
	}
	return LinuxRuntime{
		Root:                filepath.Join(base, "runtime"),
		FirewallIncludePath: firewallPath,
		DNSIncludePath:      dnsPath,
		Runner:              runner,
	}, runner
}

func activeTestLinuxRuntime(t *testing.T, candidate Candidate) (LinuxRuntime, *recordingRunner) {
	t.Helper()
	runtime, runner := newTestLinuxRuntime(t)
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	runner.outputs = expectedKernelRouteOutputs()
	runner.outputs["nft list table inet routerd"] = candidate.NFT
	return runtime, runner
}

func testCandidate(revision string) Candidate {
	return Candidate{
		RevisionID: revision,
		NFT: []byte("table inet routerd {\n" +
			"  comment \"managed-by-routerd\";\n" +
			"  chain prerouting {\n" +
			"    type filter hook prerouting priority mangle; policy accept;\n" +
			"    ct direction reply return\n" +
			"  }\n" +
			"}\n"),
		DNS: []byte("# routerd dnsmasq fragment\n"),
		Routes: []byte(`{
  "version": 1,
  "commands": [
    ["ip", "-4", "route", "replace", "table", "10001", "blackhole", "default"],
    ["ip", "-4", "rule", "add", "priority", "10001", "fwmark", "0x1000000/0xff000000", "lookup", "10001"],
    ["ip", "-6", "route", "replace", "table", "10001", "blackhole", "default"],
    ["ip", "-6", "rule", "add", "priority", "10001", "fwmark", "0x1000000/0xff000000", "lookup", "10001"]
  ]
}
`),
	}
}

func testCandidateWithSets(revision string) Candidate {
	candidate := testCandidate(revision)
	candidate.NFT = []byte("table inet routerd {\n" +
		"  comment \"managed-by-routerd\";\n" +
		"  set rd_local4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 }; }\n" +
		"  set rd_local6 { type ipv6_addr; flags interval; elements = { fd00::/8 }; }\n" +
		"  set rd_dns_shadow4 { type ipv4_addr; flags timeout; timeout 3600s; }\n" +
		"  set rd_dns_shadow6 { type ipv6_addr; flags timeout; timeout 3600s; }\n" +
		"  chain prerouting {\n" +
		"    type filter hook prerouting priority mangle; policy accept;\n" +
		"    ct direction reply return\n" +
		"  }\n" +
		"}\n")
	return candidate
}

func testCandidateForSlot(revision string, slot int) Candidate {
	candidate := testCandidate(revision)
	if slot == 1 {
		return candidate
	}
	table := 10000 + slot
	mark := slot * 0x1000000
	candidate.Routes = []byte(strings.NewReplacer(
		"10001", strconv.Itoa(table),
		"0x1000000", fmt.Sprintf("0x%x", mark),
	).Replace(string(candidate.Routes)))
	candidate.NFT = []byte(strings.Replace(string(candidate.NFT), "ct direction reply return", fmt.Sprintf("ct direction reply return comment \"slot-%d\"", slot), 1))
	candidate.DNS = []byte(fmt.Sprintf("# routerd dnsmasq fragment slot %d\n", slot))
	return candidate
}

func expectedKernelRouteOutputs() map[string][]byte {
	return expectedKernelRouteOutputsForSlot(1)
}

func expectedKernelRouteOutputsForSlot(slot int) map[string][]byte {
	table := 10000 + slot
	mark := slot * 0x1000000
	priority := strconv.Itoa(table)
	rule := []byte(fmt.Sprintf("%d: from all fwmark 0x%x/0xff000000 lookup %d\n", table, mark, table))
	return map[string][]byte{
		"ip -4 rule show":                    rule,
		"ip -6 rule show":                    rule,
		"ip -4 route show table " + priority: []byte("blackhole default\n"),
		"ip -6 route show table " + priority: []byte("blackhole default\n"),
	}
}

func emptyKernelOutputs() map[string][]byte {
	return map[string][]byte{
		"nft -j list tables": []byte(`{"nftables":[]}`),
	}
}

func expectedStartupInventoryOutputs() map[string][]byte {
	return map[string][]byte{
		"nft -j list tables":             []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd"}}]}`),
		"nft -j list table inet routerd": []byte(`{"nftables":[{"table":{"family":"inet","name":"routerd","comment":"managed-by-routerd"}}]}`),
		"ip -4 rule show":                []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -6 rule show":                []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -4 route show table all":     []byte("blackhole default table 10001\n"),
		"ip -6 route show table all":     []byte("blackhole default table 10001\n"),
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func assertFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func commandKey(program string, args []string) string {
	return strings.Join(append([]string{program}, args...), " ")
}
