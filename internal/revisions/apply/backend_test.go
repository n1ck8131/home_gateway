package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
		"nft list table inet routerd":  []byte("table inet routerd {\n comment \"managed-by-routerd\"\n chain prerouting { }\n}\n"),
		"ip -4 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -6 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -4 route show table 10001": []byte("blackhole default\n"),
		"ip -6 route show table 10001": []byte("blackhole default\n"),
	}
	if err := runtime.PostCheck(context.Background()); err != nil {
		t.Fatal(err)
	}

	runner.outputs["nft list table inet routerd"] = []byte("table inet routerd {\n comment \"foreign\"\n chain prerouting { }\n}\n")
	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "ownership marker") {
		t.Fatalf("PostCheck() error = %v, want invalid ownership marker", err)
	}
	runner.outputs["nft list table inet routerd"] = []byte("table inet routerd {\n comment \"managed-by-routerd\"\n chain prerouting { }\n}\n")

	runner.outputs["ip -6 route show table 10001"] = nil
	if err := runtime.PostCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "route table 10001") {
		t.Fatalf("PostCheck() error = %v, want missing route", err)
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
	last := runner.calls[len(runner.calls)-2:]
	if last[0].program != "fw4" || !reflect.DeepEqual(last[0].args, []string{"reload"}) {
		t.Fatalf("restore firewall reload call = %#v", last[0])
	}
	if last[1].program != "/etc/init.d/dnsmasq" || !reflect.DeepEqual(last[1].args, []string{"reload"}) {
		t.Fatalf("restore reload calls = %#v", last)
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

func testCandidate(revision string) Candidate {
	return Candidate{
		RevisionID: revision,
		NFT:        []byte("table inet routerd { comment \"managed-by-routerd\"; }\n"),
		DNS:        []byte("# routerd dnsmasq fragment\n"),
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

func expectedKernelRouteOutputs() map[string][]byte {
	return map[string][]byte{
		"ip -4 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -6 rule show":              []byte("10001: from all fwmark 0x1000000/0xff000000 lookup 10001\n"),
		"ip -4 route show table 10001": []byte("blackhole default\n"),
		"ip -6 route show table 10001": []byte("blackhole default\n"),
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
