//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	xwindows "golang.org/x/sys/windows"
)

const nativeJobHelperMode = "HG_NATIVE_JOB_HELPER"

const (
	testNativeBootID     = "10000000-0000-4000-8000-000000000001"
	testNativeNextBootID = "20000000-0000-4000-8000-000000000002"
)

func TestNativeJobParentHelper(t *testing.T) {
	if os.Getenv(nativeJobHelperMode) != "parent" {
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestNativeJobGrandchildHelper$")
	command.Env = append(os.Environ(), nativeJobHelperMode+"=grandchild")
	if err := command.Start(); err != nil {
		os.Exit(21)
	}
	time.Sleep(30 * time.Second)
}

func TestNativeJobGrandchildHelper(t *testing.T) {
	if os.Getenv(nativeJobHelperMode) != "grandchild" {
		return
	}
	time.Sleep(500 * time.Millisecond)
	if err := os.WriteFile(os.Getenv("HG_NATIVE_JOB_MARKER"), []byte("orphaned"), 0o600); err != nil {
		os.Exit(22)
	}
}

func TestNativeExecMutationRunnerKillsDescendantsWhenContextEnds(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "orphaned-child.txt")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := (nativeExecMutationRunner{}).Run(ctx, nativeMutationCommand{
		Executable:  os.Args[0],
		Arguments:   []string{"-test.run=^TestNativeJobParentHelper$"},
		Environment: append(os.Environ(), nativeJobHelperMode+"=parent", "HG_NATIVE_JOB_MARKER="+marker),
		Directory:   t.TempDir(),
	})
	if err == nil {
		t.Fatal("canceled native command unexpectedly succeeded")
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native descendant survived its kill-on-close job: %v", err)
	}
}

func TestReadNativeBootIdentifierReturnsCanonicalKernelGUID(t *testing.T) {
	value, err := readNativeBootIdentifier()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalGUID(value)
	if err != nil || value == "" || value != canonical || value != strings.ToLower(value) {
		t.Fatalf("kernel BootIdentifier is not a canonical lowercase GUID: value=%q err=%v", value, err)
	}
}

type fakeNativeMutationRunner struct {
	calls     []nativeMutationCommand
	response  []byte
	err       error
	responses map[string][]byte
	errors    map[string]error
	beforeRun func(nativeMutationCommand)
}

func (runner *fakeNativeMutationRunner) Run(ctx context.Context, command nativeMutationCommand) ([]byte, error) {
	copyCommand := command
	copyCommand.Arguments = append([]string(nil), command.Arguments...)
	copyCommand.Environment = append([]string(nil), command.Environment...)
	copyCommand.Input = append([]byte(nil), command.Input...)
	runner.calls = append(runner.calls, copyCommand)
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > nativeMutationTimeout+time.Second {
		return nil, errors.New("missing bounded deadline")
	}
	if runner.beforeRun != nil {
		runner.beforeRun(copyCommand)
	}
	var request nativeMutationRequest
	if err := json.Unmarshal(command.Input, &request); err != nil {
		return nil, err
	}
	if err := runner.errors[request.Operation]; err != nil {
		return nil, err
	}
	if response, exists := runner.responses[request.Operation]; exists {
		return append([]byte(nil), response...), nil
	}
	if runner.err != nil {
		return nil, runner.err
	}
	return append([]byte(nil), runner.response...), nil
}

func TestNativeMutationBackendUsesTrustedFixedInvocationAndStructuredStdin(t *testing.T) {
	runner := &fakeNativeMutationRunner{response: []byte(`{"version":1,"ok":true,"nrpt_name":"{11111111-2222-3333-4444-555555555555}"}`)}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestNRPT("r1")
	state.Rule.DisplayName = `safe'; Remove-NetRoute -Confirm:$false; #`
	registryObserved := false
	runner.beforeRun = func(command nativeMutationCommand) {
		if !strings.Contains(string(command.Input), `"name":""`) {
			t.Fatalf("initial structured NRPT request omitted its explicit empty native name: %s", command.Input)
		}
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != "put_nrpt" || request.NRPT == nil || request.NRPT.Rule.DisplayName != state.Rule.DisplayName {
			t.Fatalf("structured request = %#v", request)
		}
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		registryObserved = len(registry.NRPT) == 1 && registry.NRPT[0].Rule.Name == ""
	}
	if err := backend.PutNRPT(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if !registryObserved {
		t.Fatal("NRPT ownership intent was not committed before the native command")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("native calls = %d", len(runner.calls))
	}
	call := runner.calls[0]
	wantExecutable := filepath.Join(`C:\Windows\System32`, "WindowsPowerShell", "v1.0", "powershell.exe")
	if call.Executable != wantExecutable || call.Directory != `C:\Windows\System32` {
		t.Fatalf("trusted invocation path = %#v", call)
	}
	wantArguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-Command", nativeMutationScript}
	if !slices.Equal(call.Arguments, wantArguments) {
		t.Fatalf("arguments differ: %#v", call.Arguments)
	}
	for _, value := range append(append([]string(nil), call.Arguments...), call.Environment...) {
		if strings.Contains(value, state.Rule.DisplayName) || strings.Contains(value, state.Rule.Namespace) {
			t.Fatalf("caller-controlled value escaped stdin: %q", value)
		}
	}
	wantEnvironment := []string{
		`SystemRoot=C:\Windows`,
		`WINDIR=C:\Windows`,
		`ComSpec=C:\Windows\System32\cmd.exe`,
		`PATH=C:\Windows\System32`,
		`PATHEXT=.COM;.EXE;.BAT;.CMD`,
		`PSModulePath=C:\Windows\System32\WindowsPowerShell\v1.0\Modules`,
		`HG_UTILITY_MANIFEST=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1`,
		`HG_NETADAPTER_MANIFEST=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetAdapter\NetAdapter.psd1`,
		`HG_NETTCPIP_MANIFEST=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetTCPIP.psd1`,
		`HG_DNSCLIENT_MANIFEST=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClient.psd1`,
		`HG_NETSECURITY_MANIFEST=C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetSecurity\NetSecurity.psd1`,
	}
	if !slices.Equal(call.Environment, wantEnvironment) {
		t.Fatalf("environment differs:\n got: %#v\nwant: %#v", call.Environment, wantEnvironment)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.NRPT) != 1 || registry.NRPT[0].Rule.Name != "{11111111-2222-3333-4444-555555555555}" {
		t.Fatalf("final NRPT registry = %#v", registry.NRPT)
	}
}

func TestNativeFirewallEffectiveHealthUsesDocumentedPrimaryStatus(t *testing.T) {
	if !strings.Contains(nativeMutationScript, "[string]$current.PrimaryStatus -cne 'OK'") {
		t.Fatal("effective firewall check does not require documented PrimaryStatus=OK")
	}
	if strings.Contains(nativeMutationScript, "$current.StatusCode") {
		t.Fatal("effective firewall check relies on reserved provider StatusCode")
	}
}

func TestNativeMutationBackendCommitsAndRetainsRouteOwnershipInSafeOrder(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		response: []byte(`{"version":1,"ok":true}`),
		responses: map[string][]byte{
			"resolve_route_interface": []byte(`{"version":1,"ok":true,"interface_index":12}`),
		},
	}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestRoute("r1")
	wantOperation := "add_route"
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Route == nil || *request.Route != state {
			t.Fatalf("native route request = %#v", request)
		}
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		if request.Operation == "resolve_route_interface" {
			if containsNativeRoute(registry.Routes, state) {
				t.Fatal("route ownership was journaled before stable interface resolution")
			}
			return
		}
		if request.Operation != wantOperation || !containsNativeRoute(registry.Routes, state) {
			t.Fatalf("registry was not retained during %s", wantOperation)
		}
	}
	if err := backend.AddRoute(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	wantOperation = "remove_route"
	state.State = 2
	if err := backend.RemoveRoute(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Routes) != 0 {
		t.Fatalf("route registry after successful removal = %#v", registry.Routes)
	}
}

func TestNativeMutationBackendPersistsInvocationBoundRouteIndexAcrossReindex(t *testing.T) {
	runner := &fakeNativeMutationRunner{responses: map[string][]byte{
		"resolve_route_interface": []byte(`{"version":1,"ok":true,"interface_index":77}`),
		"add_route":               []byte(`{"version":1,"ok":true}`),
	}}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestRoute("r1")
	intentObserved := false
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != "add_route" {
			return
		}
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		intentObserved = request.Route != nil && request.Route.InterfaceIndex == 77 && len(registry.Routes) == 1 && registry.Routes[0].InterfaceIndex == state.InterfaceIndex && len(registry.Tombstones) == 1 && registry.Tombstones[0].Route != nil && registry.Tombstones[0].Route.InterfaceIndex == 77 && registry.Tombstones[0].BootID == testNativeBootID
	}
	if err := backend.AddRoute(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if !intentObserved {
		t.Fatal("route reindex did not persist the invocation-bound current index before mutation")
	}
	if got := nativeOperations(t, runner.calls); !slices.Equal(got, []string{"resolve_route_interface", "add_route"}) {
		t.Fatalf("route reindex operations = %v", got)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Routes) != 1 || registry.Routes[0].InterfaceIndex != state.InterfaceIndex || len(registry.Tombstones) != 0 {
		t.Fatalf("route reindex changed immutable ownership or retained intent: %#v", registry)
	}
}

func TestNativeMutationBackendJournalsFirewallAliasBeforeMutation(t *testing.T) {
	state := nativeTestFirewall("r1")
	binding := nativeFirewallOwnership{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet"}
	runner := &fakeNativeMutationRunner{responses: map[string][]byte{
		"resolve_firewall_batch": mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": []nativeFirewallOwnership{binding}}),
		"put_firewall_batch":     []byte(`{"version":1,"ok":true}`),
	}}
	backend := newTestNativeMutationBackend(t, runner)
	intentObserved := false
	preparedBinding := binding
	preparedBinding.Phase = nativeFirewallPhasePrepared
	preparedBinding.BootID = testNativeBootID
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != "put_firewall_batch" {
			return
		}
		if len(request.FirewallBindings) != 1 || request.FirewallBindings[0] != preparedBinding {
			t.Fatalf("structured firewall request = %#v", request)
		}
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		intentObserved = len(registry.Firewall) == 1 && registry.Firewall[0].State == state && registry.Firewall[0].InterfaceAlias == "Ethernet" && registry.Firewall[0].InterfacePattern == "Ethernet" && registry.Firewall[0].Phase == nativeFirewallPhasePrepared && !registry.Firewall[0].Committed
	}
	if err := backend.PutFirewall(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if !intentObserved {
		t.Fatal("firewall ownership intent and exact alias were not committed before native mutation")
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 1 || !registry.Firewall[0].Committed || registry.Firewall[0].Phase != nativeFirewallPhaseApplied || registry.Firewall[0].InterfaceAlias != "Ethernet" || registry.Firewall[0].InterfacePattern != "Ethernet" {
		t.Fatalf("final firewall registry = %#v", registry.Firewall)
	}
}

func TestNativeMutationBackendRemovesFirewallWithoutLiveAdapter(t *testing.T) {
	runner := &fakeNativeMutationRunner{response: []byte(`{"version":1,"ok":true}`)}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestFirewall("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{{State: state, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Committed: true}}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveFirewall(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("native calls = %d", len(runner.calls))
	}
	var request nativeMutationRequest
	if err := json.Unmarshal(runner.calls[0].Input, &request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != "remove_firewall_batch" || len(request.FirewallBindings) != 1 || request.FirewallBindings[0].State != state || request.FirewallBindings[0].InterfaceAlias != "Legacy Ethernet" || request.FirewallBindings[0].InterfacePattern != "Legacy Ethernet" {
		t.Fatalf("firewall removal request = %#v", request)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 0 {
		t.Fatalf("firewall ownership remained after removal: %#v", registry.Firewall)
	}
}

func TestNativeMutationBackendBatchesMaximumFirewallSetAcrossHostLikeAdapters(t *testing.T) {
	states, bindings := nativeHostFirewallBatch("r1", maxFirewallRules, 21)
	runner := &fakeNativeMutationRunner{responses: map[string][]byte{
		"resolve_firewall_batch": mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": bindings}),
		"put_firewall_batch":     []byte(`{"version":1,"ok":true}`),
		"remove_firewall_batch":  []byte(`{"version":1,"ok":true}`),
	}}
	backend := newTestNativeMutationBackend(t, runner)
	allIntentsObserved := false
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != "put_firewall_batch" {
			return
		}
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		allIntentsObserved = len(registry.Firewall) == len(states) && !slices.ContainsFunc(registry.Firewall, func(ownership nativeFirewallOwnership) bool { return ownership.Committed })
	}

	if err := backend.PutFirewallBatch(context.Background(), states); err != nil {
		t.Fatal(err)
	}
	if !allIntentsObserved {
		t.Fatal("complete firewall batch was not atomically journaled before native mutation")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("maximum firewall put used %d native invocations, want 2", len(runner.calls))
	}
	assertNativeOperation(t, runner.calls[0], "resolve_firewall_batch", len(states), 0)
	assertNativeOperation(t, runner.calls[1], "put_firewall_batch", 0, len(states))
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != maxFirewallRules || slices.ContainsFunc(registry.Firewall, func(ownership nativeFirewallOwnership) bool { return !ownership.Committed }) {
		t.Fatalf("maximum firewall registry was not committed exactly: count=%d", len(registry.Firewall))
	}

	observed := append([]FirewallState(nil), states...)
	for index := range observed {
		observed[index].Effective = true
	}
	if err := backend.RemoveFirewallBatch(context.Background(), observed); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("maximum firewall removal used %d total native invocations, want 3", len(runner.calls))
	}
	assertNativeOperation(t, runner.calls[2], "remove_firewall_batch", 0, len(states))
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 0 {
		t.Fatalf("maximum firewall registry remained after successful batch removal: %d", len(registry.Firewall))
	}
	overLimit, _ := nativeHostFirewallBatch("r1", maxFirewallRules+1, 21)
	if err := backend.PutFirewallBatch(context.Background(), overLimit); err == nil || len(runner.calls) != 3 {
		t.Fatalf("over-limit firewall batch result: err=%v calls=%d", err, len(runner.calls))
	}
}

func TestNativeMutationBackendFirewallBatchQuarantinesIndeterminatePartialMutation(t *testing.T) {
	states, bindings := nativeHostFirewallBatch("r1", 4, 2)
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"resolve_firewall_batch":    mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": bindings}),
			"put_firewall_batch":        []byte(`{"version":1,"ok":true}`),
			"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`),
		},
		errors: map[string]error{"put_firewall_batch": errors.New("partial native create")},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }

	if err := backend.PutFirewallBatch(context.Background(), states); err == nil || strings.Contains(err.Error(), "partial native create") {
		t.Fatalf("indeterminate put error was not redacted: %v", err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != len(states) || slices.ContainsFunc(registry.Firewall, func(ownership nativeFirewallOwnership) bool { return ownership.Committed }) {
		t.Fatalf("put failure did not retain every uncommitted intent: %#v", registry.Firewall)
	}
	delete(runner.errors, "put_firewall_batch")
	if err := backend.PutFirewallBatch(context.Background(), states); err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("indeterminate put retry was not quarantined: %v", err)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != len(states) || slices.ContainsFunc(registry.Firewall, func(ownership nativeFirewallOwnership) bool {
		return ownership.Committed || ownership.Phase != nativeFirewallPhaseWatch
	}) {
		t.Fatalf("retry discarded or finalized indeterminate intents: %#v", registry.Firewall)
	}
	wantOperations := []string{
		"resolve_firewall_batch", "put_firewall_batch",
		"cleanup_native_tombstones", "cleanup_native_tombstones", "cleanup_native_tombstones",
		"cleanup_native_tombstones",
	}
	if got := nativeOperations(t, runner.calls); !slices.Equal(got, wantOperations) {
		t.Fatalf("retry operation sequence = %v, want %v", got, wantOperations)
	}
}

func TestNativeMutationBackendRetainsAbsentFirewallIntentInDurableWatch(t *testing.T) {
	state := nativeTestFirewall("r1")
	binding := nativeFirewallOwnership{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet"}
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"resolve_firewall_batch":    mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": []nativeFirewallOwnership{binding}}),
			"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`),
		},
		errors: map[string]error{"put_firewall_batch": context.DeadlineExceeded},
	}
	backend := newTestNativeMutationBackend(t, runner)
	providerCommitted := false
	providerRemoved := false
	ownershipRetainedAtLateCommit := false
	waits := 0
	backend.firewallCleanupWait = func(context.Context, time.Duration) error {
		waits++
		if waits == 1 {
			providerCommitted = true
		}
		return nil
	}
	cleanupCalls := 0
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != "cleanup_native_tombstones" {
			return
		}
		cleanupCalls++
		registry, err := backend.readRegistryLocked()
		if err != nil {
			t.Fatal(err)
		}
		if len(registry.Firewall) != 1 || registry.Firewall[0].Phase != nativeFirewallPhaseCleanup && registry.Firewall[0].Phase != nativeFirewallPhaseWatch || registry.Firewall[0].Committed {
			t.Fatalf("cleanup tombstone was not durable during verification: %#v", registry.Firewall)
		}
		if providerCommitted {
			ownershipRetainedAtLateCommit = true
			providerRemoved = true
			providerCommitted = false
		}
	}

	if err := backend.PutFirewall(context.Background(), state); err == nil {
		t.Fatal("timed-out provider mutation unexpectedly succeeded")
	}
	if cleanupCalls != nativeFirewallCleanupChecks || waits != nativeFirewallCleanupChecks-1 || !providerRemoved || !ownershipRetainedAtLateCommit {
		t.Fatalf("late provider cleanup: calls=%d waits=%d removed=%v retained=%v", cleanupCalls, waits, providerRemoved, ownershipRetainedAtLateCommit)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 1 || registry.Firewall[0].Phase != nativeFirewallPhaseWatch || registry.Firewall[0].Committed {
		t.Fatalf("quiesced cleanup did not retain durable watch tombstone: %#v", registry.Firewall)
	}
	// A provider commit after the final in-process negative check is still
	// covered by the durable watch phase on the next process reconciliation.
	providerCommitted = true
	providerRemoved = false
	runner.responses["snapshot"] = nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{}, []any{}, []any{}, []any{},
		[]any{map[string]any{"name": state.Rule.Name, "exact": false}},
	)
	restarted, err := newNativeMutationBackend(backend.root, nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`}, runner, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	restarted.bootID = backend.bootID
	restarted.firewallCleanupWait = backend.firewallCleanupWait
	if _, err := restarted.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
		t.Fatalf("same-boot absent firewall intent became terminal: %v", err)
	}
	if cleanupCalls != nativeFirewallCleanupChecks+1 || !providerRemoved {
		t.Fatalf("restart reconciliation missed post-window provider commit: calls=%d removed=%v", cleanupCalls, providerRemoved)
	}
	registry, err = restarted.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 1 || registry.Firewall[0].Phase != nativeFirewallPhaseWatch {
		t.Fatalf("restart reconciliation dropped durable firewall ownership: %#v", registry.Firewall)
	}
	restarted.bootID = func() (string, error) { return testNativeNextBootID, nil }
	if _, err := restarted.Snapshot(context.Background()); err != nil {
		t.Fatalf("post-reboot exact firewall absence did not become terminal: %v", err)
	}
	registry, err = restarted.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 0 || cleanupCalls != nativeFirewallCleanupChecks+1 {
		t.Fatalf("post-reboot firewall intent was not finalized: cleanupCalls=%d registry=%#v", cleanupCalls, registry.Firewall)
	}
}

func TestFinalizeRebootedFirewallPutRequiresExactCurrentAndPreviousAliasAbsence(t *testing.T) {
	states, bindings := nativeHostFirewallBatch("r1", 3, 3)
	for index := range bindings {
		bindings[index].Phase = nativeFirewallPhaseWatch
		bindings[index].BootID = testNativeBootID
	}
	previousAlias := bindings[2].InterfaceAlias
	previousPattern := bindings[2].InterfacePattern
	bindings[2].PreviousInterfaceAlias = previousAlias
	bindings[2].PreviousInterfacePattern = previousPattern
	bindings[2].InterfaceAlias = "Renamed adapter"
	bindings[2].InterfacePattern = "Renamed adapter"

	rawRecord := func(ownership nativeFirewallOwnership, pattern, description string) rawNativeFirewallRecord {
		record := map[string]any{
			"name":             ownership.State.Rule.Name,
			"displayName":      ownership.State.Rule.Name,
			"description":      description,
			"group":            ownership.State.Rule.Group,
			"enabled":          "True",
			"direction":        "Outbound",
			"action":           "Block",
			"remoteAddresses":  []string{ownership.State.Rule.RemoteCIDR},
			"interfaceAliases": []string{pattern},
		}
		var raw rawNativeFirewallRecord
		if err := json.Unmarshal(mustNativeJSON(t, record), &raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	records := []rawNativeFirewallRecord{
		// Same-name foreign content is not claimed and does not prevent the
		// post-reboot journal generation from becoming terminal.
		rawRecord(bindings[0], bindings[0].InterfacePattern, "foreign content"),
		rawRecord(bindings[1], bindings[1].InterfacePattern, bindings[1].State.Rule.Description),
		rawRecord(bindings[2], bindings[2].PreviousInterfacePattern, bindings[2].State.Rule.Description),
	}
	raw := rawNativeMutationSnapshot{Firewall: &records}
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = bindings
	finalized := finalizeRebootedMutations(MutationSnapshot{}, raw, registry, testNativeNextBootID)
	if len(finalized.Firewall) != 2 || finalized.Firewall[0].State != states[1] || finalized.Firewall[1].State != states[2] {
		t.Fatalf("post-reboot firewall exact-absence finalization = %#v", finalized.Firewall)
	}
}

func TestNativeMutationBackendFinalizesRebootedFirewallPutBeforeForeignCleanupCollision(t *testing.T) {
	state := nativeTestFirewall("r1")
	ownership := nativeFirewallOwnership{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhaseWatch, BootID: testNativeBootID}
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"snapshot": nativeSnapshotJSON(t,
				[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{},
				[]any{map[string]any{"name": state.Rule.Name, "displayName": state.Rule.Name, "description": "foreign content", "group": state.Rule.Group, "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{state.Rule.RemoteCIDR}, "interfaceAliases": []string{"Ethernet"}}},
				[]any{}, []any{},
				[]any{map[string]any{"name": state.Rule.Name, "exact": false}},
			),
		},
		errors: map[string]error{"cleanup_native_tombstones": errors.New("foreign firewall cleanup collision")},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.bootID = func() (string, error) { return testNativeNextBootID, nil }
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{ownership}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("post-reboot foreign firewall preservation failed: %v", err)
	}
	if got := nativeOperations(t, runner.calls); !slices.Equal(got, []string{"snapshot"}) {
		t.Fatalf("post-reboot firewall finalization invoked cleanup: %v", got)
	}
	if len(snapshot.Firewall) != 1 || snapshot.Firewall[0].Owner != "" || snapshot.Firewall[0].Rule.Name != state.Rule.Name {
		t.Fatalf("same-name foreign firewall was claimed or removed: %#v", snapshot.Firewall)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 0 {
		t.Fatalf("terminal rebooted firewall journal was retained: %#v", registry.Firewall)
	}
}

func TestNativeMutationBackendFinalizesRebootedRouteBeforeMissingGUIDCleanup(t *testing.T) {
	state := nativeTestRoute("r1")
	invocationState := state
	invocationState.InterfaceIndex = 77
	tombstone := nativeMutationTombstone{Kind: nativeTombstoneRoute, Action: nativeTombstonePut, Phase: nativeFirewallPhaseWatch, BootID: testNativeBootID, Route: &invocationState}
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"snapshot": nativeSnapshotJSON(t,
				[]any{map[string]any{"name": "Reused index", "description": "Foreign adapter", "interfaceIndex": 77, "interfaceGuid": testCiscoGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{map[string]any{"interfaceIndex": 77, "addressFamily": 2, "destinationPrefix": state.Destination, "nextHop": state.NextHop, "routeMetric": state.Metric, "policyStore": state.PolicyStore, "protocol": state.Protocol, "state": 0}},
				[]any{}, []any{}, []any{}, []any{},
			),
		},
		errors: map[string]error{"cleanup_native_tombstones": errors.New("stable route GUID is absent")},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.bootID = func() (string, error) { return testNativeNextBootID, nil }
	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{state}
	registry.Tombstones = []nativeMutationTombstone{tombstone}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("post-reboot missing-GUID route finalization failed: %v", err)
	}
	if got := nativeOperations(t, runner.calls); !slices.Equal(got, []string{"snapshot"}) {
		t.Fatalf("post-reboot route finalization invoked cleanup: %v", got)
	}
	if len(snapshot.Routes) != 1 || snapshot.Routes[0].Owner != "" || snapshot.Routes[0].InterfaceGUID != testCiscoGUID || snapshot.Routes[0].InterfaceIndex != 77 {
		t.Fatalf("foreign reused-index route was claimed or removed: %#v", snapshot.Routes)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Routes) != 0 || len(registry.Tombstones) != 0 {
		t.Fatalf("terminal rebooted route journal was retained: %#v", registry)
	}
}

func TestNativeMutationBackendRemoveTimeoutReapplyRequiresRebootBarrier(t *testing.T) {
	for _, kind := range []string{nativeTombstoneRoute, nativeTombstoneFirewall, nativeTombstoneNRPT} {
		t.Run(kind, func(t *testing.T) {
			runner := &fakeNativeMutationRunner{
				responses: map[string][]byte{"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`)},
				errors:    make(map[string]error),
			}
			backend := newTestNativeMutationBackend(t, runner)
			backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
			registry := emptyNativeOwnershipRegistry()
			var remove func(*nativeMutationBackend) error
			var reapply func(*nativeMutationBackend) error
			var removeOperation string
			var putOperation string
			effectiveFirewall := []any{}

			switch kind {
			case nativeTombstoneRoute:
				state := nativeTestRoute("r1")
				registry.Routes = []RouteState{state}
				removeOperation = "remove_route"
				putOperation = "add_route"
				runner.responses["resolve_route_interface"] = []byte(`{"version":1,"ok":true,"interface_index":12}`)
				runner.responses[putOperation] = []byte(`{"version":1,"ok":true}`)
				remove = func(target *nativeMutationBackend) error { return target.RemoveRoute(context.Background(), state) }
				reapply = func(target *nativeMutationBackend) error { return target.AddRoute(context.Background(), state) }
			case nativeTombstoneFirewall:
				state := nativeTestFirewall("r1")
				ownership := nativeFirewallOwnership{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}
				registry.Firewall = []nativeFirewallOwnership{ownership}
				removeOperation = "remove_firewall_batch"
				putOperation = "put_firewall_batch"
				binding := nativeFirewallOwnership{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet"}
				runner.responses["resolve_firewall_batch"] = mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": []nativeFirewallOwnership{binding}})
				runner.responses[putOperation] = []byte(`{"version":1,"ok":true}`)
				effectiveFirewall = []any{map[string]any{"name": state.Rule.Name, "exact": false}}
				remove = func(target *nativeMutationBackend) error { return target.RemoveFirewall(context.Background(), state) }
				reapply = func(target *nativeMutationBackend) error { return target.PutFirewall(context.Background(), state) }
			case nativeTombstoneNRPT:
				state := nativeTestNRPT("r1")
				state.Rule.Name = "{11111111-2222-3333-4444-555555555555}"
				registry.NRPT = []NRPTState{state}
				removeOperation = "remove_nrpt"
				putOperation = "put_nrpt"
				runner.responses[putOperation] = []byte(`{"version":1,"ok":true,"nrpt_name":"{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}"}`)
				candidate := state
				candidate.Rule.Name = ""
				remove = func(target *nativeMutationBackend) error { return target.RemoveNRPT(context.Background(), state) }
				reapply = func(target *nativeMutationBackend) error { return target.PutNRPT(context.Background(), candidate) }
			}

			if err := backend.writeRegistryLocked(registry); err != nil {
				t.Fatal(err)
			}
			runner.errors[removeOperation] = context.DeadlineExceeded
			if err := remove(backend); err == nil {
				t.Fatalf("timed-out %s remove unexpectedly succeeded", kind)
			}
			registry, err := backend.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 1 || registry.Tombstones[0].Kind != kind || registry.Tombstones[0].Action != nativeTombstoneRemove || registry.Tombstones[0].Phase != nativeFirewallPhaseWatch || registry.Tombstones[0].BootID != testNativeBootID {
				t.Fatalf("durable %s remove generation = %#v", kind, registry.Tombstones)
			}

			runner.responses["snapshot"] = nativeSnapshotJSON(t,
				[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{}, []any{}, []any{}, []any{}, effectiveFirewall,
			)
			if _, err := backend.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
				t.Fatalf("same-boot %s remove generation became terminal: %v", kind, err)
			}
			beforeReapply := len(runner.calls)
			if err := reapply(backend); err == nil || !strings.Contains(err.Error(), "quarantined") {
				t.Fatalf("same-boot %s reapply escaped quarantine: %v", kind, err)
			}
			for _, operation := range nativeOperations(t, runner.calls[beforeReapply:]) {
				if operation == putOperation {
					t.Fatalf("same-boot %s reapply invoked %s", kind, putOperation)
				}
			}

			restarted, err := newNativeMutationBackend(backend.root, nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`}, runner, func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			restarted.bootID = func() (string, error) { return testNativeNextBootID, nil }
			restarted.firewallCleanupWait = backend.firewallCleanupWait
			if _, err := restarted.Snapshot(context.Background()); err != nil {
				t.Fatalf("post-reboot %s remove generation did not finalize: %v", kind, err)
			}
			registry, err = restarted.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 0 || len(registry.Routes) != 0 || len(registry.Firewall) != 0 || len(registry.NRPT) != 0 {
				t.Fatalf("post-reboot %s ownership generation remains: %#v", kind, registry)
			}
			delete(runner.errors, removeOperation)
			if err := reapply(restarted); err != nil {
				t.Fatalf("post-reboot %s reapply failed: %v", kind, err)
			}
			putCalls := 0
			for _, operation := range nativeOperations(t, runner.calls) {
				if operation == putOperation {
					putCalls++
				}
			}
			if putCalls != 1 {
				t.Fatalf("post-reboot %s put calls = %d", kind, putCalls)
			}
		})
	}
}

func TestNativeSnapshotReconcileDoesNotDropFirstAbsentFirewallIntent(t *testing.T) {
	state := nativeTestFirewall("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhasePrepared}}
	encoded := nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{}, []any{}, []any{}, []any{},
		[]any{map[string]any{"name": state.Rule.Name, "exact": false}},
	)
	var response nativeMutationResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response.Snapshot == nil {
		t.Fatal("test snapshot is missing")
	}
	_, reconciled, err := parseNativeMutationSnapshot(*response.Snapshot, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciled.Firewall) != 1 || reconciled.Firewall[0].Phase != nativeFirewallPhaseCleanup || reconciled.Firewall[0].Committed {
		t.Fatalf("first absent observation discarded or finalized pending intent: %#v", reconciled.Firewall)
	}
}

func TestNativeMutationBackendRouteAndNRPTTombstonesSurviveRestartAndRemoveLateCommit(t *testing.T) {
	for _, kind := range []string{nativeTombstoneRoute, nativeTombstoneNRPT} {
		t.Run(kind, func(t *testing.T) {
			operation := "add_route"
			if kind == nativeTombstoneNRPT {
				operation = "put_nrpt"
			}
			runner := &fakeNativeMutationRunner{
				responses: map[string][]byte{
					"resolve_route_interface":   []byte(`{"version":1,"ok":true,"interface_index":12}`),
					"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`),
				},
				errors: map[string]error{operation: context.DeadlineExceeded},
			}
			backend := newTestNativeMutationBackend(t, runner)
			backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
			lateCommit := false
			lateRemoved := false
			runner.beforeRun = func(command nativeMutationCommand) {
				var request nativeMutationRequest
				if err := json.Unmarshal(command.Input, &request); err != nil {
					t.Fatal(err)
				}
				if request.Operation != "cleanup_native_tombstones" || !lateCommit {
					return
				}
				if slices.ContainsFunc(request.MutationTombstones, func(tombstone nativeMutationTombstone) bool { return tombstone.Kind == kind }) {
					lateCommit = false
					lateRemoved = true
				}
			}

			var mutationErr error
			if kind == nativeTombstoneRoute {
				mutationErr = backend.AddRoute(context.Background(), nativeTestRoute("r1"))
			} else {
				mutationErr = backend.PutNRPT(context.Background(), nativeTestNRPT("r1"))
			}
			if mutationErr == nil {
				t.Fatal("timed-out provider mutation unexpectedly succeeded")
			}
			registry, err := backend.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 1 || registry.Tombstones[0].Kind != kind || registry.Tombstones[0].Action != nativeTombstonePut || registry.Tombstones[0].Phase != nativeFirewallPhaseWatch {
				t.Fatalf("durable %s tombstone = %#v", kind, registry.Tombstones)
			}
			var replacementErr error
			if kind == nativeTombstoneRoute {
				replacement := nativeTestRoute("r2")
				replacement.InterfaceIndex = 77
				replacementErr = backend.AddRoute(context.Background(), replacement)
			} else {
				replacementErr = backend.PutNRPT(context.Background(), nativeTestNRPT("r2"))
			}
			if replacementErr == nil || !strings.Contains(replacementErr.Error(), "quarantined") {
				t.Fatalf("cross-revision %s replacement escaped late-create quarantine: %v", kind, replacementErr)
			}
			mutationCalls := 0
			for _, current := range nativeOperations(t, runner.calls) {
				if current == operation {
					mutationCalls++
				}
			}
			if mutationCalls != 1 {
				t.Fatalf("cross-revision %s replacement issued a second provider mutation: %v", kind, nativeOperations(t, runner.calls))
			}

			lateCommit = true
			runner.responses["snapshot"] = nativeSnapshotJSON(t,
				[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{}, []any{}, []any{}, []any{}, []any{},
			)
			restarted, err := newNativeMutationBackend(backend.root, nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`}, runner, func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			restarted.bootID = backend.bootID
			restarted.firewallCleanupWait = backend.firewallCleanupWait
			if _, err := restarted.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
				t.Fatalf("same-boot %s cleanup became terminal: %v", kind, err)
			}
			if !lateRemoved {
				t.Fatalf("restart reconciliation did not remove late %s provider commit", kind)
			}
			registry, err = restarted.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 1 || registry.Tombstones[0].Phase != nativeFirewallPhaseWatch {
				t.Fatalf("restart dropped %s tombstone: %#v", kind, registry.Tombstones)
			}
			if kind == nativeTombstoneRoute && len(registry.Routes) != 1 || kind == nativeTombstoneNRPT && len(registry.NRPT) != 1 {
				t.Fatalf("restart dropped %s ownership: routes=%#v nrpt=%#v", kind, registry.Routes, registry.NRPT)
			}
		})
	}
}

func TestNativeMutationBackendKeepsProtectiveStateForIndeterminatePut(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`)},
		errors:    map[string]error{"put_nrpt": context.DeadlineExceeded},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
	route := nativeTestRoute("r1")
	firewall := nativeTestFirewall("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{route}
	registry.Firewall = []nativeFirewallOwnership{{State: firewall, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutNRPT(context.Background(), nativeTestNRPT("r1")); err == nil {
		t.Fatal("indeterminate NRPT put unexpectedly succeeded")
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 1 || registry.Tombstones[0].Kind != nativeTombstoneNRPT || registry.Tombstones[0].Action != nativeTombstonePut || registry.Tombstones[0].BootID != testNativeBootID {
		t.Fatalf("NRPT put tombstone = %#v", registry.Tombstones)
	}
	calls := len(runner.calls)
	if err := backend.RemoveRoute(context.Background(), route); err == nil || !strings.Contains(err.Error(), "protective state") {
		t.Fatalf("route teardown escaped NRPT put quarantine: %v", err)
	}
	if err := backend.RemoveFirewall(context.Background(), firewall); err == nil || !strings.Contains(err.Error(), "protective state") {
		t.Fatalf("firewall teardown escaped NRPT put quarantine: %v", err)
	}
	if len(runner.calls) != calls {
		t.Fatalf("protective teardown issued native calls: %v", nativeOperations(t, runner.calls[calls:]))
	}
}

func TestNativeMutationBackendKeepsProtectionForIndeterminateNRPTRemove(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		errors: map[string]error{
			"remove_nrpt":               context.DeadlineExceeded,
			"cleanup_native_tombstones": errors.New("effective NRPT policy still present"),
		},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
	route := nativeTestRoute("r1")
	firewall := nativeTestFirewall("r1")
	nrpt := nativeTestNRPT("r1")
	nrpt.Rule.Name = "{11111111-2222-3333-4444-555555555555}"
	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{route}
	registry.Firewall = []nativeFirewallOwnership{{State: firewall, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}}
	registry.NRPT = []NRPTState{nrpt}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveNRPT(context.Background(), nrpt); err == nil {
		t.Fatal("indeterminate NRPT remove unexpectedly succeeded")
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 1 || registry.Tombstones[0].Kind != nativeTombstoneNRPT || registry.Tombstones[0].Action != nativeTombstoneRemove || registry.Tombstones[0].Phase != nativeFirewallPhaseCleanup || registry.Tombstones[0].BootID != testNativeBootID {
		t.Fatalf("NRPT remove tombstone = %#v", registry.Tombstones)
	}
	calls := len(runner.calls)
	if err := backend.RemoveRoute(context.Background(), route); err == nil || !strings.Contains(err.Error(), "protective state") {
		t.Fatalf("route teardown escaped NRPT remove quarantine: %v", err)
	}
	if err := backend.RemoveFirewall(context.Background(), firewall); err == nil || !strings.Contains(err.Error(), "protective state") {
		t.Fatalf("firewall teardown escaped NRPT remove quarantine: %v", err)
	}
	if len(runner.calls) != calls {
		t.Fatalf("protective teardown issued native calls: %v", nativeOperations(t, runner.calls[calls:]))
	}
}

func TestNativeMutationBackendClearsNRPTPutOnlyAfterRebootAndLocalEffectiveAbsence(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`)},
		errors:    map[string]error{"put_nrpt": context.DeadlineExceeded},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
	bootID := testNativeBootID
	backend.bootID = func() (string, error) { return bootID, nil }
	state := nativeTestNRPT("r1")
	if err := backend.PutNRPT(context.Background(), state); err == nil {
		t.Fatal("indeterminate NRPT put unexpectedly succeeded")
	}
	emptySnapshot := nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{}, []any{}, []any{}, []any{}, []any{},
	)
	runner.responses["snapshot"] = emptySnapshot
	if _, err := backend.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
		t.Fatalf("same-boot negative observation became terminal: %v", err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 1 || len(registry.NRPT) != 1 {
		t.Fatalf("same-boot negative observation cleared quarantine: %#v", registry)
	}

	bootID = testNativeNextBootID
	runner.responses["snapshot"] = nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{}, []any{}, []any{},
		[]any{map[string]any{"namespace": state.Rule.Namespace, "nameServers": state.Rule.NameServers}},
		[]any{},
	)
	if _, err := backend.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
		t.Fatalf("post-reboot effective policy became terminal: %v", err)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 1 || len(registry.NRPT) != 1 {
		t.Fatalf("post-reboot effective policy cleared quarantine: %#v", registry)
	}
	runner.responses["snapshot"] = emptySnapshot
	if _, err := backend.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 0 || len(registry.NRPT) != 0 {
		t.Fatalf("post-reboot local/effective absence did not clear quarantine: %#v", registry)
	}
}

func TestNativeMutationBackendClearsRoutePutOnlyAfterRebootAndStableGUIDAbsence(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"resolve_route_interface":   []byte(`{"version":1,"ok":true,"interface_index":77}`),
			"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`),
		},
		errors: map[string]error{"add_route": context.DeadlineExceeded},
	}
	backend := newTestNativeMutationBackend(t, runner)
	backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
	bootID := testNativeBootID
	backend.bootID = func() (string, error) { return bootID, nil }
	state := nativeTestRoute("r1")
	if err := backend.AddRoute(context.Background(), state); err == nil {
		t.Fatal("indeterminate route put unexpectedly succeeded")
	}
	emptySnapshot := nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet renamed", "description": "Intel Ethernet", "interfaceIndex": 77, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{}, []any{}, []any{}, []any{}, []any{},
	)
	runner.responses["snapshot"] = emptySnapshot
	if _, err := backend.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
		t.Fatalf("same-boot route absence became terminal: %v", err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 1 || registry.Tombstones[0].Route == nil || registry.Tombstones[0].Route.InterfaceIndex != 77 || len(registry.Routes) != 1 || registry.Routes[0].InterfaceIndex != state.InterfaceIndex {
		t.Fatalf("same-boot route quarantine lost invocation/plan identities: %#v", registry)
	}

	bootID = testNativeNextBootID
	if _, err := backend.Snapshot(context.Background()); err != nil {
		t.Fatalf("post-reboot stable-GUID absence did not become terminal: %v", err)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Tombstones) != 0 || len(registry.Routes) != 0 {
		t.Fatalf("post-reboot stable-GUID absence did not clear route quarantine: %#v", registry)
	}
}

func TestNativeMutationBackendLeavesOwnershipOnNativeFailureAndRedactsError(t *testing.T) {
	runner := &fakeNativeMutationRunner{
		responses: map[string][]byte{
			"resolve_route_interface": []byte(`{"version":1,"ok":true,"interface_index":12}`),
		},
		errors: map[string]error{"add_route": errors.New("provider-secret and raw command stderr")},
	}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestRoute("r1")
	err := backend.AddRoute(context.Background(), state)
	if err == nil || strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), "stderr") {
		t.Fatalf("redacted error = %v", err)
	}
	registry, readErr := backend.readRegistryLocked()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !containsNativeRoute(registry.Routes, state) {
		t.Fatal("ownership was discarded after an indeterminate native failure")
	}
}

func TestNativeMutationBackendRetainsEveryOwnershipRecordWhenRemovalIsIndeterminate(t *testing.T) {
	for _, kind := range []string{"route", "firewall", "nrpt"} {
		t.Run(kind, func(t *testing.T) {
			runner := &fakeNativeMutationRunner{err: errors.New("enumeration or removal failed")}
			backend := newTestNativeMutationBackend(t, runner)
			registry := emptyNativeOwnershipRegistry()
			route := nativeTestRoute("r1")
			firewall := nativeTestFirewall("r1")
			nrpt := nativeTestNRPT("r1")
			nrpt.Rule.Name = "{11111111-2222-3333-4444-555555555555}"
			registry.Routes = []RouteState{route}
			registry.Firewall = []nativeFirewallOwnership{{State: firewall, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Committed: true}}
			registry.NRPT = []NRPTState{nrpt}
			if err := backend.writeRegistryLocked(registry); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "route":
				err = backend.RemoveRoute(context.Background(), route)
			case "firewall":
				err = backend.RemoveFirewall(context.Background(), firewall)
			case "nrpt":
				err = backend.RemoveNRPT(context.Background(), nrpt)
			}
			if err == nil {
				t.Fatal("indeterminate native removal unexpectedly succeeded")
			}
			after, readErr := backend.readRegistryLocked()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !containsNativeRoute(after.Routes, route) || len(after.Firewall) != 1 || !containsNativeNRPT(after.NRPT, nrpt) {
				t.Fatalf("ownership was discarded after failed %s removal: %#v", kind, after)
			}
		})
	}
}

func TestNativeMutationBackendQuarantinesIndeterminateRemovalAcrossRestartAndBlocksReapply(t *testing.T) {
	for _, kind := range []string{nativeTombstoneRoute, nativeTombstoneFirewall, nativeTombstoneNRPT} {
		t.Run(kind, func(t *testing.T) {
			removeOperation := "remove_" + kind
			if kind == nativeTombstoneFirewall {
				removeOperation = "remove_firewall_batch"
			}
			runner := &fakeNativeMutationRunner{
				responses: map[string][]byte{
					"cleanup_native_tombstones": []byte(`{"version":1,"ok":true}`),
				},
				errors: map[string]error{removeOperation: context.DeadlineExceeded},
			}
			backend := newTestNativeMutationBackend(t, runner)
			backend.firewallCleanupWait = func(context.Context, time.Duration) error { return nil }
			registry := emptyNativeOwnershipRegistry()
			route := nativeTestRoute("r1")
			firewall := nativeTestFirewall("r1")
			nrpt := nativeTestNRPT("r1")
			nrpt.Rule.Name = "{11111111-2222-3333-4444-555555555555}"
			switch kind {
			case nativeTombstoneRoute:
				registry.Routes = []RouteState{route}
			case nativeTombstoneFirewall:
				registry.Firewall = []nativeFirewallOwnership{{State: firewall, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}}
			case nativeTombstoneNRPT:
				registry.NRPT = []NRPTState{nrpt}
			}
			if err := backend.writeRegistryLocked(registry); err != nil {
				t.Fatal(err)
			}

			intentObserved := false
			cleanupObserved := false
			runner.beforeRun = func(command nativeMutationCommand) {
				var request nativeMutationRequest
				if err := json.Unmarshal(command.Input, &request); err != nil {
					t.Fatal(err)
				}
				if request.Operation == "cleanup_native_tombstones" {
					if kind == nativeTombstoneFirewall {
						if len(request.FirewallBindings) != 1 || len(request.MutationTombstones) != 0 || request.FirewallBindings[0].State.Rule.Name != firewall.Rule.Name {
							t.Fatalf("firewall remove tombstone cleanup request = %#v", request)
						}
					} else if len(request.FirewallBindings) != 0 || len(request.MutationTombstones) != 1 || request.MutationTombstones[0].Kind != kind || request.MutationTombstones[0].Action != nativeTombstoneRemove {
						t.Fatalf("%s remove tombstone cleanup request = %#v", kind, request)
					}
					cleanupObserved = true
					return
				}
				if request.Operation != removeOperation {
					return
				}
				current, err := backend.readRegistryLocked()
				if err != nil {
					t.Fatal(err)
				}
				intentObserved = slices.ContainsFunc(current.Tombstones, func(tombstone nativeMutationTombstone) bool {
					return tombstone.Kind == kind && tombstone.Action == nativeTombstoneRemove && tombstone.Phase == nativeFirewallPhasePrepared
				})
			}
			var removeErr error
			switch kind {
			case nativeTombstoneRoute:
				removeErr = backend.RemoveRoute(context.Background(), route)
			case nativeTombstoneFirewall:
				removeErr = backend.RemoveFirewall(context.Background(), firewall)
			case nativeTombstoneNRPT:
				removeErr = backend.RemoveNRPT(context.Background(), nrpt)
			}
			if removeErr == nil || !intentObserved || !cleanupObserved {
				t.Fatalf("indeterminate %s removal: err=%v intentObserved=%v cleanupObserved=%v", kind, removeErr, intentObserved, cleanupObserved)
			}
			registry, err := backend.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 1 || registry.Tombstones[0].Kind != kind || registry.Tombstones[0].Action != nativeTombstoneRemove || registry.Tombstones[0].Phase != nativeFirewallPhaseWatch {
				t.Fatalf("durable remove quarantine = %#v", registry.Tombstones)
			}

			delete(runner.errors, removeOperation)
			callsBeforeReapply := len(runner.calls)
			var reapplyErr error
			switch kind {
			case nativeTombstoneRoute:
				reapplyErr = backend.AddRoute(context.Background(), route)
			case nativeTombstoneFirewall:
				reapplyErr = backend.PutFirewall(context.Background(), firewall)
			case nativeTombstoneNRPT:
				candidate := nrpt
				candidate.Rule.Name = ""
				reapplyErr = backend.PutNRPT(context.Background(), candidate)
			}
			if reapplyErr == nil || !strings.Contains(reapplyErr.Error(), "quarantined") {
				t.Fatalf("%s reapply escaped remove quarantine: %v", kind, reapplyErr)
			}
			for _, operation := range nativeOperations(t, runner.calls[callsBeforeReapply:]) {
				if operation != "cleanup_native_tombstones" {
					t.Fatalf("%s reapply issued unsafe native operation %q", kind, operation)
				}
			}

			effectiveFirewall := []any{}
			if kind == nativeTombstoneFirewall {
				effectiveFirewall = []any{map[string]any{"name": firewall.Rule.Name, "exact": false}}
			}
			runner.responses["snapshot"] = nativeSnapshotJSON(t,
				[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{}, []any{}, []any{}, []any{}, effectiveFirewall,
			)
			restarted, err := newNativeMutationBackend(backend.root, nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`}, runner, func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			restarted.bootID = backend.bootID
			restarted.firewallCleanupWait = backend.firewallCleanupWait
			if _, err := restarted.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "pending cleanup") {
				t.Fatalf("same-boot absent %s remove generation became terminal: %v", kind, err)
			}
			registry, err = restarted.readRegistryLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(registry.Tombstones) != 1 || registry.Tombstones[0].Action != nativeTombstoneRemove || registry.Tombstones[0].Phase != nativeFirewallPhaseWatch {
				t.Fatalf("restart dropped remove quarantine: %#v", registry.Tombstones)
			}
			if kind == nativeTombstoneRoute && !containsNativeRoute(registry.Routes, route) || kind == nativeTombstoneFirewall && len(registry.Firewall) != 1 || kind == nativeTombstoneNRPT && !containsNativeNRPT(registry.NRPT, nrpt) {
				t.Fatalf("restart dropped quarantined %s ownership: %#v", kind, registry)
			}
			operations := nativeOperations(t, runner.calls)
			removeCalls := 0
			for _, operation := range operations {
				if operation == removeOperation {
					removeCalls++
				}
			}
			if removeCalls != 1 {
				t.Fatalf("old %s remove generation was reissued %d times: %v", kind, removeCalls, operations)
			}
		})
	}
}

func TestNativeMutationScriptUsesStrictEnumerationAndRemovalPostChecks(t *testing.T) {
	if strings.Contains(nativeMutationScript, "-ErrorAction SilentlyContinue") {
		t.Fatal("native mutation script can hide enumeration failures")
	}
	for _, required := range []string{
		"route removal post-check failed",
		"firewall removal post-check failed",
		"NRPT removal post-check failed",
		"effective NRPT removal post-check failed",
		"effective NRPT cleanup delayed negative verification failed",
		"Resolve-RemovalInterfaceIndex",
		"Test-OwnedRouteIdentity $existing[0] $request.route",
		"Test-ExactRoute $existing[0] $request.route",
	} {
		if !strings.Contains(nativeMutationScript, required) {
			t.Fatalf("native mutation script lacks %q", required)
		}
	}
}

func TestNativeMutationScriptTombstoneRouteCleanupBindsStableAdapter(t *testing.T) {
	start := strings.Index(nativeMutationScript, "function Get-TombstonedRoute")
	finish := strings.Index(nativeMutationScript, "function Resolve-RemovalInterfaceIndex")
	if start < 0 || finish <= start {
		t.Fatal("route tombstone cleanup function is missing")
	}
	block := nativeMutationScript[start:finish]
	for _, required := range []string{
		"$currentIndex = Resolve-RemovalInterfaceIndex $state",
		"[int]$_.InterfaceIndex -eq $currentIndex",
		"[string]$_.DestinationPrefix -ceq [string]$state.destination",
		"[string]$_.NextHop -ceq [string]$state.next_hop",
	} {
		if !strings.Contains(block, required) {
			t.Fatalf("route tombstone cleanup is not exact to stable adapter: missing %q", required)
		}
	}
}

func TestNativeMutationBackendCanRemoveNRPTAfterCrashBeforeIdentityCommit(t *testing.T) {
	runner := &fakeNativeMutationRunner{response: []byte(`{"version":1,"ok":true}`)}
	backend := newTestNativeMutationBackend(t, runner)
	intent := nativeTestNRPT("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.NRPT = []NRPTState{intent}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	observed := intent
	observed.Rule.Name = "{11111111-2222-3333-4444-555555555555}"
	if err := backend.RemoveNRPT(context.Background(), observed); err != nil {
		t.Fatal(err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.NRPT) != 0 {
		t.Fatalf("NRPT intent remains after exact native removal: %#v", registry.NRPT)
	}
}

func TestNativeMutationBackendCarriesTwoOwnedNRPTRulesUntilPriorRevisionIsPruned(t *testing.T) {
	const oldName = "{11111111-2222-3333-4444-555555555555}"
	const newName = "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}"
	runner := &fakeNativeMutationRunner{responses: map[string][]byte{
		"put_nrpt":    []byte(`{"version":1,"ok":true,"nrpt_name":"` + newName + `"}`),
		"remove_nrpt": []byte(`{"version":1,"ok":true}`),
	}}
	backend := newTestNativeMutationBackend(t, runner)
	oldState := nativeTestNRPT("r1")
	oldState.Rule.Name = oldName
	newState := nativeTestNRPT("r2")
	registry := emptyNativeOwnershipRegistry()
	registry.NRPT = []NRPTState{oldState}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	if err := backend.PutNRPT(context.Background(), newState); err != nil {
		t.Fatal(err)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.NRPT) != 2 || !containsNativeNRPT(registry.NRPT, oldState) {
		t.Fatalf("additive NRPT replacement lost prior ownership: %#v", registry.NRPT)
	}
	newState.Rule.Name = newName
	if !containsNativeNRPT(registry.NRPT, newState) {
		t.Fatalf("new NRPT ownership was not committed: %#v", registry.NRPT)
	}
	if err := backend.RemoveNRPT(context.Background(), oldState); err != nil {
		t.Fatal(err)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.NRPT) != 1 || !containsNativeNRPT(registry.NRPT, newState) {
		t.Fatalf("prior NRPT revision was not pruned exactly: %#v", registry.NRPT)
	}
}

func TestNativeMutationBackendRejectsUnboundedOrMalformedResponse(t *testing.T) {
	tests := map[string][]byte{
		"unknown field": []byte(`{"version":1,"ok":true,"leak":"secret"}`),
		"trailing data": []byte(`{"version":1,"ok":true}{}`),
		"too large":     make([]byte, maxSnapshotBytes+1),
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &fakeNativeMutationRunner{response: response}
			backend := newTestNativeMutationBackend(t, runner)
			if err := backend.Reload(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("response error = %v", err)
			}
		})
	}
}

func TestNativeMutationBackendSnapshotUsesExactRegistryAndOSMarkers(t *testing.T) {
	runner := &fakeNativeMutationRunner{}
	backend := newTestNativeMutationBackend(t, runner)
	route := nativeTestRoute("r1")
	firewall := nativeTestFirewall("r1")
	nrpt := nativeTestNRPT("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{route}
	registry.Firewall = []nativeFirewallOwnership{{State: firewall, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Committed: true}}
	registry.NRPT = []NRPTState{nrpt}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"version": 1,
		"ok":      true,
		"snapshot": map[string]any{
			"adapters": []any{
				map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1},
				map[string]any{"name": "Cisco AnyConnect", "description": "Cisco Secure Client", "interfaceIndex": 31, "interfaceGuid": testCiscoGUID, "hardwareInterface": false, "adminStatus": 1, "operationalStatus": 1},
			},
			"compartments": []any{map[string]any{"compartmentId": 1}},
			"routes": []any{
				map[string]any{"interfaceIndex": 12, "compartmentId": 1, "addressFamily": 2, "destinationPrefix": route.Destination, "nextHop": route.NextHop, "routeMetric": route.Metric, "policyStore": RoutePolicyStore, "protocol": RouteProtocol, "state": 0},
				map[string]any{"interfaceIndex": 31, "compartmentId": 1, "addressFamily": 2, "destinationPrefix": "0.0.0.0/0", "nextHop": "0.0.0.0", "routeMetric": 1, "policyStore": RoutePolicyStore, "protocol": RouteProtocol, "state": 2},
			},
			"firewall": []any{
				map[string]any{"name": firewall.Rule.Name, "displayName": firewall.Rule.Name, "description": firewall.Rule.Description, "group": firewall.Rule.Group, "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{firewall.Rule.RemoteCIDR}, "interfaceAliases": []string{"Ethernet"}},
				map[string]any{"name": "home-gateway-foreign", "displayName": "foreign", "description": "foreign", "group": "foreign", "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{"203.0.113.0/24"}, "interfaceAliases": []string{"Ethernet"}},
			},
			"firewallEffective": []any{
				map[string]any{"name": firewall.Rule.Name, "exact": true},
			},
			"firewallProfiles":        defaultNativeFirewallProfiles(),
			"firewallBypassAbsent":    true,
			"firewallServicesRunning": true,
			"nrpt": []any{
				map[string]any{"name": "{11111111-2222-3333-4444-555555555555}", "displayName": nrpt.Rule.DisplayName, "namespace": nrpt.Rule.Namespace, "nameServers": nrpt.Rule.NameServers, "comment": nrpt.Rule.Comment},
			},
			"nrptEffective": []any{
				map[string]any{"namespace": nrpt.Rule.Namespace, "nameServers": nrpt.Rule.NameServers},
			},
		},
	}
	runner.response = mustNativeJSON(t, raw)
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Routes) != 2 || snapshot.Routes[0].Owner != ArtifactOwner && snapshot.Routes[1].Owner != ArtifactOwner {
		t.Fatalf("route ownership = %#v", snapshot.Routes)
	}
	if !slices.ContainsFunc(snapshot.Routes, func(state RouteState) bool {
		return state.Owner == "" && state.Protected && state.InterfaceGUID == testCiscoGUID && state.Destination == "0.0.0.0/0" && state.State == 2
	}) {
		t.Fatalf("retained down Cisco default was not preserved and protected: %#v", snapshot.Routes)
	}
	if !snapshot.FirewallEnforced || len(snapshot.Firewall) != 2 || !slices.ContainsFunc(snapshot.Firewall, func(state FirewallState) bool {
		return state.Owner == ArtifactOwner && state.Revision == "r1" && state.Effective
	}) || !slices.ContainsFunc(snapshot.Firewall, func(state FirewallState) bool { return state.Rule.Name == "home-gateway-foreign" && state.Owner == "" }) {
		t.Fatalf("firewall classification = %#v", snapshot.Firewall)
	}
	if len(snapshot.NRPT) != 1 || snapshot.NRPT[0].Owner != ArtifactOwner || snapshot.NRPT[0].Revision != "r1" || snapshot.NRPT[0].Rule.Name != "{11111111-2222-3333-4444-555555555555}" || snapshot.NRPT[0].Rule.LogicalID != nrpt.Rule.LogicalID || !snapshot.NRPT[0].Effective {
		t.Fatalf("NRPT classification = %#v", snapshot.NRPT)
	}
}

func TestNativeMutationBackendSnapshotReconcilesStaleAndIncompleteIntents(t *testing.T) {
	runner := &fakeNativeMutationRunner{}
	backend := newTestNativeMutationBackend(t, runner)
	route := nativeTestRoute("r1")
	route.Role = RouteRoleVPNClass
	route.Destination = "198.51.100.0/24"
	route.NextHop = "10.20.30.1"
	route.InterfaceGUID = testRedShieldGUID
	route.InterfaceIndex = 21
	staleRoute := route
	staleRoute.Destination = "192.0.2.0/24"

	firewall := nativeTestFirewall("r1")
	staleFirewall := nativeTestFirewall("r2")
	nrpt := nativeTestNRPT("r1")
	staleNRPT := nativeTestNRPT("r2")
	staleNRPT.Rule.LogicalID = "dns-v4-stale"
	staleNRPT.Rule.DisplayName = "hg-r2-dns-v4-stale"
	staleNRPT.Rule.Namespace = ".stale.vpn.example"

	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{route, staleRoute}
	registry.Firewall = []nativeFirewallOwnership{
		{State: firewall, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Committed: true},
		{State: staleFirewall, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Committed: true},
	}
	registry.NRPT = []NRPTState{nrpt, staleNRPT}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}

	nrptName := "{11111111-2222-3333-4444-555555555555}"
	runner.response = nativeSnapshotJSON(t,
		[]any{
			map[string]any{"name": "Renamed Ethernet", "description": "Intel Ethernet", "interfaceIndex": 77, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1},
			map[string]any{"name": "RedShield", "description": "AmneziaWG Tunnel", "interfaceIndex": 21, "interfaceGuid": testRedShieldGUID, "hardwareInterface": false, "adminStatus": 1, "operationalStatus": 1},
		},
		[]any{map[string]any{"interfaceIndex": 21, "addressFamily": 2, "destinationPrefix": route.Destination, "nextHop": route.NextHop, "routeMetric": route.Metric, "policyStore": route.PolicyStore, "protocol": route.Protocol, "state": 0}},
		[]any{map[string]any{"name": firewall.Rule.Name, "displayName": firewall.Rule.Name, "description": firewall.Rule.Description, "group": firewall.Rule.Group, "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{firewall.Rule.RemoteCIDR}, "interfaceAliases": []string{"Legacy Ethernet"}}},
		[]any{map[string]any{"name": nrptName, "displayName": nrpt.Rule.DisplayName, "namespace": nrpt.Rule.Namespace, "nameServers": nrpt.Rule.NameServers, "comment": nrpt.Rule.Comment}},
		[]any{map[string]any{"namespace": nrpt.Rule.Namespace, "nameServers": nrpt.Rule.NameServers}},
		[]any{
			map[string]any{"name": firewall.Rule.Name, "exact": true},
			map[string]any{"name": staleFirewall.Rule.Name, "exact": false},
		},
	)
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Routes) != 1 || snapshot.Routes[0] != route {
		t.Fatalf("reconciled route snapshot = %#v", snapshot.Routes)
	}
	if len(snapshot.Firewall) != 1 || snapshot.Firewall[0].Rule != firewall.Rule || snapshot.Firewall[0].Owner != firewall.Owner || snapshot.Firewall[0].Revision != firewall.Revision || !snapshot.Firewall[0].Effective {
		t.Fatalf("firewall identity did not survive adapter rename/reindex: %#v", snapshot.Firewall)
	}
	if len(snapshot.NRPT) != 1 || snapshot.NRPT[0].Owner != ArtifactOwner || snapshot.NRPT[0].Rule.Name != nrptName || !snapshot.NRPT[0].Effective {
		t.Fatalf("reconciled NRPT snapshot = %#v", snapshot.NRPT)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Routes) != 1 || registry.Routes[0] != route || len(registry.Firewall) != 1 || registry.Firewall[0].State != firewall || registry.Firewall[0].InterfaceAlias != "Legacy Ethernet" || registry.Firewall[0].InterfacePattern != "Legacy Ethernet" || !registry.Firewall[0].Committed || len(registry.NRPT) != 1 || registry.NRPT[0].Rule.Name != nrptName {
		t.Fatalf("reconciled ownership registry = %#v", registry)
	}
}

func TestNativeMutationBackendMigratesStableGUIDFirewallAliasAndRuntimeSeesEffectiveRule(t *testing.T) {
	oldState := nativeTestFirewall("r1")
	newState := oldState
	newState.Rule.InterfaceIndex = 77
	model := &modeledFirewallMigration{
		adapterAlias:    "Renamed [LAN]*",
		adapterIndex:    77,
		interfaceGUID:   testPhysicalGUID,
		firewallPattern: "Legacy Ethernet",
		state:           oldState,
	}
	runner := model.runner(t)
	backend := newTestNativeMutationBackend(t, runner)
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{{State: oldState, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}

	before, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Firewall) != 1 || before.Firewall[0].Owner != ArtifactOwner || before.Firewall[0].Effective {
		t.Fatalf("renamed adapter should make prior binding owned but ineffective: %#v", before.Firewall)
	}
	if err := backend.PutFirewall(context.Background(), newState); err != nil {
		t.Fatal(err)
	}
	if model.firewallPattern != escapePowerShellWildcard(model.adapterAlias) || model.setCalls != 1 {
		t.Fatalf("owned alias was not updated in place: pattern=%q setCalls=%d", model.firewallPattern, model.setCalls)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 1 || registry.Firewall[0].State != newState || registry.Firewall[0].InterfaceAlias != model.adapterAlias || registry.Firewall[0].PreviousInterfaceAlias != "" || registry.Firewall[0].Phase != nativeFirewallPhaseApplied || !registry.Firewall[0].Committed {
		t.Fatalf("migrated registry binding = %#v", registry.Firewall)
	}
	after, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := FirewallArtifact{Version: ArtifactVersion, Owner: ArtifactOwner, Revision: "r1", Rules: []FirewallRule{newState.Rule}}
	if err := requireCandidateFirewallPresent(after, artifact); err != nil {
		t.Fatalf("runtime rejected parser-observed migrated effective firewall: %v, snapshot=%#v", err, after.Firewall)
	}
}

func TestNativeMutationBackendNeverMigratesForeignFirewallCollision(t *testing.T) {
	oldState := nativeTestFirewall("r1")
	newState := oldState
	newState.Rule.InterfaceIndex = 77
	model := &modeledFirewallMigration{
		adapterAlias:    "Renamed Ethernet",
		adapterIndex:    77,
		interfaceGUID:   testPhysicalGUID,
		firewallPattern: "Legacy Ethernet",
		state:           oldState,
		foreign:         true,
	}
	backend := newTestNativeMutationBackend(t, model.runner(t))
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{{State: oldState, InterfaceAlias: "Legacy Ethernet", InterfacePattern: "Legacy Ethernet", Phase: nativeFirewallPhaseApplied, Committed: true}}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}

	if err := backend.PutFirewall(context.Background(), newState); err == nil {
		t.Fatal("foreign same-name firewall collision was migrated")
	}
	if model.setCalls != 0 || model.firewallPattern != "Legacy Ethernet" {
		t.Fatalf("foreign firewall was changed: setCalls=%d pattern=%q", model.setCalls, model.firewallPattern)
	}
	registry, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 1 || registry.Firewall[0].Phase != nativeFirewallPhaseCleanup || registry.Firewall[0].PreviousInterfaceAlias != "Legacy Ethernet" {
		t.Fatalf("foreign collision did not retain exact cleanup ownership: %#v", registry.Firewall)
	}
}

func TestNativeMutationScriptUsesExactGaplessFirewallAliasMigration(t *testing.T) {
	putStart := strings.Index(nativeMutationScript, "'put_firewall_batch'")
	removeStart := strings.Index(nativeMutationScript, "'remove_firewall_batch'")
	if putStart < 0 || removeStart <= putStart {
		t.Fatal("native firewall batch operations are missing")
	}
	putBlock := nativeMutationScript[putStart:removeStart]
	for _, required := range []string{"previous_interface_pattern", "Test-ExactFirewall $existing[0] $state $previousPattern $false", "Set-NetFirewallRule -InputObject $item.current -InterfaceAlias $pattern", "firewall ownership collision"} {
		if !strings.Contains(putBlock, required) {
			t.Fatalf("native alias migration lacks %q", required)
		}
	}
	if strings.Contains(putBlock, "Remove-NetFirewallRule") {
		t.Fatal("native alias migration creates a fail-open remove/recreate gap")
	}
}

func TestNativeMutationBackendPreservesForeignFirewallCollision(t *testing.T) {
	runner := &fakeNativeMutationRunner{}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestFirewall("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Firewall = []nativeFirewallOwnership{{State: state, InterfaceAlias: "Ethernet", InterfacePattern: "Ethernet", Committed: true}}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	runner.response = nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{},
		[]any{map[string]any{"name": state.Rule.Name, "displayName": state.Rule.Name, "description": "foreign content", "group": state.Rule.Group, "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{state.Rule.RemoteCIDR}, "interfaceAliases": []string{"Ethernet"}}},
		[]any{},
		[]any{},
		[]any{map[string]any{"name": state.Rule.Name, "exact": false}},
	)
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Firewall) != 1 || snapshot.Firewall[0].Owner != "" || snapshot.Firewall[0].Rule.Name != state.Rule.Name {
		t.Fatalf("foreign firewall collision classification = %#v", snapshot.Firewall)
	}
	registry, err = backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Firewall) != 0 {
		t.Fatalf("foreign collision retained ownership: %#v", registry.Firewall)
	}
	callCount := len(runner.calls)
	if err := backend.RemoveFirewall(context.Background(), state); err == nil || len(runner.calls) != callCount {
		t.Fatalf("foreign collision removal: err=%v calls=%d", err, len(runner.calls))
	}
}

func TestNativeMutationBackendSeparatesLocalAndEffectiveNRPTState(t *testing.T) {
	runner := &fakeNativeMutationRunner{responses: map[string][]byte{"remove_nrpt": []byte(`{"version":1,"ok":true}`)}}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestNRPT("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.NRPT = []NRPTState{state}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	nativeName := "{11111111-2222-3333-4444-555555555555}"
	runner.responses["snapshot"] = nativeSnapshotJSON(t,
		[]any{map[string]any{"name": "Ethernet", "description": "Intel Ethernet", "interfaceIndex": 12, "interfaceGuid": testPhysicalGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
		[]any{},
		[]any{},
		[]any{map[string]any{"name": nativeName, "displayName": state.Rule.DisplayName, "namespace": state.Rule.Namespace, "nameServers": state.Rule.NameServers, "comment": state.Rule.Comment}},
		[]any{map[string]any{"namespace": state.Rule.Namespace, "nameServers": []string{"203.0.113.53"}}},
		[]any{},
	)
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.NRPT) != 1 || snapshot.NRPT[0].Owner != ArtifactOwner || snapshot.NRPT[0].Effective || snapshot.NRPT[0].Rule.Name != nativeName {
		t.Fatalf("configured/effective NRPT separation = %#v", snapshot.NRPT)
	}
	if err := backend.RemoveNRPT(context.Background(), snapshot.NRPT[0]); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("snapshot/removal calls = %d", len(runner.calls))
	}
	var request nativeMutationRequest
	if err := json.Unmarshal(runner.calls[1].Input, &request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != "remove_nrpt" || request.NRPT == nil || request.NRPT.Rule.Name != nativeName {
		t.Fatalf("exact local NRPT recovery request = %#v", request)
	}
}

func TestNativeMutationBackendRejectsForeignRemovalAndCorruptRegistry(t *testing.T) {
	runner := &fakeNativeMutationRunner{response: []byte(`{"version":1,"ok":true}`)}
	backend := newTestNativeMutationBackend(t, runner)
	state := nativeTestRoute("r1")
	if err := backend.RemoveRoute(context.Background(), state); err == nil || len(runner.calls) != 0 {
		t.Fatalf("unregistered removal result: err=%v calls=%d", err, len(runner.calls))
	}
	if err := os.WriteFile(backend.registryPath(), []byte(`{"version":1,"routes":[],"nrpt":[],"sha256":"00"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Snapshot(context.Background()); err == nil || len(runner.calls) != 0 {
		t.Fatalf("corrupt registry result: err=%v calls=%d", err, len(runner.calls))
	}
}

func TestNativeMutationBackendRecoversOnlyValidReplacementBackup(t *testing.T) {
	backend := newTestNativeMutationBackend(t, &fakeNativeMutationRunner{})
	state := nativeTestRoute("r1")
	registry := emptyNativeOwnershipRegistry()
	registry.Routes = []RouteState{state}
	if err := backend.writeRegistryLocked(registry); err != nil {
		t.Fatal(err)
	}
	backup := backend.registryPath() + nativeReplaceBackupSuffix
	if err := os.Rename(backend.registryPath(), backup); err != nil {
		t.Fatal(err)
	}

	recovered, err := backend.readRegistryLocked()
	if err != nil {
		t.Fatal(err)
	}
	if !containsNativeRoute(recovered.Routes, state) {
		t.Fatalf("replacement backup records were not recovered: %#v", recovered)
	}
	if _, err := os.Lstat(backend.registryPath()); err != nil {
		t.Fatalf("recovered registry destination: %v", err)
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement backup remains after recovery: %v", err)
	}
}

func TestNativeMutationBackendFailsClosedForInvalidOrAmbiguousReplacementBackup(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testing.T, *nativeMutationBackend, string)
	}{
		{name: "corrupt", configure: func(t *testing.T, _ *nativeMutationBackend, backup string) {
			if err := os.WriteFile(backup, []byte("not-json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonregular", configure: func(t *testing.T, _ *nativeMutationBackend, backup string) {
			if err := os.Mkdir(backup, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "ambiguous", configure: func(t *testing.T, backend *nativeMutationBackend, backup string) {
			registry := emptyNativeOwnershipRegistry()
			registry.Routes = []RouteState{nativeTestRoute("r1")}
			if err := backend.writeRegistryLocked(registry); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backend.registryPath(), backup); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(backend.registryPath()+".next", []byte("another generation\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := newTestNativeMutationBackend(t, &fakeNativeMutationRunner{})
			backup := backend.registryPath() + nativeReplaceBackupSuffix
			test.configure(t, backend, backup)
			if _, err := backend.readRegistryLocked(); err == nil {
				t.Fatal("invalid replacement backup was treated as an empty registry")
			}
		})
	}
}

func TestNativeMutationBackendRejectsAnyUnprivilegedRootAccess(t *testing.T) {
	tests := map[string]string{
		"Everyone":            `D:P(A;;GA;;;WD)`,
		"Builtin Users":       `D:P(A;;GW;;;BU)`,
		"Authenticated Users": `D:P(A;;FA;;;AU)`,
		"Local Service":       `D:P(A;;GW;;;LS)`,
	}
	for name, sddl := range tests {
		t.Run(name, func(t *testing.T) {
			descriptor, err := xwindows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNativePrivilegedDACL(dacl); err == nil {
				t.Fatal("unprivileged DACL unexpectedly passed")
			}
		})
	}
	safeDescriptor, err := xwindows.SecurityDescriptorFromString(`D:P(A;;FA;;;SY)(A;;FA;;;BA)`)
	if err != nil {
		t.Fatal(err)
	}
	safeDACL, _, err := safeDescriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNativePrivilegedDACL(safeDACL); err != nil {
		t.Fatalf("narrow administrative DACL was rejected: %v", err)
	}
}

func TestNativeMutationBackendRequiresProtectedPrivilegedOwner(t *testing.T) {
	tests := []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{name: "SYSTEM owner", sddl: `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`},
		{name: "Administrators owner", sddl: `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`},
		{name: "untrusted read", sddl: `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`, wantErr: true},
		{name: "untrusted owner", sddl: `O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: true},
		{name: "inherited DACL", sddl: `O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := xwindows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validateProtectedNativeSecurityDescriptor(descriptor)
			if (err != nil) != test.wantErr {
				t.Fatalf("security descriptor validation error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestNativeMutationBackendFailsClosedWhenRootValidatorRejects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeNativeMutationRunner{response: []byte(`{"version":1,"ok":true}`)}
	_, err := newNativeMutationBackend(
		root,
		nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`},
		runner,
		func(string) error { return errors.New("root DACL is not protected") },
	)
	if err == nil || len(runner.calls) != 0 {
		t.Fatalf("unsafe root result: err=%v calls=%d", err, len(runner.calls))
	}
}

func newTestNativeMutationBackend(t *testing.T, runner nativeMutationRunner) *nativeMutationBackend {
	t.Helper()
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	backend, err := newNativeMutationBackend(root, nativeInventoryPaths{WindowsDirectory: `C:\Windows`, SystemDirectory: `C:\Windows\System32`}, runner, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	backend.bootID = func() (string, error) { return testNativeBootID, nil }
	return backend
}

func nativeTestRoute(revision string) RouteState {
	return RouteState{ManagedRoute: ManagedRoute{
		Role: RouteRoleEndpointDirect, Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore, Protocol: RouteProtocol, JournalOwned: true,
	}, Owner: ArtifactOwner, Revision: revision}
}

func nativeTestFirewall(revision string) FirewallState {
	rule := FirewallRule{Family: FamilyIPv4, RemoteCIDR: "198.51.100.0/24", Action: "block", Direction: "outbound", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, PolicyStore: FirewallPolicyStore, Group: ownershipGroup(revision), Description: ownershipDescription(revision)}
	rule.Name = FirewallRuleName(revision, rule.Family, rule.RemoteCIDR, rule.InterfaceGUID)
	return FirewallState{Rule: rule, Owner: ArtifactOwner, Revision: revision}
}

func nativeHostFirewallBatch(revision string, ruleCount, adapterCount int) ([]FirewallState, []nativeFirewallOwnership) {
	states := make([]FirewallState, 0, ruleCount)
	bindings := make([]nativeFirewallOwnership, 0, ruleCount)
	for index := 0; index < ruleCount; index++ {
		adapter := index % adapterCount
		guid := fmt.Sprintf("00000000-0000-4000-8000-%012x", adapter+1)
		remote := fmt.Sprintf("198.18.%d.%d/32", index/256, index%256)
		rule := FirewallRule{
			Family: FamilyIPv4, RemoteCIDR: remote, Action: "block", Direction: "outbound",
			InterfaceGUID: guid, InterfaceIndex: 100 + adapter, PolicyStore: FirewallPolicyStore,
			Group: ownershipGroup(revision), Description: ownershipDescription(revision),
		}
		rule.Name = FirewallRuleName(revision, rule.Family, rule.RemoteCIDR, rule.InterfaceGUID)
		state := FirewallState{Rule: rule, Owner: ArtifactOwner, Revision: revision}
		alias := fmt.Sprintf("Adapter [%02d]*", adapter+1)
		states = append(states, state)
		bindings = append(bindings, nativeFirewallOwnership{State: state, InterfaceAlias: alias, InterfacePattern: escapePowerShellWildcard(alias)})
	}
	return states, bindings
}

func assertNativeOperation(t *testing.T, call nativeMutationCommand, operation string, firewallCount, bindingCount int) {
	t.Helper()
	var request nativeMutationRequest
	if err := json.Unmarshal(call.Input, &request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != operation || len(request.Firewalls) != firewallCount || len(request.FirewallBindings) != bindingCount {
		t.Fatalf("native operation = %#v, want operation=%s firewalls=%d bindings=%d", request, operation, firewallCount, bindingCount)
	}
}

func nativeOperations(t *testing.T, calls []nativeMutationCommand) []string {
	t.Helper()
	operations := make([]string, 0, len(calls))
	for _, call := range calls {
		var request nativeMutationRequest
		if err := json.Unmarshal(call.Input, &request); err != nil {
			t.Fatal(err)
		}
		operations = append(operations, request.Operation)
	}
	return operations
}

type modeledFirewallMigration struct {
	adapterAlias    string
	adapterIndex    int
	interfaceGUID   string
	firewallPattern string
	state           FirewallState
	foreign         bool
	setCalls        int
}

func (model *modeledFirewallMigration) runner(t *testing.T) *fakeNativeMutationRunner {
	t.Helper()
	runner := &fakeNativeMutationRunner{responses: make(map[string][]byte), errors: make(map[string]error)}
	runner.beforeRun = func(command nativeMutationCommand) {
		var request nativeMutationRequest
		if err := json.Unmarshal(command.Input, &request); err != nil {
			t.Fatal(err)
		}
		delete(runner.errors, request.Operation)
		switch request.Operation {
		case "snapshot":
			exact := false
			if len(request.FirewallExpectations) == 1 {
				expectation := request.FirewallExpectations[0]
				exact = !model.foreign && expectation.InterfaceAlias == model.adapterAlias && expectation.InterfacePattern == model.firewallPattern && nativeFirewallMigrationCompatible(expectation.State, model.state)
			}
			description := model.state.Rule.Description
			if model.foreign {
				description = "foreign content"
			}
			runner.responses[request.Operation] = nativeSnapshotJSON(t,
				[]any{map[string]any{"name": model.adapterAlias, "description": "Intel Ethernet", "interfaceIndex": model.adapterIndex, "interfaceGuid": model.interfaceGUID, "hardwareInterface": true, "adminStatus": 1, "operationalStatus": 1}},
				[]any{},
				[]any{map[string]any{"name": model.state.Rule.Name, "displayName": model.state.Rule.Name, "description": description, "group": model.state.Rule.Group, "enabled": "True", "direction": "Outbound", "action": "Block", "remoteAddresses": []string{model.state.Rule.RemoteCIDR}, "interfaceAliases": []string{model.firewallPattern}}},
				[]any{}, []any{},
				[]any{map[string]any{"name": model.state.Rule.Name, "exact": exact}},
			)
		case "resolve_firewall_batch":
			if len(request.Firewalls) != 1 || request.Firewalls[0].Rule.InterfaceGUID != model.interfaceGUID || request.Firewalls[0].Rule.InterfaceIndex != model.adapterIndex {
				t.Fatalf("stable GUID resolve request = %#v", request.Firewalls)
			}
			binding := nativeFirewallOwnership{State: request.Firewalls[0], InterfaceAlias: model.adapterAlias, InterfacePattern: escapePowerShellWildcard(model.adapterAlias)}
			runner.responses[request.Operation] = mustNativeJSON(t, map[string]any{"version": 1, "ok": true, "firewall_bindings": []nativeFirewallOwnership{binding}})
		case "put_firewall_batch":
			if len(request.FirewallBindings) != 1 {
				t.Fatalf("migration bindings = %#v", request.FirewallBindings)
			}
			binding := request.FirewallBindings[0]
			if binding.PreviousInterfaceAlias != "Legacy Ethernet" || binding.PreviousInterfacePattern != "Legacy Ethernet" || binding.InterfaceAlias != model.adapterAlias || binding.Phase != nativeFirewallPhasePrepared {
				t.Fatalf("exact migration authorization = %#v", binding)
			}
			if model.foreign {
				runner.errors[request.Operation] = errors.New("foreign firewall collision")
				return
			}
			model.firewallPattern = binding.InterfacePattern
			model.state = binding.State
			model.setCalls++
			runner.responses[request.Operation] = []byte(`{"version":1,"ok":true}`)
		case "cleanup_native_tombstones":
			if model.foreign {
				runner.errors[request.Operation] = errors.New("foreign firewall cleanup collision")
				return
			}
			runner.responses[request.Operation] = []byte(`{"version":1,"ok":true}`)
		}
	}
	return runner
}

func nativeTestNRPT(revision string) NRPTState {
	return NRPTState{Rule: NRPTRule{LogicalID: "dns-v4", DisplayName: "hg-" + revision + "-dns-v4", Namespace: ".vpn.example", NameServers: []string{"198.51.100.53"}, Comment: ownershipDescription(revision)}, Owner: ArtifactOwner, Revision: revision}
}

func mustNativeJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func nativeSnapshotJSON(t *testing.T, adapters, routes, firewall, nrpt, effective, effectiveFirewall []any) []byte {
	t.Helper()
	for _, value := range routes {
		if record, ok := value.(map[string]any); ok {
			record["compartmentId"] = 1
		}
	}
	return mustNativeJSON(t, map[string]any{
		"version": 1,
		"ok":      true,
		"snapshot": map[string]any{
			"adapters":                adapters,
			"compartments":            []any{map[string]any{"compartmentId": 1}},
			"routes":                  routes,
			"firewall":                firewall,
			"firewallEffective":       effectiveFirewall,
			"firewallProfiles":        defaultNativeFirewallProfiles(),
			"firewallBypassAbsent":    true,
			"firewallServicesRunning": true,
			"nrpt":                    nrpt,
			"nrptEffective":           effective,
		},
	})
}

func defaultNativeFirewallProfiles() []any {
	return []any{
		map[string]any{"name": "Domain", "enabled": true, "localRulesAllowed": true},
		map[string]any{"name": "Private", "enabled": true, "localRulesAllowed": true},
		map[string]any{"name": "Public", "enabled": true, "localRulesAllowed": true},
	}
}
