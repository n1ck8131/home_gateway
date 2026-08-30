package hgctlcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

type commandMutationBackend struct {
	mu       sync.Mutex
	state    windowssystem.MutationSnapshot
	failCall string
}

type blockingDisarmWatchdog struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type trackingPersistentWatchdog struct {
	recovery  bool
	reconcile bool
	arms      int
	commits   int
	disarms   int
}

func exactFullRestoreCommand(t *testing.T, root string, dependencies dependencies) canaryLiveCommand {
	t.Helper()
	seedFullRestoreIdentityFiles(t, root)
	journal, err := (apply.FileJournal{Path: filepath.Join(root, "journal.json")}).Load()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := newRecoveryTransactionLocked(root, journal, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if preflighter, ok := tx.Runtime.(apply.RecoveryPreflighter); ok {
		if err := preflighter.PreflightRecovery(t.Context(), journal); err != nil {
			t.Fatal(err)
		}
	}
	planner, ok := tx.Runtime.(interface {
		PlanFullRestore(context.Context, apply.Journal) (windowssystem.FullRestorePlan, error)
	})
	if !ok {
		t.Fatal("exact full restore planner is unavailable")
	}
	plan, err := planner.PlanFullRestore(t.Context(), journal)
	if err != nil {
		t.Fatal(err)
	}
	return canaryLiveCommand{
		action:             "full-restore",
		plan:               canaryPlanCommand{stateRoot: root},
		recoveryConfirm:    plan.ConfirmationChallenge(root),
		recoveryPlanSHA256: plan.IdentitySHA256(),
	}
}

func seedFullRestoreIdentityFiles(t *testing.T, root string) {
	t.Helper()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hgctl.exe", "p35-canary.ps1", "p35-bootstrap.ps1", "p35-bootstrap-elevated.ps1"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("synthetic-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "boot-marker.v1.json"), []byte(`{"boot":"synthetic"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "native-ownership.v1.json"), []byte(`{"version":1,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "source.conf")
	config := []byte("[synthetic-profile]")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	configDigest := sha256.Sum256(config)
	binding := map[string]any{
		"version": 1, "config_path": configPath, "config_sha256": fmt.Sprintf("%x", configDigest[:]),
		"volume_serial": "00000000", "file_index": "0000000000000000", "sddl": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
	}
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config-source-before.v1.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (watchdog *blockingDisarmWatchdog) Arm(time.Time, func()) (func(), error) {
	return func() {}, nil
}

func (*blockingDisarmWatchdog) Commit() error { return nil }

func (watchdog *blockingDisarmWatchdog) Disarm() error {
	watchdog.once.Do(func() { close(watchdog.entered) })
	<-watchdog.release
	return nil
}

func (watchdog *trackingPersistentWatchdog) Arm(time.Time, func()) (func(), error) {
	watchdog.arms++
	watchdog.recovery = true
	return func() {}, nil
}

func (watchdog *trackingPersistentWatchdog) Commit() error {
	watchdog.commits++
	watchdog.recovery = false
	watchdog.reconcile = true
	return nil
}

func (watchdog *trackingPersistentWatchdog) Disarm() error {
	watchdog.disarms++
	watchdog.recovery = false
	watchdog.reconcile = false
	return nil
}

func (backend *commandMutationBackend) Snapshot(context.Context) (windowssystem.MutationSnapshot, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	data, _ := json.Marshal(backend.state)
	var clone windowssystem.MutationSnapshot
	_ = json.Unmarshal(data, &clone)
	return clone, nil
}

func (backend *commandMutationBackend) AddRoute(_ context.Context, state windowssystem.RouteState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.Routes = slices.DeleteFunc(backend.state.Routes, func(current windowssystem.RouteState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.ManagedRoute == state.ManagedRoute
	})
	backend.state.Routes = append(backend.state.Routes, state)
	return nil
}

func (backend *commandMutationBackend) RemoveRoute(_ context.Context, state windowssystem.RouteState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.Routes = slices.DeleteFunc(backend.state.Routes, func(current windowssystem.RouteState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.ManagedRoute == state.ManagedRoute
	})
	return nil
}

func (backend *commandMutationBackend) PutSink(_ context.Context, state windowssystem.SinkState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.failCall == "put-sink:"+state.Route.Destination {
		return errors.New("persistent sink fault")
	}
	backend.state.Sinks = slices.DeleteFunc(backend.state.Sinks, func(current windowssystem.SinkState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Route == state.Route
	})
	state.PersistentPresent = true
	state.ActivePresent = true
	backend.state.Sinks = append(backend.state.Sinks, state)
	return nil
}

func (backend *commandMutationBackend) RemoveSink(_ context.Context, state windowssystem.SinkState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.failCall == "remove-sink:"+state.Route.Destination {
		return errors.New("persistent sink fault")
	}
	backend.state.Sinks = slices.DeleteFunc(backend.state.Sinks, func(current windowssystem.SinkState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Route == state.Route
	})
	return nil
}

func (backend *commandMutationBackend) ResolveRoute(_ context.Context, family windowssystem.AddressFamily, destination string) (windowssystem.ResolvedRoute, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	for _, route := range backend.state.Routes {
		if route.Owner == windowssystem.ArtifactOwner && route.Family == family && route.Destination == destination && route.Role == windowssystem.RouteRoleVPNClass {
			return windowssystem.ResolvedRoute{Family: family, Destination: destination, InterfaceGUID: route.InterfaceGUID, InterfaceIndex: route.InterfaceIndex, NextHop: route.NextHop, RouteMetric: route.Metric}, nil
		}
	}
	for _, sink := range backend.state.Sinks {
		if sink.Owner == windowssystem.ArtifactOwner && sink.Route.Family == family && sink.Route.Destination == destination && sink.PersistentPresent && sink.ActivePresent {
			return windowssystem.ResolvedRoute{Family: family, Destination: destination, InterfaceIndex: sink.Route.InterfaceIndex, NextHop: sink.Route.NextHop, RouteMetric: sink.Route.Metric}, nil
		}
	}
	return windowssystem.ResolvedRoute{Family: family, Destination: destination, NoRoute: true}, nil
}

func (backend *commandMutationBackend) PutFirewall(_ context.Context, state windowssystem.FirewallState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.Firewall = slices.DeleteFunc(backend.state.Firewall, func(current windowssystem.FirewallState) bool { return current.Rule.Name == state.Rule.Name })
	state.Effective = true
	backend.state.Firewall = append(backend.state.Firewall, state)
	backend.state.FirewallEnforced = true
	return nil
}

func (backend *commandMutationBackend) RemoveFirewall(_ context.Context, state windowssystem.FirewallState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.Firewall = slices.DeleteFunc(backend.state.Firewall, func(current windowssystem.FirewallState) bool {
		return current.Rule.Name == state.Rule.Name && current.Owner == state.Owner
	})
	return nil
}

func (backend *commandMutationBackend) PutNRPT(_ context.Context, state windowssystem.NRPTState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.NRPT = slices.DeleteFunc(backend.state.NRPT, func(current windowssystem.NRPTState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Rule.LogicalID == state.Rule.LogicalID
	})
	state.Rule.Name = "native-p35-canary-dns"
	state.Effective = true
	backend.state.NRPT = append(backend.state.NRPT, state)
	return nil
}

func (backend *commandMutationBackend) RemoveNRPT(_ context.Context, state windowssystem.NRPTState) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.state.NRPT = slices.DeleteFunc(backend.state.NRPT, func(current windowssystem.NRPTState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Rule.LogicalID == state.Rule.LogicalID
	})
	return nil
}

func (*commandMutationBackend) Reload(context.Context) error { return nil }

func TestRunCanaryLiveRejectsIsolationBeforeMutation(t *testing.T) {
	inspection, inventory := commandCanaryInputs()
	inventory.Adapters = append(inventory.Adapters, windowssystem.Adapter{
		Name: "Cisco", Index: 31, InterfaceGUID: commandCiscoGUID,
		Kind: windowssystem.AdapterCisco, Up: true,
	})
	inventory.Routes = append(inventory.Routes, windowssystem.Route{
		Family: windowssystem.FamilyIPv4, Destination: "10.20.30.0/24",
		NextHop: "0.0.0.0", InterfaceIndex: 31,
		InterfaceGUID: commandCiscoGUID, Metric: 1,
	})
	for _, action := range []string{"apply", "confirm"} {
		t.Run(action, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			mutationCalls := 0
			deps := dependencies{
				backend: staticInspectionBackend{inspection: inspection},
				collect: staticCollector{inventory: inventory},
				resolve: func(context.Context, string) ([]string, error) {
					return []string{"203.0.113.5"}, nil
				},
				validateStateRoot:    func(string) error { return nil },
				validateConfigSource: func(string) error { return nil },
				newMutation: func(string) (windowssystem.MutationBackend, error) {
					mutationCalls++
					return nil, errors.New("must not construct mutation backend")
				},
			}
			command := canaryLiveCommand{
				action: action,
				plan: canaryPlanCommand{
					configPath:   `C:\private-provider-source.conf`,
					configSHA256: strings.Repeat("a", 64),
					stateRoot:    root,
					revision:     "p35-canary-blocked",
					targets:      []string{"198.51.100.10"},
					dnsNamespace: windowssystem.CanaryDNSNamespace,
				},
				liveConfirm: "P35-APPLY-DOES-NOT-EXIST",
			}
			var stdout, stderr bytes.Buffer
			if code := runCanaryLive(command, &stdout, &stderr, deps); code != 3 {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if mutationCalls != 0 || stdout.Len() != 0 {
				t.Fatalf("mutation calls = %d, stdout = %q", mutationCalls, stdout.String())
			}
			if stderr.String() != "windows canary plan blocked: canary target isolation failed\n" {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("blocked live command created state root: %v", err)
			}
			for _, forbidden := range []string{command.plan.configPath, command.plan.configSHA256, root, "10.20.30.1", "10.20.30.0/24", "203.0.113.5", "198.51.100.10", "Cisco", commandCiscoGUID} {
				if strings.Contains(stderr.String(), forbidden) {
					t.Fatalf("blocked live stderr leaked %q", forbidden)
				}
			}
		})
	}
}

func TestRunCanaryLiveAppliesConfirmsAndFullyRestoresFakeWindowsState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	inspection, inventory := commandCanaryInputs()
	backend := &commandMutationBackend{state: commandMutationState(inventory)}
	deps := dependencies{
		backend:              staticInspectionBackend{inspection: inspection},
		collect:              staticCollector{inventory: inventory},
		resolve:              func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil },
		newMutation:          func(string) (windowssystem.MutationBackend, error) { return backend, nil },
		watchdog:             apply.TimerWatchdog{},
		validateStateRoot:    func(string) error { return nil },
		validateConfigSource: func(string) error { return nil },
	}
	planCommand := canaryPlanCommand{
		configPath:   `C:\private-provider-source.conf`,
		stateRoot:    root,
		revision:     "p35-canary-001",
		targets:      []string{"198.51.100.10"},
		dnsNamespace: windowssystem.CanaryDNSNamespace,
	}
	plan, _, err := collectCanaryPlan(t.Context(), planCommand, deps)
	if err != nil {
		t.Fatal(err)
	}
	challenge := plan.ConfirmationChallenge(root)
	applyCommand := canaryLiveCommand{action: "apply", plan: planCommand, liveConfirm: challenge, candidateSHA256: plan.CandidateSHA256()}
	var applyStdout bytes.Buffer
	var applyStderr bytes.Buffer
	applyDone := make(chan int, 1)
	go func() { applyDone <- runCanaryLive(applyCommand, &applyStdout, &applyStderr, deps) }()

	store := apply.FileJournal{Path: filepath.Join(root, "journal.json")}
	deadline := time.Now().Add(5 * time.Second)
	for {
		journal, loadErr := store.Load()
		if loadErr == nil && journal.State == apply.StatePending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canary did not become pending: %v", loadErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	mismatchPlanCommand := planCommand
	mismatchPlanCommand.targets = []string{"198.51.100.11"}
	mismatchPlan, _, err := collectCanaryPlan(t.Context(), mismatchPlanCommand, deps)
	if err != nil {
		t.Fatal(err)
	}
	var mismatchStdout, mismatchStderr bytes.Buffer
	mismatchConfirm := canaryLiveCommand{action: "confirm", plan: mismatchPlanCommand, liveConfirm: mismatchPlan.ConfirmationChallenge(root), candidateSHA256: mismatchPlan.CandidateSHA256()}
	if code := runCanaryLive(mismatchConfirm, &mismatchStdout, &mismatchStderr, deps); code == 0 {
		t.Fatal("different candidate unexpectedly confirmed the pending revision")
	}
	journalAfterMismatch, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if journalAfterMismatch.State != apply.StatePending || journalAfterMismatch.PendingRevision != planCommand.revision {
		t.Fatalf("mismatched confirmation changed journal: %+v", journalAfterMismatch)
	}

	var confirmStdout bytes.Buffer
	var confirmStderr bytes.Buffer
	confirmCommand := canaryLiveCommand{action: "confirm", plan: planCommand, liveConfirm: challenge, candidateSHA256: plan.CandidateSHA256()}
	if code := runCanaryLive(confirmCommand, &confirmStdout, &confirmStderr, deps); code != 0 {
		t.Fatalf("confirm code = %d, stderr = %q", code, confirmStderr.String())
	}
	select {
	case code := <-applyDone:
		if code != 0 {
			t.Fatalf("apply code = %d, stderr = %q", code, applyStderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apply command did not observe confirmation")
	}
	for label, output := range map[string][]byte{"apply": applyStdout.Bytes(), "confirm": confirmStdout.Bytes()} {
		var event canaryActionOutput
		if err := json.Unmarshal(output, &event); err != nil {
			t.Fatalf("%s output is not one JSON document: %v; output=%q", label, err, output)
		}
		if event.Event != "resolved" || event.State != apply.StateCommitted {
			t.Fatalf("%s event = %+v", label, event)
		}
	}

	snapshot, err := backend.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if countCommandOwnedRoutes(snapshot) != 2 || countCommandOwnedSinks(snapshot) != 2 || countCommandOwnedFirewall(snapshot) != 2 || countCommandOwnedNRPT(snapshot) != 1 {
		t.Fatalf("committed managed state = %#v", snapshot)
	}
	if !commandForeignStatePresent(snapshot) {
		t.Fatal("foreign state changed during canary apply")
	}
	beforePlan, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedFullRestoreIdentityFiles(t, root)
	var restorePlanStdout, restorePlanStderr bytes.Buffer
	if code := runCanaryFullRestorePlan(canaryFullRestorePlanCommand{stateRoot: root}, &restorePlanStdout, &restorePlanStderr, deps); code != 0 {
		t.Fatalf("full restore plan code = %d, stderr = %q", code, restorePlanStderr.String())
	}
	var restorePlan canaryFullRestorePlanOutput
	if err := json.Unmarshal(restorePlanStdout.Bytes(), &restorePlan); err != nil {
		t.Fatal(err)
	}
	if restorePlan.LiveMutationPerformed || !lowercaseSHA256Pattern.MatchString(restorePlan.RecoveryPlanSHA256) || !strings.HasPrefix(restorePlan.ConfirmationChallenge, recoveryRestoreToken+"-") || len(restorePlan.RemoveRouteIdentities) == 0 {
		t.Fatalf("full restore plan output = %#v", restorePlan)
	}
	afterPlanSnapshot, err := backend.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	afterPlan, err := json.Marshal(afterPlanSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforePlan, afterPlan) {
		t.Fatal("read-only full restore plan changed backend state")
	}
	stale := canaryLiveCommand{action: "full-restore", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: restorePlan.ConfirmationChallenge, recoveryPlanSHA256: strings.Repeat("0", 64)}
	var staleStdout, staleStderr bytes.Buffer
	if code := runCanaryLive(stale, &staleStdout, &staleStderr, deps); code == 0 {
		t.Fatal("stale full restore plan unexpectedly mutated state")
	}
	staleSnapshot, _ := backend.Snapshot(t.Context())
	staleJSON, _ := json.Marshal(staleSnapshot)
	if !bytes.Equal(beforePlan, staleJSON) {
		t.Fatal("stale full restore plan changed backend state")
	}

	var restoreStdout bytes.Buffer
	var restoreStderr bytes.Buffer
	restore := exactFullRestoreCommand(t, root, deps)
	if code := runCanaryLive(restore, &restoreStdout, &restoreStderr, deps); code != 0 {
		t.Fatalf("restore code = %d, stderr = %q", code, restoreStderr.String())
	}
	snapshot, _ = backend.Snapshot(t.Context())
	if countCommandOwnedRoutes(snapshot) != 0 || countCommandOwnedSinks(snapshot) != 0 || countCommandOwnedFirewall(snapshot) != 0 || countCommandOwnedNRPT(snapshot) != 0 || !commandForeignStatePresent(snapshot) {
		t.Fatalf("full restore state = %#v", snapshot)
	}
	journal, err := store.Load()
	if err != nil || journal.State != apply.StateRestored {
		t.Fatalf("restored journal = %#v, error = %v", journal, err)
	}
}

func TestRunCanaryLiveOutputsRedactedSinkAndRecoveryEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	inspection, inventory := commandCanaryInputs()
	backend := &commandMutationBackend{state: commandMutationState(inventory)}
	deps := dependencies{
		backend:              staticInspectionBackend{inspection: inspection},
		collect:              staticCollector{inventory: inventory},
		resolve:              func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil },
		newMutation:          func(string) (windowssystem.MutationBackend, error) { return backend, nil },
		watchdog:             apply.TimerWatchdog{},
		validateStateRoot:    func(string) error { return nil },
		validateConfigSource: func(string) error { return nil },
	}
	planCommand := canaryPlanCommand{
		configPath:   `C:\private-provider-source.conf`,
		stateRoot:    root,
		revision:     "p35-canary-001",
		targets:      []string{"198.51.100.10"},
		dnsNamespace: windowssystem.CanaryDNSNamespace,
	}
	var planStdout, planStderr bytes.Buffer
	if code := runCanaryPlan(planCommand, &planStdout, &planStderr, deps); code != 0 {
		t.Fatalf("plan code = %d, stderr = %q", code, planStderr.String())
	}
	for _, forbidden := range []string{planCommand.configPath, root, "10.20.30.1", "203.0.113.5", "198.51.100.10", "Ethernet", "redlink"} {
		if strings.Contains(planStdout.String(), forbidden) {
			t.Fatalf("plan output leaked %q: %s", forbidden, planStdout.String())
		}
	}
	var planOutput canaryPlanOutput
	if err := json.Unmarshal(planStdout.Bytes(), &planOutput); err != nil {
		t.Fatal(err)
	}
	if planOutput.SinkCount != 2 || planOutput.PersistentSinkReady {
		t.Fatalf("plan sink evidence = %#v", planOutput)
	}

	plan, _, err := collectCanaryPlan(t.Context(), planCommand, deps)
	if err != nil {
		t.Fatal(err)
	}
	mutatedPlan := plan
	mutatedPlan.Candidate.Sinks = append([]byte(nil), plan.Candidate.Sinks...)
	mutatedPlan.Candidate.Sinks[len(mutatedPlan.Candidate.Sinks)-2] ^= 1
	if mutatedPlan.ConfirmationChallenge(root) == plan.ConfirmationChallenge(root) {
		t.Fatal("confirmation challenge did not change after sink artifact changed")
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	tx, err := newLiveCanaryTransaction(root, plan.QualifiedEndpoints, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(t.Context(), plan.Candidate); err != nil {
		t.Fatal(err)
	}
	if err := tx.ConfirmCandidate(t.Context(), plan.Candidate); err != nil {
		t.Fatal(err)
	}

	var statusStdout, statusStderr bytes.Buffer
	if code := runCanaryLive(canaryLiveCommand{action: "status", plan: canaryPlanCommand{stateRoot: root}}, &statusStdout, &statusStderr, deps); code != 0 {
		t.Fatalf("status code = %d, stderr = %q", code, statusStderr.String())
	}
	for _, forbidden := range []string{planCommand.configPath, root, "10.20.30.1", "203.0.113.5", "198.51.100.10", "Ethernet", "redlink"} {
		if strings.Contains(statusStdout.String(), forbidden) {
			t.Fatalf("status output leaked %q: %s", forbidden, statusStdout.String())
		}
	}
	var statusOutput canaryStatusOutput
	if err := json.Unmarshal(statusStdout.Bytes(), &statusOutput); err != nil {
		t.Fatal(err)
	}
	if statusOutput.SinkCount != 2 || !statusOutput.PersistentSinkReady {
		t.Fatalf("status sink evidence = %#v", statusOutput)
	}

	var disableStdout, disableStderr bytes.Buffer
	disable := canaryLiveCommand{action: "emergency-disable", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: recoveryDisableToken}
	if code := runCanaryLive(disable, &disableStdout, &disableStderr, deps); code != 0 {
		t.Fatalf("disable code = %d, stderr = %q", code, disableStderr.String())
	}
	var disableOutput canaryActionOutput
	if err := json.Unmarshal(disableStdout.Bytes(), &disableOutput); err != nil {
		t.Fatal(err)
	}
	if disableOutput.RetainSinks != 2 || disableOutput.RemoveSinks != 0 {
		t.Fatalf("disable recovery sink counts = %#v", disableOutput)
	}

	var restoreStdout, restoreStderr bytes.Buffer
	restore := exactFullRestoreCommand(t, root, deps)
	if code := runCanaryLive(restore, &restoreStdout, &restoreStderr, deps); code != 0 {
		t.Fatalf("restore code = %d, stderr = %q", code, restoreStderr.String())
	}
	var restoreOutput canaryActionOutput
	if err := json.Unmarshal(restoreStdout.Bytes(), &restoreOutput); err != nil {
		t.Fatal(err)
	}
	if restoreOutput.RemoveSinks != 2 || restoreOutput.RetainSinks != 0 {
		t.Fatalf("restore recovery sink counts = %#v", restoreOutput)
	}
	for _, forbidden := range []string{planCommand.configPath, root, "10.20.30.1", "203.0.113.5", "198.51.100.10", "Ethernet", "redlink"} {
		if strings.Contains(restoreStdout.String(), forbidden) || strings.Contains(disableStdout.String(), forbidden) {
			t.Fatalf("recovery output leaked %q: disable=%s restore=%s", forbidden, disableStdout.String(), restoreStdout.String())
		}
	}
}

func TestRunCanaryFullRestoreWatchdogSemantics(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	inspection, inventory := commandCanaryInputs()
	backend := &commandMutationBackend{state: commandMutationState(inventory)}
	watchdog := &trackingPersistentWatchdog{}
	deps := dependencies{
		backend:              staticInspectionBackend{inspection: inspection},
		collect:              staticCollector{inventory: inventory},
		resolve:              func(context.Context, string) ([]string, error) { return []string{"203.0.113.5"}, nil },
		newMutation:          func(string) (windowssystem.MutationBackend, error) { return backend, nil },
		watchdog:             watchdog,
		validateStateRoot:    func(string) error { return nil },
		validateConfigSource: func(string) error { return nil },
	}
	planCommand := canaryPlanCommand{
		configPath:   `C:\private-provider-source.conf`,
		stateRoot:    root,
		revision:     "p35-canary-001",
		targets:      []string{"198.51.100.10"},
		dnsNamespace: windowssystem.CanaryDNSNamespace,
	}
	plan, _, err := collectCanaryPlan(t.Context(), planCommand, deps)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := newLiveCanaryTransaction(root, plan.QualifiedEndpoints, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(t.Context(), plan.Candidate); err != nil {
		t.Fatal(err)
	}
	if err := tx.ConfirmCandidate(t.Context(), plan.Candidate); err != nil {
		t.Fatal(err)
	}
	if watchdog.recovery || !watchdog.reconcile {
		t.Fatalf("confirmed watchdog state = %+v", watchdog)
	}
	backend.failCall = "remove-sink:198.51.100.10/32"
	var failedStdout, failedStderr bytes.Buffer
	restore := exactFullRestoreCommand(t, root, deps)
	if code := runCanaryLive(restore, &failedStdout, &failedStderr, deps); code == 0 {
		t.Fatal("faulted full restore unexpectedly succeeded")
	}
	if !watchdog.recovery || !watchdog.reconcile || watchdog.disarms != 0 {
		t.Fatalf("retryable restoring failure did not retain watchdog coverage: %+v", watchdog)
	}
	backend.failCall = ""
	var restoreStdout, restoreStderr bytes.Buffer
	recover := canaryLiveCommand{action: "recover", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: recoveryRecoverToken}
	if code := runCanaryLive(recover, &restoreStdout, &restoreStderr, deps); code != 0 {
		t.Fatalf("restore code = %d, stderr = %q", code, restoreStderr.String())
	}
	if watchdog.recovery || watchdog.reconcile || watchdog.disarms != 1 {
		t.Fatalf("successful full restore did not disarm both watchdog tasks: %+v", watchdog)
	}
}

func commandCanaryInputs() (tunnel.Inspection, windowssystem.Inventory) {
	inspection := tunnel.Inspection{
		Metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          tunnel.TransportAmneziaWG,
			Endpoint:           tunnel.Endpoint{Host: "vpn.example.test", Port: 51820},
			InterfaceAddresses: []string{"10.20.30.2/32"},
			DNS:                []string{"10.20.30.1"},
			IPv4FullTunnel:     true,
		},
		Status: tunnel.Status{State: tunnel.StateUnknown, Observed: false},
	}
	inventory := windowssystem.Inventory{
		Adapters: []windowssystem.Adapter{
			{Name: "Ethernet", Index: 1, InterfaceGUID: commandPhysicalGUID, Kind: windowssystem.AdapterPhysical, Up: true},
			{Name: "redlink", Index: 2, InterfaceGUID: commandRedShieldGUID, Kind: windowssystem.AdapterRedShield, Up: true, Addresses: []string{"10.20.30.2/32"}},
		},
		Routes: []windowssystem.Route{
			{Family: windowssystem.FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 25},
			{Family: windowssystem.FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceIndex: 1, InterfaceGUID: commandPhysicalGUID, Metric: 1},
		},
		EndpointAddresses:          []string{"203.0.113.5"},
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}
	return inspection, inventory
}

func commandMutationState(inventory windowssystem.Inventory) windowssystem.MutationSnapshot {
	routes := make([]windowssystem.RouteState, 0, len(inventory.Routes))
	for _, route := range inventory.Routes {
		routes = append(routes, windowssystem.RouteState{ManagedRoute: windowssystem.ManagedRoute{
			Family: route.Family, Destination: route.Destination, NextHop: route.NextHop,
			InterfaceGUID: route.InterfaceGUID, InterfaceIndex: route.InterfaceIndex, Metric: uint32(route.Metric),
		}})
	}
	return windowssystem.MutationSnapshot{
		Adapters:         inventory.Adapters,
		Routes:           routes,
		FirewallEnforced: true,
		Firewall:         []windowssystem.FirewallState{{Rule: windowssystem.FirewallRule{Name: "foreign-firewall", Group: "foreign"}}},
		NRPT:             []windowssystem.NRPTState{{Rule: windowssystem.NRPTRule{Name: "foreign-nrpt", LogicalID: "foreign", Namespace: ".foreign.example"}}},
	}
}

func countCommandOwnedRoutes(snapshot windowssystem.MutationSnapshot) int {
	count := 0
	for _, state := range snapshot.Routes {
		if state.Owner == windowssystem.ArtifactOwner {
			count++
		}
	}
	return count
}

func countCommandOwnedSinks(snapshot windowssystem.MutationSnapshot) int {
	count := 0
	for _, state := range snapshot.Sinks {
		if state.Owner == windowssystem.ArtifactOwner {
			count++
		}
	}
	return count
}

func countCommandOwnedFirewall(snapshot windowssystem.MutationSnapshot) int {
	count := 0
	for _, state := range snapshot.Firewall {
		if state.Owner == windowssystem.ArtifactOwner {
			count++
		}
	}
	return count
}

func countCommandOwnedNRPT(snapshot windowssystem.MutationSnapshot) int {
	count := 0
	for _, state := range snapshot.NRPT {
		if state.Owner == windowssystem.ArtifactOwner {
			count++
		}
	}
	return count
}

func commandForeignStatePresent(snapshot windowssystem.MutationSnapshot) bool {
	return slices.ContainsFunc(snapshot.Firewall, func(state windowssystem.FirewallState) bool { return state.Rule.Name == "foreign-firewall" }) &&
		slices.ContainsFunc(snapshot.NRPT, func(state windowssystem.NRPTState) bool { return state.Rule.Name == "foreign-nrpt" })
}

func TestCanaryRecoveryTokensAreActionSpecific(t *testing.T) {
	for action, token := range map[string]string{
		"rollback": recoveryRollbackToken, "recover": recoveryRecoverToken,
		"emergency-disable": recoveryDisableToken, "full-restore": recoveryRestoreToken,
	} {
		for _, wrong := range []string{recoveryRollbackToken, recoveryRecoverToken, recoveryDisableToken, recoveryRestoreToken, fmt.Sprintf("%s-extra", token)} {
			if wrong == token {
				continue
			}
			command := canaryLiveCommand{action: action, plan: canaryPlanCommand{stateRoot: filepath.Join(t.TempDir(), "state")}, recoveryConfirm: wrong}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := runCanaryLive(command, &stdout, &stderr, dependencies{
				newMutation:       func(string) (windowssystem.MutationBackend, error) { return nil, fmt.Errorf("must not run") },
				validateStateRoot: func(string) error { return nil },
			}); code != 2 {
				t.Fatalf("action %s accepted token %q with code %d", action, wrong, code)
			}
		}
	}
}

func TestParseCanaryLiveRequiresExactCandidateSHA256ForApplyAndConfirm(t *testing.T) {
	base := []string{"windows", "canary", "apply", "--config", "config", "--config-sha256", strings.Repeat("a", 64), "--state-root", "state", "--revision", "p35", "--target", "1.1.1.1", "--dns-namespace", ".probe.example", "--confirm-live", "P35-APPLY-0011223344556677", "--json"}
	if _, ok := parseCanaryLiveCommand(base); ok {
		t.Fatal("apply accepted a missing candidate SHA-256")
	}
	withCandidate := append([]string(nil), base[:len(base)-1]...)
	withCandidate = append(withCandidate, "--candidate-sha256", strings.Repeat("b", 64), "--json")
	command, ok := parseCanaryLiveCommand(withCandidate)
	if !ok || command.candidateSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("candidate-bound apply parse = %#v, %v", command, ok)
	}
	withCandidate[2] = "confirm"
	if command, ok = parseCanaryLiveCommand(withCandidate); !ok || command.candidateSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("candidate-bound confirm parse = %#v, %v", command, ok)
	}
	withCandidate[len(withCandidate)-2] = strings.Repeat("B", 64)
	if _, ok := parseCanaryLiveCommand(withCandidate); ok {
		t.Fatal("uppercase candidate SHA-256 was accepted")
	}
}

func TestReadOnlyJournalRejectsPathSubstitutionAfterIdentityCheck(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "journal.json")
	approved := []byte(`{"state":"idle"}`)
	if err := os.WriteFile(path, approved, 0o600); err != nil {
		t.Fatal(err)
	}
	substitute := filepath.Join(directory, "substitute.json")
	if err := os.WriteFile(substitute, []byte(`{"state":"restored","rollback_result":"substituted"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCanaryJournalReadOnlyBound(path, func() {
		if renameErr := os.Rename(path, filepath.Join(directory, "approved.json")); renameErr != nil {
			t.Fatal(renameErr)
		}
		if renameErr := os.Rename(substitute, path); renameErr != nil {
			t.Fatal(renameErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("path substitution error = %v", err)
	}
}

func TestCanaryLiveRejectsUntrustedRootBeforeAnyIOOrBackendCall(t *testing.T) {
	for _, root := range []string{`C:\temp\p35`, `\\server\share\p35`, `\\?\C:\ProgramData\HomeGateway\P35`} {
		for _, command := range []canaryLiveCommand{
			{action: "status", plan: canaryPlanCommand{stateRoot: root}},
			{action: "recover", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: recoveryRecoverToken},
			{
				action:      "apply",
				plan:        canaryPlanCommand{stateRoot: root, configPath: `C:\secret.conf`, revision: "r1", targets: []string{"1.1.1.1"}, dnsNamespace: windowssystem.CanaryDNSNamespace},
				liveConfirm: "P35-APPLY-0000000000000000",
			},
		} {
			t.Run(command.action+"/"+root, func(t *testing.T) {
				backendCalled := false
				var stdout, stderr bytes.Buffer
				code := runCanaryLive(command, &stdout, &stderr, dependencies{
					newMutation: func(string) (windowssystem.MutationBackend, error) {
						backendCalled = true
						return nil, errors.New("must not run")
					},
					validateStateRoot: func(got string) error {
						if got != root {
							t.Fatalf("validated root = %q, want %q", got, root)
						}
						return errors.New("blocked before IO")
					},
				})
				if code != 3 || backendCalled {
					t.Fatalf("code = %d, backendCalled = %v, stderr = %q", code, backendCalled, stderr.String())
				}
			})
		}
	}
}

func TestCanaryRecoveryNoopHoldsOperationLockThroughWatchdogDisarm(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	watchdog := &blockingDisarmWatchdog{entered: make(chan struct{}), release: make(chan struct{})}
	command := canaryLiveCommand{action: "recover", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: recoveryRecoverToken}
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runCanaryLive(command, &stdout, &stderr, dependencies{
			newMutation: func(string) (windowssystem.MutationBackend, error) {
				return nil, errors.New("no-op recovery must not construct a mutation backend")
			},
			watchdog:          watchdog,
			validateStateRoot: func(string) error { return nil },
		})
	}()
	select {
	case <-watchdog.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not reach watchdog disarm")
	}

	locked := make(chan func() error, 1)
	lockErrors := make(chan error, 1)
	go func() {
		release, err := (apply.FileLocker{Path: filepath.Join(root, "operation.lock")}).Lock(t.Context())
		if err != nil {
			lockErrors <- err
			return
		}
		locked <- release
	}()
	select {
	case release := <-locked:
		_ = release()
		t.Fatal("concurrent operation acquired the lock during watchdog disarm")
	case err := <-lockErrors:
		t.Fatal(err)
	case <-time.After(100 * time.Millisecond):
	}
	close(watchdog.release)
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("recovery code=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not finish")
	}
	select {
	case release := <-locked:
		if err := release(); err != nil {
			t.Fatal(err)
		}
	case err := <-lockErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("operation lock was not released after recovery")
	}
}

func TestRecoveryTransactionIgnoresMissingOrRotatedPendingEndpointManifest(t *testing.T) {
	t.Run("missing first pending manifest", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		journal := apply.Journal{
			State:           apply.StatePending,
			PendingRevision: "missing",
			PendingDeadline: time.Now().Add(time.Minute),
		}
		tx, err := newRecoveryTransactionLocked(root, journal, dependencies{
			newMutation: func(string) (windowssystem.MutationBackend, error) { return new(commandMutationBackend), nil },
			watchdog:    apply.TimerWatchdog{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !tx.RecoveryOnly {
			t.Fatal("missing-manifest recovery transaction is not recovery-only")
		}
	})

	t.Run("pending endpoint rotation", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		inspection, inventory := commandCanaryInputs()
		first, err := windowssystem.BuildCanaryPlan(inventory, inspection, windowssystem.CanaryRequest{
			Revision: "first", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: windowssystem.CanaryDNSNamespace,
		})
		if err != nil {
			t.Fatal(err)
		}
		secondInventory := inventory
		secondInventory.EndpointAddresses = []string{"203.0.113.6"}
		secondInventory.Routes = append([]windowssystem.Route(nil), inventory.Routes...)
		secondInventory.Routes[1].Destination = "203.0.113.6/32"
		second, err := windowssystem.BuildCanaryPlan(secondInventory, inspection, windowssystem.CanaryRequest{
			Revision: "second", TargetAddresses: []string{"198.51.100.10"}, DNSNamespace: windowssystem.CanaryDNSNamespace,
		})
		if err != nil {
			t.Fatal(err)
		}
		backend := &commandMutationBackend{state: commandMutationState(inventory)}
		runtime := &windowssystem.Runtime{Root: root, Backend: backend, QualifiedEndpoints: first.QualifiedEndpoints}
		if err := runtime.Stage(t.Context(), first.Candidate); err != nil {
			t.Fatal(err)
		}
		runtime.QualifiedEndpoints = second.QualifiedEndpoints
		if err := runtime.Stage(t.Context(), second.Candidate); err != nil {
			t.Fatal(err)
		}
		journal := apply.Journal{
			State:                 apply.StatePending,
			ActiveRevision:        "first",
			LastKnownGoodRevision: "first",
			PendingRevision:       "second",
			PendingDeadline:       time.Now().Add(time.Minute),
		}
		tx, err := newRecoveryTransactionLocked(root, journal, dependencies{
			newMutation: func(string) (windowssystem.MutationBackend, error) { return backend, nil },
			watchdog:    apply.TimerWatchdog{},
		})
		if err != nil {
			t.Fatal(err)
		}
		gotRuntime, ok := tx.Runtime.(*windowssystem.Runtime)
		if !ok || !slices.Equal(gotRuntime.QualifiedEndpoints, first.QualifiedEndpoints) {
			t.Fatalf("recovery endpoints=%v want=%v", gotRuntime.QualifiedEndpoints, first.QualifiedEndpoints)
		}
	})
}
