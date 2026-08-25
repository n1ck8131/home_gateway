package hgctlcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

type commandMutationBackend struct {
	mu    sync.Mutex
	state windowssystem.MutationSnapshot
}

type blockingDisarmWatchdog struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
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
	applyCommand := canaryLiveCommand{action: "apply", plan: planCommand, liveConfirm: challenge}
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
	mismatchConfirm := canaryLiveCommand{action: "confirm", plan: mismatchPlanCommand, liveConfirm: mismatchPlan.ConfirmationChallenge(root)}
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
	confirmCommand := canaryLiveCommand{action: "confirm", plan: planCommand, liveConfirm: challenge}
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
	if countCommandOwnedRoutes(snapshot) != 2 || countCommandOwnedFirewall(snapshot) != 2 || countCommandOwnedNRPT(snapshot) != 1 {
		t.Fatalf("committed managed state = %#v", snapshot)
	}
	if !commandForeignStatePresent(snapshot) {
		t.Fatal("foreign state changed during canary apply")
	}

	var restoreStdout bytes.Buffer
	var restoreStderr bytes.Buffer
	restore := canaryLiveCommand{action: "full-restore", plan: canaryPlanCommand{stateRoot: root}, recoveryConfirm: recoveryRestoreToken}
	if code := runCanaryLive(restore, &restoreStdout, &restoreStderr, deps); code != 0 {
		t.Fatalf("restore code = %d, stderr = %q", code, restoreStderr.String())
	}
	snapshot, _ = backend.Snapshot(t.Context())
	if countCommandOwnedRoutes(snapshot) != 0 || countCommandOwnedFirewall(snapshot) != 0 || countCommandOwnedNRPT(snapshot) != 0 || !commandForeignStatePresent(snapshot) {
		t.Fatalf("full restore state = %#v", snapshot)
	}
	journal, err := store.Load()
	if err != nil || journal.State != apply.StateRestored {
		t.Fatalf("restored journal = %#v, error = %v", journal, err)
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
