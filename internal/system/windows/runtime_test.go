package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
)

type fakeMutationBackend struct {
	state                   MutationSnapshot
	calls                   []string
	failCall                string
	persistentFailCall      string
	failSnapshotAfterReload bool
}

func (backend *fakeMutationBackend) Snapshot(context.Context) (MutationSnapshot, error) {
	if backend.failSnapshotAfterReload && slices.Contains(backend.calls, "reload") {
		backend.failSnapshotAfterReload = false
		return MutationSnapshot{}, errors.New("post-check snapshot fault")
	}
	return cloneMutationSnapshot(backend.state), nil
}

func (backend *fakeMutationBackend) AddRoute(_ context.Context, state RouteState) error {
	if err := backend.call("add-route:" + state.Role + ":" + state.Destination); err != nil {
		return err
	}
	for index, current := range backend.state.Routes {
		if routeTupleKey(current.ManagedRoute) == routeTupleKey(state.ManagedRoute) && current.Owner == ArtifactOwner {
			backend.state.Routes[index] = state
			return nil
		}
	}
	backend.state.Routes = append(backend.state.Routes, state)
	return nil
}

func (backend *fakeMutationBackend) RemoveRoute(_ context.Context, state RouteState) error {
	if err := backend.call("remove-route:" + state.Role + ":" + state.Destination); err != nil {
		return err
	}
	backend.state.Routes = slices.DeleteFunc(backend.state.Routes, func(current RouteState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && routeTupleKey(current.ManagedRoute) == routeTupleKey(state.ManagedRoute)
	})
	return nil
}

func (backend *fakeMutationBackend) PutFirewall(_ context.Context, state FirewallState) error {
	if err := backend.call("put-firewall:" + state.Rule.Name); err != nil {
		return err
	}
	for index, current := range backend.state.Firewall {
		if current.Rule.Name == state.Rule.Name && current.Owner == ArtifactOwner {
			backend.state.Firewall[index] = state
			return nil
		}
	}
	backend.state.Firewall = append(backend.state.Firewall, state)
	return nil
}

func (backend *fakeMutationBackend) RemoveFirewall(_ context.Context, state FirewallState) error {
	if err := backend.call("remove-firewall:" + state.Rule.Name); err != nil {
		return err
	}
	backend.state.Firewall = slices.DeleteFunc(backend.state.Firewall, func(current FirewallState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Rule.Name == state.Rule.Name
	})
	return nil
}

func (backend *fakeMutationBackend) PutNRPT(_ context.Context, state NRPTState) error {
	if err := backend.call("put-nrpt:" + state.Rule.LogicalID); err != nil {
		return err
	}
	for index, current := range backend.state.NRPT {
		if current.Rule.LogicalID == state.Rule.LogicalID && current.Owner == ArtifactOwner {
			state.Rule.Name = current.Rule.Name
			backend.state.NRPT[index] = state
			return nil
		}
	}
	state.Rule.Name = "generated-" + state.Rule.LogicalID
	backend.state.NRPT = append(backend.state.NRPT, state)
	return nil
}

func (backend *fakeMutationBackend) RemoveNRPT(_ context.Context, state NRPTState) error {
	if err := backend.call("remove-nrpt:" + state.Rule.LogicalID); err != nil {
		return err
	}
	backend.state.NRPT = slices.DeleteFunc(backend.state.NRPT, func(current NRPTState) bool {
		return current.Owner == state.Owner && current.Revision == state.Revision && current.Rule.Name == state.Rule.Name
	})
	return nil
}

func (backend *fakeMutationBackend) Reload(context.Context) error { return backend.call("reload") }

func (backend *fakeMutationBackend) call(name string) error {
	backend.calls = append(backend.calls, name)
	if backend.failCall == name {
		backend.failCall = ""
		return errors.New("injected mutation fault")
	}
	if backend.persistentFailCall == name {
		return errors.New("persistent mutation fault")
	}
	return nil
}

type testLocker struct{}

func (testLocker) Lock(context.Context) (func() error, error) {
	return func() error { return nil }, nil
}

type testWatchdog struct{}

func (testWatchdog) Arm(time.Time, func()) (func(), error) { return func() {}, nil }

type mutableClock struct{ now time.Time }

func (clock *mutableClock) Now() time.Time { return clock.now }

func TestWindowsRuntimeRejectsUnsafeArtifactsBeforeMutation(t *testing.T) {
	tests := map[string]func(*apply.Candidate){
		"trailing JSON": func(candidate *apply.Candidate) { candidate.Routes = append(candidate.Routes, []byte(` {}`)...) },
		"oversize":      func(candidate *apply.Candidate) { candidate.Routes = make([]byte, maxArtifactBytes+1) },
		"default route": func(candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.routes.Routes[2].Destination = "0.0.0.0/0"
			artifacts.firewall.Rules[0].RemoteCIDR = "0.0.0.0/0"
			*candidate = encodeCandidate(t, artifacts)
		},
		"duplicate route": func(candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.routes.Routes = append(artifacts.routes.Routes, artifacts.routes.Routes[0])
			*candidate = encodeCandidate(t, artifacts)
		},
		"mapped IPv6": func(candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.routes.Routes[2].Family = FamilyIPv6
			artifacts.routes.Routes[2].Destination = "::ffff:198.51.100.0/120"
			artifacts.routes.Routes[2].NextHop = "::ffff:10.20.30.1"
			*candidate = encodeCandidate(t, artifacts)
		},
		"malformed": func(candidate *apply.Candidate) { candidate.Firewall = []byte(`{"version":`) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			backend := newSafeBackend()
			candidate := safeCandidate(t, "r1")
			mutate(&candidate)
			runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
			if err := runtime.Stage(context.Background(), candidate); err == nil {
				t.Fatal("unsafe candidate staged")
			}
			if len(backend.calls) != 0 {
				t.Fatalf("mutation calls = %v", backend.calls)
			}
		})
	}
}

func TestWindowsRuntimeRejectsStaleGUIDOverlapAndUnownedCollisions(t *testing.T) {
	tests := map[string]func(*fakeMutationBackend, *apply.Candidate){
		"stale GUID": func(_ *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.routes.Routes[2].InterfaceGUID = "99999999-9999-4999-8999-999999999999"
			*candidate = encodeCandidate(t, artifacts)
		},
		"Cisco overlap": func(_ *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.routes.Routes[2].Destination = "10.50.1.0/24"
			artifacts.firewall.Rules[0].RemoteCIDR = "10.50.1.0/24"
			*candidate = encodeCandidate(t, artifacts)
		},
		"DNS outside fail-closed prefixes": func(_ *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			artifacts.dns.Rules[0].NameServers = []string{"10.20.30.53"}
			*candidate = encodeCandidate(t, artifacts)
		},
		"identical unowned route": func(backend *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			backend.state.Routes = append(backend.state.Routes, RouteState{ManagedRoute: artifacts.routes.Routes[2]})
		},
		"unowned firewall marker": func(backend *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			backend.state.Firewall = append(backend.state.Firewall, FirewallState{Rule: artifacts.firewall.Rules[0]})
		},
		"unowned NRPT marker": func(backend *fakeMutationBackend, candidate *apply.Candidate) {
			artifacts := decodeCandidate(t, *candidate)
			backend.state.NRPT = append(backend.state.NRPT, NRPTState{Rule: artifacts.dns.Rules[0]})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			backend := newSafeBackend()
			candidate := safeCandidate(t, "r1")
			mutate(backend, &candidate)
			tx := newWindowsTransaction(t, backend)
			if err := tx.Apply(context.Background(), candidate); err == nil {
				t.Fatal("unsafe state applied")
			}
			if slices.ContainsFunc(backend.calls, func(call string) bool {
				return strings.HasPrefix(call, "add-") || strings.HasPrefix(call, "put-") || strings.HasPrefix(call, "remove-")
			}) {
				t.Fatalf("mutation occurred: %v", backend.calls)
			}
		})
	}
}

func TestWindowsRuntimeRejectsVirtualDefaultAddedAfterValidate(t *testing.T) {
	backend := newSafeBackend()
	runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
	candidate := safeCandidate(t, "r1")
	if err := runtime.Preflight(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Validate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	backend.state.Routes = append(backend.state.Routes, RouteState{ManagedRoute: ManagedRoute{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "10.20.30.1", InterfaceGUID: testRedShieldGUID, InterfaceIndex: 21}})
	if err := runtime.Activate(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "default route") {
		t.Fatalf("TOCTOU virtual default error = %v", err)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("mutation occurred after TOCTOU: %v", backend.calls)
	}
}

func TestWindowsRuntimeBindsArtifactsToTrustedQualifiedEndpoints(t *testing.T) {
	t.Run("unrelated routes cannot substitute", func(t *testing.T) {
		backend := newSafeBackend()
		runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: []string{"192.0.2.99/32", "2001:db8:ffff::99/128"}}
		candidate := safeCandidate(t, "r1")
		if err := runtime.Preflight(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Stage(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Validate(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "trusted qualified endpoint") {
			t.Fatalf("untrusted endpoint coverage error = %v", err)
		}
	})
	t.Run("managed and asserted duplicate coverage", func(t *testing.T) {
		backend := newSafeBackend()
		candidate := safeCandidate(t, "r1")
		artifacts := decodeCandidate(t, candidate)
		managed := artifacts.routes.Routes[0]
		assertion := DirectRouteAssertion{Family: managed.Family, Destination: managed.Destination, NextHop: managed.NextHop, InterfaceGUID: managed.InterfaceGUID, InterfaceIndex: managed.InterfaceIndex}
		artifacts.routes.DirectAssertions = append(artifacts.routes.DirectAssertions, assertion)
		candidate = encodeCandidate(t, artifacts)
		backend.state.Routes = append(backend.state.Routes, RouteState{ManagedRoute: ManagedRoute{Family: assertion.Family, Destination: assertion.Destination, NextHop: assertion.NextHop, InterfaceGUID: assertion.InterfaceGUID, InterfaceIndex: assertion.InterfaceIndex}})
		runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
		if err := runtime.Preflight(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Stage(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Validate(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("duplicate endpoint coverage error = %v", err)
		}
	})
}

func TestWindowsFirewallNameCannotAliasAnotherRevision(t *testing.T) {
	backend := newSafeBackend()
	candidate := safeCandidate(t, "r2")
	artifacts := decodeCandidate(t, candidate)
	artifacts.routes.Routes[2].Destination = "198.51.101.0/24"
	artifacts.firewall.Rules[0].RemoteCIDR = "198.51.101.0/24"
	artifacts.firewall.Rules[0].Name = FirewallRuleName("r1", FamilyIPv4, "198.51.100.0/24", testPhysicalGUID)
	candidate = encodeCandidate(t, artifacts)
	runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
	if err := runtime.Stage(context.Background(), candidate); err == nil {
		t.Fatal("cross-revision firewall name alias staged")
	}
	if len(backend.calls) != 0 {
		t.Fatalf("mutation occurred: %v", backend.calls)
	}
}

func TestWindowsTransactionOrdersDualStackAndPreservesForeignState(t *testing.T) {
	backend := newSafeBackend()
	before := cloneMutationSnapshot(backend.state)
	tx := newWindowsTransaction(t, backend)

	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	assertOrdered(t, backend.calls,
		"add-route:endpoint-direct:203.0.113.5/32",
		"add-route:endpoint-direct:2001:db8:ffff::5/128",
		"put-firewall:"+FirewallRuleName("r1", FamilyIPv4, "198.51.100.0/24", testPhysicalGUID),
		"put-firewall:"+FirewallRuleName("r1", FamilyIPv6, "2001:db8:100::/64", testPhysicalGUID),
		"add-route:vpn-class:198.51.100.0/24",
		"add-route:vpn-class:2001:db8:100::/64",
		"put-nrpt:dns-v4",
		"put-nrpt:dns-v6",
	)
	assertForeignUnchanged(t, before, backend.state)
}

func TestWindowsTransactionFaultsRestoreBeforeSnapshot(t *testing.T) {
	faults := []string{
		"add-route:endpoint-direct:2001:db8:ffff::5/128",
		"put-firewall:" + FirewallRuleName("r1", FamilyIPv6, "2001:db8:100::/64", testPhysicalGUID),
		"add-route:vpn-class:2001:db8:100::/64",
		"put-nrpt:dns-v6",
		"reload",
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			backend := newSafeBackend()
			before := cloneMutationSnapshot(backend.state)
			backend.failCall = fault
			tx := newWindowsTransaction(t, backend)
			if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err == nil {
				t.Fatal("injected activation fault did not fail")
			}
			assertManagedEmpty(t, backend.state)
			assertForeignUnchanged(t, before, backend.state)
		})
	}

	t.Run("post-check", func(t *testing.T) {
		backend := newSafeBackend()
		before := cloneMutationSnapshot(backend.state)
		backend.failSnapshotAfterReload = true
		tx := newWindowsTransaction(t, backend)
		if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err == nil {
			t.Fatal("post-check fault did not fail")
		}
		assertManagedEmpty(t, backend.state)
		assertForeignUnchanged(t, before, backend.state)
	})
}

func TestWindowsFailedRollbackRemainsDurablyRetryable(t *testing.T) {
	backend := newSafeBackend()
	before := cloneMutationSnapshot(backend.state)
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	backend.failCall = "add-route:vpn-class:2001:db8:100::/64"
	backend.persistentFailCall = "remove-route:endpoint-direct:203.0.113.5/32"
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err == nil {
		t.Fatal("activation plus rollback fault did not fail")
	}
	journal, err := tx.Journal.Load()
	if err != nil || journal.State != apply.StateDegraded || journal.FailedRevision != "r1" {
		t.Fatalf("degraded retry journal = %#v, %v", journal, err)
	}
	if err := tx.Recover(context.Background()); err == nil {
		t.Fatal("persistent rollback fault unexpectedly converged")
	}
	backend.persistentFailCall = ""
	if err := tx.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, _ = tx.Journal.Load()
	if journal.State != apply.StateRolledBack || journal.FailedRevision != "" {
		t.Fatalf("retried rollback journal = %#v", journal)
	}
	assertManagedEmpty(t, backend.state)
	assertForeignUnchanged(t, before, backend.state)
}

func TestWindowsTransactionTimeoutAndCrashRecovery(t *testing.T) {
	for _, mode := range []string{"timeout", "crash"} {
		t.Run(mode, func(t *testing.T) {
			backend := newSafeBackend()
			before := cloneMutationSnapshot(backend.state)
			root := filepath.Join(t.TempDir(), "runtime")
			clock := &mutableClock{now: time.Unix(100, 0).UTC()}
			tx := transactionForRoot(root, backend, clock)
			if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
				t.Fatal(err)
			}
			if mode == "timeout" {
				clock.now = clock.now.Add(10 * time.Minute)
				if err := tx.Expire(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else {
				recovered := transactionForRoot(root, backend, clock)
				if err := recovered.Recover(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			assertManagedEmpty(t, backend.state)
			assertForeignUnchanged(t, before, backend.state)
		})
	}
}

func TestWindowsMidActivationRestartRestoresWithCompleteOrMissingPendingManifest(t *testing.T) {
	for _, missingManifest := range []bool{false, true} {
		name := "manifest-present"
		if missingManifest {
			name = "manifest-missing"
		}
		t.Run(name, func(t *testing.T) {
			backend := newSafeBackend()
			before := cloneMutationSnapshot(backend.state)
			root := filepath.Join(t.TempDir(), "runtime")
			runtime := &Runtime{Root: root, Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
			candidate := safeCandidate(t, "r1")
			if err := runtime.Preflight(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Stage(context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Validate(context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Snapshot(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			artifacts := decodeCandidate(t, candidate)
			if err := backend.AddRoute(context.Background(), RouteState{ManagedRoute: artifacts.routes.Routes[0], Owner: ArtifactOwner, Revision: "r1"}); err != nil {
				t.Fatal(err)
			}
			if err := backend.PutFirewall(context.Background(), FirewallState{Rule: artifacts.firewall.Rules[0], Owner: ArtifactOwner, Revision: "r1"}); err != nil {
				t.Fatal(err)
			}
			journal := apply.FileJournal{Path: filepath.Join(root, "journal.json")}
			if err := journal.Save(apply.Journal{State: apply.StatePending, PendingRevision: "r1", PendingDeadline: time.Unix(200, 0).UTC()}); err != nil {
				t.Fatal(err)
			}
			if missingManifest {
				if err := os.Remove(filepath.Join(root, "revisions", "r1", revisionManifestName)); err != nil {
					t.Fatal(err)
				}
			}
			restarted := transactionForRoot(root, backend, &mutableClock{now: time.Unix(101, 0).UTC()})
			if err := restarted.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertManagedEmpty(t, backend.state)
			assertForeignUnchanged(t, before, backend.state)
			got, err := journal.Load()
			if err != nil || got.State != apply.StateRolledBack {
				t.Fatalf("recovered journal = %#v, %v", got, err)
			}
		})
	}
}

func TestWindowsMissingManifestRecoveryIgnoresLargeForeignInventory(t *testing.T) {
	snapshot := MutationSnapshot{}
	for index := 0; index < maxManagedRoutes+1; index++ {
		snapshot.Routes = append(snapshot.Routes, RouteState{ManagedRoute: ManagedRoute{Destination: fmt.Sprintf("foreign-%d", index)}})
	}
	snapshot.Routes = append(snapshot.Routes, RouteState{
		ManagedRoute: ManagedRoute{
			Role: RouteRoleEndpointDirect, Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1",
			InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore,
			Protocol: RouteProtocol, JournalOwned: true,
		},
		Owner: ArtifactOwner, Revision: "missing",
	})
	if err := verifyOwnedStateRecovery(snapshot, nil, "missing"); err != nil {
		t.Fatalf("foreign inventory consumed pending ownership limit: %v", err)
	}
}

func TestWindowsNormalPreflightClearsMissingPendingRecoveryMode(t *testing.T) {
	backend := newSafeBackend()
	runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
	runtime.recoveryPendingRevision = "missing"
	if err := runtime.Preflight(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if runtime.recoveryPendingRevision != "" {
		t.Fatal("normal preflight retained missing-pending cleanup authority")
	}
}

func TestWindowsReplacementIsAdditiveFirstAndPrunesPriorRevision(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	clock := &mutableClock{now: time.Unix(100, 0).UTC()}
	tx := transactionForRoot(root, backend, clock)
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	backend.calls = nil
	if err := tx.Apply(context.Background(), safeCandidate(t, "r2")); err != nil {
		t.Fatal(err)
	}
	firstRemove := slices.IndexFunc(backend.calls, func(call string) bool { return strings.HasPrefix(call, "remove-") })
	lastNewAdd := slices.Index(backend.calls, "put-nrpt:dns-v6")
	if firstRemove >= 0 && firstRemove < lastNewAdd {
		t.Fatalf("prior state pruned before candidate was complete: %v", backend.calls)
	}
	for _, route := range backend.state.Routes {
		if route.Owner == ArtifactOwner && route.Revision != "r2" {
			t.Fatalf("stale route remains: %#v", route)
		}
	}
	for _, rule := range backend.state.Firewall {
		if rule.Owner == ArtifactOwner && rule.Revision != "r2" {
			t.Fatalf("stale firewall remains: %#v", rule)
		}
	}
	for _, rule := range backend.state.NRPT {
		if rule.Owner == ArtifactOwner && rule.Revision != "r2" {
			t.Fatalf("stale NRPT remains: %#v", rule)
		}
	}
}

func TestWindowsReplacementFaultRestoresLKG(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	backend.failCall = "add-route:vpn-class:2001:db8:100::/64"
	if err := tx.Apply(context.Background(), safeCandidate(t, "r2")); err == nil {
		t.Fatal("replacement fault did not fail")
	}
	for _, route := range backend.state.Routes {
		if route.Owner == ArtifactOwner && route.Revision != "r1" {
			t.Fatalf("non-LKG route remains: %#v", route)
		}
	}
	for _, rule := range backend.state.Firewall {
		if rule.Owner == ArtifactOwner && rule.Revision != "r1" {
			t.Fatalf("non-LKG firewall remains: %#v", rule)
		}
	}
	for _, rule := range backend.state.NRPT {
		if rule.Owner == ArtifactOwner && rule.Revision != "r1" {
			t.Fatalf("non-LKG NRPT remains: %#v", rule)
		}
	}
}

func TestWindowsStalePruneFaultRestoresLKG(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	backend.failCall = "remove-firewall:" + FirewallRuleName("r1", FamilyIPv4, "198.51.100.0/24", testPhysicalGUID)
	if err := tx.Apply(context.Background(), safeCandidate(t, "r2")); err == nil {
		t.Fatal("stale-prune fault did not fail")
	}
	for _, rule := range backend.state.Firewall {
		if rule.Owner == ArtifactOwner && rule.Revision != "r1" {
			t.Fatalf("non-LKG firewall remains: %#v", rule)
		}
	}
}

func TestWindowsReconcileFaultsRemainRetryable(t *testing.T) {
	tests := map[string]func(*fakeMutationBackend){
		"partial route": func(backend *fakeMutationBackend) {
			backend.failCall = "add-route:vpn-class:2001:db8:100::/64"
		},
		"reload":     func(backend *fakeMutationBackend) { backend.failCall = "reload" },
		"post-check": func(backend *fakeMutationBackend) { backend.failSnapshotAfterReload = true },
		"persistent then cleared": func(backend *fakeMutationBackend) {
			backend.persistentFailCall = "add-route:vpn-class:2001:db8:100::/64"
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			backend := newSafeBackend()
			before := cloneMutationSnapshot(backend.state)
			root := filepath.Join(t.TempDir(), "runtime")
			tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
			if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
				t.Fatal(err)
			}
			if err := tx.Confirm(); err != nil {
				t.Fatal(err)
			}
			backend.state.Routes = slices.DeleteFunc(backend.state.Routes, func(route RouteState) bool { return route.Owner == ArtifactOwner })
			backend.calls = nil
			inject(backend)
			restarted := transactionForRoot(root, backend, &mutableClock{now: time.Unix(101, 0).UTC()})
			if err := restarted.Recover(context.Background()); err == nil {
				t.Fatal("injected reconcile fault did not fail")
			}
			journal, err := restarted.Journal.Load()
			if err != nil || journal.State != apply.StateCommitted {
				t.Fatalf("reconcile journal lost retry state: %#v, %v", journal, err)
			}
			if backend.persistentFailCall != "" {
				if err := restarted.Recover(context.Background()); err == nil {
					t.Fatal("persistent reconcile fault unexpectedly converged")
				}
				backend.persistentFailCall = ""
			}
			if err := restarted.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := restarted.Runtime.(*Runtime).PostCheck(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertForeignUnchanged(t, before, backend.state)
		})
	}
}

func TestWindowsPreexistingEndpointAssertionsRemainForeign(t *testing.T) {
	backend := newSafeBackend()
	candidate := safeCandidate(t, "r1")
	artifacts := decodeCandidate(t, candidate)
	managed := artifacts.routes.Routes
	artifacts.routes.Routes = nil
	for _, route := range managed {
		if route.Role == RouteRoleEndpointDirect {
			assertion := DirectRouteAssertion{Family: route.Family, Destination: route.Destination, NextHop: route.NextHop, InterfaceGUID: route.InterfaceGUID, InterfaceIndex: route.InterfaceIndex}
			artifacts.routes.DirectAssertions = append(artifacts.routes.DirectAssertions, assertion)
			backend.state.Routes = append(backend.state.Routes, RouteState{ManagedRoute: ManagedRoute{Family: route.Family, Destination: route.Destination, NextHop: route.NextHop, InterfaceGUID: route.InterfaceGUID, InterfaceIndex: route.InterfaceIndex}})
			continue
		}
		artifacts.routes.Routes = append(artifacts.routes.Routes, route)
	}
	candidate = encodeCandidate(t, artifacts)
	before := cloneMutationSnapshot(backend.state)
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if countOwnedRole(backend.state.Routes, RouteRoleEndpointDirect) != 0 {
		t.Fatal("assertion-only endpoint route was claimed as managed")
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := tx.FullRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertForeignUnchanged(t, before, backend.state)
}

func TestWindowsRuntimeRequiresFirewallCoverageForEveryPhysicalDefault(t *testing.T) {
	backend := newSafeBackend()
	secondGUID := "22222222-2222-4222-8222-222222222222"
	backend.state.Adapters = append(backend.state.Adapters, Adapter{Index: 13, InterfaceGUID: secondGUID, Kind: AdapterPhysical, Up: true})
	backend.state.Routes = append(backend.state.Routes,
		RouteState{ManagedRoute: ManagedRoute{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.2.1", InterfaceGUID: secondGUID, InterfaceIndex: 13}},
		RouteState{ManagedRoute: ManagedRoute{Family: FamilyIPv6, Destination: "::/0", NextHop: "2001:db8:2::1", InterfaceGUID: secondGUID, InterfaceIndex: 13}},
	)
	tx := newWindowsTransaction(t, backend)
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err == nil || !strings.Contains(err.Error(), "every physical default path") {
		t.Fatalf("undercovered multi-default state error = %v", err)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("mutation occurred: %v", backend.calls)
	}
}

func TestWindowsSnapshotsDoNotPersistForeignNRPTNamespaces(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{beforeSnapshotName, installSnapshotName} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), ".foreign.example") || strings.Contains(string(data), "foreign-generated") {
			t.Fatalf("foreign NRPT data persisted in %s", name)
		}
	}
}

func TestWindowsRevisionManifestCorruptionBlocksPreflight(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "revisions", "r1", revisionManifestName), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Recover(context.Background()); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("corrupt manifest preflight error = %v", err)
	}
}

func TestWindowsForeignComparisonIgnoresOrderAndAdapterEnumerationChurn(t *testing.T) {
	before := newSafeBackend().state
	after := cloneMutationSnapshot(before)
	slices.Reverse(after.Routes)
	slices.Reverse(after.Firewall)
	slices.Reverse(after.NRPT)
	slices.Reverse(after.Adapters)
	after.Adapters = append(after.Adapters, Adapter{Index: 99, InterfaceGUID: "99999999-9999-4999-8999-999999999999", Kind: AdapterOther})
	if !foreignStateEqual(before, after) {
		t.Fatal("order or adapter enumeration churn was treated as foreign mutation")
	}
}

func TestWindowsRecoverySnapshotRejectsDigestCorruption(t *testing.T) {
	backend := newSafeBackend()
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, beforeSnapshotName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(context.Background()); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("corrupt snapshot rollback error = %v", err)
	}
}

func TestWindowsRecoverySnapshotSemanticValidation(t *testing.T) {
	backend := newSafeBackend()
	runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
	candidate := safeCandidate(t, "r1")
	if err := runtime.Preflight(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	artifacts := decodeCandidate(t, candidate)
	state := RouteState{ManagedRoute: artifacts.routes.Routes[0], Owner: ArtifactOwner, Revision: "r1"}
	for name, snapshot := range map[string]managedSnapshot{
		"duplicate": {Version: ArtifactVersion, Routes: []RouteState{state, state}},
		"default": func() managedSnapshot {
			invalid := state
			invalid.Destination = "0.0.0.0/0"
			return managedSnapshot{Version: ArtifactVersion, Routes: []RouteState{invalid}}
		}(),
		"foreign owner": {Version: ArtifactVersion, Routes: []RouteState{{ManagedRoute: state.ManagedRoute, Revision: "r1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runtime.validateManagedSnapshot(snapshot); err == nil {
				t.Fatal("unsafe recovery snapshot accepted")
			}
		})
	}
}

func TestWindowsExistingFirstInstallSnapshotMustMatchObservedBaseline(t *testing.T) {
	backend := newSafeBackend()
	runtime := &Runtime{Root: filepath.Join(t.TempDir(), "runtime"), Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()}
	candidate := safeCandidate(t, "r1")
	if err := runtime.Preflight(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stage(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	artifacts := decodeCandidate(t, candidate)
	state := RouteState{ManagedRoute: artifacts.routes.Routes[0], Owner: ArtifactOwner, Revision: "r1"}
	if err := runtime.writeSnapshot(installSnapshotName, managedSnapshot{Version: ArtifactVersion, Routes: []RouteState{state}}, false); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Snapshot(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("mismatched first-install snapshot error = %v", err)
	}
}

func TestWindowsEmergencyDisableAndFullRestorePreserveForeignState(t *testing.T) {
	backend := newSafeBackend()
	before := cloneMutationSnapshot(backend.state)
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	runtime := tx.Runtime.(*Runtime)
	if plan, err := runtime.PlanEmergencyDisable(context.Background()); err != nil || plan.RemoveVPNRoutes != 2 || plan.RemoveFirewall != 2 || plan.RemoveDNS != 2 || plan.RemoveEndpoints != 0 {
		t.Fatalf("emergency plan = %#v, %v", plan, err)
	}
	if err := tx.EmergencyDisable(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, err := tx.Journal.Load()
	if err != nil || journal.State != apply.StateDisabled {
		t.Fatalf("disabled journal = %#v, %v", journal, err)
	}
	if countOwnedRole(backend.state.Routes, RouteRoleEndpointDirect) != 2 || countOwnedRole(backend.state.Routes, RouteRoleVPNClass) != 0 {
		t.Fatalf("emergency route state = %#v", backend.state.Routes)
	}
	assertForeignUnchanged(t, before, backend.state)
	backend.calls = nil
	restarted := transactionForRoot(root, backend, &mutableClock{now: time.Unix(101, 0).UTC()})
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(backend.calls, func(call string) bool { return strings.HasPrefix(call, "add-") || strings.HasPrefix(call, "put-") }) {
		t.Fatalf("disabled recovery reapplied policy: %v", backend.calls)
	}
	if err := restarted.Apply(context.Background(), safeCandidate(t, "r2")); err == nil {
		t.Fatal("apply was not blocked while disabled")
	}
	if err := restarted.FullRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, err = restarted.Journal.Load()
	if err != nil || journal.State != apply.StateRestored {
		t.Fatalf("restored journal = %#v, %v", journal, err)
	}
	assertManagedEmpty(t, backend.state)
	assertForeignUnchanged(t, before, backend.state)
	if err := restarted.Apply(context.Background(), safeCandidate(t, "r2")); err != nil {
		t.Fatalf("apply remained blocked after safe full restore: %v", err)
	}
	if err := restarted.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertManagedEmpty(t, backend.state)
}

func TestWindowsRecoveryOperationsResumeDurableIntentAfterFault(t *testing.T) {
	backend := newSafeBackend()
	before := cloneMutationSnapshot(backend.state)
	root := filepath.Join(t.TempDir(), "runtime")
	tx := transactionForRoot(root, backend, &mutableClock{now: time.Unix(100, 0).UTC()})
	if err := tx.Apply(context.Background(), safeCandidate(t, "r1")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Confirm(); err != nil {
		t.Fatal(err)
	}
	backend.failCall = "remove-route:vpn-class:198.51.100.0/24"
	if err := tx.EmergencyDisable(context.Background()); err == nil {
		t.Fatal("emergency fault did not fail")
	}
	journal, err := tx.Journal.Load()
	if err != nil || journal.State != apply.StateDisabling {
		t.Fatalf("disable intent = %#v, %v", journal, err)
	}
	restarted := transactionForRoot(root, backend, &mutableClock{now: time.Unix(101, 0).UTC()})
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, _ = restarted.Journal.Load()
	if journal.State != apply.StateDisabled {
		t.Fatalf("disable recovery state = %#v", journal)
	}

	backend.persistentFailCall = "reload"
	if err := restarted.FullRestore(context.Background()); err == nil {
		t.Fatal("persistent full-restore fault did not fail")
	}
	journal, _ = restarted.Journal.Load()
	if journal.State != apply.StateRestoring {
		t.Fatalf("restore intent = %#v", journal)
	}
	if err := restarted.Recover(context.Background()); err == nil {
		t.Fatal("persistent restore fault unexpectedly converged")
	}
	backend.persistentFailCall = ""
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	journal, _ = restarted.Journal.Load()
	if journal.State != apply.StateRestored {
		t.Fatalf("restore recovery state = %#v", journal)
	}
	assertManagedEmpty(t, backend.state)
	assertForeignUnchanged(t, before, backend.state)
}

func safeCandidate(t *testing.T, revision string) apply.Candidate {
	t.Helper()
	artifacts := artifactSet{
		routes: RoutesArtifact{Version: ArtifactVersion, Owner: ArtifactOwner, Revision: revision, Routes: []ManagedRoute{
			{Role: RouteRoleEndpointDirect, Family: FamilyIPv4, Destination: "203.0.113.5/32", NextHop: "192.168.1.1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore, Protocol: RouteProtocol, JournalOwned: true},
			{Role: RouteRoleEndpointDirect, Family: FamilyIPv6, Destination: "2001:db8:ffff::5/128", NextHop: "2001:db8:1::1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore, Protocol: RouteProtocol, JournalOwned: true},
			{Role: RouteRoleVPNClass, Family: FamilyIPv4, Destination: "198.51.100.0/24", NextHop: "10.20.30.1", InterfaceGUID: testRedShieldGUID, InterfaceIndex: 21, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore, Protocol: RouteProtocol, JournalOwned: true},
			{Role: RouteRoleVPNClass, Family: FamilyIPv6, Destination: "2001:db8:100::/64", NextHop: "fd00::1", InterfaceGUID: testRedShieldGUID, InterfaceIndex: 21, Metric: ReservedRouteMetric, PolicyStore: RoutePolicyStore, Protocol: RouteProtocol, JournalOwned: true},
		}},
		firewall: FirewallArtifact{Version: ArtifactVersion, Owner: ArtifactOwner, Revision: revision, Rules: []FirewallRule{
			{Name: FirewallRuleName(revision, FamilyIPv4, "198.51.100.0/24", testPhysicalGUID), Family: FamilyIPv4, RemoteCIDR: "198.51.100.0/24", Action: "block", Direction: "outbound", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, PolicyStore: FirewallPolicyStore, Group: ownershipGroup(revision), Description: ownershipDescription(revision)},
			{Name: FirewallRuleName(revision, FamilyIPv6, "2001:db8:100::/64", testPhysicalGUID), Family: FamilyIPv6, RemoteCIDR: "2001:db8:100::/64", Action: "block", Direction: "outbound", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12, PolicyStore: FirewallPolicyStore, Group: ownershipGroup(revision), Description: ownershipDescription(revision)},
		}},
		dns: DNSArtifact{Version: ArtifactVersion, Owner: ArtifactOwner, Revision: revision, Rules: []NRPTRule{
			{LogicalID: "dns-v4", DisplayName: "hg-" + revision + "-dns-v4", Namespace: ".vpn.example", NameServers: []string{"198.51.100.53"}, Comment: ownershipDescription(revision)},
			{LogicalID: "dns-v6", DisplayName: "hg-" + revision + "-dns-v6", Namespace: ".v6.example", NameServers: []string{"2001:db8:100::53"}, Comment: ownershipDescription(revision)},
		}},
	}
	return encodeCandidate(t, artifacts)
}

func encodeCandidate(t *testing.T, artifacts artifactSet) apply.Candidate {
	t.Helper()
	routes, _ := json.Marshal(artifacts.routes)
	firewall, _ := json.Marshal(artifacts.firewall)
	dns, _ := json.Marshal(artifacts.dns)
	return apply.Candidate{RevisionID: artifacts.routes.Revision, Routes: routes, Firewall: firewall, DNS: dns}
}

func decodeCandidate(t *testing.T, candidate apply.Candidate) artifactSet {
	t.Helper()
	artifacts, err := parseArtifacts(candidate.RevisionID, candidate.Routes, candidate.Firewall, candidate.DNS)
	if err != nil {
		t.Fatal(err)
	}
	return artifacts
}

func newSafeBackend() *fakeMutationBackend {
	return &fakeMutationBackend{state: MutationSnapshot{
		Adapters: []Adapter{
			{Index: 12, InterfaceGUID: testPhysicalGUID, Kind: AdapterPhysical, Up: true},
			{Index: 21, InterfaceGUID: testRedShieldGUID, Kind: AdapterRedShield, Up: true},
			{Index: 31, InterfaceGUID: testCiscoGUID, Kind: AdapterCisco, Up: true},
		},
		Routes: []RouteState{
			{ManagedRoute: ManagedRoute{Family: FamilyIPv4, Destination: "0.0.0.0/0", NextHop: "192.168.1.1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12}},
			{ManagedRoute: ManagedRoute{Family: FamilyIPv6, Destination: "::/0", NextHop: "2001:db8:1::1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12}},
			{ManagedRoute: ManagedRoute{Family: FamilyIPv4, Destination: "10.50.0.0/16", NextHop: "0.0.0.0", InterfaceGUID: testCiscoGUID, InterfaceIndex: 31}, Protected: true},
			{ManagedRoute: ManagedRoute{Family: FamilyIPv4, Destination: "192.0.2.0/24", NextHop: "192.168.1.1", InterfaceGUID: testPhysicalGUID, InterfaceIndex: 12}},
		},
		Firewall: []FirewallState{{Rule: FirewallRule{Name: "foreign-firewall", Group: "foreign"}}},
		NRPT:     []NRPTState{{Rule: NRPTRule{Name: "foreign-generated", LogicalID: "foreign", Namespace: ".foreign.example"}}},
	}}
}

func newWindowsTransaction(t *testing.T, backend *fakeMutationBackend) *apply.Transaction {
	t.Helper()
	return transactionForRoot(filepath.Join(t.TempDir(), "runtime"), backend, &mutableClock{now: time.Unix(100, 0).UTC()})
}

func transactionForRoot(root string, backend *fakeMutationBackend, clock *mutableClock) *apply.Transaction {
	return &apply.Transaction{
		Runtime:         &Runtime{Root: root, Backend: backend, QualifiedEndpoints: testQualifiedEndpoints()},
		Journal:         apply.FileJournal{Path: filepath.Join(root, "journal.json")},
		Locker:          testLocker{},
		Watchdog:        testWatchdog{},
		Clock:           clock,
		ConfirmTimeout:  5 * time.Minute,
		RecoveryTimeout: 5 * time.Second,
	}
}

func testQualifiedEndpoints() []string {
	return []string{"203.0.113.5/32", "2001:db8:ffff::5/128"}
}

func cloneMutationSnapshot(snapshot MutationSnapshot) MutationSnapshot {
	data, _ := json.Marshal(snapshot)
	var clone MutationSnapshot
	_ = json.Unmarshal(data, &clone)
	return clone
}

func assertOrdered(t *testing.T, calls []string, want ...string) {
	t.Helper()
	position := -1
	for _, call := range want {
		next := slices.Index(calls[position+1:], call)
		if next < 0 {
			t.Fatalf("missing ordered call %q in %v", call, calls)
		}
		position += next + 1
	}
}

func assertManagedEmpty(t *testing.T, snapshot MutationSnapshot) {
	t.Helper()
	if slices.ContainsFunc(snapshot.Routes, func(value RouteState) bool { return value.Owner == ArtifactOwner }) ||
		slices.ContainsFunc(snapshot.Firewall, func(value FirewallState) bool { return value.Owner == ArtifactOwner }) ||
		slices.ContainsFunc(snapshot.NRPT, func(value NRPTState) bool { return value.Owner == ArtifactOwner }) {
		t.Fatalf("managed state remains: %#v", snapshot)
	}
}

func assertForeignUnchanged(t *testing.T, before, after MutationSnapshot) {
	t.Helper()
	filter := func(snapshot MutationSnapshot) MutationSnapshot {
		snapshot = cloneMutationSnapshot(snapshot)
		snapshot.Routes = slices.DeleteFunc(snapshot.Routes, func(value RouteState) bool { return value.Owner == ArtifactOwner })
		snapshot.Firewall = slices.DeleteFunc(snapshot.Firewall, func(value FirewallState) bool { return value.Owner == ArtifactOwner })
		snapshot.NRPT = slices.DeleteFunc(snapshot.NRPT, func(value NRPTState) bool { return value.Owner == ArtifactOwner })
		return snapshot
	}
	if !reflect.DeepEqual(filter(before), filter(after)) {
		t.Fatalf("foreign state changed\nbefore=%#v\nafter=%#v", filter(before), filter(after))
	}
}

func countOwnedRole(routes []RouteState, role string) int {
	count := 0
	for _, route := range routes {
		if route.Owner == ArtifactOwner && route.Role == role {
			count++
		}
	}
	return count
}
