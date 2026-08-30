package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
)

const (
	routesArtifactName      = "windows-routes.v1.json"
	sinksArtifactName       = "windows-sinks.v1.json"
	firewallArtifactName    = "windows-firewall.v1.json"
	dnsArtifactName         = "windows-nrpt.v1.json"
	beforeSnapshotName      = "pending-before.v1.json"
	installSnapshotName     = "before-install.v1.json"
	revisionManifestName    = "manifest.v1.json"
	maxManagedSnapshotBytes = 4 << 20
)

type RouteState struct {
	ManagedRoute
	Owner     string `json:"owner,omitempty"`
	Revision  string `json:"revision,omitempty"`
	Protected bool   `json:"protected,omitempty"`
	State     int    `json:"state,omitempty"`
}

type FirewallState struct {
	Rule     FirewallRule `json:"rule"`
	Owner    string       `json:"owner,omitempty"`
	Revision string       `json:"revision,omitempty"`
	// Effective is observed from ActiveStore. Ownership and removal still use
	// the exact PersistentStore identity, but VPN routes must never rely on a
	// local rule that Group Policy removed or narrowed in the resultant policy.
	Effective bool `json:"effective,omitempty"`
}

type NRPTState struct {
	Rule      NRPTRule `json:"rule"`
	Owner     string   `json:"owner,omitempty"`
	Revision  string   `json:"revision,omitempty"`
	Effective bool     `json:"effective,omitempty"`
}

type MutationSnapshot struct {
	Adapters         []Adapter       `json:"adapters"`
	Routes           []RouteState    `json:"routes"`
	Sinks            []SinkState     `json:"sinks"`
	Firewall         []FirewallState `json:"firewall"`
	FirewallEnforced bool            `json:"firewall_enforced"`
	NRPT             []NRPTState     `json:"nrpt"`
}

// MutationBackend is deliberately structured and injected. This package has
// no shell, PowerShell, executable, or live-network implementation.
type MutationBackend interface {
	Snapshot(context.Context) (MutationSnapshot, error)
	PutSink(context.Context, SinkState) error
	RemoveSink(context.Context, SinkState) error
	ResolveRoute(context.Context, AddressFamily, string) (ResolvedRoute, error)
	AddRoute(context.Context, RouteState) error
	RemoveRoute(context.Context, RouteState) error
	PutFirewall(context.Context, FirewallState) error
	RemoveFirewall(context.Context, FirewallState) error
	PutNRPT(context.Context, NRPTState) error
	RemoveNRPT(context.Context, NRPTState) error
	Reload(context.Context) error
}

// FirewallBatchMutationBackend is an optional extension for native backends
// that can resolve and mutate a bounded firewall set in a constant number of
// trusted host-process invocations. Runtime retains the single-rule fallback
// for deterministic test adapters and non-native implementations.
type FirewallBatchMutationBackend interface {
	PutFirewallBatch(context.Context, []FirewallState) error
	RemoveFirewallBatch(context.Context, []FirewallState) error
}

type Runtime struct {
	Root               string
	Backend            MutationBackend
	QualifiedEndpoints []string
	recoveryOnly       bool

	ownedRevisions          map[string]artifactSet
	recoveryPendingRevision string
	stagedRevision          string
	activeRevision          string
}

type managedSnapshot struct {
	Version  int             `json:"version"`
	Routes   []RouteState    `json:"routes"`
	Sinks    []SinkState     `json:"sinks"`
	Firewall []FirewallState `json:"firewall"`
	NRPT     []NRPTState     `json:"nrpt"`
}

type revisionManifest struct {
	Version  int                      `json:"version"`
	Revision string                   `json:"revision"`
	Files    map[string]manifestEntry `json:"files"`
}

type manifestEntry struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type WatchdogTaskIdentity struct {
	Type                string `json:"type"`
	Role                string `json:"role"`
	IdentitySHA256      string `json:"identity_sha256"`
	ObservedStateSHA256 string `json:"observed_state_sha256"`
}

type WatchdogTaskObserver interface {
	ObserveWatchdogTasks(context.Context) ([]WatchdogTaskIdentity, error)
}

type RecoveryPlan struct {
	RemoveVPNRoutes int `json:"remove_vpn_routes"`
	RetainSinks     int `json:"retain_sinks,omitempty"`
	RemoveSinks     int `json:"remove_sinks,omitempty"`
	RemoveFirewall  int `json:"remove_firewall"`
	RemoveDNS       int `json:"remove_dns"`
	RemoveEndpoints int `json:"remove_endpoint_routes,omitempty"`
	RestoreRoutes   int `json:"restore_routes,omitempty"`
	RestoreSinks    int `json:"restore_sinks,omitempty"`
	RestoreFirewall int `json:"restore_firewall,omitempty"`
	RestoreDNS      int `json:"restore_dns,omitempty"`
}

type FullRestorePlan struct {
	Schema                         string                 `json:"schema"`
	StateRootIdentity              string                 `json:"state_root_identity"`
	JournalState                   apply.State            `json:"journal_state"`
	JournalFileSHA256              string                 `json:"journal_file_sha256"`
	OwnershipRegistrySHA256        string                 `json:"ownership_registry_sha256"`
	OwnedEntryIdentities           []artifactIdentity     `json:"owned_entry_identities"`
	RegistryVersion                int                    `json:"registry_version"`
	BootMarkerSHA256               string                 `json:"boot_marker_sha256"`
	NonterminalMutation            bool                   `json:"nonterminal_mutation"`
	InstallSnapshotSHA256          string                 `json:"install_snapshot_sha256"`
	CurrentManagedSHA256           string                 `json:"current_managed_state_sha256"`
	PreservedForeignSHA256         string                 `json:"preserved_foreign_state_sha256"`
	FirewallEnforced               bool                   `json:"firewall_enforced"`
	ActiveRevisionPresent          bool                   `json:"active_revision_present"`
	ActiveRevisionManifestSHA256   string                 `json:"active_revision_manifest_sha256"`
	LKGRevisionPresent             bool                   `json:"lkg_revision_present"`
	LKGRevisionManifestSHA256      string                 `json:"lkg_revision_manifest_sha256"`
	PendingRevisionPresent         bool                   `json:"pending_revision_present"`
	PendingRevisionManifestSHA256  string                 `json:"pending_revision_manifest_sha256"`
	RecoveryRevisionPresent        bool                   `json:"recovery_revision_present"`
	RecoveryRevisionManifestSHA256 string                 `json:"recovery_revision_manifest_sha256"`
	RemoveRouteIdentities          []artifactIdentity     `json:"remove_route_identities"`
	RetainSinkIdentities           []artifactIdentity     `json:"retain_sink_identities"`
	RemoveSinkIdentities           []artifactIdentity     `json:"remove_sink_identities"`
	RemoveFirewallIdentities       []artifactIdentity     `json:"remove_firewall_identities"`
	RemoveNRPTIdentities           []artifactIdentity     `json:"remove_nrpt_identities"`
	RestoreRouteIdentities         []artifactIdentity     `json:"restore_route_identities"`
	RestoreSinkIdentities          []artifactIdentity     `json:"restore_sink_identities"`
	RestoreFirewallIdentities      []artifactIdentity     `json:"restore_firewall_identities"`
	RestoreNRPTIdentities          []artifactIdentity     `json:"restore_nrpt_identities"`
	WatchdogTaskIdentities         []WatchdogTaskIdentity `json:"watchdog_task_identities"`
	ProtectedConfigPathIdentity    string                 `json:"protected_config_path_identity"`
	CurrentConfigACLSHA256         string                 `json:"current_config_acl_sha256"`
	BaselineConfigACLSHA256        string                 `json:"baseline_config_acl_sha256"`
	ProtectedConfigSHA256          string                 `json:"protected_config_sha256"`
	ConfigACLSnapshotSHA256        string                 `json:"config_acl_snapshot_sha256"`
	ProtectedConfigOperation       string                 `json:"protected_config_operation"`
	HgctlSHA256                    string                 `json:"hgctl_sha256"`
	CanaryLauncherSHA256           string                 `json:"canary_launcher_sha256"`
	BootstrapDriverSHA256          string                 `json:"bootstrap_driver_sha256"`
	BootstrapPayloadSHA256         string                 `json:"bootstrap_payload_sha256"`
	LockAtomicIdentities           []artifactIdentity     `json:"lock_atomic_identities"`
	Counts                         RecoveryPlan           `json:"counts"`
}

func sha256JSON(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

func fileSHA256Bound(path string, beforeOpen func()) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("artifact is not one regular file")
	}
	if !os.SameFile(info, info) {
		return "", errors.New("artifact file identity is unavailable")
	}
	if beforeOpen != nil {
		beforeOpen()
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", errors.New("artifact file identity changed")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func fileSHA256IfRegular(path string) string {
	hash, _ := fileSHA256Bound(path, nil)
	return hash
}

func requiredFileSHA256(path, label string) (string, error) {
	hash, err := fileSHA256Bound(path, nil)
	if err != nil || len(hash) != 64 {
		return "", fmt.Errorf("%s identity is required", label)
	}
	return hash, nil
}

type configACLRestoreBinding struct {
	Version      int    `json:"version"`
	ConfigPath   string `json:"config_path"`
	ConfigSHA256 string `json:"config_sha256"`
	VolumeSerial string `json:"volume_serial"`
	FileIndex    string `json:"file_index"`
	SDDL         string `json:"sddl"`
}

func readConfigACLRestoreBinding(rootPath string) (configACLRestoreBinding, string, error) {
	return readConfigACLRestoreBindingBound(rootPath, nil)
}

func readConfigACLRestoreBindingBound(rootPath string, beforeOpen func()) (configACLRestoreBinding, string, error) {
	path := filepath.Join(rootPath, "config-source-before.v1.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot is not one bounded regular file")
	}
	if !os.SameFile(info, info) {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot file identity is unavailable")
	}
	if beforeOpen != nil {
		beforeOpen()
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return configACLRestoreBinding{}, "", err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return configACLRestoreBinding{}, "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var binding configACLRestoreBinding
	if err := decoder.Decode(&binding); err != nil {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot schema differs")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot contains trailing data")
	}
	if binding.Version != 1 || !filepath.IsAbs(binding.ConfigPath) || filepath.Clean(binding.ConfigPath) != binding.ConfigPath || len(binding.ConfigSHA256) != 64 || binding.SDDL == "" {
		return configACLRestoreBinding{}, "", errors.New("config ACL snapshot binding differs")
	}
	snapshotDigest := sha256.Sum256(data)
	return binding, fmt.Sprintf("%x", snapshotDigest[:]), nil
}

func (plan FullRestorePlan) IdentitySHA256() string { return sha256JSON(plan) }

func (plan FullRestorePlan) Validate() error {
	if plan.Schema != "home-gateway/windows-full-restore/v1" || plan.ProtectedConfigOperation != "restore-acl" || len(plan.WatchdogTaskIdentities) != 2 {
		return errors.New("full restore plan terminal identities are incomplete")
	}
	for label, value := range map[string]string{
		"state root": plan.StateRootIdentity, "journal": plan.JournalFileSHA256, "ownership registry": plan.OwnershipRegistrySHA256,
		"boot marker": plan.BootMarkerSHA256, "install snapshot": plan.InstallSnapshotSHA256, "managed state": plan.CurrentManagedSHA256,
		"foreign state": plan.PreservedForeignSHA256, "config path": plan.ProtectedConfigPathIdentity, "current config ACL": plan.CurrentConfigACLSHA256,
		"baseline config ACL": plan.BaselineConfigACLSHA256, "protected config": plan.ProtectedConfigSHA256, "config ACL snapshot": plan.ConfigACLSnapshotSHA256,
		"hgctl": plan.HgctlSHA256, "canary launcher": plan.CanaryLauncherSHA256, "bootstrap driver": plan.BootstrapDriverSHA256,
		"bootstrap payload": plan.BootstrapPayloadSHA256,
	} {
		if len(value) != 64 || strings.Trim(value, "0123456789abcdef") != "" {
			return fmt.Errorf("full restore plan %s identity is required", label)
		}
	}
	for label, binding := range map[string]struct {
		present bool
		hash    string
	}{
		"active revision":   {plan.ActiveRevisionPresent, plan.ActiveRevisionManifestSHA256},
		"LKG revision":      {plan.LKGRevisionPresent, plan.LKGRevisionManifestSHA256},
		"pending revision":  {plan.PendingRevisionPresent, plan.PendingRevisionManifestSHA256},
		"recovery revision": {plan.RecoveryRevisionPresent, plan.RecoveryRevisionManifestSHA256},
	} {
		validHash := len(binding.hash) == 64 && strings.Trim(binding.hash, "0123456789abcdef") == ""
		if binding.present != validHash {
			return fmt.Errorf("full restore plan %s manifest binding differs", label)
		}
	}
	expectedWatchdogs := expectedWatchdogTaskIdentitySet()
	watchdogIdentities := make(map[string]struct{}, len(plan.WatchdogTaskIdentities))
	for _, identity := range plan.WatchdogTaskIdentities {
		if identity.Type != "scheduled-task" || identity.Role != "remove" ||
			len(identity.IdentitySHA256) != 64 || strings.Trim(identity.IdentitySHA256, "0123456789abcdef") != "" ||
			len(identity.ObservedStateSHA256) != 64 || strings.Trim(identity.ObservedStateSHA256, "0123456789abcdef") != "" {
			return errors.New("full restore plan watchdog identity differs")
		}
		if _, ok := expectedWatchdogs[identity.IdentitySHA256]; !ok {
			return errors.New("full restore plan watchdog identity is not owned")
		}
		watchdogIdentities[identity.IdentitySHA256] = struct{}{}
	}
	if len(watchdogIdentities) != len(plan.WatchdogTaskIdentities) {
		return errors.New("full restore plan watchdog identities are not unique")
	}
	return nil
}

func expectedWatchdogTaskIdentitySet() map[string]struct{} {
	return map[string]struct{}{
		exactArtifactIdentity("scheduled-task", "", "remove", map[string]string{"task_name": "HomeGateway-P35-Recovery", "task_path": `\`}).SHA256:  {},
		exactArtifactIdentity("scheduled-task", "", "remove", map[string]string{"task_name": "HomeGateway-P35-Reconcile", "task_path": `\`}).SHA256: {},
	}
}

func (plan FullRestorePlan) ConfirmationChallenge(stateRoot string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(stateRoot) + "\x00" + plan.IdentitySHA256()))
	return "P35-FULL-RESTORE-" + strings.ToUpper(fmt.Sprintf("%x", digest[:8]))
}

func snapshotIdentities(snapshot managedSnapshot, role string) (routes, sinks, firewall, nrpt []artifactIdentity) {
	for _, value := range snapshot.Routes {
		routes = append(routes, exactArtifactIdentity("route", value.Family, role, value))
	}
	for _, value := range snapshot.Sinks {
		sinks = append(sinks, exactArtifactIdentity("sink", value.Route.Family, role, value))
	}
	for _, value := range snapshot.Firewall {
		firewall = append(firewall, exactArtifactIdentity("firewall", value.Rule.Family, role, value))
	}
	for _, value := range snapshot.NRPT {
		nrpt = append(nrpt, exactArtifactIdentity("nrpt", "", role, value))
	}
	for _, values := range [][]artifactIdentity{routes, sinks, firewall, nrpt} {
		sortArtifactIdentities(values)
	}
	return
}

func (runtime *Runtime) Preflight(ctx context.Context, revisions []string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	owned := make(map[string]artifactSet, len(revisions))
	for _, revision := range revisions {
		artifacts, err := runtime.readRevision(revision)
		if err != nil {
			return fmt.Errorf("read journal-owned Windows revision: %w", err)
		}
		owned[revision] = artifacts
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows mutation state: %w", err)
	}
	if err := verifyOwnedState(snapshot, owned); err != nil {
		return err
	}
	runtime.ownedRevisions = owned
	runtime.recoveryPendingRevision = ""
	return nil
}

func (runtime *Runtime) PreflightRecovery(ctx context.Context, journal apply.Journal) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	owned := make(map[string]artifactSet)
	for _, revision := range []string{journal.ActiveRevision, journal.LastKnownGoodRevision} {
		if revision == "" {
			continue
		}
		if _, exists := owned[revision]; exists {
			continue
		}
		artifacts, err := runtime.readRevision(revision)
		if err != nil {
			return fmt.Errorf("read recovery-owned Windows revision: %w", err)
		}
		owned[revision] = artifacts
	}
	pendingMissing := ""
	recoveryRevision := journal.PendingRevision
	if recoveryRevision == "" {
		recoveryRevision = journal.FailedRevision
	}
	if recoveryRevision != "" {
		artifacts, err := runtime.readRevision(recoveryRevision)
		if err != nil {
			pendingMissing = recoveryRevision
		} else {
			owned[recoveryRevision] = artifacts
		}
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := verifyOwnedStateRecovery(snapshot, owned, pendingMissing); err != nil {
		return err
	}
	runtime.ownedRevisions = owned
	runtime.recoveryPendingRevision = pendingMissing
	return nil
}

func (runtime *Runtime) Stage(_ context.Context, candidate apply.Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	artifacts, canonical, err := canonicalCandidate(candidate)
	if err != nil {
		return err
	}
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(directory); err == nil {
		if err := verifyArtifactFiles(directory, candidate.RevisionID, canonical); err != nil {
			return fmt.Errorf("immutable Windows revision differs: %w", err)
		}
		runtime.stagedRevision = candidate.RevisionID
		runtime.registerOwned(candidate.RevisionID, artifacts)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary := directory + ".next"
	if err := safeRemoveAll(runtime.Root, temporary); err != nil {
		return err
	}
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = safeRemoveAll(runtime.Root, temporary)
		}
	}()
	for _, name := range windowsArtifactNames() {
		data := canonical[name]
		if err := writeExclusive(filepath.Join(temporary, name), data); err != nil {
			return err
		}
	}
	manifestData, err := buildRevisionManifest(candidate.RevisionID, canonical)
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(temporary, revisionManifestName), manifestData); err != nil {
		return fmt.Errorf("commit Windows revision manifest: %w", err)
	}
	if err := publishDirectory(temporary, directory); err != nil {
		return fmt.Errorf("publish Windows revision: %w", err)
	}
	published = true
	runtime.stagedRevision = artifacts.routes.Revision
	runtime.registerOwned(candidate.RevisionID, artifacts)
	return nil
}

func (runtime *Runtime) Validate(ctx context.Context, candidate apply.Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	artifacts, canonical, err := canonicalCandidate(candidate)
	if err != nil {
		return err
	}
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	if err := verifyArtifactFiles(directory, candidate.RevisionID, canonical); err != nil {
		return err
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows state for validation: %w", err)
	}
	return runtime.validateCandidateAgainstSnapshot(artifacts, snapshot)
}

func (runtime *Runtime) Snapshot(ctx context.Context, activeRevision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	if runtime.stagedRevision == "" {
		return errors.New("no staged Windows revision is available for snapshot")
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("capture Windows before-snapshot: %w", err)
	}
	if err := verifyOwnedState(snapshot, runtime.ownedRevisions); err != nil {
		return fmt.Errorf("refuse snapshot after ownership drift: %w", err)
	}
	managed, err := filterManagedSnapshot(snapshot)
	if err != nil {
		return err
	}
	if err := runtime.writeSnapshot(beforeSnapshotName, managed, true); err != nil {
		return err
	}
	installPath, err := runtime.rootPath(installSnapshotName)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(installPath); errors.Is(err, os.ErrNotExist) {
		if err := runtime.writeSnapshot(installSnapshotName, managed, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		existing, err := runtime.readSnapshot(installSnapshotName)
		if err != nil {
			return fmt.Errorf("validate existing first-install snapshot: %w", err)
		}
		if activeRevision == "" && !managedSnapshotsEqual(existing, managed) {
			return errors.New("existing first-install snapshot differs from observed managed baseline")
		}
	}
	if activeRevision != "" {
		if err := runtime.writeMarker("lkg.json", activeRevision); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) Activate(ctx context.Context, candidate apply.Candidate) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	artifacts, _, err := canonicalCandidate(candidate)
	if err != nil {
		return err
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows state before activation: %w", err)
	}
	if err := verifyOwnedState(snapshot, runtime.ownedRevisions); err != nil {
		return fmt.Errorf("refuse activation after ownership drift: %w", err)
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, snapshot); err != nil {
		return err
	}
	// Additive-first replacement keeps fail-closed coverage throughout.
	if err := runtime.applyArtifacts(ctx, artifacts, true); err != nil {
		return err
	}
	if err := runtime.pruneStaleOwned(ctx, snapshot, artifacts); err != nil {
		return err
	}
	if err := runtime.requireCandidatePresent(ctx, artifacts); err != nil {
		return err
	}
	if err := runtime.writeMarker("active.json", candidate.RevisionID); err != nil {
		return err
	}
	runtime.activeRevision = candidate.RevisionID
	return nil
}

func (runtime *Runtime) Reload(ctx context.Context) error {
	if err := runtime.Backend.Reload(ctx); err != nil {
		return fmt.Errorf("reload structured Windows policy: %w", err)
	}
	return nil
}

func (runtime *Runtime) Commit(ctx context.Context, revision string) error {
	active, err := runtime.readMarker("active.json")
	if err != nil || active != revision {
		return errors.New("active Windows revision pointer does not match commit")
	}
	artifacts, err := runtime.readRevision(revision)
	if err != nil {
		return err
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, snapshot); err != nil {
		return err
	}
	if err := requireExactManagedState(snapshot, artifacts); err != nil {
		return err
	}
	return runtime.writeMarker("lkg.json", revision)
}

func (runtime *Runtime) PostCheck(ctx context.Context) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	revision := runtime.activeRevision
	if revision == "" {
		marker, err := runtime.readMarker("active.json")
		if err != nil {
			return err
		}
		revision = marker
	}
	artifacts, err := runtime.readRevision(revision)
	if err != nil {
		return err
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows post-check state: %w", err)
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, snapshot); err != nil {
		return fmt.Errorf("post-check safety validation: %w", err)
	}
	return requireExactManagedState(snapshot, artifacts)
}

func (runtime *Runtime) Reconcile(ctx context.Context, revision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	artifacts, err := runtime.readRevision(revision)
	if err != nil {
		return err
	}
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err := verifyOwnedState(snapshot, runtime.ownedRevisions); err != nil {
		return fmt.Errorf("refuse reconcile after ownership drift: %w", err)
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, snapshot); err != nil {
		return err
	}
	if err := runtime.applyArtifacts(ctx, artifacts, true); err != nil {
		return err
	}
	if err := runtime.Reload(ctx); err != nil {
		return err
	}
	runtime.activeRevision = revision
	if err := runtime.PostCheck(ctx); err != nil {
		return err
	}
	after, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if !foreignStateEqual(snapshot, after) {
		return errors.New("foreign Windows state changed during reconcile")
	}
	return nil
}

func (runtime *Runtime) Restore(ctx context.Context, revision string) error {
	if err := runtime.validateConfiguration(); err != nil {
		return err
	}
	original, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return err
	}
	if revision == "" {
		before, err := runtime.readSnapshot(beforeSnapshotName)
		if err != nil {
			return fmt.Errorf("read pre-apply Windows snapshot: %w", err)
		}
		if err := runtime.removeAllOwned(ctx, true); err != nil {
			return err
		}
		if err := runtime.applyManagedSnapshot(ctx, before); err != nil {
			return err
		}
		if err := runtime.Reload(ctx); err != nil {
			return err
		}
		after, err := runtime.Backend.Snapshot(ctx)
		if err != nil {
			return err
		}
		if !foreignStateEqual(original, after) || !managedSnapshotEqual(before, after) {
			return errors.New("windows before-snapshot restore post-check failed")
		}
		if err := runtime.clearActiveView(); err != nil {
			return err
		}
		runtime.activeRevision = ""
		runtime.recoveryPendingRevision = ""
		return nil
	}
	artifacts, err := runtime.readRevision(revision)
	if err != nil {
		return err
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, original); err != nil {
		return err
	}
	if err := runtime.applyArtifacts(ctx, artifacts, true); err != nil {
		return err
	}
	if err := runtime.pruneStaleOwned(ctx, original, artifacts); err != nil {
		return err
	}
	if err := runtime.requireCandidatePresent(ctx, artifacts); err != nil {
		return err
	}
	if err := runtime.Reload(ctx); err != nil {
		return err
	}
	if err := runtime.writeMarker("active.json", revision); err != nil {
		return err
	}
	if err := runtime.writeMarker("lkg.json", revision); err != nil {
		return err
	}
	runtime.activeRevision = revision
	if err := runtime.PostCheck(ctx); err != nil {
		return err
	}
	after, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if !foreignStateEqual(original, after) {
		return errors.New("foreign Windows state changed during restore")
	}
	runtime.recoveryPendingRevision = ""
	return nil
}

func (runtime *Runtime) PlanEmergencyDisable(ctx context.Context) (RecoveryPlan, error) {
	snapshot, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return RecoveryPlan{}, err
	}
	plan := RecoveryPlan{}
	for _, route := range snapshot.Routes {
		if route.Owner == ArtifactOwner && route.Role == RouteRoleVPNClass {
			plan.RemoveVPNRoutes++
		}
	}
	for _, sink := range snapshot.Sinks {
		if sink.Owner == ArtifactOwner {
			plan.RetainSinks++
		}
	}
	for _, rule := range snapshot.Firewall {
		if rule.Owner == ArtifactOwner {
			plan.RemoveFirewall++
		}
	}
	for _, rule := range snapshot.NRPT {
		if rule.Owner == ArtifactOwner {
			plan.RemoveDNS++
		}
	}
	return plan, nil
}

// EmergencyDisable removes only proven project-owned VPN-class, fail-closed,
// and DNS state. Endpoint-direct, foreign, Cisco, and OS state is preserved.
func (runtime *Runtime) EmergencyDisable(ctx context.Context) error {
	snapshot, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return err
	}
	if err := runtime.removeSelectiveOwned(ctx, snapshot); err != nil {
		return err
	}
	if err := runtime.Reload(ctx); err != nil {
		return err
	}
	after, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if !foreignStateEqual(snapshot, after) || countOwnedRoutes(after.Routes, RouteRoleVPNClass) != 0 || countOwnedFirewall(after.Firewall) != 0 || countOwnedNRPT(after.NRPT) != 0 || !slices.Equal(ownedRouteKeys(snapshot.Routes, RouteRoleEndpointDirect), ownedRouteKeys(after.Routes, RouteRoleEndpointDirect)) || !slices.Equal(ownedSinkStateKeys(snapshot.Sinks), ownedSinkStateKeys(after.Sinks)) {
		return errors.New("emergency disable post-check failed")
	}
	return nil
}

func (runtime *Runtime) PlanFullRestore(ctx context.Context, journal apply.Journal) (FullRestorePlan, error) {
	observer, ok := runtime.Backend.(WatchdogTaskObserver)
	if !ok {
		return FullRestorePlan{}, errors.New("bounded watchdog task observer is required")
	}
	watchdogTasks, err := observer.ObserveWatchdogTasks(ctx)
	if err != nil {
		return FullRestorePlan{}, errors.New("observe watchdog task identities")
	}
	snapshot, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return FullRestorePlan{}, err
	}
	before, err := runtime.readSnapshot(installSnapshotName)
	if err != nil {
		return FullRestorePlan{}, err
	}
	counts := RecoveryPlan{RestoreRoutes: len(before.Routes), RestoreSinks: len(before.Sinks), RestoreFirewall: len(before.Firewall), RestoreDNS: len(before.NRPT)}
	for _, route := range snapshot.Routes {
		if route.Owner != ArtifactOwner {
			continue
		}
		if route.Role == RouteRoleEndpointDirect {
			counts.RemoveEndpoints++
		} else {
			counts.RemoveVPNRoutes++
		}
	}
	counts.RemoveSinks = countOwnedSinks(snapshot.Sinks)
	counts.RemoveFirewall = countOwnedFirewall(snapshot.Firewall)
	counts.RemoveDNS = countOwnedNRPT(snapshot.NRPT)
	managed, err := filterManagedSnapshot(snapshot)
	if err != nil {
		return FullRestorePlan{}, err
	}
	removeRoutes, removeSinks, removeFirewall, removeNRPT := snapshotIdentities(managed, "remove")
	restoreRoutes, restoreSinks, restoreFirewall, restoreNRPT := snapshotIdentities(before, "restore")
	binding, configACLSnapshotSHA256, err := readConfigACLRestoreBinding(runtime.Root)
	if err != nil {
		return FullRestorePlan{}, err
	}
	protectedConfigSHA256, err := requiredFileSHA256(binding.ConfigPath, "protected config")
	if err != nil || protectedConfigSHA256 != binding.ConfigSHA256 {
		return FullRestorePlan{}, errors.New("protected config identity differs from the ACL snapshot")
	}
	currentConfigACLSHA256, err := configACLIdentity(binding.ConfigPath)
	if err != nil {
		return FullRestorePlan{}, err
	}
	baselineConfigACLDigest := sha256.Sum256([]byte(binding.SDDL))
	requiredHashes := make(map[string]string)
	for label, path := range map[string]string{
		"journal": filepath.Join(runtime.Root, "journal.json"), "ownership registry": filepath.Join(runtime.Root, "native-ownership.v1.json"),
		"boot marker": filepath.Join(runtime.Root, "boot-marker.v1.json"), "install snapshot": filepath.Join(runtime.Root, installSnapshotName),
		"hgctl": filepath.Join(runtime.Root, "bin", "hgctl.exe"), "canary launcher": filepath.Join(runtime.Root, "bin", "p35-canary.ps1"),
		"bootstrap driver": filepath.Join(runtime.Root, "bin", "p35-bootstrap.ps1"), "bootstrap payload": filepath.Join(runtime.Root, "bin", "p35-bootstrap-elevated.ps1"),
	} {
		requiredHashes[label], err = requiredFileSHA256(path, label)
		if err != nil {
			return FullRestorePlan{}, err
		}
	}
	plan := FullRestorePlan{
		Schema:                      "home-gateway/windows-full-restore/v1",
		StateRootIdentity:           StateRootIdentity(runtime.Root),
		JournalState:                journal.State,
		JournalFileSHA256:           requiredHashes["journal"],
		OwnershipRegistrySHA256:     requiredHashes["ownership registry"],
		RegistryVersion:             ArtifactVersion,
		BootMarkerSHA256:            requiredHashes["boot marker"],
		NonterminalMutation:         journal.State != apply.StateIdle && journal.State != apply.StateCommitted && journal.State != apply.StateRolledBack && journal.State != apply.StateRestored,
		InstallSnapshotSHA256:       requiredHashes["install snapshot"],
		CurrentManagedSHA256:        sha256JSON(managed),
		PreservedForeignSHA256:      sha256JSON(foreignKeys(snapshot)),
		FirewallEnforced:            snapshot.FirewallEnforced,
		RemoveRouteIdentities:       removeRoutes,
		RemoveSinkIdentities:        removeSinks,
		RemoveFirewallIdentities:    removeFirewall,
		RemoveNRPTIdentities:        removeNRPT,
		RestoreRouteIdentities:      restoreRoutes,
		RestoreSinkIdentities:       restoreSinks,
		RestoreFirewallIdentities:   restoreFirewall,
		RestoreNRPTIdentities:       restoreNRPT,
		WatchdogTaskIdentities:      watchdogTasks,
		ProtectedConfigPathIdentity: StateRootIdentity(binding.ConfigPath),
		CurrentConfigACLSHA256:      currentConfigACLSHA256,
		BaselineConfigACLSHA256:     fmt.Sprintf("%x", baselineConfigACLDigest[:]),
		ProtectedConfigSHA256:       protectedConfigSHA256,
		ConfigACLSnapshotSHA256:     configACLSnapshotSHA256,
		ProtectedConfigOperation:    "restore-acl",
		HgctlSHA256:                 requiredHashes["hgctl"],
		CanaryLauncherSHA256:        requiredHashes["canary launcher"],
		BootstrapDriverSHA256:       requiredHashes["bootstrap driver"],
		BootstrapPayloadSHA256:      requiredHashes["bootstrap payload"],
		Counts:                      counts,
	}
	plan.OwnedEntryIdentities = append(plan.OwnedEntryIdentities, removeRoutes...)
	plan.OwnedEntryIdentities = append(plan.OwnedEntryIdentities, removeSinks...)
	plan.OwnedEntryIdentities = append(plan.OwnedEntryIdentities, removeFirewall...)
	plan.OwnedEntryIdentities = append(plan.OwnedEntryIdentities, removeNRPT...)
	sortArtifactIdentities(plan.OwnedEntryIdentities)
	for label, revision := range map[string]string{"active": journal.ActiveRevision, "lkg": journal.LastKnownGoodRevision, "pending": journal.PendingRevision, "recovery": journal.FailedRevision} {
		hash := ""
		present := revision != ""
		if revision != "" {
			hash, err = runtime.bindRevisionManifest(revision)
			if err != nil {
				return FullRestorePlan{}, fmt.Errorf("bind %s revision manifest: %w", label, err)
			}
		}
		switch label {
		case "active":
			plan.ActiveRevisionPresent = present
			plan.ActiveRevisionManifestSHA256 = hash
		case "lkg":
			plan.LKGRevisionPresent = present
			plan.LKGRevisionManifestSHA256 = hash
		case "pending":
			plan.PendingRevisionPresent = present
			plan.PendingRevisionManifestSHA256 = hash
		case "recovery":
			plan.RecoveryRevisionPresent = present
			plan.RecoveryRevisionManifestSHA256 = hash
		}
	}
	// The active operation.lock is intentionally excluded: the read-only plan is
	// produced before locking, while execution recomputes it under that lock.
	// Only recoverable atomic leftovers are part of the exact restore identity.
	for _, path := range []string{filepath.Join(runtime.Root, "journal.json.next"), filepath.Join(runtime.Root, "native-ownership.v1.json.next"), filepath.Join(runtime.Root, "native-ownership.v1.json.routerd.replace-backup")} {
		if hash := fileSHA256IfRegular(path); hash != "" {
			plan.LockAtomicIdentities = append(plan.LockAtomicIdentities, exactArtifactIdentity("lock-or-atomic-leftover", "", "inspect", hash))
		}
	}
	sortArtifactIdentities(plan.LockAtomicIdentities)
	if err := plan.Validate(); err != nil {
		return FullRestorePlan{}, err
	}
	return plan, nil
}

// FullRestore returns managed resources to their exact first-install snapshot.
// The persisted snapshot contains project-owned state only; foreign NRPT
// namespaces are neither persisted nor logged.
func (runtime *Runtime) FullRestore(ctx context.Context) error {
	original, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return err
	}
	before, err := runtime.readSnapshot(installSnapshotName)
	if err != nil {
		return err
	}
	if err := runtime.removeAllOwned(ctx, true); err != nil {
		return err
	}
	if err := runtime.applyManagedSnapshot(ctx, before); err != nil {
		return err
	}
	if err := runtime.Reload(ctx); err != nil {
		return err
	}
	after, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if !foreignStateEqual(original, after) || !managedSnapshotEqual(before, after) {
		return errors.New("full restore post-check failed")
	}
	if err := runtime.clearActiveView(); err != nil {
		return err
	}
	runtime.activeRevision = ""
	return nil
}

func (runtime *Runtime) applyArtifacts(ctx context.Context, artifacts artifactSet, includeEndpoints bool) error {
	if includeEndpoints {
		for _, route := range artifacts.routes.Routes {
			if route.Role != RouteRoleEndpointDirect {
				continue
			}
			if err := runtime.Backend.AddRoute(ctx, RouteState{ManagedRoute: route, Owner: ArtifactOwner, Revision: artifacts.routes.Revision}); err != nil {
				return fmt.Errorf("apply structured endpoint-direct route: %w", err)
			}
		}
	}
	for _, route := range artifacts.sinks.Routes {
		if err := runtime.Backend.PutSink(ctx, SinkState{Route: route, Owner: ArtifactOwner, Revision: artifacts.sinks.Revision}); err != nil {
			return fmt.Errorf("apply structured Windows sink route: %w", err)
		}
	}
	afterSinks, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows sink state before firewall: %w", err)
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, afterSinks); err != nil {
		return fmt.Errorf("validate Windows sink state before firewall: %w", err)
	}
	if err := requireCandidateSinksPresent(afterSinks, artifacts.sinks); err != nil {
		return err
	}
	firewall := make([]FirewallState, 0, len(artifacts.firewall.Rules))
	for _, rule := range artifacts.firewall.Rules {
		firewall = append(firewall, FirewallState{Rule: rule, Owner: ArtifactOwner, Revision: artifacts.firewall.Revision})
	}
	if err := putFirewallStates(ctx, runtime.Backend, firewall); err != nil {
		return fmt.Errorf("apply structured Windows firewall rule: %w", err)
	}
	// Close the plan/apply race before installing any VPN-class route. A new
	// fallback /0 or a failed firewall write must be observable here, while no
	// canary target route exists yet and rollback remains network-neutral.
	afterFirewall, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows fail-closed state before VPN routes: %w", err)
	}
	if err := runtime.validateCandidateAgainstSnapshot(artifacts, afterFirewall); err != nil {
		return fmt.Errorf("validate Windows fail-closed state before VPN routes: %w", err)
	}
	if err := requireCandidateSinksPresent(afterFirewall, artifacts.sinks); err != nil {
		return err
	}
	if err := requireCandidateFirewallPresent(afterFirewall, artifacts.firewall); err != nil {
		return err
	}
	for _, route := range artifacts.routes.Routes {
		if route.Role == RouteRoleVPNClass {
			if err := runtime.Backend.AddRoute(ctx, RouteState{ManagedRoute: route, Owner: ArtifactOwner, Revision: artifacts.routes.Revision}); err != nil {
				return fmt.Errorf("apply structured VPN-class route: %w", err)
			}
		}
	}
	if err := runtime.requireTunnelEffectiveRoutes(ctx, artifacts); err != nil {
		return err
	}
	for _, rule := range artifacts.dns.Rules {
		if err := runtime.Backend.PutNRPT(ctx, NRPTState{Rule: rule, Owner: ArtifactOwner, Revision: artifacts.dns.Revision}); err != nil {
			return fmt.Errorf("apply structured Windows DNS policy: %w", err)
		}
	}
	return nil
}

func (runtime *Runtime) applyManagedSnapshot(ctx context.Context, snapshot managedSnapshot) error {
	for _, route := range snapshot.Routes {
		if route.Role == RouteRoleEndpointDirect {
			if err := runtime.Backend.AddRoute(ctx, route); err != nil {
				return err
			}
		}
	}
	for _, sink := range snapshot.Sinks {
		if err := runtime.Backend.PutSink(ctx, sink); err != nil {
			return err
		}
	}
	if err := putFirewallStates(ctx, runtime.Backend, snapshot.Firewall); err != nil {
		return err
	}
	for _, route := range snapshot.Routes {
		if route.Role != RouteRoleEndpointDirect {
			if err := runtime.Backend.AddRoute(ctx, route); err != nil {
				return err
			}
		}
	}
	for _, rule := range snapshot.NRPT {
		if err := runtime.Backend.PutNRPT(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) removeAllOwned(ctx context.Context, includeEndpoints bool) error {
	snapshot, err := runtime.verifiedCurrentSnapshot(ctx)
	if err != nil {
		return err
	}
	if err := runtime.removeSelectiveOwned(ctx, snapshot); err != nil {
		return err
	}
	if includeEndpoints {
		for _, route := range snapshot.Routes {
			if route.Owner == ArtifactOwner && route.Role == RouteRoleEndpointDirect {
				if err := runtime.Backend.RemoveRoute(ctx, route); err != nil {
					return fmt.Errorf("remove owned endpoint route: %w", err)
				}
			}
		}
	}
	for _, sink := range snapshot.Sinks {
		if sink.Owner == ArtifactOwner {
			if err := runtime.Backend.RemoveSink(ctx, sink); err != nil {
				return fmt.Errorf("remove owned sink route: %w", err)
			}
		}
	}
	return nil
}

func (runtime *Runtime) removeSelectiveOwned(ctx context.Context, snapshot MutationSnapshot) error {
	for _, route := range snapshot.Routes {
		if route.Owner == ArtifactOwner && route.Role == RouteRoleVPNClass {
			if err := runtime.Backend.RemoveRoute(ctx, route); err != nil {
				return fmt.Errorf("remove owned VPN-class route: %w", err)
			}
		}
	}
	for _, rule := range snapshot.NRPT {
		if rule.Owner == ArtifactOwner {
			if err := runtime.Backend.RemoveNRPT(ctx, rule); err != nil {
				return fmt.Errorf("remove owned DNS policy: %w", err)
			}
		}
	}
	firewall := make([]FirewallState, 0, len(snapshot.Firewall))
	for _, rule := range snapshot.Firewall {
		if rule.Owner == ArtifactOwner {
			firewall = append(firewall, rule)
		}
	}
	if err := removeFirewallStates(ctx, runtime.Backend, firewall); err != nil {
		return fmt.Errorf("remove owned firewall rule: %w", err)
	}
	return nil
}

func (runtime *Runtime) requireCandidatePresent(ctx context.Context, artifacts artifactSet) error {
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	filtered := MutationSnapshot{Adapters: snapshot.Adapters, FirewallEnforced: snapshot.FirewallEnforced}
	for _, route := range snapshot.Routes {
		if route.Owner != ArtifactOwner || route.Revision == artifacts.routes.Revision {
			filtered.Routes = append(filtered.Routes, route)
		}
	}
	for _, state := range snapshot.Firewall {
		if state.Owner != ArtifactOwner || state.Revision == artifacts.firewall.Revision {
			filtered.Firewall = append(filtered.Firewall, state)
		}
	}
	for _, state := range snapshot.Sinks {
		if state.Owner != ArtifactOwner || state.Revision == artifacts.sinks.Revision {
			filtered.Sinks = append(filtered.Sinks, state)
		}
	}
	for _, state := range snapshot.NRPT {
		if state.Owner != ArtifactOwner || state.Revision == artifacts.dns.Revision {
			filtered.NRPT = append(filtered.NRPT, state)
		}
	}
	return requireExactManagedState(filtered, artifacts)
}

func (runtime *Runtime) pruneStaleOwned(ctx context.Context, before MutationSnapshot, artifacts artifactSet) error {
	desiredRoutes := make(map[string]struct{}, len(artifacts.routes.Routes))
	for _, route := range artifacts.routes.Routes {
		desiredRoutes[routeTupleKey(route)] = struct{}{}
	}
	desiredFirewall := make(map[string]struct{}, len(artifacts.firewall.Rules))
	for _, rule := range artifacts.firewall.Rules {
		desiredFirewall[rule.Name] = struct{}{}
	}
	desiredDNS := make(map[string]struct{}, len(artifacts.dns.Rules))
	for _, rule := range artifacts.dns.Rules {
		desiredDNS[rule.LogicalID] = struct{}{}
	}
	desiredSinks := make(map[string]struct{}, len(artifacts.sinks.Routes))
	for _, route := range artifacts.sinks.Routes {
		desiredSinks[sinkTupleKey(route)] = struct{}{}
	}
	for _, state := range before.NRPT {
		if state.Owner == ArtifactOwner {
			_, retained := desiredDNS[state.Rule.LogicalID]
			if state.Revision != artifacts.dns.Revision || !retained {
				if err := runtime.Backend.RemoveNRPT(ctx, state); err != nil {
					return err
				}
			}
		}
	}
	for _, state := range before.Routes {
		if state.Owner == ArtifactOwner {
			if _, retained := desiredRoutes[routeTupleKey(state.ManagedRoute)]; !retained {
				if err := runtime.Backend.RemoveRoute(ctx, state); err != nil {
					return err
				}
			}
		}
	}
	staleFirewall := make([]FirewallState, 0, len(before.Firewall))
	for _, state := range before.Firewall {
		if state.Owner == ArtifactOwner {
			if _, retained := desiredFirewall[state.Rule.Name]; !retained {
				staleFirewall = append(staleFirewall, state)
			}
		}
	}
	if err := removeFirewallStates(ctx, runtime.Backend, staleFirewall); err != nil {
		return err
	}
	for _, state := range before.Sinks {
		if state.Owner == ArtifactOwner {
			if _, retained := desiredSinks[sinkTupleKey(state.Route)]; !retained {
				if err := runtime.Backend.RemoveSink(ctx, state); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func putFirewallStates(ctx context.Context, backend MutationBackend, states []FirewallState) error {
	if len(states) == 0 {
		return nil
	}
	if batch, ok := backend.(FirewallBatchMutationBackend); ok {
		return batch.PutFirewallBatch(ctx, append([]FirewallState(nil), states...))
	}
	for _, state := range states {
		if err := backend.PutFirewall(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func removeFirewallStates(ctx context.Context, backend MutationBackend, states []FirewallState) error {
	if len(states) == 0 {
		return nil
	}
	if batch, ok := backend.(FirewallBatchMutationBackend); ok {
		return batch.RemoveFirewallBatch(ctx, append([]FirewallState(nil), states...))
	}
	for _, state := range states {
		if err := backend.RemoveFirewall(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) verifiedCurrentSnapshot(ctx context.Context) (MutationSnapshot, error) {
	snapshot, err := runtime.Backend.Snapshot(ctx)
	if err != nil {
		return MutationSnapshot{}, err
	}
	var ownershipErr error
	if runtime.recoveryPendingRevision != "" {
		ownershipErr = verifyOwnedStateRecovery(snapshot, runtime.ownedRevisions, runtime.recoveryPendingRevision)
	} else {
		ownershipErr = verifyOwnedState(snapshot, runtime.ownedRevisions)
	}
	if ownershipErr != nil {
		return MutationSnapshot{}, ownershipErr
	}
	return snapshot, nil
}

func (runtime *Runtime) registerOwned(revision string, artifacts artifactSet) {
	if runtime.ownedRevisions == nil {
		runtime.ownedRevisions = make(map[string]artifactSet)
	}
	runtime.ownedRevisions[revision] = artifacts
}

func (runtime *Runtime) validateCandidateAgainstSnapshot(artifacts artifactSet, snapshot MutationSnapshot) error {
	if hasVPNRoutes(artifacts.routes.Routes) && !snapshot.FirewallEnforced {
		return errors.New("effective Windows firewall profiles do not enforce local fail-closed rules")
	}
	adapters := make(map[string]Adapter, len(snapshot.Adapters))
	for _, adapter := range snapshot.Adapters {
		adapters[strings.ToLower(adapter.InterfaceGUID)] = adapter
	}
	qualified := make(map[string]int, len(runtime.QualifiedEndpoints))
	for _, value := range runtime.QualifiedEndpoints {
		qualified[value] = 0
	}
	tunnelGUID := ""
	for _, route := range artifacts.routes.Routes {
		if route.Role != RouteRoleVPNClass {
			continue
		}
		guid := strings.ToLower(route.InterfaceGUID)
		adapter, exists := adapters[guid]
		if !exists || !adapter.Up || adapter.Kind != AdapterTunnel {
			return errors.New("VPN-class route does not use one active stable Tunnel adapter")
		}
		if tunnelGUID != "" && tunnelGUID != guid {
			return errors.New("vpn-class routes span multiple Tunnel adapters")
		}
		tunnelGUID = guid
	}
	failClosedAdapters := make(map[string]Adapter)
	for guid, adapter := range adapters {
		if _, err := canonicalGUID(guid); err != nil || adapter.Index <= 0 {
			return errors.New("windows adapter snapshot contains an unstable identity")
		}
		switch adapter.Kind {
		case AdapterTunnel:
			if tunnelGUID == "" || guid != tunnelGUID {
				return errors.New("unqualified Tunnel adapter could bypass canary fail-closed coverage")
			}
		case AdapterLoopback:
			continue
		default:
			failClosedAdapters[guid] = adapter
		}
	}
	if len(failClosedAdapters) == 0 || len(failClosedAdapters) > maxCanaryFallbackAdapters {
		return errors.New("windows fail-closed adapter set is empty or exceeds the bounded limit")
	}
	protected, err := protectedPrefixes(snapshot, adapters)
	if err != nil {
		return err
	}
	fallbackDefaults := make(map[AddressFamily]map[string]struct{})
	for _, current := range snapshot.Routes {
		prefix, err := netip.ParsePrefix(current.Destination)
		guid := strings.ToLower(current.InterfaceGUID)
		adapter, exists := adapters[guid]
		if err == nil && prefix.Bits() == 0 {
			if _, guidErr := canonicalGUID(guid); guidErr != nil || !exists || adapter.Index != current.InterfaceIndex || current.Family != addressFamily(prefix.Addr()) || current.State < routeStateAlive || current.State > 2 {
				return errors.New("live default route is not bound to one stable adapter")
			}
			if adapter.Kind == AdapterTunnel {
				if tunnelGUID == "" || guid != tunnelGUID {
					return errors.New("unqualified Tunnel default path could bypass canary fail-closed coverage")
				}
				continue
			}
			if adapter.Kind == AdapterLoopback {
				return errors.New("loopback default path cannot be covered safely")
			}
			if fallbackDefaults[current.Family] == nil {
				fallbackDefaults[current.Family] = make(map[string]struct{})
			}
			fallbackDefaults[current.Family][guid] = struct{}{}
		}
	}
	endpointPrefixes := make([]netip.Prefix, 0)
	for _, assertion := range artifacts.routes.DirectAssertions {
		adapter, exists := adapters[assertion.InterfaceGUID]
		if !exists || !adapter.Up || adapter.Kind != AdapterPhysical {
			return errors.New("endpoint-direct assertion refers to a stale or non-physical interface")
		}
		matched := slices.ContainsFunc(snapshot.Routes, func(current RouteState) bool {
			return current.Owner != ArtifactOwner && current.Family == assertion.Family && current.Destination == assertion.Destination && current.NextHop == assertion.NextHop && current.InterfaceGUID == assertion.InterfaceGUID
		})
		if !matched {
			return errors.New("pre-existing endpoint-direct route assertion is not satisfied")
		}
		prefix, _ := netip.ParsePrefix(assertion.Destination)
		if _, trusted := qualified[prefix.String()]; !trusted {
			return errors.New("endpoint-direct assertion is outside the trusted qualified endpoint set")
		}
		qualified[prefix.String()]++
		endpointPrefixes = append(endpointPrefixes, prefix)
	}
	for _, route := range artifacts.routes.Routes {
		adapter, exists := adapters[strings.ToLower(route.InterfaceGUID)]
		if !exists || !adapter.Up {
			return errors.New("candidate refers to a stale or mismatched interface GUID snapshot")
		}
		prefix, _ := netip.ParsePrefix(route.Destination)
		if route.Role == RouteRoleEndpointDirect {
			if adapter.Kind != AdapterPhysical {
				return errors.New("endpoint-direct route does not use a physical adapter")
			}
			if _, trusted := qualified[prefix.String()]; !trusted {
				return errors.New("managed endpoint-direct route is outside the trusted qualified endpoint set")
			}
			qualified[prefix.String()]++
			endpointPrefixes = append(endpointPrefixes, prefix)
		} else if adapter.Kind != AdapterTunnel {
			return errors.New("VPN-class route does not use the Tunnel adapter")
		}
		for _, current := range snapshot.Routes {
			if routeCollision(route, current.ManagedRoute) && current.Owner != ArtifactOwner {
				return errors.New("unowned route collision detected")
			}
		}
	}
	for _, count := range qualified {
		if count != 1 {
			return errors.New("every trusted qualified endpoint requires exactly one direct route or assertion")
		}
	}
	protected = append(protected, endpointPrefixes...)
	for _, route := range artifacts.routes.Routes {
		if route.Role != RouteRoleVPNClass {
			continue
		}
		prefix, _ := netip.ParsePrefix(route.Destination)
		if overlapsAny(prefix, protected) {
			return errors.New("VPN-class route overlaps an endpoint, system, or Cisco protected prefix")
		}
	}
	for _, rule := range artifacts.firewall.Rules {
		guid := strings.ToLower(rule.InterfaceGUID)
		adapter, exists := adapters[guid]
		if !exists || adapter.Kind == AdapterTunnel || adapter.Kind == AdapterLoopback {
			return errors.New("firewall rule refers to a stale, mismatched, or unsupported fallback interface GUID")
		}
		for _, current := range snapshot.Firewall {
			if (current.Rule.Name == rule.Name || current.Rule.Group == rule.Group) && current.Owner != ArtifactOwner {
				return errors.New("unowned firewall collision detected")
			}
		}
		prefix, _ := netip.ParsePrefix(rule.RemoteCIDR)
		if overlapsAny(prefix, protected) {
			return errors.New("firewall rule overlaps an endpoint, system, or Cisco protected prefix")
		}
		if _, covered := failClosedAdapters[guid]; !covered {
			return errors.New("firewall rule is not bound to a stable fail-closed adapter")
		}
	}
	for _, route := range artifacts.routes.Routes {
		if route.Role != RouteRoleVPNClass {
			continue
		}
		for guid := range failClosedAdapters {
			if !slices.ContainsFunc(artifacts.firewall.Rules, func(rule FirewallRule) bool {
				return rule.Family == route.Family && rule.RemoteCIDR == route.Destination && rule.InterfaceGUID == guid
			}) {
				return errors.New("VPN-class route lacks fail-closed coverage for every stable non-Tunnel adapter")
			}
		}
	}
	for _, sink := range artifacts.sinks.Routes {
		for _, current := range snapshot.Sinks {
			if sink.Family == current.Route.Family && sink.Destination == current.Route.Destination && current.Owner != ArtifactOwner {
				return errors.New("unowned sink route collision detected")
			}
		}
	}
	for _, current := range snapshot.Sinks {
		if current.Owner != ArtifactOwner {
			continue
		}
		artifactsForState, exists := runtime.ownedRevisions[current.Revision]
		if current.Revision == artifacts.sinks.Revision {
			artifactsForState = artifacts
			exists = true
		}
		if !exists || validateOwnedSinkState(current, artifactsForState) != nil {
			return errors.New("managed sink ownership collision or drift detected")
		}
	}
	for _, rule := range artifacts.dns.Rules {
		for _, server := range rule.NameServers {
			address, _ := netip.ParseAddr(server)
			covered := slices.ContainsFunc(artifacts.routes.Routes, func(route ManagedRoute) bool {
				if route.Role != RouteRoleVPNClass || route.Family != addressFamily(address) {
					return false
				}
				prefix, _ := netip.ParsePrefix(route.Destination)
				return prefix.Contains(address)
			})
			if !covered {
				return errors.New("DNS nameserver is not covered by a fail-closed VPN-class prefix")
			}
		}
		for _, current := range snapshot.NRPT {
			if (strings.EqualFold(current.Rule.Namespace, rule.Namespace) || current.Rule.LogicalID == rule.LogicalID) && current.Owner != ArtifactOwner {
				return errors.New("unowned DNS policy collision detected")
			}
		}
	}
	return nil
}

func (runtime *Runtime) requireTunnelEffectiveRoutes(ctx context.Context, artifacts artifactSet) error {
	for _, route := range artifacts.routes.Routes {
		if route.Role != RouteRoleVPNClass {
			continue
		}
		resolved, err := runtime.Backend.ResolveRoute(ctx, route.Family, route.Destination)
		if err != nil {
			return fmt.Errorf("resolve effective Windows route for %s: %w", route.Destination, err)
		}
		if resolved.NoRoute || resolved.Family != route.Family || resolved.Destination != route.Destination || !strings.EqualFold(resolved.InterfaceGUID, route.InterfaceGUID) || resolved.InterfaceIndex != route.InterfaceIndex {
			return errors.New("effective Windows route does not select the qualified Tunnel interface")
		}
	}
	return nil
}

func protectedPrefixes(snapshot MutationSnapshot, adapters map[string]Adapter) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0)
	for _, route := range snapshot.Routes {
		if route.Owner == ArtifactOwner {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || addressFamily(prefix.Addr()) != route.Family {
			return nil, errors.New("unowned system route has an invalid destination")
		}
		if prefix.Bits() == 0 {
			continue
		}
		guid := strings.ToLower(route.InterfaceGUID)
		adapter, exists := adapters[guid]
		if _, guidErr := canonicalGUID(guid); guidErr != nil || !exists || adapter.Index <= 0 || route.InterfaceIndex != adapter.Index || route.State < routeStateAlive || route.State > 2 {
			return nil, errors.New("unowned system route is not bound to one stable adapter")
		}
		if route.Protected || adapter.Kind != AdapterTunnel && adapter.Kind != AdapterLoopback {
			result = append(result, prefix)
		}
	}
	return result, nil
}

func overlapsAny(prefix netip.Prefix, others []netip.Prefix) bool {
	for _, other := range others {
		if addressFamily(prefix.Addr()) == addressFamily(other.Addr()) && (prefix.Contains(other.Addr()) || other.Contains(prefix.Addr())) {
			return true
		}
	}
	return false
}

func routeCollision(left, right ManagedRoute) bool {
	return left.Family == right.Family && left.Destination == right.Destination
}

func verifyOwnedState(snapshot MutationSnapshot, owned map[string]artifactSet) error {
	for _, route := range snapshot.Routes {
		reserved := route.PolicyStore == RoutePolicyStore && route.Metric == ReservedRouteMetric || route.Owner == ArtifactOwner
		if !reserved {
			continue
		}
		artifacts, ok := owned[route.Revision]
		if route.Owner != ArtifactOwner || !ok || !slices.ContainsFunc(artifacts.routes.Routes, func(want ManagedRoute) bool { return want == route.ManagedRoute }) {
			return errors.New("reserved route ownership collision or drift detected")
		}
	}
	for _, sink := range snapshot.Sinks {
		reserved := sink.Route.PolicyStore == SinkPolicyStore && sink.Route.Metric == ReservedSinkMetric || sink.Owner == ArtifactOwner
		if !reserved {
			continue
		}
		artifacts, ok := owned[sink.Revision]
		if sink.Owner != ArtifactOwner || !ok || validateOwnedSinkState(sink, artifacts) != nil {
			return errors.New("sink ownership collision or drift detected")
		}
	}
	for _, state := range snapshot.Firewall {
		reserved := strings.HasPrefix(state.Rule.Group, ArtifactOwner+"/") || state.Owner == ArtifactOwner
		if !reserved {
			continue
		}
		artifacts, ok := owned[state.Revision]
		if state.Owner != ArtifactOwner || !ok || !slices.Contains(artifacts.firewall.Rules, state.Rule) {
			return errors.New("firewall ownership collision or drift detected")
		}
	}
	for _, state := range snapshot.NRPT {
		reserved := strings.HasPrefix(state.Rule.Comment, ArtifactOwner+";") || state.Owner == ArtifactOwner
		if !reserved {
			continue
		}
		artifacts, ok := owned[state.Revision]
		if state.Owner != ArtifactOwner || !ok || !slices.ContainsFunc(artifacts.dns.Rules, func(want NRPTRule) bool { return nrptEqual(want, state.Rule) }) {
			return errors.New("DNS ownership collision or drift detected")
		}
	}
	return nil
}

func verifyOwnedStateRecovery(snapshot MutationSnapshot, owned map[string]artifactSet, missingPending string) error {
	if missingPending == "" {
		return verifyOwnedState(snapshot, owned)
	}
	pendingRoutes := 0
	pendingSinks := 0
	pendingFirewall := 0
	pendingDNS := 0
	for _, route := range snapshot.Routes {
		if route.Revision != missingPending {
			continue
		}
		pendingRoutes++
		prefix, prefixErr := parseExplicitPrefix(route.Family, route.Destination)
		_, guidErr := canonicalGUID(route.InterfaceGUID)
		if route.Owner != ArtifactOwner || route.Protected || prefixErr != nil || prefix.Bits() == 0 || guidErr != nil || route.InterfaceIndex <= 0 || route.Metric != ReservedRouteMetric || route.PolicyStore != RoutePolicyStore || route.Protocol != RouteProtocol || !route.JournalOwned || route.Role != RouteRoleEndpointDirect && route.Role != RouteRoleVPNClass {
			return errors.New("incomplete pending revision has an unauthorized route marker")
		}
	}
	for _, state := range snapshot.Sinks {
		if state.Revision != missingPending {
			continue
		}
		pendingSinks++
		prefix, prefixErr := parseExplicitPrefix(state.Route.Family, state.Route.Destination)
		nextHop, nextHopErr := netip.ParseAddr(state.Route.NextHop)
		if state.Owner != ArtifactOwner || prefixErr != nil || prefix.Bits() != prefix.Addr().BitLen() || nextHopErr != nil || addressFamily(nextHop) != state.Route.Family || !nextHop.IsUnspecified() || state.Route.InterfaceIndex != LoopbackInterfaceIndex || state.Route.Metric != ReservedSinkMetric || state.Route.PolicyStore != SinkPolicyStore || state.Route.Protocol != RouteProtocol || !state.Route.JournalOwned {
			return errors.New("incomplete pending revision has an unauthorized sink marker")
		}
	}
	for _, state := range snapshot.Firewall {
		if state.Revision != missingPending {
			continue
		}
		pendingFirewall++
		_, prefixErr := parseExplicitPrefix(state.Rule.Family, state.Rule.RemoteCIDR)
		_, guidErr := canonicalGUID(state.Rule.InterfaceGUID)
		if state.Owner != ArtifactOwner || prefixErr != nil || guidErr != nil || state.Rule.InterfaceIndex <= 0 || state.Rule.Action != "block" || state.Rule.Direction != "outbound" || state.Rule.PolicyStore != FirewallPolicyStore || state.Rule.Group != ownershipGroup(missingPending) || state.Rule.Description != ownershipDescription(missingPending) || state.Rule.Name != FirewallRuleName(missingPending, state.Rule.Family, state.Rule.RemoteCIDR, state.Rule.InterfaceGUID) {
			return errors.New("incomplete pending revision has an unauthorized firewall marker")
		}
	}
	for _, state := range snapshot.NRPT {
		if state.Revision != missingPending {
			continue
		}
		pendingDNS++
		validServers := len(state.Rule.NameServers) > 0 && len(state.Rule.NameServers) <= 4
		for _, server := range state.Rule.NameServers {
			address, err := netip.ParseAddr(server)
			validServers = validServers && err == nil && address.Zone() == "" && !address.Is4In6()
		}
		if state.Owner != ArtifactOwner || state.Rule.LogicalID == "" || state.Rule.Name == "" || !validDNSNamespace(state.Rule.Namespace) || !validServers || state.Rule.Comment != ownershipDescription(missingPending) {
			return errors.New("incomplete pending revision has an unauthorized DNS marker")
		}
	}
	if pendingRoutes > maxManagedRoutes || pendingSinks > maxManagedRoutes || pendingFirewall > maxFirewallRules || pendingDNS > maxDNSRules {
		return errors.New("pending recovery ownership inventory exceeds resource limits")
	}
	filtered := snapshot
	filtered.Routes = slices.DeleteFunc(append([]RouteState(nil), snapshot.Routes...), func(value RouteState) bool { return value.Revision == missingPending })
	filtered.Sinks = slices.DeleteFunc(append([]SinkState(nil), snapshot.Sinks...), func(value SinkState) bool { return value.Revision == missingPending })
	filtered.Firewall = slices.DeleteFunc(append([]FirewallState(nil), snapshot.Firewall...), func(value FirewallState) bool { return value.Revision == missingPending })
	filtered.NRPT = slices.DeleteFunc(append([]NRPTState(nil), snapshot.NRPT...), func(value NRPTState) bool { return value.Revision == missingPending })
	return verifyOwnedState(filtered, owned)
}

func validateOwnedSinkState(state SinkState, artifacts artifactSet) error {
	if state.Owner != ArtifactOwner || state.Revision != artifacts.sinks.Revision || !state.PersistentPresent || !state.ActivePresent {
		return errors.New("managed sink state lacks exact ownership or store presence")
	}
	if _, err := parseExplicitPrefix(state.Route.Family, state.Route.Destination); err != nil {
		return err
	}
	if state.Route.InterfaceIndex != LoopbackInterfaceIndex || state.Route.Metric != ReservedSinkMetric || state.Route.PolicyStore != SinkPolicyStore || state.Route.Protocol != RouteProtocol || !state.Route.JournalOwned {
		return errors.New("managed sink state has an unsafe tuple")
	}
	if !slices.Contains(artifacts.sinks.Routes, state.Route) {
		return errors.New("managed sink state is outside the owned artifact")
	}
	return nil
}

func requireExactManagedState(snapshot MutationSnapshot, artifacts artifactSet) error {
	if hasVPNRoutes(artifacts.routes.Routes) && !snapshot.FirewallEnforced {
		return errors.New("managed firewall is not enforced by every effective Windows profile")
	}
	wantRoutes := make(map[string]ManagedRoute, len(artifacts.routes.Routes))
	for _, route := range artifacts.routes.Routes {
		wantRoutes[routeTupleKey(route)] = route
	}
	wantSinks := make(map[string]SinkRoute, len(artifacts.sinks.Routes))
	for _, route := range artifacts.sinks.Routes {
		wantSinks[sinkTupleKey(route)] = route
	}
	wantFirewall := make(map[string]FirewallRule, len(artifacts.firewall.Rules))
	for _, rule := range artifacts.firewall.Rules {
		wantFirewall[rule.Name] = rule
	}
	wantDNS := make(map[string]NRPTRule, len(artifacts.dns.Rules))
	for _, rule := range artifacts.dns.Rules {
		wantDNS[rule.LogicalID] = rule
	}
	for _, route := range snapshot.Routes {
		if route.Owner == ArtifactOwner {
			if route.Revision != artifacts.routes.Revision {
				return errors.New("stale managed route remains after activation")
			}
			want, exists := wantRoutes[routeTupleKey(route.ManagedRoute)]
			if !exists || want != route.ManagedRoute || route.State != routeStateAlive {
				return errors.New("managed route post-check drift")
			}
			delete(wantRoutes, routeTupleKey(route.ManagedRoute))
		}
	}
	for _, state := range snapshot.Sinks {
		if state.Owner == ArtifactOwner {
			if state.Revision != artifacts.sinks.Revision {
				return errors.New("stale managed sink remains after activation")
			}
			want, exists := wantSinks[sinkTupleKey(state.Route)]
			if !exists || want != state.Route || !state.PersistentPresent || !state.ActivePresent {
				return errors.New("managed sink post-check drift")
			}
			delete(wantSinks, sinkTupleKey(state.Route))
		}
	}
	for _, state := range snapshot.Firewall {
		if state.Owner == ArtifactOwner {
			if state.Revision != artifacts.firewall.Revision {
				return errors.New("stale managed firewall rule remains after activation")
			}
			if want, exists := wantFirewall[state.Rule.Name]; !exists || want != state.Rule || !state.Effective {
				return errors.New("managed firewall post-check drift")
			}
			delete(wantFirewall, state.Rule.Name)
		}
	}
	for _, state := range snapshot.NRPT {
		if state.Owner == ArtifactOwner {
			if state.Revision != artifacts.dns.Revision {
				return errors.New("stale managed DNS rule remains after activation")
			}
			if !state.Effective {
				return errors.New("managed DNS policy is configured but not effective")
			}
			if state.Rule.Name == "" {
				return errors.New("managed DNS state lacks an exact OS-generated rule identity")
			}
			if want, exists := wantDNS[state.Rule.LogicalID]; !exists || !nrptEqual(want, state.Rule) {
				return errors.New("managed DNS post-check drift")
			}
			delete(wantDNS, state.Rule.LogicalID)
		}
	}
	if len(wantRoutes) != 0 || len(wantSinks) != 0 || len(wantFirewall) != 0 || len(wantDNS) != 0 {
		return errors.New("managed Windows post-check state is incomplete")
	}
	return nil
}

func requireCandidateSinksPresent(snapshot MutationSnapshot, artifact SinkArtifact) error {
	want := make(map[string]SinkRoute, len(artifact.Routes))
	for _, route := range artifact.Routes {
		want[sinkTupleKey(route)] = route
	}
	for _, state := range snapshot.Sinks {
		if state.Owner != ArtifactOwner || state.Revision != artifact.Revision {
			continue
		}
		route, exists := want[sinkTupleKey(state.Route)]
		if !exists || route != state.Route || !state.PersistentPresent || !state.ActivePresent {
			return errors.New("candidate sink pre-route check drift")
		}
		delete(want, sinkTupleKey(state.Route))
	}
	if len(want) != 0 {
		return errors.New("candidate sink set is incomplete before firewall")
	}
	return nil
}

func requireCandidateFirewallPresent(snapshot MutationSnapshot, artifact FirewallArtifact) error {
	if !snapshot.FirewallEnforced {
		return errors.New("effective Windows firewall profiles do not enforce candidate rules")
	}
	want := make(map[string]FirewallRule, len(artifact.Rules))
	for _, rule := range artifact.Rules {
		want[rule.Name] = rule
	}
	for _, state := range snapshot.Firewall {
		if state.Owner != ArtifactOwner || state.Revision != artifact.Revision {
			continue
		}
		rule, exists := want[state.Rule.Name]
		if !exists || rule != state.Rule || !state.Effective {
			return errors.New("candidate firewall pre-route check drift")
		}
		delete(want, state.Rule.Name)
	}
	if len(want) != 0 {
		return errors.New("candidate firewall is incomplete before VPN routes")
	}
	return nil
}

func nrptEqual(left, right NRPTRule) bool {
	return left.LogicalID == right.LogicalID && left.DisplayName == right.DisplayName && left.Namespace == right.Namespace && left.Comment == right.Comment && slices.Equal(left.NameServers, right.NameServers)
}

func filterManagedSnapshot(snapshot MutationSnapshot) (managedSnapshot, error) {
	managed := managedSnapshot{Version: ArtifactVersion}
	for _, route := range snapshot.Routes {
		if route.Owner == ArtifactOwner {
			managed.Routes = append(managed.Routes, route)
		}
	}
	for _, sink := range snapshot.Sinks {
		if sink.Owner == ArtifactOwner {
			managed.Sinks = append(managed.Sinks, sink)
		}
	}
	for _, rule := range snapshot.Firewall {
		if rule.Owner == ArtifactOwner {
			rule.Effective = false
			managed.Firewall = append(managed.Firewall, rule)
		}
	}
	for _, rule := range snapshot.NRPT {
		if rule.Owner == ArtifactOwner {
			managed.NRPT = append(managed.NRPT, rule)
		}
	}
	return managed, nil
}

func (runtime *Runtime) validateManagedSnapshot(snapshot managedSnapshot) error {
	if snapshot.Version != ArtifactVersion {
		return errors.New("unsupported Windows snapshot version")
	}
	if len(snapshot.Routes) > maxManagedRoutes || len(snapshot.Sinks) > maxManagedRoutes || len(snapshot.Firewall) > maxFirewallRules || len(snapshot.NRPT) > maxDNSRules {
		return errors.New("managed snapshot resource limit exceeded")
	}
	seenRoutes := make(map[string]struct{}, len(snapshot.Routes))
	for _, state := range snapshot.Routes {
		artifacts, exists := runtime.ownedRevisions[state.Revision]
		_, prefixErr := parseExplicitPrefix(state.Family, state.Destination)
		key := state.Revision + "\x00" + routeTupleKey(state.ManagedRoute)
		if state.Owner != ArtifactOwner || state.Protected || !validRevision(state.Revision) || prefixErr != nil || state.Metric != ReservedRouteMetric || state.PolicyStore != RoutePolicyStore || state.Protocol != RouteProtocol || !state.JournalOwned || !exists || !slices.Contains(artifacts.routes.Routes, state.ManagedRoute) {
			return errors.New("managed snapshot contains an invalid or unowned route")
		}
		if _, duplicate := seenRoutes[key]; duplicate {
			return errors.New("managed snapshot contains a duplicate route")
		}
		seenRoutes[key] = struct{}{}
	}
	seenSinks := make(map[string]struct{}, len(snapshot.Sinks))
	for _, state := range snapshot.Sinks {
		artifacts, exists := runtime.ownedRevisions[state.Revision]
		key := state.Revision + "\x00" + sinkTupleKey(state.Route)
		if !exists || validateOwnedSinkState(state, artifacts) != nil {
			return errors.New("managed snapshot contains an invalid or unowned sink")
		}
		if _, duplicate := seenSinks[key]; duplicate {
			return errors.New("managed snapshot contains a duplicate sink")
		}
		seenSinks[key] = struct{}{}
	}
	seenFirewall := make(map[string]struct{}, len(snapshot.Firewall))
	for _, state := range snapshot.Firewall {
		artifacts, exists := runtime.ownedRevisions[state.Revision]
		if state.Owner != ArtifactOwner || !validRevision(state.Revision) || state.Rule.Group != ownershipGroup(state.Revision) || state.Rule.Description != ownershipDescription(state.Revision) || state.Rule.Name != FirewallRuleName(state.Revision, state.Rule.Family, state.Rule.RemoteCIDR, state.Rule.InterfaceGUID) || !exists || !slices.Contains(artifacts.firewall.Rules, state.Rule) {
			return errors.New("managed snapshot contains an invalid or unowned firewall rule")
		}
		if _, duplicate := seenFirewall[state.Rule.Name]; duplicate {
			return errors.New("managed snapshot contains a duplicate firewall rule")
		}
		seenFirewall[state.Rule.Name] = struct{}{}
	}
	seenDNS := make(map[string]struct{}, len(snapshot.NRPT))
	for _, state := range snapshot.NRPT {
		artifacts, exists := runtime.ownedRevisions[state.Revision]
		key := state.Revision + "\x00" + state.Rule.LogicalID
		if state.Owner != ArtifactOwner || !validRevision(state.Revision) || state.Rule.Name == "" || state.Rule.Comment != ownershipDescription(state.Revision) || !exists || !slices.ContainsFunc(artifacts.dns.Rules, func(want NRPTRule) bool { return nrptEqual(want, state.Rule) }) {
			return errors.New("managed snapshot contains an invalid or unowned DNS rule")
		}
		if _, duplicate := seenDNS[key]; duplicate {
			return errors.New("managed snapshot contains a duplicate DNS rule")
		}
		seenDNS[key] = struct{}{}
	}
	return nil
}

func canonicalCandidate(candidate apply.Candidate) (artifactSet, map[string][]byte, error) {
	artifacts, err := parseArtifacts(candidate.RevisionID, candidate.Routes, candidate.Sinks, candidate.Firewall, candidate.DNS)
	if err != nil {
		return artifactSet{}, nil, err
	}
	canonical := make(map[string][]byte, 4)
	for name, value := range map[string]any{routesArtifactName: artifacts.routes, sinksArtifactName: artifacts.sinks, firewallArtifactName: artifacts.firewall, dnsArtifactName: artifacts.dns} {
		data, err := json.Marshal(value)
		if err != nil {
			return artifactSet{}, nil, err
		}
		canonical[name] = append(data, '\n')
	}
	return artifacts, canonical, nil
}

func (runtime *Runtime) validateConfiguration() error {
	if runtime.Backend == nil {
		return errors.New("structured Windows mutation backend is required")
	}
	if runtime.Root == "" || !filepath.IsAbs(runtime.Root) || filepath.Clean(runtime.Root) != runtime.Root {
		return errors.New("absolute clean Windows runtime root is required")
	}
	if (len(runtime.QualifiedEndpoints) == 0 && !runtime.recoveryOnly) || len(runtime.QualifiedEndpoints) > maxManagedRoutes {
		return errors.New("bounded trusted qualified endpoint set is required")
	}
	seen := make(map[string]struct{}, len(runtime.QualifiedEndpoints))
	for _, value := range runtime.QualifiedEndpoints {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().Is4In6() || prefix.String() != value {
			return errors.New("qualified endpoints must be exact canonical host prefixes")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("qualified endpoint set contains duplicates")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validRevision(revision string) bool {
	if len(revision) == 0 || len(revision) > 128 || revision == "." || revision == ".." {
		return false
	}
	for _, character := range revision {
		if character != '-' && character != '_' && character != '.' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func (runtime *Runtime) revisionDirectory(revision string) (string, error) {
	if !validRevision(revision) {
		return "", errors.New("invalid Windows revision ID")
	}
	return runtime.rootPath(filepath.Join("revisions", revision))
}

func (runtime *Runtime) rootPath(relative string) (string, error) {
	root := filepath.Clean(runtime.Root)
	target := filepath.Clean(filepath.Join(root, relative))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("windows runtime path escapes root")
	}
	return target, nil
}

func (runtime *Runtime) readRevision(revision string) (artifactSet, error) {
	directory, err := runtime.revisionDirectory(revision)
	if err != nil {
		return artifactSet{}, err
	}
	canonical := make(map[string][]byte, 4)
	for _, name := range windowsArtifactNames() {
		data, err := readBoundedFile(filepath.Join(directory, name), maxArtifactBytes)
		if err != nil {
			return artifactSet{}, err
		}
		canonical[name] = data
	}
	if err := verifyRevisionManifest(directory, revision, canonical); err != nil {
		return artifactSet{}, err
	}
	return parseArtifacts(revision, canonical[routesArtifactName], canonical[sinksArtifactName], canonical[firewallArtifactName], canonical[dnsArtifactName])
}

func readBoundedRegularFile(path string, limit int) ([]byte, error) {
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		ancestor, err := os.Lstat(current)
		if err != nil || !ancestor.IsDir() || ancestor.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("artifact path contains a reparse-backed directory")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, errors.New("artifact is not one bounded regular file")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) {
		return nil, errors.New("artifact file identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) == 0 || len(data) > limit {
		return nil, errors.New("artifact exceeds its bound")
	}
	return data, nil
}

func (runtime *Runtime) bindRevisionManifest(revision string) (string, error) {
	directory, err := runtime.revisionDirectory(revision)
	if err != nil {
		return "", err
	}
	canonical := make(map[string][]byte, len(windowsArtifactNames()))
	for _, name := range windowsArtifactNames() {
		data, readErr := readBoundedRegularFile(filepath.Join(directory, name), maxArtifactBytes)
		if readErr != nil {
			return "", fmt.Errorf("revision artifact %s is unavailable: %w", name, readErr)
		}
		canonical[name] = data
	}
	manifestData, err := readBoundedRegularFile(filepath.Join(directory, revisionManifestName), maxArtifactBytes)
	if err != nil {
		return "", errors.New("revision manifest is missing, reparse-backed, or unbounded")
	}
	var manifest revisionManifest
	if err := decodeStrict(manifestData, &manifest); err != nil {
		return "", errors.New("revision manifest schema differs")
	}
	if manifest.Version != ArtifactVersion || manifest.Revision != revision {
		return "", errors.New("revision manifest header mismatch")
	}
	if err := verifyManifestEntries(manifest, canonical); err != nil {
		return "", err
	}
	if _, err := parseArtifacts(revision, canonical[routesArtifactName], canonical[sinksArtifactName], canonical[firewallArtifactName], canonical[dnsArtifactName]); err != nil {
		return "", errors.New("referenced revision artifacts are invalid")
	}
	digest := sha256.Sum256(manifestData)
	return fmt.Sprintf("%x", digest[:]), nil
}

func (runtime *Runtime) writeSnapshot(name string, snapshot managedSnapshot, replace bool) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxManagedSnapshotBytes {
		return errors.New("managed snapshot exceeds combined size limit")
	}
	if err := runtime.validateManagedSnapshot(snapshot); err != nil {
		return err
	}
	path, err := runtime.rootPath(name)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	digestData := []byte(fmt.Sprintf("%x\n", digest[:]))
	digestPath := path + ".sha256"
	if replace {
		if err := replaceFile(path, data); err != nil {
			return err
		}
		return replaceFile(digestPath, digestData)
	}
	if err := writeExclusive(path, data); err != nil {
		return err
	}
	return writeExclusive(digestPath, digestData)
}

func (runtime *Runtime) readSnapshot(name string) (managedSnapshot, error) {
	path, err := runtime.rootPath(name)
	if err != nil {
		return managedSnapshot{}, err
	}
	data, err := readBoundedFile(path, maxManagedSnapshotBytes)
	if err != nil {
		return managedSnapshot{}, err
	}
	digestData, err := readBoundedFile(path+".sha256", sha256.Size*2+1)
	if err != nil {
		return managedSnapshot{}, errors.New("managed snapshot digest is missing")
	}
	if len(digestData) != sha256.Size*2+1 {
		return managedSnapshot{}, errors.New("managed snapshot digest has an invalid size")
	}
	digest := sha256.Sum256(data)
	if string(digestData) != fmt.Sprintf("%x\n", digest[:]) {
		return managedSnapshot{}, errors.New("managed snapshot digest mismatch")
	}
	var snapshot managedSnapshot
	if err := decodeStrictLimit(data, &snapshot, maxManagedSnapshotBytes); err != nil {
		return managedSnapshot{}, err
	}
	if err := runtime.validateManagedSnapshot(snapshot); err != nil {
		return managedSnapshot{}, err
	}
	return snapshot, nil
}

func (runtime *Runtime) clearActiveView() error {
	for _, name := range []string{"active.json", "lkg.json"} {
		marker, err := runtime.rootPath(name)
		if err != nil {
			return err
		}
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) writeMarker(name, revision string) error {
	data, _ := json.Marshal(struct {
		Version  int    `json:"version"`
		Revision string `json:"revision"`
	}{ArtifactVersion, revision})
	path, err := runtime.rootPath(name)
	if err != nil {
		return err
	}
	return replaceFile(path, append(data, '\n'))
}

func (runtime *Runtime) readMarker(name string) (string, error) {
	path, err := runtime.rootPath(name)
	if err != nil {
		return "", err
	}
	data, err := readBoundedFile(path, maxArtifactBytes)
	if err != nil {
		return "", err
	}
	var marker struct {
		Version  int    `json:"version"`
		Revision string `json:"revision"`
	}
	if err := decodeStrict(data, &marker); err != nil || marker.Version != ArtifactVersion || !validRevision(marker.Revision) {
		return "", errors.New("invalid Windows revision marker")
	}
	return marker.Revision, nil
}

func verifyArtifactFiles(directory, revision string, canonical map[string][]byte) error {
	for name, want := range canonical {
		got, err := readBoundedFile(filepath.Join(directory, name), maxArtifactBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("artifact %s differs", name)
		}
	}
	return verifyRevisionManifest(directory, revision, canonical)
}

func buildRevisionManifest(revision string, canonical map[string][]byte) ([]byte, error) {
	manifest := revisionManifest{Version: ArtifactVersion, Revision: revision, Files: make(map[string]manifestEntry, len(canonical))}
	for _, name := range windowsArtifactNames() {
		digest := sha256.Sum256(canonical[name])
		manifest.Files[name] = manifestEntry{Size: len(canonical[name]), SHA256: fmt.Sprintf("%x", digest[:])}
	}
	data, err := json.Marshal(manifest)
	return append(data, '\n'), err
}

func verifyRevisionManifest(directory, revision string, canonical map[string][]byte) error {
	data, err := readBoundedFile(filepath.Join(directory, revisionManifestName), maxArtifactBytes)
	if err != nil {
		return fmt.Errorf("revision manifest is missing or incomplete: %w", err)
	}
	var manifest revisionManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return fmt.Errorf("invalid revision manifest: %w", err)
	}
	if manifest.Version != ArtifactVersion || manifest.Revision != revision {
		return errors.New("revision manifest header mismatch")
	}
	return verifyManifestEntries(manifest, canonical)
}

func verifyManifestEntries(manifest revisionManifest, canonical map[string][]byte) error {
	if len(manifest.Files) != len(windowsArtifactNames()) {
		return errors.New("revision manifest file set mismatch")
	}
	for _, name := range windowsArtifactNames() {
		entry, exists := manifest.Files[name]
		digest := sha256.Sum256(canonical[name])
		if !exists || entry.Size != len(canonical[name]) || entry.SHA256 != fmt.Sprintf("%x", digest[:]) {
			return errors.New("revision manifest digest mismatch")
		}
	}
	return nil
}

func windowsArtifactNames() []string {
	return []string{routesArtifactName, sinksArtifactName, firewallArtifactName, dnsArtifactName}
}

func writeExclusive(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// #nosec G304 -- callers pass only root-contained paths built from validated
	// revision IDs and fixed artifact names; O_EXCL also refuses replacement.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readBoundedFile(path string, limit int) ([]byte, error) {
	// #nosec G304 -- callers pass only root-contained paths built from validated
	// revision IDs and fixed artifact, snapshot, manifest, or marker names.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("managed runtime file exceeds size limit")
	}
	return data, nil
}

func replaceFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".next"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusive(temporary, data); err != nil {
		return err
	}
	return atomicReplaceFile(temporary, path)
}

func safeRemoveAll(root, target string) error {
	cleanRoot := filepath.Clean(root)
	cleanTarget := filepath.Clean(target)
	rel, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("refuse broad Windows runtime removal")
	}
	return os.RemoveAll(cleanTarget)
}

func countOwnedFirewall(values []FirewallState) int {
	return len(slices.DeleteFunc(append([]FirewallState(nil), values...), func(value FirewallState) bool { return value.Owner != ArtifactOwner }))
}

func countOwnedNRPT(values []NRPTState) int {
	return len(slices.DeleteFunc(append([]NRPTState(nil), values...), func(value NRPTState) bool { return value.Owner != ArtifactOwner }))
}

func countOwnedSinks(values []SinkState) int {
	return len(slices.DeleteFunc(append([]SinkState(nil), values...), func(value SinkState) bool { return value.Owner != ArtifactOwner }))
}

func countOwnedRoutes(values []RouteState, role string) int {
	count := 0
	for _, value := range values {
		if value.Owner == ArtifactOwner && value.Role == role {
			count++
		}
	}
	return count
}

func ownedRouteKeys(values []RouteState, role string) []string {
	keys := make([]string, 0)
	for _, value := range values {
		if value.Owner == ArtifactOwner && value.Role == role {
			keys = append(keys, jsonKey(value))
		}
	}
	sort.Strings(keys)
	return keys
}

func ownedSinkStateKeys(values []SinkState) []string {
	keys := make([]string, 0, len(values))
	for _, value := range values {
		if value.Owner == ArtifactOwner {
			keys = append(keys, jsonKey(value))
		}
	}
	sort.Strings(keys)
	return keys
}

func foreignStateEqual(before, after MutationSnapshot) bool {
	return slices.Equal(foreignKeys(before), foreignKeys(after))
}

func managedSnapshotEqual(want managedSnapshot, current MutationSnapshot) bool {
	got, err := filterManagedSnapshot(current)
	return err == nil && managedSnapshotsEqual(want, got)
}

func managedSnapshotsEqual(left, right managedSnapshot) bool {
	return slices.Equal(snapshotKeys(left.Routes), snapshotKeys(right.Routes)) && slices.Equal(snapshotKeys(left.Sinks), snapshotKeys(right.Sinks)) && slices.Equal(snapshotKeys(left.Firewall), snapshotKeys(right.Firewall)) && slices.Equal(snapshotKeys(left.NRPT), snapshotKeys(right.NRPT))
}

func foreignKeys(snapshot MutationSnapshot) []string {
	keys := make([]string, 0, len(snapshot.Routes)+len(snapshot.Sinks)+len(snapshot.Firewall)+len(snapshot.NRPT))
	for _, value := range snapshot.Routes {
		if value.Owner != ArtifactOwner {
			keys = append(keys, "route\x00"+jsonKey(value))
		}
	}
	for _, value := range snapshot.Sinks {
		if value.Owner != ArtifactOwner {
			keys = append(keys, "sink\x00"+jsonKey(value))
		}
	}
	for _, value := range snapshot.Firewall {
		if value.Owner != ArtifactOwner {
			keys = append(keys, "firewall\x00"+jsonKey(value))
		}
	}
	for _, value := range snapshot.NRPT {
		if value.Owner != ArtifactOwner {
			keys = append(keys, "nrpt\x00"+jsonKey(value))
		}
	}
	sort.Strings(keys)
	return keys
}

func snapshotKeys[T any](values []T) []string {
	keys := make([]string, 0, len(values))
	for _, value := range values {
		keys = append(keys, jsonKey(value))
	}
	sort.Strings(keys)
	return keys
}

func jsonKey(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}
