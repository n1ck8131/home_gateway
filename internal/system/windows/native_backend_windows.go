//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

const (
	nativeMutationVersion       = 1
	nativeOwnershipRegistryName = "native-ownership.v1.json"
	nativeReplaceBackupSuffix   = ".routerd.replace-backup"
	maxNativeRegistryBytes      = 1 << 20
	maxNativeFirewallRecords    = 1024
	nativeMutationTimeout       = 30 * time.Second
	nativeFirewallCleanupDelay  = time.Second
	nativeFirewallCleanupWindow = 10 * time.Second
	nativeFirewallCleanupChecks = 3

	nativeFirewallPhasePrepared = "prepared"
	nativeFirewallPhaseApplied  = "applied"
	nativeFirewallPhaseCleanup  = "cleanup"
	nativeFirewallPhaseWatch    = "watch"

	nativeTombstoneRoute    = "route"
	nativeTombstoneFirewall = "firewall"
	nativeTombstoneNRPT     = "nrpt"
	nativeTombstonePut      = "put"
	nativeTombstoneRemove   = "remove"
)

// nativeMutationRunner is deliberately command-shaped rather than
// shell-shaped. Callers cannot select an executable, argument, module, or
// script; the backend builds the entire trusted invocation before handing it
// to the runner.
type nativeMutationRunner interface {
	Run(context.Context, nativeMutationCommand) ([]byte, error)
}

type nativeMutationCommand struct {
	Executable  string
	Arguments   []string
	Environment []string
	Directory   string
	Input       []byte
}

type nativeExecMutationRunner struct{}

type nativeMutationBackend struct {
	root                string
	command             nativeMutationCommand
	runner              nativeMutationRunner
	validateRoot        func(string) error
	bootID              func() (string, error)
	timeout             time.Duration
	firewallCleanupWait func(context.Context, time.Duration) error
	mu                  sync.Mutex
}

var _ MutationBackend = (*nativeMutationBackend)(nil)
var _ FirewallBatchMutationBackend = (*nativeMutationBackend)(nil)

// NewNativeMutationBackend creates the privileged Windows adapter. The caller
// must pass the same absolute, protected root used by Runtime so native route
// and NRPT identities survive process restart without claiming foreign state.
func NewNativeMutationBackend(root string) (MutationBackend, error) {
	if err := ValidateProductionCanaryStateRoot(root); err != nil {
		return nil, err
	}
	paths, err := resolveNativeInventoryPaths()
	if err != nil {
		return nil, errors.New("trusted Windows mutation path resolution failed")
	}
	return newNativeMutationBackend(root, paths, nativeExecMutationRunner{}, validateProtectedNativeRoot)
}

func newNativeMutationBackend(root string, paths nativeInventoryPaths, runner nativeMutationRunner, validateRoot func(string) error) (*nativeMutationBackend, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("absolute clean Windows mutation root is required")
	}
	command, err := buildNativeMutationCommand(paths)
	if err != nil {
		return nil, err
	}
	if runner == nil || validateRoot == nil {
		return nil, errors.New("native Windows mutation runner and root validator are required")
	}
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	backend := &nativeMutationBackend{
		root:                root,
		command:             command,
		runner:              runner,
		validateRoot:        validateRoot,
		bootID:              readNativeBootIdentifier,
		timeout:             nativeMutationTimeout,
		firewallCleanupWait: waitNativeFirewallCleanup,
	}
	if _, err := backend.readRegistryLocked(); err != nil {
		return nil, err
	}
	return backend, nil
}

type nativeBootEnvironmentInformation struct {
	BootIdentifier xwindows.GUID
	FirmwareType   uint32
	_              uint32
	BootFlags      uint64
}

func readNativeBootIdentifier() (string, error) {
	var information nativeBootEnvironmentInformation
	var returned uint32
	if err := xwindows.NtQuerySystemInformation(
		int32(xwindows.SystemBootEnvironmentInformation),
		unsafe.Pointer(&information),
		uint32(unsafe.Sizeof(information)),
		&returned,
	); err != nil {
		return "", errors.New("read native Windows boot identifier")
	}
	value := strings.ToLower(strings.Trim(information.BootIdentifier.String(), "{}"))
	canonical, err := canonicalGUID(value)
	if err != nil {
		return "", errors.New("native Windows boot identifier is invalid")
	}
	return canonical, nil
}

func (backend *nativeMutationBackend) currentBootID() (string, error) {
	if backend.bootID == nil {
		return "", errors.New("native Windows boot identifier source is missing")
	}
	value, err := backend.bootID()
	if err != nil {
		return "", errors.New("read native Windows boot identifier")
	}
	canonical, err := canonicalGUID(value)
	if err != nil || canonical != value {
		return "", errors.New("native Windows boot identifier is invalid")
	}
	return canonical, nil
}

func waitNativeFirewallCleanup(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type nativeACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	ACECount uint16
	Sbz2     uint16
}

func validateProtectedNativeRoot(root string) error {
	if err := ValidateProductionCanaryStateRoot(root); err != nil {
		return err
	}
	if err := rejectNativeReparseAncestors(root); err != nil {
		return err
	}
	parent := filepath.Dir(root)
	if !strings.EqualFold(filepath.Base(parent), "HomeGateway") {
		return errors.New("protected Windows mutation parent is invalid")
	}
	for _, path := range []string{parent, root} {
		if err := validateProtectedNativeDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func rejectNativeReparseAncestors(root string) error {
	volume := filepath.VolumeName(root)
	if volume == "" {
		return errors.New("protected Windows mutation root volume is invalid")
	}
	current := volume + string(filepath.Separator)
	components := strings.FieldsFunc(strings.TrimPrefix(root, volume), func(character rune) bool {
		return character == '\\' || character == '/'
	})
	paths := make([]string, 0, len(components)+1)
	paths = append(paths, current)
	for _, component := range components {
		current = filepath.Join(current, component)
		paths = append(paths, current)
	}
	for _, path := range paths {
		pathPointer, err := xwindows.UTF16PtrFromString(path)
		if err != nil {
			return errors.New("protected Windows mutation path is invalid")
		}
		attributes, err := xwindows.GetFileAttributes(pathPointer)
		if err != nil || attributes&xwindows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("protected Windows mutation path is missing or not a directory")
		}
		if attributes&xwindows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("protected Windows mutation path contains a reparse point")
		}
	}
	return nil
}

func validateProtectedNativeDirectory(path string) error {
	descriptor, err := xwindows.GetNamedSecurityInfo(path, xwindows.SE_FILE_OBJECT, xwindows.OWNER_SECURITY_INFORMATION|xwindows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("read protected Windows mutation directory security descriptor")
	}
	return validateProtectedNativeSecurityDescriptor(descriptor)
}

func validateProtectedNativeSecurityDescriptor(descriptor *xwindows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil {
		return errors.New("protected Windows mutation directory security descriptor is missing")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&xwindows.SE_DACL_PROTECTED == 0 {
		return errors.New("protected Windows mutation directory inherits its DACL")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !nativePrivilegedSID(owner) {
		return errors.New("protected Windows mutation directory owner is not trusted")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("protected Windows mutation directory has no restrictive DACL")
	}
	return validateNativePrivilegedDACL(dacl)
}

func validateNativePrivilegedDACL(dacl *xwindows.ACL) error {
	if dacl == nil {
		return errors.New("protected Windows mutation directory has no restrictive DACL")
	}
	header := (*nativeACLHeader)(unsafe.Pointer(dacl))
	if header.ACECount > 4096 || header.Size < uint16(unsafe.Sizeof(nativeACLHeader{})) {
		return errors.New("protected Windows mutation directory DACL is invalid")
	}
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *xwindows.ACCESS_ALLOWED_ACE
		if err := xwindows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("inspect protected Windows mutation directory DACL")
		}
		switch ace.Header.AceType {
		case xwindows.ACCESS_DENIED_ACE_TYPE:
			continue
		case xwindows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return errors.New("protected Windows mutation directory DACL uses an unsupported ACE type")
		}
		sid := (*xwindows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errors.New("protected Windows mutation directory DACL contains an invalid SID")
		}
		if ace.Header.AceType == xwindows.ACCESS_ALLOWED_ACE_TYPE && !nativePrivilegedSID(sid) {
			return errors.New("protected Windows mutation directory grants untrusted access")
		}
	}
	return nil
}

func nativePrivilegedSID(sid *xwindows.SID) bool {
	return sid != nil && (sid.IsWellKnown(xwindows.WinLocalSystemSid) || sid.IsWellKnown(xwindows.WinBuiltinAdministratorsSid))
}

func (nativeExecMutationRunner) Run(ctx context.Context, spec nativeMutationCommand) ([]byte, error) {
	// #nosec G204 -- executable, arguments, environment, and working directory
	// are produced only by buildNativeMutationCommand. Structured caller data is
	// delivered exclusively through stdin.
	command := exec.CommandContext(ctx, spec.Executable, spec.Arguments...)
	// Start suspended so the privileged child cannot execute a single cmdlet
	// before it belongs to a kill-on-close Job Object. Closing the hgctl process
	// then closes the last job handle and terminates PowerShell plus descendants.
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: xwindows.CREATE_SUSPENDED}
	command.Env = append([]string(nil), spec.Environment...)
	command.Dir = spec.Directory
	command.Stdin = bytes.NewReader(spec.Input)
	command.WaitDelay = 2 * time.Second
	var stdout boundedBuffer
	stdout.limit = maxSnapshotBytes
	var stderr boundedBuffer
	stderr.limit = maxStderrBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, errors.New("create trusted native Windows mutation job")
	}
	defer xwindows.CloseHandle(job)
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = xwindows.TerminateJobObject(job, 1)
		case <-stopWatch:
		}
	}()
	defer func() {
		close(stopWatch)
		<-watchDone
	}()
	if err := command.Start(); err != nil {
		return nil, errors.New("start trusted native Windows mutation command")
	}
	assigned := false
	err = command.Process.WithHandle(func(handle uintptr) {
		if xwindows.AssignProcessToJobObject(job, xwindows.Handle(handle)) == nil {
			assigned = true
		}
	})
	if err != nil || !assigned {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("assign trusted native Windows mutation job")
	}
	if err := resumeSuspendedProcess(uint32(command.Process.Pid)); err != nil {
		_ = xwindows.TerminateJobObject(job, 1)
		_ = command.Wait()
		return nil, errors.New("resume trusted native Windows mutation command")
	}
	if err := command.Wait(); err != nil {
		return nil, errors.New("trusted native Windows mutation command failed")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("trusted native Windows mutation output exceeded its limit")
	}
	return append([]byte(nil), stdout.data...), nil
}

func newKillOnCloseJob() (xwindows.Handle, error) {
	job, err := xwindows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	information := xwindows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	information.BasicLimitInformation.LimitFlags = xwindows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := xwindows.SetInformationJobObject(
		job,
		xwindows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&information)),
		uint32(unsafe.Sizeof(information)),
	); err != nil {
		_ = xwindows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func resumeSuspendedProcess(processID uint32) error {
	snapshot, err := xwindows.CreateToolhelp32Snapshot(xwindows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer xwindows.CloseHandle(snapshot)
	entry := xwindows.ThreadEntry32{Size: uint32(unsafe.Sizeof(xwindows.ThreadEntry32{}))}
	if err := xwindows.Thread32First(snapshot, &entry); err != nil {
		return err
	}
	resumed := 0
	for {
		if entry.OwnerProcessID == processID {
			thread, openErr := xwindows.OpenThread(xwindows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr != nil {
				return openErr
			}
			_, resumeErr := xwindows.ResumeThread(thread)
			closeErr := xwindows.CloseHandle(thread)
			if resumeErr != nil || closeErr != nil {
				return errors.Join(resumeErr, closeErr)
			}
			resumed++
		}
		entry.Size = uint32(unsafe.Sizeof(xwindows.ThreadEntry32{}))
		if err := xwindows.Thread32Next(snapshot, &entry); err != nil {
			if errors.Is(err, xwindows.ERROR_NO_MORE_FILES) {
				break
			}
			return err
		}
	}
	if resumed != 1 {
		return errors.New("suspended mutation process did not have exactly one main thread")
	}
	return nil
}

func buildNativeMutationCommand(paths nativeInventoryPaths) (nativeMutationCommand, error) {
	base, err := buildInventoryCommand(paths)
	if err != nil {
		return nativeMutationCommand{}, errors.New("trusted Windows mutation paths are invalid")
	}
	modulesRoot := filepath.Join(base.Directory, "WindowsPowerShell", "v1.0", "Modules")
	environment := append([]string(nil), base.Environment...)
	environment = append(environment,
		"HG_NETSECURITY_MANIFEST="+filepath.Join(modulesRoot, "NetSecurity", "NetSecurity.psd1"),
	)
	return nativeMutationCommand{
		Executable: base.Executable,
		Arguments: []string{
			"-NoLogo",
			"-NoProfile",
			"-NonInteractive",
			"-OutputFormat", "Text",
			"-Command", nativeMutationScript,
		},
		Environment: environment,
		Directory:   base.Directory,
	}, nil
}

type nativeMutationRequest struct {
	Version              int                       `json:"version"`
	Operation            string                    `json:"operation"`
	Route                *RouteState               `json:"route,omitempty"`
	Firewall             *FirewallState            `json:"firewall,omitempty"`
	Firewalls            []FirewallState           `json:"firewalls,omitempty"`
	FirewallAlias        string                    `json:"firewall_alias,omitempty"`
	FirewallPattern      string                    `json:"firewall_pattern,omitempty"`
	FirewallBindings     []nativeFirewallOwnership `json:"firewall_bindings"`
	FirewallExpectations []nativeFirewallOwnership `json:"firewall_expectations"`
	MutationTombstones   []nativeMutationTombstone `json:"mutation_tombstones"`
	NRPT                 *NRPTState                `json:"nrpt,omitempty"`
}

type nativeMutationResponse struct {
	Version          int                        `json:"version"`
	OK               *bool                      `json:"ok"`
	Snapshot         *rawNativeMutationSnapshot `json:"snapshot,omitempty"`
	NRPTName         string                     `json:"nrpt_name,omitempty"`
	InterfaceAlias   string                     `json:"interface_alias,omitempty"`
	InterfacePattern string                     `json:"interface_pattern,omitempty"`
	InterfaceIndex   int                        `json:"interface_index,omitempty"`
	FirewallBindings []nativeFirewallOwnership  `json:"firewall_bindings,omitempty"`
}

func (backend *nativeMutationBackend) invoke(ctx context.Context, request nativeMutationRequest) (nativeMutationResponse, error) {
	data, err := json.Marshal(request)
	if err != nil || len(data) > maxArtifactBytes {
		return nativeMutationResponse{}, errors.New("structured native Windows mutation input is invalid")
	}
	deadline := backend.timeout
	if deadline <= 0 || deadline > nativeMutationTimeout {
		deadline = nativeMutationTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	spec := backend.command
	spec.Arguments = append([]string(nil), backend.command.Arguments...)
	spec.Environment = append([]string(nil), backend.command.Environment...)
	spec.Input = append([]byte(nil), data...)
	output, err := backend.runner.Run(callCtx, spec)
	if err != nil {
		return nativeMutationResponse{}, errors.New("trusted native Windows mutation command failed")
	}
	if len(output) == 0 || len(output) > maxSnapshotBytes {
		return nativeMutationResponse{}, errors.New("trusted native Windows mutation response has an invalid size")
	}
	output = bytes.TrimPrefix(output, []byte{0xef, 0xbb, 0xbf})
	var response nativeMutationResponse
	if err := decodeStrictLimit(output, &response, maxSnapshotBytes); err != nil || response.Version != nativeMutationVersion || response.OK == nil || !*response.OK {
		return nativeMutationResponse{}, errors.New("trusted native Windows mutation response is invalid")
	}
	return response, nil
}

func (backend *nativeMutationBackend) Snapshot(ctx context.Context) (MutationSnapshot, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return MutationSnapshot{}, err
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return MutationSnapshot{}, err
	}
	// Inventory must precede cleanup. In particular, after a reboot the old
	// provider generation is terminal and an exact negative observation can
	// retire its journal without resolving a now-missing GUID or touching a
	// same-name foreign firewall rule.
	response, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "snapshot", FirewallExpectations: registry.Firewall})
	if err != nil {
		return MutationSnapshot{}, err
	}
	if response.Snapshot == nil {
		return MutationSnapshot{}, errors.New("trusted native Windows snapshot is missing")
	}
	snapshot, reconciled, err := parseNativeMutationSnapshot(*response.Snapshot, registry)
	if err != nil {
		return MutationSnapshot{}, err
	}
	reconciled = finalizeRebootedMutations(snapshot, *response.Snapshot, reconciled, bootID)
	if nativeRegistryDigest(registry) != nativeRegistryDigest(reconciled) {
		if err := backend.writeRegistryLocked(reconciled); err != nil {
			return MutationSnapshot{}, err
		}
	}
	reconciled, err = backend.reconcilePendingMutationsLocked(reconciled)
	if err != nil {
		return MutationSnapshot{}, err
	}
	// An absent same-boot observation is not a CIM completion barrier. Keep
	// rollback/restore nonterminal until a validated reboot proves that a
	// canceled route or NRPT provider request can no longer commit.
	if snapshotContainsPendingNativeMutation(snapshot, *response.Snapshot, reconciled) || containsNonterminalMutation(reconciled) {
		return MutationSnapshot{}, errors.New("late native Windows mutation remains pending cleanup")
	}
	return snapshot, nil
}

func finalizeRebootedMutations(snapshot MutationSnapshot, raw rawNativeMutationSnapshot, registry nativeOwnershipRegistry, bootID string) nativeOwnershipRegistry {
	retainedFirewall := make([]nativeFirewallOwnership, 0, len(registry.Firewall))
	for _, ownership := range registry.Firewall {
		if nativeFirewallOwnershipPhase(ownership) == nativeFirewallPhaseApplied || ownership.BootID == "" || ownership.BootID == bootID || !nativeRawFirewallOwnershipAbsent(*raw.Firewall, ownership) {
			retainedFirewall = append(retainedFirewall, ownership)
		}
	}
	registry.Firewall = retainedFirewall

	retained := make([]nativeMutationTombstone, 0, len(registry.Tombstones))
	for _, tombstone := range registry.Tombstones {
		if tombstone.BootID == "" || tombstone.BootID == bootID {
			retained = append(retained, tombstone)
			continue
		}
		switch tombstone.Kind {
		case nativeTombstoneRoute:
			if tombstone.Route == nil || slices.ContainsFunc(snapshot.Routes, func(state RouteState) bool {
				return containsNativeRouteMutationOwnership([]RouteState{state}, *tombstone.Route)
			}) {
				retained = append(retained, tombstone)
				continue
			}
			registry.Routes = slices.DeleteFunc(registry.Routes, func(state RouteState) bool {
				return containsNativeRouteMutationOwnership([]RouteState{state}, *tombstone.Route)
			})
		case nativeTombstoneNRPT:
			if tombstone.NRPT == nil || !nativeRawNRPTAbsent(*raw.NRPT, *tombstone.NRPT) || !nativeEffectiveNRPTNamespaceAbsent(*raw.NRPTEffective, tombstone.NRPT.Rule.Namespace) {
				retained = append(retained, tombstone)
				continue
			}
			registry.NRPT = removeNativeNRPT(registry.NRPT, *tombstone.NRPT)
		case nativeTombstoneFirewall:
			if tombstone.Firewall == nil || !nativeRawFirewallOwnershipAbsent(*raw.Firewall, *tombstone.Firewall) {
				retained = append(retained, tombstone)
				continue
			}
			registry.Firewall = removeNativeFirewall(registry.Firewall, tombstone.Firewall.State)
		default:
			retained = append(retained, tombstone)
		}
	}
	registry.Tombstones = retained
	return registry
}

func nativeRawFirewallOwnershipAbsent(records []rawNativeFirewallRecord, ownership nativeFirewallOwnership) bool {
	for _, record := range records {
		if record.Name == nil || record.DisplayName == nil || record.Description == nil || record.Group == nil || record.Enabled == nil || record.Direction == nil || record.Action == nil || record.RemoteAddresses == nil || record.InterfaceAliases == nil {
			return false
		}
		if nativeFirewallRecordMatches(record, ownership) {
			return false
		}
		if ownership.PreviousInterfacePattern != "" {
			previous := ownership
			previous.InterfacePattern = ownership.PreviousInterfacePattern
			if nativeFirewallRecordMatches(record, previous) {
				return false
			}
		}
	}
	return true
}

func containsNonterminalMutation(registry nativeOwnershipRegistry) bool {
	if slices.ContainsFunc(registry.Firewall, func(ownership nativeFirewallOwnership) bool {
		return nativeFirewallOwnershipPhase(ownership) != nativeFirewallPhaseApplied
	}) {
		return true
	}
	return len(registry.Tombstones) != 0
}

func nativeRawNRPTAbsent(records []rawNativeNRPTRecord, state NRPTState) bool {
	for _, record := range records {
		if record.Name == nil || record.DisplayName == nil || record.Namespace == nil || record.NameServers == nil || record.Comment == nil {
			return false
		}
		if state.Rule.Name != "" && *record.Name != state.Rule.Name {
			continue
		}
		servers := make([]string, 0, len(*record.NameServers))
		valid := true
		for _, value := range *record.NameServers {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" || address.Is4In6() {
				valid = false
				break
			}
			servers = append(servers, address.Unmap().String())
		}
		if !valid {
			return false
		}
		if *record.DisplayName == state.Rule.DisplayName && *record.Namespace == state.Rule.Namespace && *record.Comment == state.Rule.Comment && nativeNameServerSetEqual(servers, state.Rule.NameServers) {
			return false
		}
	}
	return true
}

func nativeEffectiveNRPTNamespaceAbsent(records []rawNativeEffectiveNRPT, namespace string) bool {
	for _, record := range records {
		if record.Namespace == nil || record.NameServers == nil {
			return false
		}
		if strings.EqualFold(*record.Namespace, namespace) {
			return false
		}
	}
	return true
}

func (backend *nativeMutationBackend) AddRoute(ctx context.Context, state RouteState) error {
	if err := validateNativeRouteState(state); err != nil {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	registry, err = backend.reconcilePendingMutationsLocked(registry)
	if err != nil {
		return err
	}
	if containsNativeRouteTombstone(registry.Tombstones, state) {
		return errors.New("native Windows route identity is quarantined by an indeterminate mutation")
	}
	response, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "resolve_route_interface", Route: &state})
	if err != nil {
		return err
	}
	if response.InterfaceIndex <= 0 {
		return errors.New("native Windows route interface resolution is invalid")
	}
	mutationState := state
	mutationState.InterfaceIndex = response.InterfaceIndex
	if err := validateNativeRouteState(mutationState); err != nil {
		return errors.New("native Windows route interface resolution is invalid")
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	registry.Routes = upsertNativeRoute(registry.Routes, state)
	tombstone := nativeMutationTombstone{Kind: nativeTombstoneRoute, Action: nativeTombstonePut, Phase: nativeFirewallPhasePrepared, BootID: bootID, Route: &mutationState}
	registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	if _, err = backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "add_route", Route: &mutationState}); err != nil {
		tombstone.Phase = nativeFirewallPhaseCleanup
		registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	registry.Tombstones = removeNativeMutationTombstone(registry.Tombstones, tombstone)
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) RemoveRoute(ctx context.Context, state RouteState) error {
	if err := validateNativeRouteState(state); err != nil {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	if !containsNativeRoute(registry.Routes, state) {
		return errors.New("native Windows route is not present in the ownership registry")
	}
	if containsNativeRouteTombstone(registry.Tombstones, state) {
		_, _ = backend.reconcilePendingMutationsLocked(registry)
		return errors.New("native Windows route identity is quarantined by an indeterminate mutation")
	}
	if containsProtectiveMutationTombstone(registry.Tombstones, state.Revision) {
		return errors.New("native Windows protective state is quarantined by an indeterminate mutation")
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	tombstone := nativeMutationTombstone{Kind: nativeTombstoneRoute, Action: nativeTombstoneRemove, Phase: nativeFirewallPhasePrepared, BootID: bootID, Route: &state}
	registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	if _, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "remove_route", Route: &state}); err != nil {
		tombstone.Phase = nativeFirewallPhaseCleanup
		registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	registry.Tombstones = removeNativeMutationTombstone(registry.Tombstones, tombstone)
	registry.Routes = removeNativeRoute(registry.Routes, state)
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) PutFirewall(ctx context.Context, state FirewallState) error {
	return backend.PutFirewallBatch(ctx, []FirewallState{state})
}

func (backend *nativeMutationBackend) PutFirewallBatch(ctx context.Context, states []FirewallState) error {
	states, err := normalizeNativeFirewallBatch(states)
	if err != nil || len(states) == 0 {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	registry, err = backend.reconcilePendingMutationsLocked(registry)
	if err != nil {
		return err
	}
	for _, state := range states {
		if containsNativeFirewallTombstone(registry.Tombstones, state.Rule.Name) {
			return errors.New("native Windows firewall identity is quarantined by an indeterminate removal")
		}
		if ownership, exists := findNativeFirewallByName(registry.Firewall, state.Rule.Name); exists && nativeFirewallOwnershipPhase(ownership) != nativeFirewallPhaseApplied {
			return errors.New("native Windows firewall identity is quarantined by an indeterminate mutation")
		}
	}
	response, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "resolve_firewall_batch", Firewalls: states})
	if err != nil {
		return err
	}
	if len(response.FirewallBindings) != len(states) {
		return errors.New("native Windows firewall binding response is incomplete")
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	bindings := make([]nativeFirewallOwnership, len(states))
	updated := append([]nativeFirewallOwnership(nil), registry.Firewall...)
	for index, ownership := range response.FirewallBindings {
		if ownership.State != states[index] || ownership.Committed || ownership.Phase != "" || ownership.BootID != "" || ownership.PreviousInterfaceAlias != "" || ownership.PreviousInterfacePattern != "" || !validNativeIdentity(ownership.InterfaceAlias) || ownership.InterfacePattern != escapePowerShellWildcard(ownership.InterfaceAlias) {
			return errors.New("native Windows firewall binding response is invalid")
		}
		ownership, err = prepareNativeFirewallOwnership(updated, ownership)
		if err != nil {
			return err
		}
		ownership.Phase = nativeFirewallPhasePrepared
		ownership.BootID = bootID
		bindings[index] = ownership
		updated, err = upsertNativeFirewall(updated, ownership)
		if err != nil {
			return err
		}
	}
	registry.Firewall = updated
	// Commit the complete binding set before any OS mutation. A failed or
	// indeterminate batch therefore leaves enough exact identity to retry or
	// reconcile every possibly-created rule without claiming foreign rules.
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	if _, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "put_firewall_batch", FirewallBindings: bindings}); err != nil {
		for index := range bindings {
			bindings[index].Phase = nativeFirewallPhaseCleanup
			bindings[index].Committed = false
			var phaseErr error
			registry.Firewall, phaseErr = upsertNativeFirewall(registry.Firewall, bindings[index])
			if phaseErr != nil {
				return phaseErr
			}
		}
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	for index := range bindings {
		bindings[index].PreviousInterfaceAlias = ""
		bindings[index].PreviousInterfacePattern = ""
		bindings[index].Phase = nativeFirewallPhaseApplied
		bindings[index].BootID = ""
		bindings[index].Committed = true
		registry.Firewall, err = upsertNativeFirewall(registry.Firewall, bindings[index])
		if err != nil {
			return err
		}
	}
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) RemoveFirewall(ctx context.Context, state FirewallState) error {
	return backend.RemoveFirewallBatch(ctx, []FirewallState{state})
}

func (backend *nativeMutationBackend) RemoveFirewallBatch(ctx context.Context, states []FirewallState) error {
	states, err := normalizeNativeFirewallBatch(states)
	if err != nil || len(states) == 0 {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	for _, state := range states {
		if containsProtectiveMutationTombstone(registry.Tombstones, state.Revision) {
			return errors.New("native Windows protective state is quarantined by an indeterminate mutation")
		}
	}
	bindings := make([]nativeFirewallOwnership, 0, len(states))
	for _, state := range states {
		ownership, exists := findNativeFirewall(registry.Firewall, state)
		if !exists {
			return errors.New("native Windows firewall rule is not present in the ownership registry")
		}
		if nativeFirewallOwnershipPhase(ownership) != nativeFirewallPhaseApplied {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
			return errors.New("native Windows firewall identity is quarantined by an indeterminate mutation")
		}
		if containsNativeFirewallTombstone(registry.Tombstones, ownership.State.Rule.Name) {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
			return errors.New("native Windows firewall identity is quarantined by an indeterminate removal")
		}
		// Canonicalize backward-compatible committed entries before embedding
		// their exact binding in a durable remove generation.
		ownership.Phase = nativeFirewallPhaseApplied
		ownership.Committed = true
		registry.Firewall, err = upsertNativeFirewall(registry.Firewall, ownership)
		if err != nil {
			return err
		}
		bindings = append(bindings, ownership)
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	for index := range bindings {
		tombstone := nativeMutationTombstone{Kind: nativeTombstoneFirewall, Action: nativeTombstoneRemove, Phase: nativeFirewallPhasePrepared, BootID: bootID, Firewall: &bindings[index]}
		registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
	}
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	if _, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "remove_firewall_batch", FirewallBindings: bindings}); err != nil {
		for index := range bindings {
			tombstone := nativeMutationTombstone{Kind: nativeTombstoneFirewall, Action: nativeTombstoneRemove, Phase: nativeFirewallPhaseCleanup, BootID: bootID, Firewall: &bindings[index]}
			registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
		}
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	for index, state := range states {
		tombstone := nativeMutationTombstone{Kind: nativeTombstoneFirewall, Firewall: &bindings[index]}
		registry.Tombstones = removeNativeMutationTombstone(registry.Tombstones, tombstone)
		registry.Firewall = removeNativeFirewall(registry.Firewall, state)
	}
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) PutNRPT(ctx context.Context, state NRPTState) error {
	if err := validateNativeNRPTState(state, false); err != nil {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	registry, err = backend.reconcilePendingMutationsLocked(registry)
	if err != nil {
		return err
	}
	tombstoneState := state
	if containsNativeNRPTTombstone(registry.Tombstones, state.Rule.Namespace) {
		return errors.New("native Windows NRPT identity is quarantined by an indeterminate mutation")
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	tombstone := nativeMutationTombstone{Kind: nativeTombstoneNRPT, Action: nativeTombstonePut, Phase: nativeFirewallPhasePrepared, BootID: bootID, NRPT: &tombstoneState}
	registry.NRPT = upsertNativeNRPT(registry.NRPT, state)
	registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	response, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "put_nrpt", NRPT: &state})
	if err != nil {
		tombstone.Phase = nativeFirewallPhaseCleanup
		registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	if !validNativeIdentity(response.NRPTName) {
		return errors.New("native Windows NRPT identity is invalid")
	}
	state.Rule.Name = response.NRPTName
	registry.NRPT = upsertNativeNRPT(registry.NRPT, state)
	registry.Tombstones = removeNativeMutationTombstone(registry.Tombstones, tombstone)
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) RemoveNRPT(ctx context.Context, state NRPTState) error {
	if err := validateNativeNRPTState(state, true); err != nil {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	registry, err := backend.readRegistryLocked()
	if err != nil {
		return err
	}
	if !containsNativeNRPT(registry.NRPT, state) {
		return errors.New("native Windows NRPT rule is not present in the ownership registry")
	}
	tombstoneState := state
	if containsNativeNRPTTombstone(registry.Tombstones, state.Rule.Namespace) {
		_, _ = backend.reconcilePendingMutationsLocked(registry)
		return errors.New("native Windows NRPT identity is quarantined by an indeterminate mutation")
	}
	bootID, err := backend.currentBootID()
	if err != nil {
		return err
	}
	tombstone := nativeMutationTombstone{Kind: nativeTombstoneNRPT, Action: nativeTombstoneRemove, Phase: nativeFirewallPhasePrepared, BootID: bootID, NRPT: &tombstoneState}
	registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
	if err := backend.writeRegistryLocked(registry); err != nil {
		return err
	}
	if _, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "remove_nrpt", NRPT: &state}); err != nil {
		tombstone.Phase = nativeFirewallPhaseCleanup
		registry.Tombstones = upsertNativeMutationTombstone(registry.Tombstones, tombstone)
		if backend.writeRegistryLocked(registry) == nil {
			_, _ = backend.reconcilePendingMutationsLocked(registry)
		}
		return err
	}
	registry.Tombstones = removeNativeMutationTombstone(registry.Tombstones, tombstone)
	registry.NRPT = removeNativeNRPT(registry.NRPT, state)
	return backend.writeRegistryLocked(registry)
}

func (backend *nativeMutationBackend) Reload(ctx context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if err := backend.validateRoot(backend.root); err != nil {
		return err
	}
	_, err := backend.invoke(ctx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "reload"})
	return err
}

type nativeOwnershipRegistry struct {
	Version    int                       `json:"version"`
	Routes     []RouteState              `json:"routes"`
	Firewall   []nativeFirewallOwnership `json:"firewall"`
	NRPT       []NRPTState               `json:"nrpt"`
	Tombstones []nativeMutationTombstone `json:"tombstones,omitempty"`
	SHA256     string                    `json:"sha256"`
}

type nativeOwnershipPayload struct {
	Version    int                       `json:"version"`
	Routes     []RouteState              `json:"routes"`
	Firewall   []nativeFirewallOwnership `json:"firewall"`
	NRPT       []NRPTState               `json:"nrpt"`
	Tombstones []nativeMutationTombstone `json:"tombstones,omitempty"`
}

type nativeMutationTombstone struct {
	Kind     string                   `json:"kind"`
	Action   string                   `json:"action"`
	Phase    string                   `json:"phase"`
	BootID   string                   `json:"boot_id,omitempty"`
	Route    *RouteState              `json:"route,omitempty"`
	Firewall *nativeFirewallOwnership `json:"firewall,omitempty"`
	NRPT     *NRPTState               `json:"nrpt,omitempty"`
}

type nativeFirewallOwnership struct {
	State                    FirewallState `json:"state"`
	InterfaceAlias           string        `json:"interface_alias"`
	InterfacePattern         string        `json:"interface_pattern"`
	PreviousInterfaceAlias   string        `json:"previous_interface_alias,omitempty"`
	PreviousInterfacePattern string        `json:"previous_interface_pattern,omitempty"`
	Phase                    string        `json:"phase,omitempty"`
	BootID                   string        `json:"boot_id,omitempty"`
	Committed                bool          `json:"committed"`
}

func emptyNativeOwnershipRegistry() nativeOwnershipRegistry {
	return nativeOwnershipRegistry{Version: nativeMutationVersion, Routes: []RouteState{}, Firewall: []nativeFirewallOwnership{}, NRPT: []NRPTState{}}
}

func (backend *nativeMutationBackend) registryPath() string {
	return filepath.Join(backend.root, nativeOwnershipRegistryName)
}

func (backend *nativeMutationBackend) readRegistryLocked() (nativeOwnershipRegistry, error) {
	if err := backend.validateRoot(backend.root); err != nil {
		return nativeOwnershipRegistry{}, err
	}
	path := backend.registryPath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		recovered, recoverErr := backend.recoverRegistryBackupLocked(path)
		if recoverErr != nil {
			return nativeOwnershipRegistry{}, recoverErr
		}
		if !recovered {
			return emptyNativeOwnershipRegistry(), nil
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nativeOwnershipRegistry{}, errors.New("native Windows ownership registry is not a regular file")
	}
	data, err := readBoundedFile(path, maxNativeRegistryBytes)
	if err != nil {
		return nativeOwnershipRegistry{}, errors.New("read native Windows ownership registry")
	}
	var registry nativeOwnershipRegistry
	if err := decodeStrictLimit(data, &registry, maxNativeRegistryBytes); err != nil {
		return nativeOwnershipRegistry{}, errors.New("native Windows ownership registry is invalid")
	}
	if err := validateNativeRegistry(registry); err != nil {
		return nativeOwnershipRegistry{}, err
	}
	return registry, nil
}

func (backend *nativeMutationBackend) recoverRegistryBackupLocked(path string) (bool, error) {
	backup := path + nativeReplaceBackupSuffix
	info, err := os.Lstat(backup)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("native Windows ownership registry replacement backup is not a regular file")
	}
	if _, err := os.Lstat(path + ".next"); err == nil {
		return false, errors.New("native Windows ownership registry replacement recovery is ambiguous")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("inspect native Windows ownership registry replacement recovery")
	}
	data, err := readBoundedFile(backup, maxNativeRegistryBytes)
	if err != nil {
		return false, errors.New("read native Windows ownership registry replacement backup")
	}
	var registry nativeOwnershipRegistry
	if err := decodeStrictLimit(data, &registry, maxNativeRegistryBytes); err != nil || validateNativeRegistry(registry) != nil {
		return false, errors.New("native Windows ownership registry replacement backup is invalid")
	}
	// Do not replace a destination that appeared after the missing check. A
	// second writer would make the authoritative registry generation ambiguous.
	if err := moveFile(backup, path, xwindows.MOVEFILE_WRITE_THROUGH); err != nil {
		return false, errors.New("recover native Windows ownership registry replacement backup")
	}
	return true, nil
}

func (backend *nativeMutationBackend) writeRegistryLocked(registry nativeOwnershipRegistry) error {
	if err := backend.validateRoot(backend.root); err != nil {
		return err
	}
	registry.Version = nativeMutationVersion
	registry.Routes = append([]RouteState(nil), registry.Routes...)
	registry.Firewall = append([]nativeFirewallOwnership(nil), registry.Firewall...)
	registry.NRPT = append([]NRPTState(nil), registry.NRPT...)
	registry.Tombstones = append([]nativeMutationTombstone(nil), registry.Tombstones...)
	sort.Slice(registry.Routes, func(left, right int) bool {
		return registry.Routes[left].Revision+"\x00"+routeTupleKey(registry.Routes[left].ManagedRoute) < registry.Routes[right].Revision+"\x00"+routeTupleKey(registry.Routes[right].ManagedRoute)
	})
	sort.Slice(registry.NRPT, func(left, right int) bool {
		return registry.NRPT[left].Revision+"\x00"+registry.NRPT[left].Rule.LogicalID < registry.NRPT[right].Revision+"\x00"+registry.NRPT[right].Rule.LogicalID
	})
	sort.Slice(registry.Firewall, func(left, right int) bool {
		return registry.Firewall[left].State.Rule.Name < registry.Firewall[right].State.Rule.Name
	})
	sort.Slice(registry.Tombstones, func(left, right int) bool {
		return nativeMutationTombstoneKey(registry.Tombstones[left]) < nativeMutationTombstoneKey(registry.Tombstones[right])
	})
	registry.SHA256 = nativeRegistryDigest(registry)
	if err := validateNativeRegistry(registry); err != nil {
		return err
	}
	data, err := json.Marshal(registry)
	if err != nil || len(data)+1 > maxNativeRegistryBytes {
		return errors.New("native Windows ownership registry exceeds its limit")
	}
	path := backend.registryPath()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("native Windows ownership registry is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect native Windows ownership registry")
	}
	if err := replaceNativeRegistryFile(path, append(data, '\n')); err != nil {
		return errors.New("commit native Windows ownership registry")
	}
	return nil
}

func replaceNativeRegistryFile(path string, data []byte) error {
	// The protected root must already exist. Unlike the generic runtime helper,
	// this privileged path deliberately never creates parent directories with
	// inherited ACLs if the validated root disappears.
	temporary := path + ".next"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := atomicReplaceFile(temporary, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateNativeRegistry(registry nativeOwnershipRegistry) error {
	if registry.Version != nativeMutationVersion || len(registry.Routes) > maxManagedRoutes || len(registry.Firewall) > maxFirewallRules || len(registry.NRPT) > maxDNSRules || len(registry.Tombstones) > maxManagedRoutes+maxFirewallRules+maxDNSRules {
		return errors.New("native Windows ownership registry header or count is invalid")
	}
	digest, err := hex.DecodeString(registry.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("native Windows ownership registry digest is invalid")
	}
	want, _ := hex.DecodeString(nativeRegistryDigest(registry))
	if subtle.ConstantTimeCompare(digest, want) != 1 {
		return errors.New("native Windows ownership registry digest mismatch")
	}
	seenRoutes := make(map[string]struct{}, len(registry.Routes))
	for _, state := range registry.Routes {
		if err := validateNativeRouteState(state); err != nil {
			return errors.New("native Windows ownership registry contains an invalid route")
		}
		key := routeTupleKey(state.ManagedRoute)
		if _, duplicate := seenRoutes[key]; duplicate {
			return errors.New("native Windows ownership registry contains duplicate routes")
		}
		seenRoutes[key] = struct{}{}
	}
	seenFirewall := make(map[string]struct{}, len(registry.Firewall))
	for _, ownership := range registry.Firewall {
		if ownership.State.Effective || validateNativeFirewallState(ownership.State) != nil || !validNativeIdentity(ownership.InterfaceAlias) || ownership.InterfacePattern != escapePowerShellWildcard(ownership.InterfaceAlias) || !validNativeFirewallOwnershipPhase(ownership) {
			return errors.New("native Windows ownership registry contains an invalid firewall rule")
		}
		if _, duplicate := seenFirewall[ownership.State.Rule.Name]; duplicate {
			return errors.New("native Windows ownership registry contains duplicate firewall identities")
		}
		seenFirewall[ownership.State.Rule.Name] = struct{}{}
	}
	seenLogical := make(map[string]struct{}, len(registry.NRPT))
	seenNames := make(map[string]struct{}, len(registry.NRPT))
	for _, state := range registry.NRPT {
		if err := validateNativeNRPTState(state, false); err != nil {
			return errors.New("native Windows ownership registry contains an invalid NRPT rule")
		}
		logical := state.Revision + "\x00" + state.Rule.LogicalID
		if _, duplicate := seenLogical[logical]; duplicate {
			return errors.New("native Windows ownership registry contains duplicate NRPT logical identities")
		}
		seenLogical[logical] = struct{}{}
		if state.Rule.Name != "" {
			if _, duplicate := seenNames[state.Rule.Name]; duplicate {
				return errors.New("native Windows ownership registry contains duplicate NRPT native identities")
			}
			seenNames[state.Rule.Name] = struct{}{}
		}
	}
	seenTombstones := make(map[string]struct{}, len(registry.Tombstones))
	for _, tombstone := range registry.Tombstones {
		if !validNativeMutationTombstone(tombstone, registry) {
			return errors.New("native Windows ownership registry contains an invalid mutation tombstone")
		}
		key := nativeMutationTombstoneKey(tombstone)
		if _, duplicate := seenTombstones[key]; duplicate {
			return errors.New("native Windows ownership registry contains duplicate mutation tombstones")
		}
		seenTombstones[key] = struct{}{}
	}
	return nil
}

func validNativeFirewallOwnershipPhase(ownership nativeFirewallOwnership) bool {
	if ownership.BootID != "" {
		if canonical, err := canonicalGUID(ownership.BootID); err != nil || canonical != ownership.BootID {
			return false
		}
	}
	switch ownership.Phase {
	case "": // Backward-compatible v1 registry entry.
	case nativeFirewallPhasePrepared, nativeFirewallPhaseCleanup, nativeFirewallPhaseWatch:
		if ownership.Committed {
			return false
		}
	case nativeFirewallPhaseApplied:
		if !ownership.Committed || ownership.BootID != "" {
			return false
		}
	default:
		return false
	}
	if ownership.PreviousInterfaceAlias == "" || ownership.PreviousInterfacePattern == "" {
		return ownership.PreviousInterfaceAlias == "" && ownership.PreviousInterfacePattern == ""
	}
	return !ownership.Committed && validNativeIdentity(ownership.PreviousInterfaceAlias) && ownership.PreviousInterfacePattern == escapePowerShellWildcard(ownership.PreviousInterfaceAlias) && ownership.PreviousInterfacePattern != ownership.InterfacePattern
}

func nativeFirewallOwnershipPhase(ownership nativeFirewallOwnership) string {
	if ownership.Phase != "" {
		return ownership.Phase
	}
	if ownership.Committed {
		return nativeFirewallPhaseApplied
	}
	return nativeFirewallPhasePrepared
}

func validNativeMutationTombstone(tombstone nativeMutationTombstone, registry nativeOwnershipRegistry) bool {
	if tombstone.Phase != nativeFirewallPhasePrepared && tombstone.Phase != nativeFirewallPhaseCleanup && tombstone.Phase != nativeFirewallPhaseWatch {
		return false
	}
	if tombstone.Action != nativeTombstonePut && tombstone.Action != nativeTombstoneRemove {
		return false
	}
	if tombstone.BootID != "" {
		if canonical, err := canonicalGUID(tombstone.BootID); err != nil || canonical != tombstone.BootID {
			return false
		}
	}
	switch tombstone.Kind {
	case nativeTombstoneRoute:
		return tombstone.Route != nil && tombstone.Firewall == nil && tombstone.NRPT == nil && validateNativeRouteState(*tombstone.Route) == nil && containsNativeRouteMutationOwnership(registry.Routes, *tombstone.Route)
	case nativeTombstoneFirewall:
		if tombstone.Action != nativeTombstoneRemove || tombstone.Route != nil || tombstone.Firewall == nil || tombstone.NRPT != nil || tombstone.Firewall.State.Effective || validateNativeFirewallState(tombstone.Firewall.State) != nil || !validNativeIdentity(tombstone.Firewall.InterfaceAlias) || tombstone.Firewall.InterfacePattern != escapePowerShellWildcard(tombstone.Firewall.InterfaceAlias) || nativeFirewallOwnershipPhase(*tombstone.Firewall) != nativeFirewallPhaseApplied {
			return false
		}
		ownership, exists := findNativeFirewallByName(registry.Firewall, tombstone.Firewall.State.Rule.Name)
		return exists && ownership == *tombstone.Firewall
	case nativeTombstoneNRPT:
		if tombstone.NRPT == nil || tombstone.Route != nil || tombstone.Firewall != nil || validateNativeNRPTState(*tombstone.NRPT, tombstone.Action == nativeTombstoneRemove) != nil {
			return false
		}
		return containsNativeNRPT(registry.NRPT, *tombstone.NRPT)
	default:
		return false
	}
}

func nativeMutationTombstoneKey(tombstone nativeMutationTombstone) string {
	switch tombstone.Kind {
	case nativeTombstoneRoute:
		if tombstone.Route != nil {
			return tombstone.Kind + "\x00" + tombstone.Route.Revision + "\x00" + nativeRouteGenerationKey(tombstone.Route.ManagedRoute)
		}
	case nativeTombstoneFirewall:
		if tombstone.Firewall != nil {
			return tombstone.Kind + "\x00" + tombstone.Firewall.State.Rule.Name
		}
	case nativeTombstoneNRPT:
		if tombstone.NRPT != nil {
			return tombstone.Kind + "\x00" + tombstone.NRPT.Revision + "\x00" + tombstone.NRPT.Rule.LogicalID
		}
	}
	return tombstone.Kind
}

func upsertNativeMutationTombstone(values []nativeMutationTombstone, tombstone nativeMutationTombstone) []nativeMutationTombstone {
	key := nativeMutationTombstoneKey(tombstone)
	result := make([]nativeMutationTombstone, 0, len(values)+1)
	for _, current := range values {
		if nativeMutationTombstoneKey(current) != key {
			result = append(result, current)
		}
	}
	return append(result, tombstone)
}

func removeNativeMutationTombstone(values []nativeMutationTombstone, tombstone nativeMutationTombstone) []nativeMutationTombstone {
	key := nativeMutationTombstoneKey(tombstone)
	return slices.DeleteFunc(values, func(current nativeMutationTombstone) bool {
		return nativeMutationTombstoneKey(current) == key
	})
}

func containsNativeMutationTombstone(values []nativeMutationTombstone, tombstone nativeMutationTombstone) bool {
	key := nativeMutationTombstoneKey(tombstone)
	return slices.ContainsFunc(values, func(current nativeMutationTombstone) bool {
		return nativeMutationTombstoneKey(current) == key
	})
}

func containsNativeFirewallTombstone(values []nativeMutationTombstone, name string) bool {
	return slices.ContainsFunc(values, func(current nativeMutationTombstone) bool {
		return current.Kind == nativeTombstoneFirewall && current.Firewall != nil && current.Firewall.State.Rule.Name == name
	})
}

func containsNativeRouteTombstone(values []nativeMutationTombstone, state RouteState) bool {
	want := nativeRouteCleanupIdentity(state.ManagedRoute)
	return slices.ContainsFunc(values, func(current nativeMutationTombstone) bool {
		return current.Kind == nativeTombstoneRoute && current.Route != nil && nativeRouteCleanupIdentity(current.Route.ManagedRoute) == want
	})
}

func containsNativeRouteMutationOwnership(values []RouteState, state RouteState) bool {
	for _, current := range values {
		if current.Owner != state.Owner || current.Revision != state.Revision {
			continue
		}
		left := current.ManagedRoute
		right := state.ManagedRoute
		left.InterfaceIndex = right.InterfaceIndex
		if left == right {
			return true
		}
	}
	return false
}

func nativeRouteGenerationKey(route ManagedRoute) string {
	route.InterfaceIndex = 0
	return routeTupleKey(route)
}

func nativeRouteCleanupIdentity(route ManagedRoute) string {
	return route.Destination + "\x00" + route.NextHop
}

func containsNativeNRPTTombstone(values []nativeMutationTombstone, namespace string) bool {
	return slices.ContainsFunc(values, func(current nativeMutationTombstone) bool {
		return current.Kind == nativeTombstoneNRPT && current.NRPT != nil && strings.EqualFold(current.NRPT.Rule.Namespace, namespace)
	})
}

func containsProtectiveMutationTombstone(values []nativeMutationTombstone, revision string) bool {
	return slices.ContainsFunc(values, func(current nativeMutationTombstone) bool {
		switch current.Kind {
		case nativeTombstoneRoute:
			return current.Action == nativeTombstonePut && current.Route != nil && current.Route.Revision == revision
		case nativeTombstoneNRPT:
			// Both an indeterminate Put and an indeterminate Remove can change
			// effective DNS after the caller regains control. Preserve routes and
			// firewall until configured and effective NRPT removal is verified.
			// A verified remove remains quarantined against reapply, but its watch
			// phase no longer prevents protective teardown.
			return current.NRPT != nil && current.NRPT.Revision == revision && (current.Action == nativeTombstonePut || current.Phase != nativeFirewallPhaseWatch)
		default:
			return false
		}
	})
}

func nativeRegistryDigest(registry nativeOwnershipRegistry) string {
	payload := nativeOwnershipPayload{Version: registry.Version, Routes: registry.Routes, Firewall: registry.Firewall, NRPT: registry.NRPT, Tombstones: registry.Tombstones}
	data, _ := json.Marshal(payload)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func upsertNativeRoute(routes []RouteState, state RouteState) []RouteState {
	result := removeNativeRouteTuple(routes, state.ManagedRoute)
	return append(result, state)
}

func removeNativeRouteTuple(routes []RouteState, route ManagedRoute) []RouteState {
	result := make([]RouteState, 0, len(routes))
	key := routeTupleKey(route)
	for _, current := range routes {
		if routeTupleKey(current.ManagedRoute) != key {
			result = append(result, current)
		}
	}
	return result
}

func removeNativeRoute(routes []RouteState, state RouteState) []RouteState {
	result := make([]RouteState, 0, len(routes))
	for _, current := range routes {
		if current.Revision != state.Revision || current.ManagedRoute != state.ManagedRoute {
			result = append(result, current)
		}
	}
	return result
}

func containsNativeRoute(routes []RouteState, state RouteState) bool {
	for _, current := range routes {
		if current.Owner == state.Owner && current.Revision == state.Revision && current.ManagedRoute == state.ManagedRoute {
			return true
		}
	}
	return false
}

func upsertNativeFirewall(values []nativeFirewallOwnership, ownership nativeFirewallOwnership) ([]nativeFirewallOwnership, error) {
	result := make([]nativeFirewallOwnership, 0, len(values)+1)
	for _, current := range values {
		if current.State.Rule.Name != ownership.State.Rule.Name {
			result = append(result, current)
			continue
		}
		if nativeFirewallOwnershipPhase(current) == nativeFirewallPhaseApplied && !nativeFirewallReplacementAuthorized(current, ownership) {
			return nil, errors.New("native Windows firewall ownership collision")
		}
	}
	return append(result, ownership), nil
}

func prepareNativeFirewallOwnership(values []nativeFirewallOwnership, ownership nativeFirewallOwnership) (nativeFirewallOwnership, error) {
	current, exists := findNativeFirewallByName(values, ownership.State.Rule.Name)
	if !exists {
		return ownership, nil
	}
	if current.State == ownership.State && current.InterfaceAlias == ownership.InterfaceAlias && current.InterfacePattern == ownership.InterfacePattern {
		ownership.PreviousInterfaceAlias = current.PreviousInterfaceAlias
		ownership.PreviousInterfacePattern = current.PreviousInterfacePattern
		return ownership, nil
	}
	if !nativeFirewallMigrationCompatible(current.State, ownership.State) {
		return nativeFirewallOwnership{}, errors.New("native Windows firewall ownership collision")
	}
	if current.InterfaceAlias == ownership.InterfaceAlias && current.InterfacePattern == ownership.InterfacePattern {
		return ownership, nil
	}
	ownership.PreviousInterfaceAlias = current.InterfaceAlias
	ownership.PreviousInterfacePattern = current.InterfacePattern
	if current.PreviousInterfaceAlias != "" {
		ownership.PreviousInterfaceAlias = current.PreviousInterfaceAlias
		ownership.PreviousInterfacePattern = current.PreviousInterfacePattern
	}
	return ownership, nil
}

func nativeFirewallReplacementAuthorized(current, replacement nativeFirewallOwnership) bool {
	if current.State == replacement.State && current.InterfaceAlias == replacement.InterfaceAlias && current.InterfacePattern == replacement.InterfacePattern {
		return true
	}
	if !nativeFirewallMigrationCompatible(current.State, replacement.State) {
		return false
	}
	if current.InterfaceAlias == replacement.InterfaceAlias && current.InterfacePattern == replacement.InterfacePattern {
		return true
	}
	return replacement.PreviousInterfaceAlias == current.InterfaceAlias && replacement.PreviousInterfacePattern == current.InterfacePattern
}

func nativeFirewallMigrationCompatible(left, right FirewallState) bool {
	left.Effective = false
	right.Effective = false
	left.Rule.InterfaceIndex = right.Rule.InterfaceIndex
	return left == right
}

func findNativeFirewallByName(values []nativeFirewallOwnership, name string) (nativeFirewallOwnership, bool) {
	for _, current := range values {
		if current.State.Rule.Name == name {
			return current, true
		}
	}
	return nativeFirewallOwnership{}, false
}

func (backend *nativeMutationBackend) reconcilePendingMutationsLocked(registry nativeOwnershipRegistry) (nativeOwnershipRegistry, error) {
	pending := make([]nativeFirewallOwnership, 0, len(registry.Firewall))
	pendingNames := make(map[string]struct{}, len(registry.Firewall))
	mutationTombstones := make([]nativeMutationTombstone, 0, len(registry.Tombstones))
	changed := false
	settling := false
	for index := range registry.Firewall {
		if nativeFirewallOwnershipPhase(registry.Firewall[index]) == nativeFirewallPhaseApplied {
			continue
		}
		if nativeFirewallOwnershipPhase(registry.Firewall[index]) != nativeFirewallPhaseWatch {
			settling = true
			registry.Firewall[index].Phase = nativeFirewallPhaseCleanup
			changed = true
		}
		registry.Firewall[index].Committed = false
		pending = append(pending, registry.Firewall[index])
		pendingNames[registry.Firewall[index].State.Rule.Name] = struct{}{}
	}
	for index := range registry.Tombstones {
		if registry.Tombstones[index].Phase != nativeFirewallPhaseWatch {
			settling = true
			registry.Tombstones[index].Phase = nativeFirewallPhaseCleanup
			changed = true
		}
		if registry.Tombstones[index].Kind == nativeTombstoneFirewall {
			if registry.Tombstones[index].Firewall == nil {
				return registry, errors.New("native Windows firewall cleanup tombstone is invalid")
			}
			name := registry.Tombstones[index].Firewall.State.Rule.Name
			if _, duplicate := pendingNames[name]; duplicate {
				return registry, errors.New("native Windows firewall identity has conflicting cleanup intents")
			}
			pendingNames[name] = struct{}{}
			pending = append(pending, *registry.Tombstones[index].Firewall)
			continue
		}
		mutationTombstones = append(mutationTombstones, registry.Tombstones[index])
	}
	if len(pending) == 0 && len(registry.Tombstones) == 0 {
		return registry, nil
	}
	if changed {
		if err := backend.writeRegistryLocked(registry); err != nil {
			return registry, err
		}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), nativeFirewallCleanupWindow)
	defer cancel()
	wait := backend.firewallCleanupWait
	if wait == nil {
		wait = waitNativeFirewallCleanup
	}
	checks := 1
	if settling {
		checks = nativeFirewallCleanupChecks
	}
	// Delayed rounds cover the common provider-lag window, but they are not a
	// CIM completion barrier. Successful negative checks only move the durable
	// tombstone to watch; no timeout ever authorizes garbage collection.
	for check := 0; check < checks; check++ {
		if check != 0 {
			if err := wait(cleanupCtx, nativeFirewallCleanupDelay); err != nil {
				return registry, errors.New("native Windows firewall cleanup settling window failed")
			}
		}
		if _, err := backend.invoke(cleanupCtx, nativeMutationRequest{Version: nativeMutationVersion, Operation: "cleanup_native_tombstones", FirewallBindings: pending, MutationTombstones: mutationTombstones}); err != nil {
			return registry, errors.New("native Windows mutation tombstone cleanup verification failed")
		}
	}
	for index := range registry.Firewall {
		if nativeFirewallOwnershipPhase(registry.Firewall[index]) != nativeFirewallPhaseApplied {
			registry.Firewall[index].Phase = nativeFirewallPhaseWatch
			registry.Firewall[index].Committed = false
		}
	}
	for index := range registry.Tombstones {
		registry.Tombstones[index].Phase = nativeFirewallPhaseWatch
	}
	if err := backend.writeRegistryLocked(registry); err != nil {
		return registry, err
	}
	return registry, nil
}

func normalizeNativeFirewallBatch(states []FirewallState) ([]FirewallState, error) {
	if len(states) > maxFirewallRules {
		return nil, errors.New("structured native Windows firewall batch exceeds its limit")
	}
	normalized := append([]FirewallState(nil), states...)
	seen := make(map[string]struct{}, len(normalized))
	for index := range normalized {
		normalized[index].Effective = false
		if err := validateNativeFirewallState(normalized[index]); err != nil {
			return nil, err
		}
		if _, duplicate := seen[normalized[index].Rule.Name]; duplicate {
			return nil, errors.New("structured native Windows firewall batch contains duplicate identities")
		}
		seen[normalized[index].Rule.Name] = struct{}{}
	}
	return normalized, nil
}

func findNativeFirewall(values []nativeFirewallOwnership, state FirewallState) (nativeFirewallOwnership, bool) {
	state.Effective = false
	for _, current := range values {
		if current.State == state {
			return current, true
		}
	}
	return nativeFirewallOwnership{}, false
}

func removeNativeFirewall(values []nativeFirewallOwnership, state FirewallState) []nativeFirewallOwnership {
	state.Effective = false
	result := make([]nativeFirewallOwnership, 0, len(values))
	for _, current := range values {
		if current.State == state {
			continue
		}
		result = append(result, current)
	}
	return result
}

func upsertNativeNRPT(values []NRPTState, state NRPTState) []NRPTState {
	result := make([]NRPTState, 0, len(values)+1)
	for _, current := range values {
		if current.Revision == state.Revision && current.Rule.LogicalID == state.Rule.LogicalID || state.Rule.Name != "" && current.Rule.Name == state.Rule.Name {
			continue
		}
		result = append(result, current)
	}
	return append(result, state)
}

func removeNativeNRPT(values []NRPTState, state NRPTState) []NRPTState {
	result := make([]NRPTState, 0, len(values))
	for _, current := range values {
		if current.Revision == state.Revision && current.Rule.LogicalID == state.Rule.LogicalID && (current.Rule.Name == "" || current.Rule.Name == state.Rule.Name) {
			continue
		}
		result = append(result, current)
	}
	return result
}

func containsNativeNRPT(values []NRPTState, state NRPTState) bool {
	for _, current := range values {
		if current.Owner == state.Owner && current.Revision == state.Revision && current.Rule.LogicalID == state.Rule.LogicalID && (current.Rule.Name == "" || current.Rule.Name == state.Rule.Name) && nativeNRPTObservableEqual(current.Rule, state.Rule) {
			return true
		}
	}
	return false
}

func validateNativeRouteState(state RouteState) error {
	route := state.ManagedRoute
	prefix, err := parseExplicitPrefix(route.Family, route.Destination)
	nextHop, nextHopErr := netip.ParseAddr(route.NextHop)
	_, guidErr := canonicalGUID(route.InterfaceGUID)
	if state.Owner != ArtifactOwner || !validRevision(state.Revision) || state.Protected || err != nil || prefix.String() != route.Destination || nextHopErr != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != route.Family || nextHop.String() != route.NextHop || guidErr != nil || route.InterfaceIndex <= 0 || route.Metric != ReservedRouteMetric || route.PolicyStore != RoutePolicyStore || route.Protocol != RouteProtocol || !route.JournalOwned || route.Role != RouteRoleEndpointDirect && route.Role != RouteRoleVPNClass {
		return errors.New("structured native Windows route is invalid or unowned")
	}
	return nil
}

func validateNativeFirewallState(state FirewallState) error {
	rule := state.Rule
	prefix, prefixErr := parseExplicitPrefix(rule.Family, rule.RemoteCIDR)
	_, guidErr := canonicalGUID(rule.InterfaceGUID)
	if state.Owner != ArtifactOwner || !validRevision(state.Revision) || prefixErr != nil || prefix.String() != rule.RemoteCIDR || guidErr != nil || rule.InterfaceIndex <= 0 || rule.Action != "block" || rule.Direction != "outbound" || rule.PolicyStore != FirewallPolicyStore || rule.Name != FirewallRuleName(state.Revision, rule.Family, rule.RemoteCIDR, rule.InterfaceGUID) || rule.Group != ownershipGroup(state.Revision) || rule.Description != ownershipDescription(state.Revision) {
		return errors.New("structured native Windows firewall rule is invalid or unowned")
	}
	return nil
}

func validateNativeNRPTState(state NRPTState, requireName bool) error {
	rule := state.Rule
	if state.Owner != ArtifactOwner || !validRevision(state.Revision) || rule.LogicalID == "" || len(rule.LogicalID) > 256 || rule.DisplayName == "" || len(rule.DisplayName) > 256 || !validDNSNamespace(rule.Namespace) || rule.Comment != ownershipDescription(state.Revision) || len(rule.NameServers) == 0 || len(rule.NameServers) > 4 || requireName && rule.Name == "" || !validOptionalNativeIdentity(rule.Name) {
		return errors.New("structured native Windows NRPT rule is invalid or unowned")
	}
	seen := make(map[string]struct{}, len(rule.NameServers))
	for _, value := range rule.NameServers {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != value {
			return errors.New("structured native Windows NRPT nameserver is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("structured native Windows NRPT nameserver is duplicated")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validOptionalNativeIdentity(value string) bool {
	return value == "" || validNativeIdentity(value)
}

func validNativeIdentity(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func escapePowerShellWildcard(value string) string {
	var escaped strings.Builder
	escaped.Grow(len(value))
	for _, character := range value {
		if character == '`' || character == '*' || character == '?' || character == '[' || character == ']' {
			escaped.WriteRune('`')
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}

type rawNativeMutationSnapshot struct {
	Adapters                *[]rawAdapterRecord           `json:"adapters"`
	Compartments            *[]rawCompartmentRecord       `json:"compartments"`
	Routes                  *[]rawNativeRouteRecord       `json:"routes"`
	Firewall                *[]rawNativeFirewallRecord    `json:"firewall"`
	FirewallEffective       *[]rawNativeEffectiveFirewall `json:"firewallEffective"`
	FirewallProfiles        *[]rawNativeFirewallProfile   `json:"firewallProfiles"`
	FirewallBypassAbsent    *bool                         `json:"firewallBypassAbsent"`
	FirewallServicesRunning *bool                         `json:"firewallServicesRunning"`
	NRPT                    *[]rawNativeNRPTRecord        `json:"nrpt"`
	NRPTEffective           *[]rawNativeEffectiveNRPT     `json:"nrptEffective"`
}

type rawNativeRouteRecord struct {
	InterfaceIndex *int    `json:"interfaceIndex"`
	CompartmentID  *int    `json:"compartmentId"`
	AddressFamily  *int    `json:"addressFamily"`
	Destination    *string `json:"destinationPrefix"`
	NextHop        *string `json:"nextHop"`
	RouteMetric    *uint64 `json:"routeMetric"`
	PolicyStore    *string `json:"policyStore"`
	Protocol       *string `json:"protocol"`
	State          *int    `json:"state"`
}

type rawNativeEffectiveFirewall struct {
	Name  *string `json:"name"`
	Exact *bool   `json:"exact"`
}

type rawNativeFirewallProfile struct {
	Name              *string `json:"name"`
	Enabled           *bool   `json:"enabled"`
	LocalRulesAllowed *bool   `json:"localRulesAllowed"`
}

type rawNativeFirewallRecord struct {
	Name             *string   `json:"name"`
	DisplayName      *string   `json:"displayName"`
	Description      *string   `json:"description"`
	Group            *string   `json:"group"`
	Enabled          *string   `json:"enabled"`
	Direction        *string   `json:"direction"`
	Action           *string   `json:"action"`
	RemoteAddresses  *[]string `json:"remoteAddresses"`
	InterfaceAliases *[]string `json:"interfaceAliases"`
}

type rawNativeNRPTRecord struct {
	Name        *string   `json:"name"`
	DisplayName *string   `json:"displayName"`
	Namespace   *string   `json:"namespace"`
	NameServers *[]string `json:"nameServers"`
	Comment     *string   `json:"comment"`
}

type rawNativeEffectiveNRPT struct {
	Namespace   *string   `json:"namespace"`
	NameServers *[]string `json:"nameServers"`
}

func parseNativeMutationSnapshot(raw rawNativeMutationSnapshot, registry nativeOwnershipRegistry) (MutationSnapshot, nativeOwnershipRegistry, error) {
	if raw.Adapters == nil || raw.Compartments == nil || raw.Routes == nil || raw.Firewall == nil || raw.FirewallEffective == nil || raw.FirewallProfiles == nil || raw.FirewallBypassAbsent == nil || raw.FirewallServicesRunning == nil || raw.NRPT == nil || raw.NRPTEffective == nil || len(*raw.Adapters) == 0 || len(*raw.Adapters) > maxAdapters || len(*raw.Compartments) == 0 || len(*raw.Compartments) > maxCompartments || len(*raw.Routes) > maxRoutes || len(*raw.Firewall) > maxNativeFirewallRecords || len(*raw.FirewallEffective) > maxFirewallRules || len(*raw.FirewallProfiles) > 3 || len(*raw.NRPT) > maxNRPTRules || len(*raw.NRPTEffective) > maxNRPTRules {
		return MutationSnapshot{}, nativeOwnershipRegistry{}, errors.New("native Windows mutation snapshot count is invalid")
	}
	if err := validateDefaultNetworkCompartment(*raw.Compartments); err != nil {
		return MutationSnapshot{}, nativeOwnershipRegistry{}, err
	}
	adapters, adaptersByIndex, err := parseAdapters(*raw.Adapters)
	if err != nil {
		return MutationSnapshot{}, nativeOwnershipRegistry{}, err
	}
	adaptersByName := make(map[string]*Adapter, len(adapters))
	for index := range adapters {
		adapter := &adapters[index]
		adaptersByName[strings.ToLower(adapter.Name)] = adapter
	}
	effective := parseNativeEffectiveNRPT(*raw.NRPTEffective)
	effectiveFirewall, err := parseNativeEffectiveFirewall(*raw.FirewallEffective, registry.Firewall)
	if err != nil {
		return MutationSnapshot{}, nativeOwnershipRegistry{}, err
	}
	firewallEnforced, err := parseNativeFirewallProfiles(*raw.FirewallProfiles)
	if err != nil {
		return MutationSnapshot{}, nativeOwnershipRegistry{}, err
	}
	snapshot := MutationSnapshot{Adapters: adapters, Routes: make([]RouteState, 0, len(*raw.Routes)), Firewall: make([]FirewallState, 0, len(*raw.Firewall)), FirewallEnforced: firewallEnforced && *raw.FirewallBypassAbsent && *raw.FirewallServicesRunning, NRPT: make([]NRPTState, 0, len(*raw.NRPT))}
	for _, record := range *raw.Routes {
		state, err := parseNativeRouteRecord(record, adaptersByIndex, registry.Routes)
		if err != nil {
			return MutationSnapshot{}, nativeOwnershipRegistry{}, err
		}
		snapshot.Routes = append(snapshot.Routes, state)
	}
	for _, record := range *raw.Firewall {
		state, err := parseNativeFirewallRecord(record, adaptersByName, registry.Firewall, effectiveFirewall)
		if err != nil {
			return MutationSnapshot{}, nativeOwnershipRegistry{}, err
		}
		snapshot.Firewall = append(snapshot.Firewall, state)
	}
	for _, record := range *raw.NRPT {
		state, err := parseNativeNRPTRecord(record, registry.NRPT, effective)
		if err != nil {
			return MutationSnapshot{}, nativeOwnershipRegistry{}, err
		}
		snapshot.NRPT = append(snapshot.NRPT, state)
	}
	sort.Slice(snapshot.Routes, func(left, right int) bool { return jsonKey(snapshot.Routes[left]) < jsonKey(snapshot.Routes[right]) })
	sort.Slice(snapshot.Firewall, func(left, right int) bool {
		return jsonKey(snapshot.Firewall[left]) < jsonKey(snapshot.Firewall[right])
	})
	sort.Slice(snapshot.NRPT, func(left, right int) bool { return jsonKey(snapshot.NRPT[left]) < jsonKey(snapshot.NRPT[right]) })
	return snapshot, reconcileNativeRegistry(raw, snapshot, registry), nil
}

func parseNativeRouteRecord(record rawNativeRouteRecord, adapters map[int]*Adapter, owned []RouteState) (RouteState, error) {
	if record.InterfaceIndex == nil || record.CompartmentID == nil || record.AddressFamily == nil || record.Destination == nil || record.NextHop == nil || record.RouteMetric == nil || record.PolicyStore == nil || record.Protocol == nil || record.State == nil {
		return RouteState{}, errors.New("native Windows route snapshot is incomplete")
	}
	family, _, err := parseNumericFamily(*record.AddressFamily)
	prefix, prefixErr := netip.ParsePrefix(strings.TrimSpace(*record.Destination))
	nextHop, nextHopErr := netip.ParseAddr(strings.TrimSpace(*record.NextHop))
	if err != nil || prefixErr != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || addressFamily(prefix.Addr()) != family || nextHopErr != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != family || *record.InterfaceIndex <= 0 || *record.CompartmentID != 1 || *record.RouteMetric > maxWindowsMetric || *record.State < routeStateAlive || *record.State > 2 || len(*record.PolicyStore) > 64 || len(*record.Protocol) > 64 {
		return RouteState{}, errors.New("native Windows route snapshot value is invalid")
	}
	adapter := adapters[*record.InterfaceIndex]
	interfaceGUID := ""
	protected := false
	if adapter != nil {
		interfaceGUID = adapter.InterfaceGUID
		protected = adapter.Kind == AdapterCisco
	}
	observed := ManagedRoute{Family: family, Destination: prefix.Masked().String(), NextHop: nextHop.Unmap().String(), InterfaceGUID: interfaceGUID, InterfaceIndex: *record.InterfaceIndex, Metric: uint32(*record.RouteMetric), PolicyStore: strings.TrimSpace(*record.PolicyStore), Protocol: strings.TrimSpace(*record.Protocol)}
	matches := make([]RouteState, 0, 1)
	for _, state := range owned {
		if nativeObservedRouteEqual(observed, state.ManagedRoute) {
			matches = append(matches, state)
		}
	}
	if len(matches) > 1 {
		return RouteState{}, errors.New("native Windows route ownership is ambiguous")
	}
	if len(matches) == 1 {
		state := matches[0]
		state.Protected = protected
		state.State = *record.State
		return state, nil
	}
	return RouteState{ManagedRoute: observed, Protected: protected, State: *record.State}, nil
}

func nativeObservedRouteEqual(observed, registered ManagedRoute) bool {
	// InterfaceIndex is an ephemeral locator on Windows. The immutable artifact
	// and registry retain the plan-time value, while stable GUID plus the exact
	// route tuple authorizes rebinding after disable/enable or restart.
	return observed.Family == registered.Family && observed.Destination == registered.Destination && observed.NextHop == registered.NextHop && observed.InterfaceGUID == registered.InterfaceGUID && observed.Metric == registered.Metric && observed.PolicyStore == registered.PolicyStore && observed.Protocol == registered.Protocol
}

func parseNativeFirewallRecord(record rawNativeFirewallRecord, adapters map[string]*Adapter, owned []nativeFirewallOwnership, effective map[string]bool) (FirewallState, error) {
	if record.Name == nil || record.DisplayName == nil || record.Description == nil || record.Group == nil || record.Enabled == nil || record.Direction == nil || record.Action == nil || record.RemoteAddresses == nil || record.InterfaceAliases == nil || !validNativeIdentity(*record.Name) || len(*record.Description) > 512 || len(*record.Group) > 256 {
		return FirewallState{}, errors.New("native Windows firewall snapshot is invalid")
	}
	matches := make([]nativeFirewallOwnership, 0, 1)
	for _, ownership := range owned {
		if nativeFirewallRecordMatches(record, ownership) {
			matches = append(matches, ownership)
		}
	}
	if len(matches) > 1 {
		return FirewallState{}, errors.New("native Windows firewall ownership is ambiguous")
	}
	if len(matches) == 1 {
		state := matches[0].State
		state.Effective = effective[state.Rule.Name]
		return state, nil
	}
	rule := FirewallRule{Name: *record.Name, Action: strings.ToLower(*record.Action), Direction: strings.ToLower(*record.Direction), PolicyStore: FirewallPolicyStore, Group: *record.Group, Description: *record.Description}
	if len(*record.RemoteAddresses) == 1 && len(*record.InterfaceAliases) == 1 {
		prefix, err := netip.ParsePrefix((*record.RemoteAddresses)[0])
		adapter := adapters[strings.ToLower((*record.InterfaceAliases)[0])]
		if err == nil && prefix == prefix.Masked() && prefix.Bits() != 0 && prefix.Addr().Zone() == "" && !prefix.Addr().Is4In6() && adapter != nil {
			rule.Family = addressFamily(prefix.Addr())
			rule.RemoteCIDR = prefix.String()
			rule.InterfaceGUID = adapter.InterfaceGUID
			rule.InterfaceIndex = adapter.Index
		}
	}
	return FirewallState{Rule: rule}, nil
}

func nativeFirewallRecordMatches(record rawNativeFirewallRecord, ownership nativeFirewallOwnership) bool {
	rule := ownership.State.Rule
	return len(*record.RemoteAddresses) == 1 && len(*record.InterfaceAliases) == 1 &&
		*record.Name == rule.Name && *record.DisplayName == rule.Name && *record.Description == rule.Description && *record.Group == rule.Group &&
		strings.EqualFold(*record.Enabled, "true") && strings.EqualFold(*record.Direction, "outbound") && strings.EqualFold(*record.Action, "block") &&
		(*record.RemoteAddresses)[0] == rule.RemoteCIDR && (*record.InterfaceAliases)[0] == ownership.InterfacePattern
}

func parseNativeEffectiveFirewall(records []rawNativeEffectiveFirewall, owned []nativeFirewallOwnership) (map[string]bool, error) {
	want := make(map[string]struct{}, len(owned))
	for _, ownership := range owned {
		want[ownership.State.Rule.Name] = struct{}{}
	}
	if len(records) != len(want) {
		return nil, errors.New("native Windows effective firewall inventory is incomplete")
	}
	result := make(map[string]bool, len(records))
	for _, record := range records {
		if record.Name == nil || record.Exact == nil || !validNativeIdentity(*record.Name) {
			return nil, errors.New("native Windows effective firewall record is invalid")
		}
		if _, expected := want[*record.Name]; !expected {
			return nil, errors.New("native Windows effective firewall identity is unexpected")
		}
		if _, duplicate := result[*record.Name]; duplicate {
			return nil, errors.New("native Windows effective firewall identity is duplicated")
		}
		result[*record.Name] = *record.Exact
	}
	return result, nil
}

func parseNativeFirewallProfiles(records []rawNativeFirewallProfile) (bool, error) {
	want := map[string]struct{}{"domain": {}, "private": {}, "public": {}}
	seen := make(map[string]struct{}, len(records))
	enforced := true
	for _, record := range records {
		if record.Name == nil || record.Enabled == nil || record.LocalRulesAllowed == nil {
			return false, errors.New("native Windows firewall profile inventory is invalid")
		}
		name := strings.ToLower(strings.TrimSpace(*record.Name))
		if _, expected := want[name]; !expected {
			return false, errors.New("native Windows firewall profile identity is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return false, errors.New("native Windows firewall profile identity is duplicated")
		}
		seen[name] = struct{}{}
		enforced = enforced && *record.Enabled && *record.LocalRulesAllowed
	}
	if len(seen) != len(want) {
		return false, errors.New("native Windows firewall profile inventory is incomplete")
	}
	return enforced, nil
}

func parseNativeNRPTRecord(record rawNativeNRPTRecord, owned []NRPTState, effective []nativeEffectiveNRPT) (NRPTState, error) {
	if record.Name == nil || record.DisplayName == nil || record.Namespace == nil || record.NameServers == nil || record.Comment == nil || !validNativeIdentity(*record.Name) || len(*record.DisplayName) > 256 || len(*record.Comment) > 512 || len(*record.NameServers) > 64 {
		return NRPTState{}, errors.New("native Windows NRPT snapshot is invalid")
	}
	observedServers := make([]string, 0, len(*record.NameServers))
	for _, value := range *record.NameServers {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return NRPTState{}, errors.New("native Windows NRPT snapshot contains an invalid nameserver")
		}
		observedServers = append(observedServers, address.Unmap().String())
	}
	observed := NRPTRule{LogicalID: *record.Name, Name: *record.Name, DisplayName: *record.DisplayName, Namespace: *record.Namespace, NameServers: observedServers, Comment: *record.Comment}
	matches := make([]NRPTState, 0, 1)
	for _, state := range owned {
		nameMatches := state.Rule.Name == "" || state.Rule.Name == observed.Name
		if nameMatches && nativeNRPTObservableEqual(state.Rule, observed) {
			matches = append(matches, state)
		}
	}
	if len(matches) > 1 {
		return NRPTState{}, errors.New("native Windows NRPT ownership is ambiguous")
	}
	if len(matches) == 1 {
		state := matches[0]
		state.Rule.Name = observed.Name
		state.Effective = nativeNRPTEffective(state.Rule, effective)
		return state, nil
	}
	return NRPTState{Rule: observed, Effective: nativeNRPTEffective(observed, effective)}, nil
}

type nativeEffectiveNRPT struct {
	Namespace   string
	NameServers []string
	Valid       bool
}

func parseNativeEffectiveNRPT(records []rawNativeEffectiveNRPT) []nativeEffectiveNRPT {
	result := make([]nativeEffectiveNRPT, 0, len(records))
	for _, record := range records {
		entry := nativeEffectiveNRPT{}
		if record.Namespace == nil || record.NameServers == nil {
			result = append(result, entry)
			continue
		}
		entry.Namespace = *record.Namespace
		entry.Valid = validDNSNamespace(entry.Namespace) && len(*record.NameServers) > 0 && len(*record.NameServers) <= 64
		for _, value := range *record.NameServers {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" || address.Is4In6() {
				entry.Valid = false
				continue
			}
			entry.NameServers = append(entry.NameServers, address.Unmap().String())
		}
		result = append(result, entry)
	}
	return result
}

func nativeNRPTEffective(rule NRPTRule, effective []nativeEffectiveNRPT) bool {
	matches := 0
	exact := false
	for _, current := range effective {
		if !strings.EqualFold(current.Namespace, rule.Namespace) {
			continue
		}
		matches++
		exact = current.Valid && nativeNameServerSetEqual(rule.NameServers, current.NameServers)
	}
	return matches == 1 && exact
}

func nativeNameServerSetEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func reconcileNativeRegistry(raw rawNativeMutationSnapshot, snapshot MutationSnapshot, current nativeOwnershipRegistry) nativeOwnershipRegistry {
	reconciled := emptyNativeOwnershipRegistry()
	reconciled.Tombstones = append([]nativeMutationTombstone(nil), current.Tombstones...)
	for _, ownership := range current.Routes {
		present := slices.ContainsFunc(snapshot.Routes, func(observed RouteState) bool {
			return observed.Owner == ArtifactOwner && observed.Revision == ownership.Revision && observed.ManagedRoute == ownership.ManagedRoute
		})
		tombstone := nativeMutationTombstone{Kind: nativeTombstoneRoute, Route: &ownership}
		if present || containsNativeMutationTombstone(current.Tombstones, tombstone) {
			reconciled.Routes = append(reconciled.Routes, ownership)
		}
	}
	for _, ownership := range current.Firewall {
		present := slices.ContainsFunc(*raw.Firewall, func(observed rawNativeFirewallRecord) bool {
			return observed.Name != nil && observed.DisplayName != nil && observed.Description != nil && observed.Group != nil && observed.Enabled != nil && observed.Direction != nil && observed.Action != nil && observed.RemoteAddresses != nil && observed.InterfaceAliases != nil && nativeFirewallRecordMatches(observed, ownership)
		})
		removeTombstone := nativeMutationTombstone{Kind: nativeTombstoneFirewall, Firewall: &ownership}
		if nativeFirewallOwnershipPhase(ownership) != nativeFirewallPhaseApplied {
			// An absent first observation is not proof that a canceled CIM/WMI
			// provider request cannot commit later. Preserve the exact cleanup
			// intent across snapshots and reboots.
			if nativeFirewallOwnershipPhase(ownership) != nativeFirewallPhaseWatch {
				ownership.Phase = nativeFirewallPhaseCleanup
			}
			ownership.Committed = false
			ownership.State.Effective = false
			reconciled.Firewall = append(reconciled.Firewall, ownership)
			continue
		}
		if present || containsNativeMutationTombstone(current.Tombstones, removeTombstone) {
			ownership.Phase = nativeFirewallPhaseApplied
			ownership.Committed = true
			ownership.State.Effective = false
			reconciled.Firewall = append(reconciled.Firewall, ownership)
		}
	}
	for _, ownership := range current.NRPT {
		present := false
		for _, observed := range snapshot.NRPT {
			if observed.Owner != ArtifactOwner || observed.Revision != ownership.Revision || observed.Rule.LogicalID != ownership.Rule.LogicalID || !nativeNRPTObservableEqual(observed.Rule, ownership.Rule) {
				continue
			}
			ownership.Rule.Name = observed.Rule.Name
			ownership.Effective = false
			reconciled.NRPT = append(reconciled.NRPT, ownership)
			present = true
			break
		}
		if !present {
			tombstoneState := ownership
			tombstone := nativeMutationTombstone{Kind: nativeTombstoneNRPT, NRPT: &tombstoneState}
			if containsNativeMutationTombstone(current.Tombstones, tombstone) {
				reconciled.NRPT = append(reconciled.NRPT, ownership)
			}
		}
	}
	return reconciled
}

func snapshotContainsPendingNativeMutation(snapshot MutationSnapshot, raw rawNativeMutationSnapshot, registry nativeOwnershipRegistry) bool {
	for _, ownership := range registry.Firewall {
		tombstone := nativeMutationTombstone{Kind: nativeTombstoneFirewall, Firewall: &ownership}
		if nativeFirewallOwnershipPhase(ownership) == nativeFirewallPhaseApplied && !containsNativeMutationTombstone(registry.Tombstones, tombstone) {
			continue
		}
		if slices.ContainsFunc(snapshot.Firewall, func(state FirewallState) bool {
			return state.Owner == ArtifactOwner && state.Rule.Name == ownership.State.Rule.Name
		}) {
			return true
		}
		if slices.ContainsFunc(*raw.Firewall, func(record rawNativeFirewallRecord) bool {
			if record.Name == nil || record.DisplayName == nil || record.Description == nil || record.Group == nil || record.Enabled == nil || record.Direction == nil || record.Action == nil || record.RemoteAddresses == nil || record.InterfaceAliases == nil {
				return false
			}
			if nativeFirewallRecordMatches(record, ownership) {
				return true
			}
			if ownership.PreviousInterfacePattern == "" {
				return false
			}
			previous := ownership
			previous.InterfacePattern = ownership.PreviousInterfacePattern
			return nativeFirewallRecordMatches(record, previous)
		}) {
			return true
		}
	}
	for _, tombstone := range registry.Tombstones {
		switch tombstone.Kind {
		case nativeTombstoneRoute:
			if tombstone.Route != nil && slices.ContainsFunc(snapshot.Routes, func(state RouteState) bool {
				return containsNativeRouteMutationOwnership([]RouteState{state}, *tombstone.Route)
			}) {
				return true
			}
			if tombstone.Route != nil && slices.ContainsFunc(*raw.Routes, func(record rawNativeRouteRecord) bool {
				if record.Destination == nil || record.NextHop == nil || record.RouteMetric == nil || record.PolicyStore == nil || record.Protocol == nil {
					return false
				}
				store := strings.TrimSpace(*record.PolicyStore)
				return strings.TrimSpace(*record.Destination) == tombstone.Route.Destination && strings.TrimSpace(*record.NextHop) == tombstone.Route.NextHop && *record.RouteMetric == uint64(tombstone.Route.Metric) && store == tombstone.Route.PolicyStore && strings.TrimSpace(*record.Protocol) == tombstone.Route.Protocol
			}) {
				return true
			}
		case nativeTombstoneNRPT:
			if tombstone.NRPT != nil && slices.ContainsFunc(snapshot.NRPT, func(state NRPTState) bool {
				return state.Owner == ArtifactOwner && state.Revision == tombstone.NRPT.Revision && state.Rule.LogicalID == tombstone.NRPT.Rule.LogicalID
			}) {
				return true
			}
		}
	}
	return false
}

func nativeNRPTObservableEqual(left, right NRPTRule) bool {
	if left.DisplayName != right.DisplayName || left.Namespace != right.Namespace || left.Comment != right.Comment || len(left.NameServers) != len(right.NameServers) {
		return false
	}
	leftServers := append([]string(nil), left.NameServers...)
	rightServers := append([]string(nil), right.NameServers...)
	sort.Strings(leftServers)
	sort.Strings(rightServers)
	for index := range leftServers {
		if leftServers[index] != rightServers[index] {
			return false
		}
	}
	return true
}

// nativeMutationScript is fixed program text. All route, firewall, NRPT, and
// revision data arrives as bounded JSON on stdin and is passed to cmdlets as
// typed variables; none of it is interpolated into this script or argv.
const nativeMutationScript = `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

Import-Module -Name $env:HG_UTILITY_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_NETADAPTER_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_NETTCPIP_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_NETSECURITY_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_DNSCLIENT_MANIFEST -Force -ErrorAction Stop

$inputText = [Console]::In.ReadToEnd()
if ([System.Text.Encoding]::UTF8.GetByteCount($inputText) -gt 1048576) { throw 'structured input limit exceeded' }
$request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $inputText -ErrorAction Stop
if ([int]$request.version -ne 1) { throw 'unsupported request version' }

function Get-VerifiedAdapter([object]$state) {
	$expectedGuid = ([guid][string]$state.interface_guid).ToString('D').ToLowerInvariant()
	$matches = @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
		([guid]$_.InterfaceGuid).ToString('D').ToLowerInvariant() -ceq $expectedGuid
	})
	if ($matches.Count -ne 1) { throw 'stable interface GUID is absent or ambiguous' }
    return $matches[0]
}

function Get-ExactRoute([object]$state, [int]$interfaceIndex) {
	return @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop | Where-Object {
		[string]$_.DestinationPrefix -ceq [string]$state.destination -and
		[int]$_.InterfaceIndex -eq $interfaceIndex -and
		[string]$_.NextHop -ceq [string]$state.next_hop
	})
}

function Get-TombstonedRoute([object]$state) {
	$currentIndex = Resolve-RemovalInterfaceIndex $state
	return @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop | Where-Object {
		[string]$_.DestinationPrefix -ceq [string]$state.destination -and
		[int]$_.InterfaceIndex -eq $currentIndex -and
		[string]$_.NextHop -ceq [string]$state.next_hop
	})
}

function Resolve-RemovalInterfaceIndex([object]$state) {
	$adapters = @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop)
	$expectedGuid = ([guid][string]$state.interface_guid).ToString('D').ToLowerInvariant()
	$guidMatches = @($adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('D').ToLowerInvariant() -ceq $expectedGuid })
	if ($guidMatches.Count -gt 1) { throw 'stable interface GUID is ambiguous' }
	if ($guidMatches.Count -eq 1) { return [int]$guidMatches[0].ifIndex }
	$indexMatches = @($adapters | Where-Object { [int]$_.ifIndex -eq [int]$state.interface_index })
	if ($indexMatches.Count -ne 0) { throw 'missing interface index was reused by another adapter' }
	return [int]$state.interface_index
}

function Get-NamedFirewall([string]$name) {
	return @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { [string]$_.Name -ceq $name })
}

function Get-NamedEffectiveFirewall([object[]]$rules, [string]$name) {
	return @($rules | Where-Object { [string]$_.Name -ceq $name })
}

function Get-NamedNrpt([string]$name) {
	return @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { [string]$_.Name -ceq $name })
}

function Test-OwnedRouteIdentity([object]$route, [object]$state) {
	$store = [string]$route.Store
	if ([string]::IsNullOrEmpty($store)) { $store = [string]$route.PolicyStore }
	return [uint64]$route.RouteMetric -eq [uint64]$state.metric -and [string]$route.Protocol -ceq [string]$state.protocol -and $store -ceq [string]$state.policy_store -and [int]$route.State -ge 0 -and [int]$route.State -le 2
}

function Test-ExactRoute([object]$route, [object]$state) {
	return (Test-OwnedRouteIdentity $route $state) -and [int]$route.State -eq 0
}

function Test-ExactFirewall([object]$current, [object]$state, [string]$interfaceAlias, [bool]$effective) {
    $addresses = @(NetSecurity\Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
    $interfaces = @(NetSecurity\Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	$interfaceTypes = @(NetSecurity\Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	$ports = @(NetSecurity\Get-NetFirewallPortFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	$applications = @(NetSecurity\Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	$services = @(NetSecurity\Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	$security = @(NetSecurity\Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $current -ErrorAction Stop)
	if ($addresses.Count -ne 1 -or $interfaces.Count -ne 1 -or $interfaceTypes.Count -ne 1 -or $ports.Count -ne 1 -or $applications.Count -ne 1 -or $services.Count -ne 1 -or $security.Count -ne 1) { return $false }
	# StatusCode is reserved for the WMI provider and is non-zero for healthy
	# local ActiveStore rules on supported Windows builds. PrimaryStatus is the
	# documented operational health contract.
	if ($effective -and ([string]$current.PolicyStoreSourceType -cne 'Local' -or [string]$current.PolicyStoreSource -cne 'PersistentStore' -or [string]$current.PrimaryStatus -cne 'OK')) { return $false }
	$local = [string[]]@($addresses[0].LocalAddress)
    $remote = [string[]]@($addresses[0].RemoteAddress)
    $aliases = [string[]]@($interfaces[0].InterfaceAlias)
    return [string]$current.Name -ceq [string]$state.rule.name -and
        [string]$current.DisplayName -ceq [string]$state.rule.name -and
        [string]$current.Description -ceq [string]$state.rule.description -and
        [string]$current.Group -ceq [string]$state.rule.group -and
        [string]$current.Enabled -ceq 'True' -and
		[string]$current.Profile -ceq 'Any' -and
        [string]$current.Direction -ceq 'Outbound' -and
        [string]$current.Action -ceq 'Block' -and
		[string]$current.EdgeTraversalPolicy -ceq 'Block' -and
		[string]$current.LooseSourceMapping -ceq 'False' -and
		[string]$current.LocalOnlyMapping -ceq 'False' -and
		$local.Count -eq 1 -and $local[0] -ceq 'Any' -and
        $remote.Count -eq 1 -and $remote[0] -ceq [string]$state.rule.remote_cidr -and
		$aliases.Count -eq 1 -and $aliases[0] -ceq $interfaceAlias -and
		[int]$interfaceTypes[0].InterfaceType -eq 0 -and
		[string]$ports[0].Protocol -ceq 'Any' -and [string]$ports[0].LocalPort -ceq 'Any' -and [string]$ports[0].RemotePort -ceq 'Any' -and [string]$ports[0].IcmpType -ceq 'Any' -and
		[string]$applications[0].Program -ceq 'Any' -and [string]::IsNullOrEmpty([string]$applications[0].Package) -and
		[string]$services[0].Service -ceq 'Any' -and
		[int]$security[0].Authentication -eq 0 -and [int]$security[0].Encryption -eq 0 -and -not [bool]$security[0].OverrideBlockRules -and
		[string]$security[0].LocalUser -ceq 'Any' -and [string]$security[0].RemoteUser -ceq 'Any' -and [string]$security[0].RemoteMachine -ceq 'Any'
}

function Test-ExactNrpt([object]$current, [object]$state) {
    $namespaces = [string[]]@($current.Namespace)
    $left = @([string[]]@($current.NameServers) | Sort-Object)
    $right = @([string[]]@($state.rule.name_servers) | Sort-Object)
    if ($namespaces.Count -ne 1 -or $namespaces[0] -cne [string]$state.rule.namespace -or
        [string]$current.DisplayName -cne [string]$state.rule.display_name -or
        [string]$current.Comment -cne [string]$state.rule.comment -or $left.Count -ne $right.Count) { return $false }
    for ($index = 0; $index -lt $left.Count; $index++) {
        if ($left[$index] -cne $right[$index]) { return $false }
    }
    return $true
}

function Test-EffectiveNrptNamespacePresent([object[]]$rules, [string]$namespace) {
	foreach ($rule in $rules) {
		foreach ($current in [string[]]@($rule.Namespace)) {
			if ([string]$current -ieq $namespace) { return $true }
		}
	}
	return $false
}

$response = [ordered]@{ version = 1; ok = $true }
switch ([string]$request.operation) {
    'snapshot' {
        $adapterRows = [System.Collections.Generic.List[object]]::new()
        $adapterByIndex = @{}
        $adapterByName = @{}
        foreach ($adapter in @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {
            if ($adapterRows.Count -ge 256) { throw 'adapter inventory limit exceeded' }
            $row = [pscustomobject][ordered]@{
                name = [string]$adapter.Name
                description = [string]$adapter.InterfaceDescription
                interfaceIndex = [int]$adapter.ifIndex
                interfaceGuid = ([guid]$adapter.InterfaceGuid).ToString('D').ToLowerInvariant()
                hardwareInterface = [bool]$adapter.HardwareInterface
                adminStatus = [int]$adapter.InterfaceAdminStatus
                operationalStatus = [int]$adapter.InterfaceOperationalStatus
            }
            $null = $adapterRows.Add($row)
            $adapterByIndex[[int]$adapter.ifIndex] = $row
            $adapterByName[[string]$adapter.Name.ToLowerInvariant()] = $row
        }

		$compartmentRows = [System.Collections.Generic.List[object]]::new()
		foreach ($compartment in @(NetTCPIP\Get-NetCompartment -ErrorAction Stop)) {
			if ($compartmentRows.Count -ge 256) { throw 'network compartment inventory limit exceeded' }
			$null = $compartmentRows.Add([pscustomobject][ordered]@{ compartmentId = [int]$compartment.CompartmentId })
		}

        $routeRows = [System.Collections.Generic.List[object]]::new()
		foreach ($route in @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop)) {
            if ($routeRows.Count -ge 20000) { throw 'route inventory limit exceeded' }
            $store = [string]$route.Store
            if ([string]::IsNullOrEmpty($store)) { $store = [string]$route.PolicyStore }
            $null = $routeRows.Add([pscustomobject][ordered]@{
                interfaceIndex = [int]$route.InterfaceIndex
				compartmentId = [int]$route.CompartmentId
                addressFamily = [int]$route.AddressFamily
                destinationPrefix = [string]$route.DestinationPrefix
                nextHop = [string]$route.NextHop
                routeMetric = [uint64]$route.RouteMetric
                policyStore = $store
                protocol = [string]$route.Protocol
                state = [int]$route.State
            })
        }

		$effectiveRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
		$firewallBypassAbsent = $true
		foreach ($rule in @($effectiveRules | Where-Object { [string]$_.Enabled -ceq 'True' -and [string]$_.Direction -ceq 'Outbound' -and [string]$_.Action -ceq 'Allow' })) {
			$securityFilters = @(NetSecurity\Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
			if ($securityFilters.Count -ne 1) { throw 'effective outbound allow security filter is ambiguous' }
			if ([bool]$securityFilters[0].OverrideBlockRules) { $firewallBypassAbsent = $false; break }
		}
		$effectiveFirewallRows = [System.Collections.Generic.List[object]]::new()
		foreach ($ownership in @($request.firewall_expectations)) {
			$name = [string]$ownership.state.rule.name
			$expectedGuid = ([guid][string]$ownership.state.rule.interface_guid).ToString('D').ToLowerInvariant()
			$currentAdapters = @($adapterRows | Where-Object { [string]$_.interfaceGuid -ceq $expectedGuid })
			if ($currentAdapters.Count -gt 1) { throw 'stable firewall interface GUID is ambiguous' }
			$aliasStable = $currentAdapters.Count -eq 1 -and [string]$currentAdapters[0].name -ceq [string]$ownership.interface_alias
			$matches = @(Get-NamedEffectiveFirewall $effectiveRules $name)
			$exact = $aliasStable -and $matches.Count -eq 1 -and (Test-ExactFirewall $matches[0] $ownership.state ([string]$ownership.interface_pattern) $true)
			$null = $effectiveFirewallRows.Add([pscustomobject][ordered]@{ name = $name; exact = [bool]$exact })
		}

		$firewallProfileRows = [System.Collections.Generic.List[object]]::new()
		foreach ($profile in @(NetSecurity\Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
			if ($firewallProfileRows.Count -ge 3) { throw 'firewall profile inventory limit exceeded' }
			$null = $firewallProfileRows.Add([pscustomobject][ordered]@{
				name = [string]$profile.Name
				enabled = ([string]$profile.Enabled -ceq 'True')
				localRulesAllowed = ([string]$profile.AllowLocalFirewallRules -ceq 'True')
			})
		}
		$firewallServicesRunning = $true
		foreach ($serviceName in @('MpsSvc', 'BFE')) {
			$service = [System.ServiceProcess.ServiceController]::new($serviceName, '.')
			try {
				if ([string]$service.Status -cne 'Running') { $firewallServicesRunning = $false }
			} finally {
				$service.Dispose()
			}
		}

        $firewallRows = [System.Collections.Generic.List[object]]::new()
        foreach ($rule in @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)) {
            $name = [string]$rule.Name
            $group = [string]$rule.Group
            if (-not $name.StartsWith('home-gateway-', [System.StringComparison]::Ordinal) -and -not $group.StartsWith('home-gateway/windows/', [System.StringComparison]::Ordinal)) { continue }
            if ($firewallRows.Count -ge 1024) { throw 'managed firewall inventory limit exceeded' }
            $addresses = @(NetSecurity\Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $interfaces = @(NetSecurity\Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            $remote = @()
            $aliases = @()
            if ($addresses.Count -eq 1) { $remote = [string[]]@($addresses[0].RemoteAddress) }
            if ($interfaces.Count -eq 1) { $aliases = [string[]]@($interfaces[0].InterfaceAlias) }
            $null = $firewallRows.Add([pscustomobject][ordered]@{
                name = $name
                displayName = [string]$rule.DisplayName
                description = [string]$rule.Description
                group = $group
                enabled = [string]$rule.Enabled
                direction = [string]$rule.Direction
                action = [string]$rule.Action
                remoteAddresses = $remote
                interfaceAliases = $aliases
            })
        }

        $nrptRows = [System.Collections.Generic.List[object]]::new()
        foreach ($rule in @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop)) {
            foreach ($namespace in @([string[]]@($rule.Namespace))) {
                if ($nrptRows.Count -ge 10000) { throw 'NRPT inventory limit exceeded' }
                $null = $nrptRows.Add([pscustomobject][ordered]@{
                    name = [string]$rule.Name
                    displayName = [string]$rule.DisplayName
                    namespace = [string]$namespace
                    nameServers = [string[]]@($rule.NameServers)
                    comment = [string]$rule.Comment
                })
            }
        }
        $effectiveNrptRows = [System.Collections.Generic.List[object]]::new()
        foreach ($rule in @(DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)) {
            foreach ($namespace in @([string[]]@($rule.Namespace))) {
                if ($effectiveNrptRows.Count -ge 10000) { throw 'effective NRPT inventory limit exceeded' }
                $null = $effectiveNrptRows.Add([pscustomobject][ordered]@{
                    namespace = [string]$namespace
                    nameServers = [string[]]@($rule.NameServers)
                })
            }
        }
        $response.snapshot = [ordered]@{
            adapters = @($adapterRows.ToArray())
			compartments = @($compartmentRows.ToArray())
            routes = @($routeRows.ToArray())
            firewall = @($firewallRows.ToArray())
			firewallEffective = @($effectiveFirewallRows.ToArray())
			firewallProfiles = @($firewallProfileRows.ToArray())
			firewallBypassAbsent = [bool]$firewallBypassAbsent
			firewallServicesRunning = [bool]$firewallServicesRunning
            nrpt = @($nrptRows.ToArray())
            nrptEffective = @($effectiveNrptRows.ToArray())
        }
    }
	'resolve_route_interface' {
		$adapter = Get-VerifiedAdapter $request.route
		$response.interface_index = [int]$adapter.ifIndex
		if ([int]$response.interface_index -le 0) { throw 'route interface index is invalid' }
	}
	'add_route' {
		$adapter = Get-VerifiedAdapter $request.route
		$currentIndex = [int]$adapter.ifIndex
		if ($currentIndex -ne [int]$request.route.interface_index) { throw 'route interface changed after ownership commit' }
		$existing = @(Get-ExactRoute $request.route $currentIndex)
		if ($existing.Count -gt 1) { throw 'route identity is ambiguous' }
		if ($existing.Count -eq 1) {
			if (-not (Test-ExactRoute $existing[0] $request.route)) { throw 'route ownership collision' }
        } else {
			$reserved = @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop | Where-Object {
				[string]$_.DestinationPrefix -ceq [string]$request.route.destination -and
				[int]$_.InterfaceIndex -eq $currentIndex -and
				[uint64]$_.RouteMetric -eq [uint64]$request.route.metric
			})
            if ($reserved.Count -ne 0) { throw 'reserved route collision' }
            $family = if ([string]$request.route.family -ceq 'ipv4') { 'IPv4' } else { 'IPv6' }
			$null = NetTCPIP\New-NetRoute -AddressFamily $family -DestinationPrefix ([string]$request.route.destination) -InterfaceIndex ([uint32]$currentIndex) -NextHop ([string]$request.route.next_hop) -RouteMetric ([uint16]$request.route.metric) -PolicyStore ActiveStore -Protocol NetMgmt -Confirm:$false -ErrorAction Stop
			$created = @(Get-ExactRoute $request.route $currentIndex)
            if ($created.Count -ne 1 -or -not (Test-ExactRoute $created[0] $request.route)) { throw 'route post-check failed' }
        }
	}
	'remove_route' {
		$currentIndex = Resolve-RemovalInterfaceIndex $request.route
		$existing = @(Get-ExactRoute $request.route $currentIndex)
        if ($existing.Count -gt 1) { throw 'route identity is ambiguous' }
        if ($existing.Count -eq 1) {
            if (-not (Test-OwnedRouteIdentity $existing[0] $request.route)) { throw 'route ownership collision' }
			$null = NetTCPIP\Remove-NetRoute -InputObject $existing[0] -Confirm:$false -ErrorAction Stop
		}
		if (@(Get-ExactRoute $request.route $currentIndex).Count -ne 0) { throw 'route removal post-check failed' }
    }
    'resolve_firewall_interface' {
        $adapter = Get-VerifiedAdapter $request.firewall.rule
        $response.interface_alias = [string]$adapter.Name
		$response.interface_pattern = [WildcardPattern]::Escape([string]$adapter.Name)
        if ([string]::IsNullOrEmpty($response.interface_alias)) { throw 'firewall interface alias is missing' }
    }
	'resolve_firewall_batch' {
		$states = @($request.firewalls)
		if ($states.Count -lt 1 -or $states.Count -gt 256) { throw 'firewall batch count is invalid' }
		$adapters = @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop)
		if ($adapters.Count -lt 1 -or $adapters.Count -gt 256) { throw 'adapter inventory limit exceeded' }
		$seenNames = @{}
		$bindings = [System.Collections.Generic.List[object]]::new()
		foreach ($state in $states) {
			$name = [string]$state.rule.name
			if ([string]::IsNullOrEmpty($name) -or $seenNames.ContainsKey($name)) { throw 'firewall batch identity is invalid or duplicated' }
			$seenNames[$name] = $true
			$expectedGuid = ([guid][string]$state.rule.interface_guid).ToString('D').ToLowerInvariant()
			$matches = @($adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('D').ToLowerInvariant() -ceq $expectedGuid })
			if ($matches.Count -ne 1) { throw 'stable interface GUID is absent or ambiguous' }
			$alias = [string]$matches[0].Name
			if ([string]::IsNullOrEmpty($alias)) { throw 'firewall interface alias is missing' }
			$null = $bindings.Add([pscustomobject][ordered]@{
				state = $state
				interface_alias = $alias
				interface_pattern = [WildcardPattern]::Escape($alias)
				committed = $false
			})
		}
		$response.firewall_bindings = @($bindings.ToArray())
	}
	'put_firewall_batch' {
		$bindings = @($request.firewall_bindings)
		if ($bindings.Count -lt 1 -or $bindings.Count -gt 256) { throw 'firewall batch count is invalid' }
		$adapters = @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop)
		if ($adapters.Count -lt 1 -or $adapters.Count -gt 256) { throw 'adapter inventory limit exceeded' }
		$persistentRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		$seenNames = @{}
		$planned = [System.Collections.Generic.List[object]]::new()
		foreach ($binding in $bindings) {
			$state = $binding.state
			$name = [string]$state.rule.name
			$alias = [string]$binding.interface_alias
			$pattern = [string]$binding.interface_pattern
			if ([string]::IsNullOrEmpty($name) -or $seenNames.ContainsKey($name)) { throw 'firewall batch identity is invalid or duplicated' }
			$seenNames[$name] = $true
			if ([string]::IsNullOrEmpty($alias) -or [WildcardPattern]::Escape($alias) -cne $pattern) { throw 'firewall interface binding is invalid' }
			$expectedGuid = ([guid][string]$state.rule.interface_guid).ToString('D').ToLowerInvariant()
			$matches = @($adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString('D').ToLowerInvariant() -ceq $expectedGuid })
			if ($matches.Count -ne 1 -or [string]$matches[0].Name -cne $alias) { throw 'firewall interface binding changed' }
			$existing = @($persistentRules | Where-Object { [string]$_.Name -ceq $name })
			if ($existing.Count -gt 1) { throw 'firewall identity is ambiguous' }
			$update = $false
			if ($existing.Count -eq 1 -and -not (Test-ExactFirewall $existing[0] $state $pattern $false)) {
				$previousAlias = [string]$binding.previous_interface_alias
				$previousPattern = [string]$binding.previous_interface_pattern
				if ([string]::IsNullOrEmpty($previousAlias) -or [WildcardPattern]::Escape($previousAlias) -cne $previousPattern -or -not (Test-ExactFirewall $existing[0] $state $previousPattern $false)) { throw 'firewall ownership collision' }
				$update = $true
			}
			$current = $null
			if ($existing.Count -eq 1) { $current = $existing[0] }
			$null = $planned.Add([pscustomobject]@{ binding = $binding; current = $current; create = ($existing.Count -eq 0); update = $update })
		}
		foreach ($item in $planned) {
			$state = $item.binding.state
			$pattern = [string]$item.binding.interface_pattern
			if ([bool]$item.create) {
				$null = NetSecurity\New-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$state.rule.name) -DisplayName ([string]$state.rule.name) -Description ([string]$state.rule.description) -Group ([string]$state.rule.group) -Enabled True -Profile Any -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress ([string]$state.rule.remote_cidr) -Protocol Any -LocalPort Any -RemotePort Any -Program Any -Service Any -InterfaceAlias $pattern -InterfaceType Any -Confirm:$false -ErrorAction Stop
			} elseif ([bool]$item.update) {
				$null = NetSecurity\Set-NetFirewallRule -InputObject $item.current -InterfaceAlias $pattern -Confirm:$false -ErrorAction Stop
			}
		}
		$verifiedRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		foreach ($binding in $bindings) {
			$name = [string]$binding.state.rule.name
			$existing = @($verifiedRules | Where-Object { [string]$_.Name -ceq $name })
			if ($existing.Count -ne 1 -or -not (Test-ExactFirewall $existing[0] $binding.state ([string]$binding.interface_pattern) $false)) { throw 'firewall batch post-check failed' }
		}
	}
	'remove_firewall_batch' {
		$bindings = @($request.firewall_bindings)
		if ($bindings.Count -lt 1 -or $bindings.Count -gt 256) { throw 'firewall batch count is invalid' }
		$persistentRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		$seenNames = @{}
		$planned = [System.Collections.Generic.List[object]]::new()
		foreach ($binding in $bindings) {
			$state = $binding.state
			$name = [string]$state.rule.name
			$alias = [string]$binding.interface_alias
			$pattern = [string]$binding.interface_pattern
			if ([string]::IsNullOrEmpty($name) -or $seenNames.ContainsKey($name)) { throw 'firewall batch identity is invalid or duplicated' }
			$seenNames[$name] = $true
			if ([string]::IsNullOrEmpty($alias) -or [WildcardPattern]::Escape($alias) -cne $pattern) { throw 'firewall interface binding is invalid' }
			$existing = @($persistentRules | Where-Object { [string]$_.Name -ceq $name })
			if ($existing.Count -gt 1) { throw 'firewall identity is ambiguous' }
			if ($existing.Count -eq 1 -and -not (Test-ExactFirewall $existing[0] $state $pattern $false)) { throw 'firewall ownership collision' }
			if ($existing.Count -eq 1) { $null = $planned.Add($existing[0]) }
		}
		foreach ($current in $planned) {
			$null = NetSecurity\Remove-NetFirewallRule -InputObject $current -Confirm:$false -ErrorAction Stop
		}
		$remaining = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		foreach ($binding in $bindings) {
			$name = [string]$binding.state.rule.name
			if (@($remaining | Where-Object { [string]$_.Name -ceq $name }).Count -ne 0) { throw 'firewall batch removal post-check failed' }
		}
	}
	'cleanup_native_tombstones' {
		$bindings = @($request.firewall_bindings)
		$tombstones = @($request.mutation_tombstones)
		if ($bindings.Count -gt 256 -or $tombstones.Count -gt 288 -or $bindings.Count + $tombstones.Count -lt 1) { throw 'native cleanup tombstone count is invalid' }
		$persistentRules = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		$seenNames = @{}
		$plannedFirewall = [System.Collections.Generic.List[object]]::new()
		$plannedRoutes = [System.Collections.Generic.List[object]]::new()
		$plannedNrpt = [System.Collections.Generic.List[object]]::new()
		foreach ($binding in $bindings) {
			$state = $binding.state
			$name = [string]$state.rule.name
			$alias = [string]$binding.interface_alias
			$pattern = [string]$binding.interface_pattern
			if ([string]::IsNullOrEmpty($name) -or $seenNames.ContainsKey($name)) { throw 'firewall cleanup identity is invalid or duplicated' }
			$seenNames[$name] = $true
			if ([string]::IsNullOrEmpty($alias) -or [WildcardPattern]::Escape($alias) -cne $pattern) { throw 'firewall cleanup binding is invalid' }
			$existing = @($persistentRules | Where-Object { [string]$_.Name -ceq $name })
			if ($existing.Count -gt 1) { throw 'firewall cleanup identity is ambiguous' }
			if ($existing.Count -eq 1) {
				$exact = Test-ExactFirewall $existing[0] $state $pattern $false
				if (-not $exact -and -not [string]::IsNullOrEmpty([string]$binding.previous_interface_alias)) {
					$previousPattern = [string]$binding.previous_interface_pattern
					$exact = [WildcardPattern]::Escape([string]$binding.previous_interface_alias) -ceq $previousPattern -and (Test-ExactFirewall $existing[0] $state $previousPattern $false)
				}
				if (-not $exact) { throw 'firewall cleanup ownership collision' }
				$null = $plannedFirewall.Add($existing[0])
			}
		}
		foreach ($tombstone in $tombstones) {
			switch ([string]$tombstone.kind) {
				'route' {
					$state = $tombstone.route
					$existing = @(Get-TombstonedRoute $state)
					if ($existing.Count -gt 1) { throw 'route cleanup identity is ambiguous' }
					if ($existing.Count -eq 1) {
						if (-not (Test-OwnedRouteIdentity $existing[0] $state)) { throw 'route cleanup ownership collision' }
						$null = $plannedRoutes.Add($existing[0])
					}
				}
				'nrpt' {
					$state = $tombstone.nrpt
					if ([string]::IsNullOrEmpty([string]$state.rule.name)) {
						$existing = @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { Test-ExactNrpt $_ $state })
					} else {
						$existing = @(Get-NamedNrpt ([string]$state.rule.name))
					}
					if ($existing.Count -gt 1) { throw 'NRPT cleanup identity is ambiguous' }
					if ($existing.Count -eq 1) {
						if (-not (Test-ExactNrpt $existing[0] $state)) { throw 'NRPT cleanup ownership collision' }
						$null = $plannedNrpt.Add($existing[0])
					}
				}
				default { throw 'native cleanup tombstone kind is invalid' }
			}
		}
		foreach ($current in $plannedFirewall) {
			$null = NetSecurity\Remove-NetFirewallRule -InputObject $current -Confirm:$false -ErrorAction Stop
		}
		foreach ($item in $plannedRoutes) {
			$null = NetTCPIP\Remove-NetRoute -InputObject $item -Confirm:$false -ErrorAction Stop
		}
		foreach ($current in $plannedNrpt) {
			$null = DnsClient\Remove-DnsClientNrptRule -Name ([string]$current.Name) -Force -Confirm:$false -ErrorAction Stop
		}
		$remaining = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
		$effectiveNrpt = @(DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
		foreach ($binding in $bindings) {
			$name = [string]$binding.state.rule.name
			if (@($remaining | Where-Object { [string]$_.Name -ceq $name }).Count -ne 0) { throw 'firewall cleanup delayed negative verification failed' }
		}
		foreach ($tombstone in $tombstones) {
			if ([string]$tombstone.kind -ceq 'route') {
				$state = $tombstone.route
				if (@(Get-TombstonedRoute $state).Count -ne 0) { throw 'route cleanup delayed negative verification failed' }
			} elseif ([string]$tombstone.kind -ceq 'nrpt') {
				$state = $tombstone.nrpt
				if ([string]::IsNullOrEmpty([string]$state.rule.name)) {
					$remainingNrpt = @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { Test-ExactNrpt $_ $state })
				} else {
					$remainingNrpt = @(Get-NamedNrpt ([string]$state.rule.name))
				}
				if ($remainingNrpt.Count -ne 0) { throw 'NRPT cleanup delayed negative verification failed' }
				if (Test-EffectiveNrptNamespacePresent $effectiveNrpt ([string]$state.rule.namespace)) { throw 'effective NRPT cleanup delayed negative verification failed' }
			}
		}
	}
    'put_firewall' {
        $adapter = Get-VerifiedAdapter $request.firewall.rule
		if ([string]$adapter.Name -cne [string]$request.firewall_alias -or [WildcardPattern]::Escape([string]$adapter.Name) -cne [string]$request.firewall_pattern) { throw 'firewall interface alias changed' }
		$existing = @(Get-NamedFirewall ([string]$request.firewall.rule.name))
        if ($existing.Count -gt 1) { throw 'firewall identity is ambiguous' }
        if ($existing.Count -eq 0) {
			$null = NetSecurity\New-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$request.firewall.rule.name) -DisplayName ([string]$request.firewall.rule.name) -Description ([string]$request.firewall.rule.description) -Group ([string]$request.firewall.rule.group) -Enabled True -Profile Any -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress ([string]$request.firewall.rule.remote_cidr) -Protocol Any -LocalPort Any -RemotePort Any -Program Any -Service Any -InterfaceAlias ([string]$request.firewall_pattern) -InterfaceType Any -Confirm:$false -ErrorAction Stop
            $existing = @(NetSecurity\Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$request.firewall.rule.name) -ErrorAction Stop)
        }
		if ($existing.Count -ne 1 -or -not (Test-ExactFirewall $existing[0] $request.firewall ([string]$request.firewall_pattern) $false)) { throw 'firewall ownership collision or post-check failure' }
	}
	'remove_firewall' {
		$existing = @(Get-NamedFirewall ([string]$request.firewall.rule.name))
        if ($existing.Count -gt 1) { throw 'firewall identity is ambiguous' }
        if ($existing.Count -eq 1) {
			if (-not (Test-ExactFirewall $existing[0] $request.firewall ([string]$request.firewall_pattern) $false)) { throw 'firewall ownership collision' }
			$null = NetSecurity\Remove-NetFirewallRule -InputObject $existing[0] -Confirm:$false -ErrorAction Stop
		}
		if (@(Get-NamedFirewall ([string]$request.firewall.rule.name)).Count -ne 0) { throw 'firewall removal post-check failed' }
	}
	'put_nrpt' {
		$existing = @()
		if (-not [string]::IsNullOrEmpty([string]$request.nrpt.rule.name)) {
			$existing = @(Get-NamedNrpt ([string]$request.nrpt.rule.name))
        } else {
            $existing = @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { Test-ExactNrpt $_ $request.nrpt })
        }
        if ($existing.Count -gt 1) { throw 'NRPT identity is ambiguous' }
        if ($existing.Count -eq 0) {
            foreach ($current in @(DnsClient\Get-DnsClientNrptRule -ErrorAction Stop)) {
                $namespaces = [string[]]@($current.Namespace)
                if ($namespaces -contains [string]$request.nrpt.rule.namespace -and -not ([string]$current.Comment).StartsWith('home-gateway/windows;revision=', [System.StringComparison]::Ordinal)) { throw 'NRPT namespace collision' }
            }
            $created = @(DnsClient\Add-DnsClientNrptRule -Namespace ([string]$request.nrpt.rule.namespace) -NameServers ([string[]]@($request.nrpt.rule.name_servers)) -Comment ([string]$request.nrpt.rule.comment) -DisplayName ([string]$request.nrpt.rule.display_name) -PassThru -ErrorAction Stop)
            if ($created.Count -ne 1) { throw 'NRPT creation did not return one identity' }
            $existing = $created
        }
        if ($existing.Count -ne 1 -or -not (Test-ExactNrpt $existing[0] $request.nrpt)) { throw 'NRPT ownership collision or post-check failure' }
        $response.nrpt_name = [string]$existing[0].Name
        if ([string]::IsNullOrEmpty($response.nrpt_name)) { throw 'NRPT native identity is missing' }
	}
	'remove_nrpt' {
		$existing = @(Get-NamedNrpt ([string]$request.nrpt.rule.name))
        if ($existing.Count -gt 1) { throw 'NRPT identity is ambiguous' }
        if ($existing.Count -eq 1) {
            if (-not (Test-ExactNrpt $existing[0] $request.nrpt)) { throw 'NRPT ownership collision' }
			$null = DnsClient\Remove-DnsClientNrptRule -Name ([string]$request.nrpt.rule.name) -Force -Confirm:$false -ErrorAction Stop
		}
		if (@(Get-NamedNrpt ([string]$request.nrpt.rule.name)).Count -ne 0) { throw 'NRPT removal post-check failed' }
		$effective = @(DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
		if (Test-EffectiveNrptNamespacePresent $effective ([string]$request.nrpt.rule.namespace)) { throw 'effective NRPT removal post-check failed' }
    }
    'reload' {
		$null = @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop).Count
        $null = @(DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count
    }
    default { throw 'unsupported native Windows mutation operation' }
}
Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject ([pscustomobject]$response) -Compress -Depth 8`
