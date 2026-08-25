package hgctlcmd

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
)

const (
	recoveryRollbackToken = "P35-ROLLBACK"
	recoveryRecoverToken  = "P35-RECOVER"
	recoveryDisableToken  = "P35-EMERGENCY-DISABLE"
	recoveryRestoreToken  = "P35-FULL-RESTORE"
	recoveryExpireToken   = "P35-EXPIRE"
)

type canaryLiveCommand struct {
	action          string
	plan            canaryPlanCommand
	liveConfirm     string
	recoveryConfirm string
}

type canaryActionOutput struct {
	Event                 string      `json:"event"`
	Action                string      `json:"action"`
	State                 apply.State `json:"state"`
	Revision              string      `json:"revision,omitempty"`
	PendingDeadline       time.Time   `json:"pending_deadline,omitempty"`
	LiveMutationPerformed bool        `json:"live_mutation_performed"`
}

type canaryStatusOutput struct {
	State           apply.State `json:"state"`
	HasActive       bool        `json:"has_active_revision"`
	HasPending      bool        `json:"has_pending_revision"`
	PendingDeadline time.Time   `json:"pending_deadline,omitempty"`
}

type alreadyHeldOperationLocker struct{}

func (alreadyHeldOperationLocker) Lock(ctx context.Context) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return func() error { return nil }, nil
}

func parseCanaryLiveCommand(args []string) (canaryLiveCommand, bool) {
	if len(args) < 5 || args[0] != "windows" || args[1] != "canary" {
		return canaryLiveCommand{}, false
	}
	command := canaryLiveCommand{action: args[2]}
	allowedAction := slices.Contains([]string{"apply", "confirm", "rollback", "recover", "emergency-disable", "full-restore", "expire", "status"}, command.action)
	if !allowedAction {
		return canaryLiveCommand{}, false
	}
	seen := make(map[string]bool)
	jsonOutput := false
	for index := 3; index < len(args); {
		name := args[index]
		if name == "--json" {
			if jsonOutput || index != len(args)-1 {
				return canaryLiveCommand{}, false
			}
			jsonOutput = true
			index++
			continue
		}
		if index+1 >= len(args) || args[index+1] == "" {
			return canaryLiveCommand{}, false
		}
		value := args[index+1]
		if name != "--target" && seen[name] {
			return canaryLiveCommand{}, false
		}
		seen[name] = true
		switch name {
		case "--config":
			command.plan.configPath = value
		case "--config-sha256":
			command.plan.configSHA256 = value
		case "--state-root":
			command.plan.stateRoot = value
		case "--revision":
			command.plan.revision = value
		case "--target":
			command.plan.targets = append(command.plan.targets, value)
		case "--dns-namespace":
			command.plan.dnsNamespace = value
		case "--confirm-live":
			command.liveConfirm = value
		case "--confirm-recovery":
			command.recoveryConfirm = value
		default:
			return canaryLiveCommand{}, false
		}
		index += 2
	}
	if !jsonOutput || command.plan.stateRoot == "" {
		return canaryLiveCommand{}, false
	}
	switch command.action {
	case "apply", "confirm":
		if command.plan.configPath == "" || !lowercaseSHA256Pattern.MatchString(command.plan.configSHA256) || command.plan.revision == "" || command.plan.dnsNamespace == "" || len(command.plan.targets) == 0 || command.liveConfirm == "" || command.recoveryConfirm != "" {
			return canaryLiveCommand{}, false
		}
	case "rollback", "recover", "emergency-disable", "full-restore", "expire":
		if command.recoveryConfirm == "" || command.liveConfirm != "" || command.plan.configPath != "" || command.plan.configSHA256 != "" || command.plan.revision != "" || command.plan.dnsNamespace != "" || len(command.plan.targets) != 0 {
			return canaryLiveCommand{}, false
		}
	case "status":
		if command.liveConfirm != "" || command.recoveryConfirm != "" || command.plan.configPath != "" || command.plan.configSHA256 != "" || command.plan.revision != "" || command.plan.dnsNamespace != "" || len(command.plan.targets) != 0 {
			return canaryLiveCommand{}, false
		}
	}
	return command, true
}

func runCanaryLive(command canaryLiveCommand, stdout, stderr io.Writer, dependencies dependencies) int {
	if dependencies.validateStateRoot == nil {
		fmt.Fprintln(stderr, "Windows canary state-root validator is unavailable")
		return 1
	}
	if err := dependencies.validateStateRoot(command.plan.stateRoot); err != nil {
		fmt.Fprintln(stderr, "Windows canary state root blocked:", err)
		return 3
	}
	isRecovery := slices.Contains([]string{"rollback", "recover", "emergency-disable", "full-restore", "expire"}, command.action)
	if isRecovery {
		expected := map[string]string{
			"rollback":          recoveryRollbackToken,
			"recover":           recoveryRecoverToken,
			"emergency-disable": recoveryDisableToken,
			"full-restore":      recoveryRestoreToken,
			"expire":            recoveryExpireToken,
		}[command.action]
		if !equalConfirmation(command.recoveryConfirm, expected) {
			fmt.Fprintln(stderr, "recovery confirmation token does not match the requested action")
			return 2
		}
		if _, err := os.Lstat(command.plan.stateRoot); errors.Is(err, os.ErrNotExist) {
			return encodeJSON(stdout, stderr, canaryActionOutput{Event: "resolved", Action: command.action, State: apply.StateIdle, LiveMutationPerformed: false})
		} else if err != nil {
			fmt.Fprintln(stderr, "Windows canary recovery root failed:", err)
			return 1
		}
	}
	if command.action == "status" {
		return runCanaryStatus(command.plan.stateRoot, stdout, stderr)
	}
	if dependencies.newMutation == nil {
		fmt.Fprintln(stderr, "native Windows mutation backend is unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if command.action == "apply" || command.action == "confirm" {
		if dependencies.validateConfigSource == nil {
			fmt.Fprintln(stderr, "RedShield config source validator is unavailable")
			return 1
		}
		if dependencies.validateLiveConfig != nil {
			if err := dependencies.validateLiveConfig(command.plan.configPath, command.plan.configSHA256); err != nil {
				fmt.Fprintln(stderr, "installed RedShield config blocked:", err)
				return 3
			}
		}
		plan, errorCode, err := collectCanaryPlan(ctx, command.plan, dependencies)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return errorCode
		}
		challenge := plan.ConfirmationChallenge(command.plan.stateRoot)
		if !equalConfirmation(command.liveConfirm, challenge) {
			fmt.Fprintln(stderr, "live confirmation challenge does not match the exact canary candidate")
			return 2
		}
		tx, err := newLiveCanaryTransaction(command.plan.stateRoot, plan.QualifiedEndpoints, dependencies)
		if err != nil {
			fmt.Fprintln(stderr, "native Windows canary initialization failed:", err)
			return 1
		}
		if command.action == "confirm" {
			if err := tx.ConfirmCandidate(ctx, plan.Candidate); err != nil {
				fmt.Fprintln(stderr, "Windows canary confirmation failed:", err)
				return 1
			}
			return encodeCanaryJournalEvent(stdout, stderr, "resolved", command.action, command.plan.stateRoot, true)
		}
		applyContext, applyCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer applyCancel()
		if err := tx.Apply(applyContext, plan.Candidate); err != nil {
			fmt.Fprintln(stderr, "Windows canary apply failed:", err)
			return 1
		}
		return waitForCanaryResolution(tx, command.plan.stateRoot, stdout, stderr)
	}

	recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer recoveryCancel()
	release, err := (apply.FileLocker{Path: filepath.Join(command.plan.stateRoot, "operation.lock")}).Lock(recoveryContext)
	if err != nil {
		fmt.Fprintln(stderr, "Windows canary recovery lock failed:", err)
		return 1
	}
	store := apply.FileJournal{Path: filepath.Join(command.plan.stateRoot, "journal.json")}
	journal, err := store.Load()
	if err != nil {
		_ = release()
		fmt.Fprintln(stderr, "Windows canary recovery journal failed:", err)
		return 1
	}
	mutated := false
	if journal.State == apply.StateIdle || journal.State == apply.StateRestored || journal.State == apply.StateRolledBack && journal.ActiveRevision == "" && journal.LastKnownGoodRevision == "" {
		err = disarmCanaryWatchdog(command.plan.stateRoot, dependencies)
	} else {
		var tx *apply.Transaction
		tx, err = newRecoveryTransactionLocked(command.plan.stateRoot, journal, dependencies)
		if err == nil {
			tx.Locker = alreadyHeldOperationLocker{}
			mutated = true
			switch command.action {
			case "rollback":
				err = tx.Rollback(recoveryContext)
			case "recover":
				err = tx.Recover(recoveryContext)
			case "emergency-disable":
				err = tx.EmergencyDisable(recoveryContext)
			case "full-restore":
				err = tx.FullRestore(recoveryContext)
			case "expire":
				err = tx.Expire(recoveryContext)
			}
		}
	}
	if err == nil {
		if code := encodeCanaryJournalEvent(stdout, stderr, "resolved", command.action, command.plan.stateRoot, mutated); code != 0 {
			err = errors.New("encode Windows canary recovery result")
		}
	}
	err = errors.Join(err, release())
	if err != nil {
		fmt.Fprintln(stderr, "Windows canary recovery action failed:", err)
		return 1
	}
	return 0
}

func disarmCanaryWatchdog(root string, dependencies dependencies) error {
	if dependencies.watchdog != nil {
		if persistent, ok := dependencies.watchdog.(apply.PersistentWatchdog); ok {
			return persistent.Disarm()
		}
		return nil
	}
	return windowssystem.DisarmProductionCanaryWatchdog(root)
}

func newLiveCanaryTransaction(root string, endpoints []string, dependencies dependencies) (*apply.Transaction, error) {
	backend, err := dependencies.newMutation(root)
	if err != nil {
		return nil, err
	}
	return windowssystem.NewCanaryTransaction(windowssystem.CanaryRuntimeConfig{
		Root:               root,
		Backend:            backend,
		QualifiedEndpoints: endpoints,
		Watchdog:           dependencies.watchdog,
	})
}

func newRecoveryTransactionLocked(root string, journal apply.Journal, dependencies dependencies) (*apply.Transaction, error) {
	revision := journal.LastKnownGoodRevision
	if revision == "" {
		revision = journal.ActiveRevision
	}
	var endpoints []string
	var err error
	if revision != "" {
		endpoints, err = windowssystem.LoadQualifiedEndpoints(root, []string{revision})
		if err != nil {
			return nil, err
		}
	}
	backend, err := dependencies.newMutation(root)
	if err != nil {
		return nil, err
	}
	return windowssystem.NewCanaryTransaction(windowssystem.CanaryRuntimeConfig{
		Root:               root,
		Backend:            backend,
		QualifiedEndpoints: endpoints,
		RecoveryOnly:       true,
		Watchdog:           dependencies.watchdog,
	})
}

func waitForCanaryResolution(tx *apply.Transaction, root string, stdout, stderr io.Writer) int {
	store := apply.FileJournal{Path: filepath.Join(root, "journal.json")}
	journal, err := store.Load()
	if err != nil {
		fmt.Fprintln(stderr, "load pending canary journal failed:", err)
		return 1
	}
	stopAt := journal.PendingDeadline.Add(tx.RecoveryTimeout + 10*time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		journal, err = store.Load()
		if err != nil {
			fmt.Fprintln(stderr, "poll canary journal failed:", err)
			return 1
		}
		if journal.State != apply.StatePending {
			if code := encodeCanaryJournalEvent(stdout, stderr, "resolved", "apply", root, true); code != 0 {
				return code
			}
			if journal.State == apply.StateCommitted {
				return 0
			}
			return 4
		}
		if time.Now().After(stopAt) {
			fmt.Fprintln(stderr, "canary watchdog did not resolve the pending revision")
			return 1
		}
		<-ticker.C
	}
}

func runCanaryStatus(root string, stdout, stderr io.Writer) int {
	journal, err := (apply.FileJournal{Path: filepath.Join(root, "journal.json")}).Load()
	if err != nil {
		fmt.Fprintln(stderr, "Windows canary status failed:", err)
		return 1
	}
	return encodeJSON(stdout, stderr, canaryStatusOutput{
		State:           journal.State,
		HasActive:       journal.ActiveRevision != "",
		HasPending:      journal.PendingRevision != "",
		PendingDeadline: journal.PendingDeadline,
	})
}

func encodeCanaryJournalEvent(stdout, stderr io.Writer, event, action, root string, mutated bool) int {
	journal, err := (apply.FileJournal{Path: filepath.Join(root, "journal.json")}).Load()
	if err != nil {
		fmt.Fprintln(stderr, "load Windows canary journal failed:", err)
		return 1
	}
	revision := journal.ActiveRevision
	if journal.PendingRevision != "" {
		revision = journal.PendingRevision
	}
	return encodeJSON(stdout, stderr, canaryActionOutput{
		Event:                 event,
		Action:                action,
		State:                 journal.State,
		Revision:              revision,
		PendingDeadline:       journal.PendingDeadline,
		LiveMutationPerformed: mutated,
	})
}

func equalConfirmation(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
