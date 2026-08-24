package servers

import (
	"context"
	"errors"
	"fmt"
)

type CurrentState struct {
	Digest      string
	SSHHardened bool
}

type DeploymentRequest struct {
	UpgradeIntent         bool
	HardenSSH             bool
	RecoveryAccountProven bool
}

type DeploymentResult struct {
	Status string
	State  CurrentState
}

type DeploymentSnapshot struct {
	PreviousState CurrentState
	RecoveryID    string
}

type DeploymentRuntime interface {
	CurrentState(context.Context) (CurrentState, error)
	Preflight(context.Context, Bundle) error
	Stage(context.Context, Bundle) error
	Snapshot(context.Context, Bundle) (DeploymentSnapshot, error)
	Validate(context.Context, Bundle) error
	Activate(context.Context, Bundle) error
	PostCheck(context.Context, Bundle) error
	VerifyRecoveryAccess(context.Context, Bundle) error
	HardenSSH(context.Context, Bundle) error
	Commit(context.Context, Bundle, CurrentState) error
	Restore(context.Context, DeploymentSnapshot) error
}

type DeploymentEngine struct {
	Runtime DeploymentRuntime
}

func (engine DeploymentEngine) Apply(ctx context.Context, bundle Bundle, request DeploymentRequest) (DeploymentResult, error) {
	if engine.Runtime == nil {
		return DeploymentResult{}, errors.New("deployment runtime is required")
	}
	if bundle.SanitizedExample {
		return DeploymentResult{}, errors.New("sanitized example bundle is not deployable")
	}
	sealedBundle, err := bundle.deploymentCopy()
	if err != nil {
		return DeploymentResult{}, err
	}
	bundle = sealedBundle
	if bundle.digest == "" {
		return DeploymentResult{}, errors.New("verified bundle digest is required")
	}
	if !bundle.artifactsVerified {
		return DeploymentResult{}, errors.New("verified bundle artifacts are required")
	}
	if request.HardenSSH && !request.RecoveryAccountProven {
		return DeploymentResult{}, errors.New("recovery_account_proven is required before SSH hardening")
	}
	current, err := engine.Runtime.CurrentState(ctx)
	if err != nil {
		return DeploymentResult{}, fmt.Errorf("current state: %w", err)
	}
	desired := CurrentState{Digest: bundle.digest, SSHHardened: current.SSHHardened || request.HardenSSH}
	if current.Digest == bundle.digest {
		if !request.HardenSSH || current.SSHHardened {
			return DeploymentResult{Status: "noop", State: current}, nil
		}
		return engine.hardenCurrent(ctx, bundle, current, desired)
	}
	if current.Digest != "" && !request.UpgradeIntent {
		return DeploymentResult{}, errors.New("explicit upgrade intent is required for a digest change")
	}
	if err := engine.Runtime.Preflight(ctx, bundle); err != nil {
		return DeploymentResult{}, fmt.Errorf("preflight: %w", err)
	}
	snapshot := DeploymentSnapshot{PreviousState: current}
	captured, err := engine.Runtime.Snapshot(ctx, bundle)
	if err != nil {
		return DeploymentResult{}, fmt.Errorf("snapshot: %w", err)
	}
	snapshot = mergeSnapshot(snapshot, captured)
	if snapshot.RecoveryID == "" {
		return DeploymentResult{}, errors.New("snapshot: snapshot recovery ID is required")
	}
	if err := engine.Runtime.Stage(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "stage", err)
	}
	if err := engine.Runtime.Validate(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "validate", err)
	}
	if err := engine.Runtime.Activate(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "activate", err)
	}
	if err := engine.Runtime.PostCheck(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "postcheck", err)
	}
	if request.HardenSSH {
		if err := engine.Runtime.VerifyRecoveryAccess(ctx, bundle); err != nil {
			return DeploymentResult{}, engine.compensate(ctx, snapshot, "recovery access", err)
		}
		if err := engine.Runtime.HardenSSH(ctx, bundle); err != nil {
			return DeploymentResult{}, engine.compensate(ctx, snapshot, "ssh harden", err)
		}
	}
	if err := engine.Runtime.Commit(ctx, bundle, desired); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "commit", err)
	}
	status := "installed"
	if current.Digest != "" {
		status = "upgraded"
	}
	if request.HardenSSH {
		status = status + "+hardened"
	}
	return DeploymentResult{Status: status, State: desired}, nil
}

func (engine DeploymentEngine) hardenCurrent(ctx context.Context, bundle Bundle, current, desired CurrentState) (DeploymentResult, error) {
	if err := engine.Runtime.Preflight(ctx, bundle); err != nil {
		return DeploymentResult{}, fmt.Errorf("preflight: %w", err)
	}
	snapshot := DeploymentSnapshot{PreviousState: current}
	captured, err := engine.Runtime.Snapshot(ctx, bundle)
	if err != nil {
		return DeploymentResult{}, fmt.Errorf("snapshot: %w", err)
	}
	snapshot = mergeSnapshot(snapshot, captured)
	if snapshot.RecoveryID == "" {
		return DeploymentResult{}, errors.New("snapshot: snapshot recovery ID is required")
	}
	if err := engine.Runtime.VerifyRecoveryAccess(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "recovery access", err)
	}
	if err := engine.Runtime.HardenSSH(ctx, bundle); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "ssh harden", err)
	}
	if err := engine.Runtime.Commit(ctx, bundle, desired); err != nil {
		return DeploymentResult{}, engine.compensate(ctx, snapshot, "commit", err)
	}
	return DeploymentResult{Status: "hardened", State: desired}, nil
}

func mergeSnapshot(fallback, captured DeploymentSnapshot) DeploymentSnapshot {
	if captured.PreviousState.Digest == "" && !captured.PreviousState.SSHHardened {
		captured.PreviousState = fallback.PreviousState
	}
	return captured
}

func (engine DeploymentEngine) compensate(ctx context.Context, snapshot DeploymentSnapshot, boundary string, cause error) error {
	err := engine.Runtime.Restore(ctx, snapshot)
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %w", boundary, cause), fmt.Errorf("compensation: %w", err))
	}
	return fmt.Errorf("%s: %w", boundary, cause)
}
