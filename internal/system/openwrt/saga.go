package openwrt

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const MaxTunnelHandshakeAge = 3 * time.Minute

type Runtime interface {
	ApplyPolicy(context.Context, PolicyState) error
	Snapshot(context.Context, SnapshotRequest) (UCISnapshot, error)
	Run(context.Context, Operation) error
	Restore(context.Context, UCISnapshot) error
	CheckTunnel(context.Context, TunnelCheck) (TunnelStatus, error)
}

type PolicyState struct {
	DesiredState    contracts.DesiredState
	IPRuleInventory iprule.Inventory
	ServerAvailable bool
}

type SnapshotRequest struct {
	Interface      string
	Peer           string
	ExpectedDigest string
}

type UCISnapshot struct {
	Interface     string
	Peer          string
	CurrentDigest string
	RecoveryID    string
}

type TunnelCheck struct {
	Interface string
	ServerID  string
}

type TunnelStatus struct {
	InterfaceUp        bool
	HandshakeObserved  bool
	LatestHandshakeAge time.Duration
	ConsecutiveSuccess int
	DNSOK              bool
	TLSOK              bool
	TunnelEgressIP     string
	WANEgressIP        string
}

type SagaResult struct {
	Plan            OperationPlan
	ServerAvailable bool
	IPRuleInventory iprule.Inventory
}

func ApplyPeer(ctx context.Context, spec PeerSpec, evaluationTime time.Time, runtime Runtime) (SagaResult, error) {
	if runtime == nil {
		return SagaResult{}, errors.New("OpenWrt runtime is required")
	}
	plan, err := BuildOperationPlan(spec)
	if err != nil {
		return SagaResult{}, err
	}
	failClosed, err := buildPolicyState(spec, evaluationTime, false)
	if err != nil {
		return SagaResult{}, err
	}
	result := SagaResult{Plan: plan, IPRuleInventory: failClosed.IPRuleInventory}
	if err := runtime.ApplyPolicy(ctx, failClosed); err != nil {
		return result, fmt.Errorf("publish fail-closed policy before OpenWrt peer activation: %w", err)
	}
	snapshot, err := runtime.Snapshot(ctx, SnapshotRequest{
		Interface:      spec.UCIInterface,
		Peer:           spec.UCIPeer,
		ExpectedDigest: plan.Digest,
	})
	if err != nil {
		return result, fmt.Errorf("snapshot OpenWrt peer state: %w", err)
	}
	if snapshot.RecoveryID == "" {
		return result, errors.New("snapshot OpenWrt peer state: recovery ID is required")
	}
	if err := runtime.Run(ctx, plan.Operations[0]); err != nil {
		return result, fmt.Errorf("openwrt operation %q: %w", plan.Operations[0].Name, err)
	}
	for _, operation := range plan.Operations[1:] {
		if err := runtime.Run(ctx, operation); err != nil {
			return result, failClosedRestore(ctx, runtime, snapshot, failClosed, fmt.Errorf("openwrt operation %q: %w", operation.Name, err))
		}
	}
	return finishHealthy(ctx, spec, evaluationTime, runtime, result, snapshot, failClosed)
}

func finishHealthy(
	ctx context.Context,
	spec PeerSpec,
	evaluationTime time.Time,
	runtime Runtime,
	result SagaResult,
	snapshot UCISnapshot,
	failClosed PolicyState,
) (SagaResult, error) {
	status, err := runtime.CheckTunnel(ctx, TunnelCheck{Interface: spec.Interface, ServerID: spec.ServerID})
	if err != nil {
		return result, failClosedRestore(ctx, runtime, snapshot, failClosed, fmt.Errorf("check tunnel health: %w", err))
	}
	if err := status.Validate(); err != nil {
		return result, failClosedRestore(ctx, runtime, snapshot, failClosed, fmt.Errorf("tunnel health check failed: %w", err))
	}
	available, err := buildPolicyState(spec, evaluationTime, true)
	if err != nil {
		return result, failClosedRestore(ctx, runtime, snapshot, failClosed, err)
	}
	if err := runtime.ApplyPolicy(ctx, available); err != nil {
		return result, failClosedRestore(ctx, runtime, snapshot, failClosed, fmt.Errorf("publish healthy policy: %w", err))
	}
	result.ServerAvailable = true
	result.IPRuleInventory = available.IPRuleInventory
	return result, nil
}

func (status TunnelStatus) Validate() error {
	if !status.InterfaceUp {
		return errors.New("interface is not up")
	}
	if !status.HandshakeObserved {
		return errors.New("fresh handshake was not observed")
	}
	if status.LatestHandshakeAge < 0 || status.LatestHandshakeAge > MaxTunnelHandshakeAge {
		return errors.New("latest handshake is stale")
	}
	if status.ConsecutiveSuccess < 2 {
		return errors.New("tunnel health requires two consecutive successful probes")
	}
	if !status.DNSOK {
		return errors.New("DNS probe failed through the tunnel")
	}
	if !status.TLSOK {
		return errors.New("TLS probe failed through the tunnel")
	}
	tunnelEgress, err := netip.ParseAddr(status.TunnelEgressIP)
	if err != nil || !publicEndpointIP(tunnelEgress) {
		return errors.New("tunnel egress IP is invalid")
	}
	wanEgress, err := netip.ParseAddr(status.WANEgressIP)
	if err != nil || !publicEndpointIP(wanEgress) {
		return errors.New("WAN egress IP is invalid")
	}
	if tunnelEgress.Unmap() == wanEgress.Unmap() {
		return errors.New("tunnel egress must differ from WAN egress")
	}
	return nil
}

func buildPolicyState(spec PeerSpec, evaluationTime time.Time, available bool) (PolicyState, error) {
	state, err := spec.DesiredState(evaluationTime)
	if err != nil {
		return PolicyState{}, err
	}
	inventory, err := IPRuleInventory(spec, available)
	if err != nil {
		return PolicyState{}, err
	}
	return PolicyState{DesiredState: state, IPRuleInventory: inventory, ServerAvailable: available}, nil
}

func failClosedRestore(ctx context.Context, runtime Runtime, snapshot UCISnapshot, failClosed PolicyState, cause error) error {
	restoreErr := runtime.Restore(ctx, snapshot)
	policyErr := runtime.ApplyPolicy(ctx, failClosed)
	if restoreErr != nil || policyErr != nil {
		return errors.Join(cause, restoreErr, policyErr)
	}
	return cause
}
