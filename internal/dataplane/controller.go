package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/vsevo/home-gateway/internal/dns/dnsmasq"
	"github.com/vsevo/home-gateway/internal/revisions/apply"
	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

type transaction interface {
	Apply(context.Context, apply.Candidate) error
	Confirm() error
	Rollback(context.Context) error
	Recover(context.Context) error
}

type RuntimeInventory struct {
	NFT    nft.Inventory
	IPRule iprule.Inventory
}

type ApplyRequest struct {
	RevisionID string
	Plan       contracts.PolicyPlan
	Inventory  RuntimeInventory
	DNSOptions dnsmasq.Options
}

type Controller struct {
	transaction transaction
}

func NewController(tx transaction) (*Controller, error) {
	if tx == nil {
		return nil, errors.New("dataplane transaction is required")
	}
	return &Controller{transaction: tx}, nil
}

func (controller *Controller) BuildCandidate(request ApplyRequest) (apply.Candidate, error) {
	if controller == nil || controller.transaction == nil {
		return apply.Candidate{}, errors.New("dataplane controller is not initialized")
	}
	nftArtifact, err := nft.Render(request.Plan, request.Inventory.NFT)
	if err != nil {
		return apply.Candidate{}, fmt.Errorf("render nftables: %w", err)
	}
	routeArtifact, err := iprule.Render(request.Plan, request.Inventory.IPRule)
	if err != nil {
		return apply.Candidate{}, fmt.Errorf("render policy routing: %w", err)
	}
	dnsArtifact, err := dnsmasq.Render(request.Plan, request.DNSOptions)
	if err != nil {
		return apply.Candidate{}, fmt.Errorf("render dnsmasq: %w", err)
	}
	return apply.Candidate{
		RevisionID: request.RevisionID,
		NFT:        nftArtifact,
		DNS:        dnsArtifact,
		Routes:     routeArtifact,
	}, nil
}

func (controller *Controller) Apply(ctx context.Context, request ApplyRequest) error {
	candidate, err := controller.BuildCandidate(request)
	if err != nil {
		return err
	}
	if err := controller.transaction.Apply(ctx, candidate); err != nil {
		return fmt.Errorf("apply dataplane revision %q: %w", request.RevisionID, err)
	}
	return nil
}

func (controller *Controller) Confirm() error {
	if controller == nil || controller.transaction == nil {
		return errors.New("dataplane controller is not initialized")
	}
	if err := controller.transaction.Confirm(); err != nil {
		return fmt.Errorf("confirm dataplane revision: %w", err)
	}
	return nil
}

func (controller *Controller) Rollback(ctx context.Context) error {
	if controller == nil || controller.transaction == nil {
		return errors.New("dataplane controller is not initialized")
	}
	if err := controller.transaction.Rollback(ctx); err != nil {
		return fmt.Errorf("roll back dataplane revision: %w", err)
	}
	return nil
}

func (controller *Controller) Recover(ctx context.Context) error {
	if controller == nil || controller.transaction == nil {
		return errors.New("dataplane controller is not initialized")
	}
	if err := controller.transaction.Recover(ctx); err != nil {
		return fmt.Errorf("recover dataplane: %w", err)
	}
	return nil
}
