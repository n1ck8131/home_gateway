package dataplane

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/dns/dnsmasq"
	"github.com/vsevo/home-gateway/internal/revisions/apply"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestControllerApplyBuildsOneCandidate(t *testing.T) {
	t.Parallel()

	transaction := &fakeTransaction{}
	controller, err := NewController(transaction)
	if err != nil {
		t.Fatalf("NewController() error = %v", err)
	}
	request := ApplyRequest{
		RevisionID: "revision-001",
		Plan: contracts.PolicyPlan{
			EvaluationTime: time.Unix(1_700_000_000, 0).UTC(),
		},
	}

	if err := controller.Apply(context.Background(), request); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if transaction.applyCalls != 1 {
		t.Fatalf("transaction Apply() calls = %d, want 1", transaction.applyCalls)
	}
	if transaction.candidate.RevisionID != request.RevisionID {
		t.Fatalf("candidate revision = %q, want %q", transaction.candidate.RevisionID, request.RevisionID)
	}
	for name, artifact := range map[string][]byte{
		"nft":    transaction.candidate.NFT,
		"dns":    transaction.candidate.DNS,
		"routes": transaction.candidate.Routes,
	} {
		if len(artifact) == 0 {
			t.Fatalf("candidate %s artifact is empty", name)
		}
	}
	if !bytes.Contains(transaction.candidate.NFT, []byte("table inet routerd")) {
		t.Fatalf("candidate nft artifact does not own the routerd table: %s", transaction.candidate.NFT)
	}
}

func TestControllerApplyDoesNotMutateWhenRenderFails(t *testing.T) {
	t.Parallel()

	transaction := &fakeTransaction{}
	controller, err := NewController(transaction)
	if err != nil {
		t.Fatalf("NewController() error = %v", err)
	}
	request := ApplyRequest{
		RevisionID: "revision-002",
		Plan: contracts.PolicyPlan{
			EvaluationTime: time.Unix(1_700_000_000, 0).UTC(),
			Entries: []contracts.RouteEntry{{
				ID:      "exact-domain",
				Pattern: "example.com",
				Kind:    contracts.EntryKindDomain,
				Match:   contracts.DomainMatchExact,
				Route:   contracts.RouteClassDirect,
				Scope:   contracts.Scope{Type: contracts.ScopeGlobal},
				Origin:  contracts.OriginManual,
			}},
		},
		DNSOptions: dnsmasq.Options{},
	}

	err = controller.Apply(context.Background(), request)
	if err == nil {
		t.Fatal("Apply() error = nil, want unsupported exact-match error")
	}
	if transaction.applyCalls != 0 {
		t.Fatalf("transaction Apply() calls = %d, want 0", transaction.applyCalls)
	}
}

func TestControllerDelegatesLifecycleOperations(t *testing.T) {
	t.Parallel()

	want := errors.New("sentinel")
	transaction := &fakeTransaction{
		confirmErr:  want,
		rollbackErr: want,
		recoverErr:  want,
	}
	controller, err := NewController(transaction)
	if err != nil {
		t.Fatalf("NewController() error = %v", err)
	}

	if err := controller.Confirm(); !errors.Is(err, want) {
		t.Fatalf("Confirm() error = %v, want sentinel", err)
	}
	if err := controller.Rollback(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Rollback() error = %v, want sentinel", err)
	}
	if err := controller.Recover(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Recover() error = %v, want sentinel", err)
	}
	if transaction.confirmCalls != 1 || transaction.rollbackCalls != 1 || transaction.recoverCalls != 1 {
		t.Fatalf(
			"lifecycle calls = confirm:%d rollback:%d recover:%d, want one each",
			transaction.confirmCalls,
			transaction.rollbackCalls,
			transaction.recoverCalls,
		)
	}
}

func TestNewControllerRejectsNilTransaction(t *testing.T) {
	t.Parallel()

	if _, err := NewController(nil); err == nil {
		t.Fatal("NewController(nil) error = nil, want error")
	}
}

type fakeTransaction struct {
	applyCalls    int
	confirmCalls  int
	rollbackCalls int
	recoverCalls  int
	candidate     apply.Candidate
	applyErr      error
	confirmErr    error
	rollbackErr   error
	recoverErr    error
}

func (transaction *fakeTransaction) Apply(_ context.Context, candidate apply.Candidate) error {
	transaction.applyCalls++
	transaction.candidate = candidate
	return transaction.applyErr
}

func (transaction *fakeTransaction) Confirm() error {
	transaction.confirmCalls++
	return transaction.confirmErr
}

func (transaction *fakeTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeTransaction) Recover(context.Context) error {
	transaction.recoverCalls++
	return transaction.recoverErr
}
