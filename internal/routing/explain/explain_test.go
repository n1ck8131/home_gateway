package explain

import (
	"testing"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func TestBuildMarksWinnerAndPreservesOrderedLosers(t *testing.T) {
	candidates := []contracts.DecisionEvidence{
		{EntryID: "system", Origin: contracts.OriginSystemDirect, Route: contracts.RouteClassDirect, Reason: "protected tier"},
		{EntryID: "manual", Origin: contracts.OriginManual, Route: contracts.RouteClassVPN, Reason: "manual match"},
	}

	got, err := Build(candidates, "system", "protected-tier")
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Winner || got[1].Winner {
		t.Fatalf("winner flags = %v, %v", got[0].Winner, got[1].Winner)
	}
	if got[0].Resolution != "protected-tier" || got[1].Resolution != "" {
		t.Fatalf("resolution = %q, %q", got[0].Resolution, got[1].Resolution)
	}
}

func TestBuildRejectsMissingWinner(t *testing.T) {
	_, err := Build([]contracts.DecisionEvidence{{EntryID: "one"}}, "missing", "")
	if err == nil {
		t.Fatal("Build() error = nil")
	}
}
