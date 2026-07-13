package explain

import (
	"errors"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

func Build(candidates []contracts.DecisionEvidence, winnerID, resolution string) ([]contracts.DecisionEvidence, error) {
	result := make([]contracts.DecisionEvidence, len(candidates))
	copy(result, candidates)
	found := false
	for i := range result {
		result[i].Winner = result[i].EntryID == winnerID
		result[i].Resolution = ""
		if result[i].Winner {
			if found {
				return nil, errors.New("winner appears more than once")
			}
			found = true
			result[i].Resolution = resolution
		}
	}
	if !found {
		return nil, errors.New("winner is missing from explanation candidates")
	}
	return result, nil
}
