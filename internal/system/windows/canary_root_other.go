//go:build !windows

package windows

import "errors"

func ProductionCanaryStateRoot() (string, error) {
	return "", errors.New("P3.5 production state root requires Windows")
}

func ValidateProductionCanaryStateRoot(string) error {
	return errors.New("P3.5 production state root requires Windows")
}

func ValidateProductionCanaryPlanRoot(string) error {
	return errors.New("P3.5 production state root requires Windows")
}

func ValidateProductionCanaryStateAccessRoot(string) error {
	return errors.New("P3.5 production state root requires Windows")
}
