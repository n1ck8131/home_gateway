//go:build !windows

package windows

import "errors"

func ValidateProductionCanaryConfigSource(string) error {
	return errors.New("P3.5 production config source requires Windows")
}

func ValidateProductionCanaryInstalledConfigSource(string, string) error {
	return errors.New("P3.5 installed production config source requires Windows")
}

func configACLIdentity(string) (string, error) {
	return "", errors.New("P3.5 config ACL identity requires Windows")
}
