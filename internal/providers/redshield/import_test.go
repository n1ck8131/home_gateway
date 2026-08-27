package redshield

import "testing"

func TestCompatibilityWrapperUsesRedShieldProviderID(t *testing.T) {
	if _, err := ImportFile("relative.conf"); err == nil {
		t.Fatal("compatibility wrapper accepted an unsafe path")
	}
}
