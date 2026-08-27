package selfhosted

import "testing"

func TestBackendIsInspectionOnly(t *testing.T) {
	capabilities := (Backend{}).Capabilities()
	if !capabilities.InspectConfig || capabilities.ApplyConfig || capabilities.ServerManagement {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}
