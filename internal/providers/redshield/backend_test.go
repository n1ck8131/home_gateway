package redshield

import (
	"context"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestBackendIsReadOnlyAndServerManagementIsUnavailable(t *testing.T) {
	backend := Backend{}
	capabilities := backend.Capabilities()
	if !capabilities.InspectConfig || capabilities.ObserveStatus || capabilities.ApplyConfig || capabilities.StartTunnel || capabilities.StopTunnel || capabilities.ServerManagement {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}

	tests := []struct {
		operation tunnel.Operation
		call      func() error
	}{
		{tunnel.OperationApplyConfig, func() error { return backend.ApplyConfig(context.Background(), tunnel.ConfigSource{}) }},
		{tunnel.OperationStart, func() error { return backend.Start(context.Background()) }},
		{tunnel.OperationStop, func() error { return backend.Stop(context.Background()) }},
		{tunnel.OperationManageServer, func() error {
			return backend.ManageServer(context.Background(), tunnel.ServerRequest{Action: tunnel.ServerProvision})
		}},
	}
	for _, test := range tests {
		if err := test.call(); !tunnel.IsUnsupported(err, test.operation) {
			t.Fatalf("operation %s returned %v", test.operation, err)
		}
	}
}

func TestBackendInspectReturnsOnlyRedactedMetadata(t *testing.T) {
	path := writeConfig(t, validConfig(t, "", "0.0.0.0/0, ::/0"))
	inspection, err := (Backend{}).Inspect(context.Background(), tunnel.ConfigSource{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Metadata.Provider != "redshield" || inspection.Status.Observed {
		t.Fatalf("unexpected inspection: %#v", inspection)
	}
}
