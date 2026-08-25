package redshield

import (
	"context"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

type Backend struct{}

var _ tunnel.Backend = Backend{}

func (Backend) Capabilities() tunnel.Capabilities {
	return tunnel.Capabilities{
		InspectConfig:    true,
		ObserveStatus:    false,
		ApplyConfig:      false,
		StartTunnel:      false,
		StopTunnel:       false,
		ServerManagement: false,
	}
}

func (backend Backend) Inspect(ctx context.Context, source tunnel.ConfigSource) (tunnel.Inspection, error) {
	if err := ctx.Err(); err != nil {
		return tunnel.Inspection{}, err
	}
	var config Config
	var err error
	if source.SHA256 == "" {
		config, err = ImportFile(source.Path)
	} else {
		config, err = ImportFilePinned(source.Path, source.SHA256)
	}
	if err != nil {
		return tunnel.Inspection{}, err
	}
	status, err := backend.Status(ctx)
	if err != nil {
		return tunnel.Inspection{}, err
	}
	return tunnel.Inspection{
		Metadata:     config.Metadata(),
		Status:       status,
		Capabilities: backend.Capabilities(),
	}, nil
}

func (Backend) Status(ctx context.Context) (tunnel.Status, error) {
	if err := ctx.Err(); err != nil {
		return tunnel.Status{}, err
	}
	return tunnel.Status{State: tunnel.StateUnknown, Observed: false}, nil
}

func (Backend) ApplyConfig(context.Context, tunnel.ConfigSource) error {
	return tunnel.NewUnsupportedError(tunnel.OperationApplyConfig)
}

func (Backend) Start(context.Context) error {
	return tunnel.NewUnsupportedError(tunnel.OperationStart)
}

func (Backend) Stop(context.Context) error {
	return tunnel.NewUnsupportedError(tunnel.OperationStop)
}

func (Backend) ManageServer(context.Context, tunnel.ServerRequest) error {
	return tunnel.NewUnsupportedError(tunnel.OperationManageServer)
}
