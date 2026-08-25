package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Transport identifies the client tunnel protocol without tying callers to a
// particular provider.
type Transport string

const (
	TransportWireGuard Transport = "wireguard"
	TransportAmneziaWG Transport = "amneziawg"
)

// Endpoint is safe, non-secret connection metadata.
type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// Metadata is the provider-neutral, redacted description returned by Inspect.
// It deliberately has no config path or key fields.
type Metadata struct {
	Provider           string    `json:"provider"`
	Transport          Transport `json:"transport"`
	Endpoint           Endpoint  `json:"endpoint"`
	InterfaceAddresses []string  `json:"interface_addresses"`
	AllowedIPs         []string  `json:"allowed_ips"`
	DNS                []string  `json:"dns,omitempty"`
	MTU                int       `json:"mtu,omitempty"`
	IPv4FullTunnel     bool      `json:"ipv4_full_tunnel"`
	IPv6FullTunnel     bool      `json:"ipv6_full_tunnel"`
}

// Capabilities makes the boundary between inspection and mutation explicit.
type Capabilities struct {
	InspectConfig    bool `json:"inspect_config"`
	ObserveStatus    bool `json:"observe_status"`
	ApplyConfig      bool `json:"apply_config"`
	StartTunnel      bool `json:"start_tunnel"`
	StopTunnel       bool `json:"stop_tunnel"`
	ServerManagement bool `json:"server_management"`
}

type State string

const (
	StateUnknown State = "unknown"
	StateDown    State = "down"
	StateUp      State = "up"
)

type Status struct {
	// State describes provider-reported tunnel or handshake health. It must not
	// be inferred from the presence of a local operating-system interface.
	State    State `json:"state"`
	Observed bool  `json:"observed"`
}

type Inspection struct {
	Metadata     Metadata     `json:"metadata"`
	Status       Status       `json:"status"`
	Capabilities Capabilities `json:"capabilities"`
}

// ConfigSource is intentionally excluded from JSON and redacted when formatted.
type ConfigSource struct {
	Path string `json:"-"`
}

func (ConfigSource) String() string   { return "local-config-source(redacted)" }
func (ConfigSource) GoString() string { return "tunnel.ConfigSource{Path:[REDACTED]}" }
func (ConfigSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "local-config-source(redacted)")
}

type ServerAction string

const (
	ServerProvision ServerAction = "provision"
	ServerRotate    ServerAction = "rotate"
	ServerRemove    ServerAction = "remove"
)

type ServerRequest struct {
	Action ServerAction
}

// Backend keeps read-only inspection separate from operations which can change
// connectivity. Providers must return UnsupportedError instead of pretending a
// mutation succeeded when a capability is false.
type Backend interface {
	Capabilities() Capabilities
	Inspect(context.Context, ConfigSource) (Inspection, error)
	Status(context.Context) (Status, error)
	ApplyConfig(context.Context, ConfigSource) error
	Start(context.Context) error
	Stop(context.Context) error
	ManageServer(context.Context, ServerRequest) error
}

type Operation string

const (
	OperationApplyConfig  Operation = "apply_config"
	OperationStart        Operation = "start_tunnel"
	OperationStop         Operation = "stop_tunnel"
	OperationManageServer Operation = "manage_server"
)

// UnsupportedError is a typed, provider-neutral refusal for unavailable
// mutation and server-management operations.
type UnsupportedError struct {
	operation Operation
}

func NewUnsupportedError(operation Operation) error {
	return &UnsupportedError{operation: operation}
}

func (err *UnsupportedError) Error() string {
	return fmt.Sprintf("tunnel operation is unsupported: %s", err.operation)
}

func (err *UnsupportedError) Operation() Operation {
	return err.operation
}

func IsUnsupported(err error, operation Operation) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported) && unsupported.Operation() == operation
}
