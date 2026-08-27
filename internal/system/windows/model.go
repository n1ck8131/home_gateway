package windows

import "context"

type AddressFamily string

const (
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
)

type AdapterKind string

const (
	AdapterPhysical AdapterKind = "physical"
	AdapterTunnel   AdapterKind = "tunnel"
	// AdapterRedShield remains a source-compatible historical alias. New canary
	// decisions must use AdapterTunnel, never a provider identity.
	AdapterRedShield AdapterKind = AdapterTunnel
	AdapterCisco     AdapterKind = "cisco"
	AdapterLoopback  AdapterKind = "loopback"
	AdapterOther     AdapterKind = "other"
)

type Adapter struct {
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	Index             int         `json:"index"`
	InterfaceGUID     string      `json:"interface_guid"`
	HardwareInterface bool        `json:"hardware_interface"`
	Kind              AdapterKind `json:"kind"`
	AdminStatus       int         `json:"admin_status"`
	OperationalStatus int         `json:"operational_status"`
	Up                bool        `json:"up"`
	Addresses         []string    `json:"addresses,omitempty"`
}

type Route struct {
	Family          AddressFamily `json:"family"`
	Destination     string        `json:"destination"`
	NextHop         string        `json:"next_hop,omitempty"`
	InterfaceIndex  int           `json:"interface_index,omitempty"`
	InterfaceGUID   string        `json:"interface_guid,omitempty"`
	RouteMetric     uint64        `json:"route_metric"`
	InterfaceMetric uint64        `json:"interface_metric"`
	Metric          uint64        `json:"metric"`
	State           int           `json:"state"`
}

type DNSServerSet struct {
	Family         AddressFamily `json:"family"`
	InterfaceIndex int           `json:"interface_index"`
	InterfaceGUID  string        `json:"interface_guid,omitempty"`
	Servers        []string      `json:"servers"`
}

type DNSPolicy struct {
	ServerSets             []DNSServerSet `json:"server_sets"`
	EffectiveNRPTRuleCount int            `json:"effective_nrpt_rule_count"`
}

type Inventory struct {
	Adapters                   []Adapter `json:"adapters"`
	Routes                     []Route   `json:"routes"`
	DNSPolicy                  DNSPolicy `json:"dns_policy"`
	EndpointAddresses          []string  `json:"endpoint_addresses,omitempty"`
	RouteSnapshotAuthoritative bool      `json:"route_snapshot_authoritative"`
	DNSPolicyObserved          bool      `json:"dns_policy_observed"`
}

// Collector obtains a read-only network snapshot. Implementations must not
// enable, disable, reconnect, or reconfigure an adapter.
type Collector interface {
	Collect(context.Context) (Inventory, error)
}

type FindingSeverity string

const (
	SeverityInfo  FindingSeverity = "info"
	SeverityBlock FindingSeverity = "block"
)

type Finding struct {
	Code     string          `json:"code"`
	Severity FindingSeverity `json:"severity"`
	Message  string          `json:"message"`
}

type OperationKind string

const (
	OperationAddEndpointDirectException OperationKind = "add_endpoint_direct_exception"
	OperationPreserveCiscoRoute         OperationKind = "preserve_cisco_route"
	OperationEnforceFailClosed          OperationKind = "enforce_fail_closed"
)

// Operation is declarative. It intentionally contains no executable, shell
// fragment, or argument vector. InterfaceGUID is required for every operation
// that refers to an existing Windows adapter.
type Operation struct {
	Kind           OperationKind `json:"kind"`
	Family         AddressFamily `json:"family,omitempty"`
	Destination    string        `json:"destination,omitempty"`
	NextHop        string        `json:"next_hop,omitempty"`
	InterfaceIndex int           `json:"interface_index,omitempty"`
	InterfaceGUID  string        `json:"interface_guid,omitempty"`
}

type LocalTunnelState string

const (
	LocalTunnelUnknown LocalTunnelState = "unknown"
	LocalTunnelDown    LocalTunnelState = "down"
	LocalTunnelUp      LocalTunnelState = "up"
)

// LocalTunnelStatus is derived only from the authoritative Windows adapter and
// address snapshot. It is deliberately separate from provider/handshake health.
type LocalTunnelStatus struct {
	State         LocalTunnelState `json:"state"`
	Observed      bool             `json:"observed"`
	InterfaceGUID string           `json:"interface_guid,omitempty"`
}

type Preflight struct {
	// Ready remains false in P3.3 because Windows mutation is unsupported.
	Ready             bool              `json:"ready"`
	ReadOnlyQualified bool              `json:"read_only_qualified"`
	ApplyBlocked      bool              `json:"apply_blocked"`
	LocalTunnelStatus LocalTunnelStatus `json:"local_tunnel_status"`
	Findings          []Finding         `json:"findings"`
	Operations        []Operation       `json:"operations"`
}
