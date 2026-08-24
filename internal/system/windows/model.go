package windows

import "context"

type AddressFamily string

const (
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
)

type AdapterKind string

const (
	AdapterPhysical  AdapterKind = "physical"
	AdapterRedShield AdapterKind = "redshield"
	AdapterCisco     AdapterKind = "cisco"
	AdapterLoopback  AdapterKind = "loopback"
	AdapterOther     AdapterKind = "other"
)

type Adapter struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Index       int         `json:"index"`
	Kind        AdapterKind `json:"kind"`
	Up          bool        `json:"up"`
	Addresses   []string    `json:"addresses,omitempty"`
}

type Route struct {
	Family           AddressFamily `json:"family"`
	Destination      string        `json:"destination"`
	NextHop          string        `json:"next_hop,omitempty"`
	InterfaceIndex   int           `json:"interface_index,omitempty"`
	InterfaceAddress string        `json:"interface_address,omitempty"`
	Metric           int           `json:"metric"`
}

type Inventory struct {
	Adapters                   []Adapter `json:"adapters"`
	Routes                     []Route   `json:"routes"`
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
// fragment, or argument vector.
type Operation struct {
	Kind           OperationKind `json:"kind"`
	Family         AddressFamily `json:"family,omitempty"`
	Destination    string        `json:"destination,omitempty"`
	NextHop        string        `json:"next_hop,omitempty"`
	InterfaceIndex int           `json:"interface_index,omitempty"`
}

type Preflight struct {
	Ready        bool        `json:"ready"`
	ApplyBlocked bool        `json:"apply_blocked"`
	Findings     []Finding   `json:"findings"`
	Operations   []Operation `json:"operations"`
}
