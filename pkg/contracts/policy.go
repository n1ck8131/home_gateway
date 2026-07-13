package contracts

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

type RouteClass string

const (
	RouteClassLocal  RouteClass = "local"
	RouteClassDirect RouteClass = "direct"
	RouteClassVPN    RouteClass = "vpn"
)

const (
	RouterdMarkMask         uint32 = 0xff000000
	RouterdRoutingTableBase uint32 = 10000
)

type DeviceMode string

const (
	DeviceModeAuto         DeviceMode = "auto"
	DeviceModeAlwaysDirect DeviceMode = "always-direct"
	DeviceModeAlwaysVPN    DeviceMode = "always-vpn"
)

type EntryKind string

const (
	EntryKindDomain EntryKind = "domain"
	EntryKindIP     EntryKind = "ip"
	EntryKindCIDR   EntryKind = "cidr"
)

type DomainMatch string

const (
	DomainMatchExact    DomainMatch = "exact"
	DomainMatchSuffix   DomainMatch = "suffix"
	DomainMatchWildcard DomainMatch = "wildcard"
)

type OriginTier string

const (
	OriginSystemDirect   OriginTier = "system-direct"
	OriginAutoCisco      OriginTier = "auto-cisco"
	OriginManual         OriginTier = "manual"
	OriginCuratedDirect  OriginTier = "curated-direct"
	OriginExternalDirect OriginTier = "external-direct"
	OriginExternalVPN    OriginTier = "external-vpn"
)

type ScopeType string

const (
	ScopeGlobal ScopeType = "global"
	ScopeDevice ScopeType = "device"
)

type IdentityKind string

const (
	IdentityMAC             IdentityKind = "mac"
	IdentityClientID        IdentityKind = "client-id"
	IdentityDHCPReservation IdentityKind = "dhcp-reservation"
)

type Scope struct {
	Type     ScopeType `json:"type"`
	DeviceID string    `json:"device_id,omitempty"`
}

type DeviceIdentity struct {
	Kind  IdentityKind `json:"kind"`
	Value string       `json:"value"`
}

type Device struct {
	ID            string           `json:"id"`
	Mode          DeviceMode       `json:"mode"`
	ProtectedWork bool             `json:"protected_work"`
	Identities    []DeviceIdentity `json:"identities,omitempty"`
}

type RouteEntry struct {
	ID        string      `json:"id"`
	Pattern   string      `json:"pattern"`
	Kind      EntryKind   `json:"kind"`
	Match     DomainMatch `json:"match,omitempty"`
	Route     RouteClass  `json:"route"`
	Scope     Scope       `json:"scope"`
	Origin    OriginTier  `json:"origin"`
	Sequence  uint64      `json:"sequence,omitempty"`
	ServerID  string      `json:"server_id,omitempty"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
}

type ServerRoute struct {
	ServerID string `json:"server_id"`
	Mark     uint32 `json:"mark"`
	Table    uint32 `json:"table"`
}

func ServerRouteForSlot(serverID string, slot uint8) (ServerRoute, error) {
	if strings.TrimSpace(serverID) == "" {
		return ServerRoute{}, errors.New("server ID is required")
	}
	if slot == 0 {
		return ServerRoute{}, errors.New("server slot must be between 1 and 255")
	}
	return ServerRoute{
		ServerID: serverID,
		Mark:     uint32(slot) << 24,
		Table:    RouterdRoutingTableBase + uint32(slot),
	}, nil
}

type DesiredState struct {
	EvaluationTime time.Time     `json:"evaluation_time"`
	Devices        []Device      `json:"devices,omitempty"`
	Entries        []RouteEntry  `json:"entries,omitempty"`
	MarkMask       uint32        `json:"mark_mask,omitempty"`
	ActiveServerID string        `json:"active_server_id,omitempty"`
	Servers        []ServerRoute `json:"servers,omitempty"`
}

type PolicyPlan struct {
	EvaluationTime time.Time     `json:"evaluation_time"`
	Entries        []RouteEntry  `json:"entries"`
	ServerRoutes   []ServerRoute `json:"server_routes"`
}

type RouteQuery struct {
	Target   string `json:"target"`
	DeviceID string `json:"device_id,omitempty"`
}

type DecisionEvidence struct {
	EntryID    string     `json:"entry_id"`
	Origin     OriginTier `json:"origin"`
	Route      RouteClass `json:"route"`
	Pattern    string     `json:"pattern,omitempty"`
	Reason     string     `json:"reason"`
	Winner     bool       `json:"winner"`
	Resolution string     `json:"resolution,omitempty"`
}

type RouteDecision struct {
	Target        string             `json:"target"`
	DeviceID      string             `json:"device_id,omitempty"`
	Route         RouteClass         `json:"route"`
	ServerID      string             `json:"server_id,omitempty"`
	WinnerEntryID string             `json:"winner_entry_id,omitempty"`
	Conflict      bool               `json:"conflict"`
	Resolution    string             `json:"resolution,omitempty"`
	Evidence      []DecisionEvidence `json:"evidence"`
}

func (entry RouteEntry) Validate() error {
	if strings.TrimSpace(entry.ID) == "" {
		return errors.New("entry ID is required")
	}
	if strings.TrimSpace(entry.Pattern) == "" {
		return fmt.Errorf("entry %q pattern is required", entry.ID)
	}
	switch entry.Kind {
	case EntryKindDomain:
		switch entry.Match {
		case DomainMatchExact, DomainMatchSuffix, DomainMatchWildcard:
		default:
			return fmt.Errorf("entry %q has invalid domain match %q", entry.ID, entry.Match)
		}
	case EntryKindIP, EntryKindCIDR:
		if entry.Match != "" {
			return fmt.Errorf("entry %q cannot use domain match for %s", entry.ID, entry.Kind)
		}
	default:
		return fmt.Errorf("entry %q has invalid kind %q", entry.ID, entry.Kind)
	}
	if entry.Route != RouteClassDirect && entry.Route != RouteClassVPN {
		return fmt.Errorf("entry %q has invalid route %q", entry.ID, entry.Route)
	}
	if !validOrigin(entry.Origin) {
		return fmt.Errorf("entry %q has invalid origin %q", entry.ID, entry.Origin)
	}
	if entry.Origin != OriginManual && entry.Sequence != 0 {
		return fmt.Errorf("entry %q sequence is only valid for manual origin", entry.ID)
	}
	if err := entry.Scope.Validate(); err != nil {
		return fmt.Errorf("entry %q: %w", entry.ID, err)
	}
	if entry.Origin == OriginSystemDirect && entry.Route != RouteClassDirect {
		return fmt.Errorf("entry %q system-direct origin must route direct", entry.ID)
	}
	if entry.Origin == OriginAutoCisco && (entry.Route != RouteClassDirect || entry.Scope.Type != ScopeDevice) {
		return fmt.Errorf("entry %q auto-cisco must be device-scoped direct", entry.ID)
	}
	if entry.Origin == OriginCuratedDirect || entry.Origin == OriginExternalDirect {
		if entry.Route != RouteClassDirect {
			return fmt.Errorf("entry %q direct origin must route direct", entry.ID)
		}
	}
	if entry.Origin == OriginExternalVPN && entry.Route != RouteClassVPN {
		return fmt.Errorf("entry %q external-vpn origin must route vpn", entry.ID)
	}
	if entry.ServerID != "" && entry.Route != RouteClassVPN {
		return fmt.Errorf("entry %q selects a server for a non-VPN route", entry.ID)
	}
	return nil
}

func (scope Scope) Validate() error {
	switch scope.Type {
	case ScopeGlobal:
		if scope.DeviceID != "" {
			return errors.New("global scope cannot specify device ID")
		}
	case ScopeDevice:
		if strings.TrimSpace(scope.DeviceID) == "" {
			return errors.New("device scope requires device ID")
		}
	default:
		return fmt.Errorf("invalid scope type %q", scope.Type)
	}
	return nil
}

func (state DesiredState) Validate() error {
	if state.EvaluationTime.IsZero() {
		return errors.New("evaluation time is required")
	}
	devicesByID := make(map[string]Device, len(state.Devices))
	identities := make(map[string]string)
	for _, device := range state.Devices {
		if err := device.Validate(); err != nil {
			return err
		}
		if _, exists := devicesByID[device.ID]; exists {
			return fmt.Errorf("duplicate device ID %q", device.ID)
		}
		devicesByID[device.ID] = device
		for _, identity := range device.Identities {
			key := identityMapKey(identity)
			if owner, exists := identities[key]; exists && owner != device.ID {
				return fmt.Errorf("identity %q belongs to devices %q and %q", identity.Value, owner, device.ID)
			}
			identities[key] = device.ID
		}
	}
	entryIDs := make(map[string]struct{}, len(state.Entries))
	for _, entry := range state.Entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		if _, exists := entryIDs[entry.ID]; exists {
			return fmt.Errorf("duplicate entry ID %q", entry.ID)
		}
		entryIDs[entry.ID] = struct{}{}
		if entry.Scope.Type == ScopeDevice {
			device, exists := devicesByID[entry.Scope.DeviceID]
			if !exists {
				return fmt.Errorf("entry %q references unknown device %q", entry.ID, entry.Scope.DeviceID)
			}
			if entry.Origin == OriginAutoCisco && !device.ProtectedWork {
				return fmt.Errorf("entry %q auto-cisco scope %q is not a protected work device", entry.ID, entry.Scope.DeviceID)
			}
		}
	}
	if err := validateServerRoutes(state.MarkMask, state.ActiveServerID, state.Servers); err != nil {
		return err
	}
	serverIDs := make(map[string]struct{}, len(state.Servers))
	for _, server := range state.Servers {
		serverIDs[server.ServerID] = struct{}{}
	}
	for _, entry := range state.Entries {
		if entry.ServerID != "" {
			if _, exists := serverIDs[entry.ServerID]; !exists {
				return fmt.Errorf("entry %q references unknown server %q", entry.ID, entry.ServerID)
			}
		}
	}
	return nil
}

func (device Device) Validate() error {
	if strings.TrimSpace(device.ID) == "" {
		return errors.New("device ID is required")
	}
	switch device.Mode {
	case DeviceModeAuto, DeviceModeAlwaysDirect, DeviceModeAlwaysVPN:
	default:
		return fmt.Errorf("device %q has invalid mode %q", device.ID, device.Mode)
	}
	if device.ProtectedWork && device.Mode == DeviceModeAlwaysVPN {
		return fmt.Errorf("protected work device %q cannot use always-vpn", device.ID)
	}
	seen := make(map[string]struct{}, len(device.Identities))
	for _, identity := range device.Identities {
		if err := identity.Validate(); err != nil {
			return fmt.Errorf("device %q: %w", device.ID, err)
		}
		key := identityMapKey(identity)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("device %q has duplicate identity %q", device.ID, identity.Value)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (identity DeviceIdentity) Validate() error {
	value := strings.TrimSpace(identity.Value)
	if value == "" {
		return errors.New("device identity value is required")
	}
	switch identity.Kind {
	case IdentityMAC:
		if _, err := net.ParseMAC(value); err != nil {
			return fmt.Errorf("invalid MAC identity %q", value)
		}
	case IdentityClientID:
	case IdentityDHCPReservation:
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("invalid DHCP reservation %q", value)
		}
	default:
		return fmt.Errorf("invalid identity kind %q", identity.Kind)
	}
	return nil
}

func identityMapKey(identity DeviceIdentity) string {
	value := strings.TrimSpace(identity.Value)
	switch identity.Kind {
	case IdentityMAC:
		address, _ := net.ParseMAC(value)
		value = address.String()
	case IdentityDHCPReservation:
		address, _ := netip.ParseAddr(value)
		value = address.Unmap().String()
	}
	return string(identity.Kind) + "\x00" + value
}

func validateServerRoutes(mask uint32, activeServerID string, servers []ServerRoute) error {
	if len(servers) == 0 {
		if activeServerID != "" {
			return fmt.Errorf("active server %q is not defined", activeServerID)
		}
		return nil
	}
	if mask == 0 {
		return errors.New("mark mask is required when servers are configured")
	}
	if mask != RouterdMarkMask {
		return fmt.Errorf("mark mask must be routerd reserved mask %#x", RouterdMarkMask)
	}
	ids := make(map[string]struct{}, len(servers))
	marks := make(map[uint32]string, len(servers))
	tables := make(map[uint32]string, len(servers))
	for _, server := range servers {
		if strings.TrimSpace(server.ServerID) == "" {
			return errors.New("server ID is required")
		}
		if server.Mark == 0 || server.Mark&^mask != 0 {
			return fmt.Errorf("server %q mark %#x is outside mask %#x", server.ServerID, server.Mark, mask)
		}
		if server.Table == 0 {
			return fmt.Errorf("server %q routing table is required", server.ServerID)
		}
		if _, exists := ids[server.ServerID]; exists {
			return fmt.Errorf("duplicate server ID %q", server.ServerID)
		}
		if owner, exists := marks[server.Mark]; exists {
			return fmt.Errorf("servers %q and %q share mark %#x", owner, server.ServerID, server.Mark)
		}
		if owner, exists := tables[server.Table]; exists {
			return fmt.Errorf("servers %q and %q share table %d", owner, server.ServerID, server.Table)
		}
		ids[server.ServerID] = struct{}{}
		marks[server.Mark] = server.ServerID
		tables[server.Table] = server.ServerID
	}
	if activeServerID != "" {
		if _, exists := ids[activeServerID]; !exists {
			return fmt.Errorf("active server %q is not defined", activeServerID)
		}
	}
	return nil
}

func validOrigin(origin OriginTier) bool {
	switch origin {
	case OriginSystemDirect, OriginAutoCisco, OriginManual, OriginCuratedDirect, OriginExternalDirect, OriginExternalVPN:
		return true
	default:
		return false
	}
}
