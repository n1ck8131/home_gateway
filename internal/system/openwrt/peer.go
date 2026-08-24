package openwrt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

const PeerSpecVersion = 1

var (
	serverIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	interfaceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	uciIDPattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,30}$`)
	secretNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type PeerSpec struct {
	Version             int           `json:"version"`
	SanitizedExample    bool          `json:"sanitized_example,omitempty"`
	ServerID            string        `json:"server_id"`
	Slot                uint8         `json:"slot"`
	Interface           string        `json:"interface"`
	UCIInterface        string        `json:"uci_interface"`
	UCIPeer             string        `json:"uci_peer"`
	Endpoint            Endpoint      `json:"endpoint"`
	PrivateKeyRef       SecretRef     `json:"private_key_ref"`
	PublicKey           string        `json:"public_key"`
	Addresses           []string      `json:"addresses"`
	AllowedIPs          []string      `json:"allowed_ips"`
	AWG                 AWGParameters `json:"awg"`
	PersistentKeepalive int           `json:"persistent_keepalive,omitempty"`
	RouteAllowedIPs     *int          `json:"route_allowed_ips,omitempty"`
	NoHostRoute         *int          `json:"nohostroute,omitempty"`
}

type Endpoint struct {
	IP         string `json:"ip"`
	Port       uint16 `json:"port"`
	WANGateway string `json:"wan_gateway"`
	WANDevice  string `json:"wan_device"`
}

type SecretRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type AWGParameters struct {
	JC   int    `json:"jc"`
	JMin int    `json:"jmin"`
	JMax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`
}

func ParsePeerSpec(data []byte) (PeerSpec, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var spec PeerSpec
	if err := decoder.Decode(&spec); err != nil {
		return PeerSpec{}, fmt.Errorf("decode OpenWrt peer spec: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return PeerSpec{}, errors.New("OpenWrt peer spec contains trailing JSON")
		}
		return PeerSpec{}, fmt.Errorf("decode trailing OpenWrt peer spec data: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return PeerSpec{}, err
	}
	return spec, nil
}

func (spec PeerSpec) Validate() error {
	if spec.Version != PeerSpecVersion {
		return fmt.Errorf("unsupported OpenWrt peer spec version %d", spec.Version)
	}
	if !safeServerID(spec.ServerID) {
		return fmt.Errorf("invalid server ID %q", spec.ServerID)
	}
	if _, err := contracts.ServerRouteForSlot(spec.ServerID, spec.Slot); err != nil {
		return err
	}
	if !safeInterfaceID(spec.Interface) {
		return fmt.Errorf("invalid interface ID %q", spec.Interface)
	}
	if !safeUCIID(spec.UCIInterface) {
		return fmt.Errorf("invalid UCI interface ID %q", spec.UCIInterface)
	}
	if !safeUCIID(spec.UCIPeer) {
		return fmt.Errorf("invalid UCI peer ID %q", spec.UCIPeer)
	}
	if spec.UCIInterface == spec.UCIPeer {
		return errors.New("UCI interface and peer IDs must differ")
	}
	if spec.Interface != spec.UCIInterface {
		return errors.New("OpenWrt amneziawg interface must match the UCI interface ID")
	}
	if err := spec.Endpoint.validate(spec.SanitizedExample); err != nil {
		return err
	}
	if err := spec.PrivateKeyRef.validate(); err != nil {
		return err
	}
	if err := validateWireGuardKey("public key", spec.PublicKey); err != nil {
		return err
	}
	if err := validateAddresses(spec.Addresses); err != nil {
		return err
	}
	if err := validateAllowedIPs(spec.AllowedIPs); err != nil {
		return err
	}
	if err := spec.AWG.validate(); err != nil {
		return err
	}
	if spec.PersistentKeepalive < 0 || spec.PersistentKeepalive > 65535 {
		return errors.New("persistent keepalive must be between 0 and 65535")
	}
	if spec.RouteAllowedIPs == nil || *spec.RouteAllowedIPs != 0 {
		return errors.New("route_allowed_ips must be explicitly 0")
	}
	if spec.NoHostRoute == nil || *spec.NoHostRoute != 1 {
		return errors.New("nohostroute must be explicitly 1")
	}
	return nil
}

func (endpoint Endpoint) validate(allowDocumentation bool) error {
	ip, err := netip.ParseAddr(endpoint.IP)
	if err != nil || endpoint.IP != ip.String() || !publicEndpointIP(ip) && !(allowDocumentation && documentationIP(ip)) {
		return errors.New("endpoint IP must be a concrete public static IP address")
	}
	if endpoint.Port == 0 {
		return errors.New("endpoint port is required")
	}
	gateway, err := netip.ParseAddr(endpoint.WANGateway)
	if err != nil || !concreteUnicast(gateway) || endpoint.WANGateway != gateway.String() {
		return errors.New("WAN gateway must be a concrete unicast IP address")
	}
	if ip.Is4() != gateway.Is4() {
		return errors.New("endpoint IP and WAN gateway address families must match")
	}
	if !safeInterfaceID(endpoint.WANDevice) {
		return fmt.Errorf("invalid WAN device %q", endpoint.WANDevice)
	}
	return nil
}

func publicEndpointIP(address netip.Addr) bool {
	if !concreteUnicast(address) || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonDeployablePublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func documentationIP(address netip.Addr) bool {
	for _, prefix := range documentationPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var documentationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

var nonDeployablePublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func concreteUnicast(address netip.Addr) bool {
	return address.IsValid() &&
		!address.IsUnspecified() &&
		!address.IsLoopback() &&
		!address.IsMulticast() &&
		!address.IsLinkLocalUnicast() &&
		!address.Is4In6()
}

func (ref SecretRef) validate() error {
	if ref.Kind != "routerd-openwrt-peer-private-key" {
		return errors.New("private key secret ref must use routerd-openwrt-peer-private-key kind")
	}
	if !secretNamePattern.MatchString(ref.Name) || strings.ContainsAny(ref.Name, `/\`) || strings.Contains(ref.Name, "..") {
		return fmt.Errorf("invalid private key secret ref name %q", ref.Name)
	}
	return nil
}

func (ref SecretRef) FilePath() string {
	return "/etc/routerd/secrets/" + ref.Kind + "_" + ref.Name + ".key"
}

func (awg AWGParameters) validate() error {
	for name, value := range map[string]int{
		"jc": awg.JC, "jmin": awg.JMin, "jmax": awg.JMax,
		"s1": awg.S1, "s2": awg.S2, "s3": awg.S3, "s4": awg.S4,
	} {
		if value <= 0 || value > 65535 {
			return fmt.Errorf("awg_%s must be between 1 and 65535", name)
		}
	}
	if awg.JMin > awg.JMax {
		return errors.New("awg_jmin cannot exceed awg_jmax")
	}
	for name, value := range map[string]string{
		"h1": awg.H1, "h2": awg.H2, "h3": awg.H3, "h4": awg.H4,
		"i1": awg.I1, "i2": awg.I2, "i3": awg.I3, "i4": awg.I4, "i5": awg.I5,
	} {
		if !safeAWGString(value) {
			return fmt.Errorf("awg_%s contains invalid input", name)
		}
	}
	for name, value := range map[string]string{"h1": awg.H1, "h2": awg.H2, "h3": awg.H3, "h4": awg.H4} {
		if err := validateAWGPair(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (awg AWGParameters) options() []uciOption {
	return []uciOption{
		{name: "awg_jc", value: strconv.Itoa(awg.JC)},
		{name: "awg_jmin", value: strconv.Itoa(awg.JMin)},
		{name: "awg_jmax", value: strconv.Itoa(awg.JMax)},
		{name: "awg_s1", value: strconv.Itoa(awg.S1)},
		{name: "awg_s2", value: strconv.Itoa(awg.S2)},
		{name: "awg_s3", value: strconv.Itoa(awg.S3)},
		{name: "awg_s4", value: strconv.Itoa(awg.S4)},
		{name: "awg_h1", value: awg.H1},
		{name: "awg_h2", value: awg.H2},
		{name: "awg_h3", value: awg.H3},
		{name: "awg_h4", value: awg.H4},
		{name: "awg_i1", value: awg.I1},
		{name: "awg_i2", value: awg.I2},
		{name: "awg_i3", value: awg.I3},
		{name: "awg_i4", value: awg.I4},
		{name: "awg_i5", value: awg.I5},
	}
}

func validateAWGPair(name, value string) error {
	left, right, ok := strings.Cut(value, "-")
	if !ok {
		return fmt.Errorf("awg_%s must be two uint32 values separated by '-'", name)
	}
	for _, part := range []string{left, right} {
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || parsed > math.MaxUint32 {
			return fmt.Errorf("awg_%s contains an invalid uint32 value", name)
		}
	}
	return nil
}

func (spec PeerSpec) EndpointAddr() netip.Addr {
	address, _ := netip.ParseAddr(spec.Endpoint.IP)
	return address
}

func (spec PeerSpec) EndpointGateway() netip.Addr {
	address, _ := netip.ParseAddr(spec.Endpoint.WANGateway)
	return address
}

func (spec PeerSpec) EndpointHostPrefix() netip.Prefix {
	address := spec.EndpointAddr()
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address, bits)
}

func (spec PeerSpec) ServerRoute() (contracts.ServerRoute, error) {
	return contracts.ServerRouteForSlot(spec.ServerID, spec.Slot)
}

func (spec PeerSpec) SystemDirectEndpointEntry() contracts.RouteEntry {
	return contracts.RouteEntry{
		ID:      "system-direct-" + spec.ServerID + "-endpoint",
		Pattern: spec.EndpointHostPrefix().String(),
		Kind:    contracts.EntryKindCIDR,
		Route:   contracts.RouteClassDirect,
		Scope:   contracts.Scope{Type: contracts.ScopeGlobal},
		Origin:  contracts.OriginSystemDirect,
	}
}

func (spec PeerSpec) DesiredState(evaluationTime time.Time) (contracts.DesiredState, error) {
	if spec.SanitizedExample {
		return contracts.DesiredState{}, errors.New("sanitized OpenWrt peer example is not deployable")
	}
	route, err := spec.ServerRoute()
	if err != nil {
		return contracts.DesiredState{}, err
	}
	state := contracts.DesiredState{
		EvaluationTime: evaluationTime,
		MarkMask:       contracts.RouterdMarkMask,
		ActiveServerID: spec.ServerID,
		Servers:        []contracts.ServerRoute{route},
		Entries:        []contracts.RouteEntry{spec.SystemDirectEndpointEntry()},
	}
	if err := state.Validate(); err != nil {
		return contracts.DesiredState{}, err
	}
	return state, nil
}

func safeServerID(value string) bool {
	return serverIDPattern.MatchString(value) && !strings.Contains(value, "..")
}

func safeInterfaceID(value string) bool {
	return interfaceIDPattern.MatchString(value) && !strings.HasPrefix(value, "-") && !strings.Contains(value, "..")
}

func safeUCIID(value string) bool {
	return uciIDPattern.MatchString(value) && !strings.Contains(value, "..")
}

func validateWireGuardKey(label, value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must be a 32-byte WireGuard base64 key", label)
	}
	return nil
}

func validateAddresses(values []string) error {
	if len(values) == 0 {
		return errors.New("at least one tunnel address is required")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || prefix.Addr().IsUnspecified() {
			return fmt.Errorf("invalid tunnel address %q", value)
		}
		if prefix.Addr().Is4() {
			if prefix.Bits() != 32 {
				return fmt.Errorf("IPv4 tunnel address %q must use /32", value)
			}
		} else if prefix.Bits() != 128 {
			return fmt.Errorf("IPv6 tunnel address %q must use /128", value)
		}
		canonical := prefix.String()
		if value != canonical {
			return fmt.Errorf("tunnel address %q must be canonical %q", value, canonical)
		}
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("duplicate tunnel address %q", value)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func validateAllowedIPs(values []string) error {
	want := []string{"0.0.0.0/0", "::/0"}
	got := append([]string(nil), values...)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return errors.New("allowed_ips must be exactly 0.0.0.0/0 and ::/0")
	}
	if !slices.Equal(values, want) {
		return errors.New("allowed_ips must be canonical and ordered as 0.0.0.0/0 then ::/0")
	}
	return nil
}

func safeAWGString(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
