package openwrt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const OperationPlanVersion = 1

type OperationPlan struct {
	Version    int         `json:"version"`
	Digest     string      `json:"digest"`
	Operations []Operation `json:"operations"`
}

type Operation struct {
	Name    string   `json:"name"`
	Program string   `json:"program"`
	Args    []string `json:"args"`
}

type uciOption struct {
	name  string
	value string
}

type uciTarget struct {
	section string
	option  string
	value   string
}

func (operation Operation) Argv() []string {
	argv := make([]string, 0, 1+len(operation.Args))
	argv = append(argv, operation.Program)
	argv = append(argv, operation.Args...)
	return argv
}

func BuildOperationPlan(spec PeerSpec) (OperationPlan, error) {
	if spec.SanitizedExample {
		return OperationPlan{}, errors.New("sanitized OpenWrt peer example is not deployable")
	}
	if err := spec.Validate(); err != nil {
		return OperationPlan{}, err
	}
	digest, err := specDigest(spec)
	if err != nil {
		return OperationPlan{}, err
	}
	family := "-6"
	if spec.EndpointAddr().Is4() {
		family = "-4"
	}
	endpointRoute := Operation{
		Name:    "preserve-endpoint-host-route",
		Program: "ip",
		Args: []string{
			family, "route", "replace", "table", "main",
			spec.EndpointHostPrefix().String(), "via", spec.EndpointGateway().String(), "dev", spec.Endpoint.WANDevice,
		},
	}
	operations := []Operation{endpointRoute}
	operations = append(operations, uciSet(spec.UCIInterface, "", "interface"))
	operations = append(operations, uciDeleteList(spec.UCIInterface, "private_key"))
	operations = append(operations, uciDeleteList(spec.UCIInterface, "fwmark"))
	operations = append(operations, uciDeleteList(spec.UCIInterface, "addresses"))
	operations = append(operations, uciSet(spec.UCIInterface, "proto", "amneziawg"))
	operations = append(operations, uciSet(spec.UCIInterface, "private_key_file", spec.PrivateKeyRef.FilePath()))
	operations = append(operations, uciSet(spec.UCIInterface, "nohostroute", "1"))
	operations = append(operations, uciSet(spec.UCIInterface, "routerd_digest", digest))
	for _, address := range spec.Addresses {
		operations = append(operations, uciAddList(spec.UCIInterface, "addresses", address))
	}
	for _, option := range spec.AWG.options() {
		operations = append(operations, uciSet(spec.UCIInterface, option.name, option.value))
	}
	operations = append(operations, uciSet(spec.UCIPeer, "", "amneziawg_"+spec.UCIInterface))
	operations = append(operations, uciDeleteList(spec.UCIPeer, "preshared_key"))
	operations = append(operations, uciDeleteList(spec.UCIPeer, "persistent_keepalive"))
	operations = append(operations, uciDeleteList(spec.UCIPeer, "allowed_ips"))
	operations = append(operations, uciSet(spec.UCIPeer, "public_key", spec.PublicKey))
	operations = append(operations, uciSet(spec.UCIPeer, "endpoint_host", spec.Endpoint.IP))
	operations = append(operations, uciSet(spec.UCIPeer, "endpoint_port", strconv.FormatUint(uint64(spec.Endpoint.Port), 10)))
	operations = append(operations, uciSet(spec.UCIPeer, "route_allowed_ips", "0"))
	for _, allowed := range spec.AllowedIPs {
		operations = append(operations, uciAddList(spec.UCIPeer, "allowed_ips", allowed))
	}
	if spec.PersistentKeepalive != 0 {
		operations = append(operations, uciSet(spec.UCIPeer, "persistent_keepalive", strconv.Itoa(spec.PersistentKeepalive)))
	}
	operations = append(operations,
		Operation{Name: "uci-commit-network", Program: "uci", Args: []string{"commit", "network"}},
		Operation{Name: "ifup-peer", Program: "ifup", Args: []string{spec.UCIInterface}},
	)
	plan := OperationPlan{Version: OperationPlanVersion, Digest: digest, Operations: operations}
	if err := plan.Validate(); err != nil {
		return OperationPlan{}, err
	}
	return plan, nil
}

func ParseOperationPlan(data []byte) (OperationPlan, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan OperationPlan
	if err := decoder.Decode(&plan); err != nil {
		return OperationPlan{}, fmt.Errorf("decode OpenWrt operation plan: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return OperationPlan{}, errors.New("OpenWrt operation plan contains trailing JSON")
		}
		return OperationPlan{}, fmt.Errorf("decode trailing OpenWrt operation plan data: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return OperationPlan{}, err
	}
	return plan, nil
}

func (plan OperationPlan) Validate() error {
	if plan.Version != OperationPlanVersion {
		return fmt.Errorf("unsupported operation plan version %d", plan.Version)
	}
	if !validDigest(plan.Digest) {
		return errors.New("operation plan digest is invalid")
	}
	if len(plan.Operations) == 0 {
		return errors.New("operation plan requires operations")
	}
	for index, operation := range plan.Operations {
		if err := validateOperation(operation); err != nil {
			return fmt.Errorf("operation %d: %w", index, err)
		}
	}
	first := plan.Operations[0]
	if first.Program != "ip" || first.Name != "preserve-endpoint-host-route" {
		return errors.New("operation plan must preserve the endpoint host route first")
	}
	for index, operation := range plan.Operations[1:] {
		if operation.Program == "ip" {
			return fmt.Errorf("operation %d: operation plan permits exactly one endpoint route", index+1)
		}
	}
	return validateUCIPlan(plan)
}

func (plan OperationPlan) JSON() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func IPRuleInventory(spec PeerSpec, available bool) (iprule.Inventory, error) {
	route, err := spec.ServerRoute()
	if err != nil {
		return iprule.Inventory{}, err
	}
	server := iprule.Server{Route: route, Available: available}
	if available {
		server.Interface = spec.Interface
	}
	return iprule.Inventory{Servers: []iprule.Server{server}}, nil
}

func RenderIPRuleArtifact(spec PeerSpec, available bool) ([]byte, error) {
	route, err := spec.ServerRoute()
	if err != nil {
		return nil, err
	}
	inventory, err := IPRuleInventory(spec, available)
	if err != nil {
		return nil, err
	}
	return iprule.Render(contracts.PolicyPlan{ServerRoutes: []contracts.ServerRoute{route}}, inventory)
}

func specDigest(spec PeerSpec) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func uciSet(section, option, value string) Operation {
	target := "network." + section
	if option != "" {
		target += "." + option
	}
	return Operation{Name: "uci-set-" + section + "-" + option, Program: "uci", Args: []string{"set", target + "=" + value}}
}

func uciAddList(section, option, value string) Operation {
	return Operation{Name: "uci-add-list-" + section + "-" + option, Program: "uci", Args: []string{"add_list", "network." + section + "." + option + "=" + value}}
}

func uciDeleteList(section, option string) Operation {
	return Operation{Name: "uci-delete-list-" + section + "-" + option, Program: "uci", Args: []string{"-q", "delete", "network." + section + "." + option}}
}

func validateOperation(operation Operation) error {
	if strings.TrimSpace(operation.Name) == "" {
		return errors.New("operation name is required")
	}
	switch operation.Program {
	case "ip":
		return validateIPOperation(operation.Args)
	case "uci":
		return validateUCIOperation(operation.Args)
	case "ifup":
		if len(operation.Args) != 1 || !safeUCIID(operation.Args[0]) {
			return errors.New("ifup requires one safe UCI interface ID")
		}
		return nil
	default:
		return fmt.Errorf("program %q is not allowed", operation.Program)
	}
}

func validateIPOperation(args []string) error {
	if len(args) != 10 || (args[0] != "-4" && args[0] != "-6") {
		return errors.New("endpoint route must be a canonical ip -4/-6 command")
	}
	if args[1] != "route" || args[2] != "replace" || args[3] != "table" || args[4] != "main" ||
		args[6] != "via" || args[8] != "dev" {
		return errors.New("endpoint route must replace an explicit main-table host route")
	}
	if args[5] == "default" || strings.Contains(args[5], "default") {
		return errors.New("endpoint route cannot change the main default route")
	}
	prefix, err := netip.ParsePrefix(args[5])
	if err != nil || !prefix.IsValid() || prefix.String() != args[5] {
		return errors.New("endpoint route requires a canonical host prefix")
	}
	if !publicEndpointIP(prefix.Addr()) {
		return errors.New("endpoint route must target a concrete public endpoint IP")
	}
	gateway, err := netip.ParseAddr(args[7])
	if err != nil || !concreteUnicast(gateway) || gateway.String() != args[7] {
		return errors.New("endpoint route requires a concrete WAN gateway")
	}
	if args[0] == "-4" && (!prefix.Addr().Is4() || prefix.Bits() != 32) {
		return errors.New("IPv4 endpoint route must be a /32 host route")
	}
	if args[0] == "-6" && (prefix.Addr().Is4() || prefix.Bits() != 128) {
		return errors.New("IPv6 endpoint route must be a /128 host route")
	}
	if prefix.Addr().Is4() != gateway.Is4() {
		return errors.New("endpoint route family must match the prefix and WAN gateway")
	}
	if !safeInterfaceID(args[9]) {
		return errors.New("endpoint route requires a safe WAN device")
	}
	return nil
}

func validateUCIOperation(args []string) error {
	if len(args) == 0 {
		return errors.New("uci operation is required")
	}
	if args[0] == "commit" {
		if len(args) != 2 || args[1] != "network" {
			return errors.New("only uci commit network is allowed")
		}
		return nil
	}
	if len(args) == 3 && args[0] == "-q" && args[1] == "delete" {
		target, err := parseUCITarget(args[2], false)
		if err != nil || target.option == "" {
			return errors.New("invalid uci delete target")
		}
		return nil
	}
	if len(args) != 2 || (args[0] != "set" && args[0] != "add_list") {
		return errors.New("only uci set/add_list/quiet-delete/commit commands are allowed")
	}
	target, err := parseUCITarget(args[1], true)
	if err != nil {
		return errors.New("invalid uci target")
	}
	if args[0] == "add_list" && target.option == "" {
		return errors.New("uci add_list requires an option")
	}
	return nil
}

func parseUCITarget(raw string, requireValue bool) (uciTarget, error) {
	left, value, hasValue := strings.Cut(raw, "=")
	if requireValue != hasValue || strings.ContainsAny(raw, "\t\r\n\x00") {
		return uciTarget{}, errors.New("invalid uci target shape")
	}
	if hasValue && (value == "" || !safeUCIValue(value)) {
		return uciTarget{}, errors.New("invalid uci value")
	}
	parts := strings.Split(left, ".")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "network" || !safeUCIID(parts[1]) {
		return uciTarget{}, errors.New("invalid uci section")
	}
	target := uciTarget{section: parts[1], value: value}
	if len(parts) == 3 {
		if !safeUCIOption(parts[2]) {
			return uciTarget{}, errors.New("invalid uci option")
		}
		target.option = parts[2]
	}
	return target, nil
}

func validateUCIPlan(plan OperationPlan) error {
	scalars := make(map[string]string)
	lists := make(map[string][]string)
	deletes := make(map[string]struct{})
	firstWrite := make(map[string]int)
	deleteAt := make(map[string]int)
	commits := 0
	ifup := ""
	for index, operation := range plan.Operations {
		switch operation.Program {
		case "uci":
			switch operation.Args[0] {
			case "set":
				target, _ := parseUCITarget(operation.Args[1], true)
				key := target.section + "." + target.option
				if _, exists := scalars[key]; exists {
					return fmt.Errorf("UCI target %s is assigned more than once", key)
				}
				scalars[key] = target.value
				if _, exists := firstWrite[key]; !exists {
					firstWrite[key] = index
				}
			case "add_list":
				target, _ := parseUCITarget(operation.Args[1], true)
				key := target.section + "." + target.option
				lists[key] = append(lists[key], target.value)
				if _, exists := firstWrite[key]; !exists {
					firstWrite[key] = index
				}
			case "-q":
				target, _ := parseUCITarget(operation.Args[2], false)
				key := target.section + "." + target.option
				if _, exists := deletes[key]; exists {
					return fmt.Errorf("UCI target %s is deleted more than once", key)
				}
				if writeIndex, exists := firstWrite[key]; exists {
					return fmt.Errorf("UCI target %s is deleted after write at operation %d", key, writeIndex)
				}
				deletes[key] = struct{}{}
				deleteAt[key] = index
			case "commit":
				commits++
			}
		case "ifup":
			if ifup != "" {
				return errors.New("operation plan must contain exactly one ifup")
			}
			ifup = operation.Args[0]
		}
	}
	if commits != 1 {
		return errors.New("operation plan must contain exactly one uci commit network")
	}
	if ifup == "" {
		return errors.New("operation plan must end with ifup")
	}
	if last := plan.Operations[len(plan.Operations)-1]; last.Program != "ifup" || last.Args[0] != ifup {
		return errors.New("operation plan must end with ifup")
	}
	commit := plan.Operations[len(plan.Operations)-2]
	if commit.Program != "uci" || len(commit.Args) != 2 || commit.Args[0] != "commit" || commit.Args[1] != "network" {
		return errors.New("uci commit network must immediately precede ifup")
	}
	iface, peer, err := resolveSections(scalars)
	if err != nil {
		return err
	}
	if ifup != iface {
		return errors.New("ifup target must match the amneziawg interface section")
	}
	if err := validateSectionOptions(iface, peer, scalars, lists, deletes); err != nil {
		return err
	}
	if scalars[iface+".proto"] != "amneziawg" {
		return errors.New("amneziawg interface proto must be exact")
	}
	if err := validatePrivateKeyFile(scalars[iface+".private_key_file"]); err != nil {
		return err
	}
	if scalars[iface+".nohostroute"] != "1" {
		return errors.New("amneziawg interface nohostroute must be 1")
	}
	if scalars[iface+".routerd_digest"] != plan.Digest {
		return errors.New("routerd digest option must match the operation plan digest")
	}
	if _, exists := deletes[iface+".addresses"]; !exists {
		return errors.New("operation plan must replace interface addresses")
	}
	for _, stale := range []string{iface + ".private_key", iface + ".fwmark", peer + ".preshared_key", peer + ".persistent_keepalive"} {
		if _, exists := deletes[stale]; !exists {
			return fmt.Errorf("operation plan must delete stale option %s", stale)
		}
	}
	if err := validateDeleteOrdering(iface, peer, firstWrite, deleteAt); err != nil {
		return err
	}
	if err := validateAddresses(lists[iface+".addresses"]); err != nil {
		return err
	}
	if err := validateAWGScalars(iface, scalars); err != nil {
		return err
	}
	if err := validateWireGuardKey("public key", scalars[peer+".public_key"]); err != nil {
		return err
	}
	endpoint, err := netip.ParseAddr(scalars[peer+".endpoint_host"])
	if err != nil || !publicEndpointIP(endpoint) || endpoint.String() != scalars[peer+".endpoint_host"] {
		return errors.New("peer endpoint_host must be a concrete public static IP")
	}
	routePrefix, _ := netip.ParsePrefix(plan.Operations[0].Args[5])
	if routePrefix.Addr() != endpoint {
		return errors.New("endpoint host route must match the amneziawg peer endpoint")
	}
	if port, err := strconv.ParseUint(scalars[peer+".endpoint_port"], 10, 16); err != nil || port == 0 {
		return errors.New("peer endpoint_port must be between 1 and 65535")
	}
	if scalars[peer+".route_allowed_ips"] != "0" {
		return errors.New("peer route_allowed_ips must be 0")
	}
	if _, exists := deletes[peer+".allowed_ips"]; !exists {
		return errors.New("operation plan must replace peer allowed_ips")
	}
	if err := validateAllowedIPs(lists[peer+".allowed_ips"]); err != nil {
		return err
	}
	if keepalive := scalars[peer+".persistent_keepalive"]; keepalive != "" {
		value, err := strconv.ParseUint(keepalive, 10, 16)
		if err != nil || value == 0 {
			return errors.New("persistent_keepalive must be between 1 and 65535 when present")
		}
	}
	return nil
}

func validateSectionOptions(
	iface string,
	peer string,
	scalars map[string]string,
	lists map[string][]string,
	deletes map[string]struct{},
) error {
	ifaceScalar := map[string]struct{}{
		"": {}, "proto": {}, "private_key_file": {}, "nohostroute": {}, "routerd_digest": {},
		"awg_jc": {}, "awg_jmin": {}, "awg_jmax": {}, "awg_s1": {}, "awg_s2": {}, "awg_s3": {}, "awg_s4": {},
		"awg_h1": {}, "awg_h2": {}, "awg_h3": {}, "awg_h4": {}, "awg_i1": {}, "awg_i2": {}, "awg_i3": {}, "awg_i4": {}, "awg_i5": {},
	}
	peerScalar := map[string]struct{}{
		"": {}, "public_key": {}, "endpoint_host": {}, "endpoint_port": {}, "route_allowed_ips": {}, "persistent_keepalive": {},
	}
	for key := range scalars {
		section, option, _ := strings.Cut(key, ".")
		switch section {
		case iface:
			if _, ok := ifaceScalar[option]; !ok {
				return fmt.Errorf("option %s is not valid for the amneziawg interface section", option)
			}
		case peer:
			if _, ok := peerScalar[option]; !ok {
				return fmt.Errorf("option %s is not valid for the amneziawg peer section", option)
			}
		default:
			return fmt.Errorf("UCI section %q is outside the peer plan", section)
		}
	}
	for key := range lists {
		if key != iface+".addresses" && key != peer+".allowed_ips" {
			return fmt.Errorf("list %s is not valid for the amneziawg peer plan", key)
		}
	}
	for key := range deletes {
		if key != iface+".addresses" && key != iface+".private_key" && key != iface+".fwmark" &&
			key != peer+".allowed_ips" && key != peer+".preshared_key" && key != peer+".persistent_keepalive" {
			return fmt.Errorf("delete %s is not valid for the amneziawg peer plan", key)
		}
	}
	return nil
}

func validateDeleteOrdering(iface, peer string, firstWrite, deleteAt map[string]int) error {
	for _, key := range []string{iface + ".addresses", peer + ".allowed_ips"} {
		deleteIndex, deleted := deleteAt[key]
		writeIndex, written := firstWrite[key]
		if !deleted || !written {
			continue
		}
		if deleteIndex > writeIndex {
			return fmt.Errorf("UCI list %s must be deleted before add_list", key)
		}
	}
	for _, dependency := range []struct {
		deleteKey string
		writeKey  string
	}{
		{deleteKey: iface + ".private_key", writeKey: iface + ".private_key_file"},
		{deleteKey: peer + ".persistent_keepalive", writeKey: peer + ".persistent_keepalive"},
	} {
		deleteIndex, deleted := deleteAt[dependency.deleteKey]
		writeIndex, written := firstWrite[dependency.writeKey]
		if deleted && written && deleteIndex > writeIndex {
			return fmt.Errorf("stale option %s must be deleted before writing %s", dependency.deleteKey, dependency.writeKey)
		}
	}
	if err := validateStaleDeleteBeforeSectionWrites(iface, iface+".fwmark", firstWrite, deleteAt); err != nil {
		return err
	}
	if err := validateStaleDeleteBeforeSectionWrites(peer, peer+".preshared_key", firstWrite, deleteAt); err != nil {
		return err
	}
	return nil
}

func validateStaleDeleteBeforeSectionWrites(section, staleKey string, firstWrite, deleteAt map[string]int) error {
	deleteIndex, deleted := deleteAt[staleKey]
	if !deleted {
		return nil
	}
	for key, writeIndex := range firstWrite {
		targetSection, option, _ := strings.Cut(key, ".")
		if targetSection != section || option == "" {
			continue
		}
		if deleteIndex > writeIndex {
			return fmt.Errorf("stale option %s must be deleted before writing section %s", staleKey, section)
		}
	}
	return nil
}

func resolveSections(scalars map[string]string) (string, string, error) {
	iface := ""
	peer := ""
	for key, value := range scalars {
		section, option, _ := strings.Cut(key, ".")
		if option != "" {
			continue
		}
		switch {
		case value == "interface":
			if iface != "" {
				return "", "", errors.New("operation plan contains multiple amneziawg interface sections")
			}
			iface = section
		case strings.HasPrefix(value, "amneziawg_"):
			if peer != "" {
				return "", "", errors.New("operation plan contains multiple amneziawg peer sections")
			}
			peer = section
		default:
			return "", "", fmt.Errorf("unsupported UCI section type %q", value)
		}
	}
	if iface == "" || peer == "" {
		return "", "", errors.New("operation plan requires one amneziawg interface and one peer section")
	}
	if scalars[iface+".proto"] != "amneziawg" {
		return "", "", errors.New("interface section must use proto amneziawg")
	}
	if scalars[peer+"."] != "amneziawg_"+iface {
		return "", "", errors.New("peer section type must match amneziawg_<interface>")
	}
	return iface, peer, nil
}

func validateAWGScalars(iface string, scalars map[string]string) error {
	params := AWGParameters{}
	intTargets := map[string]*int{
		"awg_jc": &params.JC, "awg_jmin": &params.JMin, "awg_jmax": &params.JMax,
		"awg_s1": &params.S1, "awg_s2": &params.S2, "awg_s3": &params.S3, "awg_s4": &params.S4,
	}
	for option, target := range intTargets {
		value := scalars[iface+"."+option]
		if value == "" {
			return fmt.Errorf("%s is required", option)
		}
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil || parsed == 0 {
			return fmt.Errorf("%s must be between 1 and 65535", option)
		}
		*target = int(parsed)
	}
	stringTargets := map[string]*string{
		"awg_h1": &params.H1, "awg_h2": &params.H2, "awg_h3": &params.H3, "awg_h4": &params.H4,
		"awg_i1": &params.I1, "awg_i2": &params.I2, "awg_i3": &params.I3, "awg_i4": &params.I4, "awg_i5": &params.I5,
	}
	for option, target := range stringTargets {
		value := scalars[iface+"."+option]
		if value == "" {
			return fmt.Errorf("%s is required", option)
		}
		*target = value
	}
	return params.validate()
}

func validatePrivateKeyFile(value string) error {
	if value == "" {
		return errors.New("private_key_file is required")
	}
	clean := path.Clean(value)
	if value != clean || !strings.HasPrefix(value, "/etc/routerd/secrets/") || strings.Contains(strings.TrimPrefix(value, "/etc/routerd/secrets/"), "/") {
		return errors.New("private_key_file must be confined to /etc/routerd/secrets")
	}
	name := strings.TrimPrefix(value, "/etc/routerd/secrets/")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\`) {
		return errors.New("private_key_file name is invalid")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safeUCIValue(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeUCIOption(value string) bool {
	switch value {
	case "proto", "private_key_file", "nohostroute", "routerd_digest", "addresses",
		"private_key", "fwmark", "preshared_key",
		"awg_jc", "awg_jmin", "awg_jmax", "awg_s1", "awg_s2", "awg_s3", "awg_s4",
		"awg_h1", "awg_h2", "awg_h3", "awg_h4", "awg_i1", "awg_i2", "awg_i3", "awg_i4", "awg_i5",
		"public_key", "endpoint_host", "endpoint_port", "route_allowed_ips", "allowed_ips",
		"persistent_keepalive":
		return true
	default:
		return false
	}
}
