package redshield

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

const maxConfigSize = 64 * 1024

var (
	interfaceFields = map[string]struct{}{
		"PrivateKey": {}, "Address": {}, "DNS": {}, "MTU": {}, "ListenPort": {},
		"Jc": {}, "Jmin": {}, "Jmax": {}, "S1": {}, "S2": {},
		"H1": {}, "H2": {}, "H3": {}, "H4": {},
	}
	peerFields = map[string]struct{}{
		"PublicKey": {}, "PresharedKey": {}, "AllowedIPs": {}, "Endpoint": {}, "PersistentKeepalive": {},
	}
	unsafeFields = map[string]struct{}{
		"table": {}, "preup": {}, "postup": {}, "predown": {}, "postdown": {},
	}
)

type keyMaterial struct {
	bytes [32]byte
}

func (keyMaterial) String() string   { return "[REDACTED]" }
func (keyMaterial) GoString() string { return "redshield.keyMaterial{[REDACTED]}" }
func (keyMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (keyMaterial) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Config retains parsed material only inside the provider package. Callers can
// obtain redacted Metadata but cannot access or serialize key bytes.
type Config struct {
	metadata      tunnel.Metadata
	privateKey    keyMaterial
	peerPublicKey keyMaterial
	presharedKey  *keyMaterial
	listenPort    uint16
	keepalive     uint16
	awgParameters map[string]uint32
}

func (Config) String() string   { return "redshield.Config{key_material:[REDACTED]}" }
func (Config) GoString() string { return "redshield.Config{key_material:[REDACTED]}" }
func (Config) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "redshield.Config{key_material:[REDACTED]}")
}

func (config Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Metadata tunnel.Metadata `json:"metadata"`
	}{Metadata: config.Metadata()})
}

func (config Config) Metadata() tunnel.Metadata {
	metadata := config.metadata
	metadata.InterfaceAddresses = append([]string(nil), metadata.InterfaceAddresses...)
	metadata.AllowedIPs = append([]string(nil), metadata.AllowedIPs...)
	metadata.DNS = append([]string(nil), metadata.DNS...)
	return metadata
}

// ImportFile reads a bounded, regular local file. It never accepts config
// bytes, URLs, commands, or provider key material through process arguments.
func ImportFile(path string) (Config, error) {
	data, err := readBoundedRegularFile(path)
	if err != nil {
		return Config{}, err
	}
	return parse(data)
}

func readBoundedRegularFile(path string) ([]byte, error) {
	if err := validateLocalConfigPath(path); err != nil {
		return nil, err
	}
	if err := validateLocalConfigVolume(path); err != nil {
		return nil, err
	}
	if err := validateConfigAncestors(path); err != nil {
		return nil, err
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("config file cannot be opened")
	}
	unsafeLeaf, err := isLinkOrReparse(path, initial)
	if err != nil {
		return nil, errors.New("config file cannot be inspected")
	}
	if unsafeLeaf || !initial.Mode().IsRegular() {
		return nil, errors.New("config source must be a regular file")
	}
	if initial.Size() > maxConfigSize {
		return nil, errors.New("config file exceeds the size limit")
	}

	// #nosec G304 -- the user-selected absolute local path has every component checked for symlink/reparse traversal before open and after the bounded read; leaf identity and stability are also verified.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("config file cannot be opened")
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameFileSnapshot(initial, opened) {
		return nil, errors.New("config file identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, errors.New("config file cannot be read")
	}
	if len(data) > maxConfigSize {
		return nil, errors.New("config file exceeds the size limit")
	}
	afterRead, err := file.Stat()
	if ancestorErr := validateConfigAncestors(path); ancestorErr != nil {
		return nil, errors.New("config file changed while being read")
	}
	pathAfterRead, pathErr := os.Lstat(path)
	unsafeLeafAfterRead := false
	if pathErr == nil {
		unsafeLeafAfterRead, pathErr = isLinkOrReparse(path, pathAfterRead)
	}
	if err != nil || pathErr != nil || unsafeLeafAfterRead || !pathAfterRead.Mode().IsRegular() ||
		!sameFileSnapshot(opened, afterRead) || !sameFileSnapshot(afterRead, pathAfterRead) || afterRead.Size() != int64(len(data)) {
		return nil, errors.New("config file changed while being read")
	}
	return data, nil
}

func validateConfigAncestors(path string) error {
	for ancestor := filepath.Dir(filepath.Clean(path)); ; {
		info, err := os.Lstat(ancestor)
		if err != nil {
			return errors.New("config source parent cannot be inspected")
		}
		unsafeAncestor, err := isLinkOrReparse(ancestor, info)
		if err != nil {
			return errors.New("config source parent cannot be inspected")
		}
		if unsafeAncestor {
			return errors.New("config source must not traverse a symbolic link or reparse point")
		}
		if !info.IsDir() {
			return errors.New("config source parent must be a directory")
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return nil
		}
		ancestor = parent
	}
}

func validateLocalConfigPath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return errors.New("config source must be an absolute local file path")
	}
	windowsForm := strings.ReplaceAll(path, "/", `\`)
	if strings.HasPrefix(windowsForm, `\\`) || strings.HasPrefix(strings.ToLower(windowsForm), `\??\`) {
		return errors.New("config source must not use a UNC or device namespace")
	}
	if isWindowsDriveAbsolute(path) {
		return nil
	}
	if strings.Contains(path, `\`) || strings.Contains(path, ":") || !filepath.IsAbs(path) {
		return errors.New("config source must be an absolute local file path")
	}
	return nil
}

func isWindowsDriveAbsolute(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' && path[2] != '/' {
		return false
	}
	drive := path[0]
	return drive >= 'A' && drive <= 'Z' || drive >= 'a' && drive <= 'z'
}

func sameFileSnapshot(left, right os.FileInfo) bool {
	return os.SameFile(left, right) && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

type parsedFields struct {
	interfaceValues map[string]string
	peerValues      map[string]string
}

func parse(data []byte) (Config, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return Config{}, errors.New("config contains invalid binary data")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	fields, err := parseFields(data)
	if err != nil {
		return Config{}, err
	}
	return validateFields(fields)
}

func parseFields(data []byte) (parsedFields, error) {
	fields := parsedFields{
		interfaceValues: make(map[string]string),
		peerValues:      make(map[string]string),
	}
	var current map[string]string
	var allowed map[string]struct{}
	interfaceCount := 0
	peerCount := 0

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxConfigSize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch line {
		case "[Interface]":
			interfaceCount++
			if interfaceCount > 1 {
				return parsedFields{}, safeLineError("config contains a duplicate section", lineNumber)
			}
			current = fields.interfaceValues
			allowed = interfaceFields
			continue
		case "[Peer]":
			peerCount++
			if peerCount > 1 {
				return parsedFields{}, safeLineError("config contains a duplicate section", lineNumber)
			}
			current = fields.peerValues
			allowed = peerFields
			continue
		}
		if strings.HasPrefix(line, "[") {
			return parsedFields{}, safeLineError("config contains an unknown section", lineNumber)
		}
		if current == nil {
			return parsedFields{}, safeLineError("config field appears before a section", lineNumber)
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return parsedFields{}, safeLineError("config contains a malformed field", lineNumber)
		}
		if _, unsafe := unsafeFields[strings.ToLower(name)]; unsafe {
			return parsedFields{}, safeLineError("config contains an unsafe directive", lineNumber)
		}
		if _, known := allowed[name]; !known {
			return parsedFields{}, safeLineError("config contains an unknown field", lineNumber)
		}
		if _, duplicate := current[name]; duplicate {
			return parsedFields{}, safeLineError("config contains a duplicate field", lineNumber)
		}
		current[name] = value
	}
	if err := scanner.Err(); err != nil {
		return parsedFields{}, errors.New("config cannot be parsed within the size limit")
	}
	if interfaceCount != 1 || peerCount != 1 {
		return parsedFields{}, errors.New("config requires exactly one Interface and one Peer section")
	}
	return fields, nil
}

func safeLineError(message string, line int) error {
	return fmt.Errorf("%s at line %d", message, line)
}

func validateFields(fields parsedFields) (Config, error) {
	requiredInterface := []string{"PrivateKey", "Address"}
	requiredPeer := []string{"PublicKey", "AllowedIPs", "Endpoint"}
	for _, name := range requiredInterface {
		if fields.interfaceValues[name] == "" {
			return Config{}, errors.New("config is missing a required Interface field")
		}
	}
	for _, name := range requiredPeer {
		if fields.peerValues[name] == "" {
			return Config{}, errors.New("config is missing a required Peer field")
		}
	}

	privateKey, err := parseKey(fields.interfaceValues["PrivateKey"])
	if err != nil {
		return Config{}, errors.New("config contains invalid key material")
	}
	publicKey, err := parseKey(fields.peerValues["PublicKey"])
	if err != nil {
		return Config{}, errors.New("config contains invalid key material")
	}
	var presharedKey *keyMaterial
	if encoded := fields.peerValues["PresharedKey"]; encoded != "" {
		parsed, keyErr := parseKey(encoded)
		if keyErr != nil {
			return Config{}, errors.New("config contains invalid key material")
		}
		presharedKey = &parsed
	}

	addresses, err := parsePrefixList(fields.interfaceValues["Address"], false)
	if err != nil {
		return Config{}, errors.New("config contains invalid interface addresses")
	}
	allowedIPs, err := parsePrefixList(fields.peerValues["AllowedIPs"], true)
	if err != nil {
		return Config{}, errors.New("config contains invalid allowed IP prefixes")
	}
	dns, err := parseDNS(fields.interfaceValues["DNS"])
	if err != nil {
		return Config{}, errors.New("config contains invalid DNS addresses")
	}
	endpoint, err := parseEndpoint(fields.peerValues["Endpoint"])
	if err != nil {
		return Config{}, errors.New("config contains an invalid endpoint")
	}

	mtu, err := parseOptionalInteger(fields.interfaceValues["MTU"], 576, 65535)
	if err != nil {
		return Config{}, errors.New("config contains an invalid MTU")
	}
	listenPort, err := parseOptionalInteger(fields.interfaceValues["ListenPort"], 1, 65535)
	if err != nil {
		return Config{}, errors.New("config contains an invalid listen port")
	}
	keepalive, err := parseOptionalInteger(fields.peerValues["PersistentKeepalive"], 0, 65535)
	if err != nil {
		return Config{}, errors.New("config contains an invalid keepalive")
	}

	awgParameters := make(map[string]uint32)
	for _, name := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} {
		value := fields.interfaceValues[name]
		if value == "" {
			continue
		}
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return Config{}, errors.New("config contains an invalid AmneziaWG parameter")
		}
		awgParameters[name] = uint32(parsed)
	}
	if minimum, hasMinimum := awgParameters["Jmin"]; hasMinimum {
		if maximum, hasMaximum := awgParameters["Jmax"]; hasMaximum && minimum > maximum {
			return Config{}, errors.New("config contains inconsistent AmneziaWG parameters")
		}
	}

	transport := tunnel.TransportWireGuard
	if len(awgParameters) > 0 {
		transport = tunnel.TransportAmneziaWG
	}
	ipv4Full, ipv6Full := fullTunnelFamilies(allowedIPs)
	return Config{
		metadata: tunnel.Metadata{
			Provider:           "redshield",
			Transport:          transport,
			Endpoint:           endpoint,
			InterfaceAddresses: addresses,
			AllowedIPs:         allowedIPs,
			DNS:                dns,
			MTU:                int(mtu),
			IPv4FullTunnel:     ipv4Full,
			IPv6FullTunnel:     ipv6Full,
		},
		privateKey:    privateKey,
		peerPublicKey: publicKey,
		presharedKey:  presharedKey,
		listenPort:    listenPort,
		keepalive:     keepalive,
		awgParameters: awgParameters,
	}, nil
}

func parseKey(encoded string) (keyMaterial, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return keyMaterial{}, errors.New("invalid key")
	}
	var material keyMaterial
	copy(material.bytes[:], decoded)
	clear(decoded)
	return material, nil
}

func parsePrefixList(value string, masked bool) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return nil, errors.New("empty prefix list")
	}
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid prefix")
		}
		if masked {
			prefix = prefix.Masked()
		}
		normalized := prefix.String()
		if _, duplicate := seen[normalized]; duplicate {
			return nil, errors.New("duplicate prefix")
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func parseDNS(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return nil, errors.New("invalid DNS address")
		}
		normalized := address.String()
		if _, duplicate := seen[normalized]; duplicate {
			return nil, errors.New("duplicate DNS address")
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func parseEndpoint(value string) (tunnel.Endpoint, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return tunnel.Endpoint{}, errors.New("invalid endpoint")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return tunnel.Endpoint{}, errors.New("invalid endpoint port")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Is4In6() || address.Zone() != "" {
			return tunnel.Endpoint{}, errors.New("invalid endpoint address")
		}
		host = address.String()
	} else {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !validHostname(host) {
			return tunnel.Endpoint{}, errors.New("invalid endpoint hostname")
		}
	}
	return tunnel.Endpoint{Host: host, Port: uint16(port)}, nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || !isAlphaNumeric(label[0]) || !isAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func isAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func parseOptionalInteger(value string, minimum, maximum uint64) (uint16, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New("integer out of range")
	}
	return uint16(parsed), nil
}

func fullTunnelFamilies(prefixes []string) (bool, bool) {
	var ipv4 bool
	var ipv6 bool
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() != 0 {
			continue
		}
		if prefix.Addr().Is4() {
			ipv4 = true
		} else if prefix.Addr().Is6() {
			ipv6 = true
		}
	}
	return ipv4, ipv6
}
