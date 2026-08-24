package servers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	BundleSchemaVersion = 1
	MaxBundleBytes      = 64 * 1024
	MaxArtifacts        = 16
	MaxArtifactBytes    = 128 * 1024 * 1024
)

type Bundle struct {
	SchemaVersion    int             `json:"schema_version"`
	SanitizedExample bool            `json:"sanitized_example,omitempty"`
	BundleID         string          `json:"bundle_id"`
	ServerID         string          `json:"server_id"`
	Target           Target          `json:"target"`
	Endpoint         Endpoint        `json:"endpoint"`
	Adapter          Adapter         `json:"adapter"`
	RecoveryAccount  RecoveryAccount `json:"recovery_account"`
	Tunnel           Tunnel          `json:"tunnel"`
	AWGParameters    AWGParameters   `json:"awg_parameters"`
	Secrets          SecretRefs      `json:"secrets"`
	Artifacts        []Artifact      `json:"artifacts"`

	digest            string
	semanticSeal      string
	artifactBaseDir   string
	artifactsVerified bool
}

type Target struct {
	OSFamily string `json:"os_family"`
	Arch     string `json:"arch"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type Adapter struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type RecoveryAccount struct {
	User string `json:"user"`
}

type Tunnel struct {
	InterfaceName       string `json:"interface_name"`
	ListenPort          uint16 `json:"listen_port"`
	ServerTunnelPrefix  string `json:"server_tunnel_prefix"`
	RouterPeerAddress   string `json:"router_peer_address"`
	RouterPeerPublicKey string `json:"router_peer_public_key"`
}

type AWGParameters struct {
	JC   uint16 `json:"jc"`
	JMin uint16 `json:"jmin"`
	JMax uint16 `json:"jmax"`
	S1   uint16 `json:"s1"`
	S2   uint16 `json:"s2"`
	S3   uint16 `json:"s3"`
	S4   uint16 `json:"s4"`
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

type SecretRefs struct {
	AWGPrivateKey string `json:"awg_private_key_ref"`
	SSHDeployKey  string `json:"ssh_deploy_key_ref"`
}

type Artifact struct {
	Role      string `json:"role"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type VerifyOptions struct {
	BaseDir         string
	PinnedAdapterID string
}

var identifierRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,63}$`)

func LoadBundle(bundlePath string, options VerifyOptions) (Bundle, error) {
	if !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
		return Bundle{}, errors.New("bundle path must be an absolute clean path")
	}
	info, err := os.Lstat(bundlePath)
	if err != nil {
		return Bundle{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Bundle{}, errors.New("bundle must be a regular non-symlink file")
	}
	if info.Size() > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes)
	}
	root, err := os.OpenRoot(filepath.Dir(bundlePath))
	if err != nil {
		return Bundle{}, err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(bundlePath))
	if err != nil {
		return Bundle{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Bundle{}, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return Bundle{}, errors.New("bundle changed between path validation and open")
	}
	return ParseBundle(io.LimitReader(file, MaxBundleBytes+1), options)
}

func ParseBundle(reader io.Reader, options VerifyOptions) (Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBundleBytes+1))
	if err != nil {
		return Bundle{}, err
	}
	if len(data) > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle exceeds %d bytes", MaxBundleBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, err
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(data)
	bundle.digest = hex.EncodeToString(sum[:])
	if err := bundle.Validate(options); err != nil {
		return Bundle{}, err
	}
	bundle.semanticSeal, err = semanticBundleDigest(bundle)
	if err != nil {
		return Bundle{}, err
	}
	if options.BaseDir != "" {
		if err := bundle.VerifyArtifacts(options.BaseDir); err != nil {
			return Bundle{}, err
		}
		bundle.artifactsVerified = true
	}
	return bundle, nil
}

func (bundle Bundle) Digest() string {
	return bundle.digest
}

func (bundle Bundle) ArtifactsVerified() bool {
	return bundle.artifactsVerified
}

func (bundle Bundle) ArtifactBaseDir() string {
	return bundle.artifactBaseDir
}

func (bundle Bundle) deploymentCopy() (Bundle, error) {
	copy := bundle
	copy.Artifacts = append([]Artifact(nil), bundle.Artifacts...)
	if copy.semanticSeal == "" {
		return Bundle{}, errors.New("verified bundle semantic seal is required")
	}
	seal, err := semanticBundleDigest(copy)
	if err != nil {
		return Bundle{}, err
	}
	if seal != copy.semanticSeal {
		return Bundle{}, errors.New("bundle content changed after verification")
	}
	return copy, nil
}

func semanticBundleDigest(bundle Bundle) (string, error) {
	data, err := json.Marshal(bundle)
	if err != nil {
		return "", fmt.Errorf("seal bundle content: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (bundle Bundle) Validate(options VerifyOptions) error {
	if bundle.SchemaVersion != BundleSchemaVersion {
		return fmt.Errorf("unsupported bundle schema_version %d", bundle.SchemaVersion)
	}
	for field, value := range map[string]string{
		"bundle_id":       bundle.BundleID,
		"server_id":       bundle.ServerID,
		"adapter.id":      bundle.Adapter.ID,
		"adapter.version": bundle.Adapter.Version,
		"recovery.user":   bundle.RecoveryAccount.User,
		"tunnel.iface":    bundle.Tunnel.InterfaceName,
	} {
		if err := validateIdentifier(field, value); err != nil {
			return err
		}
	}
	if err := validateTarget(bundle.Target); err != nil {
		return err
	}
	if options.PinnedAdapterID == "" {
		return errors.New("pinned adapter ID is required")
	}
	if bundle.Adapter.ID != options.PinnedAdapterID {
		return fmt.Errorf("adapter id %q does not match pinned adapter %q", bundle.Adapter.ID, options.PinnedAdapterID)
	}
	if err := validateEndpoint(bundle.Endpoint, bundle.SanitizedExample); err != nil {
		return err
	}
	if err := validateTunnel(bundle.Tunnel); err != nil {
		return err
	}
	if err := validateAWGParameters(bundle.AWGParameters); err != nil {
		return err
	}
	if err := validateSecretRefs(bundle.Secrets); err != nil {
		return err
	}
	if len(bundle.Artifacts) > MaxArtifacts {
		return fmt.Errorf("artifact count exceeds %d", MaxArtifacts)
	}
	seenNames := make(map[string]struct{}, len(bundle.Artifacts))
	seenPaths := make(map[string]struct{}, len(bundle.Artifacts))
	seenRoles := make(map[string]struct{}, len(mandatoryArtifactRoles()))
	for i, artifact := range bundle.Artifacts {
		if err := validateArtifact(i, artifact); err != nil {
			return err
		}
		if _, exists := seenNames[artifact.Name]; exists {
			return fmt.Errorf("duplicate artifact %q", artifact.Name)
		}
		seenNames[artifact.Name] = struct{}{}
		if _, exists := seenPaths[artifact.Path]; exists {
			return fmt.Errorf("duplicate artifact path %q", artifact.Path)
		}
		seenPaths[artifact.Path] = struct{}{}
		if _, exists := seenRoles[artifact.Role]; exists {
			return fmt.Errorf("duplicate artifact role %q", artifact.Role)
		}
		seenRoles[artifact.Role] = struct{}{}
	}
	for _, role := range mandatoryArtifactRoles() {
		if _, exists := seenRoles[role]; !exists {
			return fmt.Errorf("mandatory artifact role %q is missing", role)
		}
	}
	return nil
}

func (bundle *Bundle) VerifyArtifacts(baseDir string) error {
	if bundle == nil {
		return errors.New("bundle is required")
	}
	if !filepath.IsAbs(baseDir) || filepath.Clean(baseDir) != baseDir {
		return errors.New("artifact base directory must be an absolute clean path")
	}
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return fmt.Errorf("resolve artifact base directory: %w", err)
	}
	for _, artifact := range bundle.Artifacts {
		fullPath := filepath.Join(baseDir, filepath.FromSlash(artifact.Path))
		cleanBase := filepath.Clean(baseDir)
		cleanPath := filepath.Clean(fullPath)
		if cleanPath != fullPath || !strings.HasPrefix(cleanPath+string(os.PathSeparator), cleanBase+string(os.PathSeparator)) {
			return fmt.Errorf("artifact %q escapes base directory", artifact.Name)
		}
		resolvedPath, err := filepath.EvalSymlinks(cleanPath)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.Name, err)
		}
		if !pathWithin(resolvedBase, resolvedPath) {
			return fmt.Errorf("artifact %q escapes resolved base directory", artifact.Name)
		}
		info, err := os.Lstat(cleanPath)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.Name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("artifact %q must be a regular non-symlink file", artifact.Name)
		}
		if info.Size() != artifact.SizeBytes {
			return fmt.Errorf("artifact %q size mismatch: got %d want %d", artifact.Name, info.Size(), artifact.SizeBytes)
		}
		if info.Size() > MaxArtifactBytes {
			return fmt.Errorf("artifact %q exceeds %d bytes", artifact.Name, MaxArtifactBytes)
		}
		file, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.Name, err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
			changeErr := fmt.Errorf("artifact %q changed between path validation and open", artifact.Name)
			if closeErr := file.Close(); closeErr != nil {
				return errors.Join(changeErr, closeErr)
			}
			return changeErr
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, io.LimitReader(file, MaxArtifactBytes+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if got := hex.EncodeToString(hash.Sum(nil)); got != strings.ToLower(artifact.SHA256) {
			return fmt.Errorf("artifact %q sha256 mismatch", artifact.Name)
		}
	}
	bundle.artifactBaseDir = resolvedBase
	bundle.artifactsVerified = true
	return nil
}

func pathWithin(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra struct{}
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	}
	return errors.New("trailing JSON is not allowed")
}

func validateTarget(target Target) error {
	switch target.OSFamily {
	case "debian", "ubuntu":
	default:
		return errors.New("target.os_family must be debian or ubuntu")
	}
	switch target.Arch {
	case "amd64", "arm64":
	default:
		return errors.New("target.arch must be amd64 or arm64")
	}
	return nil
}

func validateEndpoint(endpoint Endpoint, allowDocumentation bool) error {
	addr, err := netip.ParseAddr(endpoint.IP)
	if err != nil {
		return fmt.Errorf("endpoint.ip must be a concrete IP address: %w", err)
	}
	if endpoint.IP != addr.String() || !deployablePublicIP(addr) && !(allowDocumentation && documentationIP(addr)) {
		return errors.New("endpoint.ip must be a canonical public static IP address")
	}
	if endpoint.Port == 0 {
		return errors.New("endpoint.port is required")
	}
	return nil
}

func deployablePublicIP(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.Is4In6() {
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

func validateTunnel(tunnel Tunnel) error {
	if tunnel.ListenPort == 0 {
		return errors.New("tunnel.listen_port is required")
	}
	prefix, err := netip.ParsePrefix(tunnel.ServerTunnelPrefix)
	if err != nil {
		return fmt.Errorf("tunnel.server_tunnel_prefix must be an IP prefix: %w", err)
	}
	if !prefix.IsValid() || prefix != prefix.Masked() || !prefix.Addr().IsPrivate() || prefix.Addr().Is4In6() {
		return errors.New("tunnel.server_tunnel_prefix must be a canonical private prefix")
	}
	address, err := netip.ParseAddr(tunnel.RouterPeerAddress)
	if err != nil {
		return fmt.Errorf("tunnel.router_peer_address must be an IP address: %w", err)
	}
	if address.String() != tunnel.RouterPeerAddress || address.Is4In6() || !address.IsPrivate() || !prefix.Contains(address) || address == prefix.Addr() {
		return errors.New("tunnel.router_peer_address must belong to server_tunnel_prefix")
	}
	decoded, err := base64.StdEncoding.DecodeString(tunnel.RouterPeerPublicKey)
	if err != nil || len(decoded) != 32 {
		return errors.New("tunnel.router_peer_public_key must be a 32-byte public key")
	}
	if containsSecretMaterial(tunnel.RouterPeerPublicKey) {
		return errors.New("tunnel.router_peer_public_key contains secret material")
	}
	return nil
}

func validateAWGParameters(params AWGParameters) error {
	if params.JC == 0 || params.JMin == 0 || params.JMax == 0 || params.JMin > params.JMax {
		return errors.New("awg_parameters jitter values must be pinned and valid")
	}
	for name, value := range map[string]uint16{
		"s1": params.S1,
		"s2": params.S2,
		"s3": params.S3,
		"s4": params.S4,
	} {
		if value == 0 {
			return fmt.Errorf("awg_parameters.%s must be pinned", name)
		}
	}
	for name, value := range map[string]string{
		"h1": params.H1,
		"h2": params.H2,
		"h3": params.H3,
		"h4": params.H4,
	} {
		if err := validateAWGPair(name, value); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{
		"i1": params.I1,
		"i2": params.I2,
		"i3": params.I3,
		"i4": params.I4,
		"i5": params.I5,
	} {
		if !validAWGInstruction(value) {
			return fmt.Errorf("awg_parameters.%s must be a pinned AWG instruction", name)
		}
	}
	return nil
}

func validateAWGPair(name, value string) error {
	left, right, ok := strings.Cut(value, "-")
	if !ok || left == "" || right == "" {
		return fmt.Errorf("awg_parameters.%s must contain two uint32 values", name)
	}
	for _, part := range []string{left, right} {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return fmt.Errorf("awg_parameters.%s must contain two uint32 values", name)
		}
	}
	return nil
}

func validAWGInstruction(value string) bool {
	if len(value) < 5 || len(value) > 64 || value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}
	for _, character := range value[1 : len(value)-1] {
		if character != ' ' && character != '-' && character != '_' && character != '.' &&
			(character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return !containsSecretMaterial(value)
}

func validateSecretRefs(secrets SecretRefs) error {
	for field, value := range map[string]string{
		"secrets.awg_private_key_ref": secrets.AWGPrivateKey,
		"secrets.ssh_deploy_key_ref":  secrets.SSHDeployKey,
	} {
		if err := validateSecretRef(field, value); err != nil {
			return err
		}
	}
	return nil
}

func validateSecretRef(field, value string) error {
	if strings.Contains(value, "/") || strings.Contains(value, `\`) || strings.Contains(value, "..") {
		return fmt.Errorf("%s must be a secret identifier, not a path", field)
	}
	if containsSecretMaterial(value) {
		return fmt.Errorf("%s contains secret material", field)
	}
	return validateIdentifier(field, value)
}

func validateArtifact(index int, artifact Artifact) error {
	if !validArtifactRole(artifact.Role) {
		return fmt.Errorf("artifacts[%d].role must be one of the mandatory artifact roles", index)
	}
	if err := validateIdentifier(fmt.Sprintf("artifacts[%d].name", index), artifact.Name); err != nil {
		return err
	}
	if artifact.Path == "" || path.IsAbs(artifact.Path) || path.Clean(artifact.Path) != artifact.Path || strings.HasPrefix(artifact.Path, "..") {
		return fmt.Errorf("artifact %q path must be relative, clean, and confined", artifact.Name)
	}
	if strings.Contains(artifact.Path, `\`) {
		return fmt.Errorf("artifact %q path must use slash-separated relative form", artifact.Name)
	}
	if artifact.SizeBytes <= 0 || artifact.SizeBytes > MaxArtifactBytes {
		return fmt.Errorf("artifact %q has invalid size_bytes", artifact.Name)
	}
	decoded, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(decoded) != sha256.Size || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
		return fmt.Errorf("artifact %q has invalid sha256", artifact.Name)
	}
	return nil
}

func mandatoryArtifactRoles() []string {
	return []string{"server-agent", "awg-adapter", "systemd-unit", "nftables", "sysctl", "sshd-policy"}
}

func validArtifactRole(role string) bool {
	for _, mandatory := range mandatoryArtifactRoles() {
		if role == mandatory {
			return true
		}
	}
	return false
}

func validateIdentifier(field, value string) error {
	if !identifierRE.MatchString(value) || containsSecretMaterial(value) {
		return fmt.Errorf("%s must be a non-secret identifier", field)
	}
	return nil
}

func containsSecretMaterial(value string) bool {
	normalized := strings.ToLower(value)
	for _, marker := range []string{
		"private key",
		"begin ",
		"password",
		"passwd",
		"token=",
		"secret=",
		"-----",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
