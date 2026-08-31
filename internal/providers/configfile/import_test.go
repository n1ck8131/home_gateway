package configfile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestInterfacePublicFingerprintSHA256DerivesX25519PublicBytes(t *testing.T) {
	config := importText(t, validConfig(t, "", "0.0.0.0/0"))
	privateBytes, err := base64.StdEncoding.DecodeString(syntheticKey(1))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(privateKey.PublicKey().Bytes())
	want := hex.EncodeToString(digest[:])
	got := config.InterfacePublicFingerprintSHA256()
	if got != want || got == hex.EncodeToString(privateBytes) || strings.Contains(fmt.Sprintf("%#v", config), syntheticKey(1)) {
		t.Fatalf("public fingerprint contract differs: got=%q want=%q", got, want)
	}
	if !bytes.Equal(config.privateKey.bytes[:], make([]byte, len(config.privateKey.bytes))) {
		t.Fatal("private key buffer was not cleared after fingerprint derivation")
	}
}

func TestImportFilePinnedBindsParsedBytesToLowercaseSHA256(t *testing.T) {
	path := writeConfig(t, validConfig(t, "", "0.0.0.0/0, ::/0"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	pin := hex.EncodeToString(digest[:])
	if _, err := ImportFilePinned(path, pin, "selfhosted"); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	replaced := strings.Replace(string(data), syntheticKey(1), syntheticKey(3), 1)
	if err := os.WriteFile(path, []byte(replaced), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportFilePinned(path, pin, "selfhosted"); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("same-metadata config with replaced key result = %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"different": strings.Repeat("0", 64),
		"uppercase": strings.ToUpper(pin),
		"short":     pin[:63],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ImportFilePinned(path, value, "selfhosted"); err == nil {
				t.Fatal("invalid or mismatched config pin was accepted")
			}
		})
	}
}

func TestImportFileWireGuardMetadata(t *testing.T) {
	configText := validConfig(t, "", "0.0.0.0/0, ::/0")
	config := importText(t, configText)
	metadata := config.Metadata()

	if metadata.Provider != "selfhosted" || metadata.Transport != tunnel.TransportWireGuard {
		t.Fatalf("unexpected identity: %#v", metadata)
	}
	if metadata.Endpoint.Host != "vpn.example.test" || metadata.Endpoint.Port != 51820 {
		t.Fatalf("unexpected endpoint: %#v", metadata.Endpoint)
	}
	if !metadata.IPv4FullTunnel || !metadata.IPv6FullTunnel {
		t.Fatalf("full-tunnel families not detected: %#v", metadata)
	}
	if got := strings.Join(metadata.InterfaceAddresses, ","); got != "10.20.30.2/32,fd00::2/128" {
		t.Fatalf("interface addresses = %q", got)
	}
	if got := strings.Join(metadata.DNS, ","); got != "10.20.30.1,fd00::1" {
		t.Fatalf("DNS = %q", got)
	}
	if metadata.MTU != 1420 {
		t.Fatalf("MTU = %d", metadata.MTU)
	}
}

func TestImportFileAmneziaWGMetadata(t *testing.T) {
	awg := strings.Join([]string{
		"Jc = 4",
		"Jmin = 40",
		"Jmax = 70",
		"S1 = 0",
		"S2 = 0",
		"H1 = 1",
		"H2 = 2",
		"H3 = 3",
		"H4 = 4",
	}, "\n")
	config := importText(t, validConfig(t, awg, "0.0.0.0/0"))

	if config.Metadata().Transport != tunnel.TransportAmneziaWG {
		t.Fatalf("transport = %q", config.Metadata().Transport)
	}
	if !config.Metadata().IPv4FullTunnel || config.Metadata().IPv6FullTunnel {
		t.Fatalf("unexpected family flags: %#v", config.Metadata())
	}
}

func TestImportFileAcceptsEveryAmneziaWG31InterfaceField(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "Jc minimum", field: "Jc", value: "0"},
		{name: "Jmin maximum", field: "Jmin", value: "65535"},
		{name: "Jmax", field: "Jmax", value: "65535"},
		{name: "S1", field: "S1", value: "1"},
		{name: "S2", field: "S2", value: "2"},
		{name: "S3", field: "S3", value: "3"},
		{name: "S4", field: "S4", value: "4"},
		{name: "H1 single", field: "H1", value: "0"},
		{name: "H2 range", field: "H2", value: "25-35"},
		{name: "H3 uint32 maximum", field: "H3", value: "4294967295"},
		{name: "H4 uint32 maximum range", field: "H4", value: "0-4294967295"},
		{name: "ContentPaddingAddition single", field: "ContentPaddingAddition", value: "0"},
		{name: "RekeyAfterTime range", field: "RekeyAfterTime", value: "25-35"},
		{name: "RekeyTimeout maximum", field: "RekeyTimeout", value: "65535"},
		{name: "RejectAfterTime", field: "RejectAfterTime", value: "1-2"},
		{name: "KeepaliveTimeout", field: "KeepaliveTimeout", value: "3"},
		{name: "MaxHandshakeAttempts", field: "MaxHandshakeAttempts", value: "4-5"},
		{name: "I1 byte tag", field: "I1", value: "<b 0x0102>"},
		{name: "I2 random tag", field: "I2", value: "<r 2>"},
		{name: "I3 random data tag", field: "I3", value: "<rd 4>"},
		{name: "I4 random char tag", field: "I4", value: "<rc 4>"},
		{name: "I5 tag sequence", field: "I5", value: "<t><r 3><b 0xaB>"},
		{name: "HeaderProtectionKey", field: "HeaderProtectionKey", value: syntheticKey(9)},
		{name: "RandomTrailers true", field: "RandomTrailers", value: "true"},
		{name: "DisableCookies false", field: "DisableCookies", value: "false"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := importText(t, validConfig(t, test.field+" = "+test.value, "0.0.0.0/0"))
			if config.Metadata().Transport != tunnel.TransportAmneziaWG {
				t.Fatalf("transport = %q", config.Metadata().Transport)
			}
		})
	}
}

func TestImportFileAcceptsCanonicalPersistentKeepaliveValues(t *testing.T) {
	for _, value := range []string{"0", "25", "65535", "25-35", "0-65535"} {
		t.Run(value, func(t *testing.T) {
			text := strings.Replace(validConfig(t, "", "0.0.0.0/0"), "PersistentKeepalive = 25", "PersistentKeepalive = "+value, 1)
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err != nil {
				t.Fatalf("canonical keepalive %q rejected: %v", value, err)
			}
		})
	}
}

func TestImportFileRejectsNonCanonicalAmneziaWG31Values(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "empty present", field: "Jc", value: ""},
		{name: "integer plus", field: "Jc", value: "+1"},
		{name: "integer leading zero", field: "S4", value: "01"},
		{name: "integer non ASCII", field: "Jmax", value: "１"},
		{name: "integer overflow", field: "Jmin", value: "65536"},
		{name: "integer range forbidden", field: "S1", value: "1-2"},
		{name: "uint32 plus", field: "H1", value: "+1"},
		{name: "uint32 leading zero", field: "H2", value: "01"},
		{name: "uint32 reversed", field: "H3", value: "2-1"},
		{name: "uint32 overflow", field: "H4", value: "4294967296"},
		{name: "uint32 range overflow", field: "H1", value: "1-4294967296"},
		{name: "uint32 malformed", field: "H2", value: "1-2-3"},
		{name: "uint32 non ASCII", field: "H3", value: "１"},
		{name: "uint16 plus", field: "RekeyAfterTime", value: "+1"},
		{name: "uint16 leading zero", field: "RekeyTimeout", value: "01"},
		{name: "uint16 reversed", field: "RejectAfterTime", value: "2-1"},
		{name: "uint16 overflow", field: "KeepaliveTimeout", value: "65536"},
		{name: "uint16 range overflow", field: "MaxHandshakeAttempts", value: "1-65536"},
		{name: "uint16 malformed", field: "ContentPaddingAddition", value: "1-2-3"},
		{name: "uint16 non ASCII", field: "RekeyAfterTime", value: "１"},
		{name: "opaque empty", field: "I1", value: ""},
		{name: "opaque unclosed", field: "I2", value: "<r 2"},
		{name: "opaque unknown tag", field: "I3", value: "<x 2>"},
		{name: "opaque embedded whitespace", field: "I4", value: "<t> <r 2>"},
		{name: "opaque non ASCII number", field: "I5", value: "<r ２>"},
		{name: "opaque odd byte hex", field: "I1", value: "<b 0x0>"},
		{name: "opaque uppercase hex prefix", field: "I2", value: "<b 0X0102>"},
		{name: "opaque oversized", field: "I3", value: strings.Repeat("<t>", 1366)},
		{name: "header key malformed", field: "HeaderProtectionKey", value: "not-a-key"},
		{name: "random trailers uppercase", field: "RandomTrailers", value: "True"},
		{name: "disable cookies numeric", field: "DisableCookies", value: "1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			text := validConfig(t, test.field+" = "+test.value, "0.0.0.0/0")
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err == nil {
				t.Fatalf("invalid %s value %q accepted", test.field, test.value)
			}
		})
	}
}

func TestImportFileRejectsNonCanonicalPersistentKeepaliveValues(t *testing.T) {
	for _, value := range []string{"", "+1", "01", "１", "2-1", "65536", "1-65536", "1-2-3", "-1"} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			text := strings.Replace(validConfig(t, "", "0.0.0.0/0"), "PersistentKeepalive = 25", "PersistentKeepalive = "+value, 1)
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err == nil {
				t.Fatalf("invalid keepalive %q accepted", value)
			}
		})
	}
}

func TestImportFileRejectsEveryDuplicateAWGFieldMultiplePeersAndUnsafeDirective(t *testing.T) {
	for _, field := range []string{
		"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
		"ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
		"I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "RandomTrailers", "DisableCookies",
	} {
		t.Run("duplicate "+field, func(t *testing.T) {
			value := "1"
			switch {
			case strings.HasPrefix(field, "I"):
				value = "<t>"
			case field == "HeaderProtectionKey":
				value = syntheticKey(8)
			case field == "RandomTrailers" || field == "DisableCookies":
				value = "true"
			}
			text := validConfig(t, field+" = "+value+"\n"+field+" = "+value, "0.0.0.0/0")
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err == nil {
				t.Fatalf("duplicate %s accepted", field)
			}
		})
	}

	base := validConfig(t, "", "0.0.0.0/0")
	peer := strings.Split(base, "[Peer]")[1]
	if _, err := ImportFile(writeConfig(t, base+"[Peer]"+peer), "selfhosted"); err == nil {
		t.Fatal("multiple peers accepted")
	}
	for _, directive := range []string{"Table", "PreUp", "PostUp", "PreDown", "PostDown"} {
		t.Run("unsafe "+directive, func(t *testing.T) {
			text := strings.Replace(base, "MTU = 1420", directive+" = synthetic", 1)
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err == nil {
				t.Fatalf("unsafe directive %s accepted", directive)
			}
		})
	}
}

func TestImportFileRejectsMalformedKeysInEveryKeyField(t *testing.T) {
	for _, field := range []string{"PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey"} {
		t.Run(field, func(t *testing.T) {
			text := validConfig(t, "", "0.0.0.0/0")
			switch field {
			case "PrivateKey":
				text = strings.Replace(text, syntheticKey(1), "not-a-key", 1)
			case "PublicKey":
				text = strings.Replace(text, syntheticKey(2), "not-a-key", 1)
			case "PresharedKey":
				text = strings.Replace(text, "[Peer]", "[Peer]\nPresharedKey = not-a-key", 1)
			case "HeaderProtectionKey":
				text = strings.Replace(text, "[Peer]", "HeaderProtectionKey = not-a-key\n[Peer]", 1)
			}
			if _, err := ImportFile(writeConfig(t, text), "selfhosted"); err == nil {
				t.Fatalf("malformed %s accepted", field)
			}
		})
	}
}

func TestImportFileRejectsMalformedDuplicateUnknownAndUnsafeFields(t *testing.T) {
	privateKey := syntheticKey(1)
	publicKey := syntheticKey(2)
	tests := map[string]string{
		"duplicate section": fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.2/32\n[Interface]\nAddress = 10.0.0.3/32\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n", privateKey, publicKey),
		"duplicate field":   strings.Replace(validConfig(t, "", "0.0.0.0/0"), "Address =", "Address = 10.0.0.9/32\nAddress =", 1),
		"unknown field":     strings.Replace(validConfig(t, "", "0.0.0.0/0"), "MTU = 1420", "UnknownOption = true", 1),
		"unsafe script":     strings.Replace(validConfig(t, "", "0.0.0.0/0"), "MTU = 1420", "PostUp = powershell something", 1),
		"unsafe table":      strings.Replace(validConfig(t, "", "0.0.0.0/0"), "MTU = 1420", "Table = off", 1),
		"missing peer":      strings.Split(validConfig(t, "", "0.0.0.0/0"), "[Peer]")[0],
		"bad private key":   strings.Replace(validConfig(t, "", "0.0.0.0/0"), privateKey, "not-a-key", 1),
		"bad endpoint":      strings.Replace(validConfig(t, "", "0.0.0.0/0"), "vpn.example.test:51820", "https://vpn.example.test", 1),
		"bad address":       strings.Replace(validConfig(t, "", "0.0.0.0/0"), "10.20.30.2/32", "not-an-address", 1),
		"bad DNS":           strings.Replace(validConfig(t, "", "0.0.0.0/0"), "10.20.30.1, fd00::1", "resolver.example.test", 1),
		"bad MTU":           strings.Replace(validConfig(t, "", "0.0.0.0/0"), "MTU = 1420", "MTU = 1", 1),
		"inline script":     strings.Replace(validConfig(t, "", "0.0.0.0/0"), "MTU = 1420", "MTU = 1420 ; PostUp = command", 1),
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, text)
			if _, err := ImportFile(path, "selfhosted"); err == nil {
				t.Fatal("expected import failure")
			}
		})
	}
}

func TestImportFileErrorsAndSerializationDoNotLeakSecrets(t *testing.T) {
	privateKey := syntheticKey(11)
	publicKey := syntheticKey(22)
	presharedKey := syntheticKey(33)
	text := validConfig(t, "", "0.0.0.0/0, ::/0")
	text = strings.Replace(text, syntheticKey(1), privateKey, 1)
	text = strings.Replace(text, syntheticKey(2), publicKey, 1)
	text = strings.Replace(text, "[Peer]", "[Peer]\nPresharedKey = "+presharedKey, 1)
	path := writeConfig(t, text)

	config, err := ImportFile(path, "selfhosted")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v %+v %#v", config, config, config)
	assertNoLeak(t, string(data)+formatted, privateKey, publicKey, presharedKey, path)

	badSecret := "THIS_VALUE_MUST_NEVER_APPEAR"
	bad := strings.Replace(text, privateKey, badSecret, 1)
	_, err = ImportFile(writeConfig(t, bad), "selfhosted")
	if err == nil {
		t.Fatal("expected invalid key error")
	}
	assertNoLeak(t, err.Error(), badSecret)

	unknownSecret := "THIS_UNKNOWN_FIELD_NAME_MUST_NOT_APPEAR"
	bad = strings.Replace(text, "MTU = 1420", unknownSecret+" = value", 1)
	_, err = ImportFile(writeConfig(t, bad), "selfhosted")
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	assertNoLeak(t, err.Error(), unknownSecret, "value")
}

func TestAmneziaOpaqueValuesKeysRawProfileAndPathStayRedactedEverywhere(t *testing.T) {
	privateKey := syntheticKey(41)
	publicKey := syntheticKey(42)
	presharedKey := syntheticKey(43)
	headerKey := syntheticKey(44)
	opaque := "<t><r 983><rd 17><rc 29><b 0x01020304>"
	text := validConfig(t, "I1 = "+opaque+"\nHeaderProtectionKey = "+headerKey, "0.0.0.0/0, ::/0")
	text = strings.Replace(text, syntheticKey(1), privateKey, 1)
	text = strings.Replace(text, syntheticKey(2), publicKey, 1)
	text = strings.Replace(text, "[Peer]", "[Peer]\nPresharedKey = "+presharedKey, 1)
	path := writeConfig(t, text)
	config, err := ImportFile(path, "selfhosted")
	if err != nil {
		t.Fatal(err)
	}
	jsonValue, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{
		config.String(), config.GoString(),
		fmt.Sprintf("%v %+v %#v %s %q %x %d %t", config, config, config, config, config, config, config, config),
		string(jsonValue),
	}
	for _, output := range outputs {
		assertNoLeak(t, output, privateKey, publicKey, presharedKey, headerKey, opaque, text, path, filepath.Base(path))
	}

	badOpaque := opaque + "RAW_OPAQUE_SENTINEL"
	_, err = ImportFile(writeConfig(t, strings.Replace(text, opaque, badOpaque, 1)), "selfhosted")
	if err == nil {
		t.Fatal("malformed opaque value accepted")
	}
	assertNoLeak(t, err.Error(), badOpaque, opaque, "RAW_OPAQUE_SENTINEL")
}

func TestSecretHoldersUseFixedRedactionForFormatVerbs(t *testing.T) {
	config := importText(t, validConfig(t, "", "0.0.0.0/0, ::/0"))
	holders := []struct {
		name  string
		value any
		want  string
	}{
		{name: "config value", value: config, want: "configfile.Config{key_material:[REDACTED]}"},
		{name: "config pointer", value: &config, want: "configfile.Config{key_material:[REDACTED]}"},
		{name: "key value", value: config.privateKey, want: "[REDACTED]"},
		{name: "key pointer", value: &config.privateKey, want: "[REDACTED]"},
	}
	formats := []string{
		"%v", "%+v", "%#v", "%s", "%q",
		"%d", "%o", "%O", "%b", "%x", "%X", "%c", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%t",
		"%20v", "%-20s", "%.3q", "%#+020.8x", "%+12.4d",
	}
	for _, holder := range holders {
		for _, format := range formats {
			if got := fmt.Sprintf(format, holder.value); got != holder.want {
				t.Errorf("%s with %q = %q, want fixed redaction %q", holder.name, format, got, holder.want)
			}
		}
	}
}

func TestImportFileRequiresBoundedRegularAbsolutePath(t *testing.T) {
	if _, err := ImportFile("relative.conf", "selfhosted"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := ImportFile(t.TempDir(), "selfhosted"); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(t.TempDir(), "large.conf")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportFile(path, "selfhosted"); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestImportFileRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(realParent, "synthetic.conf")
	if err := os.WriteFile(configPath, []byte(validConfig(t, "", "0.0.0.0/0")), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(root, "symlink-parent")
	if err := createTestDirectoryLink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportFile(filepath.Join(symlinkParent, filepath.Base(configPath)), "selfhosted"); err == nil {
		t.Fatal("config beneath a symlinked parent was accepted")
	}
}

func TestValidateLocalConfigPathRejectsWindowsUNCAndDeviceNamespaces(t *testing.T) {
	for _, allowed := range []string{`C:\Users\Example\provider.conf`, `D:/configs/provider.conf`, t.TempDir()} {
		if err := validateLocalConfigPath(allowed); err != nil {
			t.Fatalf("local absolute path %q rejected: %v", allowed, err)
		}
	}
	for _, rejected := range []string{
		`\\server\share\provider.conf`,
		`//server/share/provider.conf`,
		`\\?\C:\provider.conf`,
		`\\.\PhysicalDrive0`,
		`\??\C:\provider.conf`,
		`C:relative.conf`,
	} {
		err := validateLocalConfigPath(rejected)
		if err == nil {
			t.Fatalf("unsafe Windows path %q accepted", rejected)
		}
		if strings.Contains(err.Error(), rejected) {
			t.Fatalf("path leaked in validation error: %q", err)
		}
	}
}

func validConfig(t *testing.T, awgFields, allowedIPs string) string {
	t.Helper()
	if awgFields != "" {
		awgFields += "\n"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.20.30.2/32, fd00::2/128
DNS = 10.20.30.1, fd00::1
MTU = 1420
ListenPort = 51821
%s[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = vpn.example.test:51820
PersistentKeepalive = 25
`, syntheticKey(1), awgFields, syntheticKey(2), allowedIPs)
}

func syntheticKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func importText(t *testing.T, text string) Config {
	t.Helper()
	config, err := ImportFile(writeConfig(t, text), "selfhosted")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNoLeak(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if strings.Contains(output, value) {
			t.Fatalf("output leaked forbidden value: %q", output)
		}
	}
}
