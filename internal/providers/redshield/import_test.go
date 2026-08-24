package redshield

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestImportFileWireGuardMetadata(t *testing.T) {
	configText := validConfig(t, "", "0.0.0.0/0, ::/0")
	config := importText(t, configText)
	metadata := config.Metadata()

	if metadata.Provider != "redshield" || metadata.Transport != tunnel.TransportWireGuard {
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
			if _, err := ImportFile(path); err == nil {
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

	config, err := ImportFile(path)
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
	_, err = ImportFile(writeConfig(t, bad))
	if err == nil {
		t.Fatal("expected invalid key error")
	}
	assertNoLeak(t, err.Error(), badSecret)

	unknownSecret := "THIS_UNKNOWN_FIELD_NAME_MUST_NOT_APPEAR"
	bad = strings.Replace(text, "MTU = 1420", unknownSecret+" = value", 1)
	_, err = ImportFile(writeConfig(t, bad))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	assertNoLeak(t, err.Error(), unknownSecret, "value")
}

func TestSecretHoldersUseFixedRedactionForFormatVerbs(t *testing.T) {
	config := importText(t, validConfig(t, "", "0.0.0.0/0, ::/0"))
	holders := []struct {
		name  string
		value any
		want  string
	}{
		{name: "config value", value: config, want: "redshield.Config{key_material:[REDACTED]}"},
		{name: "config pointer", value: &config, want: "redshield.Config{key_material:[REDACTED]}"},
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
	if _, err := ImportFile("relative.conf"); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := ImportFile(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(t.TempDir(), "large.conf")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportFile(path); err == nil {
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
	if _, err := ImportFile(filepath.Join(symlinkParent, filepath.Base(configPath))); err == nil {
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
	config, err := ImportFile(writeConfig(t, text))
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
