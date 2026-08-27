package configfile

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestImportFileAcceptsBoundedAWG31FieldsWithoutLeaking(t *testing.T) {
	key := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	text := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.2/32\nJc = 1\nJmin = 2\nJmax = 3\nS1 = 4\nS2 = 5\nS3 = 6\nS4 = 7\nH1 = 1-2\nH2 = 3\nH3 = 4\nH4 = 5\nContentPaddingAddition = 1-2\nRekeyAfterTime = 3\nRekeyTimeout = 4\nRejectAfterTime = 5\nKeepaliveTimeout = 6\nMaxHandshakeAttempts = 7\nI1 = <b 0x1><r 2><rd 3><rc 4><t>\nRandomTrailers = true\nDisableCookies = false\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.invalid:51820\nPersistentKeepalive = 25-35\n", key(1), key(2))
	path := filepath.Join(t.TempDir(), "synthetic.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := ImportFile(path, "selfhosted")
	if err != nil {
		t.Fatal(err)
	}
	if config.Metadata().Provider != "selfhosted" || config.Metadata().Transport != tunnel.TransportAmneziaWG {
		t.Fatalf("metadata = %#v", config.Metadata())
	}
	output := fmt.Sprintf("%v %#v %s", config, config, path)
	if strings.Contains(output, key(1)) || strings.Contains(output, "<b 0x1>") {
		t.Fatal("secret material leaked")
	}
}

func TestImportFileRejectsUnsafeOrInvalidAWG31Values(t *testing.T) {
	for _, value := range []string{"Jc = 65536", "H1 = 4-3", "I1 = <shell x>", "PersistentKeepalive = 65536", "PostUp = powershell"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.conf")
			text := "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n" + value + "\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.invalid:51820\n"
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ImportFile(path, "selfhosted"); err == nil {
				t.Fatal("invalid field accepted")
			}
		})
	}
}

func TestConfigfileOwnsParserWithoutProviderDependency(t *testing.T) {
	data, err := os.ReadFile("import.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "providers/redshield") {
		t.Fatal("configfile parser depends on the compatibility provider")
	}
}

func TestCanonicalAWGIntegerRangesRejectAmbiguousSyntax(t *testing.T) {
	for _, value := range []string{"+1", "01", "1-02", "1-", "-1", "2-1", "4294967296"} {
		if _, err := parseOptionalRange(value, 0, 65535); err == nil {
			t.Fatalf("16-bit value accepted: %q", value)
		}
		if _, err := parseOptionalRange32(value); err == nil {
			t.Fatalf("32-bit value accepted: %q", value)
		}
	}
	if _, err := parseOptionalRange("65536", 0, 65535); err == nil {
		t.Fatal("16-bit overflow accepted")
	}
	for _, value := range []string{"0", "65535", "1-2"} {
		if _, err := parseOptionalRange(value, 0, 65535); err != nil {
			t.Fatalf("16-bit value rejected: %q: %v", value, err)
		}
	}
	for _, value := range []string{"0", "4294967295", "1-2"} {
		if _, err := parseOptionalRange32(value); err != nil {
			t.Fatalf("32-bit value rejected: %q: %v", value, err)
		}
	}
}
