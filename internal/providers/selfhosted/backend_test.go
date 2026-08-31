package selfhosted

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vsevo/home-gateway/internal/tunnel"
)

func TestBackendIsInspectionOnly(t *testing.T) {
	capabilities := (Backend{}).Capabilities()
	if !capabilities.InspectConfig || capabilities.ApplyConfig || capabilities.ServerManagement {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}

func TestInspectReturnsOnlyDerivedInterfacePublicFingerprint(t *testing.T) {
	key := func(value byte) string { return base64.StdEncoding.EncodeToString(bytesOf(value, 32)) }
	privateKey := key(1)
	path := filepath.Join(t.TempDir(), "guest.conf")
	config := strings.Join([]string{
		"[Interface]", "PrivateKey = " + privateKey, "Address = 10.0.0.2/32",
		"[Peer]", "PublicKey = " + key(2), "AllowedIPs = 0.0.0.0/0", "Endpoint = vpn.example.test:51820",
	}, "\n")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	inspection, err := (Backend{}).Inspect(context.Background(), tunnel.ConfigSource{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.InterfacePublicFingerprintSHA256) != 64 || inspection.InterfacePublicFingerprintSHA256 == privateKey {
		t.Fatalf("inspection fingerprint differs: %#v", inspection)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
