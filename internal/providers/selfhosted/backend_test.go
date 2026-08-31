package selfhosted

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestInspectRejectsConfigChangedAfterPinning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guest.conf")
	original := []byte("[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytesOf(1, 32)) + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	pin := hex.EncodeToString(digest[:])
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Backend{}).Inspect(context.Background(), tunnel.ConfigSource{Path: path, SHA256: pin}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("pinned changed config error = %v", err)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
