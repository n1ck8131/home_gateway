package servers

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseBundleRejectsUnknownTrailingAndSecretMaterial(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want string
	}{
		{name: "unknown field", json: strings.Replace(validBundleJSON(t, "payload"), `"artifacts"`, `"private_key":"x","artifacts"`, 1), want: "unknown field"},
		{name: "recovery proof in bundle", json: strings.Replace(validBundleJSON(t, "payload"), `"recovery_account":{"user":"vpnctl"}`, `"recovery_account":{"user":"vpnctl","proven":true}`, 1), want: "unknown field"},
		{name: "trailing", json: validBundleJSON(t, "payload") + `{}`, want: "trailing JSON"},
		{name: "secret ref path", json: strings.Replace(validBundleJSON(t, "payload"), `"awg_private_key_ref":"awg-private-prod"`, `"awg_private_key_ref":"C:\\secret\\key"`, 1), want: "not a path"},
		{name: "secret bytes", json: strings.Replace(validBundleJSON(t, "payload"), `"ssh_deploy_key_ref":"ssh-deploy-prod"`, `"ssh_deploy_key_ref":"-----BEGIN PRIVATE KEY-----"`, 1), want: "secret material"},
		{name: "unsupported PSK ref", json: strings.Replace(validBundleJSON(t, "payload"), `"ssh_deploy_key_ref"`, `"awg_preshared_key_ref":"psk-ref","ssh_deploy_key_ref"`, 1), want: "unknown field"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseBundle(strings.NewReader(test.json), VerifyOptions{PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseBundle() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseBundleValidatesDeployableContract(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want string
	}{
		{name: "target", json: strings.Replace(validBundleJSON(t, "payload"), `"os_family":"ubuntu"`, `"os_family":"freebsd"`, 1), want: "target.os_family"},
		{name: "documentation endpoint", json: strings.Replace(validBundleJSON(t, "payload"), `"9.9.9.9"`, `"203.0.113.10"`, 1), want: "public static"},
		{name: "tunnel public key", json: strings.Replace(validBundleJSON(t, "payload"), `"router_peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="`, `"router_peer_public_key":"short"`, 1), want: "32-byte public key"},
		{name: "router address outside prefix", json: strings.Replace(validBundleJSON(t, "payload"), `"router_peer_address":"10.44.0.2"`, `"router_peer_address":"10.45.0.2"`, 1), want: "server_tunnel_prefix"},
		{name: "AWG public params", json: strings.Replace(validBundleJSON(t, "payload"), `"jc":4`, `"jc":0`, 1), want: "jitter"},
		{name: "complete AWG public params", json: strings.Replace(validBundleJSON(t, "payload"), `"i5":"<b 0x0102>"`, `"i5":""`, 1), want: "pinned AWG instruction"},
		{name: "duplicate artifact path", json: strings.Replace(validBundleJSON(t, "payload"), `"path":"sysctl.bin"`, `"path":"nftables.bin"`, 1), want: "duplicate artifact path"},
		{name: "mandatory roles", json: strings.Replace(validBundleJSON(t, "payload"), `"role":"sysctl"`, `"role":"extra"`, 1), want: "mandatory artifact roles"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseBundle(strings.NewReader(test.json), VerifyOptions{PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseBundle() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseBundleRequiresExplicitAdapterPin(t *testing.T) {
	if _, err := ParseBundle(strings.NewReader(validBundleJSON(t, "payload")), VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "pinned adapter") {
		t.Fatalf("ParseBundle() error = %v, want explicit adapter pin", err)
	}
}

func TestServerBundleExampleMatchesContractWithoutClaimingArtifactVerification(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "server", "bundle.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseBundle(strings.NewReader(string(data)), VerifyOptions{PinnedAdapterID: "amneziawg-linux-systemd"})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ArtifactsVerified() {
		t.Fatal("sanitized example unexpectedly claims local artifact verification")
	}
	if !bundle.SanitizedExample {
		t.Fatal("bundle example must remain explicitly non-deployable")
	}
}

func TestParseBundleRejectsTraversalSymlinkHashAndSize(t *testing.T) {
	base := t.TempDir()
	payload := "payload"
	writeArtifacts(t, base, payload)
	t.Run("success", func(t *testing.T) {
		bundle, err := ParseBundle(strings.NewReader(validBundleJSON(t, payload)), VerifyOptions{
			BaseDir:         base,
			PinnedAdapterID: "amneziawg-linux-systemd",
		})
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Digest() == "" {
			t.Fatal("verified bundle digest is empty")
		}
		if !bundle.ArtifactsVerified() {
			t.Fatal("verified local artifact set was not recorded")
		}
		resolvedBase, err := filepath.EvalSymlinks(base)
		if err != nil {
			t.Fatal(err)
		}
		if bundle.ArtifactBaseDir() != resolvedBase {
			t.Fatalf("artifact base = %q, want %q", bundle.ArtifactBaseDir(), resolvedBase)
		}
	})
	t.Run("symlinked base stores resolved accessor", func(t *testing.T) {
		parent := t.TempDir()
		linkBase := filepath.Join(parent, "artifact-base-link")
		if err := os.Symlink(base, linkBase); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		bundle, err := ParseBundle(strings.NewReader(validBundleJSON(t, payload)), VerifyOptions{
			BaseDir:         linkBase,
			PinnedAdapterID: "amneziawg-linux-systemd",
		})
		if err != nil {
			t.Fatal(err)
		}
		resolvedBase, err := filepath.EvalSymlinks(base)
		if err != nil {
			t.Fatal(err)
		}
		if bundle.ArtifactBaseDir() != resolvedBase {
			t.Fatalf("artifact base = %q, want resolved base %q", bundle.ArtifactBaseDir(), resolvedBase)
		}
		if bundle.ArtifactBaseDir() == linkBase {
			t.Fatalf("artifact base retained symlink path %q", linkBase)
		}
	})
	t.Run("traversal", func(t *testing.T) {
		data := strings.Replace(validBundleJSON(t, payload), `"path":"server-agent.bin"`, `"path":"../server-agent.bin"`, 1)
		if _, err := ParseBundle(strings.NewReader(data), VerifyOptions{BaseDir: base, PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), "confined") {
			t.Fatalf("ParseBundle() error = %v, want confined path", err)
		}
	})
	t.Run("final symlink", func(t *testing.T) {
		target := filepath.Join(base, "server-agent.bin")
		link := filepath.Join(base, "server-agent-link.bin")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		data := strings.Replace(validBundleJSON(t, payload), `"path":"server-agent.bin"`, `"path":"server-agent-link.bin"`, 1)
		if _, err := ParseBundle(strings.NewReader(data), VerifyOptions{BaseDir: base, PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("ParseBundle() error = %v, want symlink rejection", err)
		}
	})
	t.Run("intermediate symlink escape", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "server-agent.bin"), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(base, "linked")
		if err := os.Symlink(outside, linkDir); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		data := strings.Replace(validBundleJSON(t, payload), `"path":"server-agent.bin"`, `"path":"linked/server-agent.bin"`, 1)
		if _, err := ParseBundle(strings.NewReader(data), VerifyOptions{BaseDir: base, PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), "resolved base") {
			t.Fatalf("ParseBundle() error = %v, want resolved-base escape", err)
		}
	})
	t.Run("hash", func(t *testing.T) {
		data := strings.Replace(validBundleJSON(t, payload), shaHex(payload), strings.Repeat("0", 64), 1)
		if _, err := ParseBundle(strings.NewReader(data), VerifyOptions{BaseDir: base, PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("ParseBundle() error = %v, want hash mismatch", err)
		}
	})
	t.Run("size", func(t *testing.T) {
		data := strings.Replace(validBundleJSON(t, payload), `"size_bytes":7`, `"size_bytes":8`, 1)
		if _, err := ParseBundle(strings.NewReader(data), VerifyOptions{BaseDir: base, PinnedAdapterID: "amneziawg-linux-systemd"}); err == nil || !strings.Contains(err.Error(), "size mismatch") {
			t.Fatalf("ParseBundle() error = %v, want size mismatch", err)
		}
	})
}

func TestLoadBundleRejectsSymlinkAndOversizeBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(validBundleJSON(t, "payload")), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "bundle-link.json")
	if err := os.Symlink(bundlePath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadBundle(linkPath, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("LoadBundle() error = %v, want symlink rejection", err)
	}
	largePath := filepath.Join(dir, "large.json")
	if err := os.WriteFile(largePath, []byte(strings.Repeat("x", MaxBundleBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(largePath, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("LoadBundle() error = %v, want size rejection", err)
	}
}

func writeArtifacts(t *testing.T, base, payload string) {
	t.Helper()
	for _, name := range []string{"server-agent.bin", "awg-adapter.bin", "systemd-unit.bin", "nftables.bin", "sysctl.bin", "sshd-policy.bin"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func validBundleJSON(t *testing.T, payload string) string {
	t.Helper()
	hash := shaHex(payload)
	size := strconv.Itoa(len(payload))
	return `{
  "schema_version":1,
  "bundle_id":"p3-bundle",
  "server_id":"nl-prod",
  "target":{"os_family":"ubuntu","arch":"amd64"},
  "endpoint":{"ip":"9.9.9.9","port":51820},
  "adapter":{"id":"amneziawg-linux-systemd","version":"v1.0.0"},
  "recovery_account":{"user":"vpnctl"},
  "tunnel":{
    "interface_name":"awg0",
    "listen_port":51820,
    "server_tunnel_prefix":"10.44.0.0/24",
    "router_peer_address":"10.44.0.2",
    "router_peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
  },
  "awg_parameters":{
    "jc":4,"jmin":10,"jmax":50,"s1":142,"s2":41,"s3":56,"s4":11,
    "h1":"684141592-1751861769","h2":"1957920865-2010016669","h3":"2043550980-2107134838","h4":"2127672251-2132651859",
    "i1":"<r 2>","i2":"<r 3>","i3":"<rd 4>","i4":"<rc 4>","i5":"<b 0x0102>"
  },
  "secrets":{
    "awg_private_key_ref":"awg-private-prod",
    "ssh_deploy_key_ref":"ssh-deploy-prod"
  },
  "artifacts":[
    {"role":"server-agent","name":"server-agent","path":"server-agent.bin","sha256":"` + hash + `","size_bytes":` + size + `},
    {"role":"awg-adapter","name":"awg-adapter","path":"awg-adapter.bin","sha256":"` + hash + `","size_bytes":` + size + `},
    {"role":"systemd-unit","name":"systemd-unit","path":"systemd-unit.bin","sha256":"` + hash + `","size_bytes":` + size + `},
    {"role":"nftables","name":"nftables","path":"nftables.bin","sha256":"` + hash + `","size_bytes":` + size + `},
    {"role":"sysctl","name":"sysctl","path":"sysctl.bin","sha256":"` + hash + `","size_bytes":` + size + `},
    {"role":"sshd-policy","name":"sshd-policy","path":"sshd-policy.bin","sha256":"` + hash + `","size_bytes":` + size + `}
  ]
}`
}

func shaHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
