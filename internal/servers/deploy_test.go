package servers

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeDeploymentRuntime struct {
	current      CurrentState
	fail         string
	restoreFails bool
	calls        []string
}

func (runtime *fakeDeploymentRuntime) CurrentState(context.Context) (CurrentState, error) {
	runtime.calls = append(runtime.calls, "current")
	if runtime.fail == "current" {
		return CurrentState{}, errors.New("current failed")
	}
	return runtime.current, nil
}
func (runtime *fakeDeploymentRuntime) Preflight(context.Context, Bundle) error {
	return runtime.call("preflight")
}
func (runtime *fakeDeploymentRuntime) Stage(context.Context, Bundle) error {
	return runtime.call("stage")
}
func (runtime *fakeDeploymentRuntime) Snapshot(context.Context, Bundle) (DeploymentSnapshot, error) {
	if err := runtime.call("snapshot"); err != nil {
		return DeploymentSnapshot{}, err
	}
	return DeploymentSnapshot{PreviousState: runtime.current, RecoveryID: "snapshot-1"}, nil
}
func (runtime *fakeDeploymentRuntime) Validate(context.Context, Bundle) error {
	return runtime.call("validate")
}
func (runtime *fakeDeploymentRuntime) Activate(context.Context, Bundle) error {
	return runtime.call("activate")
}
func (runtime *fakeDeploymentRuntime) PostCheck(context.Context, Bundle) error {
	return runtime.call("postcheck")
}
func (runtime *fakeDeploymentRuntime) VerifyRecoveryAccess(context.Context, Bundle) error {
	return runtime.call("recovery")
}
func (runtime *fakeDeploymentRuntime) HardenSSH(context.Context, Bundle) error {
	return runtime.call("harden")
}
func (runtime *fakeDeploymentRuntime) Commit(_ context.Context, _ Bundle, state CurrentState) error {
	if err := runtime.call("commit"); err != nil {
		return err
	}
	runtime.current = state
	return nil
}
func (runtime *fakeDeploymentRuntime) Restore(_ context.Context, snapshot DeploymentSnapshot) error {
	runtime.calls = append(runtime.calls, "restore")
	if runtime.restoreFails {
		return errors.New("restore failed")
	}
	runtime.current = snapshot.PreviousState
	return nil
}
func (runtime *fakeDeploymentRuntime) call(name string) error {
	runtime.calls = append(runtime.calls, name)
	if runtime.fail == name {
		return errors.New(name + " failed")
	}
	return nil
}

func TestDeploymentConvergesAndNoopsOnSameDigestAndHardenedState(t *testing.T) {
	bundle := testVerifiedBundle()
	runtime := &fakeDeploymentRuntime{}
	result, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "installed" || result.State.Digest != bundle.Digest() || result.State.SSHHardened {
		t.Fatalf("result = %+v", result)
	}
	runtime.calls = nil
	result, err = (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "noop" || strings.Join(runtime.calls, ",") != "current" {
		t.Fatalf("second apply result=%+v calls=%v", result, runtime.calls)
	}
	runtime.current.SSHHardened = true
	runtime.calls = nil
	result, err = (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{HardenSSH: true, RecoveryAccountProven: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "noop" || strings.Join(runtime.calls, ",") != "current" {
		t.Fatalf("hardened same-digest result=%+v calls=%v", result, runtime.calls)
	}
}

func TestDeploymentSameDigestRequestedHardeningRunsSafeCompensatablePath(t *testing.T) {
	bundle := testVerifiedBundle()
	runtime := &fakeDeploymentRuntime{current: CurrentState{Digest: bundle.Digest()}}
	result, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{HardenSSH: true, RecoveryAccountProven: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "hardened" || !result.State.SSHHardened {
		t.Fatalf("result = %+v", result)
	}
	wantCalls := "current,preflight,snapshot,recovery,harden,commit"
	if strings.Join(runtime.calls, ",") != wantCalls {
		t.Fatalf("calls = %v, want %s", runtime.calls, wantCalls)
	}

	runtime = &fakeDeploymentRuntime{current: CurrentState{Digest: bundle.Digest()}, fail: "harden"}
	_, err = (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{HardenSSH: true, RecoveryAccountProven: true})
	if err == nil || !strings.Contains(err.Error(), "ssh harden") || !strings.Contains(strings.Join(runtime.calls, ","), "restore") {
		t.Fatalf("Apply() error=%v calls=%v, want compensated harden failure", err, runtime.calls)
	}
}

func TestDeploymentRequiresExplicitUpgradeIntent(t *testing.T) {
	bundle := testVerifiedBundle()
	runtime := &fakeDeploymentRuntime{current: CurrentState{Digest: "previous"}}
	if _, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{}); err == nil || !strings.Contains(err.Error(), "upgrade intent") {
		t.Fatalf("Apply() error = %v, want upgrade intent", err)
	}
	if strings.Join(runtime.calls, ",") != "current" {
		t.Fatalf("calls = %v", runtime.calls)
	}
}

func TestDeploymentCompensatesEveryFailureBoundary(t *testing.T) {
	boundaries := []string{"stage", "validate", "activate", "postcheck", "recovery", "harden", "commit"}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			bundle := testVerifiedBundle()
			runtime := &fakeDeploymentRuntime{fail: boundary}
			_, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{HardenSSH: true, RecoveryAccountProven: true})
			if err == nil || !strings.Contains(err.Error(), boundary) {
				t.Fatalf("Apply() error = %v", err)
			}
			if !strings.Contains(strings.Join(runtime.calls, ","), "restore") {
				t.Fatalf("calls = %v, want restore", runtime.calls)
			}
		})
	}
}

func TestDeploymentSnapshotsBeforeFirstMutation(t *testing.T) {
	runtime := &fakeDeploymentRuntime{}
	if _, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), testVerifiedBundle(), DeploymentRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runtime.calls, ","); !strings.Contains(got, "preflight,snapshot,stage") {
		t.Fatalf("calls = %s, want preflight,snapshot,stage ordering", got)
	}
}

func TestDeploymentSnapshotFailureOccursBeforeMutationAndNeedsNoCompensation(t *testing.T) {
	runtime := &fakeDeploymentRuntime{fail: "snapshot"}
	_, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), testVerifiedBundle(), DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("Apply() error = %v, want snapshot failure", err)
	}
	if strings.Contains(strings.Join(runtime.calls, ","), "stage") || strings.Contains(strings.Join(runtime.calls, ","), "restore") {
		t.Fatalf("calls = %v, want no mutation or compensation", runtime.calls)
	}
}

func TestDeploymentDoesNotCompensatePreflightFailure(t *testing.T) {
	runtime := &fakeDeploymentRuntime{fail: "preflight"}
	_, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), testVerifiedBundle(), DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("Apply() error = %v", err)
	}
	if strings.Contains(strings.Join(runtime.calls, ","), "restore") {
		t.Fatalf("calls = %v, want no restore before mutation", runtime.calls)
	}
}

func TestDeploymentRequiresRecoveryAccountFromRequestBeforeHardening(t *testing.T) {
	runtime := &fakeDeploymentRuntime{}
	if _, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), testVerifiedBundle(), DeploymentRequest{HardenSSH: true}); err == nil || !strings.Contains(err.Error(), "recovery_account_proven") {
		t.Fatalf("Apply() error = %v, want recovery gate", err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("runtime calls = %v, want none", runtime.calls)
	}
}

func TestDeploymentRejectsBundleWithoutVerifiedArtifacts(t *testing.T) {
	bundle := testVerifiedBundle()
	bundle.artifactsVerified = false
	runtime := &fakeDeploymentRuntime{}
	if _, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{}); err == nil || !strings.Contains(err.Error(), "artifacts") {
		t.Fatalf("Apply() error = %v, want artifact verification gate", err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("runtime calls = %v, want none", runtime.calls)
	}
}

func TestDeploymentRejectsSanitizedExampleBundle(t *testing.T) {
	bundle := testVerifiedBundle()
	bundle.SanitizedExample = true
	runtime := &fakeDeploymentRuntime{}
	if _, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{}); err == nil || !strings.Contains(err.Error(), "sanitized") {
		t.Fatalf("Apply() error = %v, want sanitized-example gate", err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("runtime calls = %v, want none", runtime.calls)
	}
}

func TestDeploymentRejectsPostVerificationBundleMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Bundle)
	}{
		{name: "adapter", mutate: func(bundle *Bundle) { bundle.Adapter.Version = "v9.9.9" }},
		{name: "artifact", mutate: func(bundle *Bundle) { bundle.Artifacts[0].Path = "replacement.bin" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := testVerifiedBundle()
			test.mutate(&bundle)
			runtime := &fakeDeploymentRuntime{}
			_, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), bundle, DeploymentRequest{})
			if err == nil || !strings.Contains(err.Error(), "changed after verification") {
				t.Fatalf("Apply() error = %v, want semantic seal failure", err)
			}
			if len(runtime.calls) != 0 {
				t.Fatalf("runtime calls = %v, want none", runtime.calls)
			}
		})
	}
}

func TestDeploymentJoinsCompensationFailure(t *testing.T) {
	runtime := &fakeDeploymentRuntime{fail: "activate", restoreFails: true}
	_, err := (DeploymentEngine{Runtime: runtime}).Apply(context.Background(), testVerifiedBundle(), DeploymentRequest{})
	if err == nil || !strings.Contains(err.Error(), "activate") || !strings.Contains(err.Error(), "compensation") {
		t.Fatalf("Apply() error = %v, want joined activate and compensation failure", err)
	}
}

func testVerifiedBundle() Bundle {
	bundle := Bundle{
		SchemaVersion: BundleSchemaVersion,
		BundleID:      "p3-bundle",
		ServerID:      "nl-prod",
		Target:        Target{OSFamily: "ubuntu", Arch: "amd64"},
		Endpoint:      Endpoint{IP: "9.9.9.9", Port: 51820},
		Adapter:       Adapter{ID: "amneziawg-linux-systemd", Version: "v1.0.0"},
		RecoveryAccount: RecoveryAccount{
			User: "vpnctl",
		},
		Tunnel: Tunnel{
			InterfaceName:       "awg0",
			ListenPort:          51820,
			ServerTunnelPrefix:  "10.44.0.0/24",
			RouterPeerAddress:   "10.44.0.2",
			RouterPeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		},
		AWGParameters: AWGParameters{
			JC: 4, JMin: 10, JMax: 50, S1: 142, S2: 41, S3: 56, S4: 11,
			H1: "684141592-1751861769", H2: "1957920865-2010016669",
			H3: "2043550980-2107134838", H4: "2127672251-2132651859",
			I1: "<r 2>", I2: "<r 3>", I3: "<rd 4>", I4: "<rc 4>", I5: "<b 0x0102>",
		},
		Secrets: SecretRefs{
			AWGPrivateKey: "awg-private-prod",
			SSHDeployKey:  "ssh-deploy-prod",
		},
		Artifacts: []Artifact{
			{Role: "server-agent", Name: "server-agent", Path: "server-agent.bin", SHA256: strings.Repeat("a", 64), SizeBytes: 1},
			{Role: "awg-adapter", Name: "awg-adapter", Path: "awg-adapter.bin", SHA256: strings.Repeat("b", 64), SizeBytes: 1},
			{Role: "systemd-unit", Name: "systemd-unit", Path: "systemd-unit.bin", SHA256: strings.Repeat("c", 64), SizeBytes: 1},
			{Role: "nftables", Name: "nftables", Path: "nftables.bin", SHA256: strings.Repeat("d", 64), SizeBytes: 1},
			{Role: "sysctl", Name: "sysctl", Path: "sysctl.bin", SHA256: strings.Repeat("e", 64), SizeBytes: 1},
			{Role: "sshd-policy", Name: "sshd-policy", Path: "sshd-policy.bin", SHA256: strings.Repeat("f", 64), SizeBytes: 1},
		},
		digest:            "candidate-digest",
		artifactBaseDir:   "/verified-artifacts",
		artifactsVerified: true,
	}
	seal, err := semanticBundleDigest(bundle)
	if err != nil {
		panic(err)
	}
	bundle.semanticSeal = seal
	return bundle
}
