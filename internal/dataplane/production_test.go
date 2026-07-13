package dataplane

import (
	"context"
	"testing"
	"time"

	"github.com/vsevo/home-gateway/internal/system/linux"
)

func TestResolveProductionConfigUsesOpenWrtDefaults(t *testing.T) {
	t.Parallel()

	config, err := resolveProductionConfig(ProductionConfig{})
	if err != nil {
		t.Fatalf("resolveProductionConfig() error = %v", err)
	}
	if config.StateRoot != DefaultStateRoot {
		t.Fatalf("state root = %q, want %q", config.StateRoot, DefaultStateRoot)
	}
	if config.LockPath != DefaultLockPath {
		t.Fatalf("lock path = %q, want %q", config.LockPath, DefaultLockPath)
	}
	if config.FirewallIncludePath != DefaultFirewallIncludePath {
		t.Fatalf("firewall include = %q, want %q", config.FirewallIncludePath, DefaultFirewallIncludePath)
	}
	if config.DNSIncludePath != DefaultDNSIncludePath {
		t.Fatalf("dns include = %q, want %q", config.DNSIncludePath, DefaultDNSIncludePath)
	}
	if config.ConfirmTimeout != DefaultConfirmTimeout {
		t.Fatalf("confirm timeout = %s, want %s", config.ConfirmTimeout, DefaultConfirmTimeout)
	}
	if config.Runner == nil {
		t.Fatal("runner = nil, want production runner")
	}
}

func TestNewProductionControllerRejectsNonLinuxHost(t *testing.T) {
	t.Parallel()

	_, err := newProductionController(ProductionConfig{Runner: inertRunner{}}, "windows")
	if err == nil {
		t.Fatal("newProductionController() error = nil, want non-Linux error")
	}
}

func TestNewProductionControllerValidatesPathsAndTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config ProductionConfig
	}{
		{name: "relative state root", config: ProductionConfig{StateRoot: "state"}},
		{name: "unclean lock path", config: ProductionConfig{LockPath: "/var/run/routerd/../apply.lock"}},
		{name: "shared includes", config: ProductionConfig{FirewallIncludePath: "/tmp/shared", DNSIncludePath: "/tmp/shared"}},
		{name: "negative timeout", config: ProductionConfig{ConfirmTimeout: -time.Second}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.config.Runner = inertRunner{}
			if _, err := newProductionController(test.config, "linux"); err == nil {
				t.Fatal("newProductionController() error = nil, want validation error")
			}
		})
	}
}

func TestNewProductionControllerBuildsWithoutSystemMutation(t *testing.T) {
	t.Parallel()

	if _, err := newProductionController(ProductionConfig{Runner: inertRunner{}}, "linux"); err != nil {
		t.Fatalf("newProductionController() error = %v", err)
	}
}

type inertRunner struct{}

func (inertRunner) Run(context.Context, string, ...string) (linux.Result, error) {
	panic("production controller construction must not execute system commands")
}
