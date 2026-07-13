package dataplane

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/vsevo/home-gateway/internal/revisions/apply"
	"github.com/vsevo/home-gateway/internal/system/linux"
)

const (
	DefaultStateRoot           = "/etc/routerd/dataplane"
	DefaultLockPath            = "/var/run/routerd/apply.lock"
	DefaultFirewallIncludePath = "/usr/share/nftables.d/ruleset-post/50-routerd.nft"
	DefaultDNSIncludePath      = "/tmp/dnsmasq.d/routerd.conf"
	DefaultConfirmTimeout      = 2 * time.Minute
)

type ProductionConfig struct {
	StateRoot           string
	LockPath            string
	FirewallIncludePath string
	DNSIncludePath      string
	ConfirmTimeout      time.Duration
	Runner              linux.Runner
}

func NewProductionController(config ProductionConfig) (*Controller, error) {
	return newProductionController(config, runtime.GOOS)
}

func newProductionController(config ProductionConfig, goos string) (*Controller, error) {
	if goos != "linux" {
		return nil, fmt.Errorf("production dataplane requires Linux, got %s", goos)
	}
	resolved, err := resolveProductionConfig(config)
	if err != nil {
		return nil, err
	}
	transaction := &apply.Transaction{
		Runtime: apply.LinuxRuntime{
			Root:                resolved.StateRoot,
			FirewallIncludePath: resolved.FirewallIncludePath,
			DNSIncludePath:      resolved.DNSIncludePath,
			Runner:              resolved.Runner,
		},
		Journal:        apply.FileJournal{Path: path.Join(resolved.StateRoot, "journal.json")},
		Locker:         apply.FileLocker{Path: resolved.LockPath},
		Watchdog:       apply.TimerWatchdog{},
		ConfirmTimeout: resolved.ConfirmTimeout,
	}
	return NewController(transaction)
}

func resolveProductionConfig(config ProductionConfig) (ProductionConfig, error) {
	if config.StateRoot == "" {
		config.StateRoot = DefaultStateRoot
	}
	if config.LockPath == "" {
		config.LockPath = DefaultLockPath
	}
	if config.FirewallIncludePath == "" {
		config.FirewallIncludePath = DefaultFirewallIncludePath
	}
	if config.DNSIncludePath == "" {
		config.DNSIncludePath = DefaultDNSIncludePath
	}
	if config.ConfirmTimeout == 0 {
		config.ConfirmTimeout = DefaultConfirmTimeout
	}
	if config.Runner == nil {
		config.Runner = linux.ExecRunner{}
	}
	if config.ConfirmTimeout < 0 {
		return ProductionConfig{}, errors.New("confirm timeout cannot be negative")
	}
	paths := map[string]string{
		"state root":       config.StateRoot,
		"operation lock":   config.LockPath,
		"firewall include": config.FirewallIncludePath,
		"dns include":      config.DNSIncludePath,
	}
	for label, value := range paths {
		if !validLinuxPath(value) {
			return ProductionConfig{}, fmt.Errorf("absolute clean Linux %s path is required", label)
		}
	}
	if config.FirewallIncludePath == config.DNSIncludePath {
		return ProductionConfig{}, errors.New("firewall and dns include paths must differ")
	}
	if config.StateRoot == config.FirewallIncludePath || config.StateRoot == config.DNSIncludePath {
		return ProductionConfig{}, errors.New("managed include path cannot equal the state root")
	}
	return config, nil
}

func validLinuxPath(value string) bool {
	return value != "/" &&
		path.IsAbs(value) &&
		path.Clean(value) == value &&
		!strings.ContainsRune(value, '\x00')
}
