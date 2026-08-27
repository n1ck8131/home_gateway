// Package configfile exposes a provider-neutral, redacted profile importer.
package configfile

import (
	"fmt"
	"io"

	"github.com/vsevo/home-gateway/internal/providers/redshield"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

type Config struct{ metadata tunnel.Metadata }

func (Config) String() string   { return "configfile.Config{key_material:[REDACTED]}" }
func (Config) GoString() string { return "configfile.Config{key_material:[REDACTED]}" }
func (Config) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "configfile.Config{key_material:[REDACTED]}")
}
func (config Config) Metadata() tunnel.Metadata { return config.metadata }

func ImportFile(path, provider string) (Config, error) {
	if provider == "" {
		return Config{}, fmt.Errorf("provider ID is required")
	}
	legacy, err := redshield.ImportFile(path)
	if err != nil {
		return Config{}, err
	}
	metadata := legacy.Metadata()
	metadata.Provider = provider
	return Config{metadata: metadata}, nil
}

func ImportFilePinned(path, expectedSHA256, provider string) (Config, error) {
	if provider == "" {
		return Config{}, fmt.Errorf("provider ID is required")
	}
	legacy, err := redshield.ImportFilePinned(path, expectedSHA256)
	if err != nil {
		return Config{}, err
	}
	metadata := legacy.Metadata()
	metadata.Provider = provider
	return Config{metadata: metadata}, nil
}
