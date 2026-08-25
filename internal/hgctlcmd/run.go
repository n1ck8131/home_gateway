package hgctlcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vsevo/home-gateway/internal/providers/redshield"
	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
	"github.com/vsevo/home-gateway/internal/tunnel"
	"github.com/vsevo/home-gateway/internal/versioncmd"
)

type dependencies struct {
	backend tunnel.Backend
	collect windowssystem.Collector
	resolve func(context.Context, string) ([]string, error)
}

func defaultDependencies() dependencies {
	return dependencies{
		backend: redshield.Backend{},
		collect: windowssystem.NativeCollector{},
		resolve: windowssystem.ResolveEndpoint,
	}
}

func Run(program string, args []string, stdout, stderr io.Writer) int {
	return runWithDependencies(program, args, stdout, stderr, defaultDependencies())
}

func runWithDependencies(program string, args []string, stdout, stderr io.Writer, dependencies dependencies) int {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		return versioncmd.Run(program, args, stdout, stderr)
	}
	configPath, command, ok := parseReadOnlyCommand(args)
	if !ok {
		writeUsage(program, stderr)
		return 2
	}

	ctx := context.Background()
	inspection, err := dependencies.backend.Inspect(ctx, tunnel.ConfigSource{Path: configPath})
	if err != nil {
		fmt.Fprintln(stderr, "RedShield config inspection failed:", err)
		return 1
	}
	if command == "redshield-inspect" {
		return encodeJSON(stdout, stderr, inspection)
	}

	preflightContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	inventory, err := dependencies.collect.Collect(preflightContext)
	if err != nil {
		fmt.Fprintln(stderr, "Windows inventory failed:", err)
		return 1
	}
	resolved, resolveErr := dependencies.resolve(preflightContext, inspection.Metadata.Endpoint.Host)
	if resolveErr == nil {
		inventory.EndpointAddresses = resolved
	}
	result := struct {
		Tunnel    tunnel.Inspection       `json:"tunnel"`
		Preflight windowssystem.Preflight `json:"preflight"`
	}{
		Tunnel:    inspection,
		Preflight: (windowssystem.Planner{}).Plan(inventory, inspection),
	}
	if code := encodeJSON(stdout, stderr, result); code != 0 {
		return code
	}
	if !result.Preflight.ReadOnlyQualified {
		return 3
	}
	return 0
}

func parseReadOnlyCommand(args []string) (string, string, bool) {
	if len(args) != 5 || args[2] != "--config" || args[3] == "" || args[4] != "--json" {
		return "", "", false
	}
	switch {
	case args[0] == "redshield" && args[1] == "inspect":
		return args[3], "redshield-inspect", true
	case args[0] == "windows" && args[1] == "preflight":
		return args[3], "windows-preflight", true
	default:
		return "", "", false
	}
}

func encodeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(stderr, "JSON encoding failed")
		return 1
	}
	return 0
}

func writeUsage(program string, writer io.Writer) {
	fmt.Fprintf(writer, "usage: %s version --json\n", program)
	fmt.Fprintf(writer, "       %s redshield inspect --config <path> --json\n", program)
	fmt.Fprintf(writer, "       %s windows preflight --config <path> --json\n", program)
	fmt.Fprintln(writer, "exit codes: 0=success/read-only-qualified, 1=runtime error, 2=usage error, 3=read-only preflight blocked")
}
