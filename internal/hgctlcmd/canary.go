package hgctlcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	windowssystem "github.com/vsevo/home-gateway/internal/system/windows"
	"github.com/vsevo/home-gateway/internal/tunnel"
)

type canaryPlanCommand struct {
	configPath   string
	configSHA256 string
	stateRoot    string
	revision     string
	targets      []string
	dnsNamespace string
}

var lowercaseSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type canaryPlanOutput struct {
	Mode                  string `json:"mode"`
	Revision              string `json:"revision"`
	ReadyForLiveGate      bool   `json:"ready_for_live_gate"`
	LiveMutationPerformed bool   `json:"live_mutation_performed"`
	RouteCount            int    `json:"route_count"`
	SinkCount             int    `json:"sink_count"`
	PersistentSinkReady   bool   `json:"persistent_sink_ready"`
	FirewallRuleCount     int    `json:"firewall_rule_count"`
	DNSRuleCount          int    `json:"dns_rule_count"`
	ConfirmationChallenge string `json:"confirmation_challenge"`
	ConfirmTimeoutSeconds int    `json:"confirm_timeout_seconds"`
}

func parseCanaryPlanCommand(args []string) (canaryPlanCommand, bool) {
	if len(args) < 4 || args[0] != "windows" || args[1] != "canary" || args[2] != "plan" {
		return canaryPlanCommand{}, false
	}
	var command canaryPlanCommand
	seen := make(map[string]bool)
	jsonOutput := false
	for index := 3; index < len(args); {
		name := args[index]
		if name == "--json" {
			if jsonOutput || index != len(args)-1 {
				return canaryPlanCommand{}, false
			}
			jsonOutput = true
			index++
			continue
		}
		if index+1 >= len(args) || args[index+1] == "" {
			return canaryPlanCommand{}, false
		}
		value := args[index+1]
		switch name {
		case "--target":
			command.targets = append(command.targets, value)
		case "--config", "--config-sha256", "--state-root", "--revision", "--dns-namespace":
			if seen[name] {
				return canaryPlanCommand{}, false
			}
			seen[name] = true
			switch name {
			case "--config":
				command.configPath = value
			case "--config-sha256":
				command.configSHA256 = value
			case "--state-root":
				command.stateRoot = value
			case "--revision":
				command.revision = value
			case "--dns-namespace":
				command.dnsNamespace = value
			}
		default:
			return canaryPlanCommand{}, false
		}
		index += 2
	}
	if !jsonOutput || command.configPath == "" || !lowercaseSHA256Pattern.MatchString(command.configSHA256) || command.stateRoot == "" || command.revision == "" || command.dnsNamespace == "" || len(command.targets) == 0 {
		return canaryPlanCommand{}, false
	}
	return command, true
}

func runCanaryPlan(command canaryPlanCommand, stdout, stderr io.Writer, dependencies dependencies) int {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	plan, errorCode, err := collectCanaryPlan(ctx, command, dependencies)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return errorCode
	}
	return encodeJSON(stdout, stderr, canaryPlanOutput{
		Mode:                  "plan",
		Revision:              command.revision,
		ReadyForLiveGate:      true,
		LiveMutationPerformed: false,
		RouteCount:            plan.RouteCount,
		SinkCount:             plan.SinkCount,
		PersistentSinkReady:   false,
		FirewallRuleCount:     plan.FirewallRuleCount,
		DNSRuleCount:          plan.DNSRuleCount,
		ConfirmationChallenge: plan.ConfirmationChallenge(command.stateRoot),
		ConfirmTimeoutSeconds: int(windowssystem.DefaultCanaryConfirmTimeout / time.Second),
	})
}

func collectCanaryPlan(ctx context.Context, command canaryPlanCommand, dependencies dependencies) (windowssystem.CanaryPlan, int, error) {
	validator := dependencies.validatePlanStateRoot
	if validator == nil {
		// Preserve injected test adapters while production deliberately separates
		// non-elevated planning from privileged state-root access validation.
		validator = dependencies.validateStateRoot
	}
	if validator != nil {
		if err := validator(command.stateRoot); err != nil {
			return windowssystem.CanaryPlan{}, 3, fmt.Errorf("Windows canary state root blocked: %w", err)
		}
	}
	if dependencies.validateConfigSource != nil {
		if err := dependencies.validateConfigSource(command.configPath); err != nil {
			return windowssystem.CanaryPlan{}, 3, fmt.Errorf("RedShield config source blocked: %w", err)
		}
	}
	inspection, err := dependencies.backend.Inspect(ctx, tunnel.ConfigSource{Path: command.configPath, SHA256: command.configSHA256})
	if err != nil {
		return windowssystem.CanaryPlan{}, 1, fmt.Errorf("RedShield config inspection failed: %w", err)
	}
	inventory, err := dependencies.collect.Collect(ctx)
	if err != nil {
		return windowssystem.CanaryPlan{}, 1, fmt.Errorf("Windows inventory failed: %w", err)
	}
	resolved, err := dependencies.resolve(ctx, inspection.Metadata.Endpoint.Host)
	if err != nil {
		return windowssystem.CanaryPlan{}, 1, errors.New("RedShield endpoint qualification failed")
	}
	inventory.EndpointAddresses = resolved
	plan, err := windowssystem.BuildCanaryPlan(inventory, inspection, windowssystem.CanaryRequest{
		Revision:        command.revision,
		TargetAddresses: command.targets,
		DNSNamespace:    command.dnsNamespace,
	})
	if err != nil {
		return windowssystem.CanaryPlan{}, 3, fmt.Errorf("Windows canary plan blocked: %w", err)
	}
	plan.ConfigSHA256 = command.configSHA256
	return plan, 0, nil
}
