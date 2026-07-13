package iprule

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vsevo/home-gateway/pkg/contracts"
)

const ArtifactVersion = 1

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

type Artifact struct {
	Version  int        `json:"version"`
	Commands [][]string `json:"commands"`
}

type Server struct {
	Route     contracts.ServerRoute
	Interface string
	Available bool
}

type Inventory struct {
	Servers     []Server
	OwnedMarks  map[uint32]string
	OwnedTables map[uint32]string
}

func Render(plan contracts.PolicyPlan, inventory Inventory) ([]byte, error) {
	byID := make(map[string]Server, len(inventory.Servers))
	for _, server := range inventory.Servers {
		if _, exists := byID[server.Route.ServerID]; exists {
			return nil, fmt.Errorf("duplicate runtime inventory for server %q", server.Route.ServerID)
		}
		if server.Interface != "" && !validInterfaceName(server.Interface) {
			return nil, fmt.Errorf("server %q has invalid interface %q", server.Route.ServerID, server.Interface)
		}
		if server.Available && server.Interface == "" {
			return nil, fmt.Errorf("available server %q requires an interface", server.Route.ServerID)
		}
		byID[server.Route.ServerID] = server
	}
	routes := append([]contracts.ServerRoute(nil), plan.ServerRoutes...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Table != routes[j].Table {
			return routes[i].Table < routes[j].Table
		}
		return routes[i].ServerID < routes[j].ServerID
	})
	seenIDs := make(map[string]struct{}, len(routes))
	seenMarks := make(map[uint32]string, len(routes))
	seenTables := make(map[uint32]string, len(routes))
	artifact := Artifact{Version: ArtifactVersion, Commands: make([][]string, 0, len(routes)*4)}
	for _, route := range routes {
		if err := validateServerRoute(route); err != nil {
			return nil, err
		}
		if _, exists := seenIDs[route.ServerID]; exists {
			return nil, fmt.Errorf("duplicate server %q", route.ServerID)
		}
		if owner := seenMarks[route.Mark]; owner != "" {
			return nil, fmt.Errorf("servers %q and %q share mark %#x", owner, route.ServerID, route.Mark)
		}
		if owner := seenTables[route.Table]; owner != "" {
			return nil, fmt.Errorf("servers %q and %q share routing table %d", owner, route.ServerID, route.Table)
		}
		seenIDs[route.ServerID] = struct{}{}
		seenMarks[route.Mark] = route.ServerID
		seenTables[route.Table] = route.ServerID
		if owner := inventory.OwnedMarks[route.Mark]; owner != "" && owner != "routerd" {
			return nil, fmt.Errorf("mark %#x is owned by %s", route.Mark, owner)
		}
		if owner := inventory.OwnedTables[route.Table]; owner != "" && owner != "routerd" {
			return nil, fmt.Errorf("routing table %d is owned by %s", route.Table, owner)
		}
		server, ok := byID[route.ServerID]
		if !ok {
			return nil, fmt.Errorf("missing runtime inventory for server %q", route.ServerID)
		}
		if server.Route != route {
			return nil, fmt.Errorf("runtime inventory for server %q does not match policy route", route.ServerID)
		}
		for _, family := range []string{"-4", "-6"} {
			table := strconv.FormatUint(uint64(route.Table), 10)
			if server.Available {
				artifact.Commands = append(artifact.Commands, []string{
					"ip", family, "route", "replace", "table", table, "default", "dev", server.Interface,
				})
			} else {
				artifact.Commands = append(artifact.Commands, []string{
					"ip", family, "route", "replace", "table", table, "blackhole", "default",
				})
			}
			artifact.Commands = append(artifact.Commands, []string{
				"ip", family, "rule", "add", "priority", table,
				"fwmark", fmt.Sprintf("%#x/%#x", route.Mark, contracts.RouterdMarkMask), "lookup", table,
			})
		}
	}
	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Parse(data []byte) (Artifact, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var artifact Artifact
	if err := decoder.Decode(&artifact); err != nil {
		return Artifact{}, fmt.Errorf("decode route artifact: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Artifact{}, errors.New("route artifact contains trailing JSON")
		}
		return Artifact{}, fmt.Errorf("decode trailing route artifact data: %w", err)
	}
	if artifact.Version != ArtifactVersion {
		return Artifact{}, fmt.Errorf("unsupported route artifact version %d", artifact.Version)
	}
	if artifact.Commands == nil {
		return Artifact{}, errors.New("route artifact commands are required")
	}
	for index, command := range artifact.Commands {
		if err := validateCommand(command); err != nil {
			return Artifact{}, fmt.Errorf("route command %d: %w", index, err)
		}
	}
	return artifact, nil
}

func validateServerRoute(route contracts.ServerRoute) error {
	if strings.TrimSpace(route.ServerID) == "" {
		return errors.New("server ID is required")
	}
	if route.Mark == 0 || route.Mark&^contracts.RouterdMarkMask != 0 {
		return fmt.Errorf("server %q mark %#x is outside routerd mask", route.ServerID, route.Mark)
	}
	slot := route.Mark >> 24
	if route.Table != contracts.RouterdRoutingTableBase+slot {
		return fmt.Errorf("server %q table %d does not match mark slot %d", route.ServerID, route.Table, slot)
	}
	return nil
}

func validateCommand(command []string) error {
	if len(command) < 3 || command[0] != "ip" || (command[1] != "-4" && command[1] != "-6") {
		return errors.New("only canonical ip -4/-6 commands are allowed")
	}
	switch command[2] {
	case "rule":
		if len(command) != 10 || command[3] != "add" || command[4] != "priority" || command[6] != "fwmark" || command[8] != "lookup" {
			return errors.New("invalid ip rule command shape")
		}
		table, err := parsePositiveUint32(command[5])
		if err != nil || command[9] != command[5] {
			return errors.New("ip rule priority and lookup table must be the same positive integer")
		}
		markParts := strings.Split(command[7], "/")
		if len(markParts) != 2 || markParts[1] != fmt.Sprintf("%#x", contracts.RouterdMarkMask) {
			return errors.New("ip rule must use the routerd mark mask")
		}
		mark64, err := strconv.ParseUint(markParts[0], 0, 32)
		if err != nil {
			return errors.New("ip rule mark is invalid")
		}
		mark := uint32(mark64)
		if mark == 0 || mark&^contracts.RouterdMarkMask != 0 || table != contracts.RouterdRoutingTableBase+(mark>>24) {
			return errors.New("ip rule mark and table allocation are invalid")
		}
	case "route":
		if len(command) != 8 && len(command) != 9 {
			return errors.New("invalid ip route command shape")
		}
		if command[3] != "replace" || command[4] != "table" {
			return errors.New("ip route must replace an explicit table")
		}
		if _, err := parsePositiveUint32(command[5]); err != nil {
			return errors.New("ip route table is invalid")
		}
		if len(command) == 8 {
			if command[6] != "blackhole" || command[7] != "default" {
				return errors.New("unavailable route must be a terminal blackhole default")
			}
		} else if command[6] != "default" || command[7] != "dev" || !validInterfaceName(command[8]) {
			return errors.New("available route must use a valid interface")
		}
	default:
		return errors.New("only ip rule and ip route commands are allowed")
	}
	return nil
}

func parsePositiveUint32(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("positive uint32 is required")
	}
	return uint32(parsed), nil
}

func validInterfaceName(value string) bool {
	return interfaceNamePattern.MatchString(value) && !strings.HasPrefix(value, "-")
}
