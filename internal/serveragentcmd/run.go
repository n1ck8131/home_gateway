package serveragentcmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/vsevo/home-gateway/internal/buildinfo"
	"github.com/vsevo/home-gateway/internal/versioncmd"
)

const healthSchemaVersion = 1

type healthResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	Status        string `json:"status"`
	Scope         string `json:"scope"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
}

func Run(program string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		return versioncmd.Run(program, args, stdout, stderr)
	}
	if len(args) != 2 || args[0] != "health" || args[1] != "--json" {
		fmt.Fprintf(stderr, "usage: %s version --json\n       %s health --json\n", program, program)
		return 2
	}

	response := healthResponse{
		SchemaVersion: healthSchemaVersion,
		Component:     program,
		Status:        "ok",
		Scope:         "process",
		Version:       buildinfo.Version,
		Commit:        buildinfo.Commit,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		fmt.Fprintf(stderr, "encode health: %v\n", err)
		return 1
	}
	return 0
}
