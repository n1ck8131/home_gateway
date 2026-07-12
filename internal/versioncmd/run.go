package versioncmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/vsevo/home-gateway/internal/buildinfo"
)

func Run(program string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "version" || args[1] != "--json" {
		fmt.Fprintf(stderr, "usage: %s version --json\n", program)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(buildinfo.Current(program)); err != nil {
		fmt.Fprintf(stderr, "encode version: %v\n", err)
		return 1
	}
	return 0
}
