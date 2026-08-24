package main

import (
	"os"

	"github.com/vsevo/home-gateway/internal/serveragentcmd"
)

func main() {
	os.Exit(serveragentcmd.Run("server-agent", os.Args[1:], os.Stdout, os.Stderr))
}
