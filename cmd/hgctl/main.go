package main

import (
	"os"

	"github.com/vsevo/home-gateway/internal/versioncmd"
)

func main() {
	os.Exit(versioncmd.Run("hgctl", os.Args[1:], os.Stdout, os.Stderr))
}
