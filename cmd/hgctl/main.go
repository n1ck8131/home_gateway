package main

import (
	"os"

	"github.com/vsevo/home-gateway/internal/hgctlcmd"
)

func main() {
	os.Exit(hgctlcmd.Run("hgctl", os.Args[1:], os.Stdout, os.Stderr))
}
