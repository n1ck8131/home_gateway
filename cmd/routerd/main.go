package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vsevo/home-gateway/internal/dataplane"
	"github.com/vsevo/home-gateway/internal/routerdcmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(routerdcmd.Run(ctx, "routerd", os.Args[1:], os.Stdout, os.Stderr, func() (routerdcmd.Service, error) {
		return dataplane.NewProductionController(dataplane.ProductionConfig{})
	}))
}
