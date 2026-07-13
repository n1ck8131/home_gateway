package routerdcmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/vsevo/home-gateway/internal/versioncmd"
)

type Service interface {
	Recover(context.Context) error
}

type ServiceFactory func() (Service, error)

func Run(ctx context.Context, program string, args []string, stdout, stderr io.Writer, factory ServiceFactory) int {
	if len(args) > 0 && args[0] == "version" {
		return versioncmd.Run(program, args, stdout, stderr)
	}
	if len(args) != 1 || args[0] != "run" {
		fmt.Fprintf(stderr, "usage: %s version --json\n       %s run\n", program, program)
		return 2
	}
	if ctx == nil {
		fmt.Fprintln(stderr, "run routerd: context is required")
		return 1
	}
	if factory == nil {
		fmt.Fprintln(stderr, "run routerd: service factory is required")
		return 1
	}
	service, err := factory()
	if err != nil {
		fmt.Fprintf(stderr, "initialize routerd: %v\n", err)
		return 1
	}
	if service == nil {
		fmt.Fprintln(stderr, "initialize routerd: service is required")
		return 1
	}
	if err := service.Recover(ctx); err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(stderr, "start routerd: %v\n", err)
		return 1
	}
	<-ctx.Done()
	return 0
}
