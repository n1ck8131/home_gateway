package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vsevo/home-gateway/internal/system/linux"
)

type LinuxRuntime struct {
	Root   string
	Runner linux.Runner
}

func (runtime LinuxRuntime) Stage(_ context.Context, candidate Candidate) error {
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"50-routerd.nft": candidate.NFT, "routerd.conf": candidate.DNS, "routes.txt": candidate.Routes} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (runtime LinuxRuntime) Validate(ctx context.Context, candidate Candidate) error {
	directory, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	fw4, err := runtime.Runner.Run(ctx, "fw4", "print")
	if err != nil {
		return err
	}
	fragment, err := os.ReadFile(filepath.Join(directory, "50-routerd.nft"))
	if err != nil {
		return err
	}
	complete := append(append(fw4.Stdout, '\n'), fragment...)
	candidatePath := filepath.Join(directory, "complete.nft")
	if err := os.WriteFile(candidatePath, complete, 0o600); err != nil {
		return err
	}
	if _, err := runtime.Runner.Run(ctx, "nft", "-c", "-f", candidatePath); err != nil {
		return err
	}
	_, err = runtime.Runner.Run(ctx, "dnsmasq", "--test", "--conf-file="+filepath.Join(directory, "routerd.conf"))
	return err
}

func (runtime LinuxRuntime) Snapshot(_ context.Context, activeRevision string) error {
	if activeRevision == "" {
		return nil
	}
	source, err := runtime.revisionDirectory(activeRevision)
	if err != nil {
		return err
	}
	target := filepath.Join(runtime.Root, "lkg")
	return copyArtifacts(source, target)
}

func (runtime LinuxRuntime) Activate(_ context.Context, candidate Candidate) error {
	source, err := runtime.revisionDirectory(candidate.RevisionID)
	if err != nil {
		return err
	}
	temporary := filepath.Join(runtime.Root, "active.next")
	if err := copyArtifacts(source, temporary); err != nil {
		return err
	}
	active := filepath.Join(runtime.Root, "active")
	_ = os.RemoveAll(active + ".old")
	if _, err := os.Stat(active); err == nil {
		if err := os.Rename(active, active+".old"); err != nil {
			return err
		}
	}
	return os.Rename(temporary, active)
}

func (runtime LinuxRuntime) Reload(ctx context.Context) error {
	if _, err := runtime.Runner.Run(ctx, "fw4", "reload"); err != nil {
		return err
	}
	_, err := runtime.Runner.Run(ctx, "ubus", "call", "service", "signal", `{"name":"dnsmasq","signal":1}`)
	return err
}

func (runtime LinuxRuntime) PostCheck(ctx context.Context) error {
	if _, err := runtime.Runner.Run(ctx, "nft", "list", "table", "inet", "routerd"); err != nil {
		return err
	}
	_, err := runtime.Runner.Run(ctx, "ip", "rule", "show")
	return err
}

func (runtime LinuxRuntime) Restore(ctx context.Context, _ string) error {
	lkg := filepath.Join(runtime.Root, "lkg")
	if _, err := os.Stat(lkg); err != nil {
		return errors.New("last-known-good snapshot is unavailable")
	}
	if err := copyArtifacts(lkg, filepath.Join(runtime.Root, "active.next")); err != nil {
		return err
	}
	active := filepath.Join(runtime.Root, "active")
	_ = os.RemoveAll(active)
	if err := os.Rename(filepath.Join(runtime.Root, "active.next"), active); err != nil {
		return err
	}
	return runtime.Reload(ctx)
}

func (runtime LinuxRuntime) revisionDirectory(revision string) (string, error) {
	if runtime.Root == "" || !filepath.IsAbs(runtime.Root) {
		return "", errors.New("absolute runtime root is required")
	}
	if !validRevisionID(revision) {
		return "", errors.New("invalid revision ID")
	}
	cleanRoot := filepath.Clean(runtime.Root)
	path := filepath.Join(cleanRoot, "revisions", revision)
	if filepath.Dir(filepath.Dir(path)) != cleanRoot {
		return "", errors.New("revision path escapes runtime root")
	}
	return path, nil
}

func copyArtifacts(source, target string) error {
	if info, err := os.Lstat(source); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("artifact source is unavailable or is a symlink")
	}
	_ = os.RemoveAll(target)
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"50-routerd.nft", "routerd.conf", "routes.txt"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(target, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
