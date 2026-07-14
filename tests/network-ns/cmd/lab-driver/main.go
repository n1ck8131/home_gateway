//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vsevo/home-gateway/internal/dataplane"
	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/internal/system/linux"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	commandTimeout = 15 * time.Second
	workDeviceID   = "work"
	vpnServerID    = "vpn-1"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lab-driver:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command is required")
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "probe":
		return runProbe(args[1:])
	case "apply":
		return runApply(args[1:])
	case "confirm", "rollback", "recover":
		return runTransactionCommand(args[0], args[1:])
	default:
		return fmt.Errorf("unsupported command %q", args[0])
	}
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("address cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func runServe(args []string) error {
	set := newFlagSet("serve")
	var addresses stringList
	set.Var(&addresses, "address", "literal address to bind; repeatable")
	token := set.String("token", "", "response token")
	tcpPort := set.Int("tcp-port", 0, "TCP port")
	udpPort := set.Int("udp-port", 0, "UDP port")
	quicPort := set.Int("quic-port", 0, "QUIC-shaped UDP port")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || len(addresses) == 0 {
		return errors.New("serve requires flags only and at least one address")
	}
	if strings.TrimSpace(*token) == "" || len(*token) > 32 {
		return errors.New("serve token must contain between 1 and 32 bytes")
	}
	for _, port := range []int{*tcpPort, *udpPort, *quicPort} {
		if port < 1 || port > 65535 {
			return errors.New("serve ports must be between 1 and 65535")
		}
	}
	return serveTraffic(addresses, *token, *tcpPort, *udpPort, *quicPort)
}

func serveTraffic(addresses []string, token string, tcpPort, udpPort, quicPort int) error {
	closers := make([]io.Closer, 0, len(addresses)*3)
	errorsCh := make(chan error, len(addresses)*3)
	closeAll := func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}
	defer closeAll()

	for _, rawAddress := range addresses {
		address, err := netip.ParseAddr(rawAddress)
		if err != nil {
			return fmt.Errorf("parse serve address %q: %w", rawAddress, err)
		}
		tcpListener, err := net.Listen("tcp", net.JoinHostPort(address.String(), strconv.Itoa(tcpPort)))
		if err != nil {
			return fmt.Errorf("listen TCP on %s: %w", address, err)
		}
		closers = append(closers, tcpListener)
		go serveTCP(tcpListener, token, errorsCh)

		for _, port := range []int{udpPort, quicPort} {
			packetConn, err := net.ListenPacket("udp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
			if err != nil {
				return fmt.Errorf("listen UDP on %s:%d: %w", address, port, err)
			}
			closers = append(closers, packetConn)
			go serveUDP(packetConn, token, errorsCh)
		}
	}

	fmt.Printf("SERVE_READY %s\n", token)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		return nil
	case err := <-errorsCh:
		return err
	}
}

func serveTCP(listener net.Listener, token string, errorsCh chan<- error) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			errorsCh <- fmt.Errorf("accept TCP: %w", err)
			return
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		count, readErr := connection.Read(buffer)
		if count > 0 {
			_, readErr = connection.Write([]byte(token))
		}
		closeErr := connection.Close()
		if readErr != nil {
			errorsCh <- fmt.Errorf("serve TCP connection: %w", readErr)
			return
		}
		if closeErr != nil {
			errorsCh <- fmt.Errorf("close TCP connection: %w", closeErr)
			return
		}
	}
}

func serveUDP(connection net.PacketConn, token string, errorsCh chan<- error) {
	buffer := make([]byte, 64)
	for {
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			errorsCh <- fmt.Errorf("read UDP packet: %w", err)
			return
		}
		if count == 0 {
			continue
		}
		if _, err := connection.WriteTo([]byte(token), peer); err != nil {
			errorsCh <- fmt.Errorf("write UDP packet: %w", err)
			return
		}
	}
}

func runProbe(args []string) error {
	set := newFlagSet("probe")
	network := set.String("network", "", "tcp, udp, or udp-quic")
	target := set.String("target", "", "literal target host and port")
	source := set.String("source", "", "literal source address")
	expect := set.String("expect", "", "expected response token")
	timeoutText := set.String("timeout", "2s", "probe deadline")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *target == "" || *source == "" || *expect == "" {
		return errors.New("probe requires network, target, source, and expect flags")
	}
	if *network != "tcp" && *network != "udp" && *network != "udp-quic" {
		return fmt.Errorf("unsupported probe network %q", *network)
	}
	deadline, err := time.ParseDuration(*timeoutText)
	if err != nil || deadline <= 0 || deadline > 10*time.Second {
		return errors.New("probe timeout must be greater than zero and at most 10s")
	}
	return probeTraffic(*network, *target, *source, *expect, deadline)
}

func probeTraffic(network, target, source, expected string, timeout time.Duration) error {
	sourceAddress, err := netip.ParseAddr(source)
	if err != nil {
		return fmt.Errorf("parse source address: %w", err)
	}
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("parse target: %w", err)
	}
	targetAddress, err := netip.ParseAddr(targetHost)
	if err != nil || targetAddress.Is4() != sourceAddress.Is4() {
		return errors.New("source and target must be literal addresses of the same family")
	}

	dialNetwork := network
	if network == "udp-quic" {
		dialNetwork = "udp"
	}
	dialer := net.Dialer{Timeout: timeout}
	if dialNetwork == "tcp" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(sourceAddress.AsSlice())}
	} else {
		dialer.LocalAddr = &net.UDPAddr{IP: net.IP(sourceAddress.AsSlice())}
	}
	connection, err := dialer.Dial(dialNetwork, target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", network, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := connection.Write([]byte("probe")); err != nil {
		return fmt.Errorf("write probe: %w", err)
	}
	buffer := make([]byte, 64)
	count, err := connection.Read(buffer)
	if err != nil {
		return fmt.Errorf("read probe: %w", err)
	}
	if actual := string(buffer[:count]); actual != expected {
		return fmt.Errorf("response token %q does not match %q", actual, expected)
	}
	return nil
}

func runApply(args []string) error {
	set := newFlagSet("apply")
	revision := set.String("revision", "", "revision ID")
	profile := set.String("profile", "suffix", "domain profile")
	fault := set.String("fault", "none", "single injected fault")
	available := set.Bool("available", true, "whether the VPN interface is usable")
	labRoot := set.String("lab-root", "", "absolute lab root")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *revision == "" {
		return errors.New("apply requires revision and lab-root flags")
	}
	if !validFault(*fault) {
		return fmt.Errorf("unsupported fault %q", *fault)
	}
	controller, err := productionController(*labRoot, *fault)
	if err != nil {
		return err
	}
	request, err := applyRequest(*revision, *profile, *available)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return controller.Apply(ctx, request)
}

func runTransactionCommand(command string, args []string) error {
	set := newFlagSet(command)
	labRoot := set.String("lab-root", "", "absolute lab root")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("%s accepts flags only", command)
	}
	controller, err := productionController(*labRoot, "none")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	switch command {
	case "confirm":
		return controller.Confirm()
	case "rollback":
		return controller.Rollback(ctx)
	case "recover":
		return controller.Recover(ctx)
	default:
		return fmt.Errorf("unsupported transaction command %q", command)
	}
}

func validFault(value string) bool {
	switch value {
	case "none", "nft-validate", "dns-validate", "postcheck":
		return true
	default:
		return false
	}
}

func productionController(labRoot, fault string) (*dataplane.Controller, error) {
	if labRoot == "" || !filepath.IsAbs(labRoot) || filepath.Clean(labRoot) != labRoot || labRoot == "/" {
		return nil, errors.New("lab-root must be an absolute clean non-root path")
	}
	info, err := os.Stat(labRoot)
	if err != nil || !info.IsDir() {
		return nil, errors.New("lab-root must be an existing directory")
	}
	runner := &labRunner{
		exec:         linux.ExecRunner{},
		firewallPath: filepath.Join(labRoot, "etc", "50-routerd.nft"),
		dnsPath:      filepath.Join(labRoot, "etc", "routerd.conf"),
		dnsBasePath:  filepath.Join(labRoot, "etc", "dnsmasq-base.conf"),
		dnsPIDPath:   filepath.Join(labRoot, "run", "dnsmasq.pid"),
		fault:        fault,
	}
	return dataplane.NewProductionController(dataplane.ProductionConfig{
		StateRoot:           filepath.Join(labRoot, "state"),
		LockPath:            filepath.Join(labRoot, "run", "apply.lock"),
		FirewallIncludePath: runner.firewallPath,
		DNSIncludePath:      runner.dnsPath,
		ConfirmTimeout:      30 * time.Second,
		Runner:              runner,
	})
}

func applyRequest(revision, profile string, available bool) (dataplane.ApplyRequest, error) {
	serverRoute, err := contracts.ServerRouteForSlot(vpnServerID, 1)
	if err != nil {
		return dataplane.ApplyRequest{}, err
	}
	match := contracts.DomainMatchSuffix
	pattern := "vpn.suite.test"
	switch profile {
	case "suffix":
	case "exact":
		match = contracts.DomainMatchExact
		pattern = "target.vpn.suite.test"
	case "wildcard":
		match = contracts.DomainMatchWildcard
		pattern = "*.vpn.suite.test"
	default:
		return dataplane.ApplyRequest{}, fmt.Errorf("unsupported profile %q", profile)
	}
	plan := contracts.PolicyPlan{
		EvaluationTime: time.Unix(1_700_000_000, 0).UTC(),
		Entries: []contracts.RouteEntry{
			{
				ID: "vpn-domain", Pattern: pattern, Kind: contracts.EntryKindDomain,
				Match: match, Route: contracts.RouteClassVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal},
				Origin: contracts.OriginExternalVPN, ServerID: vpnServerID,
			},
			{
				ID: "system-direct-v4", Pattern: "9.9.9.9", Kind: contracts.EntryKindIP,
				Route: contracts.RouteClassDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}, Origin: contracts.OriginSystemDirect,
			},
			{
				ID: "system-direct-v6", Pattern: "2620:fe::9", Kind: contracts.EntryKindIP,
				Route: contracts.RouteClassDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}, Origin: contracts.OriginSystemDirect,
			},
		},
		ServerRoutes: []contracts.ServerRoute{serverRoute},
	}
	return dataplane.ApplyRequest{
		RevisionID: revision,
		Plan:       plan,
		Inventory: dataplane.RuntimeInventory{
			NFT: nft.Inventory{
				ActiveServerID: vpnServerID,
				DeviceModes: map[string]contracts.DeviceMode{
					workDeviceID: contracts.DeviceModeAlwaysDirect,
				},
				DeviceIPv4:  map[string][]netip.Addr{workDeviceID: {netip.MustParseAddr("10.10.0.3")}},
				DeviceIPv6:  map[string][]netip.Addr{workDeviceID: {netip.MustParseAddr("2001:db8:10::3")}},
				OwnedTables: map[string]string{},
			},
			IPRule: iprule.Inventory{
				Servers:    []iprule.Server{{Route: serverRoute, Interface: "vpn0", Available: available}},
				OwnedMarks: map[uint32]string{}, OwnedTables: map[uint32]string{},
			},
		},
	}, nil
}

type labRunner struct {
	exec         linux.ExecRunner
	firewallPath string
	dnsPath      string
	dnsBasePath  string
	dnsPIDPath   string
	fault        string
	faultUsed    bool
}

func (runner *labRunner) Run(ctx context.Context, program string, args ...string) (linux.Result, error) {
	if program == "fw4" {
		if equalArgs(args, "print") {
			return runner.fw4Print()
		}
		if equalArgs(args, "reload") {
			return runner.fw4Reload(ctx)
		}
		return linux.Result{}, fmt.Errorf("lab fw4 rejects argv %q", args)
	}
	if program == "/etc/init.d/dnsmasq" {
		if !equalArgs(args, "reload") {
			return linux.Result{}, fmt.Errorf("lab dnsmasq service rejects argv %q", args)
		}
		return runner.reloadDNSMasq(ctx)
	}
	if !runner.faultUsed && runner.fault == "nft-validate" && program == "nft" && len(args) == 3 && args[0] == "-c" && args[1] == "-f" {
		runner.faultUsed = true
		return linux.Result{ExitCode: 70}, errors.New("injected nft validation fault")
	}
	if !runner.faultUsed && runner.fault == "dns-validate" && program == "dnsmasq" && len(args) >= 1 && args[0] == "--test" {
		runner.faultUsed = true
		return linux.Result{ExitCode: 70}, errors.New("injected dnsmasq validation fault")
	}
	if !runner.faultUsed && runner.fault == "postcheck" && program == "nft" && equalArgs(args, "list", "table", "inet", nft.TableName) {
		runner.faultUsed = true
		return linux.Result{ExitCode: 70}, errors.New("injected post-check fault")
	}
	return runner.exec.Run(ctx, program, args...)
}

func (runner *labRunner) fw4Print() (linux.Result, error) {
	output := []byte("flush ruleset\n")
	fragment, err := os.ReadFile(runner.firewallPath)
	if errors.Is(err, os.ErrNotExist) {
		return linux.Result{Stdout: output}, nil
	}
	if err != nil {
		return linux.Result{}, fmt.Errorf("read lab firewall include: %w", err)
	}
	output = append(output, fragment...)
	if len(output) == 0 || output[len(output)-1] != '\n' {
		output = append(output, '\n')
	}
	return linux.Result{Stdout: output}, nil
}

func (runner *labRunner) fw4Reload(ctx context.Context) (linux.Result, error) {
	if _, err := runner.exec.Run(ctx, "nft", "list", "table", "inet", nft.TableName); err == nil {
		if _, err := runner.exec.Run(ctx, "nft", "delete", "table", "inet", nft.TableName); err != nil {
			return linux.Result{}, fmt.Errorf("delete active lab nft table: %w", err)
		}
	}
	if _, err := os.Stat(runner.firewallPath); errors.Is(err, os.ErrNotExist) {
		return linux.Result{}, nil
	} else if err != nil {
		return linux.Result{}, fmt.Errorf("inspect lab firewall include: %w", err)
	}
	result, err := runner.exec.Run(ctx, "nft", "-f", runner.firewallPath)
	if err != nil {
		return result, fmt.Errorf("load lab firewall include: %w", err)
	}
	return result, nil
}

func (runner *labRunner) reloadDNSMasq(ctx context.Context) (linux.Result, error) {
	if err := stopPIDFile(runner.dnsPIDPath); err != nil {
		return linux.Result{}, err
	}
	result, err := runner.exec.Run(ctx, "dnsmasq", "--conf-file="+runner.dnsBasePath, "--pid-file="+runner.dnsPIDPath)
	if err != nil {
		return result, fmt.Errorf("restart lab dnsmasq: %w", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(runner.dnsPIDPath)
		if readErr == nil && strings.TrimSpace(string(data)) != "" {
			return result, nil
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return result, fmt.Errorf("read lab dnsmasq PID: %w", readErr)
		}
		if time.Now().After(deadline) {
			return result, errors.New("lab dnsmasq did not publish its PID")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stopPIDFile(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read PID file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		return errors.New("lab dnsmasq PID file is invalid")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("stop lab dnsmasq: %w", err)
	}
	deadline := time.Now().Add(time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pid) {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("kill lab dnsmasq: %w", err)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove lab dnsmasq PID file: %w", err)
	}
	return nil
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func equalArgs(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
