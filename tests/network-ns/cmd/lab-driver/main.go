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
	revisionapply "github.com/vsevo/home-gateway/internal/revisions/apply"
	"github.com/vsevo/home-gateway/internal/routing/iprule"
	"github.com/vsevo/home-gateway/internal/routing/nft"
	"github.com/vsevo/home-gateway/internal/system/linux"
	"github.com/vsevo/home-gateway/pkg/contracts"
)

const (
	commandTimeout           = 15 * time.Second
	workDeviceID             = "work"
	vpnServer1ID             = "vpn-1"
	vpnServer2ID             = "vpn-2"
	runtimeLab               = "lab"
	runtimeOpenWRT           = "openwrt"
	watchdogRollbackRestored = "watchdog expiry: restored"
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
	case "sticky-probe":
		return runStickyProbe(args[1:])
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
		go func() {
			if err := serveTCPConnection(connection, token); err != nil {
				errorsCh <- fmt.Errorf("serve TCP connection: %w", err)
			}
		}()
	}
}

func serveTCPConnection(connection net.Conn, token string) error {
	defer connection.Close()
	buffer := make([]byte, 64)
	for {
		if err := connection.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
			return err
		}
		count, err := connection.Read(buffer)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if count == 0 {
			continue
		}
		if _, err := connection.Write([]byte(token)); err != nil {
			return err
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

func runStickyProbe(args []string) error {
	set := newFlagSet("sticky-probe")
	target := set.String("target", "", "literal TCP target host and port")
	source := set.String("source", "", "literal source address")
	expect := set.String("expect", "", "expected response token")
	readyFile := set.String("ready-file", "", "absolute synchronization file")
	continueFile := set.String("continue-file", "", "absolute synchronization file")
	timeoutText := set.String("timeout", "30s", "overall sticky probe deadline")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *target == "" || *source == "" || *expect == "" {
		return errors.New("sticky-probe requires target, source, and expect flags")
	}
	if err := validateSignalPath(*readyFile); err != nil {
		return fmt.Errorf("ready-file: %w", err)
	}
	if err := validateSignalPath(*continueFile); err != nil {
		return fmt.Errorf("continue-file: %w", err)
	}
	if *readyFile == *continueFile {
		return errors.New("ready-file and continue-file must differ")
	}
	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil || timeout <= 0 || timeout > 45*time.Second {
		return errors.New("sticky-probe timeout must be greater than zero and at most 45s")
	}
	return stickyProbe(*target, *source, *expect, *readyFile, *continueFile, timeout)
}

func validateSignalPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("path must be absolute, clean, and non-root")
	}
	return nil
}

func stickyProbe(target, source, expected, readyFile, continueFile string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	connection, err := dialLiteralTCP(target, source, timeout)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := exchangeTCP(connection, expected, time.Until(deadline)); err != nil {
		return fmt.Errorf("initial exchange: %w", err)
	}
	if err := writeSignalFile(readyFile); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(continueFile); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect continue-file: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("continue-file was not created before the deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := exchangeTCP(connection, expected, time.Until(deadline)); err != nil {
		return fmt.Errorf("sticky exchange: %w", err)
	}
	fmt.Printf("STICKY_PROBE_PASS %s\n", expected)
	return nil
}

func dialLiteralTCP(target, source string, timeout time.Duration) (net.Conn, error) {
	sourceAddress, err := netip.ParseAddr(source)
	if err != nil {
		return nil, fmt.Errorf("parse source address: %w", err)
	}
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	targetAddress, err := netip.ParseAddr(targetHost)
	if err != nil || targetAddress.Is4() != sourceAddress.Is4() {
		return nil, errors.New("source and target must be literal addresses of the same family")
	}
	dialer := net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: net.IP(sourceAddress.AsSlice())},
	}
	connection, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial TCP: %w", err)
	}
	return connection, nil
}

func exchangeTCP(connection net.Conn, expected string, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("probe deadline expired")
	}
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

func writeSignalFile(path string) (resultErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sticky-ready-")
	if err != nil {
		return fmt.Errorf("create ready-file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure ready-file: %w", err)
	}
	if _, err := temporary.WriteString("ready\n"); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write ready-file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close ready-file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish ready-file: %w", err)
	}
	return nil
}

func runApply(args []string) error {
	set := newFlagSet("apply")
	revision := set.String("revision", "", "revision ID")
	profile := set.String("profile", "suffix", "domain profile")
	fault := set.String("fault", "none", "single injected fault")
	available := set.Bool("available", true, "whether the VPN interface is usable")
	dualServer := set.Bool("dual-server", false, "render both VPN server slots")
	activeSlot := set.Int("active-slot", 1, "active VPN server slot")
	slot1Available := set.Bool("slot1-available", true, "whether vpn0 is usable")
	slot2Available := set.Bool("slot2-available", true, "whether vpn1 is usable")
	labRoot := set.String("lab-root", "", "absolute lab root")
	runtimeName := set.String("runtime", runtimeLab, "lab or openwrt runtime")
	confirmTimeoutText := set.String("confirm-timeout", "30s", "commit-confirm deadline")
	expectTimeout := set.Bool("expect-timeout", false, "wait for watchdog rollback")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *revision == "" {
		return errors.New("apply requires a revision and flags only")
	}
	if !validFault(*fault) {
		return fmt.Errorf("unsupported fault %q", *fault)
	}
	confirmTimeout, err := time.ParseDuration(*confirmTimeoutText)
	if err != nil || confirmTimeout <= 0 || confirmTimeout > 2*time.Minute {
		return errors.New("confirm-timeout must be greater than zero and at most 2m")
	}
	if *expectTimeout && (*fault != "none" || confirmTimeout > 10*time.Second) {
		return errors.New("expect-timeout requires fault=none and confirm-timeout at most 10s")
	}
	controller, journalPath, err := productionController(*runtimeName, *labRoot, *fault, confirmTimeout)
	if err != nil {
		return err
	}
	options := requestOptions{
		dualServer:     *dualServer,
		activeSlot:     *activeSlot,
		slot1Available: *slot1Available,
		slot2Available: *slot2Available,
	}
	if !options.dualServer {
		options.slot1Available = *available
	}
	request, err := applyRequest(*revision, *profile, options)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	if err := controller.Apply(ctx, request); err != nil {
		return err
	}
	if !*expectTimeout {
		return nil
	}
	return waitForWatchdogRollback(journalPath, confirmTimeout+commandTimeout)
}

func runTransactionCommand(command string, args []string) error {
	set := newFlagSet(command)
	labRoot := set.String("lab-root", "", "absolute lab root")
	runtimeName := set.String("runtime", runtimeLab, "lab or openwrt runtime")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("%s accepts flags only", command)
	}
	controller, _, err := productionController(*runtimeName, *labRoot, "none", 30*time.Second)
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

func productionController(runtimeName, labRoot, fault string, confirmTimeout time.Duration) (*dataplane.Controller, string, error) {
	if runtimeName == runtimeOpenWRT {
		if labRoot != "" {
			return nil, "", errors.New("lab-root must be empty for the openwrt runtime")
		}
		controller, err := dataplane.NewProductionController(dataplane.ProductionConfig{
			ConfirmTimeout: confirmTimeout,
			Runner:         &openWRTRunner{exec: linux.ExecRunner{}, fault: fault},
		})
		return controller, filepath.Join(dataplane.DefaultStateRoot, "journal.json"), err
	}
	if runtimeName != runtimeLab {
		return nil, "", fmt.Errorf("unsupported runtime %q", runtimeName)
	}
	if labRoot == "" || !filepath.IsAbs(labRoot) || filepath.Clean(labRoot) != labRoot || labRoot == "/" {
		return nil, "", errors.New("lab-root must be an absolute clean non-root path")
	}
	info, err := os.Stat(labRoot)
	if err != nil || !info.IsDir() {
		return nil, "", errors.New("lab-root must be an existing directory")
	}
	runner := &labRunner{
		exec:         linux.ExecRunner{},
		firewallPath: filepath.Join(labRoot, "etc", "50-routerd.nft"),
		dnsPath:      filepath.Join(labRoot, "etc", "routerd.conf"),
		dnsBasePath:  filepath.Join(labRoot, "etc", "dnsmasq-base.conf"),
		dnsPIDPath:   filepath.Join(labRoot, "run", "dnsmasq.pid"),
		fault:        fault,
	}
	controller, err := dataplane.NewProductionController(dataplane.ProductionConfig{
		StateRoot:           filepath.Join(labRoot, "state"),
		LockPath:            filepath.Join(labRoot, "run", "apply.lock"),
		FirewallIncludePath: runner.firewallPath,
		DNSIncludePath:      runner.dnsPath,
		ConfirmTimeout:      confirmTimeout,
		Runner:              runner,
	})
	return controller, filepath.Join(labRoot, "state", "journal.json"), err
}

func waitForWatchdogRollback(journalPath string, deadlineAfter time.Duration) error {
	journal := revisionapply.FileJournal{Path: journalPath}
	deadline := time.Now().Add(deadlineAfter)
	for time.Now().Before(deadline) {
		current, err := journal.Load()
		if err != nil {
			return err
		}
		if watchdogRollbackComplete(current) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("watchdog rollback did not complete before the deadline")
}

func watchdogRollbackComplete(journal revisionapply.Journal) bool {
	return journal.State == revisionapply.StateRolledBack && journal.RollbackResult == watchdogRollbackRestored
}

type requestOptions struct {
	dualServer     bool
	activeSlot     int
	slot1Available bool
	slot2Available bool
}

func applyRequest(revision, profile string, options requestOptions) (dataplane.ApplyRequest, error) {
	if options.activeSlot != 1 && (!options.dualServer || options.activeSlot != 2) {
		return dataplane.ApplyRequest{}, errors.New("active slot must be 1, or 2 in dual-server mode")
	}
	serverRoute, err := contracts.ServerRouteForSlot(vpnServer1ID, 1)
	if err != nil {
		return dataplane.ApplyRequest{}, err
	}
	serverRoutes := []contracts.ServerRoute{serverRoute}
	servers := []iprule.Server{{Route: serverRoute, Interface: "vpn0", Available: options.slot1Available}}
	activeServerID := vpnServer1ID
	entryServerID := vpnServer1ID
	if options.dualServer {
		serverRoute2, err := contracts.ServerRouteForSlot(vpnServer2ID, 2)
		if err != nil {
			return dataplane.ApplyRequest{}, err
		}
		serverRoutes = append(serverRoutes, serverRoute2)
		servers = append(servers, iprule.Server{Route: serverRoute2, Interface: "vpn1", Available: options.slot2Available})
		entryServerID = ""
		if options.activeSlot == 2 {
			activeServerID = vpnServer2ID
		}
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
	case "shared":
	default:
		return dataplane.ApplyRequest{}, fmt.Errorf("unsupported profile %q", profile)
	}
	entries := []contracts.RouteEntry{
		{
			ID: "vpn-domain", Pattern: pattern, Kind: contracts.EntryKindDomain,
			Match: match, Route: contracts.RouteClassVPN, Scope: contracts.Scope{Type: contracts.ScopeGlobal},
			Origin: contracts.OriginExternalVPN, ServerID: entryServerID,
		},
		{
			ID: "system-direct-v4", Pattern: "9.9.9.9", Kind: contracts.EntryKindIP,
			Route: contracts.RouteClassDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}, Origin: contracts.OriginSystemDirect,
		},
		{
			ID: "system-direct-v6", Pattern: "2620:fe::9", Kind: contracts.EntryKindIP,
			Route: contracts.RouteClassDirect, Scope: contracts.Scope{Type: contracts.ScopeGlobal}, Origin: contracts.OriginSystemDirect,
		},
	}
	if profile == "shared" {
		entries = append(entries, contracts.RouteEntry{
			ID: "manual-direct-shared", Pattern: "target.vpn.suite.test", Kind: contracts.EntryKindDomain,
			Match: contracts.DomainMatchExact, Route: contracts.RouteClassDirect,
			Scope: contracts.Scope{Type: contracts.ScopeGlobal}, Origin: contracts.OriginManual,
		})
	}
	plan := contracts.PolicyPlan{
		EvaluationTime: time.Unix(1_700_000_000, 0).UTC(),
		Entries:        entries,
		ServerRoutes:   serverRoutes,
	}
	return dataplane.ApplyRequest{
		RevisionID: revision,
		Plan:       plan,
		Inventory: dataplane.RuntimeInventory{
			NFT: nft.Inventory{
				ActiveServerID: activeServerID,
				DeviceModes: map[string]contracts.DeviceMode{
					workDeviceID: contracts.DeviceModeAlwaysDirect,
				},
				DeviceIPv4:  map[string][]netip.Addr{workDeviceID: {netip.MustParseAddr("10.10.0.3")}},
				DeviceIPv6:  map[string][]netip.Addr{workDeviceID: {netip.MustParseAddr("2001:470:10::3")}},
				OwnedTables: map[string]string{},
			},
			IPRule: iprule.Inventory{
				Servers:    servers,
				OwnedMarks: map[uint32]string{}, OwnedTables: map[uint32]string{},
			},
		},
	}, nil
}

type openWRTRunner struct {
	exec      linux.ExecRunner
	fault     string
	faultUsed bool
}

func (runner *openWRTRunner) Run(ctx context.Context, program string, args ...string) (linux.Result, error) {
	if !runner.faultUsed && runner.fault == "nft-validate" && program == "nft" && len(args) == 3 && args[0] == "-c" && args[1] == "-f" {
		runner.faultUsed = true
		return runner.runInvalidFixture(ctx, "nft", []byte("table inet {\n"), "-c", "-f")
	}
	if !runner.faultUsed && runner.fault == "dns-validate" && program == "dnsmasq" && len(args) >= 1 && args[0] == "--test" {
		runner.faultUsed = true
		return runner.runInvalidFixture(ctx, "dnsmasq", []byte("definitely-invalid-routerd-option\n"), "--test", "--conf-file=")
	}
	result, err := runner.exec.Run(ctx, program, args...)
	if err != nil {
		return result, err
	}
	if !runner.faultUsed && runner.fault == "postcheck" && program == "nft" && equalArgs(args, "list", "table", "inet", nft.TableName) {
		runner.faultUsed = true
		return result, errors.New("injected OpenWrt post-check fault")
	}
	return result, nil
}

func (runner *openWRTRunner) runInvalidFixture(ctx context.Context, program string, content []byte, args ...string) (result linux.Result, resultErr error) {
	fixture, err := os.CreateTemp("/tmp", "routerd-invalid-")
	if err != nil {
		return linux.Result{}, fmt.Errorf("create invalid %s fixture: %w", program, err)
	}
	path := fixture.Name()
	defer func() {
		resultErr = errors.Join(resultErr, os.Remove(path))
	}()
	if _, err := fixture.Write(content); err != nil {
		_ = fixture.Close()
		return linux.Result{}, fmt.Errorf("write invalid %s fixture: %w", program, err)
	}
	if err := fixture.Close(); err != nil {
		return linux.Result{}, fmt.Errorf("close invalid %s fixture: %w", program, err)
	}
	if program == "dnsmasq" {
		args[len(args)-1] += path
	} else {
		args = append(args, path)
	}
	result, err = runner.exec.Run(ctx, program, args...)
	if err == nil {
		return result, fmt.Errorf("%s accepted an intentionally invalid fixture", program)
	}
	return result, err
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
