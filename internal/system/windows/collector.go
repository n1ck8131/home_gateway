package windows

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	maxSnapshotBytes    = 16 << 20
	maxStderrBytes      = 64 << 10
	maxAdapters         = 256
	maxAddresses        = 4096
	maxRoutes           = 20000
	maxCompartments     = 256
	maxDNSServerSets    = 1024
	maxServersPerSet    = 64
	maxNRPTRules        = 10000
	maxWindowsMetric    = uint64(1<<32 - 1)
	adminStatusUp       = 1
	operationalStatusUp = 1
	addressDeprecated   = 3
	addressPreferred    = 4
	routeStateAlive     = 0
)

// SnapshotRunner has no command or argument parameters on purpose. Production
// code can execute only the fixed, read-only inventory program below.
type SnapshotRunner interface {
	Output(context.Context) ([]byte, error)
}

type NativeCollector struct {
	Runner SnapshotRunner
}

type ExecRunner struct{}

type nativeInventoryPaths struct {
	WindowsDirectory string
	SystemDirectory  string
}

type inventoryCommand struct {
	Executable  string
	Arguments   []string
	Environment []string
	Directory   string
}

// inventoryScript imports only pinned, absolute inbox-module manifests. It
// contains no interpolated config, endpoint, adapter, or user-controlled text.
const inventoryScript = `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

Import-Module -Name $env:HG_UTILITY_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_NETADAPTER_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_NETTCPIP_MANIFEST -Force -ErrorAction Stop
Import-Module -Name $env:HG_DNSCLIENT_MANIFEST -Force -ErrorAction Stop

$adapters = [System.Collections.Generic.List[object]]::new()
foreach ($adapter in @(NetAdapter\Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {
    if ($adapters.Count -ge 256) { throw 'adapter inventory limit exceeded' }
    $null = $adapters.Add([pscustomobject][ordered]@{
        name = [string]$adapter.Name
        description = [string]$adapter.InterfaceDescription
        interfaceIndex = [int]$adapter.ifIndex
        interfaceGuid = ([guid]$adapter.InterfaceGuid).ToString('D').ToLowerInvariant()
        hardwareInterface = [bool]$adapter.HardwareInterface
        adminStatus = [int]$adapter.InterfaceAdminStatus
        operationalStatus = [int]$adapter.InterfaceOperationalStatus
    })
}

$addresses = [System.Collections.Generic.List[object]]::new()
foreach ($address in @(NetTCPIP\Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop)) {
    if ($addresses.Count -ge 4096) { throw 'address inventory limit exceeded' }
    $null = $addresses.Add([pscustomobject][ordered]@{
        interfaceIndex = [int]$address.InterfaceIndex
        addressFamily = [int]$address.AddressFamily
        ipAddress = [string]$address.IPAddress
        prefixLength = [int]$address.PrefixLength
        addressState = [int]$address.AddressState
        skipAsSource = [bool]$address.SkipAsSource
    })
}

$compartments = [System.Collections.Generic.List[object]]::new()
foreach ($compartment in @(NetTCPIP\Get-NetCompartment -ErrorAction Stop)) {
    if ($compartments.Count -ge 256) { throw 'network compartment inventory limit exceeded' }
    $null = $compartments.Add([pscustomobject][ordered]@{ compartmentId = [int]$compartment.CompartmentId })
}

$routes = [System.Collections.Generic.List[object]]::new()
foreach ($route in @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop)) {
    if ($routes.Count -ge 20000) { throw 'route inventory limit exceeded' }
    $null = $routes.Add([pscustomobject][ordered]@{
        interfaceIndex = [int]$route.InterfaceIndex
        compartmentId = [int]$route.CompartmentId
        addressFamily = [int]$route.AddressFamily
        destinationPrefix = [string]$route.DestinationPrefix
        nextHop = [string]$route.NextHop
        routeMetric = [uint64]$route.RouteMetric
        interfaceMetric = [uint64]$route.InterfaceMetric
        state = [int]$route.State
    })
}

$dnsServers = [System.Collections.Generic.List[object]]::new()
foreach ($dns in @(DnsClient\Get-DnsClientServerAddress -ErrorAction Stop)) {
    if ($dnsServers.Count -ge 1024) { throw 'DNS inventory limit exceeded' }
    $serverAddresses = [string[]]@($dns.ServerAddresses)
    if ($serverAddresses.Count -gt 64) { throw 'DNS server limit exceeded' }
    $null = $dnsServers.Add([pscustomobject][ordered]@{
        interfaceIndex = [int]$dns.InterfaceIndex
        addressFamily = [int]$dns.AddressFamily
        serverAddresses = $serverAddresses
    })
}

$nrptRuleCount = @((DnsClient\Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)).Count
if ($nrptRuleCount -gt 10000) { throw 'NRPT inventory limit exceeded' }

$snapshot = [pscustomobject][ordered]@{
    adapters = @($adapters.ToArray())
    compartments = @($compartments.ToArray())
    addresses = @($addresses.ToArray())
    routes = @($routes.ToArray())
    dnsServers = @($dnsServers.ToArray())
    nrptRuleCount = [int]$nrptRuleCount
}
Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $snapshot -Compress -Depth 5`

func (ExecRunner) Output(ctx context.Context) ([]byte, error) {
	paths, err := resolveNativeInventoryPaths()
	if err != nil {
		return nil, err
	}
	spec, err := buildInventoryCommand(paths)
	if err != nil {
		return nil, err
	}
	// #nosec G204 -- executable, arguments, and environment come only from the
	// fixed System32 resolver and buildInventoryCommand; no caller input enters
	// this command surface.
	command := exec.CommandContext(ctx, spec.Executable, spec.Arguments...)
	command.Env = append([]string(nil), spec.Environment...)
	command.Dir = spec.Directory
	var stdout boundedBuffer
	stdout.limit = maxSnapshotBytes
	var stderr boundedBuffer
	stderr.limit = maxStderrBytes
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("trusted Windows inventory command failed")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("trusted Windows inventory output exceeded its limit")
	}
	return append([]byte(nil), stdout.data...), nil
}

func buildInventoryCommand(paths nativeInventoryPaths) (inventoryCommand, error) {
	windowsDirectory := filepath.Clean(paths.WindowsDirectory)
	systemDirectory := filepath.Clean(paths.SystemDirectory)
	if !filepath.IsAbs(windowsDirectory) || !filepath.IsAbs(systemDirectory) {
		return inventoryCommand{}, errors.New("trusted Windows inventory paths are not absolute")
	}
	if !strings.EqualFold(filepath.Base(systemDirectory), "System32") {
		return inventoryCommand{}, errors.New("trusted Windows system directory is not System32")
	}
	relativeSystem, err := filepath.Rel(windowsDirectory, systemDirectory)
	if err != nil || relativeSystem == "." || relativeSystem == ".." || strings.HasPrefix(relativeSystem, ".."+string(filepath.Separator)) {
		return inventoryCommand{}, errors.New("trusted Windows system directory is invalid")
	}
	powerShellRoot := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0")
	modulesRoot := filepath.Join(powerShellRoot, "Modules")
	powerShell := filepath.Join(powerShellRoot, "powershell.exe")
	utilityManifest := filepath.Join(modulesRoot, "Microsoft.PowerShell.Utility", "Microsoft.PowerShell.Utility.psd1")
	netAdapterManifest := filepath.Join(modulesRoot, "NetAdapter", "NetAdapter.psd1")
	netTCPIPManifest := filepath.Join(modulesRoot, "NetTCPIP", "NetTCPIP.psd1")
	dnsClientManifest := filepath.Join(modulesRoot, "DnsClient", "DnsClient.psd1")
	environment := []string{
		"SystemRoot=" + windowsDirectory,
		"WINDIR=" + windowsDirectory,
		"ComSpec=" + filepath.Join(systemDirectory, "cmd.exe"),
		"PATH=" + systemDirectory,
		"PATHEXT=.COM;.EXE;.BAT;.CMD",
		"PSModulePath=" + modulesRoot,
		"HG_UTILITY_MANIFEST=" + utilityManifest,
		"HG_NETADAPTER_MANIFEST=" + netAdapterManifest,
		"HG_NETTCPIP_MANIFEST=" + netTCPIPManifest,
		"HG_DNSCLIENT_MANIFEST=" + dnsClientManifest,
	}
	return inventoryCommand{
		Executable: powerShell,
		Arguments: []string{
			"-NoLogo",
			"-NoProfile",
			"-NonInteractive",
			"-OutputFormat", "Text",
			"-Command", inventoryScript,
		},
		Environment: environment,
		Directory:   systemDirectory,
	}, nil
}

type boundedBuffer struct {
	data     []byte
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - len(buffer.data)
	if remaining > 0 {
		count := len(data)
		if count > remaining {
			count = remaining
		}
		buffer.data = append(buffer.data, data[:count]...)
	}
	if len(data) > remaining {
		buffer.overflow = true
	}
	return len(data), nil
}

type rawInventorySnapshot struct {
	Adapters      *[]rawAdapterRecord     `json:"adapters"`
	Compartments  *[]rawCompartmentRecord `json:"compartments"`
	Addresses     *[]rawAddressRecord     `json:"addresses"`
	Routes        *[]rawRouteRecord       `json:"routes"`
	DNSServers    *[]rawDNSRecord         `json:"dnsServers"`
	NRPTRuleCount *int                    `json:"nrptRuleCount"`
}

type rawCompartmentRecord struct {
	CompartmentID *int `json:"compartmentId"`
}

type rawAdapterRecord struct {
	Name              *string `json:"name"`
	Description       *string `json:"description"`
	InterfaceIndex    *int    `json:"interfaceIndex"`
	InterfaceGUID     *string `json:"interfaceGuid"`
	HardwareInterface *bool   `json:"hardwareInterface"`
	AdminStatus       *int    `json:"adminStatus"`
	OperationalStatus *int    `json:"operationalStatus"`
}

type rawAddressRecord struct {
	InterfaceIndex *int    `json:"interfaceIndex"`
	AddressFamily  *int    `json:"addressFamily"`
	IPAddress      *string `json:"ipAddress"`
	PrefixLength   *int    `json:"prefixLength"`
	AddressState   *int    `json:"addressState"`
	SkipAsSource   *bool   `json:"skipAsSource"`
}

type rawRouteRecord struct {
	InterfaceIndex  *int    `json:"interfaceIndex"`
	CompartmentID   *int    `json:"compartmentId"`
	AddressFamily   *int    `json:"addressFamily"`
	Destination     *string `json:"destinationPrefix"`
	NextHop         *string `json:"nextHop"`
	RouteMetric     *uint64 `json:"routeMetric"`
	InterfaceMetric *uint64 `json:"interfaceMetric"`
	State           *int    `json:"state"`
}

type rawDNSRecord struct {
	InterfaceIndex *int      `json:"interfaceIndex"`
	AddressFamily  *int      `json:"addressFamily"`
	Servers        *[]string `json:"serverAddresses"`
}

func (collector NativeCollector) Collect(ctx context.Context) (Inventory, error) {
	runner := collector.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	data, err := runner.Output(ctx)
	if err != nil {
		return Inventory{}, errors.New("windows network inventory failed")
	}
	return parseInventorySnapshot(data)
}

func parseInventorySnapshot(data []byte) (Inventory, error) {
	if len(data) > maxSnapshotBytes {
		return Inventory{}, errors.New("windows network inventory exceeds its size limit")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw rawInventorySnapshot
	if err := decoder.Decode(&raw); err != nil {
		return Inventory{}, errors.New("windows network inventory is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Inventory{}, errors.New("windows network inventory has trailing data")
	}
	if raw.Adapters == nil || raw.Compartments == nil || raw.Addresses == nil || raw.Routes == nil || raw.DNSServers == nil || raw.NRPTRuleCount == nil {
		return Inventory{}, errors.New("windows network inventory is incomplete")
	}
	if len(*raw.Adapters) == 0 || len(*raw.Adapters) > maxAdapters || len(*raw.Compartments) == 0 || len(*raw.Compartments) > maxCompartments || len(*raw.Addresses) > maxAddresses || len(*raw.Routes) > maxRoutes || len(*raw.DNSServers) > maxDNSServerSets || *raw.NRPTRuleCount < 0 || *raw.NRPTRuleCount > maxNRPTRules {
		return Inventory{}, errors.New("windows network inventory count is invalid")
	}
	if err := validateDefaultNetworkCompartment(*raw.Compartments); err != nil {
		return Inventory{}, err
	}

	adapters, adaptersByIndex, err := parseAdapters(*raw.Adapters)
	if err != nil {
		return Inventory{}, err
	}
	if err := joinAddresses(*raw.Addresses, adaptersByIndex); err != nil {
		return Inventory{}, err
	}
	routes, err := parseRoutes(*raw.Routes, adaptersByIndex)
	if err != nil {
		return Inventory{}, err
	}
	dnsPolicy, err := parseDNSPolicy(*raw.DNSServers, *raw.NRPTRuleCount, adaptersByIndex)
	if err != nil {
		return Inventory{}, err
	}
	sort.Slice(adapters, func(left, right int) bool { return adapters[left].Index < adapters[right].Index })
	return Inventory{
		Adapters:                   adapters,
		Routes:                     routes,
		DNSPolicy:                  dnsPolicy,
		RouteSnapshotAuthoritative: true,
		DNSPolicyObserved:          true,
	}, nil
}

func parseAdapters(records []rawAdapterRecord) ([]Adapter, map[int]*Adapter, error) {
	adapters := make([]Adapter, 0, len(records))
	byIndex := make(map[int]*Adapter, len(records))
	guids := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.Name == nil || record.Description == nil || record.InterfaceIndex == nil || record.InterfaceGUID == nil || record.HardwareInterface == nil || record.AdminStatus == nil || record.OperationalStatus == nil {
			return nil, nil, errors.New("windows adapter inventory is incomplete")
		}
		name := strings.TrimSpace(*record.Name)
		description := strings.TrimSpace(*record.Description)
		if name == "" || *record.InterfaceIndex <= 0 || !validAdminStatus(*record.AdminStatus) || !validOperationalStatus(*record.OperationalStatus) {
			return nil, nil, errors.New("windows adapter inventory value is invalid")
		}
		guid, err := canonicalGUID(*record.InterfaceGUID)
		if err != nil {
			return nil, nil, errors.New("windows adapter inventory GUID is invalid")
		}
		if _, duplicate := byIndex[*record.InterfaceIndex]; duplicate {
			return nil, nil, errors.New("windows adapter inventory has duplicate indices")
		}
		if _, duplicate := guids[guid]; duplicate {
			return nil, nil, errors.New("windows adapter inventory has duplicate GUIDs")
		}
		kind := DetectAdapterKind(name, description)
		if kind == AdapterOther && *record.HardwareInterface {
			kind = AdapterPhysical
		}
		up := *record.AdminStatus == adminStatusUp && *record.OperationalStatus == operationalStatusUp
		if description == "" && up && kind == AdapterOther {
			return nil, nil, errors.New("active Windows adapter cannot be classified without a description")
		}
		adapters = append(adapters, Adapter{
			Name:              name,
			Description:       description,
			Index:             *record.InterfaceIndex,
			InterfaceGUID:     guid,
			HardwareInterface: *record.HardwareInterface,
			Kind:              kind,
			AdminStatus:       *record.AdminStatus,
			OperationalStatus: *record.OperationalStatus,
			Up:                up,
		})
		byIndex[*record.InterfaceIndex] = &adapters[len(adapters)-1]
		guids[guid] = struct{}{}
	}
	return adapters, byIndex, nil
}

func joinAddresses(records []rawAddressRecord, adapters map[int]*Adapter) error {
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.InterfaceIndex == nil || record.AddressFamily == nil || record.IPAddress == nil || record.PrefixLength == nil || record.AddressState == nil || record.SkipAsSource == nil {
			return errors.New("windows address inventory is incomplete")
		}
		family, bitLength, err := parseNumericFamily(*record.AddressFamily)
		if err != nil || *record.InterfaceIndex <= 0 || *record.PrefixLength < 0 || *record.PrefixLength > bitLength || *record.AddressState < 0 || *record.AddressState > addressPreferred {
			return errors.New("windows address inventory value is invalid")
		}
		address, err := netip.ParseAddr(strings.TrimSpace(*record.IPAddress))
		if err != nil || address.Is4In6() || addressFamily(address) != family {
			return errors.New("windows address inventory address is invalid")
		}
		if address.Zone() != "" {
			if family != FamilyIPv6 || address.Zone() != strconv.Itoa(*record.InterfaceIndex) {
				return errors.New("windows address inventory zone is invalid")
			}
			address = address.WithZone("")
		}
		address = address.Unmap()
		key := strings.Join([]string{strconv.Itoa(*record.InterfaceIndex), string(family), address.String()}, "|")
		if _, duplicate := seen[key]; duplicate {
			return errors.New("windows address inventory has duplicate entries")
		}
		seen[key] = struct{}{}
		adapter := adapters[*record.InterfaceIndex]
		if adapter == nil || (*record.AddressState != addressPreferred && *record.AddressState != addressDeprecated) {
			continue
		}
		adapter.Addresses = append(adapter.Addresses, netip.PrefixFrom(address, *record.PrefixLength).String())
	}
	for _, adapter := range adapters {
		sort.Strings(adapter.Addresses)
	}
	return nil
}

func parseRoutes(records []rawRouteRecord, adapters map[int]*Adapter) ([]Route, error) {
	routes := make([]Route, 0, len(records))
	for _, record := range records {
		if record.InterfaceIndex == nil || record.CompartmentID == nil || record.AddressFamily == nil || record.Destination == nil || record.NextHop == nil || record.RouteMetric == nil || record.InterfaceMetric == nil || record.State == nil {
			return nil, errors.New("windows route inventory is incomplete")
		}
		family, _, err := parseNumericFamily(*record.AddressFamily)
		if err != nil || *record.InterfaceIndex <= 0 || *record.CompartmentID != 1 || *record.RouteMetric > maxWindowsMetric || *record.InterfaceMetric > maxWindowsMetric || *record.State < routeStateAlive || *record.State > 2 {
			return nil, errors.New("windows route inventory value is invalid")
		}
		destination, err := netip.ParsePrefix(strings.TrimSpace(*record.Destination))
		if err != nil || destination.Addr().Zone() != "" || destination.Addr().Is4In6() || addressFamily(destination.Addr()) != family {
			return nil, errors.New("windows route inventory destination is invalid")
		}
		nextHop, err := netip.ParseAddr(strings.TrimSpace(*record.NextHop))
		if err != nil || nextHop.Zone() != "" || nextHop.Is4In6() || addressFamily(nextHop) != family {
			return nil, errors.New("windows route inventory next hop is invalid")
		}
		adapter := adapters[*record.InterfaceIndex]
		interfaceGUID := ""
		if adapter != nil {
			interfaceGUID = adapter.InterfaceGUID
		} else if *record.State == routeStateAlive && destination.Bits() == 0 {
			return nil, errors.New("windows default route interface identity is unresolved")
		}
		routes = append(routes, Route{
			Family:          family,
			Destination:     destination.Masked().String(),
			NextHop:         nextHop.Unmap().String(),
			InterfaceIndex:  *record.InterfaceIndex,
			InterfaceGUID:   interfaceGUID,
			RouteMetric:     *record.RouteMetric,
			InterfaceMetric: *record.InterfaceMetric,
			Metric:          *record.RouteMetric + *record.InterfaceMetric,
			State:           *record.State,
		})
	}
	sort.Slice(routes, func(left, right int) bool {
		if routes[left].Family != routes[right].Family {
			return routes[left].Family < routes[right].Family
		}
		if routes[left].Destination != routes[right].Destination {
			return routes[left].Destination < routes[right].Destination
		}
		if routes[left].Metric != routes[right].Metric {
			return routes[left].Metric < routes[right].Metric
		}
		return routes[left].InterfaceIndex < routes[right].InterfaceIndex
	})
	return routes, nil
}

func validateDefaultNetworkCompartment(records []rawCompartmentRecord) error {
	if len(records) != 1 || records[0].CompartmentID == nil || *records[0].CompartmentID != 1 {
		return errors.New("P3.5 requires the single default Windows network compartment")
	}
	return nil
}

func parseDNSPolicy(records []rawDNSRecord, nrptRuleCount int, adapters map[int]*Adapter) (DNSPolicy, error) {
	serverSets := make([]DNSServerSet, 0, len(records))
	seenSets := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record.InterfaceIndex == nil || record.AddressFamily == nil || record.Servers == nil {
			return DNSPolicy{}, errors.New("windows DNS inventory is incomplete")
		}
		family, _, err := parseNumericFamily(*record.AddressFamily)
		if err != nil || *record.InterfaceIndex <= 0 || len(*record.Servers) > maxServersPerSet {
			return DNSPolicy{}, errors.New("windows DNS inventory value is invalid")
		}
		setKey := strings.Join([]string{strconv.Itoa(*record.InterfaceIndex), string(family)}, "|")
		if _, duplicate := seenSets[setKey]; duplicate {
			return DNSPolicy{}, errors.New("windows DNS inventory has duplicate interface families")
		}
		seenSets[setKey] = struct{}{}
		servers := make([]string, 0, len(*record.Servers))
		seenServers := make(map[string]struct{}, len(*record.Servers))
		for _, value := range *record.Servers {
			address, parseErr := netip.ParseAddr(strings.TrimSpace(value))
			if parseErr != nil || address.Is4In6() || addressFamily(address) != family {
				return DNSPolicy{}, errors.New("windows DNS server address is invalid")
			}
			if address.Zone() != "" && (family != FamilyIPv6 || address.Zone() != strconv.Itoa(*record.InterfaceIndex)) {
				return DNSPolicy{}, errors.New("windows DNS server zone is invalid")
			}
			canonical := address.String()
			if _, duplicate := seenServers[canonical]; duplicate {
				return DNSPolicy{}, errors.New("windows DNS inventory has duplicate servers")
			}
			seenServers[canonical] = struct{}{}
			servers = append(servers, canonical)
		}
		sort.Strings(servers)
		interfaceGUID := ""
		if adapter := adapters[*record.InterfaceIndex]; adapter != nil {
			interfaceGUID = adapter.InterfaceGUID
		}
		serverSets = append(serverSets, DNSServerSet{
			Family:         family,
			InterfaceIndex: *record.InterfaceIndex,
			InterfaceGUID:  interfaceGUID,
			Servers:        servers,
		})
	}
	sort.Slice(serverSets, func(left, right int) bool {
		if serverSets[left].InterfaceIndex != serverSets[right].InterfaceIndex {
			return serverSets[left].InterfaceIndex < serverSets[right].InterfaceIndex
		}
		return serverSets[left].Family < serverSets[right].Family
	})
	return DNSPolicy{ServerSets: serverSets, EffectiveNRPTRuleCount: nrptRuleCount}, nil
}

func validAdminStatus(value int) bool {
	return value >= 1 && value <= 3
}

func validOperationalStatus(value int) bool {
	return value >= 1 && value <= 7
}

func parseNumericFamily(value int) (AddressFamily, int, error) {
	switch value {
	case 2:
		return FamilyIPv4, 32, nil
	case 23:
		return FamilyIPv6, 128, nil
	default:
		return "", 0, errors.New("unsupported address family")
	}
}

func canonicalGUID(value string) (string, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value != strings.ToLower(value) {
		return "", errors.New("GUID is not canonical")
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("GUID is invalid")
	}
	nonzero := false
	for _, item := range decoded {
		if item != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return "", errors.New("GUID is zero")
	}
	return value, nil
}

func DetectAdapterKind(name, description string) AdapterKind {
	normalized := strings.ToLower(name + " " + description)
	if strings.Contains(normalized, "loopback") {
		return AdapterLoopback
	}
	for _, marker := range []string{"redshield", "redlink", "wireguard", "amnezia", "amneziawg", "awg"} {
		if strings.Contains(normalized, marker) {
			return AdapterRedShield
		}
	}
	for _, marker := range []string{"cisco", "anyconnect", "secure client", "secure mobility"} {
		if strings.Contains(normalized, marker) {
			return AdapterCisco
		}
	}
	return AdapterOther
}

func ResolveEndpoint(ctx context.Context, host string) ([]string, error) {
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" && !address.Is4In6() {
		return []string{address.String()}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("endpoint address resolution failed")
	}
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.Zone() != "" {
			continue
		}
		value := address.String()
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, errors.New("endpoint address resolution returned no usable addresses")
	}
	sort.Strings(result)
	return result, nil
}

func routeUsesAdapter(route Route, adapter Adapter) bool {
	if route.InterfaceGUID != "" {
		return route.InterfaceGUID == adapter.InterfaceGUID
	}
	return route.InterfaceIndex > 0 && route.InterfaceIndex == adapter.Index
}
