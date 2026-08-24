[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InventoryFile,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$KnownHostsFile,

    [Parameter(Mandatory)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
$maximumInventoryBytes = 64KB

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string[]]$Required,
        [Parameter(Mandatory)][string]$Path
    )
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) {
        throw "$Path must be an object"
    }
    $names = @($Object.PSObject.Properties.Name)
    foreach ($name in $names) {
        if ($name -notin $Allowed) { throw "$Path contains unknown field: $name" }
    }
    foreach ($name in $Required) {
        if ($name -notin $names) { throw "$Path is missing required field: $name" }
    }
}

function Assert-String {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern
    )
    if ($Value -isnot [string] -or $Value -notmatch $Pattern) {
        throw "$Path is invalid"
    }
    return [string]$Value
}

function Assert-Boolean {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    if ($Value -isnot [bool]) { throw "$Path must be boolean" }
    return [bool]$Value
}

function Assert-NoReparseAncestors {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label cannot contain a symlink or reparse-point path component"
            }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function ConvertTo-IPv4 {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    if ($Value -isnot [string]) { throw "$Path must be an IPv4 address" }
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Path must be an IPv4 address"
    }
    return $address
}

function Assert-PublicIPv4 {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $address = ConvertTo-IPv4 -Value $Value -Path $Path
    $bytes = $address.GetAddressBytes()
    $reserved =
        $bytes[0] -eq 0 -or $bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224 -or
        ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 2) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and $bytes[2] -eq 99) -or
        ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) -or
        ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
        ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)
    if ($reserved) { throw "$Path must be a deployable public IPv4 address" }
    return $address.ToString()
}

function Assert-PrivateIPv4 {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $address = ConvertTo-IPv4 -Value $Value -Path $Path
    $bytes = $address.GetAddressBytes()
    $private =
        $bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    if (-not $private) { throw "$Path must be an RFC1918 management address" }
    return $address.ToString()
}

function Read-Inventory {
    Assert-NoReparseAncestors -Path $InventoryFile -Label 'Acceptance inventory'
    $path = (Resolve-Path -LiteralPath $InventoryFile).Path
    $item = Get-Item -LiteralPath $path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Acceptance inventory cannot be a symlink or reparse point'
    }
    try {
        $inventoryBytes = [IO.File]::ReadAllBytes($path)
    } catch {
        throw "Acceptance inventory could not be read: $($_.Exception.Message)"
    }
    if ($inventoryBytes.Length -le 0 -or $inventoryBytes.Length -gt $maximumInventoryBytes) {
        throw "Acceptance inventory must be between 1 byte and $maximumInventoryBytes bytes"
    }
    try {
        $inventoryText = [Text.UTF8Encoding]::new($false, $true).GetString($inventoryBytes)
        $inventory = $inventoryText | ConvertFrom-Json
    } catch {
        throw "Acceptance inventory is not valid JSON: $($_.Exception.Message)"
    }
    $inventoryHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $inventoryHash = [BitConverter]::ToString($inventoryHasher.ComputeHash($inventoryBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $inventoryHasher.Dispose()
    }
    Assert-ExactProperties -Object $inventory -Allowed @('schema_version', 'sanitized_example', 'router', 'vps', 'tunnel', 'recovery') -Required @('schema_version', 'sanitized_example', 'router', 'vps', 'tunnel', 'recovery') -Path 'inventory'
    if ($inventory.schema_version -ne 1) { throw 'inventory.schema_version must equal 1' }
    $sanitized = Assert-Boolean -Value $inventory.sanitized_example -Path 'inventory.sanitized_example'

    Assert-ExactProperties -Object $inventory.router -Allowed @('host', 'ssh_user', 'board_name', 'openwrt_release', 'openwrt_revision', 'package_arch', 'kernel_version', 'kernel_abi', 'management_ipv4', 'wan_device') -Required @('host', 'ssh_user', 'board_name', 'openwrt_release', 'openwrt_revision', 'package_arch', 'kernel_version', 'kernel_abi', 'management_ipv4', 'wan_device') -Path 'inventory.router'
    $routerHost = Assert-String -Value $inventory.router.host -Path 'inventory.router.host' -Pattern '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'
    $sshUser = Assert-String -Value $inventory.router.ssh_user -Path 'inventory.router.ssh_user' -Pattern '^[a-z_][a-z0-9_-]{0,31}$'
    $board = Assert-String -Value $inventory.router.board_name -Path 'inventory.router.board_name' -Pattern '^glinet,gl-mt6000$'
    $release = Assert-String -Value $inventory.router.openwrt_release -Path 'inventory.router.openwrt_release' -Pattern '^25\.12\.5$'
    $revision = Assert-String -Value $inventory.router.openwrt_revision -Path 'inventory.router.openwrt_revision' -Pattern '^r33051-f5dae5ece4$'
    $architecture = Assert-String -Value $inventory.router.package_arch -Path 'inventory.router.package_arch' -Pattern '^aarch64_cortex-a53$'
    $kernel = Assert-String -Value $inventory.router.kernel_version -Path 'inventory.router.kernel_version' -Pattern '^6\.12\.94$'
    $kernelABI = Assert-String -Value $inventory.router.kernel_abi -Path 'inventory.router.kernel_abi' -Pattern '^kernel-6\.12\.94~5a6c1f71be683ae9980b15d3ce73e24d-r1$'
    $management = if ($sanitized -and $WhatIfPreference) {
        (ConvertTo-IPv4 -Value $inventory.router.management_ipv4 -Path 'inventory.router.management_ipv4').ToString()
    } else {
        Assert-PrivateIPv4 -Value $inventory.router.management_ipv4 -Path 'inventory.router.management_ipv4'
    }
    $wanDevice = Assert-String -Value $inventory.router.wan_device -Path 'inventory.router.wan_device' -Pattern '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$'

    Assert-ExactProperties -Object $inventory.vps -Allowed @('endpoint_ipv4', 'endpoint_port', 'expected_country') -Required @('endpoint_ipv4', 'endpoint_port', 'expected_country') -Path 'inventory.vps'
    $endpoint = if ($sanitized -and $WhatIfPreference) {
        (ConvertTo-IPv4 -Value $inventory.vps.endpoint_ipv4 -Path 'inventory.vps.endpoint_ipv4').ToString()
    } else {
        Assert-PublicIPv4 -Value $inventory.vps.endpoint_ipv4 -Path 'inventory.vps.endpoint_ipv4'
    }
    if ($inventory.vps.endpoint_port -isnot [int] -and $inventory.vps.endpoint_port -isnot [long]) { throw 'inventory.vps.endpoint_port must be an integer' }
    $endpointPort = [int]$inventory.vps.endpoint_port
    if ($endpointPort -lt 1 -or $endpointPort -gt 65535) { throw 'inventory.vps.endpoint_port is outside 1..65535' }
    $country = Assert-String -Value $inventory.vps.expected_country -Path 'inventory.vps.expected_country' -Pattern '^[A-Z]{2}$'

    Assert-ExactProperties -Object $inventory.tunnel -Allowed @('interface', 'expected_up', 'max_handshake_age_seconds') -Required @('interface', 'expected_up', 'max_handshake_age_seconds') -Path 'inventory.tunnel'
    $interface = Assert-String -Value $inventory.tunnel.interface -Path 'inventory.tunnel.interface' -Pattern '^[A-Za-z][A-Za-z0-9_.-]{0,14}$'
    $expectedUp = Assert-Boolean -Value $inventory.tunnel.expected_up -Path 'inventory.tunnel.expected_up'
    if ($inventory.tunnel.max_handshake_age_seconds -isnot [int] -and $inventory.tunnel.max_handshake_age_seconds -isnot [long]) { throw 'inventory.tunnel.max_handshake_age_seconds must be an integer' }
    $maxHandshakeAge = [int]$inventory.tunnel.max_handshake_age_seconds
    if ($maxHandshakeAge -lt 30 -or $maxHandshakeAge -gt 600) { throw 'inventory.tunnel.max_handshake_age_seconds is outside 30..600' }

    Assert-ExactProperties -Object $inventory.recovery -Allowed @('wired_management_verified', 'factory_image_verified', 'vps_console_verified') -Required @('wired_management_verified', 'factory_image_verified', 'vps_console_verified') -Path 'inventory.recovery'
    $wired = Assert-Boolean -Value $inventory.recovery.wired_management_verified -Path 'inventory.recovery.wired_management_verified'
    $factory = Assert-Boolean -Value $inventory.recovery.factory_image_verified -Path 'inventory.recovery.factory_image_verified'
    $console = Assert-Boolean -Value $inventory.recovery.vps_console_verified -Path 'inventory.recovery.vps_console_verified'
    if (-not $WhatIfPreference -and (-not $wired -or -not $factory -or -not $console)) {
        throw 'All recovery attestations must be true before P3 preflight'
    }
    if (-not $WhatIfPreference -and $sanitized) { throw 'Sanitized acceptance inventory is not executable' }

    return [pscustomobject]@{
        InventorySHA256 = $inventoryHash
        Sanitized = $sanitized
        Host = $routerHost
        SSHUser = $sshUser
        Board = $board
        Release = $release
        Revision = $revision
        Architecture = $architecture
        Kernel = $kernel
        KernelABI = $kernelABI
        ManagementIPv4 = $management
        WANDevice = $wanDevice
        EndpointIPv4 = $endpoint
        EndpointPort = $endpointPort
        ExpectedCountry = $country
        TunnelInterface = $interface
        TunnelExpectedUp = $expectedUp
        MaxHandshakeAge = $maxHandshakeAge
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter()][int[]]$AllowedExitCodes = @(0)
    )
    $priorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exitCode -notin $AllowedExitCodes) {
        throw "$FilePath failed with exit code $exitCode"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine).Trim() }
}

$input = Read-Inventory
if ($WhatIfPreference) {
    "WHATIF P3 read-only preflight: $($input.SSHUser)@$($input.Host)"
    "WHATIF evidence directory: $EvidenceDirectory"
    return
}

$knownHostsLexicalPath = [IO.Path]::GetFullPath($KnownHostsFile)
Assert-NoReparseAncestors -Path $knownHostsLexicalPath -Label 'Known hosts'
$knownHosts = (Resolve-Path -LiteralPath $knownHostsLexicalPath).Path
$knownHostsItem = Get-Item -LiteralPath $knownHosts
if (($knownHostsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $knownHostsItem.Length -le 0) {
    throw 'Known hosts must be a non-empty regular file, not a symlink or reparse point'
}
$knownHostsSHA256 = (Get-FileHash -LiteralPath $knownHosts -Algorithm SHA256).Hash.ToLowerInvariant()
$preflightScriptSHA256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$evidencePath = [IO.Path]::GetFullPath($EvidenceDirectory)
Assert-NoReparseAncestors -Path $evidencePath -Label 'Evidence directory'
$evidenceRoot = [IO.Path]::GetPathRoot($evidencePath)
if ($evidencePath -eq $evidenceRoot) { throw 'EvidenceDirectory cannot be a filesystem root' }
if (Test-Path -LiteralPath $evidencePath) {
    if (-not (Test-Path -LiteralPath $evidencePath -PathType Container)) { throw 'EvidenceDirectory must be a directory' }
    $evidenceItem = Get-Item -LiteralPath $evidencePath
    if (($evidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'EvidenceDirectory cannot be a symlink or reparse point'
    }
    if (Get-ChildItem -LiteralPath $evidencePath -Force | Select-Object -First 1) { throw 'EvidenceDirectory must be empty' }
} else {
    New-Item -ItemType Directory -Path $evidencePath | Out-Null
    Assert-NoReparseAncestors -Path $evidencePath -Label 'Evidence directory'
}

$ssh = (Get-Command -Name ssh -ErrorAction Stop).Source
$connectionOptions = @(
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHosts",
    '-o', "GlobalKnownHostsFile=$knownHosts",
    '-o', 'ConnectTimeout=10',
    '-o', 'ConnectionAttempts=1',
    '-o', 'ServerAliveInterval=5',
    '-o', 'ServerAliveCountMax=2',
    '-o', 'LogLevel=ERROR'
)
$target = "$($input.SSHUser)@$($input.Host)"
function Invoke-P3SSH {
    param(
        [Parameter(Mandatory)][string[]]$RemoteArguments,
        [Parameter()][int[]]$AllowedExitCodes = @(0)
    )
    return Invoke-CheckedNative -FilePath $ssh -Arguments ($connectionOptions + @($target) + $RemoteArguments) -AllowedExitCodes $AllowedExitCodes
}

$board = (Invoke-P3SSH -RemoteArguments @('ubus', 'call', 'system', 'board')).Output | ConvertFrom-Json
if ($board.board_name -ne $input.Board) { throw "Unexpected board_name: $($board.board_name)" }
$architecture = (Invoke-P3SSH -RemoteArguments @('apk', '--print-arch')).Output
if ($architecture -ne $input.Architecture) { throw "Unexpected package architecture: $architecture" }
$kernel = (Invoke-P3SSH -RemoteArguments @('uname', '-r')).Output
if ($kernel -ne $input.Kernel) { throw "Unexpected kernel: $kernel" }
$release = (Invoke-P3SSH -RemoteArguments @('cat', '/etc/openwrt_release')).Output
if ($release -notmatch "(?m)^DISTRIB_RELEASE='$([regex]::Escape($input.Release))'$" -or
    $release -notmatch "(?m)^DISTRIB_REVISION='$([regex]::Escape($input.Revision))'$") {
    throw 'Unexpected OpenWrt release or revision'
}
$kernelPackage = Invoke-P3SSH -RemoteArguments @('apk', 'info', '-e', $input.KernelABI) -AllowedExitCodes @(0, 1)
if ($kernelPackage.ExitCode -ne 0) { throw 'Installed kernel ABI/vermagic mismatch' }
$temporaryState = Invoke-P3SSH -RemoteArguments @('test', '-e', '/tmp/home-gateway-p0') -AllowedExitCodes @(0, 1)
if ($temporaryState.ExitCode -eq 0) { throw 'Unresolved AWG2 recovery state exists on the router' }

$defaultRoute = (Invoke-P3SSH -RemoteArguments @('ip', '-4', 'route', 'show', 'table', 'main', 'default')).Output
$defaultLines = @($defaultRoute -split "`r?`n" | Where-Object { $_ })
if ($defaultLines.Count -ne 1 -or $defaultLines[0] -notmatch "(?:^| )dev $([regex]::Escape($input.WANDevice))(?: |$)" -or
    $defaultLines[0] -match "(?:^| )dev $([regex]::Escape($input.TunnelInterface))(?: |$)") {
    throw 'The main IPv4 default route is not the expected WAN route'
}
$endpointRoute = (Invoke-P3SSH -RemoteArguments @('ip', '-4', 'route', 'get', $input.EndpointIPv4)).Output
if ($endpointRoute -notmatch "(?:^| )dev $([regex]::Escape($input.WANDevice))(?: |$)" -or
    $endpointRoute -match "(?:^| )dev $([regex]::Escape($input.TunnelInterface))(?: |$)") {
    throw 'The VPS endpoint route does not remain on WAN'
}
$managementRoute = (Invoke-P3SSH -RemoteArguments @('ip', '-4', 'route', 'get', $input.ManagementIPv4)).Output
if ($managementRoute -match "(?:^| )dev $([regex]::Escape($input.TunnelInterface))(?: |$)") {
    throw 'The router management route unexpectedly uses the tunnel'
}

$handshakeFresh = $false
$tunnelLink = Invoke-P3SSH -RemoteArguments @('ip', 'link', 'show', 'dev', $input.TunnelInterface) -AllowedExitCodes @(0, 1)
if ($input.TunnelExpectedUp) {
    if ($tunnelLink.ExitCode -ne 0) { throw 'The expected AWG tunnel interface is absent' }
    $remoteNow = [long](Invoke-P3SSH -RemoteArguments @('date', '+%s')).Output
    $handshakes = (Invoke-P3SSH -RemoteArguments @('awg', 'show', $input.TunnelInterface, 'latest-handshakes')).Output
    $handshakeLines = @($handshakes -split "`r?`n" | Where-Object { $_ })
    if ($handshakeLines.Count -ne 1 -or $handshakeLines[0] -notmatch "^[^\s]+\s+([0-9]+)$") {
        throw 'Expected exactly one parseable AWG handshake'
    }
    $handshakeAge = $remoteNow - [long]$Matches[1]
    if ($handshakeAge -lt 0 -or $handshakeAge -gt $input.MaxHandshakeAge) {
        throw 'The AWG handshake is missing or stale'
    }
    $endpoints = (Invoke-P3SSH -RemoteArguments @('awg', 'show', $input.TunnelInterface, 'endpoints')).Output
    if ($endpoints -notmatch "^[^\s]+\s+$([regex]::Escape($input.EndpointIPv4)):$($input.EndpointPort)$") {
        throw 'The AWG peer endpoint differs from the approved VPS endpoint'
    }
    $handshakeFresh = $true
} elseif ($tunnelLink.ExitCode -eq 0) {
    throw 'An unexpected AWG tunnel interface already exists'
}

$targetHashBytes = [Text.Encoding]::UTF8.GetBytes($target.ToLowerInvariant())
$targetHasher = [Security.Cryptography.SHA256]::Create()
try {
    $targetHash = [BitConverter]::ToString($targetHasher.ComputeHash($targetHashBytes)).Replace('-', '').ToLowerInvariant()
} finally {
    $targetHasher.Dispose()
}
$report = [ordered]@{
    schema_version = 1
    status = 'preflight-passed'
    collected_at_utc = [DateTime]::UtcNow.ToString('o')
    target_sha256 = $targetHash
    tool = [ordered]@{
        name = 'preflight-p3'
        version = 1
        script_sha256 = $preflightScriptSHA256
    }
    commitments = [ordered]@{
        inventory_sha256 = $input.InventorySHA256
        known_hosts_sha256 = $knownHostsSHA256
    }
    identity = [ordered]@{
        board_name = $input.Board
        openwrt_release = $input.Release
        openwrt_revision = $input.Revision
        package_arch = $input.Architecture
        kernel_version = $input.Kernel
    }
    checks = [ordered]@{
        kernel_abi = 'ok'
        recovery_state_clear = 'ok'
        main_default_route_wan = 'ok'
        endpoint_route_wan = 'ok'
        management_route_not_tunnel = 'ok'
        tunnel_expected_up = $input.TunnelExpectedUp
        handshake_fresh = $handshakeFresh
    }
}
$reportPath = Join-Path $evidencePath 'p3-read-only-preflight.json'
[IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 6) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
'P3_READ_ONLY_PREFLIGHT_PASS'
