[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPayloadSHA256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Schema = 'home-gateway/p35/sink-preflight/v1'
$script:Targets = @(
    [pscustomobject]@{ Family = 'IPv4'; Address = '192.0.2.1'; Prefix = '192.0.2.1/32' },
    [pscustomobject]@{ Family = 'IPv6'; Address = '2001:db8::1'; Prefix = '2001:db8::1/128' }
)

function Test-ElevatedWindows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-PayloadSHA256 {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'expected payload digest must be one lowercase SHA-256 value'
    }
}

function Import-TrustedWindowsModule {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -notin @('CimCmdlets', 'NetAdapter', 'NetTCPIP')) {
        throw 'trusted module name is not allowlisted'
    }
    $modulesRoot = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\Modules'
    $expectedBase = Join-Path $modulesRoot $Name
    $manifest = Join-Path $expectedBase ($Name + '.psd1')
    $item = Get-Item -LiteralPath $manifest -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'trusted module manifest is invalid'
    }
    $loaded = @(Import-Module -Name $manifest -Force -PassThru -ErrorAction Stop)
    if ($loaded.Count -ne 1 -or -not [string]::Equals($loaded[0].ModuleBase, $expectedBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'trusted module resolved outside System32'
    }
}

function Get-TextSHA256 {
    param([Parameter(Mandatory = $true)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Invoke-PktmonReadOnly {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $pktmon = Join-Path ([Environment]::SystemDirectory) 'pktmon.exe'
    $text = & $pktmon @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw 'pktmon read-only query failed'
    }
    if ($text.Length -gt 4MB) {
        throw 'pktmon read-only output exceeds its bound'
    }
    return $text
}

function ConvertFrom-CodePoints {
    param([Parameter(Mandatory = $true)][int[]]$Value)

    return -join @($Value | ForEach-Object { [char]$_ })
}

function Test-ContainsAny {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string[]]$Value
    )

    foreach ($candidate in $Value) {
        if ($Text.IndexOf($candidate, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Get-PktmonStatusState {
    param([Parameter(Mandatory = $true)][string]$Text)

    $stoppedMarkers = @(
        'Packet Monitor is stopped.',
        'Packet Monitor is not running.',
        (ConvertFrom-CodePoints -Value @(1052, 1086, 1085, 1080, 1090, 1086, 1088, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 32, 1085, 1077, 32, 1079, 1072, 1087, 1091, 1097, 1077, 1085, 46))
    )
    $runningMarkers = @(
        'Packet Monitor is running.',
        'Packet Monitor is already running.',
        (ConvertFrom-CodePoints -Value @(1052, 1086, 1085, 1080, 1090, 1086, 1088, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 32, 1091, 1078, 1077, 32, 1079, 1072, 1087, 1091, 1097, 1077, 1085, 46))
    )
    $stopped = Test-ContainsAny -Text $Text -Value $stoppedMarkers
    $running = Test-ContainsAny -Text $Text -Value $runningMarkers
    return [ordered]@{
        recognized = $stopped -xor $running
        stopped    = $stopped -and -not $running
        running    = $running -and -not $stopped
    }
}

function Get-PktmonFilterState {
    param([Parameter(Mandatory = $true)][string]$Text)

    $lines = @($Text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $headers = @(
        'Packet Filters:',
        (ConvertFrom-CodePoints -Value @(1060, 1080, 1083, 1100, 1090, 1088, 1099, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 58))
    )
    $emptyMarkers = @(
        'None',
        (ConvertFrom-CodePoints -Value @(1053, 1077, 1090))
    )
    $hasHeader = @($lines | Where-Object { $_ -in $headers }).Count -eq 1
    $hasEmpty = @($lines | Where-Object { $_ -in $emptyMarkers }).Count -eq 1
    $filterCount = @($lines | Where-Object { $_ -match '^\d+\s+' }).Count
    $recognizedEmpty = $hasHeader -and $hasEmpty -and $filterCount -eq 0
    $recognizedNonEmpty = $hasHeader -and -not $hasEmpty -and $filterCount -gt 0
    return [ordered]@{
        recognized = $recognizedEmpty -or $recognizedNonEmpty
        count      = $filterCount
        empty      = $recognizedEmpty
    }
}

function Get-PktmonComponentState {
    param([Parameter(Mandatory = $true)][string]$Text)

    try {
        $parsed = $Text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }

    if ($null -eq $parsed -or $parsed -is [Array]) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }
    $componentProperties = @($parsed.PSObject.Properties | Where-Object { $_.Name -ceq 'Components' })
    if ($componentProperties.Count -ne 1 -or $componentProperties[0].Value -isnot [Array]) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }
    $components = @($componentProperties[0].Value)
    if ($components.Count -eq 0 -or $components.Count -gt 65535) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }

    $integerTypes = @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])
    $ids = @{}
    foreach ($component in $components) {
        if ($null -eq $component -or $component -is [Array]) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $idProperties = @($component.PSObject.Properties | Where-Object { $_.Name -ceq 'Id' })
        $secondaryProperties = @($component.PSObject.Properties | Where-Object { $_.Name -ceq 'SecondaryId' })
        if ($idProperties.Count -ne 1 -or $secondaryProperties.Count -ne 1) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $id = $idProperties[0].Value
        $secondaryID = $secondaryProperties[0].Value
        if ($id.GetType() -notin $integerTypes -or [decimal]$id -le 0 -or
            $secondaryID.GetType() -notin $integerTypes -or [decimal]$secondaryID -lt 0) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $idKey = ([uint64]$id).ToString([Globalization.CultureInfo]::InvariantCulture)
        if ($ids.ContainsKey($idKey)) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $ids[$idKey] = $true
    }

    return [ordered]@{
        recognized       = $true
        monitorable_count = $ids.Count
    }
}

function Get-PreflightExitCode {
    param([Parameter(Mandatory = $true)][bool]$Ready)

    if ($Ready) { return 0 }
    return 3
}

function Get-TargetState {
    param([Parameter(Mandatory = $true)]$Target)

    $active = @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop | Where-Object {
        [string]$_.DestinationPrefix -ceq $Target.Prefix
    })
    $persistent = @(NetTCPIP\Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {
        [string]$_.DestinationPrefix -ceq $Target.Prefix
    })
    $found = @(NetTCPIP\Find-NetRoute -RemoteIPAddress $Target.Address -ErrorAction Stop)
    $route = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' })
    $adapter = @()
    if ($route.Count -eq 1) {
        $adapter = @(NetAdapter\Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$route[0].InterfaceIndex) -ErrorAction Stop)
    }
    $selectedIsDefault = $route.Count -eq 1 -and [string]$route[0].DestinationPrefix -in @('0.0.0.0/0', '::/0')
    $selectedIsHardware = $adapter.Count -eq 1 -and [bool]$adapter[0].HardwareInterface
    $selectedIsUp = $adapter.Count -eq 1 -and [int]$adapter[0].MediaConnectionState -eq 1

    return [ordered]@{
        family                    = $Target.Family
        active_exact_count        = $active.Count
        persistent_exact_count    = $persistent.Count
        selected_route_count      = $route.Count
        selected_is_default       = $selectedIsDefault
        selected_adapter_count    = $adapter.Count
        selected_adapter_hardware = $selectedIsHardware
        selected_adapter_up       = $selectedIsUp
        ready                     = $active.Count -eq 0 -and $persistent.Count -eq 0 -and $selectedIsDefault -and $selectedIsHardware -and $selectedIsUp
    }
}

function Get-LoopbackState {
    param([Parameter(Mandatory = $true)][string]$Family)

    $items = @(NetTCPIP\Get-NetIPInterface -AddressFamily $Family -IncludeAllCompartments -ErrorAction Stop | Where-Object {
        [int]$_.CompartmentId -eq 1 -and
        [int]$_.InterfaceIndex -eq 1 -and
        [int]$_.ProtocolIFType -eq 24
    })
    $metric = $null
    $connected = $false
    if ($items.Count -eq 1) {
        $metric = [uint64]$items[0].InterfaceMetric
        $connected = [int]$items[0].ConnectionState -eq 1
    }
    return [ordered]@{
        family    = $Family
        count     = $items.Count
        metric    = $metric
        connected = $connected
        ready     = $items.Count -eq 1 -and $connected -and $metric -le 65535
    }
}

if (-not [string]::IsNullOrEmpty($PSCommandPath)) {
    throw 'P3.5 sink preflight accepts only a hash-pinned in-memory payload'
}
Assert-PayloadSHA256 -Value $ExpectedPayloadSHA256
foreach ($moduleName in @('CimCmdlets', 'NetAdapter', 'NetTCPIP')) {
    Import-TrustedWindowsModule -Name $moduleName
}
if (-not (Test-ElevatedWindows)) {
    throw 'P3.5 sink preflight requires an elevated Administrator session'
}

$statusText = Invoke-PktmonReadOnly -Arguments @('status')
$filterText = Invoke-PktmonReadOnly -Arguments @('filter', 'list')
$componentText = Invoke-PktmonReadOnly -Arguments @('list', '--json')
$statusState = Get-PktmonStatusState -Text $statusText
$filterState = Get-PktmonFilterState -Text $filterText
$componentState = Get-PktmonComponentState -Text $componentText

$targets = @($script:Targets | ForEach-Object { Get-TargetState -Target $_ })
$loopback = @(@('IPv4', 'IPv6') | ForEach-Object { Get-LoopbackState -Family $_ })
$operatingSystem = CimCmdlets\Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$bootMarkerUTC = ([DateTime]$operatingSystem.LastBootUpTime).ToUniversalTime().ToString('O')
$observedAtUTC = [DateTime]::UtcNow.ToString('O')
$ready = $statusState.recognized -and $statusState.stopped
$ready = $ready -and $filterState.recognized -and $filterState.empty
$ready = $ready -and $componentState.recognized -and $componentState.monitorable_count -gt 0
$ready = $ready -and @($targets | Where-Object { -not $_.ready }).Count -eq 0
$ready = $ready -and @($loopback | Where-Object { -not $_.ready }).Count -eq 0
$exitCode = Get-PreflightExitCode -Ready $ready

$result = [ordered]@{
    schema                      = $script:Schema
    payload_sha256              = $ExpectedPayloadSHA256
    observed_at_utc             = $observedAtUTC
    boot_marker_utc             = $bootMarkerUTC
    elevated                    = $true
    advisory_only               = $true
    ready                       = $ready
    exit_code                   = $exitCode
    pktmon_status_recognized    = $statusState.recognized
    pktmon_status_stopped       = $statusState.stopped
    pktmon_filter_recognized    = $filterState.recognized
    pktmon_filter_count         = $filterState.count
    pktmon_status_sha256        = Get-TextSHA256 -Text $statusText
    pktmon_filters_sha256       = Get-TextSHA256 -Text $filterText
    pktmon_component_recognized = $componentState.recognized
    pktmon_component_count      = $componentState.monitorable_count
    targets                     = $targets
    loopback                    = $loopback
}

$result | ConvertTo-Json -Depth 6 -Compress
if ($exitCode -ne 0) {
    $global:LASTEXITCODE = $exitCode
    throw 'P3.5 sink preflight is not ready'
}
