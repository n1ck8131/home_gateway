[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPayloadSHA256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Schema = 'home-gateway/p35/sink-preflight/v2'
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

    $argumentKey = [string]::Join([char]0, $Arguments)
    $argumentLine = switch ($argumentKey) {
        'status' { 'status'; break }
        "filter$([char]0)list" { 'filter list'; break }
        "list$([char]0)--json" { 'list --json'; break }
        default { throw 'pktmon read-only arguments are not allowlisted' }
    }
    $pktmon = Join-Path ([Environment]::SystemDirectory) 'pktmon.exe'
    $item = Get-Item -LiteralPath $pktmon -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'pktmon executable is invalid'
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pktmon
    $startInfo.Arguments = $argumentLine
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.StandardOutputEncoding = $utf8
    $startInfo.StandardErrorEncoding = $utf8

    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'pktmon read-only query did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $text = $stdoutTask.GetAwaiter().GetResult()
        $errorText = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0 -or $errorText.Length -ne 0) {
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
    $emptySummaries = @(
        'No packet filters are specified.',
        'Packet filters are not specified.',
        (ConvertFrom-CodePoints -Value @(1060, 1080, 1083, 1100, 1090, 1088, 1099, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 32, 1085, 1077, 32, 1091, 1082, 1072, 1079, 1072, 1085, 1099, 46))
    )
    $hasHeader = @($lines | Where-Object { $_ -in $headers }).Count -eq 1
    $hasEmpty = @($lines | Where-Object { $_ -in $emptyMarkers }).Count -eq 1
    $hasEmptySummary = @($lines | Where-Object { $_ -in $emptySummaries }).Count -eq 1
    $filterCount = @($lines | Where-Object { $_ -match '^\d+\s+' }).Count
    $recognizedEmpty = ($lines.Count -eq 2 -and $hasHeader -and $hasEmpty -and $filterCount -eq 0) -or
        ($lines.Count -eq 1 -and $hasEmptySummary -and $filterCount -eq 0)
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

    if ($null -eq $parsed) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }
    $roots = @()
    if ($parsed -is [Array]) {
        $roots = @($parsed)
    } else {
        $roots = @($parsed)
    }
    if ($roots.Count -eq 0 -or $roots.Count -gt 1024) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }

    $components = [Collections.Generic.List[object]]::new()
    foreach ($root in $roots) {
        if ($null -eq $root -or $root -is [Array] -or $root -is [string] -or $root.GetType().IsValueType) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $componentProperties = @($root.PSObject.Properties | Where-Object { $_.Name -ceq 'Components' })
        if ($componentProperties.Count -ne 1 -or $null -eq $componentProperties[0].Value) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $componentValue = $componentProperties[0].Value
        if ($componentValue -isnot [Array] -and $componentValue -isnot [Management.Automation.PSCustomObject]) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $rootComponents = @($componentValue)
        if ($rootComponents.Count -eq 0 -or $components.Count + $rootComponents.Count -gt 65535) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        foreach ($component in $rootComponents) { $components.Add($component) }
    }
    if ($components.Count -eq 0) {
        return [ordered]@{ recognized = $false; monitorable_count = 0 }
    }

    $integerTypes = @([byte], [sbyte], [int16], [uint16], [int32], [uint32], [int64], [uint64])
    $ids = @{}
    foreach ($component in $components) {
        if ($null -eq $component -or $component -is [Array] -or $component -is [string] -or $component.GetType().IsValueType) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $idProperties = @($component.PSObject.Properties | Where-Object { $_.Name -ceq 'Id' })
        $secondaryProperties = @($component.PSObject.Properties | Where-Object { $_.Name -ceq 'SecondaryId' })
        if ($idProperties.Count -ne 1 -or $secondaryProperties.Count -gt 1) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        $id = $idProperties[0].Value
        if ($null -eq $id -or $id.GetType() -notin $integerTypes -or [decimal]$id -le 0) {
            return [ordered]@{ recognized = $false; monitorable_count = 0 }
        }
        if ($secondaryProperties.Count -eq 1) {
            $secondaryID = $secondaryProperties[0].Value
            if ($null -eq $secondaryID -or $secondaryID.GetType() -notin $integerTypes -or [decimal]$secondaryID -lt 0) {
                return [ordered]@{ recognized = $false; monitorable_count = 0 }
            }
            $secondaryKey = ([uint64]$secondaryID).ToString([Globalization.CultureInfo]::InvariantCulture)
        } else {
            $secondaryKey = '<none>'
        }
        $idKey = ([uint64]$id).ToString([Globalization.CultureInfo]::InvariantCulture) + '|' + $secondaryKey
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

function Test-TargetRouteUnavailableError {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExceptionTypeName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FullyQualifiedErrorId,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$MessageId,
        [Parameter(Mandatory = $true)][uint32]$StatusCode,
        [Parameter(Mandatory = $true)][int]$ErrorHResult
    )

    return $ExceptionTypeName -ceq 'Microsoft.Management.Infrastructure.CimException' -and
        $FullyQualifiedErrorId -ceq 'Windows System Error 1231,Find-NetRoute' -and
        $MessageId -ceq 'Windows System Error 1231' -and $StatusCode -eq 1 -and
        $ErrorHResult -eq -2146233088
}

function Get-TargetRouteLookup {
    param([Parameter(Mandatory = $true)][string]$Address)

    try {
        $items = @(NetTCPIP\Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
        return [ordered]@{ unreachable = $false; items = $items }
    } catch {
        $exceptionTypeName = $_.Exception.GetType().FullName
        if ($exceptionTypeName -cne 'Microsoft.Management.Infrastructure.CimException') { throw }
        $fullyQualifiedErrorId = [string]$_.FullyQualifiedErrorId
        $messageId = [string]$_.Exception.MessageId
        $statusCode = $_.Exception.StatusCode
        if ([string]::IsNullOrEmpty($fullyQualifiedErrorId) -or [string]::IsNullOrEmpty($messageId) -or
            $statusCode -isnot [uint32]) { throw }
        $isUnavailable = Test-TargetRouteUnavailableError `
            -ExceptionTypeName $exceptionTypeName `
            -FullyQualifiedErrorId $fullyQualifiedErrorId `
            -MessageId $messageId `
            -StatusCode $statusCode `
            -ErrorHResult ([int]$_.Exception.HResult)
        if (-not $isUnavailable) { throw }
        return [ordered]@{ unreachable = $true; items = @() }
    }
}

function Test-TargetStateReady {
    param(
        [Parameter(Mandatory = $true)][int]$ActiveExactCount,
        [Parameter(Mandatory = $true)][int]$PersistentExactCount,
        [Parameter(Mandatory = $true)][int]$ActiveDefaultCount,
        [Parameter(Mandatory = $true)][int]$SelectedRouteCount,
        [Parameter(Mandatory = $true)][bool]$SelectedIsDefault,
        [Parameter(Mandatory = $true)][int]$SelectedAdapterCount,
        [Parameter(Mandatory = $true)][bool]$SelectedAdapterUp,
        [Parameter(Mandatory = $true)][bool]$SelectedAdapterLoopback,
        [Parameter(Mandatory = $true)][bool]$SelectedRouteUnavailable
    )

    # This qualifies only the documentation-target sink primitive. The real
    # provider endpoint remains subject to its separate physical-route gate.
    $defaultReady = -not $SelectedRouteUnavailable -and
        $ActiveDefaultCount -gt 0 -and
        $SelectedRouteCount -eq 1 -and $SelectedIsDefault -and
        $SelectedAdapterCount -eq 1 -and $SelectedAdapterUp -and -not $SelectedAdapterLoopback
    $unreachableReady = $SelectedRouteUnavailable -and
        $ActiveDefaultCount -eq 0 -and
        $SelectedRouteCount -eq 0 -and -not $SelectedIsDefault -and
        $SelectedAdapterCount -eq 0 -and -not $SelectedAdapterUp -and -not $SelectedAdapterLoopback
    return $ActiveExactCount -eq 0 -and $PersistentExactCount -eq 0 -and
        ($defaultReady -or $unreachableReady)
}

function Get-TargetState {
    param([Parameter(Mandatory = $true)]$Target)

    $expectedDefault = if ($Target.Family -ceq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
    $activeRoutes = @(NetTCPIP\Get-NetRoute -PolicyStore ActiveStore -IncludeAllCompartments -ErrorAction Stop)
    $active = @($activeRoutes | Where-Object {
        [string]$_.DestinationPrefix -ceq $Target.Prefix
    })
    $defaultScopeRoutes = @(NetTCPIP\Get-NetRoute -AddressFamily $Target.Family -PolicyStore ActiveStore -ErrorAction Stop)
    $activeDefaults = @($defaultScopeRoutes | Where-Object {
        [string]$_.DestinationPrefix -ceq $expectedDefault
    })
    $persistent = @(NetTCPIP\Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {
        [string]$_.DestinationPrefix -ceq $Target.Prefix
    })
    $lookup = Get-TargetRouteLookup -Address $Target.Address
    $found = @($lookup.items)
    $route = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' })
    $adapter = @()
    if ($route.Count -eq 1) {
        $adapter = @(NetAdapter\Get-NetAdapter -IncludeHidden -InterfaceIndex ([int]$route[0].InterfaceIndex) -ErrorAction Stop)
    }
    $selectedIsDefault = $route.Count -eq 1 -and [string]$route[0].DestinationPrefix -ceq $expectedDefault
    $selectedIsHardware = $adapter.Count -eq 1 -and [bool]$adapter[0].HardwareInterface
    $selectedIsUp = $adapter.Count -eq 1 -and [int]$adapter[0].MediaConnectionState -eq 1
    $selectedIsLoopback = $route.Count -eq 1 -and [int]$route[0].InterfaceIndex -eq 1
    $ready = Test-TargetStateReady -ActiveExactCount $active.Count -PersistentExactCount $persistent.Count `
        -ActiveDefaultCount $activeDefaults.Count `
        -SelectedRouteCount $route.Count -SelectedIsDefault $selectedIsDefault -SelectedAdapterCount $adapter.Count `
        -SelectedAdapterUp $selectedIsUp -SelectedAdapterLoopback $selectedIsLoopback `
        -SelectedRouteUnavailable ([bool]$lookup.unreachable)
    $pathState = if ($ready -and [bool]$lookup.unreachable) { 'no_route' } elseif ($ready) { 'qualified_default' } else { 'unqualified' }
    $routeResolutionError = if ([bool]$lookup.unreachable) { 1231 } else { $null }

    return [ordered]@{
        family                    = $Target.Family
        active_exact_count        = $active.Count
        persistent_exact_count    = $persistent.Count
        active_default_count      = $activeDefaults.Count
        path_state                = $pathState
        current_egress_path       = $route.Count -eq 1
        route_resolution_error    = $routeResolutionError
        selected_route_count      = $route.Count
        selected_is_default       = $selectedIsDefault
        selected_adapter_count    = $adapter.Count
        selected_adapter_hardware = $selectedIsHardware
        selected_adapter_up       = $selectedIsUp
        selected_adapter_loopback = $selectedIsLoopback
        selected_route_unreachable = [bool]$lookup.unreachable
        ready                     = $ready
    }
}

function Get-LoopbackAssessment {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][object[]]$InterfaceItems,
        [Parameter(Mandatory = $true)][object[]]$AddressItems
    )

    $expectedAddress = if ($Family -ceq 'IPv4') { '127.0.0.1' } else { '::1' }
    $expectedPrefixLength = if ($Family -ceq 'IPv4') { 8 } else { 128 }
    $items = @($InterfaceItems | Where-Object {
        [int]$_.CompartmentId -eq 1 -and [int]$_.InterfaceIndex -eq 1
    })
    $addresses = @($AddressItems | Where-Object {
        $compartmentProperties = @($_.PSObject.Properties | Where-Object { $_.Name -ceq 'CompartmentId' })
        $isDefaultCompartment = $compartmentProperties.Count -eq 0 -or
            ($compartmentProperties.Count -eq 1 -and [int]$compartmentProperties[0].Value -eq 1)
        $isDefaultCompartment -and [int]$_.InterfaceIndex -eq 1 -and
        [string]$_.IPAddress -ceq $expectedAddress -and
        [int]$_.PrefixLength -eq $expectedPrefixLength -and
        [int]$_.AddressState -eq 4
    })
    $metric = $null
    $connected = $false
    if ($items.Count -eq 1 -and $null -ne $items[0].InterfaceMetric) {
        $metric = [uint64]$items[0].InterfaceMetric
        $connected = [int]$items[0].ConnectionState -eq 1
    }
    return [ordered]@{
        family        = $Family
        count         = $items.Count
        address_count = $addresses.Count
        metric        = $metric
        connected     = $connected
        ready         = $items.Count -eq 1 -and $addresses.Count -eq 1 -and $connected -and $null -ne $metric -and $metric -le 65535
    }
}

function Get-LoopbackState {
    param([Parameter(Mandatory = $true)][string]$Family)

    $interfaceItems = @(NetTCPIP\Get-NetIPInterface -AddressFamily $Family -IncludeAllCompartments -ErrorAction Stop)
    $addressItems = @(NetTCPIP\Get-NetIPAddress -AddressFamily $Family -ErrorAction Stop)
    return Get-LoopbackAssessment -Family $Family -InterfaceItems $interfaceItems -AddressItems $addressItems
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
