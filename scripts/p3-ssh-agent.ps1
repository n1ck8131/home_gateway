[CmdletBinding()]
param(
    [ValidateSet('', 'AgentPlan', 'AgentStart', 'AgentValidate', 'AgentStop')]
    [string]$Action = '',
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-P3AgentSHA256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-P3AgentSHA256Text([string]$Text) {
    return Get-P3AgentSHA256Bytes -Bytes ([Text.Encoding]::UTF8.GetBytes($Text))
}

function Get-P3AgentFileSHA256([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw 'Git tool path must be absolute' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) { throw 'Git tool file is missing' }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Git tool must be a regular file' }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 67108864) { throw 'Git tool size differs' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function ConvertTo-P3AgentCanonicalValue([object]$Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) {
        $utc = if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        } else { $Value.ToUniversalTime() }
        return $utc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $ordered[$key] = ConvertTo-P3AgentCanonicalValue $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
            $ordered[$property] = ConvertTo-P3AgentCanonicalValue $Value.$property
        }
        return $ordered
    }
    if ($Value -is [Array]) {
        $array = @()
        foreach ($item in $Value) { $array += ,(ConvertTo-P3AgentCanonicalValue $item) }
        return $array
    }
    return $Value
}

function Get-P3AgentCanonicalSHA256([object]$Value) {
    $canonical = ConvertTo-P3AgentCanonicalValue $Value
    $json = ConvertTo-Json -InputObject $canonical -Depth 16 -Compress
    return Get-P3AgentSHA256Text $json
}

function Assert-P3AgentSHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label hash differs" }
}

function Resolve-P3GitOpenSshToolchain([object]$Manifest) {
    $spec = @(
        @{ Path = 'git_ssh_agent_path'; Hash = 'git_ssh_agent_sha256'; Leaf = 'ssh-agent.exe' },
        @{ Path = 'git_ssh_add_path'; Hash = 'git_ssh_add_sha256'; Leaf = 'ssh-add.exe' },
        @{ Path = 'git_ssh_path'; Hash = 'git_ssh_sha256'; Leaf = 'ssh.exe' },
        @{ Path = 'git_scp_path'; Hash = 'git_scp_sha256'; Leaf = 'scp.exe' }
    )
    $resolved = [ordered]@{}
    $roots = @()
    foreach ($entry in $spec) {
        $path = [IO.Path]::GetFullPath([string]$Manifest.($entry.Path))
        if (-not [string]::Equals([IO.Path]::GetFileName($path), $entry.Leaf, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Git OpenSSH executable name differs'
        }
        if ($path -match '(?i)\\Windows\\System32\\OpenSSH\\') { throw 'Windows OpenSSH cannot be mixed with the Git agent' }
        $expected = [string]$Manifest.($entry.Hash)
        Assert-P3AgentSHA256 -Value $expected -Label $entry.Leaf
        if ((Get-P3AgentFileSHA256 $path) -cne $expected) { throw 'Git OpenSSH executable hash differs' }
        $roots += [IO.Path]::GetDirectoryName($path).TrimEnd('\')
        $resolved[$entry.Path] = $path
        $resolved[$entry.Hash] = $expected
    }
    $distinctRoots = @($roots | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    if ($distinctRoots.Count -ne 1) { throw 'all tools must share one Git OpenSSH root' }
    $resolved['toolchain_root'] = $roots[0]
    $resolved['toolchain_root_sha256'] = Get-P3AgentSHA256Text $roots[0].ToLowerInvariant()
    return [pscustomobject]$resolved
}

function New-P3AgentPlan([object]$Manifest) {
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    Assert-P3AgentSHA256 -Value ([string]$Manifest.public_key_fingerprint_sha256) -Label 'public key fingerprint'
    if (-not [IO.File]::Exists([string]$Manifest.public_key_path)) { throw 'dedicated public key file is missing' }
    $publicKeyFileSHA256 = Get-P3AgentFileSHA256 ([string]$Manifest.public_key_path)
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-plan/v1'
        manifest_sha256 = [string]$Manifest.manifest_sha256
        toolchain_root_sha256 = $toolchain.toolchain_root_sha256
        git_ssh_agent_sha256 = $toolchain.git_ssh_agent_sha256
        git_ssh_add_sha256 = $toolchain.git_ssh_add_sha256
        git_ssh_sha256 = $toolchain.git_ssh_sha256
        git_scp_sha256 = $toolchain.git_scp_sha256
        public_key_file_sha256 = $publicKeyFileSHA256
        public_key_fingerprint_sha256 = [string]$Manifest.public_key_fingerprint_sha256
        expected_key_count = 1
    }
    $planHash = Get-P3AgentCanonicalSHA256 $identity
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result['plan_sha256'] = $planHash
    $result['confirmation_challenge'] = 'P3-SSH-AGENT-' + $planHash.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function ConvertFrom-P3AgentOutput([string]$Output) {
    $socketMatches = [regex]::Matches($Output, '(?m)^SSH_AUTH_SOCK=([^;\r\n]+); export SSH_AUTH_SOCK;$')
    $pidMatches = [regex]::Matches($Output, '(?m)^SSH_AGENT_PID=([1-9][0-9]*); export SSH_AGENT_PID;$')
    if ($socketMatches.Count -ne 1 -or $pidMatches.Count -ne 1) { throw 'ssh-agent output is malformed' }
    $socket = $socketMatches[0].Groups[1].Value
    $processId = 0
    if (-not [int]::TryParse($pidMatches[0].Groups[1].Value, [ref]$processId) -or $processId -le 0) { throw 'ssh-agent PID differs' }
    return [pscustomobject]@{ socket = $socket; agent_pid = $processId }
}

function Assert-P3WindowsAgentLaunch([object]$Launch) {
    $expected = @('output', 'schema', 'started_at_utc', 'windows_process_id')
    if ($null -eq $Launch -or $Launch -is [Array] -or
        @(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject @($Launch.PSObject.Properties.Name | Sort-Object)).Count -ne 0 -or
        [string]$Launch.schema -cne 'home-gateway/p3-windows-agent-launch/v1' -or
        $Launch.output -is [string] -or $Launch.output -isnot [Array] -or
        [int]$Launch.windows_process_id -le 0) {
        throw 'Windows agent launch record differs'
    }
    $null = ConvertTo-P3AgentReceiptUtcInstant -Value $Launch.started_at_utc
    return $Launch
}

function Get-P3WindowsAgentStartedAtUtc([object]$Process) {
    if ($null -eq $Process -or $Process.PSObject.Properties.Name -notcontains 'StartTime') {
        throw 'Windows agent process start time differs'
    }
    return ConvertTo-P3AgentObservedUtcInstant -Value $Process.StartTime
}

function Complete-P3OwnedWindowsAgentCleanup([object]$Process, [bool]$Started) {
    if (-not $Started) { return }
    try {
        if (-not [bool]$Process.HasExited) { $Process.Kill() }
        if (-not [bool]$Process.WaitForExit(5000)) { throw 'Windows agent process cleanup timed out' }
    }
    catch { throw "Windows agent process cleanup failed: $($_.Exception.Message)" }
}

function Start-P3WindowsAgentProcess(
    [string]$ExecutablePath,
    [scriptblock]$ProcessRunner,
    [int]$TimeoutSeconds = 10,
    [int]$MaximumOutputRecords = 16,
    [int]$MaximumOutputBytes = 65536
) {
    if ([string]::IsNullOrWhiteSpace($ExecutablePath) -or $ExecutablePath.Contains('"') -or -not [IO.Path]::IsPathRooted($ExecutablePath) -or
        $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 30 -or $MaximumOutputRecords -lt 2 -or $MaximumOutputRecords -gt 64 -or
        $MaximumOutputBytes -lt 128 -or $MaximumOutputBytes -gt 1048576) { throw 'Windows agent launch input differs' }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [IO.Path]::GetFullPath($ExecutablePath)
    $startInfo.Arguments = '-D -s'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $false
    if ($null -ne $ProcessRunner) {
        $records = @(& $ProcessRunner $startInfo $TimeoutSeconds $MaximumOutputRecords $MaximumOutputBytes)
        if ($records.Count -ne 1) { throw 'Windows agent launch record differs' }
        return Assert-P3WindowsAgentLaunch -Launch $records[0]
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $outputBytes = $null
    $started = $false
    try {
        if (-not $process.Start()) { throw 'Windows agent process did not start' }
        $started = $true
        $startedAtUtc = Get-P3WindowsAgentStartedAtUtc -Process $process
        $deadline = $startedAtUtc.AddSeconds($TimeoutSeconds)
        $outputBytes = [IO.MemoryStream]::new()
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        $buffer = [byte[]]::new([Math]::Min(4096, $MaximumOutputBytes))
        $bytes = 0
        $quietDeadline = $null
        $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($readTask.Wait(50)) {
                $read = [int]$readTask.Result
                if ($read -le 0) { break }
                $bytes += $read
                if ($bytes -gt $MaximumOutputBytes) { throw 'Windows agent output bounds differ' }
                $outputBytes.Write($buffer, 0, $read)
                $records = @(($strictUtf8.GetString($outputBytes.ToArray()) -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($records.Count -gt $MaximumOutputRecords) { throw 'Windows agent output bounds differ' }
                if ($records.Count -ge 2) { $quietDeadline = [DateTime]::UtcNow.AddMilliseconds(100) }
                $readTask = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
                continue
            }
            if ($process.HasExited -or ($null -ne $quietDeadline -and [DateTime]::UtcNow -ge $quietDeadline)) { break }
        }
        $records = @(($strictUtf8.GetString($outputBytes.ToArray()) -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($records.Count -lt 2) { throw 'Windows agent output timed out' }
        return [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-windows-agent-launch/v1'
            output = $records
            started_at_utc = $startedAtUtc.ToString('o')
            windows_process_id = [int]$process.Id
        }
    }
    catch {
        $failure = $_
        Complete-P3OwnedWindowsAgentCleanup -Process $process -Started $started
        throw
    }
    finally {
        if ($null -ne $outputBytes) { $outputBytes.Dispose() }
        $process.Dispose()
    }
}

function ConvertTo-P3WindowsCommandLineArgument([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains('"') -or -not [IO.Path]::IsPathRooted($Value)) { throw 'Windows command line path differs' }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\\"')
    $escaped = [regex]::Replace($escaped, '(\\*)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-P3InteractiveAgentAdd([string]$ExecutablePath, [string]$KeyPath, [scriptblock]$ProcessRunner) {
    if ([string]::IsNullOrWhiteSpace($ExecutablePath) -or $ExecutablePath.Contains('"') -or -not [IO.Path]::IsPathRooted($ExecutablePath)) { throw 'ssh-add executable path differs' }
    if ([string]::IsNullOrWhiteSpace($KeyPath) -or $KeyPath.Contains('"') -or -not [IO.Path]::IsPathRooted($KeyPath)) { throw 'ssh-add key path differs' }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [IO.Path]::GetFullPath($ExecutablePath)
    $startInfo.Arguments = ConvertTo-P3WindowsCommandLineArgument -Value $KeyPath
    $startInfo.UseShellExecute = $true
    $startInfo.CreateNoWindow = $false
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Normal
    $startInfo.RedirectStandardInput = $false
    $startInfo.RedirectStandardOutput = $false
    $startInfo.RedirectStandardError = $false
    if ($null -ne $ProcessRunner) {
        $result = @(& $ProcessRunner $startInfo)
        if ($result.Count -ne 1 -or $result[0].PSObject.Properties.Name -notcontains 'exit_code' -or [int]$result[0].exit_code -ne 0) {
            throw 'ssh-add failed for the dedicated key'
        }
        return
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($startInfo)
        if ($null -eq $process) { throw 'ssh-add failed for the dedicated key' }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'ssh-add failed for the dedicated key' }
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Start-P3Agent([object]$Manifest, [scriptblock]$AgentRunner, [scriptblock]$ProcessRunner, [scriptblock]$AddRunner, [scriptblock]$StopRunner) {
    if (-not [string]::IsNullOrEmpty([string]$env:SSH_AUTH_SOCK) -or -not [string]::IsNullOrEmpty([string]$env:SSH_AGENT_PID)) {
        throw 'pre-existing SSH agent environment is not allowed'
    }
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    $launch = $null
    $launchCandidate = $null
    $identityValidated = $false
    try {
        $launchRecords = @(& $AgentRunner $toolchain.git_ssh_agent_path)
        if ($launchRecords.Count -ne 1) { throw 'Windows agent launch record differs' }
        $launchCandidate = $launchRecords[0]
        $launch = Assert-P3WindowsAgentLaunch -Launch $launchCandidate
        $identityReceipt = [pscustomobject]@{
            windows_process_id = [int]$launch.windows_process_id
            started_at_utc = [string]$launch.started_at_utc
        }
        $processes = @(& $ProcessRunner ([int]$identityReceipt.windows_process_id))
        $null = Assert-P3AgentObservedProcess -Toolchain $toolchain -AgentReceipt $identityReceipt -Processes $processes
        $identityValidated = $true
        $output = @($launch.output) -join "`n"
        $started = ConvertFrom-P3AgentOutput -Output $output
        $rawReceipt = [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-ssh-agent-receipt/v2'
            manifest_sha256 = [string]$Manifest.manifest_sha256
            agent_pid = $started.agent_pid
            windows_process_id = [int]$launch.windows_process_id
            socket = $started.socket
            agent_executable_path = $toolchain.git_ssh_agent_path
            agent_executable_sha256 = $toolchain.git_ssh_agent_sha256
            expected_fingerprint_sha256 = [string]$Manifest.public_key_fingerprint_sha256
            started_at_utc = [string]$launch.started_at_utc
        }
        $env:SSH_AUTH_SOCK = $started.socket
        $env:SSH_AGENT_PID = [string]$started.agent_pid
        try { $null = & $AddRunner ([string]$Manifest.private_key_path) }
        catch { throw 'ssh-add failed for the dedicated key' }
        return $rawReceipt
    }
    catch {
        $failure = $_
        $cleanupFailure = $null
        if ($identityValidated) {
            try { $null = & $StopRunner ([int]$launch.windows_process_id) } catch { $cleanupFailure = $_ }
        }
        $env:SSH_AUTH_SOCK = $null
        $env:SSH_AGENT_PID = $null
        if ($null -ne $cleanupFailure) { throw 'agent cleanup failed after start failure' }
        throw $failure
    }
}

function Assert-P3AgentReceipt([object]$Manifest, [object]$AgentReceipt) {
    $expected = @('agent_executable_path', 'agent_executable_sha256', 'agent_pid', 'expected_fingerprint_sha256', 'manifest_sha256', 'schema', 'socket', 'started_at_utc', 'windows_process_id')
    $actual = @($AgentReceipt.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) { throw 'agent receipt schema differs' }
    if ([string]$AgentReceipt.schema -cne 'home-gateway/p3-ssh-agent-receipt/v2' -or
        [string]$AgentReceipt.manifest_sha256 -cne [string]$Manifest.manifest_sha256 -or
        [string]$AgentReceipt.expected_fingerprint_sha256 -cne [string]$Manifest.public_key_fingerprint_sha256) {
        throw 'agent receipt binding differs'
    }
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    if (-not [string]::Equals([string]$AgentReceipt.agent_executable_path, $toolchain.git_ssh_agent_path, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$AgentReceipt.agent_executable_sha256 -cne $toolchain.git_ssh_agent_sha256 -or [int]$AgentReceipt.agent_pid -le 0 -or
        [int]$AgentReceipt.windows_process_id -le 0 -or [string]::IsNullOrWhiteSpace([string]$AgentReceipt.socket)) { throw 'agent receipt process binding differs' }
    return $toolchain
}

function ConvertTo-P3AgentReceiptUtcInstant([object]$Value) {
    if ($Value -is [DateTime]) {
        $instant = [DateTime]$Value
        if ($instant.Kind -ne [DateTimeKind]::Utc) { throw 'agent receipt start must be UTC' }
        return $instant.ToUniversalTime()
    }
    $text = [string]$Value
    if ($text -cnotmatch 'Z$') { throw 'agent receipt start must be UTC' }
    try {
        $instant = [DateTime]::Parse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    } catch { throw 'agent receipt start must be UTC' }
    if ($instant.Kind -ne [DateTimeKind]::Utc) { throw 'agent receipt start must be UTC' }
    return $instant.ToUniversalTime()
}

function ConvertTo-P3AgentObservedUtcInstant([object]$Value) {
    if ($Value -isnot [DateTime]) { throw 'agent process start time differs' }
    $instant = [DateTime]$Value
    if ($instant.Kind -eq [DateTimeKind]::Unspecified) {
        $instant = [DateTime]::SpecifyKind($instant, [DateTimeKind]::Local)
    }
    return $instant.ToUniversalTime()
}

function Assert-P3AgentObservedProcess([object]$Toolchain, [object]$AgentReceipt, [object[]]$Processes) {
    if ($processes.Count -ne 1 -or [int]$processes[0].Id -ne [int]$AgentReceipt.windows_process_id -or
        -not [string]::Equals([string]$processes[0].Path, $Toolchain.git_ssh_agent_path, [StringComparison]::OrdinalIgnoreCase) -or
        $processes[0].PSObject.Properties.Name -notcontains 'StartTime') {
        throw 'agent process identity differs'
    }
    $started = ConvertTo-P3AgentReceiptUtcInstant -Value $AgentReceipt.started_at_utc
    $observed = ConvertTo-P3AgentObservedUtcInstant -Value $processes[0].StartTime
    $delta = ($observed - $started).Duration().TotalSeconds
    if ($delta -gt 10) { throw 'agent process creation window differs' }
    return $processes[0]
}

function Test-P3AgentState([object]$Manifest, [object]$AgentReceipt, [scriptblock]$ListRunner, [scriptblock]$ProcessRunner) {
    $toolchain = Assert-P3AgentReceipt -Manifest $Manifest -AgentReceipt $AgentReceipt
    $processes = @(& $ProcessRunner ([int]$AgentReceipt.windows_process_id))
    $null = Assert-P3AgentObservedProcess -Toolchain $toolchain -AgentReceipt $AgentReceipt -Processes $processes
    $lines = @(([string](& $ListRunner $toolchain.git_ssh_add_path) -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) { throw 'agent must contain exactly one key' }
    $match = [regex]::Match($lines[0], '^\s*[0-9]+\s+(SHA256:\S+)\s+')
    if (-not $match.Success) { throw 'agent key listing is malformed' }
    $fingerprintHash = Get-P3AgentSHA256Text $match.Groups[1].Value
    if ($fingerprintHash -cne [string]$Manifest.public_key_fingerprint_sha256) { throw 'agent key fingerprint differs' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-combined-receipt/v3'
        manifest_sha256 = [string]$Manifest.manifest_sha256
        agent_pid = [int]$AgentReceipt.agent_pid
        windows_process_id = [int]$AgentReceipt.windows_process_id
        socket = [string]$AgentReceipt.socket
        agent_executable_path = [string]$AgentReceipt.agent_executable_path
        agent_executable_sha256 = [string]$AgentReceipt.agent_executable_sha256
        expected_fingerprint_sha256 = [string]$AgentReceipt.expected_fingerprint_sha256
        started_at_utc = [string]$AgentReceipt.started_at_utc
        loaded_key_count = 1
        expected_key_match = $true
        agent_pid_match = $true
        windows_process_id_match = $true
        toolchain_match = $true
    }
}

function Wait-P3BoundedAgentExit(
    [int]$ProcessId,
    [scriptblock]$ObserveRunner,
    [scriptblock]$SleepRunner,
    [scriptblock]$ClockRunner,
    [int]$TimeoutSeconds = 10,
    [int]$PollMilliseconds = 50
) {
    if ($ProcessId -le 0 -or $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 30 -or
        $PollMilliseconds -lt 1 -or $PollMilliseconds -gt 1000) { throw 'agent bounded wait input differs' }
    $started = ([DateTime](& $ClockRunner)).ToUniversalTime()
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $maximumPolls = [int][Math]::Ceiling(($TimeoutSeconds * 1000.0) / $PollMilliseconds)
    for ($poll = 0; $poll -le $maximumPolls; $poll++) {
        $observed = @(& $ObserveRunner $ProcessId)
        if ($observed.Count -eq 0) { return [pscustomobject]@{ process_absent = $true } }
        if ($observed.Count -ne 1 -or [int]$observed[0].Id -ne $ProcessId) { throw 'agent process wait identity differs' }
        $now = ([DateTime](& $ClockRunner)).ToUniversalTime()
        if ($now -lt $started -or $now -ge $deadline -or $poll -eq $maximumPolls) { throw 'agent process wait timed out' }
        & $SleepRunner $PollMilliseconds
    }
    throw 'agent process wait timed out'
}

function Stop-P3Agent(
    [object]$Manifest,
    [object]$AgentReceipt,
    [scriptblock]$DeleteRunner,
    [scriptblock]$StopRunner,
    [scriptblock]$ListRunner,
    [scriptblock]$ProcessRunner,
    [scriptblock]$WaitRunner,
    [scriptblock]$ReobserveRunner,
    [scriptblock]$SocketExistsRunner
) {
    if ([string]$env:SSH_AUTH_SOCK -cne [string]$AgentReceipt.socket -or [string]$env:SSH_AGENT_PID -cne [string]$AgentReceipt.agent_pid) {
        throw 'agent environment differs from receipt'
    }
    $null = Test-P3AgentState -Manifest $Manifest -AgentReceipt $AgentReceipt -ListRunner $ListRunner -ProcessRunner $ProcessRunner
    $failures = @()
    try { $null = & $DeleteRunner } catch { $failures += 'key delete failure' }
    try { $null = & $StopRunner ([int]$AgentReceipt.windows_process_id) } catch { $failures += 'process stop failure' }
    try { $null = & $WaitRunner ([int]$AgentReceipt.windows_process_id) } catch { $failures += 'process wait failure' }
    try {
        if (@(& $ReobserveRunner ([int]$AgentReceipt.windows_process_id)).Count -ne 0) { $failures += 'process reobserve failure' }
    } catch { $failures += 'process reobserve failure' }
    try {
        if ([bool](& $SocketExistsRunner ([string]$AgentReceipt.socket))) { $failures += 'socket reobserve failure' }
    } catch { $failures += 'socket reobserve failure' }
    if ([string]$env:SSH_AUTH_SOCK -ceq [string]$AgentReceipt.socket) { $env:SSH_AUTH_SOCK = $null }
    if ([string]$env:SSH_AGENT_PID -ceq [string]$AgentReceipt.agent_pid) { $env:SSH_AGENT_PID = $null }
    if ($failures.Count -ne 0) { throw "agent cleanup failed: $($failures -join ',')" }
    return [pscustomobject]@{ schema = 'home-gateway/p3-ssh-agent-stop-receipt/v1'; stopped = $true; removed_key_count = 1 }
}

function Stop-P3OwnedAgentEmergency(
    [object]$Manifest,
    [object]$AgentReceipt,
    [scriptblock]$DeleteRunner,
    [scriptblock]$StopRunner,
    [scriptblock]$ProcessRunner,
    [scriptblock]$WaitRunner,
    [scriptblock]$ReobserveRunner,
    [scriptblock]$SocketExistsRunner
) {
    $toolchain = Assert-P3AgentReceipt -Manifest $Manifest -AgentReceipt $AgentReceipt
    try { $null = ConvertTo-P3AgentReceiptUtcInstant -Value $AgentReceipt.started_at_utc }
    catch { throw 'owned agent start binding differs' }
    $failures = @()
    $identityMismatch = $false
    try { $processes = @(& $ProcessRunner ([int]$AgentReceipt.windows_process_id)) }
    catch { $processes = $null; $identityMismatch = $true; $failures += 'process identity failure' }
    if ($null -ne $processes) {
        try { $null = Assert-P3AgentObservedProcess -Toolchain $toolchain -AgentReceipt $AgentReceipt -Processes $processes }
        catch { $identityMismatch = $true; $failures += 'process identity failure' }
    }
    $socketMatches = [string]$env:SSH_AUTH_SOCK -ceq [string]$AgentReceipt.socket
    $pidMatches = [string]$env:SSH_AGENT_PID -ceq [string]$AgentReceipt.agent_pid
    if ($socketMatches -and $pidMatches -and -not $identityMismatch) {
        try { $null = & $DeleteRunner } catch { $failures += 'key delete failure' }
    } elseif (-not $identityMismatch) { $failures += 'environment' }
    if (-not $identityMismatch) {
        try { $null = & $StopRunner ([int]$AgentReceipt.windows_process_id) } catch { $failures += 'process stop failure' }
        try { $null = & $WaitRunner ([int]$AgentReceipt.windows_process_id) } catch { $failures += 'process wait failure' }
    }
    try {
        if (@(& $ReobserveRunner ([int]$AgentReceipt.windows_process_id)).Count -ne 0) { $failures += 'process reobserve failure' }
    } catch { $failures += 'process reobserve failure' }
    try {
        if ([bool](& $SocketExistsRunner ([string]$AgentReceipt.socket))) { $failures += 'socket reobserve failure' }
    } catch { $failures += 'socket reobserve failure' }
    if ($socketMatches -and [string]$env:SSH_AUTH_SOCK -ceq [string]$AgentReceipt.socket) { $env:SSH_AUTH_SOCK = $null }
    if ($pidMatches -and [string]$env:SSH_AGENT_PID -ceq [string]$AgentReceipt.agent_pid) { $env:SSH_AGENT_PID = $null }
    if ($failures.Count -ne 0) { throw "owned agent emergency cleanup failed: $($failures -join ',')" }
    return [pscustomobject]@{ schema = 'home-gateway/p3-ssh-agent-stop-receipt/v1'; stopped = $true; removed_key_count = 1 }
}

function ConvertTo-P3AgentReceiptFromCombined([object]$CombinedReceipt) {
    $expected = @(
        'agent_executable_path', 'agent_executable_sha256', 'agent_pid', 'agent_pid_match',
        'expected_fingerprint_sha256', 'expected_key_match', 'loaded_key_count', 'manifest_sha256',
        'schema', 'socket', 'started_at_utc', 'toolchain_match', 'windows_process_id', 'windows_process_id_match'
    )
    if ($null -eq $CombinedReceipt -or $CombinedReceipt -is [Array] -or
        @(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject @($CombinedReceipt.PSObject.Properties.Name | Sort-Object)).Count -ne 0 -or
        [string]$CombinedReceipt.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v3' -or
        [int]$CombinedReceipt.loaded_key_count -ne 1 -or -not [bool]$CombinedReceipt.expected_key_match -or
        -not [bool]$CombinedReceipt.agent_pid_match -or -not [bool]$CombinedReceipt.windows_process_id_match -or
        [int]$CombinedReceipt.windows_process_id -le 0 -or -not [bool]$CombinedReceipt.toolchain_match) {
        throw 'protected agent receipt differs'
    }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-receipt/v2'
        manifest_sha256 = [string]$CombinedReceipt.manifest_sha256
        agent_pid = [int]$CombinedReceipt.agent_pid
        windows_process_id = [int]$CombinedReceipt.windows_process_id
        socket = [string]$CombinedReceipt.socket
        agent_executable_path = [string]$CombinedReceipt.agent_executable_path
        agent_executable_sha256 = [string]$CombinedReceipt.agent_executable_sha256
        expected_fingerprint_sha256 = [string]$CombinedReceipt.expected_fingerprint_sha256
        started_at_utc = $CombinedReceipt.started_at_utc
    }
}

function Write-P3ProtectedAgentReceipt([string]$Root, [string]$ManifestSHA256, [object]$Receipt) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        Assert-P3ExactProperties -Value $Receipt -ExpectedProperties $script:P3CombinedAgentReceiptProperties -Label 'combined agent receipt'
        if ([string]$Receipt.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v3' -or [string]$Receipt.manifest_sha256 -cne $ManifestSHA256) {
            throw 'combined agent receipt binding differs'
        }
        Write-P3RuntimeJson -RuntimeRoot $Root -Name 'agent-receipt.json' -Value $Receipt
    } finally { $Action = $savedAction }
}

function Get-P3ProtectedAgentManifest([string]$Root, [string]$ManifestSHA256) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $trust = Open-P3BoundedStableJson -Path (Join-Path $Root 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
        $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
        return [pscustomobject]@{
            manifest_sha256 = $ManifestSHA256
            git_ssh_agent_path = [string]$trust.git_ssh_agent_path; git_ssh_agent_sha256 = [string]$manifest.git_ssh_agent_sha256
            git_ssh_add_path = [string]$trust.git_ssh_add_path; git_ssh_add_sha256 = [string]$manifest.git_ssh_add_sha256
            git_ssh_path = [string]$trust.git_ssh_path; git_ssh_sha256 = [string]$manifest.git_ssh_sha256
            git_scp_path = [string]$trust.git_scp_path; git_scp_sha256 = [string]$manifest.git_scp_sha256
            public_key_path = [string]$trust.public_key_path; private_key_path = [string]$trust.private_key_path
            public_key_fingerprint_sha256 = [string]$manifest.public_key_fingerprint_sha256
        }
    } finally { $Action = $savedAction }
}

function Get-P3ProtectedAgentReceipt([string]$Root, [string]$ManifestSHA256) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $stored = Open-P3BoundedStableJson -Path (Join-Path $Root 'agent-receipt.json') -MaximumBytes 65536 `
            -ExpectedProperties $script:P3CombinedAgentReceiptProperties
        if ([string]$stored.manifest_sha256 -cne $ManifestSHA256) { throw 'protected agent receipt differs' }
        $null = ConvertTo-P3AgentReceiptFromCombined -CombinedReceipt $stored
        return $stored
    } finally { $Action = $savedAction }
}

function Assert-P3AgentManifestMatchesProtected([object]$Candidate, [object]$Protected) {
    $expected = @(
        'git_scp_path', 'git_scp_sha256', 'git_ssh_add_path', 'git_ssh_add_sha256',
        'git_ssh_agent_path', 'git_ssh_agent_sha256', 'git_ssh_path', 'git_ssh_sha256',
        'manifest_sha256', 'private_key_path', 'public_key_fingerprint_sha256', 'public_key_path'
    )
    if ($null -eq $Candidate -or $Candidate -is [Array] -or
        @(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject @($Candidate.PSObject.Properties.Name | Sort-Object)).Count -ne 0 -or
        (Get-P3AgentCanonicalSHA256 $Candidate) -cne (Get-P3AgentCanonicalSHA256 $Protected)) {
        throw 'caller agent manifest differs from protected runtime'
    }
}

function Invoke-P3AgentAction(
    [string]$SelectedAction,
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation,
    [object]$InputObject,
    [object]$Boundaries
) {
    if ($SelectedAction -notin @('AgentStart', 'AgentValidate', 'AgentStop')) { throw 'protected agent action differs' }
    $required = @(
        'AddRunner', 'AgentRunner', 'DeleteRunner', 'ListRunner', 'ProcessRunner', 'ReceiptRemoveRunner',
        'ReobserveRunner', 'SocketExistsRunner', 'StopRunner', 'WaitRunner'
    )
    if ($null -eq $Boundaries -or $Boundaries -is [Array] -or
        @(Compare-Object -ReferenceObject ($required | Sort-Object) -DifferenceObject @($Boundaries.PSObject.Properties.Name | Sort-Object)).Count -ne 0) {
        throw 'protected agent boundaries differ'
    }
    $protected = Get-P3ProtectedAgentManifest -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256
    $candidate = if ($SelectedAction -ceq 'AgentStart') { $InputObject } else { $InputObject.manifest }
    Assert-P3AgentManifestMatchesProtected -Candidate $candidate -Protected $protected
    switch ($SelectedAction) {
        'AgentStart' {
            $plan = New-P3AgentPlan -Manifest $protected
            if ($ExpectedPlanSHA256 -cne $plan.plan_sha256 -or $Confirmation -cne $plan.confirmation_challenge -or
                $Confirmation -cnotmatch '^P3-SSH-AGENT-[0-9A-F]{16}$') { throw 'agent approval differs' }
            return Start-P3Agent -Manifest $protected -AgentRunner $Boundaries.AgentRunner `
                -ProcessRunner $Boundaries.ProcessRunner -AddRunner $Boundaries.AddRunner -StopRunner $Boundaries.StopRunner
        }
        'AgentValidate' {
            if ([string]$InputObject.receipt.manifest_sha256 -cne $ExpectedManifestSHA256) { throw 'caller agent receipt differs from protected runtime' }
            $combined = Test-P3AgentState -Manifest $protected -AgentReceipt $InputObject.receipt `
                -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner
            Write-P3ProtectedAgentReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256 -Receipt $combined
            return $combined
        }
        'AgentStop' {
            if ([string]$InputObject.receipt.manifest_sha256 -cne $ExpectedManifestSHA256 -or
                [string]$InputObject.combined_receipt.manifest_sha256 -cne $ExpectedManifestSHA256) {
                throw 'caller agent receipt differs from protected runtime'
            }
            $storedCombined = Get-P3ProtectedAgentReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256
            if ((Get-P3AgentCanonicalSHA256 $storedCombined) -cne (Get-P3AgentCanonicalSHA256 $InputObject.combined_receipt)) {
                throw 'protected agent receipt differs'
            }
            $storedReceipt = ConvertTo-P3AgentReceiptFromCombined -CombinedReceipt $storedCombined
            if ((Get-P3AgentCanonicalSHA256 $storedReceipt) -cne (Get-P3AgentCanonicalSHA256 $InputObject.receipt)) {
                throw 'protected agent receipt differs'
            }
            $stop = Stop-P3Agent -Manifest $protected -AgentReceipt $storedReceipt `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner
            Remove-P3ProtectedAgentState -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256 `
                -Receipt $storedCombined -ReceiptRemoveRunner $Boundaries.ReceiptRemoveRunner
            return $stop
        }
    }
}

function Remove-P3ProtectedAgentState(
    [string]$Root,
    [string]$ManifestSHA256,
    [object]$Receipt,
    [scriptblock]$ReceiptRemoveRunner
) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $receiptPath = [IO.Path]::GetFullPath((Join-Path $Root 'agent-receipt.json'))
        $stored = Open-P3BoundedStableJson -Path $receiptPath -MaximumBytes 65536 -ExpectedProperties $script:P3CombinedAgentReceiptProperties
        if ((Get-P3AgentCanonicalSHA256 $stored) -cne (Get-P3AgentCanonicalSHA256 $Receipt)) { throw 'protected agent receipt differs' }
        & $ReceiptRemoveRunner $receiptPath
        if ([IO.File]::Exists($receiptPath)) { throw 'agent protected cleanup failed' }
    } finally { $Action = $savedAction }
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $requestText = [Console]::In.ReadToEnd()
    $request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
    if ($Action -ceq 'AgentPlan') { New-P3AgentPlan -Manifest $request | ConvertTo-Json -Depth 16 -Compress }
    else {
        $boundaries = [pscustomobject]@{
            AgentRunner={param($Executable)Start-P3WindowsAgentProcess -ExecutablePath $Executable};AddRunner={param($KeyPath)Invoke-P3InteractiveAgentAdd -ExecutablePath $protected.git_ssh_add_path -KeyPath $KeyPath}
            StopRunner={param($ProcessId)Stop-Process -Id $ProcessId -ErrorAction Stop}
            ListRunner={param($Executable)& $Executable -l -E sha256}
            ProcessRunner={param($ProcessId)Get-Process -Id $ProcessId -ErrorAction Stop|Select-Object Id,Path,StartTime}
            DeleteRunner={& $protected.git_ssh_add_path -D};WaitRunner={param($ProcessId)Wait-Process -Id $ProcessId -ErrorAction Stop}
            ReobserveRunner={param($ProcessId)@(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)}
            SocketExistsRunner={param($Path)[IO.File]::Exists($Path)};ReceiptRemoveRunner={param($Path)[IO.File]::Delete($Path)}
        }
        Invoke-P3AgentAction -SelectedAction $Action -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 `
            -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation -InputObject $request -Boundaries $boundaries |
            ConvertTo-Json -Depth 16 -Compress
    }
}
