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

function Get-P3AgentOwnedPidCandidate([string]$Output) {
    $matches = [regex]::Matches($Output, '(?m)^SSH_AGENT_PID=([1-9][0-9]*); export SSH_AGENT_PID;$')
    if ($matches.Count -ne 1) { return $null }
    $processId = 0
    if (-not [int]::TryParse($matches[0].Groups[1].Value, [ref]$processId) -or $processId -le 0) { return $null }
    return $processId
}

function Start-P3Agent([object]$Manifest, [scriptblock]$AgentRunner, [scriptblock]$AddRunner, [scriptblock]$StopRunner) {
    if (-not [string]::IsNullOrEmpty([string]$env:SSH_AUTH_SOCK) -or -not [string]::IsNullOrEmpty([string]$env:SSH_AGENT_PID)) {
        throw 'pre-existing SSH agent environment is not allowed'
    }
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    $started = $null
    $output = ''
    try {
        $output = @(& $AgentRunner $toolchain.git_ssh_agent_path) -join "`n"
        $started = ConvertFrom-P3AgentOutput -Output $output
        $env:SSH_AUTH_SOCK = $started.socket
        $env:SSH_AGENT_PID = [string]$started.agent_pid
        try { $null = & $AddRunner ([string]$Manifest.private_key_path) }
        catch { throw 'ssh-add failed for the dedicated key' }
        return [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-ssh-agent-receipt/v1'
            manifest_sha256 = [string]$Manifest.manifest_sha256
            agent_pid = $started.agent_pid
            socket = $started.socket
            agent_executable_path = $toolchain.git_ssh_agent_path
            agent_executable_sha256 = $toolchain.git_ssh_agent_sha256
            expected_fingerprint_sha256 = [string]$Manifest.public_key_fingerprint_sha256
            started_at_utc = [DateTime]::UtcNow.ToString('o')
        }
    }
    catch {
        $failure = $_
        $ownedPid = if ($null -ne $started) { [int]$started.agent_pid } else { Get-P3AgentOwnedPidCandidate -Output $output }
        $cleanupFailure = $null
        if ($null -ne $ownedPid) {
            try { $null = & $StopRunner $ownedPid } catch { $cleanupFailure = $_ }
        }
        $env:SSH_AUTH_SOCK = $null
        $env:SSH_AGENT_PID = $null
        if ($null -ne $cleanupFailure) { throw 'agent cleanup failed after start failure' }
        throw $failure
    }
}

function Assert-P3AgentReceipt([object]$Manifest, [object]$AgentReceipt) {
    $expected = @('agent_executable_path', 'agent_executable_sha256', 'agent_pid', 'expected_fingerprint_sha256', 'manifest_sha256', 'schema', 'socket', 'started_at_utc')
    $actual = @($AgentReceipt.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) { throw 'agent receipt schema differs' }
    if ([string]$AgentReceipt.schema -cne 'home-gateway/p3-ssh-agent-receipt/v1' -or
        [string]$AgentReceipt.manifest_sha256 -cne [string]$Manifest.manifest_sha256 -or
        [string]$AgentReceipt.expected_fingerprint_sha256 -cne [string]$Manifest.public_key_fingerprint_sha256) {
        throw 'agent receipt binding differs'
    }
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    if (-not [string]::Equals([string]$AgentReceipt.agent_executable_path, $toolchain.git_ssh_agent_path, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$AgentReceipt.agent_executable_sha256 -cne $toolchain.git_ssh_agent_sha256 -or [int]$AgentReceipt.agent_pid -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$AgentReceipt.socket)) { throw 'agent receipt process binding differs' }
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
    if ($processes.Count -ne 1 -or [int]$processes[0].Id -ne [int]$AgentReceipt.agent_pid -or
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
    $processes = @(& $ProcessRunner ([int]$AgentReceipt.agent_pid))
    $null = Assert-P3AgentObservedProcess -Toolchain $toolchain -AgentReceipt $AgentReceipt -Processes $processes
    $lines = @(([string](& $ListRunner $toolchain.git_ssh_add_path) -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) { throw 'agent must contain exactly one key' }
    $match = [regex]::Match($lines[0], '^\s*[0-9]+\s+(SHA256:\S+)\s+')
    if (-not $match.Success) { throw 'agent key listing is malformed' }
    $fingerprintHash = Get-P3AgentSHA256Text $match.Groups[1].Value
    if ($fingerprintHash -cne [string]$Manifest.public_key_fingerprint_sha256) { throw 'agent key fingerprint differs' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-combined-receipt/v2'
        manifest_sha256 = [string]$Manifest.manifest_sha256
        agent_pid = [int]$AgentReceipt.agent_pid
        socket = [string]$AgentReceipt.socket
        agent_executable_path = [string]$AgentReceipt.agent_executable_path
        agent_executable_sha256 = [string]$AgentReceipt.agent_executable_sha256
        expected_fingerprint_sha256 = [string]$AgentReceipt.expected_fingerprint_sha256
        started_at_utc = [string]$AgentReceipt.started_at_utc
        loaded_key_count = 1
        expected_key_match = $true
        agent_pid_match = $true
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
    try { $null = & $StopRunner ([int]$AgentReceipt.agent_pid) } catch { $failures += 'process stop failure' }
    try { $null = & $WaitRunner ([int]$AgentReceipt.agent_pid) } catch { $failures += 'process wait failure' }
    try {
        if (@(& $ReobserveRunner ([int]$AgentReceipt.agent_pid)).Count -ne 0) { $failures += 'process reobserve failure' }
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
    try { $processes = @(& $ProcessRunner ([int]$AgentReceipt.agent_pid)) }
    catch { $processes = $null }
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
        try { $null = & $StopRunner ([int]$AgentReceipt.agent_pid) } catch { $failures += 'process stop failure' }
        try { $null = & $WaitRunner ([int]$AgentReceipt.agent_pid) } catch { $failures += 'process wait failure' }
    }
    try {
        if (@(& $ReobserveRunner ([int]$AgentReceipt.agent_pid)).Count -ne 0) { $failures += 'process reobserve failure' }
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
        'schema', 'socket', 'started_at_utc', 'toolchain_match'
    )
    if ($null -eq $CombinedReceipt -or $CombinedReceipt -is [Array] -or
        @(Compare-Object -ReferenceObject ($expected | Sort-Object) -DifferenceObject @($CombinedReceipt.PSObject.Properties.Name | Sort-Object)).Count -ne 0 -or
        [string]$CombinedReceipt.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v2' -or
        [int]$CombinedReceipt.loaded_key_count -ne 1 -or -not [bool]$CombinedReceipt.expected_key_match -or
        -not [bool]$CombinedReceipt.agent_pid_match -or -not [bool]$CombinedReceipt.toolchain_match) {
        throw 'protected agent receipt differs'
    }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-receipt/v1'
        manifest_sha256 = [string]$CombinedReceipt.manifest_sha256
        agent_pid = [int]$CombinedReceipt.agent_pid
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
        if ([string]$Receipt.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v2' -or [string]$Receipt.manifest_sha256 -cne $ManifestSHA256) {
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
                -AddRunner $Boundaries.AddRunner -StopRunner $Boundaries.StopRunner
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
            AgentRunner={param($Executable)& $Executable -s};AddRunner={param($KeyPath)& $protected.git_ssh_add_path $KeyPath}
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
