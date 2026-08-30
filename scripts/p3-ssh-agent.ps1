[CmdletBinding()]
param(
    [ValidateSet('', 'AgentPlan', 'AgentStart', 'AgentValidate', 'AgentStop')]
    [string]$Action = '',
    [string]$RuntimeRoot,
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

function Start-P3Agent([object]$Manifest, [scriptblock]$AgentRunner, [scriptblock]$AddRunner, [scriptblock]$StopRunner) {
    if (-not [string]::IsNullOrEmpty([string]$env:SSH_AUTH_SOCK) -or -not [string]::IsNullOrEmpty([string]$env:SSH_AGENT_PID)) {
        throw 'pre-existing SSH agent environment is not allowed'
    }
    $toolchain = Resolve-P3GitOpenSshToolchain -Manifest $Manifest
    $started = $null
    try {
        $output = [string](& $AgentRunner $toolchain.git_ssh_agent_path)
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
        if ($null -ne $started) {
            try { $null = & $StopRunner $started.agent_pid } catch { }
        }
        $env:SSH_AUTH_SOCK = $null
        $env:SSH_AGENT_PID = $null
        throw
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

function Test-P3AgentState([object]$Manifest, [object]$AgentReceipt, [scriptblock]$ListRunner, [scriptblock]$ProcessRunner) {
    $toolchain = Assert-P3AgentReceipt -Manifest $Manifest -AgentReceipt $AgentReceipt
    $processes = @(& $ProcessRunner ([int]$AgentReceipt.agent_pid))
    if ($processes.Count -ne 1 -or [int]$processes[0].Id -ne [int]$AgentReceipt.agent_pid -or
        -not [string]::Equals([string]$processes[0].Path, $toolchain.git_ssh_agent_path, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'agent process identity differs'
    }
    $started = [DateTime]::Parse([string]$AgentReceipt.started_at_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    if ($processes[0].PSObject.Properties.Name -contains 'StartTime') {
        $delta = ([DateTime]$processes[0].StartTime - $started).Duration().TotalSeconds
        if ($delta -gt 10) { throw 'agent process creation window differs' }
    }
    $lines = @(([string](& $ListRunner $toolchain.git_ssh_add_path) -split "`r?`n") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) { throw 'agent must contain exactly one key' }
    $match = [regex]::Match($lines[0], '^\s*[0-9]+\s+(SHA256:\S+)\s+')
    if (-not $match.Success) { throw 'agent key listing is malformed' }
    $fingerprintHash = Get-P3AgentSHA256Text $match.Groups[1].Value
    if ($fingerprintHash -cne [string]$Manifest.public_key_fingerprint_sha256) { throw 'agent key fingerprint differs' }
    return [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-ssh-agent-validation/v1'
        manifest_sha256 = [string]$Manifest.manifest_sha256
        loaded_key_count = 1
        expected_key_match = $true
        agent_pid_match = $true
        toolchain_match = $true
    }
}

function Stop-P3Agent(
    [object]$Manifest,
    [object]$AgentReceipt,
    [scriptblock]$DeleteRunner,
    [scriptblock]$StopRunner,
    [scriptblock]$ListRunner,
    [scriptblock]$ProcessRunner
) {
    if ([string]$env:SSH_AUTH_SOCK -cne [string]$AgentReceipt.socket -or [string]$env:SSH_AGENT_PID -cne [string]$AgentReceipt.agent_pid) {
        throw 'agent environment differs from receipt'
    }
    $null = Test-P3AgentState -Manifest $Manifest -AgentReceipt $AgentReceipt -ListRunner $ListRunner -ProcessRunner $ProcessRunner
    $null = & $DeleteRunner
    $null = & $StopRunner ([int]$AgentReceipt.agent_pid)
    if ([string]$env:SSH_AUTH_SOCK -ceq [string]$AgentReceipt.socket) { $env:SSH_AUTH_SOCK = $null }
    if ([string]$env:SSH_AGENT_PID -ceq [string]$AgentReceipt.agent_pid) { $env:SSH_AGENT_PID = $null }
    return [pscustomobject]@{ schema = 'home-gateway/p3-ssh-agent-stop-receipt/v1'; stopped = $true; removed_key_count = 1 }
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $requestText = [Console]::In.ReadToEnd()
    $request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
    switch ($Action) {
        'AgentPlan' { New-P3AgentPlan -Manifest $request | ConvertTo-Json -Depth 16 -Compress }
        'AgentStart' {
            $plan = New-P3AgentPlan -Manifest $request
            if ($ExpectedPlanSHA256 -cne $plan.plan_sha256 -or $Confirmation -cne $plan.confirmation_challenge -or $Confirmation -cnotmatch '^P3-SSH-AGENT-[0-9A-F]{16}$') { throw 'agent approval differs' }
            Start-P3Agent -Manifest $request `
                -AgentRunner { param($Executable) & $Executable -s } `
                -AddRunner { param($KeyPath) & $request.git_ssh_add_path $KeyPath } `
                -StopRunner { param($ProcessId) Stop-Process -Id $ProcessId -ErrorAction Stop } | ConvertTo-Json -Compress
        }
        'AgentValidate' {
            Test-P3AgentState -Manifest $request.manifest -AgentReceipt $request.receipt `
                -ListRunner { param($Executable) & $Executable -l -E sha256 } `
                -ProcessRunner { param($ProcessId) Get-Process -Id $ProcessId -ErrorAction Stop | Select-Object Id, Path, StartTime } | ConvertTo-Json -Compress
        }
        'AgentStop' {
            Stop-P3Agent -Manifest $request.manifest -AgentReceipt $request.receipt `
                -DeleteRunner { & $request.manifest.git_ssh_add_path -D } `
                -StopRunner { param($ProcessId) Stop-Process -Id $ProcessId -ErrorAction Stop } `
                -ListRunner { param($Executable) & $Executable -l -E sha256 } `
                -ProcessRunner { param($ProcessId) Get-Process -Id $ProcessId -ErrorAction Stop | Select-Object Id, Path, StartTime } | ConvertTo-Json -Compress
        }
    }
}
