[CmdletBinding()]
param(
    [ValidateSet('', 'RemoteInstallPlan', 'RemoteInstall', 'RemoteRemovePlan', 'RemoteRemove')]
    [string]$Action = '',
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:P3RemoteTarget = '/usr/local/libexec/home-gateway-p3-peer-guard'
$script:P3RemoteStateProperties = @('group_match', 'mode_match', 'owner_match', 'payload_sha256', 'regular', 'state', 'temporary_leftover_count')
$script:P3InstallReceiptProperties = @('group_match', 'installed_by_gate', 'mode_match', 'owner_match', 'payload_sha256', 'preinstall_state', 'schema', 'target_state', 'temporary_leftover_count')

function Get-P3RemoteSHA256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-P3RemoteSHA256Text([string]$Text) {
    return Get-P3RemoteSHA256Bytes ([Text.Encoding]::UTF8.GetBytes($Text))
}

function Get-P3RemoteFileSHA256([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw 'remote lifecycle file path must be absolute' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) { throw 'remote lifecycle file is missing' }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'remote lifecycle file must be regular' }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'remote lifecycle file size differs' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Assert-P3RemoteSHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label hash differs" }
}

function ConvertTo-P3RemoteCanonicalValue([object]$Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $ordered[$key] = ConvertTo-P3RemoteCanonicalValue $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) {
            $ordered[$property] = ConvertTo-P3RemoteCanonicalValue $Value.$property
        }
        return $ordered
    }
    if ($Value -is [Array]) {
        $array = @()
        foreach ($item in $Value) { $array += ,(ConvertTo-P3RemoteCanonicalValue $item) }
        return $array
    }
    return $Value
}

function Get-P3RemoteCanonicalSHA256([object]$Value) {
    $json = ConvertTo-Json -InputObject (ConvertTo-P3RemoteCanonicalValue $Value) -Depth 20 -Compress
    return Get-P3RemoteSHA256Text $json
}

function Assert-P3RemoteExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value -or $Value -is [Array]) { throw "$Label schema differs" }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($Expected | Sort-Object) -DifferenceObject $actual).Count -ne 0) { throw "$Label schema differs" }
}

function Test-P3RemoteContext([object]$Context) {
    Assert-P3RemoteSHA256 -Value ([string]$Context.manifest_sha256) -Label 'manifest'
    if ([string]$Context.Trust.ssh_user -cne 'homegateway') { throw 'remote lifecycle SSH user differs' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse([string]$Context.Trust.ssh_host, [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'remote lifecycle SSH host must be one IPv4 address'
    }
    foreach ($pair in @(
        @('known_hosts_path', 'known_hosts_sha256', 'known-hosts'),
        @('git_ssh_path', 'git_ssh_sha256', 'Git ssh'),
        @('git_scp_path', 'git_scp_sha256', 'Git scp'),
        @('local_payload_path', 'local_payload_sha256', 'local payload')
    )) {
        $expected = [string]$Context.Trust.($pair[1])
        Assert-P3RemoteSHA256 -Value $expected -Label $pair[2]
        if ((Get-P3RemoteFileSHA256 ([string]$Context.Trust.($pair[0]))) -cne $expected) { throw "$($pair[2]) hash differs" }
    }
    Assert-P3RemoteSHA256 -Value ([string]$Context.Trust.remote_payload_sha256) -Label 'remote payload'
    if ([string]$Context.Trust.local_payload_sha256 -cne [string]$Context.Trust.remote_payload_sha256) { throw 'local and remote payload identity differs' }
    Assert-P3RemoteSHA256 -Value ([string]$Context.Trust.management_source_cidr_sha256) -Label 'management source CIDR'
    $egress = @($Context.Trust.egress)
    if ($egress.Count -ne 3) { throw 'three egress authorities are required' }
    $authorities = @()
    foreach ($item in $egress) {
        Assert-P3RemoteSHA256 -Value ([string]$item.authority_sha256) -Label 'egress authority'
        Assert-P3RemoteSHA256 -Value ([string]$item.source_cidr_sha256) -Label 'egress source CIDR'
        if ([string]$item.source_cidr_sha256 -cne [string]$Context.Trust.management_source_cidr_sha256) { throw 'egress source consensus differs' }
        $authorities += [string]$item.authority_sha256
    }
    if (@($authorities | Select-Object -Unique).Count -ne 3) { throw 'egress authorities must be distinct' }
    if ([int]$Context.Agent.agent_pid -le 0 -or [string]::IsNullOrWhiteSpace([string]$Context.Agent.socket) -or
        [int]$Context.Agent.loaded_key_count -ne 1 -or -not [bool]$Context.Agent.expected_key_match -or
        -not [bool]$Context.Agent.toolchain_match -or [string]$Context.Agent.manifest_sha256 -cne [string]$Context.manifest_sha256) {
        throw 'validated one-key agent receipt differs'
    }
    return [pscustomobject]@{
        context_sha256 = Get-P3RemoteCanonicalSHA256 $Context
        payload_sha256 = [string]$Context.Trust.local_payload_sha256
    }
}

function New-P3GitSshArguments([object]$Trust, [object]$Agent, [string[]]$RemoteCommand) {
    return @(
        '-F', 'NUL',
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$($Trust.known_hosts_path)",
        '-o', 'GlobalKnownHostsFile=NUL',
        '-o', "IdentityAgent=$($Agent.socket)",
        '-o', 'ConnectTimeout=10',
        "$($Trust.ssh_user)@$($Trust.ssh_host)"
    ) + $RemoteCommand
}

function ConvertFrom-P3RemoteState([string]$Json, [string]$ExpectedPayloadSHA256) {
    try { $state = ConvertFrom-Json -InputObject $Json -ErrorAction Stop } catch { throw 'remote target receipt is malformed' }
    Assert-P3RemoteExactProperties -Value $state -Expected $script:P3RemoteStateProperties -Label 'remote target receipt'
    if ([string]$state.state -notin @('absent', 'exact', 'conflict')) { throw 'remote target state differs' }
    Assert-P3RemoteSHA256 -Value ([string]$state.payload_sha256) -Label 'remote target payload'
    if ([int]$state.temporary_leftover_count -ne 0) { throw 'remote temporary cleanup differs' }
    if ([string]$state.state -ceq 'absent') { return [pscustomobject]@{ classification = 'absent'; raw = $state } }
    $isExact = [bool]$state.regular -and [bool]$state.owner_match -and [bool]$state.group_match -and [bool]$state.mode_match -and
        [string]$state.payload_sha256 -ceq $ExpectedPayloadSHA256
    if ([string]$state.state -ceq 'exact' -and $isExact) { return [pscustomobject]@{ classification = 'exact'; raw = $state } }
    return [pscustomobject]@{ classification = 'conflict'; raw = $state }
}

function Invoke-P3RemoteInstallPlan([object]$Context, [scriptblock]$SshRunner) {
    $validated = Test-P3RemoteContext -Context $Context
    $command = @('sudo', '-n', '/usr/bin/stat', '--format=%F|%U|%G|%a', $script:P3RemoteTarget, '&&', '/usr/bin/sha256sum', $script:P3RemoteTarget)
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand $command
    $json = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'classify')
    $classification = ConvertFrom-P3RemoteState -Json $json -ExpectedPayloadSHA256 $validated.payload_sha256
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-remote-helper-install-plan/v1'
        manifest_sha256 = [string]$Context.manifest_sha256
        context_sha256 = $validated.context_sha256
        payload_sha256 = $validated.payload_sha256
        target_path_sha256 = Get-P3RemoteSHA256Text $script:P3RemoteTarget
        state = $classification.classification
        temporary_leftover_count = 0
    }
    $hash = Get-P3RemoteCanonicalSHA256 $identity
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result['plan_sha256'] = $hash
    $result['confirmation_challenge'] = 'P3-REMOTE-INSTALL-' + $hash.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function Assert-P3RemoteInstallPlan([object]$Context, [object]$Plan) {
    $validated = Test-P3RemoteContext -Context $Context
    if ([string]$Plan.context_sha256 -cne $validated.context_sha256 -or [string]$Plan.payload_sha256 -cne $validated.payload_sha256 -or
        [string]$Plan.manifest_sha256 -cne [string]$Context.manifest_sha256) { throw 'remote install plan is stale' }
    $identity = [pscustomobject][ordered]@{
        schema = [string]$Plan.schema
        manifest_sha256 = [string]$Plan.manifest_sha256
        context_sha256 = [string]$Plan.context_sha256
        payload_sha256 = [string]$Plan.payload_sha256
        target_path_sha256 = [string]$Plan.target_path_sha256
        state = [string]$Plan.state
        temporary_leftover_count = [int]$Plan.temporary_leftover_count
    }
    if ((Get-P3RemoteCanonicalSHA256 $identity) -cne [string]$Plan.plan_sha256) { throw 'remote install plan hash differs' }
    return $validated
}

function ConvertFrom-P3InstallReceipt([string]$Json, [string]$ExpectedPayloadSHA256) {
    try { $receipt = ConvertFrom-Json -InputObject $Json -ErrorAction Stop } catch { throw 'remote install receipt is malformed' }
    Assert-P3RemoteExactProperties -Value $receipt -Expected $script:P3InstallReceiptProperties -Label 'remote install receipt'
    if ([string]$receipt.schema -cne 'home-gateway/p3-remote-helper-install-receipt/v1' -or [string]$receipt.target_state -cne 'exact' -or
        [string]$receipt.payload_sha256 -cne $ExpectedPayloadSHA256 -or -not [bool]$receipt.owner_match -or -not [bool]$receipt.group_match -or
        -not [bool]$receipt.mode_match) { throw 'remote install receipt identity differs' }
    if ([int]$receipt.temporary_leftover_count -ne 0) { throw 'remote install cleanup failed' }
    return $receipt
}

function Invoke-P3RemoteInstall([object]$Context, [object]$Plan, [scriptblock]$ScpRunner, [scriptblock]$SshRunner) {
    $validated = Assert-P3RemoteInstallPlan -Context $Context -Plan $Plan
    if ([string]$Plan.state -ceq 'conflict') { throw 'remote target conflict prevents overwrite' }
    if ([string]$Plan.state -ceq 'exact') {
        return [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
            payload_sha256 = $validated.payload_sha256; owner_match = $true; group_match = $true; mode_match = $true
            installed_by_gate = $false; preinstall_state = 'exact'; temporary_leftover_count = 0
        }
    }
    if ([string]$Plan.state -cne 'absent') { throw 'remote install plan state differs' }
    $token = [guid]::NewGuid().ToString('N')
    $upload = "/tmp/.home-gateway-p3-$token.upload"
    $next = "$script:P3RemoteTarget.next-$token"
    $scpArguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand @()
    $uploadResult = & $ScpRunner ([string]$Context.Trust.git_scp_path) $scpArguments ([string]$Context.Trust.local_payload_path) $upload
    if ($null -eq $uploadResult -or [int]$uploadResult.exit_code -ne 0) { throw 'remote helper upload failed' }
    $request = [pscustomobject][ordered]@{
        upload_path = $upload; next_path = $next; target_path = $script:P3RemoteTarget
        payload_sha256 = $validated.payload_sha256; owner = 'root'; group = 'root'; mode = '0755'
        cleanup_required = $true; atomic_create_new = $true
    }
    $command = @('sudo', '-n', '/usr/bin/install', '--owner=root', '--group=root', '--mode=0755', '--no-target-directory', $upload, $next, '&&', 'sudo', '-n', '/usr/bin/mv', '--no-clobber', $next, $script:P3RemoteTarget)
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand $command
    $json = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'install' $request)
    return ConvertFrom-P3InstallReceipt -Json $json -ExpectedPayloadSHA256 $validated.payload_sha256
}

function Assert-P3InstallReceiptForRemoval([object]$Context, [object]$InstallReceipt) {
    Assert-P3RemoteExactProperties -Value $InstallReceipt -Expected $script:P3InstallReceiptProperties -Label 'remote install receipt'
    if ([string]$InstallReceipt.schema -cne 'home-gateway/p3-remote-helper-install-receipt/v1' -or
        -not [bool]$InstallReceipt.installed_by_gate -or [string]$InstallReceipt.preinstall_state -cne 'absent') {
        throw 'helper was not installed by this gate'
    }
    if ([string]$InstallReceipt.payload_sha256 -cne [string]$Context.Trust.local_payload_sha256 -or
        [string]$InstallReceipt.target_state -cne 'exact' -or -not [bool]$InstallReceipt.owner_match -or
        -not [bool]$InstallReceipt.group_match -or -not [bool]$InstallReceipt.mode_match -or
        [int]$InstallReceipt.temporary_leftover_count -ne 0) { throw 'remote install receipt cannot authorize removal' }
}

function Invoke-P3RemoteRemovePlan([object]$Context, [object]$InstallReceipt, [scriptblock]$SshRunner) {
    $validated = Test-P3RemoteContext -Context $Context
    Assert-P3InstallReceiptForRemoval -Context $Context -InstallReceipt $InstallReceipt
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand @('sudo', '-n', '/usr/bin/stat', $script:P3RemoteTarget, '&&', '/usr/bin/sha256sum', $script:P3RemoteTarget)
    $state = ConvertFrom-P3RemoteState -Json ([string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'classify')) -ExpectedPayloadSHA256 $validated.payload_sha256
    if ($state.classification -cne 'exact') { throw 'remote helper is no longer exact' }
    $identity = [pscustomobject][ordered]@{
        schema = 'home-gateway/p3-remote-helper-remove-plan/v1'
        manifest_sha256 = [string]$Context.manifest_sha256
        context_sha256 = $validated.context_sha256
        install_receipt_sha256 = Get-P3RemoteCanonicalSHA256 $InstallReceipt
        payload_sha256 = $validated.payload_sha256
        target_path_sha256 = Get-P3RemoteSHA256Text $script:P3RemoteTarget
        current_state = 'exact'
        removal_scope = 'gate-installed-exact-helper-only'
    }
    $hash = Get-P3RemoteCanonicalSHA256 $identity
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result['remove_plan_sha256'] = $hash
    $result['confirmation_challenge'] = 'P3-REMOTE-REMOVE-' + $hash.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function Invoke-P3RemoteRemove([object]$Context, [object]$InstallReceipt, [object]$RemovePlan, [scriptblock]$SshRunner) {
    $validated = Test-P3RemoteContext -Context $Context
    Assert-P3InstallReceiptForRemoval -Context $Context -InstallReceipt $InstallReceipt
    $identity = [pscustomobject][ordered]@{
        schema = [string]$RemovePlan.schema; manifest_sha256 = [string]$RemovePlan.manifest_sha256
        context_sha256 = [string]$RemovePlan.context_sha256; install_receipt_sha256 = [string]$RemovePlan.install_receipt_sha256
        payload_sha256 = [string]$RemovePlan.payload_sha256; target_path_sha256 = [string]$RemovePlan.target_path_sha256
        current_state = [string]$RemovePlan.current_state; removal_scope = [string]$RemovePlan.removal_scope
    }
    if ((Get-P3RemoteCanonicalSHA256 $identity) -cne [string]$RemovePlan.remove_plan_sha256 -or
        [string]$RemovePlan.context_sha256 -cne $validated.context_sha256 -or
        [string]$RemovePlan.install_receipt_sha256 -cne (Get-P3RemoteCanonicalSHA256 $InstallReceipt)) { throw 'remote remove plan differs' }
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand @('sudo', '-n', '/usr/bin/rm', '--', $script:P3RemoteTarget)
    $json = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'remove')
    try { $receipt = ConvertFrom-Json -InputObject $json -ErrorAction Stop } catch { throw 'remote remove receipt is malformed' }
    Assert-P3RemoteExactProperties -Value $receipt -Expected @('removed', 'schema', 'target_state', 'temporary_leftover_count') -Label 'remote remove receipt'
    if ([string]$receipt.schema -cne 'home-gateway/p3-remote-helper-remove-receipt/v1' -or -not [bool]$receipt.removed -or
        [string]$receipt.target_state -cne 'absent' -or [int]$receipt.temporary_leftover_count -ne 0) { throw 'remote remove receipt differs' }
    return $receipt
}

if (-not [string]::IsNullOrEmpty($Action)) {
    $request = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()) -ErrorAction Stop
    $nativeSshRunner = {
        param($Executable, $Arguments, $Mode, $Payload)
        $payloadJson = if ($null -eq $Payload) { '' } else { ConvertTo-Json -InputObject $Payload -Depth 12 -Compress }
        $output = $payloadJson | & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) { throw 'pinned SSH command failed' }
        return [string]$output
    }
    switch ($Action) {
        'RemoteInstallPlan' { Invoke-P3RemoteInstallPlan -Context $request.context -SshRunner $nativeSshRunner | ConvertTo-Json -Depth 16 -Compress }
        'RemoteInstall' {
            if ([string]$request.plan.plan_sha256 -cne $ExpectedPlanSHA256 -or $Confirmation -cne [string]$request.plan.confirmation_challenge -or $Confirmation -cnotmatch '^P3-REMOTE-INSTALL-[0-9A-F]{16}$') { throw 'remote install approval differs' }
            Invoke-P3RemoteInstall -Context $request.context -Plan $request.plan `
                -ScpRunner { param($Executable, $Arguments, $Source, $Target) & $Executable @Arguments $Source "homegateway@$($request.context.Trust.ssh_host):$Target"; [pscustomobject]@{ exit_code = $LASTEXITCODE } } `
                -SshRunner $nativeSshRunner | ConvertTo-Json -Compress
        }
        'RemoteRemovePlan' { Invoke-P3RemoteRemovePlan -Context $request.context -InstallReceipt $request.install_receipt -SshRunner $nativeSshRunner | ConvertTo-Json -Compress }
        'RemoteRemove' {
            if ([string]$request.remove_plan.remove_plan_sha256 -cne $ExpectedPlanSHA256 -or $Confirmation -cne [string]$request.remove_plan.confirmation_challenge -or $Confirmation -cnotmatch '^P3-REMOTE-REMOVE-[0-9A-F]{16}$') { throw 'remote remove approval differs' }
            Invoke-P3RemoteRemove -Context $request.context -InstallReceipt $request.install_receipt -RemovePlan $request.remove_plan -SshRunner $nativeSshRunner | ConvertTo-Json -Compress
        }
    }
}
