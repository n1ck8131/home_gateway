[CmdletBinding()]
param(
    [ValidateSet('', 'RemoteInstallPlan', 'RemoteInstall', 'RemoteRemovePlan', 'RemoteRemove')]
    [string]$Action = '',
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
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
    if ([string]$Context.Agent.schema -cne 'home-gateway/p3-ssh-agent-combined-receipt/v2' -or
        [int]$Context.Agent.agent_pid -le 0 -or [string]::IsNullOrWhiteSpace([string]$Context.Agent.socket) -or
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

function New-P3GitScpArguments([object]$Trust, [object]$Agent) {
    return @(
        '-F', 'NUL', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$($Trust.known_hosts_path)", '-o', 'GlobalKnownHostsFile=NUL',
        '-o', "IdentityAgent=$($Agent.socket)", '-o', 'ConnectTimeout=10'
    )
}

function Get-P3RemoteAdapterProgram {
    return @'
import glob, hashlib, json, os, shutil, stat, sys
mode, expected, token, TARGET, UPLOAD_ROOT = sys.argv[1:6]
ZERO = "0" * 64
def digest(path):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(131072), b""):
            h.update(chunk)
    return h.hexdigest()
def leftovers():
    return len(glob.glob(TARGET + ".next-*")) + len(glob.glob(os.path.join(UPLOAD_ROOT, ".home-gateway-p3-*.upload")))
def classify(expected):
    if not os.path.lexists(TARGET):
        return {"state":"absent","regular":False,"owner_match":False,"group_match":False,"mode_match":False,"payload_sha256":ZERO,"temporary_leftover_count":leftovers()}
    info = os.lstat(TARGET)
    regular = stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    value = digest(TARGET) if regular else ZERO
    owner_match = os.name == "nt" or info.st_uid == 0
    group_match = os.name == "nt" or info.st_gid == 0
    mode_match = os.name == "nt" or stat.S_IMODE(info.st_mode) == 0o755
    exact = regular and owner_match and group_match and mode_match and value == expected
    return {"state":"exact" if exact else "conflict","regular":regular,"owner_match":owner_match,"group_match":group_match,"mode_match":mode_match,"payload_sha256":value,"temporary_leftover_count":leftovers()}
def cleanup(paths, strict=False):
    failed = False
    for path in paths:
        try:
            if os.path.lexists(path): os.unlink(path)
        except OSError:
            failed = True
    if strict and failed: raise RuntimeError("cleanup")
if mode == "classify":
    result = classify(expected)
elif mode == "cleanup":
    upload = os.path.join(UPLOAD_ROOT, ".home-gateway-p3-" + token + ".upload")
    nxt = TARGET + ".next-" + token
    cleanup([nxt, upload], strict=True)
    result = classify(expected)
    if result["temporary_leftover_count"] != 0: raise RuntimeError("cleanup")
elif mode == "install":
    upload = os.path.join(UPLOAD_ROOT, ".home-gateway-p3-" + token + ".upload")
    nxt = TARGET + ".next-" + token
    try:
        if classify(expected)["state"] != "absent": raise RuntimeError("target race")
        info = os.lstat(upload)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or digest(upload) != expected: raise RuntimeError("upload identity")
        fd = os.open(nxt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        with os.fdopen(fd, "wb", buffering=0) as target, open(upload, "rb", buffering=0) as source:
            shutil.copyfileobj(source, target, 131072); target.flush(); os.fsync(target.fileno())
        if hasattr(os, "chown"): os.chown(nxt, 0, 0)
        os.chmod(nxt, 0o755)
        if digest(nxt) != expected: raise RuntimeError("staged identity")
        os.link(nxt, TARGET)
        cleanup([nxt, upload])
        state = classify(expected)
        if state["state"] != "exact" or state["temporary_leftover_count"] != 0: raise RuntimeError("post install")
        result = {"schema":"home-gateway/p3-remote-helper-install-receipt/v1","target_state":"exact","payload_sha256":expected,"owner_match":True,"group_match":True,"mode_match":True,"installed_by_gate":True,"preinstall_state":"absent","temporary_leftover_count":0}
    except Exception:
        cleanup([nxt, upload]); raise
elif mode == "remove":
    state = classify(expected)
    if state["state"] != "exact": raise RuntimeError("target race")
    os.unlink(TARGET)
    state = classify(expected)
    if state["state"] != "absent" or state["temporary_leftover_count"] != 0: raise RuntimeError("post remove")
    result = {"schema":"home-gateway/p3-remote-helper-remove-receipt/v1","removed":True,"target_state":"absent","temporary_leftover_count":0}
else:
    raise RuntimeError("mode")
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",",":")))
'@
}

function New-P3RemoteAdapterCommand([string]$Mode, [string]$ExpectedPayloadSHA256, [string]$Token) {
    if ($Mode -notin @('classify', 'cleanup', 'install', 'remove')) { throw 'remote adapter mode differs' }
    Assert-P3RemoteSHA256 -Value $ExpectedPayloadSHA256 -Label 'remote adapter payload'
    if ($Mode -in @('cleanup', 'install') -and $Token -cnotmatch '^[0-9a-f]{32}$') { throw 'remote adapter token differs' }
    if ($Mode -notin @('cleanup', 'install') -and -not [string]::IsNullOrEmpty($Token)) { throw 'remote adapter token differs' }
    $program = Get-P3RemoteAdapterProgram
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))
    $bootstrap = "import base64;exec(compile(base64.b64decode('$encoded'),'<p3-lifecycle>','exec'))"
    $wireToken = if ([string]::IsNullOrEmpty($Token)) { '0' * 32 } else { $Token }
    return @('sudo', '-n', '/usr/bin/python3', '-c', $bootstrap, $Mode, $ExpectedPayloadSHA256, $wireToken, $script:P3RemoteTarget, '/tmp')
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
    $command = New-P3RemoteAdapterCommand -Mode classify -ExpectedPayloadSHA256 $validated.payload_sha256 -Token ''
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
    $classifyArguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent `
        -RemoteCommand (New-P3RemoteAdapterCommand -Mode classify -ExpectedPayloadSHA256 $validated.payload_sha256 -Token '')
    $current = ConvertFrom-P3RemoteState -Json ([string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $classifyArguments 'classify' $null)) `
        -ExpectedPayloadSHA256 $validated.payload_sha256
    if ([string]$Plan.state -ceq 'exact') {
        if ($current.classification -cne 'exact') { throw 'remote target race differs from exact plan' }
        return [pscustomobject][ordered]@{
            schema = 'home-gateway/p3-remote-helper-install-receipt/v1'; target_state = 'exact'
            payload_sha256 = $validated.payload_sha256; owner_match = $true; group_match = $true; mode_match = $true
            installed_by_gate = $false; preinstall_state = 'exact'; temporary_leftover_count = 0
        }
    }
    if ([string]$Plan.state -cne 'absent') { throw 'remote install plan state differs' }
    if ($current.classification -cne 'absent') { throw 'remote target race differs from absent plan' }
    $token = [guid]::NewGuid().ToString('N')
    $upload = "/tmp/.home-gateway-p3-$token.upload"
    $next = "$script:P3RemoteTarget.next-$token"
    $scpArguments = New-P3GitScpArguments -Trust $Context.Trust -Agent $Context.Agent
    try {
        $uploadResult = & $ScpRunner ([string]$Context.Trust.git_scp_path) $scpArguments ([string]$Context.Trust.local_payload_path) $upload
        if ($null -eq $uploadResult -or [int]$uploadResult.exit_code -ne 0) { throw 'remote helper upload failed' }
        $request = [pscustomobject][ordered]@{
            upload_path = $upload; next_path = $next; target_path = $script:P3RemoteTarget
            payload_sha256 = $validated.payload_sha256; owner = 'root'; group = 'root'; mode = '0755'
            cleanup_required = $true; atomic_create_new = $true
        }
        $command = New-P3RemoteAdapterCommand -Mode install -ExpectedPayloadSHA256 $validated.payload_sha256 -Token $token
        $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand $command
        $json = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'install' $request)
        return ConvertFrom-P3InstallReceipt -Json $json -ExpectedPayloadSHA256 $validated.payload_sha256
    }
    finally {
        try {
            $cleanupCommand = New-P3RemoteAdapterCommand -Mode cleanup -ExpectedPayloadSHA256 $validated.payload_sha256 -Token $token
            $cleanupArguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand $cleanupCommand
            $cleanupJson = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $cleanupArguments 'cleanup' $null)
            $null = ConvertFrom-P3RemoteState -Json $cleanupJson -ExpectedPayloadSHA256 $validated.payload_sha256
        }
        catch { throw 'remote helper cleanup failed' }
    }
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
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand (New-P3RemoteAdapterCommand -Mode classify -ExpectedPayloadSHA256 $validated.payload_sha256 -Token '')
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
    $classifyArguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand (New-P3RemoteAdapterCommand -Mode classify -ExpectedPayloadSHA256 $validated.payload_sha256 -Token '')
    $current = ConvertFrom-P3RemoteState -Json ([string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $classifyArguments 'classify' $null)) -ExpectedPayloadSHA256 $validated.payload_sha256
    if ($current.classification -cne 'exact') { throw 'remote remove target race differs' }
    $arguments = New-P3GitSshArguments -Trust $Context.Trust -Agent $Context.Agent -RemoteCommand (New-P3RemoteAdapterCommand -Mode remove -ExpectedPayloadSHA256 $validated.payload_sha256 -Token '')
    $json = [string](& $SshRunner ([string]$Context.Trust.git_ssh_path) $arguments 'remove')
    try { $receipt = ConvertFrom-Json -InputObject $json -ErrorAction Stop } catch { throw 'remote remove receipt is malformed' }
    Assert-P3RemoteExactProperties -Value $receipt -Expected @('removed', 'schema', 'target_state', 'temporary_leftover_count') -Label 'remote remove receipt'
    if ([string]$receipt.schema -cne 'home-gateway/p3-remote-helper-remove-receipt/v1' -or -not [bool]$receipt.removed -or
        [string]$receipt.target_state -cne 'absent' -or [int]$receipt.temporary_leftover_count -ne 0) { throw 'remote remove receipt differs' }
    return $receipt
}

function Write-P3ProtectedInstallReceipt([string]$Root, [string]$ManifestSHA256, [object]$Receipt) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
        Assert-P3ExactProperties -Value $Receipt -ExpectedProperties $script:P3InstallReceiptProperties -Label 'install receipt'
        if ([string]$Receipt.schema -cne 'home-gateway/p3-remote-helper-install-receipt/v1' -or
            [string]$Receipt.payload_sha256 -cne [string]$manifest.local_payload_sha256) {
            throw 'install receipt payload differs from protected manifest'
        }
        Write-P3RuntimeJson -RuntimeRoot $Root -Name 'remote-install-receipt.json' -Value $Receipt
    } finally { $Action = $savedAction }
}

function Get-P3ProtectedInstallReceipt([string]$Root, [string]$ManifestSHA256) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
        $stored = Open-P3BoundedStableJson -Path (Join-Path $Root 'remote-install-receipt.json') -MaximumBytes 65536 `
            -ExpectedProperties $script:P3InstallReceiptProperties
        if ([string]$stored.schema -cne 'home-gateway/p3-remote-helper-install-receipt/v1' -or
            [string]$stored.payload_sha256 -cne [string]$manifest.local_payload_sha256) {
            throw 'protected remote install receipt differs'
        }
        return $stored
    } finally { $Action = $savedAction }
}

function Get-P3ProtectedRemoteContext([string]$Root, [string]$ManifestSHA256) {
    $savedAction = $Action
    try {
        . (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1')
        $null = Invoke-P3RuntimeValidate -RuntimeRoot $Root -ExpectedManifestSHA256 $ManifestSHA256
        $trust = Open-P3BoundedStableJson -Path (Join-Path $Root 'trust.json') -MaximumBytes 65536 -ExpectedProperties $script:P3TrustProperties
        $manifest = Open-P3BoundedStableJson -Path (Join-Path $Root 'manifest.json') -MaximumBytes 65536 -ExpectedProperties $script:P3ManifestProperties
        $egressReceipt = Open-P3BoundedStableJson -Path (Join-Path $Root 'egress-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3EgressReceiptProperties
        $agent = Open-P3BoundedStableJson -Path (Join-Path $Root 'agent-receipt.json') -MaximumBytes 65536 -ExpectedProperties $script:P3CombinedAgentReceiptProperties
        $egress = @()
        foreach ($observation in @($egressReceipt.observations)) {
            Assert-P3ExactProperties -Value $observation -ExpectedProperties $script:P3EgressObservationProperties -Label 'remote egress observation'
            $egress += [pscustomobject]@{
                authority_sha256 = [string]$observation.authority_sha256
                source_cidr_sha256 = [string]$observation.source_cidr_sha256
            }
        }
        return [pscustomobject]@{
            manifest_sha256 = $ManifestSHA256
            Trust = [pscustomobject]@{
                ssh_user=[string]$trust.ssh_user;ssh_host=[string]$trust.ssh_host
                known_hosts_path=[string]$trust.known_hosts_path;known_hosts_sha256=[string]$manifest.known_hosts_sha256
                git_ssh_path=[string]$trust.git_ssh_path;git_ssh_sha256=[string]$manifest.git_ssh_sha256
                git_scp_path=[string]$trust.git_scp_path;git_scp_sha256=[string]$manifest.git_scp_sha256
                local_payload_path=[string]$trust.local_payload_path;local_payload_sha256=[string]$manifest.local_payload_sha256
                remote_payload_sha256=[string]$manifest.remote_payload_sha256
                management_source_cidr_sha256=[string]$manifest.management_source_cidr_sha256;egress=$egress
            }
            Agent = $agent
        }
    } finally { $Action = $savedAction }
}

function Assert-P3RemoteContextMatchesProtected([object]$Candidate, [object]$Protected) {
    if ($null -eq $Candidate -or $Candidate -is [Array] -or
        (Get-P3RemoteCanonicalSHA256 $Candidate) -cne (Get-P3RemoteCanonicalSHA256 $Protected)) {
        throw 'caller remote context differs from protected runtime'
    }
}

function Invoke-P3RemoteAction(
    [string]$SelectedAction,
    [string]$RuntimeRoot,
    [string]$ExpectedManifestSHA256,
    [string]$ExpectedPlanSHA256,
    [string]$Confirmation,
    [object]$InputObject,
    [object]$Boundaries
) {
    if ($SelectedAction -notin @('RemoteInstall', 'RemoteRemove')) { throw 'protected remote action differs' }
    Assert-P3RemoteExactProperties -Value $Boundaries -Expected @('ScpRunner', 'SshRunner') -Label 'protected remote boundaries'
    $protected = Get-P3ProtectedRemoteContext -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256
    Assert-P3RemoteContextMatchesProtected -Candidate $InputObject.context -Protected $protected
    if ($SelectedAction -ceq 'RemoteInstall') {
        if ([string]$InputObject.plan.plan_sha256 -cne $ExpectedPlanSHA256 -or
            $Confirmation -cne [string]$InputObject.plan.confirmation_challenge -or
            $Confirmation -cnotmatch '^P3-REMOTE-INSTALL-[0-9A-F]{16}$') { throw 'remote install approval differs' }
        $receipt = Invoke-P3RemoteInstall -Context $protected -Plan $InputObject.plan `
            -ScpRunner $Boundaries.ScpRunner -SshRunner $Boundaries.SshRunner
        Write-P3ProtectedInstallReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256 -Receipt $receipt
        return $receipt
    }
    if ([string]$InputObject.remove_plan.remove_plan_sha256 -cne $ExpectedPlanSHA256 -or
        $Confirmation -cne [string]$InputObject.remove_plan.confirmation_challenge -or
        $Confirmation -cnotmatch '^P3-REMOTE-REMOVE-[0-9A-F]{16}$') { throw 'remote remove approval differs' }
    $storedInstall = Get-P3ProtectedInstallReceipt -Root $RuntimeRoot -ManifestSHA256 $ExpectedManifestSHA256
    if ((Get-P3RemoteCanonicalSHA256 $storedInstall) -cne (Get-P3RemoteCanonicalSHA256 $InputObject.install_receipt)) {
        throw 'protected remote install receipt differs'
    }
    return Invoke-P3RemoteRemove -Context $protected -InstallReceipt $storedInstall `
        -RemovePlan $InputObject.remove_plan -SshRunner $Boundaries.SshRunner
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
            $boundaries = [pscustomobject]@{
                SshRunner=$nativeSshRunner
                ScpRunner={param($Executable,$Arguments,$Source,$Target)& $Executable @Arguments $Source "homegateway@$($protected.Trust.ssh_host):$Target";[pscustomobject]@{exit_code=$LASTEXITCODE}}
            }
            Invoke-P3RemoteAction -SelectedAction $Action -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 `
                -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation -InputObject $request -Boundaries $boundaries |
                ConvertTo-Json -Compress
        }
        'RemoteRemovePlan' { Invoke-P3RemoteRemovePlan -Context $request.context -InstallReceipt $request.install_receipt -SshRunner $nativeSshRunner | ConvertTo-Json -Compress }
        'RemoteRemove' {
            Invoke-P3RemoteAction -SelectedAction $Action -RuntimeRoot $RuntimeRoot -ExpectedManifestSHA256 $ExpectedManifestSHA256 `
                -ExpectedPlanSHA256 $ExpectedPlanSHA256 -Confirmation $Confirmation -InputObject $request `
                -Boundaries ([pscustomobject]@{SshRunner=$nativeSshRunner;ScpRunner={throw 'SCP is not allowed for remove'}}) |
                ConvertTo-Json -Compress
        }
    }
}
