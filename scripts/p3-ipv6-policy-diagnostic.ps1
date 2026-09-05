Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:P3Ipv6DiagnosticDriverPath = [IO.Path]::GetFullPath($PSCommandPath)

$script:P3Ipv6DiagnosticProperties = @(
    'expected_ipv6_policy_sha256','observed_ipv6_policy_sha256','sample_set_sha256',
    'sample_count','unique_policy_identity_count','whole_policy_relation_class',
    'docker_user_chain_class','docker_user_declaration_count','docker_user_rule_count','forward_jump_count',
    'forward_jump_position_class','project_owned_chain_count','project_owned_jump_count',
    'project_owned_comment_count','policy_comment_line_count','parse_complete','parse_failure_classes','project_scope_nonmutation_confirmed',
    'rebaseline_eligible'
)
$script:P3Ipv6RemoteReceiptProperties = @(
    'schema','diagnostic','payload_sha256','protocol_sha256','nonce_sha256',
    'ssh_observation_count','https_observation_count','live_mutation_performed','raw_identity_exposed'
)
$script:P3Ipv6ReceiptProperties = @(
    'schema','prerequisite_manifest_sha256','ssh_trust_sha256','payload_sha256','protocol_sha256',
    'expected_ipv6_policy_sha256','observed_ipv6_policy_sha256','sample_set_sha256',
    'sample_count','unique_policy_identity_count','whole_policy_relation_class',
    'docker_user_chain_class','docker_user_declaration_count','docker_user_rule_count','forward_jump_count',
    'forward_jump_position_class','project_owned_chain_count','project_owned_jump_count',
    'project_owned_comment_count','policy_comment_line_count','parse_complete','parse_failure_classes','project_scope_nonmutation_confirmed',
    'rebaseline_eligible','nonce_sha256','observed_at_utc','ssh_observation_count',
    'https_observation_count','live_mutation_performed','raw_identity_exposed'
)

function Assert-P3Ipv6DiagnosticDependencies {
    foreach ($name in @(
            'Test-P3PrerequisiteManifest','Test-P3PrerequisiteSshTrust','Test-P3PrerequisiteAgentTrust',
            'Assert-P3PrerequisiteExternalFiles','Assert-P3PrerequisiteKnownHostPin',
            'Initialize-P3PrerequisiteRoot','Get-P3PrerequisiteStoredAgentManifest',
            'Assert-P3PrerequisiteFileSet','Read-P3BoundedStableBytes','Open-P3BoundedStableJson',
            'Install-P3ExactRuntimeFile','ConvertTo-P3CanonicalJson','Get-P3SHA256Bytes',
            'Get-P3SHA256Text','Assert-P3SHA256','Assert-P3ExactProperties','Test-P3ExactJsonInteger',
            'Resolve-P3FixedCleanPath','Start-P3Agent','Test-P3AgentState',
            'ConvertTo-P3AgentCanonicalValue','Get-P3AgentCanonicalSHA256',
            'ConvertTo-P3AgentReceiptFromCombined','Stop-P3Agent','Stop-P3OwnedAgentEmergency'
        )) {
        if ($null -eq (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw 'P3 IPv6 diagnostic dependency differs'
        }
    }
}

function Initialize-P3Ipv6VisibleConsoleProcess {
    if ('HomeGateway.P3.Ipv6VisibleConsoleProcess' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace HomeGateway.P3 {
    public static class Ipv6VisibleConsoleProcess {
        private const uint CreateNewConsole = 0x00000010;
        private const uint Infinite = 0xffffffff;
        private const uint WaitObject0 = 0x00000000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static int RunAndWait(string applicationPath, string arguments, string currentDirectory) {
            var startup = new StartupInfo();
            startup.cb = Marshal.SizeOf(typeof(StartupInfo));
            var commandLine = new StringBuilder("\"" + applicationPath + "\" " + arguments);
            ProcessInformation process;
            if (!CreateProcessW(
                    applicationPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateNewConsole,
                    IntPtr.Zero,
                    currentDirectory,
                    ref startup,
                    out process)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            CloseHandle(process.hThread);
            try {
                if (WaitForSingleObject(process.hProcess, Infinite) != WaitObject0) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return unchecked((int)exitCode);
            }
            finally { CloseHandle(process.hProcess); }
        }
    }
}
'@
}

function Invoke-P3Ipv6VisibleSshAddWrapper(
    [string]$PowerShellPath,
    [string]$WrapperPath,
    [string]$SshAddPath,
    [string]$KeyPath,
    [string]$WorkingDirectory,
    [scriptblock]$ProcessRunner = $null
) {
    foreach ($value in @($PowerShellPath,$WrapperPath,$SshAddPath,$KeyPath,$WorkingDirectory)) {
        if ([string]::IsNullOrWhiteSpace($value) -or -not [IO.Path]::IsPathRooted($value) -or
            $value -match '["%\r\n&|<>^!]') { throw 'IPv6 diagnostic visible wrapper input differs' }
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::GetFullPath($PowerShellPath)
    $start.Arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File ' +
        (ConvertTo-P3WindowsCommandLineArgument ([IO.Path]::GetFullPath($WrapperPath))) +
        ' -SshAddPath ' + (ConvertTo-P3WindowsCommandLineArgument ([IO.Path]::GetFullPath($SshAddPath))) +
        ' -KeyPath ' + (ConvertTo-P3WindowsCommandLineArgument ([IO.Path]::GetFullPath($KeyPath)))
    $start.WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory)
    $start.UseShellExecute = $true
    $start.CreateNoWindow = $false
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Normal
    if ($null -ne $ProcessRunner) {
        $result = @(& $ProcessRunner $start)
        if ($result.Count -ne 1 -or $result[0].PSObject.Properties.Name -notcontains 'exit_code' -or
            [int]$result[0].exit_code -ne 0) { throw 'ssh-add failed for the dedicated key' }
        return
    }
    Initialize-P3Ipv6VisibleConsoleProcess
    $exitCode = [HomeGateway.P3.Ipv6VisibleConsoleProcess]::RunAndWait(
        $start.FileName,
        $start.Arguments,
        $start.WorkingDirectory
    )
    if ($exitCode -ne 0) { throw 'ssh-add failed for the dedicated key' }
}

function New-P3PrerequisiteIpv6DiagnosticPlan(
    [object]$Manifest,
    [string]$Nonce,
    [string]$DiagnosticRoot
) {
    Assert-P3Ipv6DiagnosticDependencies
    $null = Test-P3PrerequisiteManifest $Manifest
    Assert-P3SHA256 $Nonce 'IPv6 diagnostic nonce'
    $canonicalRoot = Resolve-P3FixedCleanPath $DiagnosticRoot 'IPv6 diagnostic root'
    $driverRoot = Split-Path -Parent $script:P3Ipv6DiagnosticDriverPath
    $identity = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-ipv6-diagnostic-plan/v1'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        diagnostic_root_sha256=Get-P3SHA256Text $canonicalRoot.ToUpperInvariant()
        nonce_sha256=Get-P3SHA256Text $Nonce
        payload_sha256=[string]$Manifest.payload_sha256
        protocol_sha256=[string]$Manifest.protocol_sha256
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        expected_ipv6_policy_sha256=[string]$Manifest.ssh_trust.expected_ipv6_policy_sha256
        diagnostic_driver_sha256=Get-P3ExactFileSHA256 $script:P3Ipv6DiagnosticDriverPath 'IPv6 diagnostic driver'
        prerequisite_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $driverRoot 'p3-prelive-prerequisite.ps1') 'prerequisite driver'
        ssh_agent_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $driverRoot 'p3-ssh-agent.ps1') 'SSH agent driver'
        runtime_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $driverRoot 'p3-prelive-runtime.ps1') 'prerequisite runtime driver'
        ssh_observation_count=1
        ipv6_sample_count=3
        https_observation_count=0
        connect_timeout_seconds=10
        command_timeout_seconds=30
        maximum_output_bytes=65536
        no_write_scope=$true
        live_mutation_performed=$false
    }
    $planSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $identity)
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $planSHA256
    $result.confirmation_challenge = 'P3-IPV6-DIAGNOSTIC-' + $planSHA256.Substring(0, 16).ToUpperInvariant()
    return [pscustomobject]$result
}

function New-P3PrerequisiteIpv6RebasedPlan(
    [object]$Manifest,
    [string]$Nonce,
    [string]$PrerequisiteRoot,
    [object]$DiagnosticManifest,
    [object]$DiagnosticReceipt,
    [string]$DiagnosticReceiptSHA256,
    [DateTime]$NowUtc
) {
    Assert-P3Ipv6DiagnosticDependencies
    $basePlan = New-P3PrerequisitePlan $Manifest $Nonce $PrerequisiteRoot
    Assert-P3SHA256 $DiagnosticReceiptSHA256 'IPv6 diagnostic receipt'
    $receiptIdentity = [ordered]@{}
    foreach ($property in $DiagnosticReceipt.PSObject.Properties) {
        $value = $property.Value
        if ($property.Name -ceq 'observed_at_utc' -and $value -is [DateTime]) {
            $value = $value.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        $receiptIdentity[$property.Name] = $value
    }
    if ((Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $receiptIdentity)) -cne $DiagnosticReceiptSHA256) {
        throw 'IPv6 rebased plan receipt hash differs'
    }
    $validated = Test-P3PrerequisiteIpv6DiagnosticReceipt $DiagnosticReceipt $DiagnosticManifest $NowUtc
    foreach ($field in @('ssh_host','ssh_user','host_key_fingerprint_sha256','public_key_fingerprint_sha256')) {
        if ([string]$Manifest.ssh_trust.$field -cne [string]$DiagnosticManifest.ssh_trust.$field) {
            throw 'IPv6 rebased plan server identity differs'
        }
    }
    if ([string]$Manifest.payload_sha256 -cne [string]$DiagnosticManifest.payload_sha256 -or
        [string]$Manifest.protocol_sha256 -cne [string]$DiagnosticManifest.protocol_sha256) {
        throw 'IPv6 rebased plan payload identity differs'
    }
    if (-not [bool]$validated.rebaseline_eligible -or
        [string]$validated.whole_policy_relation_class -cne 'stable_mismatch' -or
        [int]$validated.unique_policy_identity_count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$validated.observed_ipv6_policy_sha256) -or
        [string]$Manifest.ssh_trust.expected_ipv6_policy_sha256 -cne
            [string]$validated.observed_ipv6_policy_sha256) {
        throw 'IPv6 rebased plan evidence differs'
    }
    $identity = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-ipv6-rebased-plan/v1'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        prerequisite_plan_sha256=[string]$basePlan.plan_sha256
        prerequisite_root_sha256=[string]$basePlan.prerequisite_root_sha256
        nonce_sha256=[string]$basePlan.nonce_sha256
        diagnostic_manifest_sha256=[string]$DiagnosticManifest.manifest_sha256
        diagnostic_receipt_sha256=$DiagnosticReceiptSHA256
        observed_ipv6_policy_sha256=[string]$validated.observed_ipv6_policy_sha256
        payload_sha256=[string]$Manifest.payload_sha256
        protocol_sha256=[string]$Manifest.protocol_sha256
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        diagnostic_driver_sha256=Get-P3ExactFileSHA256 $script:P3Ipv6DiagnosticDriverPath 'IPv6 diagnostic driver'
        prerequisite_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $PSScriptRoot 'p3-prelive-prerequisite.ps1') 'prerequisite driver'
        ssh_agent_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $PSScriptRoot 'p3-ssh-agent.ps1') 'SSH agent driver'
        runtime_driver_sha256=Get-P3ExactFileSHA256 (Join-Path $PSScriptRoot 'p3-prelive-runtime.ps1') 'runtime driver'
        ssh_observation_count=1
        https_observation_count=3
        no_write_scope=$true
        live_mutation_performed=$false
    }
    $planSHA256 = Get-P3SHA256Bytes (ConvertTo-P3CanonicalJson $identity)
    $result = [ordered]@{}
    foreach ($property in $identity.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result.plan_sha256 = $planSHA256
    $result.confirmation_challenge = 'P3-PRELIVE-REBASED-' + $planSHA256.Substring(0, 16).ToUpperInvariant()
    $result.prerequisite_plan = $basePlan
    return [pscustomobject]$result
}

function Invoke-P3PrerequisiteProductionRebasedObservation(
    [string]$PrerequisiteRoot,
    [object]$InputObject,
    [object]$Boundaries,
    [string]$DiagnosticRoot,
    [object]$DiagnosticManifest,
    [string]$ExpectedDiagnosticReceiptSHA256,
    [string]$ExpectedRebasedPlanSHA256,
    [string]$RebasedConfirmationChallenge
) {
    $receiptCommand = Get-Command Get-P3ProtectedPrerequisiteIpv6DiagnosticReceipt
    $planCommand = Get-Command New-P3PrerequisiteIpv6RebasedPlan
    $check = {
        $now = ([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
        $receipt = & $receiptCommand $DiagnosticRoot $DiagnosticManifest `
            $ExpectedDiagnosticReceiptSHA256 $now $true
        $plan = & $planCommand $InputObject.manifest $InputObject.nonce $PrerequisiteRoot `
            $DiagnosticManifest $receipt $ExpectedDiagnosticReceiptSHA256 $now
        if ($plan.plan_sha256 -cne $ExpectedRebasedPlanSHA256 -or
            $plan.confirmation_challenge -cne $RebasedConfirmationChallenge) {
            throw 'IPv6 rebased execution approval differs'
        }
    }.GetNewClosure()
    & $check
    $guarded = [pscustomobject][ordered]@{}
    foreach ($property in $Boundaries.PSObject.Properties) {
        Add-Member -InputObject $guarded -NotePropertyName $property.Name -NotePropertyValue $property.Value
    }
    $originalSshRunner = $Boundaries.SshRunner
    $guarded.SshRunner = {
        param($Executable,$Arguments,$InputBytes,$TimeoutSeconds,$MaximumBytes)
        & $check
        & $originalSshRunner $Executable $Arguments $InputBytes $TimeoutSeconds $MaximumBytes
    }.GetNewClosure()
    return Invoke-P3PrerequisiteProductionObservation $PrerequisiteRoot $InputObject $guarded
}

function New-P3PrerequisiteIpv6DiagnosticInvocation(
    [object]$Trust,
    [object]$AgentReceipt,
    [string]$Nonce,
    [byte[]]$Payload
) {
    Assert-P3Ipv6DiagnosticDependencies
    Assert-P3ExactProperties $Trust @(
        'git_ssh_path','known_hosts_path','public_key_path','ssh_host','ssh_user',
        'connect_timeout_seconds','command_timeout_seconds','maximum_output_bytes',
        'observer_payload_sha256','observer_protocol_sha256','expected_ipv6_policy_sha256'
    ) 'IPv6 diagnostic trust'
    Assert-P3ExactProperties $AgentReceipt @('ssh_auth_sock') 'IPv6 diagnostic agent receipt'
    Assert-P3SHA256 $Nonce 'IPv6 diagnostic nonce'
    foreach ($name in @('observer_payload_sha256','observer_protocol_sha256','expected_ipv6_policy_sha256')) {
        Assert-P3SHA256 ([string]$Trust.$name) "IPv6 diagnostic $name"
    }
    if ([string]$Trust.ssh_user -cne 'homegateway' -or
        [string]::IsNullOrWhiteSpace([string]$Trust.ssh_host) -or
        [string]::IsNullOrWhiteSpace([string]$Trust.git_ssh_path) -or
        [string]::IsNullOrWhiteSpace([string]$Trust.known_hosts_path) -or
        [string]::IsNullOrWhiteSpace([string]$Trust.public_key_path) -or
        [string]::IsNullOrWhiteSpace([string]$AgentReceipt.ssh_auth_sock) -or
        -not (Test-P3ExactJsonInteger $Trust.connect_timeout_seconds) -or [int]$Trust.connect_timeout_seconds -ne 10 -or
        -not (Test-P3ExactJsonInteger $Trust.command_timeout_seconds) -or [int]$Trust.command_timeout_seconds -ne 30 -or
        -not (Test-P3ExactJsonInteger $Trust.maximum_output_bytes) -or [int]$Trust.maximum_output_bytes -ne 65536 -or
        $null -eq $Payload -or $Payload.Length -lt 1 -or $Payload.Length -gt 524288 -or
        (Get-P3SHA256Bytes $Payload) -cne [string]$Trust.observer_payload_sha256) {
        throw 'IPv6 diagnostic invocation differs'
    }
    $header = [pscustomobject][ordered]@{
        expected_ipv6_policy_sha256=[string]$Trust.expected_ipv6_policy_sha256
        length=$Payload.Length
        nonce=$Nonce
        payload_sha256=[string]$Trust.observer_payload_sha256
        protocol_sha256=[string]$Trust.observer_protocol_sha256
        schema='home-gateway/p3-prelive-ipv6-diagnostic-frame/v1'
    }
    $headerBytes = ConvertTo-P3CanonicalJson $header
    $stdin = [byte[]]::new($headerBytes.Length + 1 + $Payload.Length)
    [Array]::Copy($headerBytes, 0, $stdin, 0, $headerBytes.Length)
    $stdin[$headerBytes.Length] = 10
    [Array]::Copy($Payload, 0, $stdin, $headerBytes.Length + 1, $Payload.Length)
    $loader = @'
import hashlib,json,re,sys,types
maximum=526337
bom=b'\xef\xbb\xbf'
raw=sys.stdin.buffer.read(maximum+len(bom)+1)
if raw.startswith(bom): raw=raw[len(bom):]
if not raw or len(raw)>maximum or raw.count(b'\n')<1: raise ValueError('diagnostic frame length differs')
header_raw,payload=raw.split(b'\n',1)
header=json.loads(header_raw.decode('utf-8','strict'))
expected={'expected_ipv6_policy_sha256','length','nonce','payload_sha256','protocol_sha256','schema'}
if not isinstance(header,dict) or set(header)!=expected: raise ValueError('diagnostic frame header differs')
if header['schema']!='home-gateway/p3-prelive-ipv6-diagnostic-frame/v1': raise ValueError('diagnostic frame schema differs')
if not isinstance(header['length'],int) or isinstance(header['length'],bool) or header['length']<1 or header['length']>524288 or len(payload)!=header['length']: raise ValueError('diagnostic frame length differs')
for name in ('nonce','payload_sha256','protocol_sha256','expected_ipv6_policy_sha256'):
    if not isinstance(header[name],str) or re.fullmatch('[0-9a-f]{64}',header[name]) is None: raise ValueError('diagnostic frame identity differs')
if hashlib.sha256(payload).hexdigest()!=header['payload_sha256']: raise ValueError('diagnostic frame hash differs')
module_name='p3_transient_ipv6_diagnostic'
if module_name in sys.modules: raise ValueError('diagnostic module collision differs')
module=types.ModuleType(module_name)
module.__file__='<memory>'
scope=module.__dict__
sys.modules[module_name]=module
try:
    exec(compile(payload,'<p3-ipv6-diagnostic>','exec'),scope)
    for name in ('classify_ipv6_policy_samples','run_checked_command','public_protocol_sha256','_sha'):
        if name not in scope: raise ValueError('diagnostic payload contract differs')
    if scope['public_protocol_sha256']()!=header['protocol_sha256']: raise ValueError('diagnostic protocol identity differs')
    samples=[scope['run_checked_command'](['/usr/sbin/ip6tables-save']) for _ in range(3)]
    diagnostic=scope['classify_ipv6_policy_samples'](samples,header['expected_ipv6_policy_sha256'])
    receipt={'schema':'home-gateway/p3-prelive-ipv6-remote-diagnostic/v1','diagnostic':diagnostic,'payload_sha256':header['payload_sha256'],'protocol_sha256':header['protocol_sha256'],'nonce_sha256':scope['_sha'](header['nonce'].encode()),'ssh_observation_count':1,'https_observation_count':0,'live_mutation_performed':False,'raw_identity_exposed':False}
    receipt_json=json.dumps(receipt,sort_keys=True,separators=(',',':'))
finally:
    for sample in locals().get('samples',[]):
        if isinstance(sample,bytes): del sample
    if sys.modules.get(module_name) is module: del sys.modules[module_name]
sys.stdout.write(receipt_json)
'@.Trim()
    $loaderEncoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($loader))
    $remoteCommand = 'sudo -n /usr/bin/python3 -c "import base64;exec(base64.b64decode(''' + $loaderEncoded + '''))"'
    $arguments = @(
        '-F','/dev/null','-o','GlobalKnownHostsFile=/dev/null',
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-i',[string]$Trust.public_key_path,
        '-o',('IdentityAgent=' + [string]$AgentReceipt.ssh_auth_sock),
        '-o',('UserKnownHostsFile=' + [string]$Trust.known_hosts_path),'-o','StrictHostKeyChecking=yes',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','ClearAllForwardings=yes',
        '-o','RequestTTY=no','-o',('ConnectTimeout=' + [string]$Trust.connect_timeout_seconds),'-T',
        ([string]$Trust.ssh_user + '@' + [string]$Trust.ssh_host),
        $remoteCommand
    )
    return [pscustomobject][ordered]@{
        executable=[string]$Trust.git_ssh_path
        arguments=$arguments
        stdin=$stdin
        timeout_seconds=[int]$Trust.command_timeout_seconds
        maximum_output_bytes=[int]$Trust.maximum_output_bytes
    }
}

function Test-P3PrerequisiteIpv6DiagnosticData([object]$Diagnostic, [string]$ExpectedSHA256) {
    Assert-P3Ipv6DiagnosticDependencies
    Assert-P3ExactProperties $Diagnostic $script:P3Ipv6DiagnosticProperties 'IPv6 diagnostic data'
    Assert-P3SHA256 $ExpectedSHA256 'expected IPv6 policy'
    if ([string]$Diagnostic.expected_ipv6_policy_sha256 -cne $ExpectedSHA256) {
        throw 'IPv6 diagnostic expected policy differs'
    }
    foreach ($name in @('sample_set_sha256')) { Assert-P3SHA256 ([string]$Diagnostic.$name) "IPv6 diagnostic $name" }
    if ($null -ne $Diagnostic.observed_ipv6_policy_sha256) {
        Assert-P3SHA256 ([string]$Diagnostic.observed_ipv6_policy_sha256) 'observed IPv6 policy'
    }
    foreach ($name in @('sample_count','unique_policy_identity_count','docker_user_declaration_count','docker_user_rule_count','forward_jump_count',
            'project_owned_chain_count','project_owned_jump_count','project_owned_comment_count','policy_comment_line_count')) {
        if (-not (Test-P3ExactJsonInteger $Diagnostic.$name) -or [int]$Diagnostic.$name -lt 0) {
            throw 'IPv6 diagnostic count differs'
        }
    }
    if ([int]$Diagnostic.sample_count -ne 3 -or [int]$Diagnostic.unique_policy_identity_count -lt 1 -or
        [int]$Diagnostic.unique_policy_identity_count -gt 3 -or
        [string]$Diagnostic.whole_policy_relation_class -notin @('historical_match','stable_mismatch','unstable') -or
        [string]$Diagnostic.docker_user_chain_class -notin @('missing','empty','return_only','nonempty','ambiguous') -or
        [string]$Diagnostic.forward_jump_position_class -notin @('absent','first','not_first') -or
        $Diagnostic.parse_complete -isnot [bool] -or $Diagnostic.project_scope_nonmutation_confirmed -isnot [bool] -or
        $Diagnostic.rebaseline_eligible -isnot [bool]) {
        throw 'IPv6 diagnostic data differs'
    }
    $allowedFailures = @(
        'invalid_utf8','blank_line','unexpected_top_level_line','duplicate_table','chain_after_rule',
        'duplicate_chain','unexpected_table_line','invalid_rule_quoting','invalid_rule_shape',
        'unclosed_table','filter_table_count','undeclared_source_chain','missing_target_argument',
        'missing_comment_argument','multiple_targets','multiple_comments','incomplete_backend_view'
    )
    $failures = @($Diagnostic.parse_failure_classes)
    if ($Diagnostic.parse_failure_classes -isnot [Array] -or
        @($failures | Select-Object -Unique).Count -ne $failures.Count -or
        @($failures | Where-Object { [string]$_ -notin $allowedFailures }).Count -ne 0 -or
        ([bool]$Diagnostic.parse_complete -and $failures.Count -ne 0) -or
        (-not [bool]$Diagnostic.parse_complete -and $failures.Count -eq 0)) {
        throw 'IPv6 diagnostic parse failure classes differ'
    }
    $stable = [int]$Diagnostic.unique_policy_identity_count -eq 1
    if (($stable -and $null -eq $Diagnostic.observed_ipv6_policy_sha256) -or
        (-not $stable -and $null -ne $Diagnostic.observed_ipv6_policy_sha256) -or
        ([string]$Diagnostic.whole_policy_relation_class -ceq 'unstable') -ne (-not $stable)) {
        throw 'IPv6 diagnostic stability differs'
    }
    $eligible = $stable -and [bool]$Diagnostic.parse_complete -and
        [string]$Diagnostic.docker_user_chain_class -in @('empty','return_only') -and
        [int]$Diagnostic.forward_jump_count -eq 1 -and
        [string]$Diagnostic.forward_jump_position_class -ceq 'first' -and
        [int]$Diagnostic.project_owned_chain_count -eq 0 -and
        [int]$Diagnostic.project_owned_jump_count -eq 0 -and
        [int]$Diagnostic.project_owned_comment_count -eq 0 -and
        [bool]$Diagnostic.project_scope_nonmutation_confirmed
    if ([bool]$Diagnostic.rebaseline_eligible -ne $eligible) { throw 'IPv6 diagnostic eligibility differs' }
    return $Diagnostic
}

function Invoke-P3PrerequisiteIpv6SshDiagnostic(
    [object]$Manifest,
    [object]$Trust,
    [object]$AgentReceipt,
    [string]$Nonce,
    [scriptblock]$Runner
) {
    Assert-P3Ipv6DiagnosticDependencies
    $null = Test-P3PrerequisiteSshTrust $Trust $Manifest
    foreach ($pair in @(
            @('known_hosts_path','known_hosts_sha256','known-hosts'),
            @('git_ssh_path','git_ssh_sha256','Git ssh'),
            @('public_key_path','public_key_sha256','public key'),
            @('observer_payload_path','observer_payload_sha256','observer payload'))) {
        $actual = Get-P3ExactFileSHA256 ([string]$Trust.($pair[0])) ([string]$pair[2])
        if ($actual -cne [string]$Trust.($pair[1])) { throw 'IPv6 diagnostic SSH boundary identity differs' }
    }
    Assert-P3PrerequisiteKnownHostPin $Trust
    $payload = Read-P3BoundedStableBytes ([string]$Trust.observer_payload_path) 524288 'observer payload'
    $invocationTrust = [pscustomobject]@{
        git_ssh_path=[string]$Trust.git_ssh_path;known_hosts_path=[string]$Trust.known_hosts_path
        public_key_path=[string]$Trust.public_key_path;ssh_host=[string]$Trust.ssh_host;ssh_user=[string]$Trust.ssh_user
        connect_timeout_seconds=[int]$Trust.connect_timeout_seconds;command_timeout_seconds=[int]$Trust.command_timeout_seconds
        maximum_output_bytes=[int]$Trust.maximum_output_bytes;observer_payload_sha256=[string]$Trust.observer_payload_sha256
        observer_protocol_sha256=[string]$Trust.observer_protocol_sha256;expected_ipv6_policy_sha256=[string]$Trust.expected_ipv6_policy_sha256
    }
    $invocation = New-P3PrerequisiteIpv6DiagnosticInvocation $invocationTrust ([pscustomobject]@{ssh_auth_sock=[string]$AgentReceipt.socket}) $Nonce $payload
    $result = & $Runner $invocation.executable @($invocation.arguments) ([byte[]]$invocation.stdin) `
        ([int]$invocation.timeout_seconds) ([int]$invocation.maximum_output_bytes)
    Assert-P3ExactProperties $result @('ExitCode','TimedOut','Oversized','StdOut','StdErr') 'IPv6 diagnostic SSH result'
    $stdout = [string]$result.StdOut
    $stderr = [string]$result.StdErr
    if ([bool]$result.TimedOut -or [bool]$result.Oversized -or [int]$result.ExitCode -ne 0 -or
        [Text.UTF8Encoding]::new($false).GetByteCount($stderr) -ne 0 -or
        [Text.UTF8Encoding]::new($false).GetByteCount($stdout) -lt 2 -or
        [Text.UTF8Encoding]::new($false).GetByteCount($stdout) -gt [int]$Trust.maximum_output_bytes) {
        throw 'IPv6 diagnostic SSH observation failed'
    }
    try { $receipt = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop }
    catch { throw 'IPv6 diagnostic SSH JSON differs' }
    if ($receipt -is [Array]) { throw 'IPv6 diagnostic SSH JSON differs' }
    Assert-P3ExactProperties $receipt $script:P3Ipv6RemoteReceiptProperties 'IPv6 remote diagnostic receipt'
    $null = Test-P3PrerequisiteIpv6DiagnosticData $receipt.diagnostic ([string]$Trust.expected_ipv6_policy_sha256)
    if ([string]$receipt.schema -cne 'home-gateway/p3-prelive-ipv6-remote-diagnostic/v1' -or
        [string]$receipt.payload_sha256 -cne [string]$Manifest.payload_sha256 -or
        [string]$receipt.protocol_sha256 -cne [string]$Manifest.protocol_sha256 -or
        [string]$receipt.nonce_sha256 -cne (Get-P3SHA256Text $Nonce) -or
        [int]$receipt.ssh_observation_count -ne 1 -or [int]$receipt.https_observation_count -ne 0 -or
        [bool]$receipt.live_mutation_performed -or [bool]$receipt.raw_identity_exposed) {
        throw 'IPv6 remote diagnostic receipt differs'
    }
    return $receipt
}

function New-P3PrerequisiteIpv6DiagnosticReceipt(
    [object]$Manifest,
    [object]$RemoteReceipt,
    [DateTime]$NowUtc
) {
    Assert-P3ExactProperties $RemoteReceipt $script:P3Ipv6RemoteReceiptProperties 'IPv6 remote diagnostic receipt'
    $null = Test-P3PrerequisiteIpv6DiagnosticData $RemoteReceipt.diagnostic ([string]$Manifest.ssh_trust.expected_ipv6_policy_sha256)
    $diagnostic = $RemoteReceipt.diagnostic
    $receipt = [pscustomobject][ordered]@{
        schema='home-gateway/p3-prelive-ipv6-diagnostic-receipt/v1'
        prerequisite_manifest_sha256=[string]$Manifest.manifest_sha256
        ssh_trust_sha256=[string]$Manifest.ssh_trust_sha256
        payload_sha256=[string]$RemoteReceipt.payload_sha256
        protocol_sha256=[string]$RemoteReceipt.protocol_sha256
        expected_ipv6_policy_sha256=[string]$diagnostic.expected_ipv6_policy_sha256
        observed_ipv6_policy_sha256=$diagnostic.observed_ipv6_policy_sha256
        sample_set_sha256=[string]$diagnostic.sample_set_sha256
        sample_count=[int]$diagnostic.sample_count
        unique_policy_identity_count=[int]$diagnostic.unique_policy_identity_count
        whole_policy_relation_class=[string]$diagnostic.whole_policy_relation_class
        docker_user_chain_class=[string]$diagnostic.docker_user_chain_class
        docker_user_declaration_count=[int]$diagnostic.docker_user_declaration_count
        docker_user_rule_count=[int]$diagnostic.docker_user_rule_count
        forward_jump_count=[int]$diagnostic.forward_jump_count
        forward_jump_position_class=[string]$diagnostic.forward_jump_position_class
        project_owned_chain_count=[int]$diagnostic.project_owned_chain_count
        project_owned_jump_count=[int]$diagnostic.project_owned_jump_count
        project_owned_comment_count=[int]$diagnostic.project_owned_comment_count
        policy_comment_line_count=[int]$diagnostic.policy_comment_line_count
        parse_complete=[bool]$diagnostic.parse_complete
        parse_failure_classes=@($diagnostic.parse_failure_classes)
        project_scope_nonmutation_confirmed=[bool]$diagnostic.project_scope_nonmutation_confirmed
        rebaseline_eligible=[bool]$diagnostic.rebaseline_eligible
        nonce_sha256=[string]$RemoteReceipt.nonce_sha256
        observed_at_utc=$NowUtc.ToUniversalTime().ToString('o')
        ssh_observation_count=1
        https_observation_count=0
        live_mutation_performed=$false
        raw_identity_exposed=$false
    }
    return Test-P3PrerequisiteIpv6DiagnosticReceipt $receipt $Manifest $NowUtc
}

function Test-P3PrerequisiteIpv6DiagnosticReceipt([object]$Receipt, [object]$Manifest, [DateTime]$NowUtc) {
    Assert-P3Ipv6DiagnosticDependencies
    $null = Test-P3PrerequisiteManifest $Manifest
    Assert-P3ExactProperties $Receipt $script:P3Ipv6ReceiptProperties 'IPv6 diagnostic receipt'
    $diagnostic = [pscustomobject][ordered]@{}
    foreach ($name in $script:P3Ipv6DiagnosticProperties) { Add-Member -InputObject $diagnostic -NotePropertyName $name -NotePropertyValue $Receipt.$name }
    $null = Test-P3PrerequisiteIpv6DiagnosticData $diagnostic ([string]$Manifest.ssh_trust.expected_ipv6_policy_sha256)
    $null = Assert-P3PrerequisiteFresh $Receipt.observed_at_utc $NowUtc 'IPv6 diagnostic receipt'
    if ([string]$Receipt.schema -cne 'home-gateway/p3-prelive-ipv6-diagnostic-receipt/v1' -or
        [string]$Receipt.prerequisite_manifest_sha256 -cne [string]$Manifest.manifest_sha256 -or
        [string]$Receipt.ssh_trust_sha256 -cne [string]$Manifest.ssh_trust_sha256 -or
        [string]$Receipt.payload_sha256 -cne [string]$Manifest.payload_sha256 -or
        [string]$Receipt.protocol_sha256 -cne [string]$Manifest.protocol_sha256 -or
        [int]$Receipt.ssh_observation_count -ne 1 -or [int]$Receipt.https_observation_count -ne 0 -or
        [bool]$Receipt.live_mutation_performed -or [bool]$Receipt.raw_identity_exposed) {
        throw 'IPv6 diagnostic receipt provenance differs'
    }
    Assert-P3SHA256 ([string]$Receipt.nonce_sha256) 'IPv6 diagnostic receipt nonce'
    return $Receipt
}

function Write-P3ProtectedPrerequisiteIpv6DiagnosticReceipt(
    [string]$Root,
    [object]$Manifest,
    [object]$Receipt,
    [DateTime]$NowUtc
) {
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $baseFiles = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json')
    Assert-P3PrerequisiteFileSet $resolved $baseFiles
    $validated = Test-P3PrerequisiteIpv6DiagnosticReceipt $Receipt $Manifest $NowUtc
    $bytes = ConvertTo-P3CanonicalJson $validated
    $hash = Get-P3SHA256Bytes $bytes
    $path = Join-Path $resolved 'ipv6-diagnostic-receipt.json'
    $null = Install-P3ExactRuntimeFile $bytes $path $hash
    $reopened = Open-P3BoundedStableJson $path 65536 $script:P3Ipv6ReceiptProperties
    if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $validated) -or
        (Get-P3ExactFileSHA256 $path 'IPv6 diagnostic receipt') -cne $hash) {
        throw 'protected IPv6 diagnostic receipt differs'
    }
    $null = Test-P3PrerequisiteIpv6DiagnosticReceipt $reopened $Manifest $NowUtc
    Assert-P3PrerequisiteFileSet $resolved @($baseFiles + 'ipv6-diagnostic-receipt.json')
    return [pscustomobject]@{receipt=$reopened;receipt_sha256=$hash}
}

function Get-P3ProtectedPrerequisiteIpv6DiagnosticReceipt(
    [string]$Root,
    [object]$Manifest,
    [string]$ExpectedReceiptSHA256,
    [DateTime]$NowUtc,
    [bool]$RequireEligible = $true
) {
    Assert-P3SHA256 $ExpectedReceiptSHA256 'expected IPv6 diagnostic receipt'
    $resolved = Assert-P3PrerequisiteRoot $Root $Manifest
    $expected = @('.home-gateway-p3-prerequisite-owner.v1','manifest.json','agent-manifest.json','ipv6-diagnostic-receipt.json')
    Assert-P3PrerequisiteFileSet $resolved $expected
    $path = Join-Path $resolved 'ipv6-diagnostic-receipt.json'
    if ((Get-P3ExactFileSHA256 $path 'IPv6 diagnostic receipt') -cne $ExpectedReceiptSHA256) {
        throw 'protected IPv6 diagnostic receipt hash differs'
    }
    $receipt = Open-P3BoundedStableJson $path 65536 $script:P3Ipv6ReceiptProperties
    $null = Test-P3PrerequisiteIpv6DiagnosticReceipt $receipt $Manifest $NowUtc
    if ($RequireEligible -and -not [bool]$receipt.rebaseline_eligible) { throw 'IPv6 diagnostic receipt is not eligible for rebaseline' }
    return $receipt
}

function Invoke-P3PrerequisiteProductionIpv6Diagnostic(
    [string]$DiagnosticRoot,
    [object]$InputObject,
    [object]$Boundaries
) {
    Assert-P3Ipv6DiagnosticDependencies
    $required = @('AddRunner','AgentRunner','ClockRunner','DeleteRunner','ListRunner','ProcessRunner',
        'ReceiptRemoveRunner','ReobserveRunner','SocketExistsRunner','SshRunner','StopRunner','WaitRunner')
    Assert-P3ExactProperties $Boundaries $required 'IPv6 diagnostic production boundaries'
    Assert-P3ExactProperties $InputObject @('manifest','ssh_trust','agent_manifest','nonce','expected_plan_sha256','confirmation_challenge') 'IPv6 diagnostic production input'
    $manifest = Test-P3PrerequisiteManifest $InputObject.manifest
    $trust = Test-P3PrerequisiteSshTrust $InputObject.ssh_trust $manifest
    $agentManifest = Test-P3PrerequisiteAgentTrust $trust $InputObject.agent_manifest $manifest
    Assert-P3SHA256 ([string]$InputObject.nonce) 'IPv6 diagnostic nonce'
    $plan = New-P3PrerequisiteIpv6DiagnosticPlan $manifest ([string]$InputObject.nonce) $DiagnosticRoot
    if ([string]$InputObject.expected_plan_sha256 -cne [string]$plan.plan_sha256 -or
        [string]$InputObject.confirmation_challenge -cne [string]$plan.confirmation_challenge) {
        throw 'IPv6 diagnostic approval differs'
    }
    Assert-P3PrerequisiteExternalFiles $trust
    $null = Initialize-P3PrerequisiteRoot $DiagnosticRoot $manifest $agentManifest
    $storedManifest = Get-P3PrerequisiteStoredAgentManifest $DiagnosticRoot $manifest $agentManifest
    $started = Start-P3Agent $storedManifest $Boundaries.AgentRunner $Boundaries.ProcessRunner $Boundaries.AddRunner $Boundaries.StopRunner
    $protectedCombined = $null
    $remoteReceipt = $null
    try {
        $combined = Test-P3AgentState $storedManifest $started $Boundaries.ListRunner $Boundaries.ProcessRunner
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json (ConvertTo-P3AgentCanonicalValue $combined) -Depth 16 -Compress))
        $receiptPath = Join-Path $DiagnosticRoot 'agent-receipt.json'
        $null = Install-P3ExactRuntimeFile $bytes $receiptPath (Get-P3SHA256Bytes $bytes)
        $reopened = Open-P3BoundedStableJson $receiptPath 65536 $script:P3CombinedAgentReceiptProperties
        if ((Get-P3AgentCanonicalSHA256 $reopened) -cne (Get-P3AgentCanonicalSHA256 $combined)) {
            throw 'protected IPv6 diagnostic agent receipt differs'
        }
        $protectedCombined = $reopened
        $remoteReceipt = Invoke-P3PrerequisiteIpv6SshDiagnostic $manifest $trust $protectedCombined ([string]$InputObject.nonce) $Boundaries.SshRunner
    }
    finally {
        $protectedReceiptFailure = $null
        $storedCombined = $null
        if ($null -ne $protectedCombined) {
            try {
                $receiptPath = Join-Path $DiagnosticRoot 'agent-receipt.json'
                $storedCombined = Open-P3BoundedStableJson $receiptPath 65536 $script:P3CombinedAgentReceiptProperties
                if ((Get-P3AgentCanonicalSHA256 $storedCombined) -cne (Get-P3AgentCanonicalSHA256 $protectedCombined)) {
                    throw 'protected IPv6 diagnostic agent receipt differs'
                }
            } catch { $protectedReceiptFailure = $_ }
        }
        if ($null -eq $protectedCombined -or $null -ne $protectedReceiptFailure) {
            Stop-P3OwnedAgentEmergency -Manifest $storedManifest -AgentReceipt $started `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ProcessRunner $Boundaries.ProcessRunner -WaitRunner $Boundaries.WaitRunner `
                -ReobserveRunner $Boundaries.ReobserveRunner -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
            if ($null -ne $protectedReceiptFailure) { throw $protectedReceiptFailure }
        } else {
            $storedReceipt = ConvertTo-P3AgentReceiptFromCombined $storedCombined
            Stop-P3Agent -Manifest $storedManifest -AgentReceipt $storedReceipt `
                -DeleteRunner $Boundaries.DeleteRunner -StopRunner $Boundaries.StopRunner `
                -ListRunner $Boundaries.ListRunner -ProcessRunner $Boundaries.ProcessRunner `
                -WaitRunner $Boundaries.WaitRunner -ReobserveRunner $Boundaries.ReobserveRunner `
                -SocketExistsRunner $Boundaries.SocketExistsRunner | Out-Null
            & $Boundaries.ReceiptRemoveRunner $receiptPath
            if ([IO.File]::Exists($receiptPath)) { throw 'protected IPv6 diagnostic agent cleanup differs' }
        }
    }
    $now = ([DateTime](& $Boundaries.ClockRunner)).ToUniversalTime()
    $receipt = New-P3PrerequisiteIpv6DiagnosticReceipt $manifest $remoteReceipt $now
    return Write-P3ProtectedPrerequisiteIpv6DiagnosticReceipt $DiagnosticRoot $manifest $receipt $now
}
