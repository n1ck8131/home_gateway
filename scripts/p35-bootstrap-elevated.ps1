# This file is a reviewed payload template. Production bootstrap MUST pass its
# exact UTF-8 bytes to inbox Windows PowerShell 5.1 via -EncodedCommand after
# verifying the approved SHA-256. It must never be invoked elevated via -File.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not [string]::IsNullOrEmpty($PSCommandPath)) { throw 'P3.5 bootstrap must execute only as a pinned EncodedCommand payload' }
if ($PSVersionTable.PSEdition -cne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'P3.5 bootstrap requires inbox Windows PowerShell 5.1' }
$windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$expectedPSHome = [IO.Path]::Combine($windows, 'System32', 'WindowsPowerShell', 'v1.0')
if (-not [string]::Equals($PSHOME.TrimEnd('\'), $expectedPSHome.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'P3.5 bootstrap requires trusted System32 Windows PowerShell' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'P3.5 bootstrap requires an elevated Administrator token' }

$requestText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$env:HG_P35_BOOTSTRAP_REQUEST_B64))
$env:HG_P35_BOOTSTRAP_REQUEST_B64 = $null
if ([Text.Encoding]::UTF8.GetByteCount($requestText) -gt 65536) { throw 'P3.5 bootstrap request exceeds its limit' }
$request = ConvertFrom-Json -InputObject $requestText -ErrorAction Stop
$action = [string]$request.action
if ([int]$request.version -ne 1 -or $action -notin @('install', 'restore-config-acl')) { throw 'P3.5 bootstrap request action differs' }
$expectedProperties = @('version', 'action', 'confirmation', 'caller_sid', 'config_path', 'config_sha256')
if ($action -ceq 'install') { $expectedProperties += @('launcher_path', 'launcher_sha256', 'hgctl_path', 'hgctl_sha256') }
$actualProperties = @($request.PSObject.Properties.Name | Sort-Object)
if (@(Compare-Object -ReferenceObject ($expectedProperties | Sort-Object) -DifferenceObject $actualProperties).Count -ne 0) { throw 'P3.5 bootstrap request schema differs' }
$expectedConfirmation = if ($action -ceq 'install') { 'P35-BOOTSTRAP-FILESYSTEM-V1' } else { 'P35-RESTORE-CONFIG-ACL-V1' }
if ([string]$request.confirmation -cne $expectedConfirmation) { throw 'P3.5 bootstrap confirmation differs' }

$script:OwnerMarker = 'home-gateway/p35/windows/v1'
$script:ParentMarkerName = '.p35-parent-owner.v1'
$script:RootMarkerName = '.p35-root-owner.v1'
$script:BinMarkerName = '.p35-bin-owner.v1'
$script:SecretsMarkerName = '.p35-secrets-owner.v1'
$script:SystemSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$script:AdministratorsSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$script:CurrentSID = [Security.Principal.SecurityIdentifier]::new([string]$request.caller_sid)
if ($script:CurrentSID.Value -in @($script:SystemSID.Value, $script:AdministratorsSID.Value)) { throw 'P3.5 bootstrap caller SID must identify the non-elevated operator' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HomeGateway.P35 {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    public static class NativeFileIdentity {
        private const uint GenericRead = 0x80000000;
        private const uint ReadControl = 0x00020000;
        private const uint WriteDac = 0x00040000;
        private const uint WriteOwner = 0x00080000;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        public static SafeFileHandle OpenConfigSecurityFile(string path) {
            return CreateFileW(
                path,
                GenericRead | ReadControl | WriteDac | WriteOwner,
                0,
                IntPtr.Zero,
                OpenExisting,
                OpenReparsePoint,
                IntPtr.Zero);
        }
    }
}
'@

function Assert-SHA256([string]$Value, [string]$Label) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be one lowercase SHA-256 value" }
}

function Resolve-LocalCleanPath([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\?\', [StringComparison]::Ordinal) -or $Path.StartsWith('\\.\', [StringComparison]::Ordinal)) { throw "$Label must be a local absolute path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($Path.TrimEnd('\'), $full.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be clean" }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw "$Label must be on a fixed local volume" }
    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label contains a reparse point" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent) -or [string]::Equals($parent, $current, [StringComparison]::OrdinalIgnoreCase)) { break }
        $current = $parent
    }
    return $full
}

function Assert-RegularFile([string]$Path, [string]$Label) {
    $null = Resolve-LocalCleanPath -Path $Path -Label $Label
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$Label must be a regular non-reparse file" }
}

function Get-StreamSHA256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Get-ExclusiveFileSHA256([string]$Path) {
    Assert-RegularFile -Path $Path -Label 'hash source'
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { return Get-StreamSHA256 -Stream $stream } finally { $stream.Dispose() }
}

function New-ProtectedDirectorySecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($script:AdministratorsSID)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($script:SystemSID, $script:AdministratorsSID)) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    return $security
}

function Assert-ProtectedDirectory([string]$Path) {
    $null = Resolve-LocalCleanPath -Path $Path -Label 'protected directory'
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'P3.5 protected path is not a real directory' }
    $acl = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    if (-not $acl.AreAccessRulesProtected) { throw 'P3.5 protected directory inherits access rules' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($script:SystemSID.Value, $script:AdministratorsSID.Value)) { throw 'P3.5 protected directory owner differs' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'P3.5 protected directory DACL count differs' }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $sid -notin @($script:SystemSID.Value, $script:AdministratorsSID.Value) -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $seen.ContainsKey($sid)) { throw 'P3.5 protected directory DACL differs' }
        $seen[$sid] = $true
    }
    if (-not $seen.ContainsKey($script:SystemSID.Value) -or -not $seen.ContainsKey($script:AdministratorsSID.Value)) { throw 'P3.5 protected directory lacks a privileged ACE' }
}

function Ensure-OwnedProtectedDirectory([string]$Path, [string]$MarkerName) {
    if ([IO.Directory]::Exists($Path)) {
        Assert-ProtectedDirectory -Path $Path
        Assert-ExactTextFile -Path ([IO.Path]::Combine($Path, $MarkerName)) -Text $script:OwnerMarker
        return
    }
    if ([IO.File]::Exists($Path)) { throw 'P3.5 protected directory path collides with a file' }
    $staging = $Path + '.p35-next-' + [Guid]::NewGuid().ToString('N')
    $null = [IO.Directory]::CreateDirectory($staging, (New-ProtectedDirectorySecurity))
    Ensure-ExactTextFile -Path ([IO.Path]::Combine($staging, $MarkerName)) -Text $script:OwnerMarker
    Assert-ProtectedDirectory -Path $staging
    Assert-ExactTextFile -Path ([IO.Path]::Combine($staging, $MarkerName)) -Text $script:OwnerMarker
    [IO.Directory]::Move($staging, $Path)
    Assert-ProtectedDirectory -Path $Path
    Assert-ExactTextFile -Path ([IO.Path]::Combine($Path, $MarkerName)) -Text $script:OwnerMarker
}

function Ensure-ExactTextFile([string]$Path, [string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    if ([IO.File]::Exists($Path)) {
        Assert-RegularFile -Path $Path -Label 'protected text file'
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try {
            if ($stream.Length -ne $bytes.Length) { throw 'protected text file differs' }
            $actual = [byte[]]::new($bytes.Length)
            $offset = 0
            while ($offset -lt $actual.Length) {
                $read = $stream.Read($actual, $offset, $actual.Length - $offset)
                if ($read -eq 0) { throw 'protected text file differs' }
                $offset += $read
            }
            for ($index = 0; $index -lt $bytes.Length; $index++) {
                if ($actual[$index] -ne $bytes[$index]) { throw 'protected text file differs' }
            }
        } finally { $stream.Dispose() }
        return
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Assert-ExactTextFile([string]$Path, [string]$Text) {
    if (-not [IO.File]::Exists($Path)) { throw 'protected text file is missing' }
    Ensure-ExactTextFile -Path $Path -Text $Text
}

function Read-ExactUTF8File([string]$Path, [string]$Label) {
    Assert-RegularFile -Path $Path -Label $Label
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 65536) { throw "$Label length differs" }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "$Label is truncated" }
            $offset += $read
        }
    } finally { $stream.Dispose() }
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    return $encoding.GetString($bytes)
}

function Get-StreamFileIdentity([IO.FileStream]$Stream) {
    $information = [HomeGateway.P35.ByHandleFileInformation]::new()
    if (-not [HomeGateway.P35.NativeFileIdentity]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$information)) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    return [pscustomobject]@{
        volume_serial = ('{0:x8}' -f $information.VolumeSerialNumber)
        file_index = ('{0:x8}{1:x8}' -f $information.FileIndexHigh, $information.FileIndexLow)
    }
}

function Open-ConfigSecurityStream([string]$Path) {
    Assert-RegularFile -Path $Path -Label 'RedShield config source'
    $handle = [HomeGateway.P35.NativeFileIdentity]::OpenConfigSecurityFile($Path)
    if ($null -eq $handle -or $handle.IsInvalid) {
        if ($null -ne $handle) { $handle.Dispose() }
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $stream = $null
    try {
        $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 4096, $false)
        $handle = $null
        $information = [HomeGateway.P35.ByHandleFileInformation]::new()
        if (-not [HomeGateway.P35.NativeFileIdentity]::GetFileInformationByHandle($stream.SafeFileHandle, [ref]$information)) {
            throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        if (($information.FileAttributes -band 0x10) -ne 0 -or ($information.FileAttributes -band 0x400) -ne 0) {
            throw 'RedShield config security handle is not a regular non-reparse file'
        }
        return $stream
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    } finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
}

function Assert-ConfigStreamBinding([object]$Binding, [IO.FileStream]$Stream, [string]$Path, [string]$Expected) {
    if ([int]$Binding.version -ne 1 -or -not [string]::Equals([string]$Binding.config_path, $Path, [StringComparison]::OrdinalIgnoreCase) -or [string]$Binding.config_sha256 -cne $Expected -or [string]$Binding.volume_serial -cnotmatch '^[0-9a-f]{8}$' -or [string]$Binding.file_index -cnotmatch '^[0-9a-f]{16}$') {
        throw 'config ACL snapshot binding differs'
    }
    $Stream.Position = 0
    $actual = Get-StreamSHA256 -Stream $Stream
    $fileIdentity = Get-StreamFileIdentity -Stream $Stream
    if ($actual -cne $Expected -or [string]$fileIdentity.volume_serial -cne [string]$Binding.volume_serial -or [string]$fileIdentity.file_index -cne [string]$Binding.file_index) {
        throw 'RedShield config file identity differs from the protected snapshot'
    }
}

function Get-ConfigSourceBinding([string]$Path, [string]$Expected) {
    $stream = Open-ConfigSecurityStream -Path $Path
    try {
        $actual = Get-StreamSHA256 -Stream $stream
        if ($actual -cne $Expected) { throw 'RedShield config hash differs from the approved local file' }
        $fileIdentity = Get-StreamFileIdentity -Stream $stream
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        $sddl = $stream.GetAccessControl().GetSecurityDescriptorSddlForm($sections)
    } finally { $stream.Dispose() }
    return [pscustomobject][ordered]@{
        version = 1
        config_path = $Path
        config_sha256 = $Expected
        volume_serial = $fileIdentity.volume_serial
        file_index = $fileIdentity.file_index
        sddl = $sddl
    }
}

function Assert-ConfigSourceBinding([object]$Binding, [string]$Path, [string]$Expected) {
    if ([int]$Binding.version -ne 1 -or -not [string]::Equals([string]$Binding.config_path, $Path, [StringComparison]::OrdinalIgnoreCase) -or [string]$Binding.config_sha256 -cne $Expected -or [string]$Binding.volume_serial -cnotmatch '^[0-9a-f]{8}$' -or [string]$Binding.file_index -cnotmatch '^[0-9a-f]{16}$') {
        throw 'config ACL snapshot binding differs'
    }
    $current = Get-ConfigSourceBinding -Path $Path -Expected $Expected
    if ([string]$current.volume_serial -cne [string]$Binding.volume_serial -or [string]$current.file_index -cne [string]$Binding.file_index) { throw 'RedShield config file identity differs from the protected snapshot' }
}

function Read-ConfigAclSnapshot([string]$Path, [string]$ConfigPath, [string]$Expected) {
    $text = Read-ExactUTF8File -Path $Path -Label 'config ACL snapshot'
    $snapshot = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    $expectedProperties = @('version', 'config_path', 'config_sha256', 'volume_serial', 'file_index', 'sddl')
    $actualProperties = @($snapshot.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($expectedProperties | Sort-Object) -DifferenceObject $actualProperties).Count -ne 0) { throw 'config ACL snapshot schema differs' }
    Assert-ConfigSourceBinding -Binding $snapshot -Path $ConfigPath -Expected $Expected
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm([string]$snapshot.sddl, $sections)
    return $snapshot
}

function Install-PinnedFile([string]$Source, [string]$Destination, [string]$Expected) {
    Assert-RegularFile -Path $Source -Label 'bootstrap source'
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $actual = Get-StreamSHA256 -Stream $sourceStream
        if ($actual -cne $Expected) { throw 'bootstrap source hash differs from the approved value' }
        if ([IO.File]::Exists($Destination)) {
            if ((Get-ExclusiveFileSHA256 -Path $Destination) -cne $Expected) { throw 'protected destination differs from the approved source' }
            return
        }
        $temporary = $Destination + '.next'
        if ([IO.File]::Exists($temporary)) {
            if ((Get-ExclusiveFileSHA256 -Path $temporary) -cne $Expected) { throw 'protected staging collision differs' }
        } else {
            $sourceStream.Position = 0
            $destinationStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $sourceStream.CopyTo($destinationStream); $destinationStream.Flush($true) } finally { $destinationStream.Dispose() }
        }
        [IO.File]::Move($temporary, $Destination)
    } finally { $sourceStream.Dispose() }
    if ((Get-ExclusiveFileSHA256 -Path $Destination) -cne $Expected) { throw 'protected destination post-check failed' }
}

function Install-PinnedConfig([string]$Source, [string]$Destination, [string]$Expected, [object]$Binding) {
    Assert-RegularFile -Path $Source -Label 'RedShield config source'
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $actual = Get-StreamSHA256 -Stream $sourceStream
        $fileIdentity = Get-StreamFileIdentity -Stream $sourceStream
        if ($actual -cne $Expected -or [string]$fileIdentity.volume_serial -cne [string]$Binding.volume_serial -or [string]$fileIdentity.file_index -cne [string]$Binding.file_index) { throw 'RedShield config differs from the approved bound source' }
        if ([IO.File]::Exists($Destination)) {
            if ((Get-ExclusiveFileSHA256 -Path $Destination) -cne $Expected) { throw 'installed RedShield config differs from the approved source' }
            return
        }
        $temporary = $Destination + '.next'
        if ([IO.File]::Exists($temporary)) {
            if ((Get-ExclusiveFileSHA256 -Path $temporary) -cne $Expected) { throw 'RedShield config staging collision differs' }
        } else {
            $sourceStream.Position = 0
            $destinationStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $sourceStream.CopyTo($destinationStream); $destinationStream.Flush($true) } finally { $destinationStream.Dispose() }
        }
        [IO.File]::Move($temporary, $Destination)
    } finally { $sourceStream.Dispose() }
    if ((Get-ExclusiveFileSHA256 -Path $Destination) -cne $Expected) { throw 'installed RedShield config post-check failed' }
}

function Protect-ConfigSource([string]$Path, [string]$Expected, [object]$Binding) {
    $stream = Open-ConfigSecurityStream -Path $Path
    try {
        Assert-ConfigStreamBinding -Binding $Binding -Stream $stream -Path $Path -Expected $Expected
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($script:CurrentSID)
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($script:CurrentSID, [Security.AccessControl.FileSystemRights]::ReadAndExecute, $allow))
        foreach ($sid in @($script:SystemSID, $script:AdministratorsSID)) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $allow))
        }
        $stream.SetAccessControl($security)
        $acl = $stream.GetAccessControl()
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $script:CurrentSID.Value -or $rules.Count -ne 3) { throw 'RedShield config ACL post-check failed' }
        $seen = @{}
        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            $expectedRights = if ($sid -ceq $script:CurrentSID.Value) { [Security.AccessControl.FileSystemRights]::ReadAndExecute } else { [Security.AccessControl.FileSystemRights]::FullControl }
            if ($rule.IsInherited -or $rule.AccessControlType -ne $allow -or $sid -notin @($script:CurrentSID.Value, $script:SystemSID.Value, $script:AdministratorsSID.Value) -or $rule.FileSystemRights -ne $expectedRights -or $seen.ContainsKey($sid)) { throw 'RedShield config ACL contains an unauthorized ACE' }
            $seen[$sid] = $true
        }
        if (-not $seen.ContainsKey($script:CurrentSID.Value) -or -not $seen.ContainsKey($script:SystemSID.Value) -or -not $seen.ContainsKey($script:AdministratorsSID.Value)) { throw 'RedShield config ACL lacks an authorized ACE' }
        Assert-ConfigStreamBinding -Binding $Binding -Stream $stream -Path $Path -Expected $Expected
    } finally { $stream.Dispose() }
}

function Restore-ConfigSourceACL([string]$Path, [string]$Expected, [object]$Binding) {
    $stream = Open-ConfigSecurityStream -Path $Path
    try {
        Assert-ConfigStreamBinding -Binding $Binding -Stream $stream -Path $Path -Expected $Expected
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        $security = [Security.AccessControl.FileSecurity]::new()
        $security.SetSecurityDescriptorSddlForm([string]$Binding.sddl, $sections)
        $stream.SetAccessControl($security)
        Assert-ConfigStreamBinding -Binding $Binding -Stream $stream -Path $Path -Expected $Expected
        $actual = $stream.GetAccessControl().GetSecurityDescriptorSddlForm($sections)
        if ($actual -cne [string]$Binding.sddl) { throw 'RedShield config ACL restore post-check failed' }
    } finally { $stream.Dispose() }
}

Assert-SHA256 -Value ([string]$request.config_sha256) -Label 'approved config hash'
$configSource = Resolve-LocalCleanPath -Path ([string]$request.config_path) -Label 'RedShield config source'

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($programData)) { throw 'trusted ProgramData known folder is unavailable' }
$parent = [IO.Path]::Combine($programData, 'HomeGateway')
$root = [IO.Path]::Combine($parent, 'P35')
$bin = [IO.Path]::Combine($root, 'bin')
$secrets = [IO.Path]::Combine($root, 'secrets')
$null = Resolve-LocalCleanPath -Path $programData -Label 'ProgramData'
$configAclSnapshot = [IO.Path]::Combine($root, 'config-source-before.v1.json')

if ($action -ceq 'restore-config-acl') {
    Assert-ProtectedDirectory -Path $parent
    Assert-ExactTextFile -Path ([IO.Path]::Combine($parent, $script:ParentMarkerName)) -Text $script:OwnerMarker
    Assert-ProtectedDirectory -Path $root
    Assert-ExactTextFile -Path ([IO.Path]::Combine($root, $script:RootMarkerName)) -Text $script:OwnerMarker
    Assert-ProtectedDirectory -Path $bin
    Assert-ExactTextFile -Path ([IO.Path]::Combine($bin, $script:BinMarkerName)) -Text $script:OwnerMarker
    Assert-ProtectedDirectory -Path $secrets
    Assert-ExactTextFile -Path ([IO.Path]::Combine($secrets, $script:SecretsMarkerName)) -Text $script:OwnerMarker
    $binding = Read-ConfigAclSnapshot -Path $configAclSnapshot -ConfigPath $configSource -Expected ([string]$request.config_sha256)
    Restore-ConfigSourceACL -Path $configSource -Expected ([string]$request.config_sha256) -Binding $binding
    [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject ([pscustomobject][ordered]@{
        version = 1
        ok = $true
        action = 'restore-config-acl'
        root = $root
        config_acl_restored = $true
    })))
    return
}

Assert-SHA256 -Value ([string]$request.launcher_sha256) -Label 'approved launcher hash'
Assert-SHA256 -Value ([string]$request.hgctl_sha256) -Label 'approved hgctl hash'
$launcherSource = Resolve-LocalCleanPath -Path ([string]$request.launcher_path) -Label 'launcher source'
$hgctlSource = Resolve-LocalCleanPath -Path ([string]$request.hgctl_path) -Label 'hgctl source'

Ensure-OwnedProtectedDirectory -Path $parent -MarkerName $script:ParentMarkerName
Ensure-OwnedProtectedDirectory -Path $root -MarkerName $script:RootMarkerName
Ensure-OwnedProtectedDirectory -Path $bin -MarkerName $script:BinMarkerName
Ensure-OwnedProtectedDirectory -Path $secrets -MarkerName $script:SecretsMarkerName
if ([IO.File]::Exists($configAclSnapshot)) {
    $binding = Read-ConfigAclSnapshot -Path $configAclSnapshot -ConfigPath $configSource -Expected ([string]$request.config_sha256)
} else {
    $binding = Get-ConfigSourceBinding -Path $configSource -Expected ([string]$request.config_sha256)
    Ensure-ExactTextFile -Path $configAclSnapshot -Text (ConvertTo-Json -Compress -InputObject $binding)
    $binding = Read-ConfigAclSnapshot -Path $configAclSnapshot -ConfigPath $configSource -Expected ([string]$request.config_sha256)
}

$installedConfig = [IO.Path]::Combine($secrets, 'redshield.conf')
Install-PinnedConfig -Source $configSource -Destination $installedConfig -Expected ([string]$request.config_sha256) -Binding $binding
Ensure-ExactTextFile -Path ([IO.Path]::Combine($secrets, 'redshield.sha256')) -Text ([string]$request.config_sha256)
Protect-ConfigSource -Path $configSource -Expected ([string]$request.config_sha256) -Binding $binding

$installedLauncher = [IO.Path]::Combine($bin, 'p35-canary.ps1')
$installedHgctl = [IO.Path]::Combine($bin, 'hgctl.exe')
Install-PinnedFile -Source $launcherSource -Destination $installedLauncher -Expected ([string]$request.launcher_sha256)
Install-PinnedFile -Source $hgctlSource -Destination $installedHgctl -Expected ([string]$request.hgctl_sha256)
Ensure-ExactTextFile -Path ([IO.Path]::Combine($bin, 'p35-canary.sha256')) -Text ([string]$request.launcher_sha256)
Ensure-ExactTextFile -Path ([IO.Path]::Combine($bin, 'hgctl.sha256')) -Text ([string]$request.hgctl_sha256)
Assert-ProtectedDirectory -Path $parent
Assert-ProtectedDirectory -Path $root
Assert-ProtectedDirectory -Path $bin
Assert-ProtectedDirectory -Path $secrets
Assert-ExactTextFile -Path ([IO.Path]::Combine($parent, $script:ParentMarkerName)) -Text $script:OwnerMarker
Assert-ExactTextFile -Path ([IO.Path]::Combine($root, $script:RootMarkerName)) -Text $script:OwnerMarker
Assert-ExactTextFile -Path ([IO.Path]::Combine($bin, $script:BinMarkerName)) -Text $script:OwnerMarker
Assert-ExactTextFile -Path ([IO.Path]::Combine($secrets, $script:SecretsMarkerName)) -Text $script:OwnerMarker

[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject ([pscustomobject][ordered]@{
    version = 1
    ok = $true
    action = 'install'
    root = $root
    config_acl_hardened = $true
    config_acl_snapshot = $configAclSnapshot
    config_sha256 = [string]$request.config_sha256
    launcher_sha256 = [string]$request.launcher_sha256
    hgctl_sha256 = [string]$request.hgctl_sha256
})))
