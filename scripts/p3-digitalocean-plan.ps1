[CmdletBinding(SupportsShouldProcess = $true)]
param([string]$PublicKeyPath)

$ErrorActionPreference = 'Stop'
$script:P3DigitalOceanPlanRoot = Split-Path -Parent $PSScriptRoot
$script:P3MaximumPublicKeyBytes = 4096
$script:P3MaximumManifestBytes = 16384
$script:P3DriveFixed = 3

function Test-P3LocalPublicKeyPathSyntax([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0) { return $false }
    $windowsPath = $Path.Replace('/', '\')
    if ($windowsPath -match '^(\\\\|\\\?\?\\|\\Device\\|\\GLOBAL\?\?\\)') { return $false }
    if ($windowsPath -notmatch '^[A-Za-z]:\\') { return $false }
    if ($windowsPath.IndexOf(':', 2) -ge 0) { return $false }
    if ([IO.Path]::GetExtension($windowsPath) -cne '.pub') { return $false }
    return $true
}

function Get-P3CanonicalPublicKeyPath([string]$Path) {
    if (-not (Test-P3LocalPublicKeyPathSyntax $Path)) {
        throw 'public key must be an absolute local .pub path'
    }
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    } catch {
        throw 'public key must be an absolute local .pub path'
    }
    if (-not (Test-P3LocalPublicKeyPathSyntax $fullPath)) {
        throw 'public key must be an absolute local .pub path'
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root) -or (Get-P3DriveType -Root $root) -ne $script:P3DriveFixed) {
        throw 'public key must be on a local fixed drive'
    }
    return $fullPath
}

function Get-P3DriveType([string]$Root) {
    try {
        $drive = New-Object -TypeName IO.DriveInfo -ArgumentList $Root
        return [int]$drive.DriveType
    } catch {
        return 0
    }
}

function Get-P3PathItem([string]$Path) {
    return Get-Item -LiteralPath $Path -Force
}

function Assert-P3NoReparsePath([string]$Path) {
    $root = [IO.Path]::GetPathRoot($Path)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw 'public key file or an ancestor is unavailable'
    }
    $segments = @($Path.Substring($root.Length) -split '[\\/]' | Where-Object { $_ -ne '' })
    $current = $root
    for ($index = -1; $index -lt $segments.Count; $index++) {
        if ($index -ge 0) { $current = Join-Path $current $segments[$index] }
        try {
            $item = Get-P3PathItem -Path $current
        } catch {
            throw 'public key file or an ancestor is unavailable'
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'public key path must not traverse a reparse point'
        }
    }
}

function Read-P3FileBytes([string]$Path) {
    return ,[IO.File]::ReadAllBytes($Path)
}

function Read-P3BoundedFileBytes([string]$Path, [int]$MaximumBytes, [string]$Kind) {
    Assert-P3NoReparsePath $Path
    try {
        $item = Get-Item -LiteralPath $Path -Force
    } catch {
        throw "$Kind file is unavailable"
    }
    if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        throw "$Kind source must be a regular file"
    }
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Kind file is outside the size limit"
    }
    try {
        $bytes = Read-P3FileBytes -Path $Path
    } catch {
        throw "$Kind file cannot be read"
    }
    if ($bytes.Length -le 0 -or $bytes.Length -gt $MaximumBytes) {
        throw "$Kind file is outside the size limit"
    }
    return ,$bytes
}

function ConvertFrom-P3StrictUtf8([byte[]]$Bytes, [string]$Kind) {
    try {
        $encoding = New-Object Text.UTF8Encoding($false, $true)
        return $encoding.GetString($Bytes)
    } catch {
        throw "$Kind file must contain strict UTF-8"
    }
}

function Assert-P3CanonicalPublicKey([string]$Text) {
    if ($Text -match '(?i)BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) KEY|private|password|token') {
        throw 'private, password, and token material is forbidden'
    }
    if ($Text -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [\x21-\x7E]+)?$') {
        throw 'public key must be one canonical ssh-ed25519 line'
    }
}

function Get-P3TrustedSshKeygenPath {
    $windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $path = [IO.Path]::GetFullPath((Join-Path $windowsRoot 'System32\OpenSSH\ssh-keygen.exe'))
    if (-not $path.StartsWith(([IO.Path]::GetFullPath($windowsRoot).TrimEnd('\') + '\System32\OpenSSH\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'trusted System32 OpenSSH path cannot be computed'
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'trusted System32 OpenSSH key validator is unavailable'
    }
    return $path
}

function Invoke-P3NativeSshKeygen([string]$ExecutablePath, [string[]]$Arguments) {
    & $ExecutablePath @Arguments | Out-Null
    return $LASTEXITCODE
}

function Skip-P3JsonWhitespace([string]$Json, [ref]$Index) {
    while ($Index.Value -lt $Json.Length -and [char]::IsWhiteSpace($Json[$Index.Value])) {
        $Index.Value++
    }
}

function Read-P3JsonString([string]$Json, [ref]$Index) {
    if ($Index.Value -ge $Json.Length -or $Json[$Index.Value] -cne '"') {
        throw 'manifest JSON object key is malformed'
    }
    $start = $Index.Value
    $Index.Value++
    while ($Index.Value -lt $Json.Length) {
        $character = $Json[$Index.Value]
        if ($character -ceq '\') {
            $Index.Value += 2
            continue
        }
        $Index.Value++
        if ($character -ceq '"') {
            $token = $Json.Substring($start, $Index.Value - $start)
            try { return ($token | ConvertFrom-Json) } catch { throw 'manifest JSON string is malformed' }
        }
    }
    throw 'manifest JSON string is unterminated'
}

function Read-P3JsonValue([string]$Json, [ref]$Index) {
    Skip-P3JsonWhitespace $Json $Index
    if ($Index.Value -ge $Json.Length) { throw 'manifest JSON value is missing' }
    switch ($Json[$Index.Value]) {
        '{' { Read-P3JsonObject $Json $Index; return }
        '[' { Read-P3JsonArray $Json $Index; return }
        '"' { $null = Read-P3JsonString $Json $Index; return }
    }
    $start = $Index.Value
    while ($Index.Value -lt $Json.Length -and ',]}'.IndexOf($Json[$Index.Value]) -lt 0 -and -not [char]::IsWhiteSpace($Json[$Index.Value])) {
        $Index.Value++
    }
    if ($Index.Value -eq $start) { throw 'manifest JSON value is malformed' }
}

function Read-P3JsonObject([string]$Json, [ref]$Index) {
    $Index.Value++
    $keys = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    Skip-P3JsonWhitespace $Json $Index
    if ($Index.Value -lt $Json.Length -and $Json[$Index.Value] -ceq '}') { $Index.Value++; return }
    while ($true) {
        Skip-P3JsonWhitespace $Json $Index
        $key = Read-P3JsonString $Json $Index
        if (-not $keys.Add($key)) { throw 'manifest contains a duplicate JSON property' }
        Skip-P3JsonWhitespace $Json $Index
        if ($Index.Value -ge $Json.Length -or $Json[$Index.Value] -cne ':') { throw 'manifest JSON property is malformed' }
        $Index.Value++
        Read-P3JsonValue $Json $Index
        Skip-P3JsonWhitespace $Json $Index
        if ($Index.Value -ge $Json.Length) { throw 'manifest JSON object is unterminated' }
        if ($Json[$Index.Value] -ceq '}') { $Index.Value++; return }
        if ($Json[$Index.Value] -cne ',') { throw 'manifest JSON object is malformed' }
        $Index.Value++
    }
}

function Read-P3JsonArray([string]$Json, [ref]$Index) {
    $Index.Value++
    Skip-P3JsonWhitespace $Json $Index
    if ($Index.Value -lt $Json.Length -and $Json[$Index.Value] -ceq ']') { $Index.Value++; return }
    while ($true) {
        Read-P3JsonValue $Json $Index
        Skip-P3JsonWhitespace $Json $Index
        if ($Index.Value -ge $Json.Length) { throw 'manifest JSON array is unterminated' }
        if ($Json[$Index.Value] -ceq ']') { $Index.Value++; return }
        if ($Json[$Index.Value] -cne ',') { throw 'manifest JSON array is malformed' }
        $Index.Value++
    }
}

function Assert-P3NoDuplicateJsonProperties([string]$Json) {
    $index = 0
    Read-P3JsonValue $Json ([ref]$index)
    Skip-P3JsonWhitespace $Json ([ref]$index)
    if ($index -ne $Json.Length) { throw 'manifest JSON has trailing content' }
}

function Assert-P3ExactProperties($Object, [string[]]$Expected, [string]$Context) {
    if ($null -eq $Object -or $Object.GetType() -ne [Management.Automation.PSCustomObject]) {
        throw "manifest $Context must be an object"
    }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    $expectedSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($name in $Expected) { $null = $expectedSet.Add($name) }
    if ($actual.Count -ne $Expected.Count) { throw "manifest $Context property set differs from the approved plan" }
    foreach ($name in $actual) {
        if (-not $expectedSet.Contains($name)) { throw "manifest $Context property set differs from the approved plan" }
    }
}

function Assert-P3JsonType($Value, [Type]$ExpectedType, [string]$Name) {
    if ($null -eq $Value -or $Value.GetType() -ne $ExpectedType) {
        throw "manifest $Name has the wrong JSON primitive type"
    }
}

function Assert-P3JsonInteger($Value, [int]$Expected, [string]$Name) {
    if ($null -eq $Value -or ($Value.GetType() -ne [int] -and $Value.GetType() -ne [long]) -or $Value -ne $Expected) {
        throw "manifest $Name must be the approved JSON integer"
    }
}

function Read-P3ApprovedManifest([string]$ManifestPath) {
    $bytes = Read-P3BoundedFileBytes $ManifestPath $script:P3MaximumManifestBytes 'manifest'
    $raw = ConvertFrom-P3StrictUtf8 $bytes 'manifest'
    Assert-P3NoDuplicateJsonProperties $raw
    try { $manifest = $raw | ConvertFrom-Json } catch { throw 'manifest must be valid JSON' }

    Assert-P3ExactProperties $manifest @('provider', 'regions', 'image', 'size', 'ipv6', 'monitoring', 'backups', 'volumes', 'marketplace_or_one_click', 'api_automation', 'inbound') 'root'
    Assert-P3ExactProperties $manifest.regions @('primary', 'fallback') 'regions'
    Assert-P3ExactProperties $manifest.size @('family', 'vcpu', 'memory_gib', 'disk_gib', 'transfer_gib', 'monthly_label') 'size'
    Assert-P3ExactProperties $manifest.inbound @('ssh', 'amneziawg_udp') 'inbound'
    Assert-P3ExactProperties $manifest.inbound.ssh @('source_prefixes', 'default_routes_forbidden') 'inbound.ssh'
    Assert-P3ExactProperties $manifest.inbound.amneziawg_udp @('observed_port', 'source_prefixes', 'count') 'inbound.amneziawg_udp'

    foreach ($item in @(
        @($manifest.provider, [string], 'provider'), @($manifest.regions.primary, [string], 'regions.primary'),
        @($manifest.regions.fallback, [string], 'regions.fallback'), @($manifest.image, [string], 'image'),
        @($manifest.size.family, [string], 'size.family'), @($manifest.size.monthly_label, [string], 'size.monthly_label'),
        @($manifest.ipv6, [bool], 'ipv6'), @($manifest.monitoring, [bool], 'monitoring'),
        @($manifest.backups, [bool], 'backups'), @($manifest.volumes, [bool], 'volumes'),
        @($manifest.marketplace_or_one_click, [bool], 'marketplace_or_one_click'), @($manifest.api_automation, [bool], 'api_automation'),
        @($manifest.inbound.ssh.source_prefixes, [string], 'inbound.ssh.source_prefixes'),
        @($manifest.inbound.ssh.default_routes_forbidden, [bool], 'inbound.ssh.default_routes_forbidden'),
        @($manifest.inbound.amneziawg_udp.observed_port, [string], 'inbound.amneziawg_udp.observed_port'),
        @($manifest.inbound.amneziawg_udp.source_prefixes, [string], 'inbound.amneziawg_udp.source_prefixes')
    )) { Assert-P3JsonType $item[0] $item[1] $item[2] }
    Assert-P3JsonInteger $manifest.size.vcpu 1 'size.vcpu'
    Assert-P3JsonInteger $manifest.size.memory_gib 1 'size.memory_gib'
    Assert-P3JsonInteger $manifest.size.disk_gib 25 'size.disk_gib'
    Assert-P3JsonInteger $manifest.size.transfer_gib 1000 'size.transfer_gib'
    Assert-P3JsonInteger $manifest.inbound.amneziawg_udp.count 1 'inbound.amneziawg_udp.count'

    if ($manifest.provider -cne 'digitalocean' -or $manifest.regions.primary -cne 'ams3' -or $manifest.regions.fallback -cne 'fra1' -or $manifest.image -cne 'ubuntu-24-04-x64') { throw 'manifest provider, region, or image differs from the approved plan' }
    if ($manifest.size.family -cne 'Basic Regular' -or $manifest.size.monthly_label -cne '$6') { throw 'manifest size baseline differs from the approved plan' }
    if ($manifest.ipv6 -ne $true -or $manifest.monitoring -ne $true -or $manifest.backups -ne $false -or $manifest.volumes -ne $false -or $manifest.marketplace_or_one_click -ne $false -or $manifest.api_automation -ne $false) { throw 'manifest safety switches differ from the approved plan' }
    if ($manifest.inbound.ssh.source_prefixes -cne 'pending-observation' -or $manifest.inbound.ssh.default_routes_forbidden -ne $true -or $manifest.inbound.amneziawg_udp.observed_port -cne 'pending-observation' -or $manifest.inbound.amneziawg_udp.source_prefixes -cne 'pending-observation') { throw 'manifest inbound rules differ from the approved plan' }
    if ($raw -match '(?i)(token|password|secret|private[\s_-]*key)') { throw 'manifest contains forbidden credential markers' }
    return @{ Manifest = $manifest; Bytes = $bytes }
}

function Get-P3SHA256Hex([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha256.ComputeHash($Bytes) } finally { $sha256.Dispose() }
    return ([BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
}

function Invoke-P3DigitalOceanPlan {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$PublicKeyPath)

    $canonicalKeyPath = Get-P3CanonicalPublicKeyPath $PublicKeyPath
    $keyBytes = Read-P3BoundedFileBytes $canonicalKeyPath $script:P3MaximumPublicKeyBytes 'public key'
    $keyText = ConvertFrom-P3StrictUtf8 $keyBytes 'public key'
    Assert-P3CanonicalPublicKey $keyText

    $manifestPath = Join-Path $script:P3DigitalOceanPlanRoot 'deploy/digitalocean/p3-droplet.v1.json'
    $manifestResult = Read-P3ApprovedManifest $manifestPath
    $manifest = $manifestResult.Manifest

    $sshKeygen = Get-P3TrustedSshKeygenPath
    $nativeArguments = @('-lf', $canonicalKeyPath)
    $exitCode = Invoke-P3NativeSshKeygen -ExecutablePath $sshKeygen -Arguments $nativeArguments
    if ($exitCode -ne 0) { throw 'public key failed trusted OpenSSH validation' }

    $result = [ordered]@{
        version = 1; mode = 'plan-only'; billable_action_performed = $false
        provider = $manifest.provider; primary_region = $manifest.regions.primary; fallback_region = $manifest.regions.fallback
        image = $manifest.image; size = $manifest.size; ipv6 = $manifest.ipv6; monitoring = $manifest.monitoring
        backups = $manifest.backups; volumes = $manifest.volumes; marketplace_or_one_click = $manifest.marketplace_or_one_click
        ssh_source_prefixes = $manifest.inbound.ssh.source_prefixes; amneziawg_udp_port = $manifest.inbound.amneziawg_udp.observed_port
        manifest_sha256 = Get-P3SHA256Hex $manifestResult.Bytes
        public_key_sha256 = Get-P3SHA256Hex $keyBytes
        public_key_path = '[REDACTED]'
    }
    return ($result | ConvertTo-Json -Depth 6 -Compress)
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($PublicKeyPath)) { throw 'PublicKeyPath is required' }
    Invoke-P3DigitalOceanPlan -PublicKeyPath $PublicKeyPath -WhatIf:$WhatIfPreference
}
