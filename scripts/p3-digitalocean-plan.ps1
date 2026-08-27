[CmdletBinding(SupportsShouldProcess = $true)]
param([Parameter(Mandatory)][string]$PublicKeyPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'deploy/digitalocean/p3-droplet.v1.json'
if (-not [IO.Path]::IsPathFullyQualified($PublicKeyPath) -or [IO.Path]::GetExtension($PublicKeyPath) -cne '.pub') { throw 'public key must be an absolute local .pub path' }
if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) { throw 'public key file is unavailable' }
$key = Get-Content -LiteralPath $PublicKeyPath -Raw -Encoding UTF8
if ($key -match '(?i)BEGIN (OPENSSH|RSA|EC|PRIVATE) KEY|private|password|token') { throw 'private-key material is forbidden' }
if ($key.Trim() -notmatch '^ssh-ed25519\s+[A-Za-z0-9+/]+={0,2}(\s+[^\r\n]+)?$') { throw 'public key is not one ssh-ed25519 key' }
$sshKeygen = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path -LiteralPath $sshKeygen -PathType Leaf)) { throw 'trusted System32 OpenSSH key validator is unavailable' }
& $sshKeygen -lf $PublicKeyPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'public key failed trusted OpenSSH validation' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$result = [ordered]@{
    version = 1; mode = 'plan-only'; billable_action_performed = $false
    provider = $manifest.provider; primary_region = $manifest.regions.primary; fallback_region = $manifest.regions.fallback
    image = $manifest.image; size = $manifest.size; ipv6 = $manifest.ipv6; monitoring = $manifest.monitoring
    backups = $manifest.backups; volumes = $manifest.volumes; marketplace_or_one_click = $manifest.marketplace_or_one_click
    ssh_source_prefixes = $manifest.inbound.ssh.source_prefixes; amneziawg_udp_port = $manifest.inbound.amneziawg_udp.observed_port
    manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    public_key_sha256 = (Get-FileHash -LiteralPath $PublicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    public_key_path = '[REDACTED]'
}
$result | ConvertTo-Json -Depth 6 -Compress
