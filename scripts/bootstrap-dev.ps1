param(
    [Parameter()][switch]$WhatIf,
    [Parameter()][switch]$IncludePowerShell
)

$ErrorActionPreference = 'Stop'
$script:RepositoryRoot = Split-Path -Parent $PSScriptRoot

function Test-WindowsPlatform {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Invoke-CurlDownload {
    param(
        [Parameter(Mandatory)][string]$CurlPath,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Partial
    )
    $arguments = @(
        '--fail',
        '--location',
        '--continue-at', '-',
        '--retry', '3',
        '--retry-all-errors',
        '--connect-timeout', '30',
        '--max-time', '900',
        '--proto', '=https',
        '--tlsv1.2',
        $Uri,
        '--output', $Partial
    )
    & $CurlPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "curl download failed for $Uri with exit code $LASTEXITCODE"
    }
}

function Invoke-ArtifactDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Partial
    )
    $curlName = if (Test-WindowsPlatform) { 'curl.exe' } else { 'curl' }
    $curl = Get-Command -Name $curlName -ErrorAction SilentlyContinue
    if ($curl) {
        $curlPath = if ($curl.Path) { $curl.Path } elseif ($curl.Source) { $curl.Source } else { $curl.Definition }
        Invoke-CurlDownload -CurlPath $curlPath -Uri $Uri -Partial $Partial
        return
    }
    if ((Test-Path -LiteralPath $Partial) -and (Get-Item -LiteralPath $Partial).Length -ne 0) {
        throw "Partial download requires curl resume support: $Partial"
    }
    foreach ($attempt in 1..2) {
        try {
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 900 -Uri $Uri -OutFile $Partial
            return
        } catch {
            if ($attempt -eq 2) {
                throw
            }
            Remove-Item -LiteralPath $Partial -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
}

function Get-VerifiedArtifact {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Artifact,
        [Parameter(Mandatory)][string]$DownloadDirectory
    )
    $final = Join-Path $DownloadDirectory $Name
    $partial = "$final.partial"
    New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null
    if (-not (Test-Path -LiteralPath $final)) {
        Invoke-ArtifactDownload -Uri $Artifact.url -Partial $partial
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $partial).Hash.ToLowerInvariant()
        if ($actual -ne $Artifact.sha256) {
            Remove-Item -LiteralPath $partial -Force
            throw "SHA256 mismatch for $Name"
        }
        Move-Item -LiteralPath $partial -Destination $final
    }
    $installed = (Get-FileHash -Algorithm SHA256 -LiteralPath $final).Hash.ToLowerInvariant()
    if ($installed -ne $Artifact.sha256) {
        throw "Cached SHA256 mismatch for $Name"
    }
    return $final
}

function Get-PlatformArtifactNames {
    param(
        [Parameter(Mandatory)][ValidateSet('windows_amd64', 'linux_amd64')][string]$Platform,
        [Parameter()][switch]$IncludePowerShell
    )
    $items = @(
        [pscustomobject]@{ Component = 'go'; ArtifactKey = "go_$Platform" },
        [pscustomobject]@{ Component = 'pester'; ArtifactKey = 'pester' },
        [pscustomobject]@{ Component = 'gitleaks'; ArtifactKey = "gitleaks_$Platform" },
        [pscustomobject]@{ Component = 'actionlint'; ArtifactKey = "actionlint_$Platform" }
    )
    if ($Platform -eq 'linux_amd64') {
        $items += [pscustomobject]@{ Component = 'shellcheck'; ArtifactKey = 'shellcheck_linux_amd64' }
    }
    if ($IncludePowerShell) {
        $items += [pscustomobject]@{ Component = 'powershell'; ArtifactKey = "powershell_$Platform" }
    }
    return $items
}

function Get-ArtifactFilename {
    param([Parameter(Mandatory)]$Artifact)
    if ($Artifact.filename) {
        return [string]$Artifact.filename
    }
    return [Uri]::UnescapeDataString(([Uri]$Artifact.url).Segments[-1])
}

function Expand-ToolArchive {
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Component
    )
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    if ($Component -eq 'pester') {
        $zipPath = Join-Path (Split-Path -Parent $Destination) 'Pester.6.0.0.zip'
        Copy-Item -LiteralPath $Archive -Destination $zipPath -Force
        try {
            Expand-Archive -LiteralPath $zipPath -DestinationPath $Destination -Force
        } finally {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
        }
        return
    }
    if ($Archive -match '\.zip$') {
        Expand-Archive -LiteralPath $Archive -DestinationPath $Destination -Force
        return
    }
    & tar -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "tar extraction failed for $Archive with exit code $LASTEXITCODE"
    }
}

function Move-InstalledDirectory {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    Move-Item -LiteralPath $Source -Destination $Destination
}

function Install-ToolComponent {
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$WindowsPlatform
    )
    $tools = Join-Path $Root '.tools'
    $staging = Join-Path $tools (".staging-$Component-$([guid]::NewGuid().ToString('N'))")
    $payload = Join-Path $staging 'payload'
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    try {
        Expand-ToolArchive -Archive $Archive -Destination $payload -Component $Component
        switch ($Component) {
            'go' {
                $source = Join-Path $payload 'go'
                if (-not (Test-Path -LiteralPath $source)) {
                    throw 'Go archive does not contain go directory'
                }
                Move-InstalledDirectory -Source $source -Destination (Join-Path $tools 'go')
            }
            'pester' {
                $manifest = Join-Path $payload 'Pester.psd1'
                if (-not (Test-Path -LiteralPath $manifest)) {
                    throw 'Pester archive does not contain Pester.psd1'
                }
                Move-InstalledDirectory -Source $payload -Destination (Join-Path $tools 'modules/Pester/6.0.0')
            }
            'powershell' {
                Move-InstalledDirectory -Source $payload -Destination (Join-Path $tools 'pwsh')
            }
            default {
                $suffix = if ($WindowsPlatform) { '.exe' } else { '' }
                $expectedName = "$Component$suffix"
                $binary = Get-ChildItem -LiteralPath $payload -Recurse -File | Where-Object {
                    $_.Name -eq $expectedName
                } | Select-Object -First 1
                if (-not $binary) {
                    throw "$Component archive does not contain $expectedName"
                }
                $binDirectory = Join-Path $tools 'bin'
                New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null
                Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $binDirectory $expectedName) -Force
                if (-not $WindowsPlatform) {
                    & chmod +x (Join-Path $binDirectory $expectedName)
                    if ($LASTEXITCODE -ne 0) {
                        throw "chmod failed for $expectedName"
                    }
                }
            }
        }
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-ToolVersionArguments {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('gitleaks', 'actionlint', 'shellcheck')]
        [string]$Component
    )
    switch ($Component) {
        'actionlint' { return '-version' }
        'shellcheck' { return '--version' }
        default { return 'version' }
    }
}

function Test-InstalledComponent {
    param(
        [Parameter(Mandatory)][string]$Component,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$WindowsPlatform
    )
    $suffix = if ($WindowsPlatform) { '.exe' } else { '' }
    try {
        switch ($Component) {
            'go' {
                $path = Join-Path $Root ".tools/go/bin/go$suffix"
                if (-not (Test-Path -LiteralPath $path)) { return $false }
                $output = @(& $path version 2>&1)
                return $LASTEXITCODE -eq 0 -and ($output -join ' ') -match '\bgo1\.26\.6\b'
            }
            'pester' {
                $path = Join-Path $Root '.tools/modules/Pester/6.0.0/Pester.psd1'
                if (-not (Test-Path -LiteralPath $path)) { return $false }
                Import-Module $path -Force
                return (Get-Module Pester).Version.ToString() -eq '6.0.0'
            }
            'powershell' {
                $path = Join-Path $Root ".tools/pwsh/pwsh$suffix"
                if (-not (Test-Path -LiteralPath $path)) { return $false }
                $output = @(& $path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1)
                return $LASTEXITCODE -eq 0 -and ($output -join ' ').Trim() -eq '7.6.2'
            }
            default {
                $path = Join-Path $Root ".tools/bin/$Component$suffix"
                if (-not (Test-Path -LiteralPath $path)) { return $false }
                [string[]]$arguments = Get-ToolVersionArguments -Component $Component
                $output = @(& $path @arguments 2>&1)
                if ($LASTEXITCODE -ne 0) { return $false }
                $expected = switch ($Component) {
                    'gitleaks' { '8.30.1' }
                    'actionlint' { '1.7.12' }
                    'shellcheck' { '0.11.0' }
                }
                $pattern = [regex]::Escape($expected)
                return ($output -join ' ') -match $pattern
            }
        }
    } catch {
        return $false
    }
}

function Assert-BootstrapVersions {
    param(
        [Parameter(Mandatory)][object[]]$Selections,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][bool]$WindowsPlatform
    )
    foreach ($selection in $Selections) {
        if (-not (Test-InstalledComponent -Component $selection.Component -Root $Root -WindowsPlatform $WindowsPlatform)) {
            throw "Installed version check failed for $($selection.Component)"
        }
    }
    $env:GOTOOLCHAIN = 'local'
    $goSuffix = if ($WindowsPlatform) { '.exe' } else { '' }
    $go = Join-Path $Root ".tools/go/bin/go$goSuffix"
    $goOutput = @(& $go version 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($goOutput -join ' ') -notmatch '\bgo1\.26\.6\b') {
        throw 'Pinned Go version is not go1.26.6'
    }
    $pesterPath = Join-Path $Root '.tools/modules/Pester/6.0.0/Pester.psd1'
    Import-Module $pesterPath -Force
    if ((Get-Module Pester).Version.ToString() -ne '6.0.0') {
        throw 'Pinned Pester version is not 6.0.0'
    }
}

function Invoke-Bootstrap {
    param(
        [Parameter()][string]$Root = $script:RepositoryRoot,
        [Parameter()][switch]$WhatIf,
        [Parameter()][switch]$IncludePowerShell
    )
    $Root = [System.IO.Path]::GetFullPath($Root)
    $lockPath = Join-Path $Root 'manifest/versions.lock.yaml'
    if (-not (Test-Path -LiteralPath $lockPath)) {
        throw 'versions lock missing'
    }
    $lock = (Get-Content -LiteralPath $lockPath -Raw) | ConvertFrom-Json
    $windowsPlatform = Test-WindowsPlatform
    $platform = if ($windowsPlatform) { 'windows_amd64' } else { 'linux_amd64' }
    $selections = @(Get-PlatformArtifactNames -Platform $platform -IncludePowerShell:$IncludePowerShell)
    if ($WhatIf) {
        foreach ($selection in $selections) {
            "WOULD_INSTALL $($selection.ArtifactKey)"
        }
        return
    }
    if ($windowsPlatform) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    $downloadDirectory = Join-Path $Root '.cache/downloads'
    foreach ($selection in $selections) {
        if (Test-InstalledComponent -Component $selection.Component -Root $Root -WindowsPlatform $windowsPlatform) {
            continue
        }
        $artifactProperty = $lock.artifacts.PSObject.Properties[$selection.ArtifactKey]
        if (-not $artifactProperty) {
            throw "Artifact missing from lock: $($selection.ArtifactKey)"
        }
        $artifact = $artifactProperty.Value
        $filename = Get-ArtifactFilename -Artifact $artifact
        $archive = Get-VerifiedArtifact -Name $filename -Artifact $artifact -DownloadDirectory $downloadDirectory
        Install-ToolComponent -Component $selection.Component -Archive $archive -Root $Root -WindowsPlatform $windowsPlatform
    }
    Assert-BootstrapVersions -Selections $selections -Root $Root -WindowsPlatform $windowsPlatform
    'BOOTSTRAP_DEV_PASS'
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Bootstrap -Root $script:RepositoryRoot -WhatIf:$WhatIf -IncludePowerShell:$IncludePowerShell
}
