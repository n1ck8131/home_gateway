BeforeAll {
    $ErrorActionPreference = 'Stop'
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:sourceScript = Join-Path $script:root 'scripts/p3-digitalocean-plan.ps1'
    $script:sourceManifest = Join-Path $script:root 'deploy/digitalocean/p3-droplet.v1.json'
    $script:syntheticPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA synthetic'

function Initialize-P3PlanFixture {
    $script:P3FixtureRoot = Join-Path $TestDrive 'fixture'
    $script:P3FixtureScripts = Join-Path $script:P3FixtureRoot 'scripts'
    $script:P3FixtureDeploy = Join-Path $script:P3FixtureRoot 'deploy/digitalocean'
    New-Item -ItemType Directory -Path $script:P3FixtureScripts -Force | Out-Null
    New-Item -ItemType Directory -Path $script:P3FixtureDeploy -Force | Out-Null
    Copy-Item -LiteralPath $sourceScript -Destination (Join-Path $script:P3FixtureScripts 'p3-digitalocean-plan.ps1')
    Copy-Item -LiteralPath $sourceManifest -Destination (Join-Path $script:P3FixtureDeploy 'p3-droplet.v1.json')
    $script:P3FixtureScript = Join-Path $script:P3FixtureScripts 'p3-digitalocean-plan.ps1'
    $script:P3FixtureManifest = Join-Path $script:P3FixtureDeploy 'p3-droplet.v1.json'
    $script:P3KeyPath = Join-Path $TestDrive 'operator.pub'
    [IO.File]::WriteAllText($script:P3KeyPath, $syntheticPublicKey, [Text.UTF8Encoding]::new($false))
}

function Set-P3ManifestText([string]$Text) {
    [IO.File]::WriteAllText($script:P3FixtureManifest, $Text, [Text.UTF8Encoding]::new($false))
}

function Invoke-P3ManifestMutation([string]$Old, [string]$New) {
    $raw = [IO.File]::ReadAllText($script:P3FixtureManifest, [Text.Encoding]::UTF8)
    $changed = $raw.Replace($Old, $New)
    if ($changed -ceq $raw) { throw "test mutation did not match: $Old" }
    Set-P3ManifestText $changed
}

    Initialize-P3PlanFixture
    . $script:P3FixtureScript
}

Describe 'P3 DigitalOcean plan-only guard' {
    BeforeEach {
        Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
        [IO.File]::WriteAllText($script:P3KeyPath, $syntheticPublicKey, [Text.UTF8Encoding]::new($false))
        Mock Invoke-P3NativeSshKeygen { return 0 }
    }

    It 'dot-sources functions without executing the plan' {
        (Get-Command Invoke-P3DigitalOceanPlan -CommandType Function) | Should -Not -BeNullOrEmpty
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'contains no cloud, browser, provider, network, or remote command boundary' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:P3FixtureScript, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($forbidden in @('doctl', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-Process', 'curl', 'curl.exe', 'wget', 'ssh', 'ssh.exe')) {
            $commands -contains $forbidden | Should -BeFalse
        }
    }

    It 'invokes only absolute System32 ssh-keygen once with -lf and the local public key' {
        $expectedExecutable = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
        $output = Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath
        Should-Invoke Invoke-P3NativeSshKeygen -Times 1 -Exactly -Scope It -ParameterFilter {
            $ExecutablePath -ceq $expectedExecutable -and
            $Arguments.Count -eq 2 -and
            $Arguments[0] -ceq '-lf' -and
            $Arguments[1] -ceq $script:P3KeyPath
        }
        $json = $output | ConvertFrom-Json
        $json.billable_action_performed | Should -BeFalse
        $json.provider | Should -Be 'digitalocean'
        $json.primary_region | Should -Be 'ams3'
        $json.fallback_region | Should -Be 'fra1'
        $json.image | Should -Be 'ubuntu-24-04-x64'
        $json.public_key_path | Should -Be '[REDACTED]'
        $json.public_key_sha256 | Should -Be ((Get-FileHash -LiteralPath $script:P3KeyPath -Algorithm SHA256).Hash.ToLowerInvariant())
        $json.manifest_sha256 | Should -Be ((Get-FileHash -LiteralPath $script:P3FixtureManifest -Algorithm SHA256).Hash.ToLowerInvariant())
        ($output -join '') | Should -Not -Match ([regex]::Escape($script:P3KeyPath))
    }

    It 'emits byte-stable compressed JSON for unchanged inputs' {
        $first = Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath
        $second = Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath
        ($first -join '') | Should -Be ($second -join '')
        ($first -join '') | Should -Not -Match "`r|`n"
        Should-Invoke Invoke-P3NativeSshKeygen -Times 2 -Exactly -Scope It
    }

    It 'rejects unsafe path syntax before native invocation' {
        foreach ($path in @(
            'relative.pub',
            (Join-Path $TestDrive 'not-public.txt'),
            '\\server\share\operator.pub',
            '//server/share/operator.pub',
            '\\?\C:\operator.pub',
            '\??\C:\operator.pub',
            '\\.\C:\operator.pub',
            '\Device\HarddiskVolume1\operator.pub',
            'C:operator.pub',
            'C:\safe\operator.pub:stream',
            'C:\safe:bad\operator.pub'
        )) {
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $path } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects every reparse ancestor and reparse leaf before native invocation' {
        $realDirectory = Join-Path $TestDrive 'real'
        $junctionDirectory = Join-Path $TestDrive 'junction'
        New-Item -ItemType Directory -Path $realDirectory | Out-Null
        $realKey = Join-Path $realDirectory 'operator.pub'
        [IO.File]::WriteAllText($realKey, $syntheticPublicKey, [Text.UTF8Encoding]::new($false))
        New-Item -ItemType Junction -Path $junctionDirectory -Target $realDirectory | Out-Null
        { Invoke-P3DigitalOceanPlan -PublicKeyPath (Join-Path $junctionDirectory 'operator.pub') } | Should -Throw

        $leafTarget = Join-Path $TestDrive 'leaf-target'
        $leafReparse = Join-Path $TestDrive 'leaf.pub'
        New-Item -ItemType Directory -Path $leafTarget | Out-Null
        New-Item -ItemType Junction -Path $leafReparse -Target $leafTarget | Out-Null
        { Invoke-P3DigitalOceanPlan -PublicKeyPath $leafReparse } | Should -Throw
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects unavailable, oversized, non-UTF8, multiline, malformed, and sensitive public-key content' {
        $cases = @(
            @{ Path = (Join-Path $TestDrive 'missing.pub'); Bytes = $null },
            @{ Path = (Join-Path $TestDrive 'oversized.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes(('x' * 4097)) },
            @{ Path = (Join-Path $TestDrive 'non-utf8.pub'); Bytes = [byte[]](0xff, 0xfe, 0xfd) },
            @{ Path = (Join-Path $TestDrive 'multiline.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes($syntheticPublicKey + "`n" + $syntheticPublicKey) },
            @{ Path = (Join-Path $TestDrive 'rsa.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes('ssh-rsa AAAA synthetic') },
            @{ Path = (Join-Path $TestDrive 'private.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes('-----BEGIN OPENSSH PRIVATE KEY-----') },
            @{ Path = (Join-Path $TestDrive 'password.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes($syntheticPublicKey + ' password') },
            @{ Path = (Join-Path $TestDrive 'token.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes($syntheticPublicKey + ' token') },
            @{ Path = (Join-Path $TestDrive 'leading.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes(' ' + $syntheticPublicKey) },
            @{ Path = (Join-Path $TestDrive 'trailing.pub'); Bytes = [Text.Encoding]::UTF8.GetBytes($syntheticPublicKey + ' ') }
        )
        foreach ($case in $cases) {
            if ($null -ne $case.Bytes) { [IO.File]::WriteAllBytes($case.Path, $case.Bytes) }
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $case.Path } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects a failed trusted native key validation' {
        Mock Invoke-P3NativeSshKeygen { return 1 }
        { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        Should-Invoke Invoke-P3NativeSshKeygen -Times 1 -Exactly -Scope It
    }

    It 'rejects unknown properties at every manifest object depth before native invocation' {
        $mutations = @(
            @('{', '{"unknown_root":false,'),
            @('"regions": {', '"regions": { "unknown_regions": false,'),
            @('"size": {', '"size": { "unknown_size": false,'),
            @('"inbound": {', '"inbound": { "unknown_inbound": false,'),
            @('"ssh": {', '"ssh": { "unknown_ssh": false,'),
            @('"amneziawg_udp": {', '"amneziawg_udp": { "unknown_udp": false,')
        )
        foreach ($mutation in $mutations) {
            Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
            Invoke-P3ManifestMutation $mutation[0] $mutation[1]
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects missing properties at every manifest object depth before native invocation' {
        $mutations = @(
            @('  "provider": "digitalocean",', ''),
            @('"primary": "ams3", ', ''),
            @('"family": "Basic Regular", ', ''),
            @('    "ssh": { "source_prefixes": "pending-observation", "default_routes_forbidden": true },', ''),
            @('"source_prefixes": "pending-observation", ', ''),
            @(', "count": 1', '')
        )
        foreach ($mutation in $mutations) {
            Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
            Invoke-P3ManifestMutation $mutation[0] $mutation[1]
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects duplicate properties at every manifest object depth before ConvertFrom-Json collapse' {
        $mutations = @(
            @('{', '{"provider":"digitalocean",'),
            @('"regions": {', '"regions": { "primary": "ams3",'),
            @('"size": {', '"size": { "family": "Basic Regular",'),
            @('"inbound": {', '"inbound": { "ssh": {},'),
            @('"ssh": {', '"ssh": { "source_prefixes": "pending-observation",'),
            @('"amneziawg_udp": {', '"amneziawg_udp": { "count": 1,')
        )
        foreach ($mutation in $mutations) {
            Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
            Invoke-P3ManifestMutation $mutation[0] $mutation[1]
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects wrong JSON primitive types without PowerShell coercion' {
        $mutations = @(
            @('"provider": "digitalocean"', '"provider": true'),
            @('"primary": "ams3"', '"primary": 1'),
            @('"vcpu": 1', '"vcpu": "1"'),
            @('"memory_gib": 1', '"memory_gib": 1.0'),
            @('"ipv6": true', '"ipv6": "true"'),
            @('"backups": false', '"backups": 0'),
            @('"source_prefixes": "pending-observation"', '"source_prefixes": false'),
            @('"default_routes_forbidden": true', '"default_routes_forbidden": "true"'),
            @('"observed_port": "pending-observation"', '"observed_port": 51820'),
            @('"count": 1', '"count": true')
        )
        foreach ($mutation in $mutations) {
            Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
            Invoke-P3ManifestMutation $mutation[0] $mutation[1]
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }

    It 'rejects unsafe defaults and every non-single pending UDP port contract' {
        $mutations = @(
            @('"source_prefixes": "pending-observation"', '"source_prefixes": "0.0.0.0/0"'),
            @('"source_prefixes": "pending-observation"', '"source_prefixes": "::/0"'),
            @('"observed_port": "pending-observation"', '"observed_port": "51820"'),
            @('"count": 1', '"count": 0'),
            @('"count": 1', '"count": 2')
        )
        foreach ($mutation in $mutations) {
            Copy-Item -LiteralPath $sourceManifest -Destination $script:P3FixtureManifest -Force
            Invoke-P3ManifestMutation $mutation[0] $mutation[1]
            { Invoke-P3DigitalOceanPlan -PublicKeyPath $script:P3KeyPath } | Should -Throw
        }
        Should-Invoke Invoke-P3NativeSshKeygen -Times 0 -Exactly -Scope It
    }
}
