$ErrorActionPreference = 'Stop'

Describe 'read-only P3 client gate v2' {
    BeforeAll {
        $script:Gate = Join-Path $PSScriptRoot '..\..\scripts\p3-client-gate.ps1'
        . $script:Gate

        function New-ClientContext {
            return [pscustomobject]@{
                LauncherPath = Join-Path $PSScriptRoot '..\..\scripts\p3-amnezia-peer-guard.ps1'
                RuntimeRoot = Join-Path $TestDrive 'runtime'
                ExpectedManifestSHA256 = ('1' * 64)
                PayloadSHA256 = ('2' * 64)
                ProtocolSHA256 = ('3' * 64)
                SelectedGuestFingerprintSHA256 = ('4' * 64)
                PreviousNonceSHA256 = ('5' * 64)
                ExpectedBeforeCounterSHA256 = ('6' * 64)
                ExpectedAfterCounterSHA256 = ('7' * 64)
            }
        }

        function New-ClientReceipt([object]$Context, [string]$Nonce) {
            return [ordered]@{
                schema = 'home-gateway/p3-peer-client-observe/v2'; payload_sha256 = $Context.PayloadSHA256
                protocol_sha256 = $Context.ProtocolSHA256; nonce_sha256 = Get-P3ClientTextSHA256 $Nonce
                selected_guest_match = $true; handshake_fresh = $true
                before_counter_sha256 = $Context.ExpectedBeforeCounterSHA256
                after_counter_sha256 = $Context.ExpectedAfterCounterSHA256
                traffic_delta = $true; observation_duration_seconds = 10
            }
        }

        function New-FixtureObservation {
            return [ordered]@{
                schema = 'home-gateway/p3-client-local-observation/v2'
                profile_sha256 = ('8' * 64); profile_absent = $false; client_sha256 = ('9' * 64)
                client_version_match = $true; signature_valid = $true
                redshield_class_sha256 = ('a' * 64); redshield_class_count = 1
                cisco_class_sha256 = ('b' * 64); cisco_class_count = 0
                selfhosted_adapter_count = 1; selfhosted_class_sha256 = ('c' * 64)
                route_matches_selfhosted = $true; egress_identity_sha256 = ('d' * 64); egress_observation_count = 3
                observed_at_utc = [DateTime]::UtcNow.ToString('o'); live_mutation_performed = $false
            }
        }
    }

    BeforeEach {
        $script:Context = New-ClientContext
        $script:FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:FixtureRoot
        $script:Fixture = Join-Path $script:FixtureRoot 'observation.json'
        [IO.File]::WriteAllText($script:Fixture, (New-FixtureObservation | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    }

    It 'rejects synthetic observation input outside explicit test mode for every action' {
        foreach ($action in @('Preflight', 'PostConnect', 'PostRollback')) {
            { Read-P3ClientObservation -Action $action -ObservationPath $script:Fixture -TestOnlyFixture:$false -TestFixtureRoot $script:FixtureRoot } |
                Should -Throw '*test-only*'
        }
    }

    It 'accepts fixtures only with explicit test mode under the injected root' {
        $value = Read-P3ClientObservation -Action Preflight -ObservationPath $script:Fixture -TestOnlyFixture -TestFixtureRoot $script:FixtureRoot
        $value.schema | Should -BeExactly 'home-gateway/p3-client-local-observation/v2'
        $outside = Join-Path $TestDrive 'outside.json'
        [IO.File]::WriteAllText($outside, '{}')
        { Read-P3ClientObservation -Action Preflight -ObservationPath $outside -TestOnlyFixture -TestFixtureRoot $script:FixtureRoot } |
            Should -Throw '*fixture root*'
        { Read-P3ClientObservation -Action Preflight -ObservationPath '' -TestOnlyFixture -TestFixtureRoot $script:FixtureRoot } |
            Should -Throw '*requires ObservationPath*'
    }

    It 'binds client observation to one fresh nonce through the fixed guard launcher' {
        $nonce = 'a' * 64
        $script:Calls = 0
        $receipt = Invoke-P3ClientPeerObservation -Context $script:Context -Nonce $nonce -Runner {
            param($Executable, $Arguments, $InputJson, $TimeoutSeconds, $MaximumBytes)
            $script:Calls++
            $Arguments | Should -Contain '-Action'
            $Arguments | Should -Contain 'ClientObserve'
            $Arguments | Should -Not -Contain '/usr/local/libexec/home-gateway-p3-peer-observe'
            $request = $InputJson | ConvertFrom-Json
            $request.selected_guest_fingerprint_sha256 | Should -BeExactly $script:Context.SelectedGuestFingerprintSHA256
            [pscustomobject]@{
                ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''
                StdOut = (New-ClientReceipt $script:Context $nonce | ConvertTo-Json -Compress)
            }
        }
        $receipt.nonce_sha256 | Should -BeExactly (Get-P3ClientTextSHA256 $nonce)
        $receipt.traffic_delta | Should -BeTrue
        $script:Calls | Should -Be 1
    }

    It 'rejects wrong replayed stale mismatched no-delta and extra client receipts' {
        $nonce = 'a' * 64
        $base = New-ClientReceipt $script:Context $nonce
        $cases = @(
            @{ Name = 'nonce'; Change = { param($r) $r.nonce_sha256 = ('0' * 64) } },
            @{ Name = 'payload'; Change = { param($r) $r.payload_sha256 = ('0' * 64) } },
            @{ Name = 'protocol'; Change = { param($r) $r.protocol_sha256 = ('0' * 64) } },
            @{ Name = 'selected Guest'; Change = { param($r) $r.selected_guest_match = $false } },
            @{ Name = 'handshake'; Change = { param($r) $r.handshake_fresh = $false } },
            @{ Name = 'before counter'; Change = { param($r) $r.before_counter_sha256 = ('0' * 64) } },
            @{ Name = 'after counter'; Change = { param($r) $r.after_counter_sha256 = ('0' * 64) } },
            @{ Name = 'traffic'; Change = { param($r) $r.traffic_delta = $false } },
            @{ Name = 'duration'; Change = { param($r) $r.observation_duration_seconds = 181 } },
            @{ Name = 'schema'; Change = { param($r) $r.extra = $true } }
        )
        foreach ($case in $cases) {
            $receipt = [ordered]@{}; foreach ($key in $base.Keys) { $receipt[$key] = $base[$key] }
            & $case.Change $receipt
            $script:BadReceipt = $receipt
            { Invoke-P3ClientPeerObservation -Context $script:Context -Nonce $nonce -Runner {
                [pscustomobject]@{ ExitCode = 0; TimedOut = $false; Oversized = $false; StdErr = ''; StdOut = ($script:BadReceipt | ConvertTo-Json -Compress) }
            } } | Should -Throw "*$($case.Name)*"
        }
        $script:Context.PreviousNonceSHA256 = Get-P3ClientTextSHA256 $nonce
        $calls = 0
        { Invoke-P3ClientPeerObservation -Context $script:Context -Nonce $nonce -Runner { $calls++ } } | Should -Throw '*replayed*'
        $calls | Should -Be 0
    }

    It 'writes PRE preservation classes and computes later equality itself' {
        $pre = New-P3ClientPreReceipt -Observation ([pscustomobject](New-FixtureObservation)) -NowUtc ([DateTime]::UtcNow)
        $pre.schema | Should -BeExactly 'home-gateway/p3-client-pre-receipt/v2'
        $same = Test-P3ClientPreservation -PreReceipt $pre -Observation ([pscustomobject](New-FixtureObservation)) -NowUtc ([DateTime]::UtcNow)
        $same.redshield_equals_pre | Should -BeTrue
        $same.cisco_equals_pre | Should -BeTrue
        $changed = [pscustomobject](New-FixtureObservation)
        $changed.redshield_class_sha256 = ('0' * 64)
        { Test-P3ClientPreservation -PreReceipt $pre -Observation $changed -NowUtc ([DateTime]::UtcNow) } |
            Should -Throw '*RedShield*'
    }

    It 'returns a sanitized action record without raw adapter profile or host values' {
        $observation = [pscustomobject](New-FixtureObservation)
        $record = ConvertTo-P3ClientRecord -Action PostConnect -Observation $observation -ClientReceipt ([pscustomobject](New-ClientReceipt $script:Context ('a' * 64)))
        $record.schema | Should -BeExactly 'home-gateway/p3-client-gate/v2'
        $record.live_mutation_performed | Should -BeFalse
        $json = $record | ConvertTo-Json -Compress
        $json | Should -Not -Match 'ssh_host|adapter_name|profile_path|raw'
    }

    It 'contains no second observer synthetic production bypass or network mutation command' {
        $text = Get-Content -LiteralPath $script:Gate -Raw
        $text | Should -Not -Match 'home-gateway-p3-peer-observe|System32.{1,4}OpenSSH|Import-Vpn|Connect-Vpn|Disconnect-Vpn|Remove-Vpn|Remove-Net|Set-Net|New-Net|Disable-Net|Enable-Net|Restart-Service|Stop-Service'
        $text | Should -Match 'p3-amnezia-peer-guard\.ps1'
        $text | Should -Match 'TestOnlyFixture'
    }
}
