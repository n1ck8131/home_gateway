BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Gate = Join-Path $script:Root 'scripts/p3-client-gate.ps1'
}

Describe 'read-only P3 client gate' {
    It 'parses and exposes only read-only observation actions' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Gate, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
        $text = $ast.Extent.Text
        $text | Should -Match "ValidateSet\('Preflight', 'PostConnect', 'PostRollback'\)"
        $text | Should -Match '5\.0\.1\.5'
        $text | Should -Match 'Get-AuthenticodeSignature'
        $text | Should -Match 'ExpectedGuestPeerFingerprintSHA256'
        $text | Should -Match 'ExpectedEgressIdentitySHA256'
        $text | Should -Not -Match 'IdentityAgent=none'
        $text | Should -Not -Match 'Import-Vpn|Connect-Vpn|Disconnect-Vpn|Remove-Vpn|Remove-Net|Set-Net|New-Net|Disable-Net|Enable-Net|Restart-Service|Stop-Service'
    }

    It 'converts synthetic observations to a sanitized schema without raw identities' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Gate, [ref]$tokens, [ref]$errors)
        $definitions = foreach ($name in @('Get-TextSHA256', 'ConvertTo-SanitizedClientRecord')) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            }, $true))
            $definition.Count | Should -Be 1
            $definition[0].Extent.Text
        }
        . ([ScriptBlock]::Create(($definitions -join "`r`n")))
        $raw = [pscustomobject]@{
            profile_sha256 = ('a' * 64); client_sha256 = ('b' * 64); client_version = '5.0.1.5'; signature_valid = $true
            redshield_identity = 'redshield-adapter'; cisco_identity = 'cisco-adapter'; selfhosted_identity = 'selfhosted-adapter'
            route_interface_identity = 'selfhosted-adapter'; peer_fingerprint_sha256 = (Get-TextSHA256 'guest-peer'); handshake_fresh = $true; traffic_delta = $true
            egress_values = @('198.51.100.9', '198.51.100.9', '198.51.100.9')
        }
        $record = ConvertTo-SanitizedClientRecord -Action PostConnect -Observation $raw `
            -ExpectedGuestPeerFingerprintSHA256 (Get-TextSHA256 'guest-peer') -ExpectedEgressIdentitySHA256 (Get-TextSHA256 '198.51.100.9')
        $record.live_mutation_performed | Should -BeFalse
        $record.handshake_fresh | Should -BeTrue
        $record.traffic_delta_observed | Should -BeTrue
        $record.route_matches_selfhosted | Should -BeTrue
        $record.egress_match_count | Should -Be 3
        $json = ConvertTo-Json -Compress -InputObject $record
        $json | Should -Not -Match '198\.51\.100\.9|guest-peer|redshield-adapter|cisco-adapter|selfhosted-adapter'
    }

    It 'accepts PostRollback only with a sanitized proof that the selected profile is absent' {
        $observationPath = Join-Path $TestDrive 'post-rollback.json'
        $observation = [pscustomobject][ordered]@{
            profile_sha256='';profile_absent=$true;client_sha256=('b' * 64);client_version='5.0.1.5';signature_valid=$true
            redshield_identity='redshield';cisco_identity='cisco';selfhosted_identity='';route_interface_identity=''
            peer_fingerprint_sha256='';handshake_fresh=$false;traffic_delta=$false;egress_values=@()
            redshield_equals_pre=$true;cisco_equals_pre=$true
        }
        [IO.File]::WriteAllText($observationPath,(ConvertTo-Json -Compress -InputObject $observation),[Text.UTF8Encoding]::new($false))

        $json = & pwsh.exe -NoLogo -NoProfile -NonInteractive -File $script:Gate -Action PostRollback -ObservationPath $observationPath `
            -ExpectedGuestPeerFingerprintSHA256 ('a' * 64) -ExpectedEgressIdentitySHA256 ('c' * 64) `
            -ExpectedProfileSHA256 ('d' * 64) -ExpectedClientSHA256 ('b' * 64) -ExpectedKnownHostsSHA256 ('e' * 64)
        $LASTEXITCODE | Should -Be 0
        ($json | ConvertFrom-Json).profile_absent | Should -BeTrue
        $observation.profile_absent = $false
        [IO.File]::WriteAllText($observationPath,(ConvertTo-Json -Compress -InputObject $observation),[Text.UTF8Encoding]::new($false))
        { & $script:Gate -Action PostRollback -ObservationPath $observationPath `
            -ExpectedGuestPeerFingerprintSHA256 ('a' * 64) -ExpectedEgressIdentitySHA256 ('c' * 64) `
            -ExpectedProfileSHA256 ('d' * 64) -ExpectedClientSHA256 ('b' * 64) -ExpectedKnownHostsSHA256 ('e' * 64) } | Should -Throw '*post-rollback*'
    }

    It 'fails closed on timed-out or oversized injected SSH process results' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Gate, [ref]$tokens, [ref]$errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-BoundedSshObservation'
        }, $true))
        $definition.Count | Should -Be 1
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
        { Invoke-BoundedSshObservation -Executable 'synthetic-ssh.exe' -Arguments @('arg') -TimeoutSeconds 15 -MaxOutputBytes 1024 `
            -Runner { [pscustomobject]@{ExitCode=-1;TimedOut=$true;StdOut='';StdErr=''} } } | Should -Throw '*timed out*'
        { Invoke-BoundedSshObservation -Executable 'synthetic-ssh.exe' -Arguments @('arg') -TimeoutSeconds 15 -MaxOutputBytes 256 `
            -Runner { [pscustomobject]@{ExitCode=0;TimedOut=$false;StdOut=('x' * 257);StdErr=''} } } | Should -Throw '*output exceeds*'
        $value = Invoke-BoundedSshObservation -Executable 'synthetic-ssh.exe' -Arguments @('arg') -TimeoutSeconds 15 -MaxOutputBytes 1024 `
            -Runner { [pscustomobject]@{ExitCode=0;TimedOut=$false;StdOut='{"selected_peer_fingerprint_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","handshake_fresh":true,"traffic_delta":true}';StdErr=''} }
        $value.handshake_fresh | Should -BeTrue
    }

    It 'requires exact profile, client and known-hosts trust pins before processing an observation' {
        $observationPath = Join-Path $TestDrive 'trust-inputs.json'
        $observation = [pscustomobject][ordered]@{
            profile_sha256=('c' * 64);profile_absent=$false;client_sha256=('d' * 64);client_version='5.0.1.5';signature_valid=$true
            redshield_identity='redshield';cisco_identity='cisco';selfhosted_identity='';route_interface_identity=''
            peer_fingerprint_sha256='';handshake_fresh=$false;traffic_delta=$false;egress_values=@();redshield_equals_pre=$true;cisco_equals_pre=$true
        }
        [IO.File]::WriteAllText($observationPath,(ConvertTo-Json -Compress -InputObject $observation),[Text.UTF8Encoding]::new($false))
        { & $script:Gate -Action Preflight -ObservationPath $observationPath `
            -ExpectedGuestPeerFingerprintSHA256 ('a' * 64) -ExpectedEgressIdentitySHA256 ('b' * 64) } | Should -Throw
    }
}
