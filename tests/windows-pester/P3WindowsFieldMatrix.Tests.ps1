BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Matrix = Join-Path $script:Root 'scripts/p3-windows-field-matrix.ps1'
}

Describe 'bounded P3 Windows field matrix' {
    It 'parses with the exact action set and contains no native mutation command' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Matrix,[ref]$tokens,[ref]$errors)
        $errors | Should -BeNullOrEmpty
        $text = $ast.Extent.Text
        foreach ($action in @('PreApply','PendingQuickCheck','CommittedMatrix','TunnelDown','ProcessRecovery','AdapterLoss','RebootRecovery','RollbackVerify')) { $text | Should -Match $action }
        $text | Should -Match 'MaxDurationSeconds'
        $text | Should -Match '^[\s\S]*schema'
        $text | Should -Not -Match 'New-Net|Set-Net|Remove-Net|Disable-Net|Enable-Net|Restart-Service|Stop-Service|Start-Process|shutdown|Restart-Computer|AmneziaVPN'
    }

    It 'converts complete synthetic observations to sanitized hashes and booleans' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Matrix,[ref]$tokens,[ref]$errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-FieldMatrixRecord'
        },$true))
        $definition.Count | Should -Be 1
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
        $observation = [pscustomobject]@{
            target_identities=@('target-one','target-two'); direct_egress_identity='direct-egress'; selfhosted_egress_identity='self-egress'; cisco_egress_identity='cisco-egress'
            dns_ok=$true; ipv4_ok=$true; ipv6_ok=$true; mtu_ok=$true; tcp_ok=$true; udp_ok=$true; quic_ok=$true
            tunnel_down_blocked=$true; process_recovered=$true; adapter_loss_blocked=$true; reboot_recovered=$true; emergency_disabled=$true
            redshield_equals_pre=$true;cisco_equals_pre=$true;selfhosted_absent=$true;elapsed_seconds=20
        }
        $record = ConvertTo-FieldMatrixRecord -Action CommittedMatrix -Observation $observation -MaxDurationSeconds 90
        $record.target_count | Should -Be 2
        $record.transport_pass_count | Should -Be 3
        $record.live_mutation_performed | Should -BeFalse
        $json = ConvertTo-Json -Compress -InputObject $record
        $json | Should -Not -Match 'target-one|target-two|direct-egress|self-egress|cisco-egress'
    }

    It 'fails closed on incomplete quick checks or unsafe timeout bounds' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Matrix,[ref]$tokens,[ref]$errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-FieldMatrixRecord'
        },$true))
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
        $observation = [pscustomobject]@{target_identities=@('one');dns_ok=$true;ipv4_ok=$true;ipv6_ok=$true;mtu_ok=$true;tcp_ok=$true;udp_ok=$false;quic_ok=$true;elapsed_seconds=20}
        { ConvertTo-FieldMatrixRecord -Action PendingQuickCheck -Observation $observation -MaxDurationSeconds 90 } | Should -Throw '*failed*'
        { ConvertTo-FieldMatrixRecord -Action PendingQuickCheck -Observation $observation -MaxDurationSeconds 120 } | Should -Throw '*safety margin*'
    }

    It 'emits a fresh candidate/root/deadline-bound PendingQuickCheck record' {
        $observationPath = Join-Path $TestDrive 'pending-observation.json'
        $observation = [pscustomobject][ordered]@{
            target_identities=@('target-one'); direct_egress_identity=''; selfhosted_egress_identity='self'; cisco_egress_identity=''
            dns_ok=$true; ipv4_ok=$true; ipv6_ok=$true; mtu_ok=$true; tcp_ok=$true; udp_ok=$true; quic_ok=$true
            tunnel_down_blocked=$false; process_recovered=$false; adapter_loss_blocked=$false; reboot_recovered=$false; emergency_disabled=$false
            emergency_disable_required=$false; redshield_equals_pre=$true; cisco_equals_pre=$true; selfhosted_absent=$false; elapsed_seconds=20
        }
        [IO.File]::WriteAllText($observationPath,(ConvertTo-Json -Compress -InputObject $observation),[Text.UTF8Encoding]::new($false))
        $candidate = 'a' * 64
        $rootIdentity = 'b' * 64
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(100).ToString('O')

        $json = & pwsh.exe -NoLogo -NoProfile -NonInteractive -File $script:Matrix -Action PendingQuickCheck `
            -ObservationPath $observationPath -MaxDurationSeconds 90 -CandidateSHA256 $candidate `
            -StateRootIdentity $rootIdentity -PendingDeadlineUtc $deadline
        $LASTEXITCODE | Should -Be 0

        $record = $json | ConvertFrom-Json
        $record.action | Should -Be 'pendingquickcheck'
        $record.candidate_sha256 | Should -BeExactly $candidate
        $record.state_root_identity | Should -BeExactly $rootIdentity
        ([DateTimeOffset]$record.pending_deadline_utc).ToUniversalTime() | Should -Be ([DateTimeOffset]::Parse($deadline)).ToUniversalTime()
        ([DateTimeOffset]$record.created_utc) | Should -BeLessThan ([DateTimeOffset]::UtcNow.AddSeconds(2))
    }

    It 'requires emergency-disable evidence only when that rollback path was used' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Matrix,[ref]$tokens,[ref]$errors)
        $definition = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-FieldMatrixRecord'
        },$true))
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
        $observation = [pscustomobject]@{
            target_identities=@('one'); direct_egress_identity=''; selfhosted_egress_identity=''; cisco_egress_identity=''
            dns_ok=$false;ipv4_ok=$false;ipv6_ok=$false;mtu_ok=$false;tcp_ok=$false;udp_ok=$false;quic_ok=$false
            tunnel_down_blocked=$false;process_recovered=$false;adapter_loss_blocked=$false;reboot_recovered=$false
            emergency_disable_required=$false;emergency_disabled=$false;redshield_equals_pre=$true;cisco_equals_pre=$true;selfhosted_absent=$true;elapsed_seconds=1
        }
        (ConvertTo-FieldMatrixRecord -Action RollbackVerify -Observation $observation -MaxDurationSeconds 90).action | Should -Be 'rollbackverify'
        $observation.emergency_disable_required = $true
        { ConvertTo-FieldMatrixRecord -Action RollbackVerify -Observation $observation -MaxDurationSeconds 90 } | Should -Throw '*failed*'
    }
}
