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
}
