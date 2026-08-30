BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Launcher = Join-Path $script:Root 'scripts/p3-amnezia-peer-guard.ps1'
    $script:Payload = Join-Path $script:Root 'scripts/p3-amnezia-peer-guard.py'
}

Describe 'bounded P3 Amnezia peer guard' {
    It 'parses and contains only runtime-injected trust and candidate inputs' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Launcher,[ref]$tokens,[ref]$errors)
        $errors | Should -BeNullOrEmpty
        $text = $ast.Extent.Text
        $text | Should -Match 'gate65-pins\.json'
        $text | Should -Match 'SSH_AUTH_SOCK'
        $text | Should -Match 'StrictHostKeyChecking=yes'
        $text | Should -Match 'IdentitiesOnly=yes'
        $text | Should -Match 'READY_FOR_UI=YES'
        $text | Should -Match 'ValidateOnly'
        $text | Should -Not -Match 'IdentityAgent=none|BEGIN (RSA|OPENSSH|PRIVATE) KEY|ARM|VERIFY'
    }

    It 'ValidateOnly performs payload checks without SSH or mutation' {
        $pins = Join-Path $TestDrive 'gate65-pins.json'
        [IO.File]::WriteAllText($pins,'{"schema":"home-gateway/p3-peer-guard-pins/v1"}',[Text.UTF8Encoding]::new($false))
        & $script:Launcher -ValidateOnly -PinsPath $pins -PythonPath (Get-Command python.exe).Source -PayloadPath $script:Payload
        $LASTEXITCODE | Should -Be 0
    }

    It 'rejects a corrupted transport pin before SSH' {
        $knownHosts = Join-Path $TestDrive 'known_hosts'
        [IO.File]::WriteAllText($knownHosts,'synthetic-host-pin',[Text.Encoding]::ASCII)
        $pins = Join-Path $TestDrive 'gate65-live-pins.json'
        $body = [pscustomobject][ordered]@{
            schema='home-gateway/p3-peer-guard-pins/v1';ssh_host='host.invalid';ssh_user='operator'
            known_hosts_path=$knownHosts;known_hosts_sha256=('0' * 64);current_egress_cidr_sha256=('1' * 64)
            expected_source_prefix_length=32
        }
        [IO.File]::WriteAllText($pins,(ConvertTo-Json -Compress -InputObject $body),[Text.UTF8Encoding]::new($false))
        $previousAgent = $env:SSH_AUTH_SOCK
        try {
            $env:SSH_AUTH_SOCK = 'memory-agent-test-sentinel'
            { & $script:Launcher -PinsPath $pins -PythonPath (Get-Command python.exe).Source -PayloadPath $script:Payload } | Should -Throw '*known-hosts hash differs*'
        } finally { $env:SSH_AUTH_SOCK = $previousAgent }
    }
}
