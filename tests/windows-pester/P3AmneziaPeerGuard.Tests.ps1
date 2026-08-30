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
        $body = [pscustomobject][ordered]@{schema='home-gateway/p3-peer-guard-pins/v1';local_payload_sha256=(Get-FileHash -LiteralPath $script:Payload -Algorithm SHA256).Hash.ToLowerInvariant()}
        [IO.File]::WriteAllText($pins,(ConvertTo-Json -Compress -InputObject $body),[Text.UTF8Encoding]::new($false))
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
            expected_source_prefix_length=32;local_payload_sha256=(Get-FileHash -LiteralPath $script:Payload -Algorithm SHA256).Hash.ToLowerInvariant()
            remote_payload_sha256=('2' * 64);remote_protocol_sha256=('3' * 64)
            egress_https_endpoints=@('https://one.invalid','https://two.invalid','https://three.invalid')
        }
        [IO.File]::WriteAllText($pins,(ConvertTo-Json -Compress -InputObject $body),[Text.UTF8Encoding]::new($false))
        $previousAgent = $env:SSH_AUTH_SOCK
        try {
            $env:SSH_AUTH_SOCK = 'memory-agent-test-sentinel'
            { & $script:Launcher -PinsPath $pins -PythonPath (Get-Command python.exe).Source -PayloadPath $script:Payload } | Should -Throw '*known-hosts hash differs*'
        } finally { $env:SSH_AUTH_SOCK = $previousAgent }
    }

    It 'verifies bounded current egress and remote payload/protocol identity through injected runners' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Launcher,[ref]$tokens,[ref]$errors)
        $definitions = foreach ($name in @('Get-TextSHA256','Test-CurrentEgress','Invoke-BoundedPeerGuard')) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            },$true))
            $definition.Count | Should -Be 1
            $definition[0].Extent.Text
        }
        . ([ScriptBlock]::Create(($definitions -join "`r`n")))
        $expectedCIDR = Get-TextSHA256 '198.51.100.7/32'
        (Test-CurrentEgress -Endpoints @('https://one.invalid','https://two.invalid','https://three.invalid') `
            -ExpectedCIDRSHA256 $expectedCIDR -Runner { param($endpoint) '198.51.100.7' }) | Should -BeExactly $expectedCIDR
        { Test-CurrentEgress -Endpoints @('https://one.invalid','https://two.invalid','https://three.invalid') `
            -ExpectedCIDRSHA256 $expectedCIDR -Runner { param($endpoint) if ($endpoint -match 'two') {'198.51.100.8'} else {'198.51.100.7'} } } | Should -Throw '*consensus*'

        $payloadHash = 'a' * 64
        $protocolHash = 'b' * 64
        $result = Invoke-BoundedPeerGuard -Executable 'synthetic-ssh.exe' -Arguments @('arg') -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 20 -MaxOutputBytes 1024 -Runner {
                [pscustomobject]@{ExitCode=0;TimedOut=$false;StdOut=(ConvertTo-Json -Compress -InputObject ([pscustomobject]@{payload_sha256=('a' * 64);protocol_sha256=('b' * 64);ready_for_ui=$true}));StdErr=''}
            }
        $result.ready_for_ui | Should -BeTrue
        { Invoke-BoundedPeerGuard -Executable 'synthetic-ssh.exe' -Arguments @('arg') -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 20 -MaxOutputBytes 1024 -Runner { [pscustomobject]@{ExitCode=-1;TimedOut=$true;StdOut='';StdErr=''} } } | Should -Throw '*timed out*'
        { Invoke-BoundedPeerGuard -Executable 'synthetic-ssh.exe' -Arguments @('arg') -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 20 -MaxOutputBytes 256 -Runner { [pscustomobject]@{ExitCode=0;TimedOut=$false;StdOut=('x' * 257);StdErr=''} } } | Should -Throw '*output exceeds*'
        { Invoke-BoundedPeerGuard -Executable 'synthetic-ssh.exe' -Arguments @('arg') -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 20 -MaxOutputBytes 1024 -Runner { [pscustomobject]@{ExitCode=0;TimedOut=$false;StdOut='{"payload_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","protocol_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ready_for_ui":true}';StdErr=''} } } | Should -Throw '*payload identity*'
    }

    It 'executes the tracked Python automatic attestation protocol and rejects incompatible process output' {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($script:Launcher,[ref]$tokens,[ref]$errors)
        $definitions = foreach ($name in @('Invoke-BoundedNativeProcess','Invoke-BoundedPeerGuard')) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
            },$true))
            $definition.Count | Should -Be 1
            $definition[0].Extent.Text
        }
        . ([ScriptBlock]::Create(($definitions -join "`r`n")))
        $python = (Get-Command python.exe).Source
        $payloadHash = (Get-FileHash -LiteralPath $script:Payload -Algorithm SHA256).Hash.ToLowerInvariant()
        $protocolHash = '79f5908e0c944d8076e2646595ca0342b192765a36288224a6cab071f59354c8'
        $arguments = @($script:Payload,'--automatic','--json','--expected-payload-sha256',$payloadHash,'--expected-protocol-sha256',$protocolHash)

        $receipt = Invoke-BoundedPeerGuard -Executable $python -Arguments $arguments -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 10 -MaxOutputBytes 4096
        $receipt.ready_for_ui | Should -BeTrue
        [string]$receipt.payload_sha256 | Should -BeExactly $payloadHash
        [string]$receipt.protocol_sha256 | Should -BeExactly $protocolHash

        foreach ($badArguments in @(
            @($script:Payload,'--unsupported'),
            @($script:Payload,'--automatic','--json','--expected-payload-sha256',('0' * 64),'--expected-protocol-sha256',$protocolHash),
            @($script:Payload,'--automatic','--json','--expected-payload-sha256',$payloadHash,'--expected-protocol-sha256',('0' * 64))
        )) {
            { Invoke-BoundedPeerGuard -Executable $python -Arguments $badArguments -ExpectedPayloadSHA256 $payloadHash `
                -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 10 -MaxOutputBytes 4096 } | Should -Throw
        }

        $malformed = Join-Path $TestDrive 'malformed-receipt.py'
        $extra = Join-Path $TestDrive 'extra-receipt.py'
        $nonzero = Join-Path $TestDrive 'nonzero-receipt.py'
        [IO.File]::WriteAllText($malformed,"print('not-json')",[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($extra,"print('{`"payload_sha256`":`"$payloadHash`",`"protocol_sha256`":`"$protocolHash`",`"ready_for_ui`":true}');print('extra')",[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($nonzero,'raise SystemExit(7)',[Text.UTF8Encoding]::new($false))
        { Invoke-BoundedPeerGuard -Executable $python -Arguments @($malformed) -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 10 -MaxOutputBytes 4096 } | Should -Throw
        { Invoke-BoundedPeerGuard -Executable $python -Arguments @($extra) -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 10 -MaxOutputBytes 4096 } | Should -Throw
        { Invoke-BoundedPeerGuard -Executable $python -Arguments @($nonzero) -ExpectedPayloadSHA256 $payloadHash `
            -ExpectedProtocolSHA256 $protocolHash -TimeoutSeconds 10 -MaxOutputBytes 4096 } | Should -Throw '*transport failed*'
    }
}
