Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'P3.5 sink qualification preflight' {
    BeforeAll {
        $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $script:PreflightPath = Join-Path $script:RepoRoot 'scripts\p35-sink-preflight.ps1'
        $script:Tokens = $null
        $script:ParseErrors = $null
        $script:Ast = [Management.Automation.Language.Parser]::ParseFile(
            $script:PreflightPath,
            [ref]$script:Tokens,
            [ref]$script:ParseErrors
        )
        $script:Commands = @($script:Ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
            $_.GetCommandName()
        })
        $script:Content = [IO.File]::ReadAllText($script:PreflightPath)
        $functionNames = @(
            'Get-TextSHA256',
            'ConvertFrom-CodePoints',
            'Test-ContainsAny',
            'Get-PktmonStatusState',
            'Get-PktmonFilterState',
            'Get-PktmonComponentState',
            'Get-PreflightExitCode',
            'Test-TargetStateReady',
            'Get-LoopbackAssessment'
        )
        foreach ($functionName in $functionNames) {
            $definition = @($script:Ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName
            }, $true))
            $definition.Count | Should -Be 1
            . ([scriptblock]::Create($definition[0].Extent.Text))
        }
    }

    It 'parses without syntax errors' {
        $script:ParseErrors.Count | Should -Be 0
    }

    It 'contains no network, adapter, service, task, firewall, DNS or route mutation command' {
        $forbidden = @(
            'Add-DnsClientNrptRule',
            'Disable-NetAdapter',
            'Enable-NetAdapter',
            'New-NetFirewallRule',
            'New-NetRoute',
            'Register-ScheduledTask',
            'Remove-DnsClientNrptRule',
            'Remove-NetFirewallRule',
            'Remove-NetRoute',
            'Rename-NetAdapter',
            'Restart-Service',
            'Set-DnsClientServerAddress',
            'Set-NetFirewallRule',
            'Set-NetIPInterface',
            'Set-NetRoute',
            'Start-Service',
            'Stop-Service',
            'Unregister-ScheduledTask'
        )
        @($script:Commands | Where-Object { $_ -in $forbidden }).Count | Should -Be 0
    }

    It 'uses only documentation-only probe targets' {
        $script:Content | Should -Match "Address = '192\.0\.2\.1'"
        $script:Content | Should -Match "Prefix = '192\.0\.2\.1/32'"
        $script:Content | Should -Match "Address = '2001:db8::1'"
        $script:Content | Should -Match "Prefix = '2001:db8::1/128'"
    }

    It 'pins pktmon to System32 and invokes only read-only subcommands' {
        $script:Content | Should -Match "Join-Path \(\[Environment\]::SystemDirectory\) 'pktmon\.exe'"
        $script:Content | Should -Not -Match '\$env:SystemRoot'
        $script:Content | Should -Match 'StandardOutputEncoding = \$utf8'
        $script:Content | Should -Match 'StandardErrorEncoding = \$utf8'
        $script:Content | Should -Match "'filter list'"
        $script:Content | Should -Match "'list --json'"
        $script:Content | Should -Not -Match '& \$pktmon'
        $script:Content | Should -Match "Invoke-PktmonReadOnly -Arguments @\('status'\)"
        $script:Content | Should -Match "Invoke-PktmonReadOnly -Arguments @\('filter', 'list'\)"
        $script:Content | Should -Match "Invoke-PktmonReadOnly -Arguments @\('list', '--json'\)"
        $script:Content | Should -Not -Match "Invoke-PktmonReadOnly -Arguments @\('(start|stop|reset|unload)'"
    }

    It 'pins trusted System32 modules and uses module-qualified inventory commands' {
        $script:Content | Should -Match "WindowsPowerShell\\v1\.0\\Modules"
        $script:Content | Should -Match "Name -notin @\('CimCmdlets', 'NetAdapter', 'NetTCPIP'\)"
        $script:Content | Should -Match 'Import-Module -Name \$manifest -Force -PassThru'
        $script:Content | Should -Match 'NetTCPIP\\Get-NetRoute'
        $script:Content | Should -Match 'NetTCPIP\\Find-NetRoute'
        $script:Content | Should -Match 'NetTCPIP\\Get-NetIPInterface'
        $script:Content | Should -Match 'NetTCPIP\\Get-NetIPAddress -AddressFamily \$Family -ErrorAction Stop'
        $script:Content | Should -Not -Match 'NetTCPIP\\Get-NetIPAddress -AddressFamily \$Family -IncludeAllCompartments'
        $script:Content | Should -Match 'NetAdapter\\Get-NetAdapter'
        $script:Content | Should -Match 'CimCmdlets\\Get-CimInstance'
    }

    It 'rejects direct file execution and binds output to the approved payload and boot' {
        $script:Content | Should -Match '\$PSCommandPath'
        $script:Content | Should -Match 'hash-pinned in-memory payload'
        $script:Content | Should -Match 'ExpectedPayloadSHA256'
        $script:Content | Should -Match 'payload_sha256'
        $script:Content | Should -Match 'boot_marker_utc'
        $script:Content | Should -Match 'advisory_only\s+=\s+\$true'
        $script:Content | Should -Match 'observed_at_utc'
        $script:Content | Should -Not -Match '\bOutputPath\b'
        $script:Content | Should -Not -Match '\[IO\.File\]::(Open|WriteAllText)'
    }

    It 'parses stopped and running pktmon status as mutually exclusive for English and Russian' {
        $englishStopped = Get-PktmonStatusState -Text "Packet Monitor is not running.`r`n"
        $englishStopped.recognized | Should -BeTrue
        $englishStopped.stopped | Should -BeTrue
        $englishStopped.running | Should -BeFalse

        $russianStoppedText = ConvertFrom-CodePoints -Value @(1052, 1086, 1085, 1080, 1090, 1086, 1088, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 32, 1085, 1077, 32, 1079, 1072, 1087, 1091, 1097, 1077, 1085, 46)
        $russianStopped = Get-PktmonStatusState -Text $russianStoppedText
        $russianStopped.recognized | Should -BeTrue
        $russianStopped.stopped | Should -BeTrue
        $russianStopped.running | Should -BeFalse

        $legacyOEM = [Text.Encoding]::GetEncoding(866).GetString([Text.Encoding]::UTF8.GetBytes($russianStoppedText))
        $legacyOEM.Length | Should -Be 50
        (Get-TextSHA256 -Text $legacyOEM) | Should -Be 'c40ef82dac4ecfe635a8863f085690e5f686e605fc1429ae13867fdcac9613ee'
        (Get-PktmonStatusState -Text $legacyOEM).recognized | Should -BeFalse

        $englishRunning = Get-PktmonStatusState -Text 'Packet Monitor is already running.'
        $englishRunning.recognized | Should -BeTrue
        $englishRunning.running | Should -BeTrue
        $englishRunning.stopped | Should -BeFalse
    }

    It 'recognizes only exact empty or numbered pktmon filter layouts' {
        $englishEmpty = Get-PktmonFilterState -Text "Packet Filters:`r`n    None`r`n"
        $englishEmpty.recognized | Should -BeTrue
        $englishEmpty.empty | Should -BeTrue
        $englishEmpty.count | Should -Be 0

        $russianHeader = ConvertFrom-CodePoints -Value @(1060, 1080, 1083, 1100, 1090, 1088, 1099, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 58)
        $russianNone = ConvertFrom-CodePoints -Value @(1053, 1077, 1090)
        $russianEmpty = Get-PktmonFilterState -Text ($russianHeader + "`r`n    " + $russianNone)
        $russianEmpty.recognized | Should -BeTrue
        $russianEmpty.empty | Should -BeTrue

        $legacyHeader = [Text.Encoding]::GetEncoding(866).GetString([Text.Encoding]::UTF8.GetBytes($russianHeader))
        $legacyNone = [Text.Encoding]::GetEncoding(866).GetString([Text.Encoding]::UTF8.GetBytes($russianNone))
        (Get-TextSHA256 -Text $legacyHeader) | Should -Be 'e10086990c97ed0b56ab48a87734c8b37cfe98a475d9fbc4fb5f18c660de95e9'
        (Get-TextSHA256 -Text $legacyNone) | Should -Be '9f66b7ccd12590c02b4c489255863d72ca23bf5651f7d40cf06308b8dd6968bd'

        $russianSummary = ConvertFrom-CodePoints -Value @(1060, 1080, 1083, 1100, 1090, 1088, 1099, 32, 1087, 1072, 1082, 1077, 1090, 1086, 1074, 32, 1085, 1077, 32, 1091, 1082, 1072, 1079, 1072, 1085, 1099, 46)
        $summaryEmpty = Get-PktmonFilterState -Text $russianSummary
        $summaryEmpty.recognized | Should -BeTrue
        $summaryEmpty.empty | Should -BeTrue

        $emptyWithUnknownLine = Get-PktmonFilterState -Text ("Packet Filters:`r`nNone`r`nunexpected")
        $emptyWithUnknownLine.recognized | Should -BeFalse
        $emptyWithUnknownLine.empty | Should -BeFalse

        $nonEmpty = Get-PktmonFilterState -Text "Packet Filters:`r`n # Name IP Address`r`n - ---- ----------`r`n 1 owned 192.0.2.1/32"
        $nonEmpty.recognized | Should -BeTrue
        $nonEmpty.empty | Should -BeFalse
        $nonEmpty.count | Should -Be 1

        $malformed = Get-PktmonFilterState -Text 'valid text without a supported header'
        $malformed.recognized | Should -BeFalse
        $malformed.empty | Should -BeFalse
    }

    It 'fails closed for empty, malformed or unknown pktmon component JSON' {
        $valid = Get-PktmonComponentState -Text '{"Components":[{"Id":7,"SecondaryId":0,"Name":"nic"}]}'
        $valid.recognized | Should -BeTrue
        $valid.monitorable_count | Should -Be 1

        $grouped = Get-PktmonComponentState -Text '[{"Layer":"one","Components":[{"Id":7,"SecondaryId":0,"UnknownA":1}]},{"Layer":"two","Components":[{"Id":8,"UnknownB":2}]}]'
        $grouped.recognized | Should -BeTrue
        $grouped.monitorable_count | Should -Be 2

        (Get-PktmonComponentState -Text '{}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '[]').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '[{"Layer":"one"}]').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '[{"Components":[]}]').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text 'not-json').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"note":"\\"Id\\":7,\\"SecondaryId\\":0"}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"Components":{"Id":7,"SecondaryId":0}}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"Components":[{"Id":"7","SecondaryId":0}]}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"Components":[{"Id":7,"SecondaryId":"0"}]}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"Components":[{"Id":null}]}').recognized | Should -BeFalse
        (Get-PktmonComponentState -Text '{"Components":[{"Id":7,"SecondaryId":0},{"Id":7,"SecondaryId":1}]}').recognized | Should -BeFalse
    }

    It 'accepts an active non-loopback virtual default only for the sink primitive baseline' {
        $ready = Test-TargetStateReady -ActiveExactCount 0 -PersistentExactCount 0 -SelectedRouteCount 1 `
            -SelectedIsDefault $true -SelectedAdapterCount 1 -SelectedAdapterUp $true -SelectedAdapterLoopback $false
        $ready | Should -BeTrue

        (Test-TargetStateReady -ActiveExactCount 0 -PersistentExactCount 0 -SelectedRouteCount 1 `
                -SelectedIsDefault $true -SelectedAdapterCount 1 -SelectedAdapterUp $true -SelectedAdapterLoopback $true) | Should -BeFalse
    }

    It 'identifies loopback by stable index and canonical address without ProtocolIFType' {
        $interface = [pscustomobject]@{ CompartmentId = 1; InterfaceIndex = 1; ProtocolIFType = $null; InterfaceMetric = 75; ConnectionState = 1 }
        $ipv4 = [pscustomobject]@{ InterfaceIndex = 1; IPAddress = '127.0.0.1'; PrefixLength = 8; AddressState = 4 }
        $state = Get-LoopbackAssessment -Family 'IPv4' -InterfaceItems @($interface) -AddressItems @($ipv4)
        $state.ready | Should -BeTrue
        $state.address_count | Should -Be 1

        $wrongAddress = [pscustomobject]@{ InterfaceIndex = 1; IPAddress = '127.0.0.2'; PrefixLength = 8; AddressState = 4 }
        (Get-LoopbackAssessment -Family 'IPv4' -InterfaceItems @($interface) -AddressItems @($wrongAddress)).ready | Should -BeFalse

        $otherCompartment = [pscustomobject]@{ CompartmentId = 2; InterfaceIndex = 1; IPAddress = '127.0.0.1'; PrefixLength = 8; AddressState = 4 }
        (Get-LoopbackAssessment -Family 'IPv4' -InterfaceItems @($interface) -AddressItems @($otherCompartment)).ready | Should -BeFalse
    }

    It 'returns a nonzero fail-closed code for an unready result' {
        (Get-PreflightExitCode -Ready $true) | Should -Be 0
        (Get-PreflightExitCode -Ready $false) | Should -Be 3
        $script:Content | Should -Match '\$global:LASTEXITCODE = \$exitCode'
        $script:Content | Should -Match "throw 'P3\.5 sink preflight is not ready'"
    }
}
