BeforeAll {
    $script:AdvisorPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')).Path
    $script:ReportHarness = Join-Path $PSScriptRoot 'fixtures\Invoke-OfflineReportHarness.ps1'
    $script:ReportPowerShell = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    . $script:AdvisorPath
}

Describe 'Report and rule consistency' {
    It 'round-trips the integration rule through the existing rule export/import interface' {
        $path = Join-Path $TestDrive 'rules.json'
        $null = Export-PurviewRuleSet -Path $path
        $null = Import-PurviewRuleSet -Path $path
        $rule = $script:Rules | Where-Object id -eq 'PA-SEN-0001'
        $rule.condition.analysis | Should -Be 'SentinelPurviewIntegration'
        $rule.version | Should -Be '3.0.0'
    }

    It 'uses one interpretation for the finding, checklist and inventory' {
        $snapshot = Get-PurviewDemoSnapshot
        $findings = @(Invoke-PurviewRuleEngine -Snapshot $snapshot)
        $finding = $findings | Where-Object ruleId -eq 'PA-SEN-0001'
        $inventory = Get-PurviewInventory -Snapshot $snapshot | Where-Object {
            $_.Collector -eq 'SentinelPurviewIntegration' -and $_.Metric -eq 'Microsoft 365 audit and compliance data'
        }
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $finding.status | Should -Be $outcome.Status
        $finding.reason | Should -Be $outcome.Reason
        $inventory.Value | Should -Be $outcome.Value
        $inventory.Detail | Should -Be $outcome.Reason
        @($inventory).Count | Should -Be 1
        $outcome.SentinelValue | Should -Be '1'
    }

    It 'keeps legacy evidence without configuration verification unknown' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.PSObject.Properties.Remove('EvidenceScope')
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $outcome.Status | Should -Be 'NeedsReview'
        $outcome.Value | Should -Be 'not checked'
    }

    It 'renders the shared integration inventory in a full demo report' {
        $folder = Join-Path $TestDrive 'demo report'
        $output = @(& $script:ReportPowerShell -NoLogo -NoProfile -File $script:ReportHarness `
            -ScriptPath $script:AdvisorPath -ReportFolder $folder 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $html = Get-Content -LiteralPath (Join-Path $folder 'report.html') -Raw
        $html | Should -Match 'Events observed'
        $html | Should -Not -Match 'DataSensitivityLogEvent|PurviewDataSensitivityLogs'
        $findings = Get-Content -LiteralPath (Join-Path $folder 'findings.json') -Raw | ConvertFrom-Json
        ($findings | Where-Object ruleId -eq 'PA-SEN-0001').status | Should -Be 'Pass'
        Test-Path -LiteralPath (Join-Path $folder 'Set-PurviewTenantOptIns.ps1') | Should -BeTrue
        ($output -join "`n") | Should -Not -Match 'FIXTURE_AUTH_PENDING'
    }

    It 'replays a snapshot in brief mode without authenticating' {
        $snapshotPath = Join-Path $TestDrive 'synthetic-snapshot.json'
        Get-PurviewDemoSnapshot | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $snapshotPath -Encoding utf8
        $folder = Join-Path $TestDrive 'brief report'
        $output = @(& $script:ReportPowerShell -NoLogo -NoProfile -File $script:ReportHarness `
            -ScriptPath $script:AdvisorPath -ReportFolder $folder -Mode Replay -SnapshotPath $snapshotPath -Brief 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $findings = Get-Content -LiteralPath (Join-Path $folder 'findings.json') -Raw | ConvertFrom-Json
        ($findings | Where-Object ruleId -eq 'PA-SEN-0001').status | Should -Be 'Pass'
        Test-Path -LiteralPath (Join-Path $folder 'report.html') | Should -BeTrue
        ($output -join "`n") | Should -Not -Match 'FIXTURE_AUTH_PENDING'
    }

    It 'collects available Azure evidence with SkipConnect and preserves the existing missing-service states' {
        $folder = Join-Path $TestDrive 'existing session report'
        $output = @(& $script:ReportPowerShell -NoLogo -NoProfile -File $script:ReportHarness `
            -ScriptPath $script:AdvisorPath -ReportFolder $folder -Mode SkipConnect 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $snapshot = Get-Content -LiteralPath (Join-Path $folder 'snapshot.json') -Raw | ConvertFrom-Json -Depth 100
        $snapshot.tenant.tenantId | Should -Be '11111111-1111-1111-1111-111111111111'
        ($snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration').status | Should -Be 'Success'
        @($snapshot.collectorResults | Where-Object status -eq 'NotConnected').Count | Should -BeGreaterThan 0
        ($output -join "`n") | Should -Not -Match 'FIXTURE_AUTH_PENDING'
    }
}
