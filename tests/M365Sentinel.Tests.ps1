BeforeAll {
    . (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')
}

Describe 'Microsoft 365 telemetry evidence boundaries' {
    It 'does not accept a legacy Data Map snapshot as Microsoft 365 ingestion' {
        $snapshot = @{
            collectorResults = @(@{
                collector = 'SentinelPurviewIntegration'
                status = 'Success'
                data = @{
                    SentinelWorkspaces = @('/subscriptions/test/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/sentinel')
                    SentinelDiscoveryComplete = $true
                    Results = @(@{
                        Verdict = 'ConfirmedIntegratedAndIngesting'
                        SentinelOnboarded = $true
                        PurviewSolutionInstalled = $true
                        PurviewDiagnosticConfigured = $true
                        IntegrationConfigured = $true
                        DataIngestionConfirmed = $true
                        IngestionTable = 'PurviewDataSensitivityLogs'
                        EventCount = 500
                        ReportStatement = 'Legacy governance evidence.'
                    })
                }
                errors = @()
                limitations = @()
            })
        }
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $outcome.Status | Should -Be 'NeedsReview'
        $outcome.Value | Should -Be 'not checked'
        $outcome.Reason | Should -Match 'Microsoft 365'
    }

    It 'keeps the verified authentication and Sentinel-presence evidence distinct from ingestion' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results = @()
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $outcome.SentinelValue | Should -Be '1'
        $outcome.Status | Should -Not -Be 'Pass'
    }

    It 'cites Microsoft 365 API-based integration rather than the Data Map integration guide' {
        $script:DocUrl.SentinelPurview | Should -Be 'https://learn.microsoft.com/azure/sentinel/connect-services-api-based'
        $rule = $script:Rules | Where-Object id -eq 'PA-SEN-0001'
        $rule.title | Should -Match 'Microsoft 365'
        $rule.rationale | Should -Not -Match 'DataSensitivityLogEvent|diagnostic route|Data Map'
    }

    It 'does not accept source records belonging to another Microsoft 365 tenant' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Sources[0].SourceTenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $outcome.Status | Should -Be 'NeedsReview'
        $outcome.Value | Should -Not -Be 'Events observed'
    }

    It 'does not accept a partial or failed query just because it contains a positive count' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Sources[0].QueryState = 'Failed'
        (Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot).Status | Should -Be 'NeedsReview'
    }

    It 'does not accept a generic SecurityAlert source as M365 audit evidence' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Sources[0].Table = 'SecurityAlert'
        (Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot).Status | Should -Be 'NeedsReview'
    }

    It 'does not accept governance tables even if the snapshot claims the new evidence scope' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Sources[0].Table = 'PurviewDataSensitivityLogs'
        (Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot).Status | Should -Be 'NeedsReview'
    }

    It 'does not accept historical audit telemetry in a workspace not verified as Sentinel-enabled' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].SentinelOnboarded = $false
        (Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot).Status | Should -Not -Be 'Pass'
    }

    It 'keeps the report to one Sentinel finding and one compact inventory row' {
        $snapshot = Get-PurviewDemoSnapshot
        $rows = @(Get-PurviewInventory -Snapshot $snapshot | Where-Object Collector -eq 'SentinelPurviewIntegration')
        $rows.Count | Should -Be 1
        $findings = @(Invoke-PurviewRuleEngine -Snapshot $snapshot | Where-Object ruleId -eq 'PA-SEN-0001')
        $findings.Count | Should -Be 1
        $findings[0].reason.Length | Should -BeLessThan 400
        @($findings[0].observed).Count | Should -BeLessOrEqual 8
    }
}

Describe 'Documented connector identifiers' {
    It 'recognizes <Kind> from its kind and tenant rather than its GUID resource name' -TestCases @(
        @{ Kind = 'Office365'; DataType = 'exchange' }
        @{ Kind = 'MicrosoftPurviewInformationProtection'; DataType = 'logs' }
        @{ Kind = 'OfficeIRM'; DataType = 'alerts' }
    ) {
        param($Kind, $DataType)
        $dataTypes = @{}
        $dataTypes[$DataType] = @{ state = 'Enabled' }
        $connector = @{
            kind = $Kind
            name = '77777777-7777-7777-7777-777777777777'
            properties = @{ tenantId = '11111111-1111-1111-1111-111111111111'; dataTypes = $dataTypes }
        }
        $result = @(ConvertTo-PurviewSentinelM365Connector -Connector @($connector) -TenantId '11111111-1111-1111-1111-111111111111')
        $result.Count | Should -Be 1
        $result[0].Kind | Should -Be $Kind
        $result[0].State | Should -Be 'Enabled'
    }

    It 'keeps <Case> distinct from an enabled connector for the assessed tenant' -TestCases @(
        @{ Case = 'other tenant'; Tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; State = 'Enabled'; Expected = 'OtherTenant' }
        @{ Case = 'missing tenant'; Tenant = ''; State = 'Enabled'; Expected = 'Unknown' }
        @{ Case = 'invalid tenant'; Tenant = 'not-a-tenant'; State = 'Enabled'; Expected = 'Unknown' }
        @{ Case = 'disabled feed'; Tenant = '11111111-1111-1111-1111-111111111111'; State = 'Disabled'; Expected = 'Disabled' }
        @{ Case = 'missing feed state'; Tenant = '11111111-1111-1111-1111-111111111111'; State = ''; Expected = 'Unknown' }
    ) {
        param($Case, $Tenant, $State, $Expected)
        $connector = @{ kind = 'OfficeIRM'; properties = @{ tenantId = $Tenant; dataTypes = @{ alerts = @{ state = $State } } } }
        (ConvertTo-PurviewSentinelM365Connector -Connector @($connector) -TenantId '11111111-1111-1111-1111-111111111111').State |
            Should -Be $Expected
    }

    It 'does not infer Office365 from a display name or resource name' {
        $connector = @{ kind = 'Custom'; name = 'Office365'; properties = @{ displayName = 'Microsoft 365' } }
        @(ConvertTo-PurviewSentinelM365Connector -Connector @($connector) -TenantId '11111111-1111-1111-1111-111111111111').Count |
            Should -Be 0
    }

    It 'does not claim Purview configuration from a broad XDR incidents connector alone' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Connectors[0].Kind = 'MicrosoftThreatProtection'
        $collector.data.Results[0].Sources[0].EventCount = 0
        $collector.data.Results[0].Sources[0].LastEventUtc = $null
        (Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot).Value | Should -Be 'Not observed'
    }

    It 'recognizes an enabled IRM connector as configured without inventing alert events' {
        $snapshot = Get-PurviewDemoSnapshot
        $collector = $snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration'
        $collector.data.Results[0].Connectors[0].Kind = 'OfficeIRM'
        $collector.data.Results[0].Sources[0].EventCount = 0
        $collector.data.Results[0].Sources[0].LastEventUtc = $null
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot $snapshot
        $outcome.Value | Should -Be 'Configured; ingestion not confirmed'
        $outcome.Status | Should -Be 'NeedsReview'
        ($outcome.Observed -join ' ') | Should -Match 'OfficeIRM'
    }
}

Describe 'Aggregate query boundaries' {
    BeforeEach {
        $script:Queries = @(Get-PurviewSentinelM365Query -TenantId '11111111-1111-1111-1111-111111111111' -LookbackDays 7)
    }

    It 'uses exactly three documented tables and never queries governance evidence' {
        $script:Queries.Count | Should -Be 3
        @($script:Queries.Table) | Should -Be @('OfficeActivity', 'MicrosoftPurviewInformationProtection', 'SecurityAlert')
        ($script:Queries.Query -join ' ') | Should -Not -Match 'PurviewDataSensitivityLogs|DataSensitivityLogEvent|scan|union|isfuzzy|best_effort'
    }

    It 'uses the M365 organization ID, not the workspace TenantId, for audit and MIP queries' {
        foreach ($query in $script:Queries | Where-Object Scope -eq 'Microsoft365Tenant') {
            $query.Query | Should -Match "OrganizationId =~ '11111111-1111-1111-1111-111111111111'"
            $query.Query | Should -Not -Match '\bTenantId\b|\bOfficeTenantId\b'
            $query.Query | Should -Match 'ago\(7d\)'
            $query.Query | Should -Match 'summarize EventCount=count\(\), LastEventUtc=max\(TimeGenerated\)'
        }
    }

    It 'uses exact IRM product identity and excludes customized alerts' {
        $query = $script:Queries | Where-Object Table -eq 'SecurityAlert'
        $query.Scope | Should -Be 'Workspace'
        $query.Query | Should -Match 'ProductName == "Microsoft 365 Insider Risk Management"'
        $query.Query | Should -Match 'bag_has_key\(todynamic\(ExtendedProperties\), "OriginalProductName"\)'
        $query.Query | Should -Match 'where alertWasCustomized == false'
        $query.Query | Should -Not -Match 'ProviderName|TenantId|OrganizationId|Defender XDR|OATP'
    }

    It 'counts documented label actions separately from general audit and MIP records' {
        foreach ($query in $script:Queries | Where-Object Scope -eq 'Microsoft365Tenant') {
            $query.Query | Should -Match 'LabelEventCount=countif\(Operation in~'
            $query.Query | Should -Match '"FileSensitivityLabelApplied"'
            $query.Query | Should -Not -Match 'AipHeartBeat|Operation has|Operation contains'
        }
    }

    It 'does not classify generic Office or Defender activity as raw DLP events' {
        $query = $script:Queries | Where-Object Table -eq 'OfficeActivity'
        $query.Query | Should -Match 'toint\(RecordType\) in \(11, 13, 63\)'
        $query.Query | Should -Match 'Operation in~ \("DlpRuleMatch", "DlpRuleUndo", "DlpInfo"\)'
        $query.Query | Should -Match 'UserKey == "DlpAgent"'
    }

    It 'refuses a missing tenant identity or an out-of-bounds lookback' {
        { Get-PurviewSentinelM365Query -TenantId ([guid]::Empty) } | Should -Throw
        { Get-PurviewSentinelM365Query -TenantId '11111111-1111-1111-1111-111111111111' -LookbackDays 0 } | Should -Throw
        { Get-PurviewSentinelM365Query -TenantId '11111111-1111-1111-1111-111111111111' -LookbackDays 3651 } | Should -Throw
    }
}
