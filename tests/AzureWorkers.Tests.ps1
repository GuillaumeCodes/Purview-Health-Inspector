BeforeAll {
    $script:WorkerPowerShell = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    $script:WorkerHarness = Join-Path $PSScriptRoot 'fixtures\Invoke-AzureSessionHarness.ps1'
}

Describe 'Real isolated Azure worker protocol with synthetic SDK modules' {
    BeforeEach {
        $script:PreviousTestMode = $env:PURVIEW_ADVISOR_TEST_MODE
        $script:WorkerResultPath = Join-Path $TestDrive 'worker result with spaces.json'
    }

    AfterEach {
        $env:PURVIEW_ADVISOR_TEST_MODE = $script:PreviousTestMode
    }

    It 'completes <Mode> authentication, imports the same context, and cleans up' -TestCases @(
        @{ Mode = 'fresh'; Reused = $false }
        @{ Mode = 'reuse'; Reused = $true }
        @{ Mode = 'expired'; Reused = $false }
    ) {
        param($Mode, $Reused)
        $env:PURVIEW_ADVISOR_TEST_MODE = $Mode
        $output = @(& $script:WorkerPowerShell -NoLogo -NoProfile -File $script:WorkerHarness -ResultPath $script:WorkerResultPath 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $result = Get-Content -LiteralPath $script:WorkerResultPath -Raw | ConvertFrom-Json -Depth 100
        ($result.Services | Where-Object Service -eq 'Azure').State | Should -Be 'Connected' -Because (
            ($result.Services | Where-Object Service -eq 'Azure').Detail + ($output -join "`n"))
        $result.Azure.Reused | Should -Be $Reused
        $result.Role | Should -Contain 'Reader'
        $result.Collector.status | Should -Be 'Success'
        $result.Collector.data.TenantId | Should -Be $result.Azure.TenantId
        $result.Collector.data.SubscriptionId | Should -Be $result.Azure.SubscriptionId
        $result.Collector.data.EvidenceScope | Should -Be 'Microsoft365Purview'
        $result.Collector.data.Results[0].Sources.Count | Should -Be 3
        $result.Collector.data.Results[0].Sources[0].EventCount | Should -Be 5
        $result.Collector.data.Results[0].Sources[0].SourceTenantId | Should -Be $result.Azure.TenantId
        $result.ContextRemoved | Should -BeTrue
        ($result | ConvertTo-Json -Depth 100) | Should -Not -Match 'synthetic-worker-token'
        $console = ($output -join "`n") -replace '\x1b\[[0-9;]*[A-Za-z]', ''
        $console | Should -Not -Match 'FIXTURE_AUTH_|Please select the account|Retrieving subscriptions'
        $azureRow = @($console -split '\r?\n' | Where-Object { $_ -match '^\s*Azure\s+Connected\s*$' })
        $azureRow.Count | Should -Be 1
        $serviceRows = @($console -split '\r?\n' | Where-Object {
                $_ -match '^\s*(Security & Compliance|Exchange Online|Microsoft Graph|Azure|SharePoint Online)\s+Connected\s*$'
            })
        $serviceRows.Count | Should -Be 5
        $statusColumns = @($serviceRows | ForEach-Object { $_.IndexOf('Connected') } | Sort-Object -Unique)
        $statusColumns.Count | Should -Be 1
    }

    It 'returns an explicit failed sign-in and uncollected evidence after cancellation' {
        $env:PURVIEW_ADVISOR_TEST_MODE = 'cancel'
        $output = @(& $script:WorkerPowerShell -NoLogo -NoProfile -File $script:WorkerHarness -ResultPath $script:WorkerResultPath 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $result = Get-Content -LiteralPath $script:WorkerResultPath -Raw | ConvertFrom-Json -Depth 100
        ($result.Services | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
        $result.Collector.status | Should -Be 'NotConnected'
        $result.Collector.errors[0].message | Should -Match 'cancelled'
        $result.ContextRemoved | Should -BeTrue
        ($output -join "`n") | Should -Not -Match 'FIXTURE_AUTH_|Please select the account|Retrieving subscriptions'
        ($output -join "`n") | Should -Match '(?m)^\s*Azure\s+Failed\s*$'
        ($output -join "`n") | Should -Match 'cancelled'
    }

    It 'keeps a role denial separate from authenticated resource collection' {
        $env:PURVIEW_ADVISOR_TEST_MODE = 'rbac-denied'
        $output = @(& $script:WorkerPowerShell -NoLogo -NoProfile -File $script:WorkerHarness -ResultPath $script:WorkerResultPath 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $result = Get-Content -LiteralPath $script:WorkerResultPath -Raw | ConvertFrom-Json -Depth 100
        ($result.Services | Where-Object Service -eq 'Azure').State | Should -Be 'Connected' -Because (
            ($result.Services | Where-Object Service -eq 'Azure').Detail + ($output -join "`n"))
        $result.RoleDetail | Should -Match 'AuthorizationFailed'
        $result.Collector.status | Should -Be 'Success'
        $result.ContextRemoved | Should -BeTrue
    }
}
