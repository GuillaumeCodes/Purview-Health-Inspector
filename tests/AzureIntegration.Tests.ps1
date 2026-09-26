BeforeAll {
    . (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')

    function Connect-MgGraph {
        [CmdletBinding()]
        param([string]$LoginHint)
        throw 'Unexpected live Graph sign-in in a test.'
    }

    function Get-AzContext {
        [CmdletBinding()]
        param()
        throw 'Unexpected live Azure context read in a test.'
    }

    function Connect-AzAccount {
        [CmdletBinding()]
        param([string]$Tenant, [string]$Environment)
        throw 'Unexpected live Azure sign-in in a test.'
    }

    function Enable-AzContextAutosave {
        [CmdletBinding()]
        param([string]$Scope)
        throw 'Unexpected Azure autosave change in a test.'
    }

    function Update-AzConfig {
        [CmdletBinding()]
        param([string]$LoginExperienceV2, [string]$Scope)
        throw 'Unexpected Azure configuration change in a test.'
    }

    function Save-AzContext {
        [CmdletBinding()]
        param([string]$Path, [switch]$Force)
        throw 'Unexpected Azure context export in a test.'
    }

    function Get-AzRoleAssignment {
        [CmdletBinding()]
        param([string]$SignInName, [string]$Scope, [object]$DefaultProfile)
        throw 'Unexpected live Azure role read in a test.'
    }

    function Get-AzSubscription {
        [CmdletBinding()]
        param([string]$TenantId, [object]$DefaultProfile)
        throw 'Unexpected live Azure subscription read in a test.'
    }

    function Get-AzAccessToken {
        [CmdletBinding()]
        param([string]$ResourceUrl, [string]$TenantId, [object]$DefaultProfile)
        throw 'Unexpected live Azure token request in a test.'
    }

    function Invoke-AzRestMethod {
        [CmdletBinding()]
        param([string]$Method, [string]$Path, [object]$DefaultProfile)
        throw 'Unexpected live Azure request in a test.'
    }

    function New-TestAzureContext {
        [pscustomobject]@{
            Account = [pscustomobject]@{ Id = 'operator@example.test'; Type = 'User' }
            Tenant = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }
            Subscription = [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' }
            Environment = [pscustomobject]@{ Name = 'AzureCloud' }
        }
    }
}

Describe 'Azure sign-in result handling' {
    BeforeEach {
        $script:AzureRole = @()
        $script:AzureRoleDetail = 'not read; Azure RBAC role assignments could not be determined'
        $script:AzureSession = $null
        $script:AzureSessionContextPath = ''
        $script:ExpectedTenantId = ''
        $script:GraphSeparate = $false
        $script:OwnedSession = @()
        $script:OwnedExchangeConnectionId = @()
        $script:TempArtifact = @()
        $script:WorkerExitCode = 2
        $script:WorkerOutputMode = 'Json'
        $script:WorkerSavesContext = $true
        $script:CurrentService = ''
        $script:WorkerOutput = @{
            Connected = $true
            TenantId = '11111111-1111-1111-1111-111111111111'
            SubscriptionId = '22222222-2222-2222-2222-222222222222'
            AccountId = 'operator@example.test'
            Role = @('Reader')
            RoleDetail = ''
        }
        Mock Get-PurviewExchangeConnection { @() }
        Mock Get-PurviewPowerShell7Path { 'test-pwsh.exe' }
        Mock Test-PurviewConnected { $true }
        Mock Get-PurviewSignedInAccount { 'operator@example.test' }
        Mock Assert-PurviewSessionTenant { }
        Mock Write-PurviewStep { param($Name) $script:CurrentService = $Name }
        Mock Write-PurviewStepResult {
            param($Status)
            if ($script:CurrentService -eq 'Azure' -and $Status -eq 'Connected' -and
                -not $script:AzureSignInProcess.Waited) {
                throw 'Connected was reported before the authentication worker finished.'
            }
        }
        Mock Write-Line { }
        Mock Start-Process {
            param($ArgumentList)
            $outputIndex = [array]::IndexOf($ArgumentList, '-AzureSignInOutputPath')
            $outputPath = $ArgumentList[$outputIndex + 1].Trim('"')
            if ($script:WorkerOutputMode -eq 'Json') {
                $script:WorkerOutput | ConvertTo-Json -Depth 20 |
                    Set-Content -LiteralPath $outputPath -Encoding utf8
            }
            elseif ($script:WorkerOutputMode -eq 'Malformed') {
                '{' | Set-Content -LiteralPath $outputPath -Encoding utf8
            }
            $contextIndex = [array]::IndexOf($ArgumentList, '-AzureContextPath')
            if ($contextIndex -ge 0 -and $script:WorkerSavesContext) {
                '{}' | Set-Content -LiteralPath $ArgumentList[$contextIndex + 1].Trim('"') -Encoding utf8
            }
            $process = [pscustomobject]@{ ExitCode = $script:WorkerExitCode; HasExited = $false; Handle = 1; Waited = $false }
            $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { $this.HasExited = $true; $this.Waited = $true }
            $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
            return $process
        }
    }

    AfterEach {
        foreach ($path in $script:TempArtifact) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }

    It 'reads RBAC results when an authenticated Azure session was reused' {
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Connected'
        $script:AzureRole | Should -Contain 'Reader'
    }

    It 'does not call an unauthenticated worker result connected just because it exited successfully' {
        $script:WorkerExitCode = 0
        $script:WorkerOutput = @{ Connected = $false; Error = 'Azure authentication did not complete.' }
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
        $script:AzureRole.Count | Should -Be 0
    }

    It 'waits for a new sign-in before recording the shared Connected status' {
        $script:WorkerExitCode = 0
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Connected'
        $script:AzureRole | Should -Contain 'Reader'
        $script:AzureSession.AccountId | Should -Be 'operator@example.test'
        if ($IsWindows) {
            Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
                $NoNewWindow -and -not $Wait -and $RedirectStandardOutput -and $RedirectStandardError
            }
        }
    }

    It 'rejects a missing or malformed worker payload: <Mode>' -TestCases @(
        @{ Mode = 'None' }
        @{ Mode = 'Malformed' }
    ) {
        param($Mode)
        $script:WorkerOutputMode = $Mode
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
    }

    It 'does not trust a success payload from a failed process' {
        $script:WorkerExitCode = 1
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
    }

    It 'requires a Boolean connection flag rather than a truthy string' {
        $script:WorkerOutput.Connected = 'false'
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
    }

    It 'requires identity evidence: <Field>' -TestCases @(
        @{ Field = 'TenantId' }
        @{ Field = 'SubscriptionId' }
        @{ Field = 'AccountId' }
    ) {
        param($Field)
        $script:WorkerOutput.Remove($Field)
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
    }

    It 'requires the saved context before reporting connected' {
        $script:WorkerSavesContext = $false
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
    }

    It 'passes the Microsoft 365 tenant into Azure authentication' {
        Mock Assert-PurviewSessionTenant { $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111' }
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Connected'
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains '-AzureTenantId' -and $ArgumentList -contains '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'refuses an Azure identity from another tenant' {
        Mock Assert-PurviewSessionTenant { $script:ExpectedTenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Failed'
        ($result | Where-Object Service -eq 'Azure').Detail | Should -Match 'different tenant'
    }

    It 'keeps missing Graph authentication from aborting Azure and the remaining services' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Connect-MgGraph' }
        Mock Test-PurviewConnected { $false } -ParameterFilter { $Service -eq 'Graph' }
        Mock Test-PurviewCommand { $false } -ParameterFilter { $Name -eq 'Connect-MgGraph' }
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Microsoft Graph').State | Should -Be 'Unavailable'
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Connected'
    }

    It 'does not require an existing account hint before connecting' {
        Mock Get-PurviewSignedInAccount { '' }
        $result = @(Connect-PurviewSession)
        ($result | Where-Object Service -eq 'Azure').State | Should -Be 'Connected'
    }
}

Describe 'Azure authentication verification' {
    BeforeEach {
        $script:TestAzureContext = New-TestAzureContext
        $script:TestToken = [pscustomobject]@{
            Token = ConvertTo-SecureString 'synthetic-test-token' -AsPlainText -Force
            ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1)
            TenantId = $script:TestAzureContext.Tenant.Id
        }
        Mock Get-AzContext { $script:TestAzureContext }
        Mock Get-AzAccessToken { $script:TestToken }
    }

    It 'accepts a current SecureString ARM token for the assessed tenant' {
        $context = Get-PurviewVerifiedAzureContext -TenantId '11111111-1111-1111-1111-111111111111'
        $context.Account.Id | Should -Be 'operator@example.test'
        Should -Invoke Get-AzAccessToken -Times 1 -Exactly -ParameterFilter {
            $ResourceUrl -eq 'https://management.azure.com/' -and
            $TenantId -eq '11111111-1111-1111-1111-111111111111' -and
            $DefaultProfile.Subscription.Id -eq '22222222-2222-2222-2222-222222222222'
        }
    }

    It 'supports the plain-text token shape returned by older Az.Accounts versions' {
        $script:TestToken.Token = 'synthetic-test-token'
        (Get-PurviewVerifiedAzureContext).Tenant.Id | Should -Be '11111111-1111-1111-1111-111111111111'
    }

    It 'rejects an unusable token: <Case>' -TestCases @(
        @{ Case = 'EmptySecureString' }
        @{ Case = 'Whitespace' }
        @{ Case = 'Expired' }
        @{ Case = 'MissingExpiry' }
        @{ Case = 'WrongTenant' }
    ) {
        param($Case)
        switch ($Case) {
            'EmptySecureString' { $script:TestToken.Token = [System.Security.SecureString]::new() }
            'Whitespace' { $script:TestToken.Token = ' ' }
            'Expired' { $script:TestToken.ExpiresOn = [DateTimeOffset]::UtcNow.AddMinutes(-1) }
            'MissingExpiry' { $script:TestToken.ExpiresOn = $null }
            'WrongTenant' { $script:TestToken.TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        }
        { Get-PurviewVerifiedAzureContext } | Should -Throw
    }

    It 'rejects unusable saved metadata before requesting a token: <Case>' -TestCases @(
        @{ Case = 'NoContext' }
        @{ Case = 'NoSubscription' }
        @{ Case = 'NoAccount' }
        @{ Case = 'WrongTenant' }
        @{ Case = 'UnsupportedCloud' }
    ) {
        param($Case)
        switch ($Case) {
            'NoContext' { $script:TestAzureContext = $null }
            'NoSubscription' { $script:TestAzureContext.Subscription.Id = '' }
            'NoAccount' { $script:TestAzureContext.Account.Id = '' }
            'WrongTenant' { $script:TestAzureContext.Tenant.Id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
            'UnsupportedCloud' { $script:TestAzureContext.Environment.Name = 'AzureUSGovernment' }
        }
        { Get-PurviewVerifiedAzureContext -TenantId '11111111-1111-1111-1111-111111111111' } | Should -Throw
        Should -Invoke Get-AzAccessToken -Times 0 -Exactly
    }
}

Describe 'Azure sign-in worker operations' {
    BeforeEach {
        $script:TestAzureContext = New-TestAzureContext
        $script:FreshSignIn = $false
        $script:ContextUsable = $true
        $script:SavedContext = Join-Path $TestDrive 'azure-context.json'
        Mock Import-Module { } -ParameterFilter { $Name -contains 'Az.Accounts' }
        Mock Enable-AzContextAutosave { }
        Mock Update-AzConfig { }
        Mock Get-PurviewVerifiedAzureContext {
            if (-not $script:ContextUsable -and -not $script:FreshSignIn) { throw 'Run Connect-AzAccount again.' }
            $script:TestAzureContext
        }
        Mock Connect-AzAccount { $script:FreshSignIn = $true }
        Mock Save-AzContext { param($Path) '{}' | Set-Content -LiteralPath $Path -Encoding utf8 }
        Mock Get-AzRoleAssignment { [pscustomobject]@{ RoleDefinitionName = 'Reader' } }
    }

    It 'returns RBAC evidence for an authenticated reused context without prompting' {
        $result = Connect-PurviewAzureAccount -ContextPath $script:SavedContext
        $result.Connected | Should -BeTrue
        $result.Reused | Should -BeTrue
        $result.Role | Should -Contain 'Reader'
        Should -Invoke Connect-AzAccount -Times 0 -Exactly
        Should -Invoke Update-AzConfig -Times 0 -Exactly
        Should -Invoke Enable-AzContextAutosave -Times 1 -Exactly -ParameterFilter { $Scope -eq 'Process' }
    }

    It 'signs in once and revalidates before saving a previously unusable context' {
        $script:ContextUsable = $false
        $result = Connect-PurviewAzureAccount -ContextPath $script:SavedContext -TenantId $script:TestAzureContext.Tenant.Id
        $result.Connected | Should -BeTrue
        $result.Reused | Should -BeFalse
        Should -Invoke Connect-AzAccount -Times 1 -Exactly -ParameterFilter {
            $Tenant -eq '11111111-1111-1111-1111-111111111111' -and $Environment -eq 'AzureCloud'
        }
        Should -Invoke Get-PurviewVerifiedAzureContext -Times 2 -Exactly
        Should -Invoke Save-AzContext -Times 1 -Exactly
        Should -Invoke Update-AzConfig -Times 1 -Exactly -ParameterFilter {
            $LoginExperienceV2 -eq 'Off' -and $Scope -eq 'Process'
        }
    }

    It 'preserves compatibility with older modules without the new subscription selector' {
        $script:ContextUsable = $false
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Update-AzConfig' }
        (Connect-PurviewAzureAccount -ContextPath $script:SavedContext).Connected | Should -BeTrue
        Should -Invoke Update-AzConfig -Times 0 -Exactly
    }

    It 'surfaces a configuration failure instead of waiting on a hidden subscription prompt' {
        $script:ContextUsable = $false
        Mock Update-AzConfig { throw 'Could not configure the worker login experience.' }
        { Connect-PurviewAzureAccount -ContextPath $script:SavedContext } | Should -Throw '*Could not configure*'
        Should -Invoke Connect-AzAccount -Times 0 -Exactly
        Should -Invoke Save-AzContext -Times 0 -Exactly
    }

    It 'does not export a context or read roles after cancelled authentication' {
        $script:ContextUsable = $false
        Mock Connect-AzAccount { throw 'Authentication was cancelled.' }
        { Connect-PurviewAzureAccount -ContextPath $script:SavedContext } | Should -Throw '*cancelled*'
        Should -Invoke Save-AzContext -Times 0 -Exactly
        Should -Invoke Get-AzRoleAssignment -Times 0 -Exactly
    }

    It 'does not report success when sign-in returns without a usable context' {
        Mock Get-PurviewVerifiedAzureContext { throw 'No active account. Run Connect-AzAccount again.' }
        { Connect-PurviewAzureAccount -ContextPath $script:SavedContext } | Should -Throw '*No active account*'
        Should -Invoke Save-AzContext -Times 0 -Exactly
    }

    It 'requires successful context export for the independent collector' {
        Mock Save-AzContext { throw 'Context export failed.' }
        { Connect-PurviewAzureAccount -ContextPath $script:SavedContext } | Should -Throw '*Context export failed*'
    }

    It 'preserves a role-read error without falsely declaring authentication failed' {
        Mock Get-AzRoleAssignment { throw 'AuthorizationFailed: role assignments are not readable.' }
        $result = Connect-PurviewAzureAccount -ContextPath $script:SavedContext
        $result.Connected | Should -BeTrue
        $result.Role.Count | Should -Be 0
        $result.RoleDetail | Should -Match 'AuthorizationFailed'
        ($result | ConvertTo-Json -Depth 10) | Should -Not -Match 'synthetic-test-token'
    }

    It 'retains named roles while flagging incomplete assignment data' {
        Mock Get-AzRoleAssignment {
            [pscustomobject]@{ RoleDefinitionName = 'Reader' }
            [pscustomobject]@{ RoleDefinitionName = $null }
        }
        $result = Connect-PurviewAzureAccount -ContextPath $script:SavedContext
        $result.Role | Should -Contain 'Reader'
        $result.RoleDetail | Should -Match 'did not report a role name'
    }
}

Describe 'Sentinel Microsoft 365 telemetry evidence' {
    BeforeEach {
        $script:IsSentinelWorker = $true
        $script:ExpectedTenantId = ''
        $script:TestAzureContext = New-TestAzureContext
        $script:TestWorkspaceId = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/security/providers/Microsoft.OperationalInsights/workspaces/sentinel'
        $script:TestQueryResult = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"EventCount"},{"name":"LastEventUtc"},{"name":"LabelEventCount"},{"name":"LastLabelEventUtc"},{"name":"DlpEventCount"},{"name":"LastDlpEventUtc"}],"rows":[[7,"2026-09-24T12:00:00Z",2,"2026-09-24T12:00:00Z",1,"2026-09-24T12:00:00Z"]]}]}' |
            ConvertFrom-Json
        $script:EmptyQueryResult = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"},{"name":"LabelEventCount"},{"name":"LastLabelEventUtc"},{"name":"DlpEventCount"},{"name":"LastDlpEventUtc"}],"rows":[[0,null,0,null,0,null]]}]}' | ConvertFrom-Json
        Mock Test-PurviewCommand { $true }
        Mock Get-AzContext { $script:TestAzureContext }
        Mock Get-AzSubscription {
            [pscustomobject]@{
                Id = $script:TestAzureContext.Subscription.Id
                TenantId = $script:TestAzureContext.Tenant.Id
            }
        }
        Mock Get-AzAccessToken {
            [pscustomobject]@{
                Token = ConvertTo-SecureString 'synthetic-test-token' -AsPlainText -Force
                ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1)
                TenantId = $script:TestAzureContext.Tenant.Id
            }
        }
        Mock Invoke-AzRestMethod {
            param($Path)
            $body = switch -Regex ($Path) {
                '/providers/Microsoft.OperationalInsights/workspaces\?' {
                    @{ value = @(@{ id = $script:TestWorkspaceId; properties = @{ customerId = '33333333-3333-3333-3333-333333333333' } }) }; break
                }
                '/onboardingStates\?' {
                    @{ value = @(@{ name = 'default' }) }; break
                }
                '/dataConnectors\?' {
                    @{ value = @(@{ name = '77777777-7777-7777-7777-777777777777'; kind = 'Office365'; properties = @{
                        tenantId = $script:TestAzureContext.Tenant.Id
                        dataTypes = @{ exchange = @{ state = 'Enabled' }; sharePoint = @{ state = 'Disabled' }; teams = @{ state = 'Disabled' } }
                    } }) }; break
                }
                '/workspaces/sentinel\?' {
                    @{ id = $script:TestWorkspaceId; properties = @{ customerId = '33333333-3333-3333-3333-333333333333' } }; break
                }
                default { throw "Unexpected ARM path in a test: $Path" }
            }
            [pscustomobject]@{ StatusCode = 200; Content = ($body | ConvertTo-Json -Depth 20) }
        }
        Mock Invoke-RestMethod {
            param($Body)
            if (($Body | ConvertFrom-Json).query.StartsWith('OfficeActivity')) { $script:TestQueryResult }
            else { $script:EmptyQueryResult }
        }
    }

    AfterEach {
        $script:IsSentinelWorker = $false
    }

    It 'accepts the documented Log Analytics single summary row' {
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Success'
        $result.data.Results[0].Sources[0].EventCount | Should -Be 7
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'Pass'
    }

    It 'shows collected integration evidence in the inventory rather than hard-coded Not read' {
        $snapshot = Get-PurviewDemoSnapshot
        $inventory = @(Get-PurviewInventory -Snapshot $snapshot)
        $row = $inventory | Where-Object {
            $_.Collector -eq 'SentinelPurviewIntegration' -and $_.Metric -eq 'Microsoft 365 audit and compliance data'
        }
        $row.Value | Should -Not -Be 'Not read'
        $row.Value | Should -Be 'Events observed'
    }

    It 'separates configured integration from a zero-event lookback window' {
        $script:TestQueryResult = $script:EmptyQueryResult
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Success'
        $result.data.Results[0].Connectors[0].State | Should -Be 'Enabled'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Status | Should -Be 'NeedsReview'
        $outcome.Value | Should -Be 'Configured; ingestion not confirmed'
    }

    It 'accepts Information Protection ingestion independently of Microsoft 365 audit ingestion' {
        Mock Invoke-RestMethod {
            param($Body)
            if (($Body | ConvertFrom-Json).query.StartsWith('MicrosoftPurviewInformationProtection')) { $script:TestQueryResult }
            else { $script:EmptyQueryResult }
        }
        $result = Get-PurviewSentinelIntegrationData
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Status | Should -Be 'Pass'
        $outcome.Reason | Should -Match 'Information Protection'
    }

    It 'does not count a disabled connector as configured when no events are observed' {
        $script:TestQueryResult = $script:EmptyQueryResult
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(@{ kind = 'OfficeIRM'; properties = @{
                tenantId = $script:TestAzureContext.Tenant.Id; dataTypes = @{ alerts = @{ state = 'Disabled' } }
            } }) } | ConvertTo-Json -Depth 10) }
        } -ParameterFilter { $Path -match '/dataConnectors\?' }
        $result = Get-PurviewSentinelIntegrationData
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'Warning'
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly
    }

    It 'distinguishes a Log Analytics workspace without Sentinel onboarding' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[]}' }
        } -ParameterFilter { $Path -match '/onboardingStates\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.Results.Count | Should -Be 0
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'does not mistake a general Defender for Office connector for Purview coverage' {
        $script:TestQueryResult = $script:EmptyQueryResult
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"kind":"OfficeATP","properties":{"dataTypes":{"alerts":{"state":"Enabled"}}}}]}' }
        } -ParameterFilter { $Path -match '/dataConnectors\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.Results[0].Connectors.Count | Should -Be 0
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'Warning'
    }

    It 'preserves observed ingestion when connector configuration is inaccessible' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed","message":"Connector read denied."}}' }
        } -ParameterFilter { $Path -match '/dataConnectors\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results[0].ConnectorRead | Should -Be 'Failed'
        ($result.limitations -join ' ') | Should -Match 'AuthorizationFailed'
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'Pass'
    }

    It 'retains proven configuration when the Log Analytics query is denied' {
        Mock Invoke-RestMethod { throw 'HTTP 403: Log Analytics query access denied.' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results[0].Connectors[0].State | Should -Be 'Enabled'
        $result.data.Results[0].Sources[0].EventCount | Should -BeNullOrEmpty
        $result.data.Results[0].Sources[0].ErrorMessage | Should -Match '403'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Status | Should -Be 'NeedsReview'
        ($outcome.Observed -join ' ') | Should -Match 'query access denied'
    }

    It 'never requests Data Map resources or diagnostic settings as evidence' {
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Success'
        Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly -ParameterFilter {
            $Path -match 'Microsoft.Purview|diagnosticSettings|contentPackages|Microsoft.OperationsManagement'
        }
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter {
            $Body -match 'PurviewDataSensitivityLogs|DataSensitivityLogEvent'
        }
        Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly -ParameterFilter { $Path -match '/providers/Microsoft.OperationalInsights/workspaces\?' }
    }

    It 'does not claim complete workspace discovery when subscription access is denied' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed"}}' }
        } -ParameterFilter { $Path -match '/providers/Microsoft.OperationalInsights/workspaces\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results.Count | Should -Be 0
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'NeedsReview'
    }

    It 'discovers Sentinel workspaces across subscriptions within the verified tenant' {
        $script:TestWorkspaceId = '/subscriptions/44444444-4444-4444-4444-444444444444/resourceGroups/security/providers/Microsoft.OperationalInsights/workspaces/sentinel'
        Mock Get-AzSubscription {
            [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222'; TenantId = $script:TestAzureContext.Tenant.Id }
            [pscustomobject]@{ Id = '44444444-4444-4444-4444-444444444444'; TenantId = $script:TestAzureContext.Tenant.Id }
        }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[]}' }
        } -ParameterFilter { $Path -match '/subscriptions/22222222-.*/providers/Microsoft.OperationalInsights/workspaces\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.SubscriptionIds.Count | Should -Be 2
        $result.data.Results[0].Sources[0].EventCount | Should -Be 7
        $result.data.Results[0].SentinelWorkspaceResourceId | Should -Be $script:TestWorkspaceId
        Should -Invoke Get-AzSubscription -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'does not issue resource requests against a subscription from a different tenant' {
        Mock Get-AzSubscription {
            [pscustomobject]@{ Id = '55555555-5555-5555-5555-555555555555'; TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.SubscriptionIds | Should -Not -Contain '55555555-5555-5555-5555-555555555555'
        Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly -ParameterFilter { $Path -match '55555555-' }
    }

    It 'uses independent tenant-scoped queries, a secure token and the requested lookback' {
        $null = Get-PurviewSentinelIntegrationData -LookbackDays 7
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly -ParameterFilter {
            $Authentication -eq 'Bearer' -and $Token -is [System.Security.SecureString] -and
            ($Body | ConvertFrom-Json).timespan -eq 'P7D' -and
            ($Body | ConvertFrom-Json).query.Contains("OrganizationId =~ '11111111-1111-1111-1111-111111111111'") -and
            ($Body | ConvertFrom-Json).query.Contains('ago(7d)')
        }
    }

    It 'adapts legacy string tokens to secure bearer authentication without changing ingestion results' {
        Mock Get-AzAccessToken {
            [pscustomobject]@{
                Token = 'synthetic-legacy-token'
                ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1)
                TenantId = $script:TestAzureContext.Tenant.Id
            }
        }
        (Get-PurviewSentinelIntegrationData).data.Results[0].Sources[0].EventCount | Should -Be 7
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly -ParameterFilter { $Token -is [System.Security.SecureString] }
    }

    It 'detects Sentinel without treating ordinary workspace onboarding 404s as incomplete evidence' {
        $script:OrdinaryWorkspaceId = $script:TestWorkspaceId -replace '/sentinel$', '/ordinary-logs'
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = (@{ value = @(
                @{ id = $script:TestWorkspaceId }
                @{ id = $script:OrdinaryWorkspaceId }
            ) } | ConvertTo-Json -Depth 10) }
        } -ParameterFilter { $Path -match '/providers/Microsoft.OperationalInsights/workspaces\?' }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"properties":{"customerId":"66666666-6666-6666-6666-666666666666"}}' }
        } -ParameterFilter { $Path -match '/workspaces/ordinary-logs\?' }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 404; Content = (@{ error = @{
                code = 'NotFound'; message = "Microsoft Sentinel was not found on the workspace 'ordinary-logs'"
            } } | ConvertTo-Json -Depth 5) }
        } -ParameterFilter { $Path -match '/workspaces/ordinary-logs/providers/Microsoft.SecurityInsights/onboardingStates\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Success'
        $result.data.SentinelWorkspaces | Should -Contain $script:TestWorkspaceId
        $result.data.SentinelWorkspaces | Should -Not -Contain $script:OrdinaryWorkspaceId
        $result.limitations.Count | Should -Be 0
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Reason | Should -Not -Match 'HTTP 404|Read limitations'
        ($outcome.Observed -join ' ') | Should -Not -Match 'HTTP 404|ordinary-logs'
    }

    It 'does not require a particular connector instance when tenant-attributed telemetry is present' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[]}' }
        } -ParameterFilter { $Path -match '/dataConnectors\?' }
        $result = Get-PurviewSentinelIntegrationData
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.SentinelValue | Should -Be '1'
        $outcome.SentinelReason | Should -Match 'sentinel'
        $outcome.Status | Should -Be 'Pass'
        $outcome.Value | Should -Be 'Events observed'
    }

    It 'retains detected Sentinel presence when the connector read is denied and data is absent' {
        $script:TestQueryResult = $script:EmptyQueryResult
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed"}}' }
        } -ParameterFilter { $Path -match '/dataConnectors\?' }
        $result = Get-PurviewSentinelIntegrationData
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.SentinelValue | Should -Be '1'
        $outcome.Status | Should -Be 'NeedsReview'
    }

    It 'does not mistake an unrelated onboarding 404 for confirmed Sentinel absence' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 404; Content = '{"error":{"code":"ResourceNotFound","message":"The requested resource was not found."}}' }
        } -ParameterFilter { $Path -match '/onboardingStates\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results.Count | Should -Be 0
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).SentinelValue |
            Should -Be 'not checked'
    }

    It 'keeps observed IRM alerts qualified when the source tenant is not exposed by the schema' {
        Mock Invoke-RestMethod {
            param($Body)
            if (($Body | ConvertFrom-Json).query.StartsWith('SecurityAlert')) { $script:TestQueryResult }
            else { $script:EmptyQueryResult }
        }
        $result = Get-PurviewSentinelIntegrationData
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.SentinelValue | Should -Be '1'
        $outcome.Value | Should -Be 'IRM alerts observed'
        $outcome.Status | Should -Be 'NeedsReview'
        $outcome.Reason | Should -Match 'source tenant cannot be verified'
    }

    It 'does not suppress an accessible MIP source when OfficeActivity is unavailable' {
        Mock Invoke-RestMethod {
            param($Body)
            $query = ($Body | ConvertFrom-Json).query
            if ($query.StartsWith('OfficeActivity')) {
                throw "Failed to resolve table or column expression named 'OfficeActivity'"
            }
            if ($query.StartsWith('MicrosoftPurviewInformationProtection')) { return $script:TestQueryResult }
            return $script:EmptyQueryResult
        }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.Results[0].Sources[0].QueryState | Should -Be 'Unavailable'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Status | Should -Be 'Pass'
        $outcome.Reason | Should -Match 'Information Protection'
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly
    }

    It 'does not turn an HTTP 200 partial query response with rows into confirmed ingestion' {
        $script:TestQueryResult | Add-Member -MemberType NoteProperty -Name error -Value @{ code = 'PartialError'; message = 'Results were incomplete.' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results[0].Sources[0].QueryState | Should -Be 'Failed'
        $result.data.Results[0].Sources[0].EventCount | Should -BeNullOrEmpty
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'NeedsReview'
    }

    It 'does not replace a malformed detail aggregate with zero or claim complete data' {
        $script:TestQueryResult.tables[0].rows[0][2] = 99
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results[0].Sources[0].QueryState | Should -Be 'Failed'
        (Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }).Status | Should -Be 'NeedsReview'
    }

    It 'keeps failures independent so audit ingestion can pass while IRM is unread' {
        Mock Invoke-RestMethod { throw 'HTTP 403: the SecurityAlert table is not authorized.' } -ParameterFilter {
            ($Body | ConvertFrom-Json).query.StartsWith('SecurityAlert')
        }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Status | Should -Be 'Pass'
        $outcome.LowConfidence | Should -BeTrue
        ($outcome.Observed -join ' ') | Should -Match 'Insider Risk alerts: not read'
    }

    It 'retains configured connectors but does not query when the workspace query ID is invalid' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"properties":{"customerId":"not-a-guid"}}' }
        } -ParameterFilter { $Path -match '/workspaces/sentinel\?' }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Results[0].Connectors[0].State | Should -Be 'Enabled'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'follows paginated connector lists before deciding configuration is missing' {
        $script:TestQueryResult = $script:EmptyQueryResult
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = (@{
                value = @(); nextLink = "https://management.azure.com$script:TestWorkspaceId/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2025-09-01&skip=2"
            } | ConvertTo-Json) }
        } -ParameterFilter { $Path -match '/dataConnectors\?' -and $Path -notmatch 'skip=2' }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"kind":"OfficeIRM","properties":{"tenantId":"11111111-1111-1111-1111-111111111111","dataTypes":{"alerts":{"state":"Enabled"}}}}]}' }
        } -ParameterFilter { $Path -match '/dataConnectors\?.*skip=2' }
        $result = Get-PurviewSentinelIntegrationData
        $result.data.Results[0].Connectors[0].Kind | Should -Be 'OfficeIRM'
        $outcome = Get-PurviewSentinelIntegrationOutcome -Snapshot @{ collectorResults = @($result) }
        $outcome.Value | Should -Be 'Configured; ingestion not confirmed'
    }
}

Describe 'Log Analytics summary parsing' {
    It 'maps named columns rather than assuming their ordinal order' {
        $response = '{"tables":[{"columns":[{"name":"LastEventUtc"},{"name":"EventCount"}],"rows":[["2026-09-24T12:00:00Z",7]]}]}' | ConvertFrom-Json
        (ConvertFrom-PurviewLogAnalyticsSummary -Response $response).EventCount | Should -Be 7
    }

    It 'preserves UTC event times when JSON conversion returns a DateTime value' {
        $response = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[1,"2026-09-24T08:00:00-04:00"]]}]}' | ConvertFrom-Json
        (ConvertFrom-PurviewLogAnalyticsSummary -Response $response).LastEventUtc | Should -Be '2026-09-24T12:00:00.0000000+00:00'
    }

    It 'rejects incomplete or malformed aggregates: <Name>' -TestCases @(
        @{ Name = 'no table'; Json = '{"tables":[]}' }
        @{ Name = 'no row'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[]}]}' }
        @{ Name = 'multiple rows'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[0,null],[0,null]]}]}' }
        @{ Name = 'missing column'; Json = '{"tables":[{"columns":[{"name":"EventCount"}],"rows":[[0]]}]}' }
        @{ Name = 'negative count'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[-1,null]]}]}' }
        @{ Name = 'null count'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[null,null]]}]}' }
        @{ Name = 'missing last event'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[1,null]]}]}' }
        @{ Name = 'timestamp without events'; Json = '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[0,"2026-09-24T12:00:00Z"]]}]}' }
        @{ Name = 'partial error'; Json = '{"error":{"code":"PartialError"},"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"}],"rows":[[0,null]]}]}' }
    ) {
        param($Name, $Json)
        { ConvertFrom-PurviewLogAnalyticsSummary -Response ($Json | ConvertFrom-Json) } | Should -Throw
    }
}

Describe 'ARM response handling' {
    BeforeEach {
        $script:TestAzureContext = New-TestAzureContext
    }

    It 'follows absolute nextLink pages without dropping resources' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"first"}],"nextLink":"https://management.azure.com/subscriptions/test/resources?api-version=1&skip=2"}' }
        }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"second"}]}' }
        } -ParameterFilter { $Path -match 'skip=2' }
        $result = Invoke-PurviewAzureGet -Path '/subscriptions/test/resources?api-version=1' -Context $script:TestAzureContext -List
        $result.value.Count | Should -Be 2
        $result.value[1].name | Should -Be 'second'
    }

    It 'does not turn an HTTP error into an empty resource list: <Code>' -TestCases @(
        @{ Code = 401 }
        @{ Code = 403 }
        @{ Code = 500 }
    ) {
        param($Code)
        $script:StatusCode = $Code
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = $script:StatusCode; Content = '{"error":{"code":"RequestFailed"}}' }
        }
        { Invoke-PurviewAzureGet -Path '/subscriptions/test/resources' -Context $script:TestAzureContext -List } |
            Should -Throw "*HTTP $Code*"
    }

    It 'rejects a list response without the documented value array' {
        Mock Invoke-AzRestMethod { [pscustomobject]@{ StatusCode = 200; Content = '{}' } }
        { Invoke-PurviewAzureGet -Path '/subscriptions/test/resources' -Context $script:TestAzureContext -List } |
            Should -Throw '*expected resource list*'
    }

    It 'does not follow a pagination URL outside ARM' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[],"nextLink":"https://example.test/collect"}' }
        }
        { Invoke-PurviewAzureGet -Path '/subscriptions/test/resources' -Context $script:TestAzureContext -List } |
            Should -Throw '*unexpected ARM pagination*'
        Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly
    }

    It 'rejects a repeated pagination link instead of looping' {
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[],"nextLink":"/subscriptions/test/resources"}' }
        }
        { Invoke-PurviewAzureGet -Path '/subscriptions/test/resources' -Context $script:TestAzureContext -List } |
            Should -Throw '*repeated ARM page*'
        Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly
    }
}
