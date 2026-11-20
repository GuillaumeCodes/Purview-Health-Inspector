BeforeAll {
    . (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')

    function Get-MgContext {
        [CmdletBinding()]
        param()
        throw 'Unexpected live Graph context read in a test.'
    }

    function Export-ContentExplorerData {
        [CmdletBinding()]
        param([string]$TagType, [string]$TagName, [int]$PageSize)
        throw 'Unexpected live Content Explorer read in a test.'
    }
}

Describe 'Azure identity follows the existing tenant safeguards' {
    BeforeEach {
        $script:GraphSeparate = $false
        $script:ExpectedTenantId = ''
        $script:AzureSession = [pscustomobject]@{
            Connected = $true
            TenantId = '11111111-1111-1111-1111-111111111111'
            SubscriptionId = '22222222-2222-2222-2222-222222222222'
            AccountId = 'operator@example.test'
        }
        Mock Test-PurviewCommand { $false }
        Mock Get-PurviewExchangeConnection {
            [pscustomobject]@{ TenantID = '11111111-1111-1111-1111-111111111111' }
        }
    }

    It 'accepts Azure and Microsoft 365 in the same tenant' {
        (Get-PurviewSessionTenantState).Valid | Should -BeTrue
    }

    It 'rejects cross-tenant Azure and Microsoft 365 sessions' {
        $script:AzureSession.TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        (Get-PurviewSessionTenantState).Valid | Should -BeFalse
        { Assert-PurviewSessionTenant } | Should -Throw '*different tenants*'
    }

    It 'does not treat a failed Azure sign-in as another connected tenant' {
        $script:AzureSession = [pscustomobject]@{ Connected = $false; Error = 'Authentication cancelled.' }
        (Get-PurviewSessionTenantState).Valid | Should -BeTrue
    }

    It 'retains authenticated subscriptionless identity for tenant verification without listing Azure' {
        $script:AzureSession.Connected = $false
        $script:AzureSession | Add-Member -NotePropertyName NoSubscriptions -NotePropertyValue $true
        Mock Test-PurviewConnected { $true }
        (Get-PurviewSessionTenantState).Valid | Should -BeTrue
        (Get-PurviewTenantIdentity).tenantId | Should -Be '11111111-1111-1111-1111-111111111111'
        (Get-PurviewSignInContext).Service | Should -Not -Contain 'Azure'
        $script:AzureSession.TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        { Assert-PurviewSessionTenant } | Should -Throw '*different tenants*'
    }

    It 'includes a verified Azure session in the existing signed-in service list' {
        Mock Test-PurviewConnected { $false }
        $context = Get-PurviewSignInContext
        $context.Service | Should -Contain 'Azure'
        $context.Account | Should -Be 'operator@example.test'
    }

    It 'uses the verified Azure identity for an Azure-only snapshot header' {
        $tenant = Get-PurviewTenantIdentity
        $tenant.tenantId | Should -Be '11111111-1111-1111-1111-111111111111'
    }

    It 'uses collected Azure identity when SkipConnect did not run a sign-in worker' {
        $script:AzureSession = $null
        $collector = [pscustomobject]@{
            collector = 'SentinelPurviewIntegration'
            status = 'Success'
            data = @{ TenantId = '11111111-1111-1111-1111-111111111111'; AccountId = 'operator@example.test' }
        }
        $tenant = Get-PurviewTenantIdentity -CollectorResult @($collector)
        $tenant.tenantId | Should -Be '11111111-1111-1111-1111-111111111111'
    }
}

Describe 'Azure worker failures use ordinary collector results' {
    BeforeEach {
        $script:IsSentinelWorker = $false
        $script:AzureSession = $null
        $script:AzureSessionContextPath = ''
        $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
        $script:TempArtifact = @()
        $script:WorkerMode = 'Failure'
        $script:EvidenceTenant = $script:ExpectedTenantId
        Mock Get-PurviewPowerShell7Path { 'fixture-pwsh.exe' }
        Mock Start-Process {
            param($ArgumentList, $RedirectStandardError)
            $outputPath = $ArgumentList[[array]::IndexOf($ArgumentList, '-SentinelOutputPath') + 1].Trim('"')
            if ($script:WorkerMode -eq 'Failure') {
                'The required Azure module does not exist.' | Set-Content -LiteralPath $RedirectStandardError
            }
            elseif ($script:WorkerMode -eq 'Malformed') {
                '{' | Set-Content -LiteralPath $outputPath
            }
            elseif ($script:WorkerMode -eq 'Success') {
                @{
                    collector = 'SentinelPurviewIntegration'
                    status = 'Success'
                    data = @{ TenantId = $script:EvidenceTenant; Results = @() }
                    errors = @()
                    limitations = @()
                } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $outputPath
            }
            $process = [pscustomobject]@{
                ExitCode = if ($script:WorkerMode -eq 'Failure') { 1 } else { 0 }
                Handle = 1
                HasExited = $true
            }
            $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
            $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
            return $process
        }
    }

    It 'does not turn an Azure module-not-found failure into legacy empty Success' {
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Failed'
        $result.errors[0].message | Should -Match 'does not exist'
    }

    It 'preserves the absence-like mapping used by existing Microsoft 365 collectors' {
        $result = Invoke-PurviewCollector -Collector 'ExistingCollector' -SolutionArea 'Audit' `
            -Interface 'Fixture' -Kind 'MicrosoftGraph' -RequiredCommand @() -Collect { throw 'The object does not exist.' }
        $result.status | Should -Be 'Success'
    }

    It 'returns a failed collector rather than aborting the assessment: <Mode>' -TestCases @(
        @{ Mode = 'Malformed' }
        @{ Mode = 'Missing' }
    ) {
        param($Mode)
        $script:WorkerMode = $Mode
        (Get-PurviewSentinelIntegrationData).status | Should -Be 'Failed'
    }

    It 'does not collect through a stale default after the user cancels sign-in' {
        $script:AzureSession = [pscustomobject]@{ Connected = $false; Error = 'Authentication cancelled.' }
        (Get-PurviewSentinelIntegrationData).status | Should -Be 'NotConnected'
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'persists a confirmed exclusion without launching the Sentinel worker' {
        $script:AzureSession = [pscustomobject]@{
            Connected = $false
            NoSubscriptions = $true
            TenantId = $script:ExpectedTenantId
            AccountId = 'operator@example.test'
        }
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'NotApplicable'
        $result.data.NoSubscriptions | Should -BeTrue
        $result.errors.Count | Should -Be 0
        $result.limitations.Count | Should -Be 0
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'passes the explicit context and tenant to the noninteractive collector' {
        $script:WorkerMode = 'Success'
        $script:AzureSessionContextPath = Join-Path $TestDrive 'context with spaces.json'
        (Get-PurviewSentinelIntegrationData).status | Should -Be 'Success'
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $ArgumentList -contains '-NonInteractive' -and $ArgumentList -contains '-AzureContextPath' -and
            $ArgumentList -contains '-AzureTenantId' -and $ArgumentList -contains '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'refuses a worker result from another tenant' {
        $script:WorkerMode = 'Success'
        $script:EvidenceTenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $result = Get-PurviewSentinelIntegrationData
        $result.status | Should -Be 'Failed'
        $result.errors[0].message | Should -Match 'different or unverified tenant'
    }
}

Describe 'Subscriptionless snapshot collection' {
    BeforeEach {
        $script:IsSentinelWorker = $false
        $script:AzureSession = [pscustomobject]@{
            Connected = $false
            NoSubscriptions = $true
            TenantId = '11111111-1111-1111-1111-111111111111'
            AccountId = 'operator@example.test'
        }
        Mock Test-PurviewCommand { $false }
        Mock Get-PurviewCloudAppConnectorData {
            [pscustomobject]@{ collector = 'CloudAppConnector'; status = 'Success'; data = @{} }
        }
        Mock Get-PurviewDataSecurityTelemetryData {
            [pscustomobject]@{ collector = 'DataSecurityTelemetry'; status = 'Success'; data = @{} }
        }
        Mock Get-PurviewProtectedFilesConsentData {
            [pscustomobject]@{ collector = 'ProtectedFilesConsent'; status = 'Success'; data = @{} }
        }
        Mock Write-PurviewStep { }
        Mock Write-PurviewStepResult { }
        Mock Start-Process { throw 'An excluded workload must not start a worker.' }
    }

    It 'skips the Azure worker and progress row while retaining all Microsoft 365 posture checks' {
        $snapshot = Get-PurviewTenantSnapshot -SolutionArea PostureValidation
        $snapshot.collectorResults.Count | Should -Be 4
        @($snapshot.collectorResults | Where-Object status -eq 'Success').Count | Should -Be 3
        ($snapshot.collectorResults | Where-Object collector -eq 'SentinelPurviewIntegration').status | Should -Be 'NotApplicable'
        Should -Invoke Start-Process -Times 0 -Exactly
        Should -Invoke Get-PurviewCloudAppConnectorData -Times 1 -Exactly
        Should -Invoke Get-PurviewDataSecurityTelemetryData -Times 1 -Exactly
        Should -Invoke Get-PurviewProtectedFilesConsentData -Times 1 -Exactly
        Should -Invoke Write-PurviewStep -Times 0 -Exactly -ParameterFilter { $Name -eq 'SentinelPurviewIntegration' }
        Should -Invoke Write-PurviewStep -Times 3 -Exactly
        Should -Invoke Write-PurviewStepResult -Times 3 -Exactly -ParameterFilter { $Status -eq 'Success' }
        $script:StepIndex | Should -Be 3
        $script:StepTotal | Should -Be 3
    }
}

Describe 'Prerequisite and cleanup consistency' {
    It 'keeps both Azure modules out of the Microsoft 365 process' {
        Mock Get-Module {
            [pscustomobject]@{ Name = 'FixtureModule'; Version = [version]'99.0.0'; Path = 'fixture.psd1' }
        } -ParameterFilter {
            $ListAvailable -and $Name -in 'Az.Accounts', 'Az.Resources', 'ExchangeOnlineManagement',
                'Microsoft.Graph.Authentication', 'Microsoft.Online.SharePoint.PowerShell'
        }
        Mock Import-Module { }
        Mock Import-PurviewSharePointModule { }
        Mock Get-Command { $null }
        $modules = @(Install-PurviewPrerequisite -SkipInstall)
        @($modules | Where-Object { $_.Service -eq 'Azure' -and $_.State -eq 'Present' }).Count | Should -Be 2
        Should -Invoke Import-Module -Times 0 -Exactly -ParameterFilter { $Name -in 'Az.Accounts', 'Az.Resources' }
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'Microsoft.Graph.Authentication' }
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
    }

    It 'stops owned workers and disconnects before deleting their context file' {
        $contextPath = Join-Path $TestDrive 'owned-context.json'
        '{}' | Set-Content -LiteralPath $contextPath
        $script:AzureSignInProcess = [pscustomobject]@{ Id = 999991; HasExited = $false }
        $script:SentinelProcess = [pscustomobject]@{ Id = 999992; HasExited = $false }
        $script:TempArtifact = @($contextPath)
        $script:AzureSessionContextPath = $contextPath
        Mock Stop-Process { }
        Mock Disconnect-PurviewSession {
            Test-Path -LiteralPath $script:AzureSessionContextPath | Should -BeTrue
        }
        Clear-PurviewRunState
        Should -Invoke Stop-Process -Times 1 -Exactly -ParameterFilter { $Id -eq 999991 }
        Should -Invoke Stop-Process -Times 1 -Exactly -ParameterFilter { $Id -eq 999992 }
        Test-Path -LiteralPath $contextPath | Should -BeFalse
    }
}

Describe 'Actionable collector access diagnostics' {
    BeforeEach {
        $script:GraphSeparate = $false
        $script:ExpectedTenantId = ''
        $script:GrantedGraphScope = @($script:GraphScope)
        $script:ReadReached = $false
        Mock Test-PurviewCommand { $true }
        Mock Get-MgContext {
            [pscustomobject]@{
                TenantId = '11111111-1111-1111-1111-111111111111'
                AuthType = 'Delegated'
                Scopes = $script:GrantedGraphScope
            }
        }
        Mock Start-Sleep { throw 'Access failures must not be retried.' }
    }

    It 'names an unavailable delegated permission and skips only that read: <Permission>' -TestCases @(
        @{ Permission = 'LicenseAssignment.Read.All'; Collector = 'Licensing'; Interface = 'GET /subscribedSkus' }
        @{ Permission = 'GroupSettings.Read.All'; Collector = 'ContainerLabel'; Interface = 'GET /groupSettings' }
        @{ Permission = 'Application.Read.All'; Collector = 'ProtectedFilesConsent'; Interface = 'GET /servicePrincipals' }
        @{ Permission = 'ThreatHunting.Read.All'; Collector = 'InsiderRiskSharing'; Interface = 'POST /security/runHuntingQuery' }
    ) {
        param($Permission, $Collector, $Interface)
        $script:GrantedGraphScope = @('User.Read')
        Test-PurviewConnected -Service Graph | Should -BeTrue
        $result = Invoke-PurviewCollector -Collector $Collector -SolutionArea Fixture `
            -Interface $Interface -Kind MicrosoftGraph -RequiredCommand @() -Collect {
            $script:ReadReached = $true
            [pscustomobject]@{ Count = 1 }
        }
        $result.status | Should -Be 'NotPermitted'
        $result.errors[0].missingPermissions | Should -Contain $Permission
        $result.errors[0].message | Should -Match ([regex]::Escape($Permission))
        $result.errors[0].guidance | Should -Match 'consent'
        $script:ReadReached | Should -BeFalse
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'accepts a documented higher permission instead of claiming the read scope is missing: <Scope>' -TestCases @(
        @{ Scope = 'Directory.Read.All'; Collector = 'Licensing'; Interface = 'GET /subscribedSkus' }
        @{ Scope = 'Directory.Read.All'; Collector = 'ContainerLabel'; Interface = 'GET /groupSettings' }
        @{ Scope = 'Directory.Read.All'; Collector = 'ProtectedFilesConsent'; Interface = 'GET /servicePrincipals' }
        @{ Scope = 'ThreatHunting.ReadWrite.All'; Collector = 'EndpointDeviceHealth'; Interface = 'POST /security/runHuntingQuery' }
    ) {
        param($Scope, $Collector, $Interface)
        $script:GrantedGraphScope = @('User.Read', $Scope)
        $result = Invoke-PurviewCollector -Collector $Collector -SolutionArea Fixture `
            -Interface $Interface -Kind MicrosoftGraph -RequiredCommand @() -Collect {
            $script:ReadReached = $true
            [pscustomobject]@{ Count = 1 }
        }
        $result.status | Should -Be 'Success'
        $result.errors.Count | Should -Be 0
        $script:ReadReached | Should -BeTrue
    }

    It 'keeps structured access denials ahead of retry and absence fallbacks: <Signal>' -TestCases @(
        @{ Signal = 'HTTP status' }
        @{ Signal = 'Graph error details' }
    ) {
        param($Signal)
        $failure = [System.InvalidOperationException]::new('The resource does not exist. Try again. Bearer fixture-secret')
        $script:AccessFailure = [System.Management.Automation.ErrorRecord]::new(
            $failure, 'FixtureFailure', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        if ($Signal -eq 'HTTP status') { $failure.Data['HttpStatusCode'] = 403 }
        else {
            $script:AccessFailure.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                '{"error":{"code":"Authorization_RequestDenied","message":"Access to this resource was denied."}}')
        }
        $result = Invoke-PurviewCollector -Collector InsiderRiskSharing -SolutionArea InsiderRisk `
            -Interface 'POST /security/runHuntingQuery' -Kind MicrosoftGraph -RequiredCommand @() `
            -AbsenceMeans 'The read was unavailable.' -Collect { throw $script:AccessFailure }
        $result.status | Should -Be 'NotPermitted'
        $result.errors[0].guidance | Should -Match 'Security Reader'
        $result.errors[0].guidance | Should -Match 'Insider Risk Management Analysts'
        $result.errors[0].missingPermissions.Count | Should -Be 0
        $result.errors[0].message | Should -Match 'resource does not exist'
        ($result | ConvertTo-Json -Depth 20) | Should -Not -Match 'fixture-secret'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'suggests Exchange RBAC for an unavailable cmdlet in a live Exchange session without asserting a missing role' {
        Mock Test-PurviewCommand { $false } -ParameterFilter { $Name -eq 'Get-RetentionPolicy' }
        Mock Test-PurviewConnected { $true } -ParameterFilter { $Service -eq 'ExchangeOnline' }
        $result = Invoke-PurviewCollector -Collector LegacyRetention -SolutionArea DataLifecycleManagement `
            -Interface 'Get-RetentionPolicy' -Kind ExchangeOnlinePowerShell -RequiredCommand Get-RetentionPolicy `
            -Collect { throw 'An unavailable read must not run.' }
        $result.status | Should -Be 'NotPermitted'
        $result.errors[0].guidance | Should -Match 'View-Only Organization Management'
        $result.errors[0].missingPermissions.Count | Should -Be 0
        $result.errors[0].message | Should -Match 'does not establish a missing role|cause is not established'
    }

    It 'retains successful Content Explorer counts and reports the permission behind a denied tag' {
        Mock Export-ContentExplorerData { [pscustomobject]@{ TotalCount = 12 } }
        Mock Export-ContentExplorerData { throw 'Forbidden: this tag is not authorized.' } -ParameterFilter { $TagName -eq 'Denied' }
        $tags = @('Allowed', 'Denied') | ForEach-Object {
            [pscustomobject]@{ Type = 'SensitiveInformationType'; Name = $_; UniqueName = $_ }
        }
        $result = Get-PurviewClassificationCoverageData -Tag $tags
        $result.status | Should -Be 'PartialSuccess'
        $result.data.Tags[0].TotalCount | Should -Be 12
        $result.errors.Count | Should -Be 1
        $result.errors[0].guidance | Should -Match 'Content Explorer List Viewer'
        $result.errors[0].message | Should -Match 'this tag is not authorized'
        $result.errors[0].missingPermissions.Count | Should -Be 0
    }

    It 'does not infer delegated permissions from an unverifiable context: <Case>' -TestCases @(
        @{ Case = 'empty scopes' }
        @{ Case = 'app-only context' }
        @{ Case = 'separate Graph process' }
    ) {
        param($Case)
        switch ($Case) {
            'empty scopes' { $script:GrantedGraphScope = @() }
            'app-only context' {
                Mock Get-MgContext { [pscustomobject]@{ AuthType = 'AppOnly'; Scopes = @('User.Read') } }
            }
            'separate Graph process' {
                $script:GrantedGraphScope = @('User.Read')
                $script:GraphSeparate = $true
            }
        }
        $result = Invoke-PurviewCollector -Collector Licensing -SolutionArea Licensing -Interface 'GET /subscribedSkus' `
            -Kind MicrosoftGraph -RequiredCommand @() -Collect { [pscustomobject]@{ Count = 1 } }
        $result.status | Should -Be 'Success'
        $result.errors.Count | Should -Be 0
    }

    It 'reports a rejected token as a connection gap rather than suggesting an additional role' {
        $script:TokenFailure = [System.InvalidOperationException]::new('The current token could not be accepted.')
        $script:TokenFailure.Data['HttpStatusCode'] = 401
        $result = Invoke-PurviewCollector -Collector EndpointDeviceHealth -SolutionArea EndpointDlp `
            -Interface 'POST /security/runHuntingQuery' -Kind MicrosoftGraph -RequiredCommand @() `
            -Collect { throw $script:TokenFailure }
        $result.status | Should -Be 'NotConnected'
        $result.errors[0].guidance | Should -Match 'Reconnect'
        $result.errors[0].guidance | Should -Not -Match 'Suggested.*Reader'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'does not invent permission guidance for an unrelated collector failure' {
        $result = Invoke-PurviewCollector -Collector Fixture -SolutionArea Audit -Interface Fixture `
            -Kind MicrosoftGraph -RequiredCommand @() -Collect { throw 'Invalid response schema.' }
        $result.status | Should -Be 'Failed'
        $result.errors[0].category | Should -Be 'Unexpected'
        Test-PurviewProperty -InputObject $result.errors[0] -Name guidance | Should -BeFalse
    }
}
