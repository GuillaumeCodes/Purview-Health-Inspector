BeforeAll {
    . (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')
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
