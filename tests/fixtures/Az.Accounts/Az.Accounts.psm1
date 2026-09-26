Set-StrictMode -Version Latest
if ($env:PURVIEW_ADVISOR_TEST_MODE -notin 'fresh', 'reuse', 'expired', 'cancel', 'rbac-denied') {
    throw 'This synthetic Azure module is only for the inspector regression tests.'
}

function New-FixtureContext {
    [pscustomobject]@{
        Account = [pscustomobject]@{ Id = 'operator@example.test'; Type = 'User' }
        Tenant = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' }
        Subscription = [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222' }
        Environment = [pscustomobject]@{ Name = 'AzureCloud' }
        FixtureAuthenticated = $env:PURVIEW_ADVISOR_TEST_MODE -ne 'expired'
    }
}

$script:Context = if ($env:PURVIEW_ADVISOR_TEST_MODE -in 'fresh', 'cancel') { $null } else { New-FixtureContext }
$script:LoginExperienceV2 = 'On'

function Get-AzContext {
    [CmdletBinding()]
    param()
    $script:Context
}

function Connect-AzAccount {
    [CmdletBinding()]
    param([string]$Tenant, [string]$Environment)
    if ($Environment -ne 'AzureCloud' -or $Tenant -ne '11111111-1111-1111-1111-111111111111') {
        throw 'The fixture received an unexpected sign-in target.'
    }
    if ($script:LoginExperienceV2 -ne 'Off') { throw 'The fixture would block on an invisible subscription-selection prompt.' }
    Write-Host 'FIXTURE_AUTH_PENDING'
    Write-Warning 'Please select the account you want to login with.'
    [Console]::WriteLine('Retrieving subscriptions for the selection...')
    Start-Sleep -Milliseconds 200
    if ($env:PURVIEW_ADVISOR_TEST_MODE -eq 'cancel') { throw 'Authentication was cancelled by the fixture.' }
    $script:Context = New-FixtureContext
    $script:Context.FixtureAuthenticated = $true
    Write-Host 'FIXTURE_AUTH_COMPLETE'
}

function Get-AzAccessToken {
    [CmdletBinding()]
    param([string]$ResourceUrl, [string]$TenantId, [object]$DefaultProfile)
    if ($null -eq $script:Context -or $TenantId -ne $script:Context.Tenant.Id -or
        $DefaultProfile.Subscription.Id -ne $script:Context.Subscription.Id) {
        throw 'No active account in the fixture. Run Connect-AzAccount.'
    }
    [pscustomobject]@{
        Token = ConvertTo-SecureString 'synthetic-worker-token' -AsPlainText -Force
        ExpiresOn = if ($script:Context.FixtureAuthenticated) { [DateTimeOffset]::UtcNow.AddHours(1) }
            else { [DateTimeOffset]::UtcNow.AddHours(-1) }
        TenantId = $script:Context.Tenant.Id
    }
}

function Enable-AzContextAutosave {
    [CmdletBinding()]
    param([string]$Scope)
    if ($Scope -ne 'Process') { throw 'The fixture refuses a persistent autosave setting change.' }
}

function Update-AzConfig {
    [CmdletBinding()]
    param([string]$LoginExperienceV2, [string]$Scope)
    if ($Scope -ne 'Process' -or $LoginExperienceV2 -ne 'Off') {
        throw 'The fixture refuses any configuration change outside the worker login experience.'
    }
    $script:LoginExperienceV2 = $LoginExperienceV2
}

function Save-AzContext {
    [CmdletBinding()]
    param([string]$Path, [switch]$Force)
    $script:Context | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Import-AzContext {
    [CmdletBinding()]
    param([string]$Path, [string]$Scope)
    if ($Scope -ne 'Process') { throw 'The fixture refuses a persistent default-context change.' }
    $script:Context = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-AzSubscription {
    [CmdletBinding()]
    param([string]$TenantId, [object]$DefaultProfile)
    if ($TenantId -ne $script:Context.Tenant.Id) { throw 'The fixture received a cross-tenant subscription query.' }
    [pscustomobject]@{ Id = $script:Context.Subscription.Id; TenantId = $script:Context.Tenant.Id }
}

function Invoke-AzRestMethod {
    [CmdletBinding()]
    param([string]$Method, [string]$Path, [object]$DefaultProfile)
    if ($Method -ne 'GET' -or $null -eq $DefaultProfile) {
        throw "Unexpected resource operation in the fixture: $Method $Path"
    }
    $workspace = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/sentinel'
    $body = switch -Regex ($Path) {
        '^/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.OperationalInsights/workspaces\?' {
            @{ value = @(@{ id = $workspace }) }; break
        }
        '^/subscriptions/22222222-.*/workspaces/sentinel\?' {
            @{ properties = @{ customerId = '33333333-3333-3333-3333-333333333333' } }; break
        }
        '^/subscriptions/22222222-.*/workspaces/sentinel/providers/Microsoft.SecurityInsights/onboardingStates\?' {
            @{ value = @(@{ name = 'default' }) }; break
        }
        '^/subscriptions/22222222-.*/workspaces/sentinel/providers/Microsoft.SecurityInsights/dataConnectors\?' {
            @{ value = @(@{ kind = 'Office365'; properties = @{
                tenantId = '11111111-1111-1111-1111-111111111111'; dataTypes = @{ exchange = @{ state = 'Enabled' } }
            } }) }; break
        }
        default { throw "Unexpected resource path in the fixture: $Path" }
    }
    [pscustomobject]@{ StatusCode = 200; Content = ($body | ConvertTo-Json -Depth 20) }
}

function Invoke-RestMethod {
    [CmdletBinding()]
    param([string]$Method, [string]$Uri, [string]$Authentication, [securestring]$Token, [string]$ContentType, [string]$Body)
    if ($Method -ne 'POST' -or $Uri -ne 'https://api.loganalytics.io/v1/workspaces/33333333-3333-3333-3333-333333333333/query' -or
        $Authentication -ne 'Bearer' -or $null -eq $Token -or $Token.Length -eq 0) {
        throw 'The synthetic fixture refuses an unrecognized telemetry request.'
    }
    $query = [string]($Body | ConvertFrom-Json).query
    if ($query -match '^(OfficeActivity|MicrosoftPurviewInformationProtection)\r?\n') {
        if ($query -notmatch "OrganizationId =~ '11111111-1111-1111-1111-111111111111'") { throw 'The fixture query was not tenant-scoped.' }
    }
    elseif (-not $query.StartsWith('SecurityAlert')) { throw 'The fixture refuses an unrecognized table.' }
    if ($query.StartsWith('OfficeActivity')) {
        '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"},{"name":"LabelEventCount"},{"name":"LastLabelEventUtc"},{"name":"DlpEventCount"},{"name":"LastDlpEventUtc"}],"rows":[[5,"2026-09-24T12:00:00Z",1,"2026-09-24T12:00:00Z",0,null]]}]}' | ConvertFrom-Json
    }
    else {
        '{"tables":[{"columns":[{"name":"EventCount"},{"name":"LastEventUtc"},{"name":"LabelEventCount"},{"name":"LastLabelEventUtc"}],"rows":[[0,null,0,null]]}]}' | ConvertFrom-Json
    }
}

function Disconnect-AzAccount {
    [CmdletBinding()]
    param()
    $script:Context = $null
}

Export-ModuleMember -Function Get-AzContext, Connect-AzAccount, Get-AzAccessToken, Enable-AzContextAutosave,
    Update-AzConfig, Save-AzContext, Import-AzContext, Get-AzSubscription, Invoke-AzRestMethod, Invoke-RestMethod, Disconnect-AzAccount
