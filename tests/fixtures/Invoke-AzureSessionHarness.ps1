[CmdletBinding()]
param([Parameter(Mandatory)][string]$ResultPath)

. (Join-Path $PSScriptRoot 'Use-SyntheticAzure.ps1')
. (Join-Path $PSScriptRoot '..\..\Invoke-PurviewAdvisor.ps1')

function Get-PurviewExchangeConnection { param($Service) @() }
function Get-PurviewSignedInAccount { 'operator@example.test' }
function Test-PurviewConnected { param($Service) $true }
function Assert-PurviewSessionTenant {
    param([switch]$ExchangeOnly)
    $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
}
function Connect-MgGraph { param($LoginHint) throw 'The fixture must not initiate Graph sign-in.' }

$observed = $null
try {
    $services = @(Connect-PurviewSession)
    $collector = Get-PurviewSentinelIntegrationData -LookbackDays 7
    $observed = [ordered]@{
        Services = $services
        Azure = $script:AzureSession
        Role = $script:AzureRole
        RoleDetail = $script:AzureRoleDetail
        ContextPath = $script:AzureSessionContextPath
        Collector = $collector
        ContextRemoved = $false
    }
}
finally {
    Clear-PurviewRunState
}
if ($null -ne $observed) {
    $observed.ContextRemoved = -not $observed.ContextPath -or -not (Test-Path -LiteralPath $observed.ContextPath)
    $observed | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $ResultPath -Encoding utf8
}
