Set-StrictMode -Version Latest
if (-not $env:PURVIEW_ADVISOR_TEST_MODE) { throw 'This synthetic Azure module is only for regression tests.' }

function Get-AzRoleAssignment {
    [CmdletBinding()]
    param([string]$SignInName, [string]$Scope, [object]$DefaultProfile)
    if ($env:PURVIEW_ADVISOR_TEST_MODE -eq 'rbac-denied') {
        throw 'AuthorizationFailed: the fixture denied role-assignment reads.'
    }
    if ($SignInName -ne 'operator@example.test' -or
        $Scope -ne '/subscriptions/22222222-2222-2222-2222-222222222222' -or
        $DefaultProfile.Account.Id -ne $SignInName) {
        throw 'The role read did not use the authenticated fixture context.'
    }
    [pscustomobject]@{ RoleDefinitionName = 'Reader' }
}

Export-ModuleMember -Function Get-AzRoleAssignment
