[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run these tests in PowerShell 7.' }
Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

$configuration = New-PesterConfiguration
$configuration.Run.Path = $PSScriptRoot
$configuration.Run.PassThru = $true
$configuration.TestRegistry.Enabled = $false
$configuration.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0 -or $result.PassedCount -eq 0) {
    exit 1
}
