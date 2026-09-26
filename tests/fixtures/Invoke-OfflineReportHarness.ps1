[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [Parameter(Mandatory)][string]$ReportFolder,
    [ValidateSet('Demo', 'Replay', 'SkipConnect')][string]$Mode = 'Demo',
    [string]$SnapshotPath = '',
    [switch]$Brief
)

$env:PURVIEW_ADVISOR_TEST_MODE = 'reuse'
. (Join-Path $PSScriptRoot 'Use-SyntheticAzure.ps1')
$arguments = @{ ReportFolder = $ReportFolder; NoRecord = $true; NoOpen = $true; Brief = $Brief }
switch ($Mode) {
    'Demo' { $arguments['Demo'] = $true }
    'Replay' {
        if (-not $SnapshotPath) { throw 'The replay fixture requires a snapshot path.' }
        $arguments['SnapshotPath'] = $SnapshotPath
    }
    'SkipConnect' {
        $arguments['Collect'] = $true
        $arguments['SkipConnect'] = $true
        $arguments['SkipModuleInstall'] = $true
        $arguments['SkipInsights'] = $true
        $arguments['Solution'] = 'InformationProtection'
    }
}
$global:LASTEXITCODE = 0
& $ScriptPath @arguments
exit $LASTEXITCODE
