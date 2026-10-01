$ErrorActionPreference = 'Stop'
if (-not $env:PURVIEW_ADVISOR_TEST_MODE) { throw 'The worker harness requires an explicit synthetic test mode.' }
$env:PSModulePath = $PSScriptRoot + [IO.Path]::PathSeparator + (Join-Path $PSHOME 'Modules')
$env:PATH = $PSHOME + [IO.Path]::PathSeparator + $env:PATH

function Start-Process {
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [string]$RedirectStandardError,
        [string]$RedirectStandardOutput,
        [string]$WindowStyle,
        [switch]$PassThru,
        [switch]$Wait,
        [switch]$NoNewWindow
    )

    # PowerShell startup can prepend real user module folders. Preload only the exact fixtures
    # in each child, then run the unmodified production worker and its real process protocol.
    $fileIndex = [array]::IndexOf($ArgumentList, '-File')
    if ($fileIndex -lt 0) { throw 'The fixture refuses to launch an unrecognized worker command.' }
    $workerPath = $ArgumentList[$fileIndex + 1].Trim('"')
    $workerParameters = @{}
    for ($index = $fileIndex + 2; $index -lt $ArgumentList.Count; $index++) {
        $name = $ArgumentList[$index].TrimStart('-')
        if ($name -in 'AzureSignInWorker', 'AzureSignOutWorker', 'SentinelWorker') {
            $workerParameters[$name] = $true
        }
        else {
            $index++
            $workerParameters[$name] = $ArgumentList[$index].Trim('"')
        }
    }
    $modules = ConvertTo-PurviewPowerShellLiteral -Value $env:PSModulePath
    $accounts = ConvertTo-PurviewPowerShellLiteral -Value (Join-Path $PSScriptRoot 'Az.Accounts\Az.Accounts.psm1')
    $resources = ConvertTo-PurviewPowerShellLiteral -Value (Join-Path $PSScriptRoot 'Az.Resources\Az.Resources.psm1')
    $worker = ConvertTo-PurviewPowerShellLiteral -Value $workerPath
    $parameters = ConvertTo-PurviewPowerShellLiteral -Value ($workerParameters | ConvertTo-Json -Compress)
    $bootstrap = @"
`$ErrorActionPreference = 'Stop'
`$env:PSModulePath = $modules
Import-Module -Name $accounts -Global -ErrorAction Stop
Import-Module -Name $resources -Global -ErrorAction Stop
if ((Get-Module Az.Accounts).Path -ne $accounts -or (Get-Module Az.Resources).Path -ne $resources) {
    throw 'The synthetic worker module isolation check failed.'
}
`$parameters = $parameters | ConvertFrom-Json -AsHashtable
& $worker @parameters
exit `$LASTEXITCODE
"@
    $launch = @{}
    foreach ($key in $PSBoundParameters.Keys) { $launch[$key] = $PSBoundParameters[$key] }
    $launch.ArgumentList = @('-NoLogo', '-NoProfile', '-OutputFormat', 'Text')
    if ($ArgumentList -contains '-NonInteractive') { $launch.ArgumentList += '-NonInteractive' }
    $launch.ArgumentList += @('-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap)))
    Microsoft.PowerShell.Management\Start-Process @launch
}
