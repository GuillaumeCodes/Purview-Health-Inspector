BeforeAll {
    $script:HelpAdvisorPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\Invoke-PurviewAdvisor.ps1')).Path
    $script:HelpPowerShell = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
}

Describe 'Full option list without an assessment' {
    It 'lists public options and exits without setup, sign-in or report writes in <Runtime>' -TestCases @(
        @{ Runtime = 'PowerShell 7' }
        @{ Runtime = 'Windows PowerShell 5.1' }
    ) {
        param($Runtime)
        if ($Runtime -eq 'Windows PowerShell 5.1' -and -not $IsWindows) {
            Set-ItResult -Skipped -Because 'Windows PowerShell 5.1 is available only on Windows.'
            return
        }
        $shell = if ($Runtime -eq 'Windows PowerShell 5.1') {
            Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        }
        else { $script:HelpPowerShell }
        $reportFolder = Join-Path $TestDrive 'no-help-report'
        $exportPath = Join-Path $TestDrive 'no-help-export.json'
        $missingRule = Join-Path $TestDrive 'missing-rules.json'
        $output = @(& $shell -NoLogo -NoProfile -NonInteractive -File $script:HelpAdvisorPath `
            -Help -Collect -ProtectPdf -ReportFolder $reportFolder -ExportRules $exportPath -RuleFile $missingRule 2>&1)
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        $text = $output -join "`n"

        $parameters = (Get-Command -Name $script:HelpAdvisorPath).Parameters
        $publicNames = @($parameters.Values | Where-Object {
                $_.Name -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and
                $_.Name -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters -and
                @($_.Attributes | Where-Object {
                        $_ -is [System.Management.Automation.ParameterAttribute] -and $_.DontShow
                    }).Count -eq 0
            } | ForEach-Object Name)
        foreach ($name in $publicNames) {
            $text | Should -Match ("(?m)^\s*-{0}(?:\s|$)" -f [regex]::Escape($name))
        }
        $text | Should -Match '(?i)password'
        $text | Should -Not -Match 'AzureSignInWorker|AzureSignOutWorker|SentinelWorker|AzureContextPath|SentinelOutputPath'
        $text | Should -Not -Match 'Restarting in PowerShell 7|Assessing your tenant|^\s*Signing in|FIXTURE_AUTH_'
        Test-Path -LiteralPath $reportFolder | Should -BeFalse
        Test-Path -LiteralPath $exportPath | Should -BeFalse
    }

    It 'documents encrypted PDF export and the help switch in the short README list' {
        $readme = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\README.md') -Raw
        $section = [regex]::Match($readme, '(?s)### Common options\r?\n(.*?)\r?\n## Prerequisites').Groups[1].Value
        $section | Should -Match '\| `-ProtectPdf` \|'
        $section | Should -Match '\| `-Help` \|'
        $section | Should -Match '(?i)password'
        [regex]::Matches($section, '(?m)^\| `-').Count | Should -BeLessOrEqual 7
    }
}
