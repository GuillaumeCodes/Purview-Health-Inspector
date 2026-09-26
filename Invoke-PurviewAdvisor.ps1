<#
.SYNOPSIS
    Assesses Microsoft Purview configuration against evidence-based rules and reports the result.

.DESCRIPTION
    Collects Microsoft Purview configuration, evaluates it against built-in deterministic rules,
    and produces a console summary plus HTML and JSON reports in one self-contained script.

    Supported scope is the Microsoft 365 commercial cloud, including education tenants in that
    cloud. GCC, GCC High, DoD and China are not supported or validated by this release.

    Collection does not change tenant configuration. It uses read and export cmdlets and API queries,
    including hunting POST requests; setup can install local modules. Anything you are not
    connected to is reported as not collected, so a partial run still tells you what it could reach.

    Collection produces a snapshot; analysis reads only that snapshot. The same snapshot yields
    the same findings, so results can be re-examined after the tenant configuration changes.

    Built-in rules carry source references, retrieval dates and confidence levels. These support
    review, not certification of the rule. Where a fix exists, it is printed for you to review
    and run yourself. This script never runs it.

.PARAMETER Collect
    Collect tenant configuration and assess it. This is the default.

.PARAMETER TenantAdminUrl
    Your SharePoint admin URL, https://<tenant>-admin.sharepoint.com. Only needed to sign in to
    SharePoint; you are asked for it otherwise, and skipping it just omits the SharePoint checks.

.PARAMETER Environment
    Commercial is the default and only accepted value, including education tenants in that cloud.
    This selects connection defaults. Tenant IDs are compared across Graph, Security & Compliance,
    Exchange Online and Azure where available. Azure must use AzureCloud; the cloud of existing
    Microsoft 365 sessions is not independently verified.

.PARAMETER Solution
    Assess only the named Purview solutions instead of all of them. Anything not named is neither
    collected nor scored, and the report says which solutions were in scope.

.PARAMETER Brief
    Write the condensed report: what is configured, the summary, what to do, and the limitations.
    Only report detail changes; the assessment is unchanged.

.PARAMETER SkipConnect
    Do not sign in to anything. Use only sessions you established yourself.
    Graph, Security & Compliance and Exchange Online must report one consistent tenant ID or collection
    stops. The Azure worker also refuses a context from another tenant and never prompts in this mode.
    You must still verify the SharePoint session and supported commercial cloud yourself.

.PARAMETER LookbackDays
    Lookback window in days for Microsoft 365 audit and compliance telemetry in Sentinel, defaulting to 30.
    An empty window does not establish that a configured connection is broken.

.PARAMETER SnapshotPath
    Assess a snapshot already on disk.

.PARAMETER SnapshotOutputPath
    Where collection writes the snapshot. Defaults to snapshot.json in the report folder.

.PARAMETER SkipModuleInstall
    Do not install missing modules; use only what is already present.

.PARAMETER IncludeSites
    Also enumerate SharePoint sites. Slow on a large tenant.

.PARAMETER SiteLimit
    Maximum sites to enumerate with -IncludeSites.

.PARAMETER RedactTenant
    Blank the tenant name and id in the snapshot. Other identifying configuration remains;
    review the output before sharing it outside the customer. Generated remediation then cannot
    bind Graph, compliance and Exchange Online changes to the assessed tenant ID; verify sign-ins manually.

.PARAMETER SkipInsights
    Skip Activity Explorer label events, requested Content Explorer counts and SharePoint
    oversharing report metadata. Other applicable telemetry and consent reads still run.

.PARAMETER InsightDays
    Days of activity to summarise, defaulting to a rolling 30-day window, the most Activity Explorer
    retains. This controls the sensitivity-label application-operation count, not the delayed
    Content Explorer counts requested with -InsightTag. An event absent from the window is not proof
    that a label is unused.

.PARAMETER InsightTag
    Sensitive information type names to ask Content Explorer for. No sensitivity labels are
    requested automatically because the accepted TagName identity is not documented. Repeated names
    are collapsed case-insensitively. Each delayed count is reported independently and never summed,
    because one item can match more than one type.

.PARAMETER BaselineFolder
    Folder of saved posture records. Defaults to a per-user folder, so a later run can compare
    against this one wherever you run it from.

.PARAMETER NoRecord
    Do not save this run's posture.

.PARAMETER BaselinePath
    Compare against this specific posture record instead of the most recent. Use -NoRecord to
    prevent saving the current run's posture.

.PARAMETER AcrossTenants
    Allow the -BaselinePath record to belong to a different tenant, for comparing a lab against
    production. The report says the comparison is across tenants and does not call a difference
    progress. Refused without -BaselinePath, so one customer is never silently compared to another.

.PARAMETER ReportFolder
    Where to write the report. Defaults to a PurviewReport folder in the current directory.
    Files written by a run overwrite the same paths; other files remain. Treat reports as customer data.

.PARAMETER NoOpen
    Do not open the report when it is finished.

.PARAMETER DarkMode
    Render the report on a dark background. Affects the HTML and any PDF made from it.

.PARAMETER PdfReport
    Also render the report to PDF. Needs Edge, Chrome or Chromium installed.

.PARAMETER ProtectPdf
    Encrypt the PDF so it cannot be opened without a password, which you are asked for. Needs qpdf,
    because the browser export does not encrypt it. If encryption fails, deletion is attempted;
    verify the output folder. Other report formats remain unencrypted.

.PARAMETER WordReport
    Also convert the report to .docx. Needs Word on Windows.

.PARAMETER CheckEvidence
    Check URLs in the built-in evidence registry and compare available content fingerprints.
    This does not verify every citation in the script or whether a source supports a claim.

.PARAMETER RuleFile
    Assess using rules from this JSON file. Rules sharing an id with a built-in replace it, so one
    check can be corrected without restating the rest.

.PARAMETER ExportRules
    Write the built-in rules and citations to this path and stop. Edit that file and pass it back
    with -RuleFile.

.PARAMETER PassThru
    Returns the findings as objects so you can filter or pipe them.

.PARAMETER Demo
    Create a sample report from fabricated data without signing in to a tenant.

.PARAMETER Help
    Show the full list of user options and stop without signing in or running an assessment.

.EXAMPLE
    .\Invoke-PurviewAdvisor.ps1

    Assesses your tenant. Installs what it needs, signs you in for anything you are not already
    connected to, and prints the result. Launched from Windows PowerShell it restarts itself in
    PowerShell 7.

.EXAMPLE
    Connect-IPPSSession
    Connect-SPOService -Url https://contoso-admin.sharepoint.com -UseSystemBrowser $true
    Connect-MgGraph -Scopes LicenseAssignment.Read.All, GroupSettings.Read.All
    .\Invoke-PurviewAdvisor.ps1 -Collect -ReportFolder .\out

.EXAMPLE
    .\Invoke-PurviewAdvisor.ps1 -Collect -RedactTenant -PassThru |
        Where-Object status -eq 'Fail'

.EXAMPLE
    .\Invoke-PurviewAdvisor.ps1 -Collect -BaselineFolder .\posture

    Assess configuration against observed activity, then record the result so the next run can
    report what moved.

.NOTES
    The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official
    Microsoft guidance used as references for selected checks. This script is not a
    Microsoft product: it reads what is configured in a tenant and reports it against those
    recommendations. It describes configuration observed at a point in time and is not a
    compliance certification.
#>

[CmdletBinding()]
param(
    [switch]$Collect,
    [string]$SnapshotPath = '',
    [string]$SnapshotOutputPath = '',
    [string]$TenantAdminUrl = '',
    [ValidateSet('Commercial')][string]$Environment = 'Commercial',
    [ValidateSet('InformationProtection', 'DataLossPrevention', 'DataLifecycleManagement', 'RecordsManagement', 'CommunicationCompliance', 'InsiderRisk', 'Audit')][string[]]$Solution = @(),
    [switch]$Brief,
    [switch]$SkipConnect,
    [switch]$SkipModuleInstall,
    [switch]$IncludeSites,
    [int]$SiteLimit = 200,
    [switch]$RedactTenant,
    [switch]$SkipInsights,
    [ValidateRange(1, 30)][int]$InsightDays = 30,
    [ValidateRange(1, 3650)][int]$LookbackDays = 30,
    [string[]]$InsightTag = @(),
    [string]$BaselineFolder = '',
    [string]$BaselinePath = '',
    [switch]$AcrossTenants,
    [switch]$NoRecord,
    [string]$ReportFolder = '',
    [switch]$NoOpen,
    [switch]$DarkMode,
    [switch]$PdfReport,
    [switch]$ProtectPdf,
    [switch]$WordReport,
    [switch]$CheckEvidence,
    [string]$RuleFile = '',
    [string]$ExportRules = '',
    [switch]$Demo,
    [switch]$PassThru,
    [switch]$Help,
    [Parameter(DontShow)][switch]$SentinelWorker,
    [Parameter(DontShow)][switch]$AzureSignInWorker,
    [Parameter(DontShow)][switch]$AzureSignOutWorker,
    [Parameter(DontShow)][string]$AzureSignInOutputPath = '',
    [Parameter(DontShow)][string]$AzureContextPath = '',
    [Parameter(DontShow)][string]$AzureTenantId = '',
    [Parameter(DontShow)][string]$SentinelOutputPath = '',
    [Parameter(DontShow)][ValidateRange(1, 3650)][int]$SentinelLookbackDays = 30
)

if ($Help) {
    $helpParameters = (Get-Command -Name $PSCommandPath -ErrorAction Stop).Parameters
    Get-Help -Name $PSCommandPath -Parameter * -ErrorAction Stop |
        Where-Object {
            $metadata = $helpParameters[$_.name]
            $null -ne $metadata -and @($metadata.Attributes | Where-Object {
                    $_ -is [System.Management.Automation.ParameterAttribute] -and $_.DontShow
                }).Count -eq 0
        }
    return
}

# Keep the entire file 5.1-parseable so Windows PowerShell can reach the PowerShell 7 relaunch.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $candidates = @()
    $onPath = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { $candidates += $onPath.Source }

    # Join-Path throws on a null root, and these variables are not guaranteed to be set.
    foreach ($pair in @(
            @($env:ProgramFiles, 'PowerShell\7\pwsh.exe'),
            @(${env:ProgramFiles(x86)}, 'PowerShell\7\pwsh.exe'),
            @($env:LOCALAPPDATA, 'Microsoft\WindowsApps\pwsh.exe'))) {
        if ($pair[0]) { $candidates += (Join-Path $pair[0] $pair[1]) }
    }

    $pwsh = $null
    foreach ($candidate in $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique) {
        try {
            $probeErrorPreference = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            $probe = @(& $candidate -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.Major' *>&1)
            $ErrorActionPreference = $probeErrorPreference
            if ($LASTEXITCODE -eq 0 -and @($probe | Where-Object { [int]$_ -ge 7 }).Count -gt 0) {
                $pwsh = $candidate
                break
            }
        }
        catch { $ErrorActionPreference = $probeErrorPreference }
    }

    if (-not $pwsh) {
        Write-Host ''
        Write-Host '  This needs PowerShell 7, and it is not installed.' -ForegroundColor Yellow
        Write-Host '  Install it, then run this again:' -ForegroundColor Gray
        Write-Host '    winget install --id Microsoft.PowerShell --source winget' -ForegroundColor Gray
        Write-Host ''
        exit 1
    }

    Write-Host ''
    Write-Host '  Restarting in PowerShell 7.' -ForegroundColor DarkGray

    $forward = @()
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Value -is [switch]) {
            if ($entry.Value.IsPresent) { $forward += "-$($entry.Key)" }
        }
        elseif ($entry.Value -is [array]) {
            $forward += "-$($entry.Key)"
            $forward += @($entry.Value | ForEach-Object { [string]$_ })
        }
        else {
            $forward += "-$($entry.Key)"
            $forward += [string]$entry.Value
        }
    }

    & $pwsh -NoLogo -NoProfile -File $PSCommandPath @forward
    exit $LASTEXITCODE
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Record the version in snapshots, findings and posture records to trace results to their checks
# and distinguish rule changes from tenant changes.
$script:ToolVersion = '1.63.90'
$script:IsSentinelWorker = $SentinelWorker.IsPresent

# Anything the run creates and must undo before it exits.
$script:OwnedSession = @()
$script:OwnedCompatibilitySession = @()
$script:OwnedCompatibilityModule = @()
$script:OwnedExchangeConnectionId = @()
$script:HadPreExistingExchangeConnection = $false
$script:AzureSignInProcess = $null
$script:SentinelProcess = $null
$script:AzureSession = $null
$script:AzureSessionContextPath = ''
$script:AzureRole = @()
$script:AzureRoleDetail = 'not read; Azure RBAC role assignments could not be determined'
$script:ExpectedTenantId = ''
$script:TempArtifact = @()

# Kept so a connection failure can report the actual module load result rather than replacing it
# with a generic platform message.
$script:PrerequisiteModuleResult = @()

# Whether a cmdlet exists, remembered for the run. Emptied whenever a connect could change it.
$script:CommandCache = @{}

function Get-PurviewPowerShell7Path {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $executable = if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' }
        $candidates.Add((Join-Path $PSHOME $executable))
    }
    $onPath = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) {
        $candidates.Add([string]$onPath.Source)
    }
    foreach ($pair in @(
            @($env:ProgramFiles, 'PowerShell\7\pwsh.exe'),
            @(${env:ProgramFiles(x86)}, 'PowerShell\7\pwsh.exe'),
            @($env:LOCALAPPDATA, 'Programs\PowerShell\7\pwsh.exe'))) {
        if ($pair[0]) { $candidates.Add((Join-Path $pair[0] $pair[1])) }
    }
    foreach ($candidate in $candidates | Where-Object { $_ } | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $probeErrorPreference = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            $probe = @(& $candidate -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.Major' *>&1)
            $ErrorActionPreference = $probeErrorPreference
            if ($LASTEXITCODE -eq 0 -and @($probe | Where-Object { [int]$_ -ge 7 }).Count -gt 0) {
                return $candidate
            }
        }
        catch { $ErrorActionPreference = $probeErrorPreference }
    }
    return ''
}

# Cache module-to-connection mappings to avoid scanning every connection and module per collector.
# A new connection invalidates the cache.
$script:ServiceModuleCache = @{}

# Keep shared Microsoft documentation URLs together so moved pages need one update.
$script:DocUrl = [ordered]@{
    SharePointLabelledFiles = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    AutoLabelling = 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically'
    AuditLogEnable = 'https://learn.microsoft.com/purview/audit-log-enable-disable'
    GraphSubscribedSku = 'https://learn.microsoft.com/graph/api/subscribedsku-list?view=graph-rest-1.0'
    SentinelPurview = 'https://learn.microsoft.com/azure/sentinel/connect-services-api-based'
}

# Set when the operator declines explicitly requested Content Explorer counts rather than granting the role.
$script:SkipContentExplorer = $false

# User.Read is included because Microsoft documents it as sufficient to read an organisation's
# verifiedDomains, which is how the SharePoint admin URL is worked out without prompting. Microsoft
# documents it as the least privileged permission for the signed-in user's own memberships too, so
# the Entra roles shown at sign-in cost no consent beyond what the run already asks for.
$script:GraphScope = @('LicenseAssignment.Read.All', 'GroupSettings.Read.All', 'User.Read', 'ThreatHunting.Read.All', 'Application.Read.All')
# True when Graph has to run in its own process because this one cannot load its sign-in library.
$script:GraphSeparate = $false

#region Console output

function Write-Line {
    <# .SYNOPSIS Writes one console line. Write-Host is this script's interface, not logging. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('Plain', 'Good', 'Warn', 'Bad', 'Head', 'Dim')][string]$Style = 'Plain',
        [switch]$NoNewline
    )

    # Let the operator keep the terminal's own contrast settings. PSStyle is absent before 7.2.
    $hostArguments = @{}
    if (-not $env:NO_COLOR -and (-not (Test-Path variable:PSStyle) -or $PSStyle.OutputRendering -ne 'PlainText')) {
        $hostArguments['ForegroundColor'] = switch ($Style) {
            'Good' { 'Green' }
            'Warn' { 'Yellow' }
            'Bad' { 'Red' }
            'Head' { 'Cyan' }
            'Dim' { 'DarkGray' }
            default { 'Gray' }
        }
    }
    Write-Host $Message -NoNewline:$NoNewline @hostArguments
}

# Every collector row starts with this, so a result can be put back in the same column later.
$script:StepPrefixFormat = '    {0,-8}{1,-34}'

function Write-PurviewStep {
    <#
    .SYNOPSIS
        Names the step before it runs, then completes the line when it finishes.

    .DESCRIPTION
        Announcing the call before it starts identifies the active step during long waits.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [string]$Position = ''
    )

    Write-Line -Style Dim -Message ($script:StepPrefixFormat -f $Position, $Name) -NoNewline
}

function Clear-PurviewStepScaffold {
    <#
    .SYNOPSIS
        Erases the rows a slow collector printed and returns to the step row it left open.

    .DESCRIPTION
        Remove temporary progress rows after completion, leaving one summary row per collector.

        Reports false where the host has no addressable screen buffer, or where the heading wrapped
        and the rows to erase can no longer be counted. The caller then leaves those rows alone
        rather than writing over output it cannot see.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 10)][int]$Rows,
        [Parameter(Mandatory)][ValidateRange(0, 1000)][int]$FirstRowLength
    )

    if ([Console]::IsOutputRedirected -or -not [Environment]::UserInteractive) { return $false }

    try {
        $ui = $Host.UI.RawUI
        if ($null -eq $ui) { return $false }

        $column = ($script:StepPrefixFormat -f '', '').Length
        $width = $ui.BufferSize.Width
        # A wrapped heading occupies more rows than were counted, so the arithmetic no longer holds.
        if ($column + $FirstRowLength -ge $width) { return $false }

        $top = $ui.CursorPosition.Y - $Rows
        if ($top -lt 0) { return $false }

        $blank = [System.Management.Automation.Host.BufferCell]::new(
            ' ', $ui.ForegroundColor, $ui.BackgroundColor, 'Complete')
        $ui.SetBufferContents(
            [System.Management.Automation.Host.Rectangle]::new($column, $top, $width - 1, $top + $Rows - 1),
            $blank)
        $ui.CursorPosition = [System.Management.Automation.Host.Coordinates]::new($column, $top)
        return $true
    }
    catch {
        Write-Verbose "The console would not take a cursor move, so the progress heading stays: $($_.Exception.Message)"
        return $false
    }
}

function Write-PurviewStepResult {
    <# .SYNOPSIS Closes the line opened by Write-PurviewStep. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Status,
        [double]$Seconds = -1
    )

    $style = switch ($Status) {
        'Success' { 'Good' }
        'Reused' { 'Good' }
        'Connected' { 'Good' }
        'PartialSuccess' { 'Warn' }
        'Failed' { 'Warn' }
        default { 'Dim' }
    }
    $timing = if ($Seconds -ge 0) { '{0,6:N1}s' -f $Seconds } else { '' }
    Write-Line -Style $style -Message ('{0,-17}{1}' -f $Status, $timing)
}

#endregion

#region Time
# Store ISO 8601 timestamps with explicit offsets for comparison across time zones.
# Display them in the running operator's local time zone, resolved at runtime.

function Get-PurviewTimestamp {
    <# .SYNOPSIS The current instant, carrying the running host's UTC offset. #>
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param()

    return [DateTimeOffset]::Now
}

function ConvertFrom-PurviewTimestamp {
    <# .SYNOPSIS Parses a stored ISO 8601 timestamp without letting the host culture reinterpret it. #>
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'A timestamp value is required.' }

    $parsed = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::RoundtripKind
    if (-not [DateTimeOffset]::TryParse($Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "The value '$Value' is not an ISO 8601 timestamp."
    }

    return $parsed
}

function ConvertTo-PurviewLocalTimestamp {
    <# .SYNOPSIS Converts an instant into the target zone, defaulting to the running host's zone. #>
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][DateTimeOffset]$Timestamp,
        [TimeZoneInfo]$TimeZone = [TimeZoneInfo]::Local
    )

    process { return [TimeZoneInfo]::ConvertTime($Timestamp, $TimeZone) }
}

function Format-PurviewTimestamp {
    <# .SYNOPSIS Renders an instant for storage, or for a human reader with -Friendly. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][DateTimeOffset]$Timestamp,
        [TimeZoneInfo]$TimeZone = [TimeZoneInfo]::Local,
        [switch]$Friendly
    )

    process {
        $target = ConvertTo-PurviewLocalTimestamp -Timestamp $Timestamp -TimeZone $TimeZone
        if ($Friendly) {
            # Use invariant culture to match the English report, while retaining the local time zone.
            return '{0} ({1})' -f $target.ToString('f', [cultureinfo]::InvariantCulture), $TimeZone.Id
        }
        return $target.ToString('yyyy-MM-ddTHH:mm:sszzz', [cultureinfo]::InvariantCulture)
    }
}

function Get-PurviewTimeZoneContext {
    <# .SYNOPSIS Describes the target zone, for report headers. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [TimeZoneInfo]$TimeZone = [TimeZoneInfo]::Local
    )

    $now = Get-PurviewTimestamp
    return [pscustomobject]@{
        Id = $TimeZone.Id
        DisplayName = $TimeZone.DisplayName
        CurrentOffset = [TimeZoneInfo]::ConvertTime($now, $TimeZone).ToString('zzz', [cultureinfo]::InvariantCulture)
        Culture = [cultureinfo]::CurrentCulture.Name
    }
}

#endregion

#region Object helpers
# Purview property sets vary by tenant; missing properties throw under strict mode.
# Preserve absence rather than supplying defaults that could create false findings.

function Get-PurviewProperty {
    <# .SYNOPSIS Reads the first property that exists, returning $null when none do. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Name
    )

    if ($null -eq $InputObject) { return $null }

    foreach ($candidate in $Name) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($candidate)) { return $InputObject[$candidate] }
            continue
        }
        $property = $InputObject.PSObject.Properties[$candidate]
        if ($property) { return $property.Value }
    }

    return $null
}

function Test-PurviewProperty {
    <# .SYNOPSIS Reports whether a property is present, which is distinct from it being null. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return [bool]$InputObject.PSObject.Properties[$Name]
}

function ConvertTo-PurviewPowerShellLiteral {
    <# .SYNOPSIS Quotes data as a PowerShell string literal, never as executable syntax. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value)

    # PowerShell also treats U+2018/U+2019/U+201A/U+201B as single quotes. Use the
    # tokenizer's escaping API (available in Windows PowerShell 5.1), not ASCII-only replacement.
    return "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent([string]$Value) + "'"
}

function ConvertTo-PurviewArray {
    <# .SYNOPSIS Normalises null, scalar and collection into an array. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object]$InputObject
    )

    if ($null -eq $InputObject) { return @() }
    # A single-element array unrolls to a scalar at the call site, so re-wrap rather than trust it.
    return @($InputObject)
}

function ConvertTo-PurviewApplicationScope {
    <# .SYNOPSIS Normalises an application scope into exact, case-insensitive tokens. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object]$InputObject
    )

    $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $complete = $true

    if ($null -eq $InputObject) {
        return [pscustomobject]@{ Complete = $false; Tokens = @() }
    }

    $values = @(ConvertTo-PurviewArray -InputObject $InputObject)
    if ($values.Count -eq 0) { $complete = $false }

    foreach ($value in $values) {
        if ($value -isnot [string]) {
            $complete = $false
            continue
        }

        # The service can return one comma-delimited value, separate values, or a mixture of both.
        # Empty segments carry no scope and are discarded; an entirely empty result is incomplete.
        foreach ($token in @(([string]$value) -split ',')) {
            $trimmed = $token.Trim()
            if ($trimmed) { $null = $tokens.Add($trimmed) }
        }
    }

    if ($tokens.Count -eq 0) { $complete = $false }
    return [pscustomobject]@{ Complete = $complete; Tokens = @($tokens | Sort-Object) }
}

function ConvertTo-PurviewBoolean {
    <# .SYNOPSIS Parses a Boolean without treating null or a non-empty string as a value. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    $value = $false
    $valid = $null -ne $InputObject -and [bool]::TryParse(([string]$InputObject).Trim(), [ref]$value)
    return [pscustomobject]@{ Valid = $valid; Value = $(if ($valid) { $value } else { $null }) }
}

function ConvertTo-PurviewNonNegativeInteger {
    <# .SYNOPSIS Parses an aggregate count without turning missing or malformed data into zero. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    $value = [long]0
    $valid = $null -ne $InputObject -and [long]::TryParse(
        ([string]$InputObject).Trim(),
        [System.Globalization.NumberStyles]::Integer,
        [cultureinfo]::InvariantCulture,
        [ref]$value)
    if ($valid -and $value -lt 0) { $valid = $false }
    return [pscustomobject]@{ Valid = $valid; Value = $(if ($valid) { $value } else { $null }) }
}

#endregion

#region Evidence
# Every rule cites one or more of these. A recommendation without a source, a retrieval date and a
# confidence level cannot be checked by the person receiving it, so it is not made.

$script:Evidence = @{
    'EV-CMDLET-VERIFY-001' = @{
        Title = 'Security & Compliance PowerShell cmdlet reference'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/'
        RetrievedAt = '2026-08-20'
        ContentHash = 'D9B49BE8E89BEE12A38C1DE461C8DA1C'
        Status = 'GA'
        Note = 'Cmdlet reference for reviewing command availability and semantics; this registry entry is not verification of every interface used.'
    }
    'EV-SCC-CONNECT-001' = @{
        Title = 'Connect to Security & Compliance PowerShell'
        Url = 'https://learn.microsoft.com/powershell/exchange/connect-to-scc-powershell'
        RetrievedAt = '2026-08-20'
        ContentHash = '3E8CAD14F9E101616A1219F59D656DEE'
        Status = 'GA'
        Note = 'Import-Module ExchangeOnlineManagement then Connect-IPPSSession. Works in Windows PowerShell 5.1 and PowerShell 7.'
    }
    'EV-SPO-PS7-001' = @{
        Title = 'Connect to SharePoint Online PowerShell'
        Url = 'https://learn.microsoft.com/powershell/sharepoint/sharepoint-online/connect-sharepoint-online'
        RetrievedAt = '2026-08-20'
        ContentHash = '75FCE542F66A759BE3C814F63DF11D4C'
        Status = 'GA'
        Note = 'To run SharePoint Online commands in PowerShell 7, the module must be imported with -UseWindowsPowerShell.'
    }
    'EV-GRAPH-SKU-001' = @{
        Title = 'List subscribedSkus'
        Url = $script:DocUrl.GraphSubscribedSku
        RetrievedAt = '2026-08-20'
        ContentHash = 'C818582BF75B17E4E8C1CCBDCAABF06A'
        Status = 'GA'
        Note = 'Least privileged permission is LicenseAssignment.Read.All. Organization.Read.All and Directory.Read.All are listed as higher privileged and are not requested.'
    }
    'EV-PURVIEW-ROLES-001' = @{
        Title = 'Permissions in the Microsoft Purview portal'
        Url = 'https://learn.microsoft.com/purview/purview-permissions'
        RetrievedAt = '2026-08-20'
        ContentHash = '6F724CCFB56E29331CFCB32B0C2228FA'
        Status = 'GA'
        Note = 'Review workload-specific read roles; an Entra role alone does not establish access to every Purview collector.'
    }
    'EV-DLP-MODE-001' = @{
        Title = 'Set-DlpCompliancePolicy'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-dlpcompliancepolicy'
        RetrievedAt = '2026-08-20'
        ContentHash = '84CA28F27DAACB697C9FEF79879A2B78'
        Status = 'GA'
        Note = 'Mode values are Enable, Disable, TestWithNotifications and TestWithoutNotifications.'
    }
    'EV-SESSION-001' = @{
        Title = 'Disconnect-MgGraph'
        Url = 'https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/disconnect-mggraph'
        RetrievedAt = '2026-08-21'
        ContentHash = '59B6150185FD5C4B6B9F1D485A29B9F8'
        Status = 'GA'
        Note = 'Reference for Graph sign-out. The script attempts cleanup of tracked sessions; this does not verify token revocation, cache removal or cleanup of isolated Graph sign-ins. Module-wide disconnects can affect other connections.'
    }
    'EV-AUDIT-ENABLE-001' = @{
        Title = 'Turn auditing on or off'
        Url = $script:DocUrl.AuditLogEnable
        RetrievedAt = '2026-08-21'
        ContentHash = '498A014C0095D213DFC6C0BE83269637'
        Status = 'GA'
        Note = 'UnifiedAuditLogIngestionEnabled True means auditing is on. It must be read in Exchange Online PowerShell: the same property is always False in Security & Compliance PowerShell even when auditing is on, so reading it there would report every tenant as unaudited.'
    }
    'EV-DLP-RULE-001' = @{
        Title = 'Get-DlpComplianceRule'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/get-dlpcompliancerule'
        RetrievedAt = '2026-08-21'
        ContentHash = '14A29DD9A079C2A6F3BC11380789548E'
        Status = 'GA'
        Note = 'A DLP policy carries no conditions or actions of its own; its rules do. A policy with no rules matches nothing.'
    }
    'EV-M365MAPS-001' = @{
        Title = 'Microsoft 365 Licensing (m365maps.com)'
        Url = 'https://m365maps.com/'
        RetrievedAt = '2026-08-20'
        ContentHash = 'EDA61287246D1FFFD89027E761B5E2EE'
        Status = 'GA'
        Note = 'Supplementary licensing reference. Revision byline read August 2026 when checked, so within the freshness window. Microsoft Learn overrides any conflict.'
    }
    'EV-AUTOLABEL-001' = @{
        Title = 'Apply a sensitivity label to content automatically'
        Url = $script:DocUrl.AutoLabelling
        RetrievedAt = '2026-08-20'
        ContentHash = 'EF4E418D952177D6A784E5348E2265CB'
        Status = 'GA'
        Note = 'Service-side auto-labeling supports eligible SharePoint and OneDrive files at rest and Exchange email in transit, not email already at rest in mailboxes.'
    }
    'EV-RETENTION-001' = @{
        Title = 'Retention cmdlets'
        Url = 'https://learn.microsoft.com/purview/retention-cmdlets'
        RetrievedAt = '2026-08-20'
        ContentHash = 'B19E14C670FD7736551985EE5DFD9509'
        Status = 'GA'
        Note = 'Reference for the retention policy and retention label cmdlets used to read lifecycle configuration.'
    }
    'EV-RETENTION-OVERVIEW-001' = @{
        Title = 'Learn about retention policies and retention labels'
        Url = 'https://learn.microsoft.com/en-us/purview/retention'
        RetrievedAt = '2026-09-15'
        ContentHash = ''
        Status = 'GA'
        Note = 'Policies, labels or both can be used. Labels can classify without actions and can remain on content after a publishing policy is removed. Definition counts do not establish publication, application or satisfaction of retention requirements.'
    }
    'EV-AUDIT-001' = @{
        Title = 'Manage audit log retention policies'
        Url = 'https://learn.microsoft.com/purview/audit-log-retention-policies'
        RetrievedAt = '2026-08-20'
        ContentHash = 'C06D2CB6959C7AE35744AE56929F3FED'
        Status = 'GA'
        Note = 'Custom audit retention policies override the default and can shorten or extend retention, subject to licensing.'
    }
    'EV-COMMCOMP-001' = @{
        Title = 'Communication compliance reports and audits'
        Url = 'https://learn.microsoft.com/purview/communication-compliance-reports-audits'
        RetrievedAt = '2026-08-20'
        ContentHash = '35C08E35B5955097AB576922B433671C'
        Status = 'GA'
        Note = 'Communication compliance identifies potential regulatory and conduct violations for review in supported communication channels.'
    }
    'EV-DLP-REF-001' = @{
        Title = 'Data loss prevention policy reference'
        Url = 'https://learn.microsoft.com/purview/dlp-policy-reference'
        RetrievedAt = '2026-08-20'
        ContentHash = 'F9019070B807273B2211B16A18E32354'
        Status = 'GA'
        Note = 'Reference for DLP policy structure, locations and rules.'
    }
    'EV-CONTENT-EXPLORER-001' = @{
        Title = 'Export-ContentExplorerData'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/export-contentexplorerdata'
        RetrievedAt = '2026-09-02'
        ContentHash = '2C5B70C6885B2EE026F5A52EEF5C1D7D'
        Status = 'GA'
        Note = 'This is a Security & Compliance PowerShell cmdlet despite the ExchangePowerShell documentation path. The script queries only explicitly named sensitive information types. With TagName and TagType but no Workload, TotalCount covers that one type across the supported Exchange, SharePoint, OneDrive and Teams workloads. The first object carries the total, so no item record is retained. Counts for different types are not added together.'
    }
    'EV-CONTENT-EXPLORER-ROLES-001' = @{
        Title = 'Get started with content explorer'
        Url = 'https://learn.microsoft.com/purview/data-classification-content-explorer'
        RetrievedAt = '2026-09-02'
        ContentHash = '35083BDC6F914403DC969B7837087EC3'
        Status = 'GA'
        Note = 'Content Explorer List Viewer shows each item and its location. Counts can take seven days to update and SharePoint files 14 days; encrypted sensitivity labels do not surface for SharePoint and OneDrive. Content Explorer Content Viewer additionally exposes contents and item names and is not requested.'
    }
    'EV-DAG-001' = @{
        Title = 'Get-SPODataAccessGovernanceInsight'
        Url = 'https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell/get-spodataaccessgovernanceinsight'
        RetrievedAt = '2026-08-21'
        ContentHash = '3D4D7EE684F79047F2DC681028FC183D'
        Status = 'GA'
        Note = 'Lists oversharing report metadata such as status and site count. Generating a report is a separate Start-* cmdlet and downloading one is a separate Export-* cmdlet; neither is called here.'
    }
    'EV-DAG-GUIDE-001' = @{
        Title = 'Manage Data access governance reports by using SharePoint Online PowerShell'
        Url = 'https://learn.microsoft.com/sharepoint/powershell-for-data-access-governance'
        RetrievedAt = '2026-08-21'
        ContentHash = '31CF278C3CA4D1668B1170AA83828DB8'
        Status = 'GA'
        Note = 'Site permission reports provide oversharing context, not a complete measurement of Copilot exposure. This script lists existing report metadata rather than generating or exporting reports.'
    }
    'EV-DSPM-PORTAL-001' = @{
        Title = 'Prevent oversharing with data risk assessments from Data Security Posture Management'
        Url = 'https://learn.microsoft.com/purview/data-security-posture-management-oversharing'
        RetrievedAt = '2026-08-21'
        ContentHash = '8532B62962FD203929119B81099CD0DB'
        Status = 'GA'
        Note = 'Data risk assessment results are not collected by this script; review them separately in Microsoft Purview.'
    }
    'EV-SBD-PREREQ-001' = @{
        Title = 'Secure by default: turn on data security prerequisites and advanced analytics'
        Url = 'https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-step1'
        RetrievedAt = '2026-08-21'
        ContentHash = 'FE53E5E83F31BD6F838D59EB83DB4B2F'
        Status = 'GA'
        Note = 'Lists supporting settings to review; not all are off by default. It recommends retaining mismatch emails by keeping BlockSendLabelMismatchEmail False.'
    }
    'EV-PURVIEW-REPORTS-001' = @{
        Title = 'Microsoft Purview posture reports overview'
        Url = 'https://learn.microsoft.com/purview/purview-reports'
        RetrievedAt = '2026-08-21'
        ContentHash = 'CF15EBB77C2FBB15DDEB93C6E9B0B18C'
        Status = 'Preview'
        Note = 'Posture reports are not collected here. The selected Activity Explorer and Content Explorer reads do not reproduce those reports.'
    }
    'EV-DLP-REPORT-RETIRE-001' = @{
        Title = 'Get-DlpDetectionsReport'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/get-dlpdetectionsreport'
        RetrievedAt = '2026-08-21'
        ContentHash = '1C9D46C0A167447BFE6E656502F6B001'
        Status = 'Retiring'
        Note = 'Marked for retirement, with Export-ActivityExplorerData named as the replacement. Get-DlpSiDetectionsReport carries the same notice. Neither is used.'
    }
    'EV-SAM-PREREQ-001' = @{
        Title = 'Prerequisites for SharePoint Advanced Management'
        Url = 'https://learn.microsoft.com/sharepoint/sharepoint-advanced-management-prerequisites'
        RetrievedAt = '2026-08-21'
        ContentHash = 'B7589A108B44C92850BADDF259BCBEDB'
        Status = 'GA'
        Note = 'SharePoint Advanced Management entitlement depends on the feature and licensing route. Check the current prerequisites rather than inferring entitlement from E5 alone.'
    }
    'EV-DEFAULT-TAXONOMY-001' = @{
        Title = 'Default sensitivity labels and policies to protect your data'
        Url = 'https://learn.microsoft.com/purview/default-sensitivity-labels-policies'
        RetrievedAt = '2026-08-21'
        ContentHash = 'CF11AFC417A880654B4F848366E9C7E4'
        Status = 'GA'
        Note = 'Documents the default tiers Personal, Public, General, Confidential and Highly Confidential. Used as a reference to compare against, not a target: a different taxonomy is a design choice, not a defect.'
    }
    'EV-SENTINEL-PURVIEW-001' = @{
        Title = 'Connect Microsoft Sentinel to Microsoft services with an API-based data connector'
        Url = $script:DocUrl.SentinelPurview
        RetrievedAt = '2026-09-25'
        ContentHash = ''
        Status = 'GA'
        Note = 'Documents API-based Microsoft 365 and Microsoft Purview Information Protection connectors. Connector configuration is context, not proof of ingestion; the assessment requires observed tenant-scoped Microsoft 365 audit or compliance telemetry in a Sentinel workspace.'
    }
    'EV-SENTINEL-M365-AUDIT-001' = @{
        Title = 'OfficeActivity table reference'
        Url = 'https://learn.microsoft.com/azure/azure-monitor/reference/tables/officeactivity'
        RetrievedAt = '2026-09-25'; ContentHash = ''; Status = 'GA'
        Note = 'OrganizationId identifies the Microsoft 365 source tenant; TenantId identifies the Log Analytics workspace. Audit records do not establish every Purview workload or all Unified Audit Log coverage.'
    }
    'EV-SENTINEL-MIP-001' = @{
        Title = 'Connect Microsoft Purview Information Protection to Microsoft Sentinel'
        Url = 'https://learn.microsoft.com/azure/sentinel/connect-microsoft-purview'
        RetrievedAt = '2026-09-25'; ContentHash = ''; Status = 'GA'
        Note = 'Documents Office Management API ingestion into MicrosoftPurviewInformationProtection. Records can overlap with OfficeActivity, so cross-source counts are not summed.'
    }
    'EV-SENTINEL-MIP-002' = @{
        Title = 'Microsoft Purview Information Protection record types and activities'
        Url = 'https://learn.microsoft.com/azure/sentinel/microsoft-purview-record-types-activities'
        RetrievedAt = '2026-09-25'; ContentHash = ''; Status = 'GA'
        Note = 'Names the supported sensitivity-label operations. A general information-protection event or heartbeat does not prove a label change.'
    }
    'EV-SENTINEL-IRM-001' = @{
        Title = 'Microsoft Purview Insider Risk Management Sentinel connector definition'
        Url = 'https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/MicrosoftPurviewInsiderRiskManagement/Data%20Connectors/template_OfficeIRM.JSON'
        RetrievedAt = '2026-09-25'; ContentHash = ''; Status = 'GA'
        Note = 'The official native connector queries SecurityAlert by exact ProductName Microsoft 365 Insider Risk Management, excluding customized OriginalProductName records. This evidence is workspace-scoped; no source-tenant field is inferred.'
    }
    'EV-SENTINEL-DLP-001' = @{
        Title = 'Office 365 Management Activity API schema: DLP'
        Url = 'https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema#dlp-schema'
        RetrievedAt = '2026-09-25'; ContentHash = ''; Status = 'GA'
        Note = 'Documents DLP record types, DlpAgent and exact DlpRuleMatch/DlpRuleUndo/DlpInfo operations. Qualified raw audit records are distinguished from DLP alerts; generic Defender alerts are not accepted as DLP evidence.'
    }
}

#endregion

#region Rules
# Rules are data. Conditions are declarative and are never evaluated as code: a rule can describe a
# comparison but can never introduce a code path.

# The Purview solution each area belongs to, which is what a reader recognises from the portal.
# Anything mapping to an empty string carries no rule. Kept as data so the scope of the assessment
# is a table edit rather than a code change.
$script:SolutionWorkload = [ordered]@{
    'SensitivityLabels' = 'Information Protection'
    'LabelPolicies' = 'Information Protection'
    'Classification' = 'Information Protection'
    'DataLossPrevention' = 'Information Protection'
    'AutoLabeling' = 'Information Protection (Microsoft 365 E5)'
    'EndpointDlp' = 'Information Protection (Microsoft 365 E5)'
    'ContentExplorer' = 'Information Protection (Microsoft 365 E5)'
    'ActivityExplorer' = 'Information Protection (Microsoft 365 E5)'
    'DataLifecycleManagement' = 'Data Lifecycle Management'
    'RecordsManagement' = 'Records Management'
    'CommunicationCompliance' = 'Communication Compliance'
    'Audit' = 'Audit (Premium)'
    'PostureValidation' = 'Data Security Posture Management'
    # Oversharing is collected as context and graded by no rule, so it names no solution.
    'Oversharing' = ''
}

$script:Rules = @(
    @{
        id = 'PA-SEN-0001'
        version = '3.0.0'
        title = 'Microsoft 365 Purview telemetry in Microsoft Sentinel'
        solutionArea = 'PostureValidation'
        severity = 'Medium'
        rationale = 'Microsoft 365 audit and Purview compliance telemetry in Sentinel provides evidence that events reached the workspace. An enabled connector or installed content solution alone does not prove data flow. Audit, information protection, DLP and Insider Risk coverage must be distinguished; one observed source does not establish every workload or continuous ingestion.'
        recommendation = 'Review the per-source event counts, last event times and read limitations. Verify the appropriate Microsoft 365, Microsoft Purview Information Protection or Defender connector and query permissions. Check the source tenant, selected data types and lookback window before changing configuration; no events alone do not establish a broken integration.'
        condition = @{
            collector = 'SentinelPurviewIntegration'
            analysis = 'SentinelPurviewIntegration'
        }
        licensing = @{ capability = 'Microsoft 365 Purview telemetry in Microsoft Sentinel'; includedIn = @(); addOns = @() }
        evidence = @('EV-SENTINEL-PURVIEW-001', 'EV-SENTINEL-M365-AUDIT-001', 'EV-SENTINEL-MIP-001',
            'EV-SENTINEL-MIP-002', 'EV-SENTINEL-IRM-001', 'EV-SENTINEL-DLP-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'sentinel integration'
    }
    @{
        id = 'PA-IP-0003'
        version = '1.0.0'
        title = 'Label publishing policies'
        solutionArea = 'LabelPolicies'
        severity = 'Critical'
        rationale = 'Publishing makes labels available to assigned users in supported apps and can configure defaults, mandatory labelling and downgrade justification. A policy definition does not prove delivery or application. Previously applied labels can remain effective without a current publishing policy.'
        recommendation = 'Publish at least one label publishing policy to the users or groups who should be able to apply labels.'
        condition = @{
            collector = 'SensitivityLabelPolicy'
            select = 'Policies'
            where = @{ field = 'Enabled'; operator = 'eq'; value = $true }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'enabled label publishing policy'
                itemPlural = 'enabled label publishing policies'
            }
        }
        licensing = @{ capability = 'Label publishing policies'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-IP-0004'
        version = '1.0.0'
        title = 'Sensitivity labels for Office files in SharePoint and OneDrive'
        solutionArea = 'SensitivityLabels'
        severity = 'High'
        rationale = 'EnableAIPIntegration supports service processing of eligible labelled Office files in SharePoint and OneDrive, including supported encrypted files. Search, DLP, eDiscovery and collaboration support depend on file type, encryption settings and processing state; this switch does not verify those outcomes.'
        recommendation = 'Turn on EnableAIPIntegration for the tenant. Files labelled and encrypted before that only gain the capability once they are edited, or downloaded and uploaded again.'
        remediationCommand = 'Set-SPOTenant -EnableAIPIntegration $true'
        condition = @{
            collector = 'SharePointLabelingReadiness'
            select = 'Settings'
            where = @{ field = 'Name'; operator = 'eq'; value = 'EnableAIPIntegration' }
            assert = @{
                type = 'allHave'
                itemSingular = 'SharePoint label-processing setting'
                itemPlural = 'SharePoint label-processing settings'
                subject = 'label processing to be enabled'
                where = @{ field = 'Enabled'; operator = 'eq'; value = $true }
            }
        }
        licensing = @{ capability = 'Sensitivity labels for Office files'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-IP-0007'
        version = '1.0.0'
        title = 'Tenant opt-in values'
        solutionArea = 'SensitivityLabels'
        severity = 'High'
        rationale = 'Supporting settings affect file processing, notifications and guest access. Defaults and applicability differ by feature. This check compares returned values with the report reference values; a difference requires design review, not automatic enablement.'
        recommendation = 'Review Prerequisites and Tenant Opt-ins for each reference value, its applicability and consequences before making changes.'
        condition = @{
            collector = 'SharePointLabelingReadiness'
            select = 'Settings'
            assert = @{
                type = 'allHave'
                itemSingular = 'tenant opt-in'
                itemPlural = 'tenant opt-ins'
                subject = 'the report''s reference value'
                where = @{ field = 'AsRecommended'; operator = 'eq'; value = $true }
            }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-SBD-PREREQ-001', 'EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-DLP-0001'
        version = '1.0.0'
        title = 'DLP policy enforcement'
        solutionArea = 'DataLossPrevention'
        severity = 'High'
        rationale = 'Policy mode distinguishes on, off and simulation with or without policy tips. For Endpoint DLP, simulation changes Block to Block with override when tips are on, and to Audit when tips are off. Enable mode is configuration evidence, not proof of effective enforcement.'
        recommendation = 'Review the policies still in test mode and move the validated ones into enforcement.'
        condition = @{
            collector = 'DataLossPrevention'
            select = 'Policies'
            where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'DLP policy in Enable mode'
                itemPlural = 'DLP policies in Enable mode'
            }
        }
        licensing = @{ capability = 'Data Loss Prevention'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-DLP-MODE-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Manage Data Access'
        deploymentModel = 'lightweight-dlp step 1'
    }
    @{
        id = 'PA-DLP-0002'
        version = '1.2.0'
        title = 'Endpoint DLP coverage'
        solutionArea = 'EndpointDlp'
        severity = 'Medium'
        rationale = 'Endpoint DLP can audit or restrict supported device activities, such as copying, printing and browser uploads. A Devices location is only configuration evidence: rules, platform support, user and device scope, onboarding and device health determine application.'
        recommendation = 'Review the Devices-scoped policies and their modes. If none is configured, add Devices to an appropriate policy. Validate simulation results before enabling enforcement, and confirm user scope and device onboarding.'
        condition = @{
            collector = 'DataLossPrevention'
            analysis = 'EndpointCoverage'
        }
        licensing = @{
            capability = 'Endpoint DLP'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-DLP-REF-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Manage Data Access'
        deploymentModel = 'lightweight-dlp step 2'
    }
    @{
        id = 'PA-AUD-0001'
        version = '1.0.0'
        title = 'Custom audit log retention'
        solutionArea = 'Audit'
        severity = 'Medium'
        rationale = 'Qualifying Audit (Premium) users receive one-year default retention for Exchange, SharePoint, OneDrive and Entra audit records; other activities and users generally receive 180 days. Custom policies override defaults and can shorten retention. Multi-year retention requires the appropriate add-on. No custom policy may be appropriate if defaults meet requirements.'
        recommendation = 'Compare default and custom audit retention with investigation requirements. Create a custom policy only where needed, with the required licensing.'
        condition = @{
            collector = 'AuditConfiguration'
            select = 'RetentionPolicies'
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'custom audit log retention policy'
                itemPlural = 'custom audit log retention policies'
            }
        }
        licensing = @{
            capability = 'Audit (Premium) log retention policies'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        # No blueprint step covers custom audit retention. Secure by default asks only that auditing
        # is on, which PA-AUD-0002 carries.
        deploymentModel = ''
    }
    @{
        id = 'PA-IP-0005'
        version = '1.1.0'
        title = 'Sensitivity labels defined'
        solutionArea = 'SensitivityLabels'
        severity = 'Critical'
        rationale = 'Sensitivity-label-based controls need label definitions. If no enabled definitions are returned, that does not establish absence of other classification methods or labels already applied to content.'
        recommendation = 'Create a label taxonomy, starting with the default set, before configuring policies that depend on labels.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'enabled sensitivity label'
                itemPlural = 'enabled sensitivity labels'
            }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-IP-0006'
        version = '1.0.0'
        title = 'Auto-labeling policies'
        solutionArea = 'AutoLabeling'
        severity = 'Medium'
        rationale = 'Service-side auto-labeling can reduce reliance on manual labelling for eligible SharePoint and OneDrive files at rest and Exchange email in transit. Other labelling methods also exist. Policy definitions alone do not establish successful processing or coverage.'
        recommendation = 'Create auto-labeling policies for the sensitive information types that matter most, starting in simulation to assess the impact.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'auto-labeling policy'
                itemPlural = 'auto-labeling policies'
            }
        }
        licensing = @{
            capability = 'Auto-labeling'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-AUTOLABEL-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 2'
    }
    @{
        id = 'PA-IP-0008'
        version = '1.0.0'
        title = 'Auto-labeling policy state'
        solutionArea = 'AutoLabeling'
        severity = 'Medium'
        rationale = 'Simulation validates service-side auto-labeling without applying labels. If all returned policies are simulating, those policies are not applying labels; manual, default or other labelling methods may still operate.'
        recommendation = 'Review the simulation results and turn on the policies that are labelling what you expected.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{
                type = 'anyHave'
                itemSingular = 'auto-labeling policy'
                itemPlural = 'auto-labeling policies'
                subject = 'the policy is in Enable mode'
                where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' }
            }
        }
        licensing = @{
            capability = 'Auto-labeling'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-AUTOLABEL-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 2'
    }
    @{
        id = 'PA-DLP-0003'
        version = '1.0.0'
        title = 'Disabled DLP policies'
        solutionArea = 'DataLossPrevention'
        severity = 'Medium'
        rationale = 'A policy in Disable mode is configured but inactive. This can be intentional during design, replacement or retirement; other policies may still apply.'
        recommendation = 'Review why each policy is disabled before deciding whether to validate and enable it or retire it.'
        condition = @{
            collector = 'DataLossPrevention'
            select = 'Policies'
            assert = @{
                type = 'noneHave'
                itemSingular = 'DLP policy'
                itemPlural = 'DLP policies'
                subject = 'being in Disable mode'
                where = @{ field = 'Mode'; operator = 'eq'; value = 'Disable' }
            }
        }
        licensing = @{ capability = 'Data Loss Prevention'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-DLP-MODE-001', 'EV-DLP-REF-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Manage Data Access'
        deploymentModel = 'lightweight-dlp step 3'
    }
    @{
        id = 'PA-DLM-0001'
        version = '1.1.0'
        title = 'Retention policy coverage'
        solutionArea = 'DataLifecycleManagement'
        severity = 'High'
        rationale = 'This check examines the classic retention policy family and its returned mode and linked-rule metadata. Retention policies, labels, holds and separately collected app-retention policies can address different requirements. Passing this check does not validate retention actions, duration, assignments or distribution; absence does not establish that content has no retention.'
        recommendation = 'Define retention policies covering Exchange, SharePoint, OneDrive and Teams according to your retention schedule.'
        condition = @{
            collector = 'RetentionPolicy'
            select = 'Policies'
            where = @{
                all = @(
                    @{ field = 'Enabled'; operator = 'eq'; value = $true }
                    @{ field = 'Mode'; operator = 'eq'; value = 'Enforce' }
                    @{ field = 'HasRules'; operator = 'eq'; value = $true }
                    @{ field = 'RuleTypes'; operator = 'isNotNullOrEmpty' }
                    @{ field = 'RuleTypes'; operator = 'notContains'; value = 'Publish' }
                    @{ field = 'RuleTypes'; operator = 'notContains'; value = 'Apply' }
                    @{ field = 'RuleTypes'; operator = 'notContains'; value = 'ProactiveDataRetention' }
                )
            }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'classic retention policy in force'
                itemPlural = 'classic retention policies in force'
            }
        }
        licensing = @{ capability = 'Retention policies'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        # Retention is its own solution. No step of the blueprints this report tracks covers it.
        deploymentModel = ''
    }
    @{
        id = 'PA-DLM-0002'
        version = '1.1.0'
        title = 'Retention label definitions'
        solutionArea = 'RecordsManagement'
        severity = 'Medium'
        rationale = 'Microsoft supports retention policies, retention labels or both. Labels provide item-level configuration and can classify content without retention actions. This check establishes only whether readable label definitions exist, not whether they are published, applied to content or valid for the retention schedule.'
        recommendation = 'Use labels where item-level configuration is needed, and verify the intended application method and retention schedule separately. An empty label list does not require labels to be created; PA-DLM-0001 assesses classic retention policies independently.'
        condition = @{
            collector = 'RetentionLabel'
            analysis = 'RetentionLabelConfiguration'
        }
        licensing = @{ capability = 'Retention labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001', 'EV-RETENTION-OVERVIEW-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = ''
    }
    @{
        id = 'PA-RM-0001'
        version = '1.0.0'
        title = 'Records declaration'
        solutionArea = 'RecordsManagement'
        severity = 'Low'
        rationale = 'Record labels support additional restrictions, but ordinary record behaviour depends on lock state and settings: unlocked records can allow edits, and property changes can be allowed on locked records. Regulatory records impose stronger restrictions, including an irremovable label. Definitions do not prove that records have been declared on content.'
        recommendation = 'If recordkeeping obligations apply, choose the appropriate record type and settings and verify application to content. Otherwise this finding can be dismissed.'
        condition = @{
            collector = 'RetentionLabel'
            select = 'Labels'
            where = @{ field = 'IsRecordLabel'; operator = 'eq'; value = $true }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'retention label that declares content as a record'
                itemPlural = 'retention labels that declare content as records'
            }
        }
        licensing = @{
            capability = 'Records management'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001')
        confidence = 'Low'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        deploymentModel = ''
    }
    @{
        id = 'PA-CC-0001'
        version = '1.3.0'
        title = 'Communication compliance policies'
        solutionArea = 'CommunicationCompliance'
        severity = 'Low'
        rationale = 'Communication compliance identifies potential policy violations for human review in supported communication and AI channels. This check establishes only that a policy is configured, not its effective scope, current inspection, review operations, health or last scan.'
        recommendation = 'If you are subject to supervision obligations or want conduct detection, configure at least one communication compliance policy and confirm its current state in the portal. Otherwise dismiss this finding.'
        condition = @{
            collector = 'CommunicationCompliance'
            select = 'Policies'
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'communication compliance policy'
                itemPlural = 'communication compliance policies'
            }
        }
        licensing = @{
            capability = 'Communication Compliance'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-COMMCOMP-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        # DSPM step 3 is analytics reports, trends and recommendations, and reaches DLP and insider
        # risk. Communication compliance appears in no step of it.
        deploymentModel = ''
    }
    @{
        id = 'PA-TAX-0001'
        version = '1.0.0'
        title = 'Label taxonomy tiers'
        solutionArea = 'SensitivityLabels'
        severity = 'Medium'
        rationale = 'The two-label threshold is a report heuristic, not a Microsoft requirement. Label count alone does not establish a useful taxonomy. The documented default tiers are a reference; different names and structures can be valid design choices.'
        recommendation = 'Review whether the available labels distinguish the information your organisation needs to classify. Treat the default taxonomy as a reference, not a mandatory target.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{
                type = 'countGreaterThan'
                value = 1
                itemSingular = 'enabled sensitivity label'
                itemPlural = 'enabled sensitivity labels'
            }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-DEFAULT-TAXONOMY-001', 'EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-AUD-0002'
        version = '1.0.0'
        title = 'Unified audit logging'
        solutionArea = 'Audit'
        severity = 'Critical'
        rationale = 'Unified audit ingestion supports investigation of supported user and admin activities. Enabling it does not backfill activity missed while ingestion was off. Audit is not the sole evidence source: Copilot conversation content and eDiscovery compliance copies are stored and retained separately.'
        recommendation = 'Turn on auditing in the Microsoft Purview portal, or run Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true in Exchange Online PowerShell.'
        condition = @{
            collector = 'AuditIngestion'
            select = 'Settings'
            assert = @{
                type = 'allHave'
                itemSingular = 'unified audit setting'
                itemPlural = 'unified audit settings'
                subject = 'auditing to be enabled'
                where = @{ field = 'Enabled'; operator = 'eq'; value = $true }
            }
        }
        licensing = @{ capability = 'Unified audit logging'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-AUDIT-ENABLE-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-DLP-0004'
        version = '1.2.0'
        title = 'DLP rule coverage'
        solutionArea = 'DataLossPrevention'
        severity = 'High'
        rationale = 'DLP conditions and actions reside in rules. A policy without rules has nothing to evaluate. An enabled linked rule establishes configuration only, not effective detection, scope or enforcement.'
        recommendation = 'Open each DLP policy and confirm it has at least one enabled rule with conditions and actions.'
        condition = @{
            collector = 'DlpRule'
            analysis = 'PolicyRuleCoverage'
        }
        licensing = @{ capability = 'Data loss prevention'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-DLP-RULE-001', 'EV-DLP-REF-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Prevent Data Leakage'
        deploymentModel = 'lightweight-dlp step 2'
    }
    @{
        id = 'PA-DLP-0005'
        version = '1.2.0'
        title = 'Disabled DLP rules'
        solutionArea = 'DataLossPrevention'
        severity = 'Medium'
        rationale = 'An enabled policy can contain disabled rules. Those rules are inactive, but other enabled rules may still evaluate the same conditions. Disabled rules can be intentional.'
        recommendation = 'Review the purpose and replacement coverage of disabled rules before enabling or retiring them.'
        condition = @{
            collector = 'DlpRule'
            analysis = 'DisabledRulesInEnforcingPolicies'
        }
        licensing = @{ capability = 'Data loss prevention'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-DLP-RULE-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Prevent Data Leakage'
        deploymentModel = 'lightweight-dlp step 2'
    }
    @{
        id = 'PA-CLS-0001'
        version = '1.1.0'
        title = 'Organisation-specific sensitive information types'
        solutionArea = 'Classification'
        severity = 'Low'
        rationale = 'Custom sensitive information types can identify organisation-specific patterns. They are optional where built-in types or other classification methods meet requirements. This check counts non-Microsoft definitions; it does not assess classification effectiveness.'
        recommendation = 'Review classification requirements and add custom types, exact data match or trainable classifiers only where existing methods are insufficient.'
        condition = @{
            collector = 'Classification'
            select = 'SensitiveInformationTypes'
            # Anything Microsoft published is out of scope: it is identical in every tenant.
            where = @{ field = 'Publisher'; operator = 'ne'; value = 'Microsoft Corporation' }
            assert = @{
                type = 'isNotEmpty'
                itemSingular = 'organisation-specific sensitive information type'
                itemPlural = 'organisation-specific sensitive information types'
            }
        }
        licensing = @{ capability = 'Classification'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'Low'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know Your Data'
        deploymentModel = 'dspm step 1'
    }
)

# Keep the original objects: imported replacements must not inherit built-in planning advice,
# even when the supplied rule keeps the same ID and version. Import replaces, not mutates, rules.
$script:BuiltInRules = @($script:Rules)

# Selected supporting settings and signals. Defaults and applicability differ by feature.
# Items with a collector are read; a portal-only entry here means this script does not collect it,
# not that no programmatic interface exists.
$script:Prerequisite = @(
    @{
        Name = 'Devices onboarded to Microsoft Purview'
        DeviceHealth = $true
        Portal = 'Purview portal > Settings > Device onboarding > Devices, then turn on Windows or macOS device monitoring'
        Why = 'Onboarding and Purview device monitoring support device signals for Endpoint DLP and Insider Risk Management. Supported activities depend on platform, configuration and health; policy application also requires user and device scope. Historical device signals do not establish the current monitoring setting.'
        Url = 'https://learn.microsoft.com/purview/device-onboarding-overview'
    }
    @{
        Name = 'Labels processed for Office files in SharePoint and OneDrive'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableAIPIntegration'
        Recommended = 'Set-SPOTenant -EnableAIPIntegration $true'
        Command = 'Set-SPOTenant -EnableAIPIntegration $true'; Session = 'SharePoint'
        Why = 'Supports service processing of eligible labelled Office files, including supported encryption configurations. The returned setting does not establish processing of every file or the state of search, eDiscovery, DLP or collaboration.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on PDF files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforPDF'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'; Session = 'SharePoint'
        Why = 'Adds supported PDF labelling and service-processing capabilities in SharePoint and OneDrive, including auto-labeling and library defaults. File and encryption limitations still apply; signed PDFs are not supported. This is not a test of all PDF protection.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on OneNote sections'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforOneNote'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'; Session = 'SharePoint'
        Why = 'Enables manual sensitivity labelling of OneNote sections in supported apps. Section-level support and app requirements apply; this setting is not proof that sections have been labelled.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on MP4 video files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelForVideoFiles'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'; Session = 'SharePoint'
        Why = 'Lets people apply sensitivity labels to MP4 videos in SharePoint and OneDrive. Teams recordings can inherit the meeting label when "Apply meeting label to artifacts" (preview) is enabled. MP4 files do not support auto-labeling policies or library default labels. Videos encrypted by a label can be played but not downloaded.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Label mismatch email to uploader and site owners'
        Collector = 'SharePointLabelingReadiness'; Setting = 'BlockSendLabelMismatchEmail'
        Recommended = 'Leave off: Set-SPOTenant -BlockSendLabelMismatchEmail $false'
        Command = 'Set-SPOTenant -BlockSendLabelMismatchEmail $false'; Session = 'SharePoint'
        Why = 'Retains email notification for supported document/site label-priority mismatches. This notifies rather than blocks the upload. Sublabels under the same parent are treated as equal for this comparison.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites'
    }
    @{
        Name = 'Default labels on document libraries'
        Collector = 'SharePointLabelingReadiness'; Setting = 'DisableDocumentLibraryDefaultLabeling'
        Recommended = 'Leave off: Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'
        Command = 'Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'; Session = 'SharePoint'
        Why = 'Allows library default labels to be configured. Eligible new or edited files are labelled subject to precedence and processing delays; existing files at rest are not automatically covered. A tenant setting alone proves neither library configuration nor file protection.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-default-label'
    }
    @{
        Name = 'Sensitive by default for new files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'MarkNewFilesSensitiveByDefault'
        Recommended = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'
        Command = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'; Session = 'SharePoint'
        Why = 'Blocks guest access to newly added files pending applicable content-based DLP evaluation. This is not a sensitivity label. Content outside suitable DLP coverage can remain inaccessible to guests; review sharing requirements and policy coverage before enabling it.'
        Url = 'https://learn.microsoft.com/sharepoint/sensitive-by-default'
    }
    @{
        Name = 'Co-authoring for files encrypted with sensitivity labels'
        Collector = 'TenantPolicyConfig'; Setting = 'EnableLabelCoauth'; ExpectedValue = 'True'
        Recommended = 'Purview portal > Settings > Information Protection > Co-authoring for files with sensitivity labels, then select "Turn on co-authoring for files with sensitivity labels"'
        Command = 'Set-PolicyConfig -EnableLabelCoauth $true'; Session = 'SecurityAndCompliance'
        Caution = 'One way in the portal: once on, it can only be turned off with Set-PolicyConfig -EnableLabelCoauth:$false, and Microsoft documents that doing so loses the newer labelling metadata for unencrypted Word, Excel and PowerPoint files. Turning it on also enables sensitivity labels for Office files in SharePoint and OneDrive if that is not already on.'
        Why = 'Lets people edit encrypted Office files together and use AutoSave in supported desktop and mobile apps. In Office for the web, co-authoring is available when sensitivity labels are enabled for SharePoint and OneDrive. Check app versions, encryption restrictions and compatibility with the updated label format before turning this on.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-coauthoring'
    }
    @{
        Name = 'Container labels for groups, Teams and sites'
        Collector = 'ContainerLabel'; Setting = 'EnableMIPLabels'
        Script = @{
            Builder = 'ContainerLabel'
            File = 'Enable-ContainerLabels.ps1'
            # Both, and in this order: the directory setting is written through Graph, the label
            # sync runs in Security & Compliance, and Graph's MSAL must not load first.
            Session = @('SecurityAndCompliance', 'Graph')
        }
        Recommended = 'Set EnableMIPLabels to True on the Group.Unified directory setting in Microsoft Entra, then run Execute-AzureAdLabelSync in Security & Compliance PowerShell'
        Caution = 'Needs at least one active Microsoft Entra ID P1 licence. Once this is on, the classic group classifications are no longer applied to groups, and Microsoft recommends not changing the group settings on a label after that label has been published and applied.'
        Why = 'Container labels configure supported privacy and access settings for groups, Teams and sites. Content does not inherit the container label or its encryption, but may have its own labels, encryption and permissions. This directory setting alone does not establish label application or effective container access controls.'
        Url = 'https://learn.microsoft.com/entra/identity/users/groups-assign-sensitivity-labels'
    }
    @{
        Name = 'Unified audit logging'
        RuleId = 'PA-AUD-0002'
        Summary = 'Unified audit ingestion is reported off; supported audit activity may be missing.'
        SummaryOk = 'Unified audit ingestion is reported on; this does not verify recording of every activity.'
        Recommended = 'Purview portal > Audit, then select "Start recording user and admin activity"'
        Command = 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'; Session = 'ExchangeOnline'
        Caution = 'Requires the Audit Logs role in Exchange Online. Enablement can take up to 60 minutes, and audit events can take several hours to become searchable. This changes ingestion only, not audit retention or mailbox auditing.'
        Why = 'Audit ingestion supports activity investigations. Defaults and retention depend on licensing, users, workloads and custom policies. Audit metadata is separate from retained conversation content; turning ingestion on does not backfill missed audit activity.'
        Url = $script:DocUrl.AuditLogEnable
    }
    @{
        Name = 'Teams DLP policies extended to SharePoint and OneDrive'
        # The property read back is not the parameter that sets it: Get-PolicyConfig returns
        # ExtendTeamsDlpToSpoOdbConsent, while Set-PolicyConfig takes the longer name below.
        Collector = 'TenantPolicyConfig'; Setting = 'ExtendTeamsDlpToSpoOdbConsent'; ExpectedValue = 'True'
        Recommended = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'
        Command = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'; Session = 'SecurityAndCompliance'
        Why = 'Extends Teams DLP policies to OneDrive content shared in 1:1 chats and SharePoint content associated with teams shared through channel chats. The setting does not prove coverage of all Teams files or successful rule application; verify the applicable policy and content scope.'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-policyconfig'
    }
    @{
        Name = 'DLP analytics'
        Evidence = @{
            Collector = 'DataLossPrevention'; Select = 'Policies'; Field = 'Name'; Match = '^RiskSpotlighting-'
            FoundState = 'Evidence found'
            Found = 'At least one policy name matches RiskSpotlighting-. This naming indicator does not verify recommendation objects or the current analytics setting.'
            NotFound = 'No policy name matches RiskSpotlighting-. This does not establish whether analytics is on or recommendations exist. Confirm in the portal.'
        }
        Portal = 'Purview portal > Settings > Data Loss Prevention > Analytics, then turn on "Activate analytics"'
        Why = 'DLP analytics uses the past 30 days of signals to suggest policy improvements. Microsoft documents it as off by default, with seven days to generate recommendations and weekly refreshes. A policy-name match here does not verify activation, recommendation availability or freshness.'
        Url = 'https://learn.microsoft.com/purview/dlp-analytics-get-started'
    }
    @{
        Name = 'Insider risk analytics'
        Portal = 'Purview portal > Settings > Insider Risk Management > Analytics, then turn on "Show insights at tenant level"'
        Why = 'Tenant-level analytics can inform policy design before policies are configured. Aggregated and anonymised presentation is not a guarantee that individuals cannot be identified through other authorised views or correlated data. This setting is not collected here.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-analytics'
    }
    @{
        Name = 'Insider risk data shared with other security solutions'
        Evidence = @{
            Collector = 'InsiderRiskSharing'; Select = 'Behaviors'
            FoundState = 'Seen recently'
            Found = 'DataSecurityBehaviors records were returned for the last 30 days. This does not prove delivery to alert queues or the sharing setting''s present state.'
            NotFound = 'No insider risk detail was recorded in Defender during the last 30 days. That does not mean sharing is off, since a tenant with nothing to report looks the same. Confirm in the portal.'
        }
        Optional = $true
        Portal = 'Purview portal > Settings > Insider Risk Management > Data sharing, then turn on "Share user risk details with other security solutions"'
        Why = 'Shares insider risk severity and supported activity context with Defender XDR, Communication Compliance and DLP investigation experiences, subject to policy scope and viewer permissions. This is investigation context, not an enforcement control; historical records here do not verify current sharing or delivery.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-share-data'
    }
    # Three Microsoft Defender for Cloud Apps settings, not Purview ones, but they decide how far
    # Purview labelling and DLP reach SaaS files. This script reads historical connector activity;
    # it does not read the file-monitoring or label-integration settings.
    @{
        Name = 'Defender for Cloud Apps: Microsoft 365 app connector'
        Evidence = @{
            Collector = 'CloudAppConnector'; Select = 'Connectors'
            FoundState = 'Seen recently'
            Found = 'Microsoft 365 activity from the Defender for Cloud Apps app connector was recorded during the last 30 days. This does not establish the connector''s present status or health.'
            NotFound = 'No Microsoft 365 app-connector activity was recorded during the last 30 days. That does not mean the connector is off, since an idle or undeployed tenant looks the same. Confirm in the portal.'
        }
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > App Connectors, then confirm the Microsoft 365 connector reads Connected'
        Why = 'The Microsoft 365 connector provides supported activity and file integration. CloudAppEvents gives historical activity evidence, not current connector health. Defender for Cloud Apps file policies retire January 6, 2027; that notice does not retire the connector or the product.'
        Url = 'https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365#connect-microsoft-365-to-microsoft-defender-for-cloud-apps'
    }
    @{
        Name = 'Defender for Cloud Apps: file monitoring'
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Files, then confirm "Enable file monitoring" is selected'
        Why = 'File monitoring supports Defender for Cloud Apps file policies and can switch off after seven days without an enabled file policy. Those file policies retire January 6, 2027; review the documented Purview migration path before investing in them. This is separate from native Purview scanning.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/data-protection-policies'
    }
    @{
        Name = 'Defender for Cloud Apps: sensitivity label integration'
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Microsoft Information Protection'
        Why = 'These settings support Defender for Cloud Apps sensitivity-label inspection and handling of labels from external tenants. They are not collected here. Review their use in light of the January 6, 2027 retirement of Defender for Cloud Apps file policies.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/content-inspection'
    }
    @{
        Name = 'Defender for Cloud Apps: inspect protected files'
        Evidence = @{
            Collector = 'ProtectedFilesConsent'; Select = 'Grants'
            FoundState = 'Granted'
            Found = 'A display-name-matched service-principal candidate has an assignment resolved to Content.SuperUser. Documented application and resource identities are not pinned by this check; verify the consent separately.'
            NotFound = 'No Content.SuperUser assignment was returned for the matched candidates. This is not proof that protected-file consent is absent. Confirm the application identity and consent in the portal.'
        }
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Microsoft Information Protection > Inspect protected files, then select Grant permission'
        Why = 'Protected-file inspection uses highly privileged Content.SuperUser access to decrypt supported protected content. This assessment reads candidate assignments, not a fully identity-validated consent. Review necessity and the file-policy retirement before granting access; the assessment grants nothing.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/content-inspection'
    }
    @{
        Name = 'Modern label scheme'
        LabelScheme = $true
        Portal = 'Purview portal > Solutions > Information Protection > Sensitivity labels. If the migration banner is present, select "Get started" > "Review new scheme". Review naming conflicts and newly selectable sublabels before separately approving migration. Migration and label unpublishing are not included in downloaded fixes.'
        Why = 'The modern scheme replaces parent labels with label groups. Migration is irreversible and can make additional sublabels selectable. Review the proposed scheme and publishing impact first; a reported scheme does not establish migration readiness or history.'
        Caution = 'Migration is irreversible. Microsoft recommends testing it first in a tenant with the same label configuration.'
        Url = 'https://learn.microsoft.com/purview/migrate-sensitivity-label-scheme'
    }
)

#endregion

#region Prerequisites
# Installing a module changes this machine, not the tenant. The read-only guarantee concerns tenant
# configuration; modules also supply authentication and export commands used by collection.

function Get-PurviewRequiredModule {
    <# .SYNOPSIS The modules live collection depends on, and how each must be loaded. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject]@{
            Name = 'Az.Accounts'
            Service = 'Azure'
            Connect = 'Connect-AzAccount'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
            MinimumVersion = ''
        }
        [pscustomobject]@{
            Name = 'Az.Resources'
            Service = 'Azure'
            Connect = 'Connect-AzAccount'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
            MinimumVersion = ''
        }
        [pscustomobject]@{
            Name = 'ExchangeOnlineManagement'
            Service = 'Exchange Online and Security & Compliance'
            Connect = 'Connect-IPPSSession; Connect-ExchangeOnline'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
            MinimumVersion = ''
        }
        [pscustomobject]@{
            Name = 'Microsoft.Graph.Authentication'
            Service = 'Microsoft Graph'
            Connect = 'Connect-MgGraph -Scopes LicenseAssignment.Read.All, GroupSettings.Read.All'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
            MinimumVersion = ''
        }
        [pscustomobject]@{
            Name = 'Microsoft.Online.SharePoint.PowerShell'
            Service = 'SharePoint Online'
            Connect = 'Connect-SPOService -Url https://<tenant>-admin.sharepoint.com -UseSystemBrowser $true'
            WindowsOnly = $true
            CommandName = @(
                'Connect-SPOService'
                'Disconnect-SPOService'
                'Get-SPOTenant'
                'Get-SPOSite'
                'Get-SPODataAccessGovernanceInsight'
            )
            # Microsoft documents that this module must be imported with -UseWindowsPowerShell on 7.
            NeedsWindowsPowerShell = $true
            # The version Microsoft documents for labelling OneNote sections, which is the newest
            # requirement any switch this script reads or writes carries.
            MinimumVersion = '16.0.26914.12004'
        }
    )
}

function Import-PurviewSharePointModule {
    <# .SYNOPSIS Imports only the SharePoint commands this run uses from an owned Windows PowerShell session. #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSModuleInfo])]
    param(
        [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$Path,
        [Parameter(Mandatory)][ValidateCount(1, 20)][string[]]$CommandName
    )

    $compatibilitySession = $null
    $proxyModule = $null
    try {
        # Import-Module -UseWindowsPowerShell shares one process-wide WinPSCompatSession. A module
        # loaded there earlier can pin an incompatible SharePoint Client assembly and make a later
        # SharePoint import fail. A fresh local runspace gives this module its own assembly boundary.
        $modulePath = [string]$Path
        $compatibilitySession = New-PSSession -UseWindowsPowerShell `
            -Name ('PurviewAdvisorSharePoint-{0}' -f [guid]::NewGuid().ToString('D')) -ErrorAction Stop

        $remoteName = @(Invoke-Command -Session $compatibilitySession -ErrorAction Stop -ScriptBlock {
            $null = Import-Module -Name $using:modulePath -Force -ErrorAction Stop -WarningAction SilentlyContinue
                @(Get-Module -Name Microsoft.Online.SharePoint.PowerShell | Select-Object -First 1 -ExpandProperty Name)
            })
        if ($remoteName.Count -ne 1 -or
            -not [string]::Equals([string]$remoteName[0], 'Microsoft.Online.SharePoint.PowerShell',
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The SharePoint Online module did not load in its Windows PowerShell session.'
        }

        $proxy = @(Import-PSSession -Session $compatibilitySession `
                -Module Microsoft.Online.SharePoint.PowerShell -CommandName $CommandName `
                -AllowClobber -DisableNameChecking -ErrorAction Stop -WarningAction SilentlyContinue)
        if ($proxy.Count -ne 1) {
            throw 'The SharePoint Online command proxy was not created.'
        }
        $proxyModule = $proxy[0]

        $imported = @(Get-Command -Module $proxyModule.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        $missing = @($CommandName | Where-Object { $imported -notcontains $_ })
        if ($missing.Count -gt 0) {
            throw ('The SharePoint Online module did not export: {0}.' -f ($missing -join ', '))
        }

        $script:OwnedCompatibilitySession += $compatibilitySession
        $script:OwnedCompatibilityModule += $proxyModule
        $script:CommandCache = @{}
        return $proxyModule
    }
    catch {
        # Neither object is user-owned: both were created inside this call and can be removed even
        # when the import stopped halfway through. Pre-existing compatibility sessions are untouched.
        if ($null -ne $proxyModule) {
            Remove-Module -ModuleInfo $proxyModule -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $compatibilitySession) {
            Remove-PSSession -Session $compatibilitySession -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Clear-PurviewCompatibilityModule {
    <# .SYNOPSIS Removes only Windows PowerShell sessions and proxy modules created by this run. #>
    [CmdletBinding()]
    param()

    foreach ($module in @($script:OwnedCompatibilityModule)) {
        try {
            if ($null -ne $module -and (Get-Module -Name $module.Name -ErrorAction SilentlyContinue)) {
                Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
            }
        }
        catch { Write-Verbose "The SharePoint command proxy could not be removed: $($_.Exception.Message)" }
    }
    foreach ($session in @($script:OwnedCompatibilitySession)) {
        try {
            if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction Stop }
        }
        catch { Write-Verbose "The SharePoint compatibility session could not be removed: $($_.Exception.Message)" }
    }

    $script:OwnedCompatibilityModule = @()
    $script:OwnedCompatibilitySession = @()
    $script:CommandCache = @{}
}

function Assert-PurviewGalleryRepository {
    <# .SYNOPSIS Verifies that the PSGallery name resolves to Microsoft's HTTPS module feed. #>
    [CmdletBinding()]
    param()

    if (-not (Get-Command -Name 'Get-PSRepository' -ErrorAction SilentlyContinue)) {
        throw 'PowerShellGet cannot inspect the registered PSGallery source.'
    }

    $repositories = @(Get-PSRepository -Name 'PSGallery' -ErrorAction Stop)
    if ($repositories.Count -ne 1) {
        throw 'Exactly one PSGallery repository must be registered before modules can be downloaded.'
    }

    $source = [string](Get-PurviewProperty -InputObject $repositories[0] -Name 'SourceLocation')
    $provider = [string](Get-PurviewProperty -InputObject $repositories[0] -Name 'PackageManagementProvider')
    $uri = $null
    $validUri = [uri]::TryCreate($source, [System.UriKind]::Absolute, [ref]$uri)
    $valid = $validUri -and $uri.Scheme -eq 'https' -and
        $uri.IdnHost -eq 'www.powershellgallery.com' -and
        $uri.IsDefaultPort -and
        $uri.AbsolutePath.TrimEnd('/') -eq '/api/v2' -and
        [string]::IsNullOrEmpty($uri.UserInfo) -and
        [string]::IsNullOrEmpty($uri.Query) -and
        [string]::IsNullOrEmpty($uri.Fragment) -and
        (-not $provider -or $provider -eq 'NuGet')
    if (-not $valid) {
        throw 'The repository named PSGallery is not the official HTTPS PowerShell Gallery feed. Restore it with Register-PSRepository -Default, or use -SkipModuleInstall.'
    }
}

function Test-PurviewCanPrompt {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false }
    return $null -ne $Host -and $null -ne $Host.UI
}

function Install-PurviewPrerequisite {
    <#
    .SYNOPSIS
        Installs any missing collection module to CurrentUser scope, then imports all of them.

    .DESCRIPTION
        Returns one result per module so the caller can report it rather than failing the run. A
        module that cannot be installed is reported, and its collectors record NotConnected.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject[]])]
    param(
        [switch]$SkipInstall,
        [switch]$AllowPrompt
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $plan = [System.Collections.Generic.List[object]]::new()
    $galleryReady = $SkipInstall
    $galleryProblem = ''
    if (-not $SkipInstall) {
        try {
            Assert-PurviewGalleryRepository
            $galleryReady = $true
        }
        catch {
            $galleryProblem = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
        }
    }

    # Hides PowerShellGet's progress bar and its warning that PackageManagement is already loaded.
    $quiet = {
        param([scriptblock]$Action)
        $was = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { & $Action } finally { $ProgressPreference = $was }
    }

    foreach ($module in Get-PurviewRequiredModule) {
        $outcome = [ordered]@{ Name = $module.Name; Service = $module.Service; Connect = $module.Connect; State = 'Unknown'; Detail = ''; Version = ''; LoadedBeforeUpdate = $false }

        if ($module.WindowsOnly -and -not $IsWindows) {
            $outcome.State = 'Unavailable'
            $outcome.Detail = 'Windows only, so this service cannot be collected on this platform.'
            $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
            continue
        }

        if (@(Get-Module -ListAvailable -Name $module.Name).Count -eq 0) {
            if ($SkipInstall) {
                $outcome.State = 'Missing'
                $outcome.Detail = "Install-Module $($module.Name) -Scope CurrentUser"
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }
            if (-not $galleryReady) {
                $outcome.State = 'Failed'
                $outcome.Detail = $galleryProblem
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }

            $canAsk = $AllowPrompt -and (Test-PurviewCanPrompt)
            if (-not $canAsk) {
                $outcome.State = 'Missing'
                $outcome.Detail = 'Installation requires interactive confirmation. Run without -SkipModuleInstall in an interactive PowerShell session.'
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }
            Write-Line -Message ''
            Write-Line -Style Warn -Message ('    {0} is not installed.' -f $module.Name)
            Write-Line -Style Dim -Message '    It will be installed from PSGallery for the current user.'
            if (([string](Read-Host '    Install it now? [y/N]')) -notmatch '^\s*(y|yes)\s*$') {
                $outcome.State = 'Missing'
                $outcome.Detail = 'Installation was declined.'
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($module.Name, 'Install from PSGallery for the current user')) {
                $outcome.State = 'Missing'
                $outcome.Detail = 'Installation was declined.'
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }

            try {
                & $quiet { Install-Module -Name $module.Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue }
                $installedAfter = @(Get-Module -ListAvailable -Name $module.Name |
                    Sort-Object Version -Descending | Select-Object -First 1)
                if ($installedAfter.Count -eq 0) {
                    throw "Install-Module completed, but $($module.Name) is not discoverable in the current user's module path."
                }
                $outcome.State = 'Installed'
                $outcome.Version = [string]$installedAfter[0].Version
            }
            catch {
                $outcome.State = 'Failed'
                $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }
        }
        else {
            $outcome.State = 'Present'
            $installed = @(Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending)[0].Version
            $outcome.Version = [string]$installed

            # Check the version as well as presence: missing parameters in old modules are local
            # prerequisite failures, not tenant faults.
            $floor = if ($module.MinimumVersion) { [version]$module.MinimumVersion } else { $null }
            $stale = $null -ne $floor -and $installed -lt $floor

            # No point asking the gallery when this run cannot offer the update.
            $canAsk = $AllowPrompt -and (Test-PurviewCanPrompt)
            $latest = $null
            if (-not $SkipInstall -and $canAsk -and $galleryReady) {
                try { $latest = [version](Find-Module -Name $module.Name -Repository PSGallery -ErrorAction Stop).Version }
                catch { $latest = $null }
            }
            $newer = $null -ne $latest -and $installed -lt $latest
            $target = if ($latest) { [string]$latest } else { 'the latest published version' }

            # Updating a working module changes this machine, so ask first. Unattended runs report it.
            $update = $false
            if (($stale -or $newer) -and -not $SkipInstall) {
                if ($canAsk) {
                    Write-Line -Message ''
                    Write-Line -Style Warn -Message ('    {0} is at {1}; {2} is available.' -f $module.Name, $installed, $target)
                    if ($stale) { Write-Line -Style Dim -Message ('    Microsoft documents {0} or later for the settings this reads.' -f $floor) }
                    $update = ([string](Read-Host '    Update it now? [y/N]')) -match '^\s*(y|yes)\s*$'
                }
            }

            if ($update) {
                $outcome.LoadedBeforeUpdate = $null -ne (Get-Module -Name $module.Name -ErrorAction SilentlyContinue)
                Write-Line -Style Dim -Message ('    Updating {0}.' -f $module.Name)
                try {
                    if ($null -ne $latest) {
                        & $quiet {
                            Install-Module -Name $module.Name -RequiredVersion $latest -Scope CurrentUser `
                                -Repository PSGallery -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                        }
                    }
                    else {
                        & $quiet {
                            Install-Module -Name $module.Name -Scope CurrentUser -Repository PSGallery `
                                -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                        }
                    }
                    $updatedAfter = @(Get-Module -ListAvailable -Name $module.Name |
                        Sort-Object Version -Descending | Select-Object -First 1)
                    if ($updatedAfter.Count -eq 0) {
                        throw "Module update completed, but $($module.Name) is not discoverable in the current user's module path."
                    }
                    $outcome.State = 'Updated'
                    $outcome.Version = [string]$updatedAfter[0].Version
                }
                catch {
                    if ($stale) { $outcome.State = 'Outdated' }
                    $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
                }
            }
            elseif ($stale) {
                $outcome.State = 'Outdated'
                $outcome.Detail = 'Version {0} is installed. Microsoft documents {1} or later for the settings this reads. Update-Module {2}' -f $installed, $floor, $module.Name
            }
            elseif ($newer) {
                $outcome.Detail = 'Version {0} is installed, {1} is published. Update-Module {2}' -f $installed, $latest, $module.Name
            }
        }

        $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $true })
    }

    # Do not import Az.Accounts into the advisor process. The Sentinel collector runs in a separate
    # process because Az.Accounts and the Microsoft 365 sign-in modules can load overlapping Azure
    # identity assemblies.
    $order = @($plan | Sort-Object @{ Expression = { if ($_.Module.Name -eq 'Microsoft.Graph.Authentication') { 0 } else { 1 } } })
    foreach ($item in $order) {
        $outcome = $item.Outcome
        if (-not $item.Import) { continue }
        if ($item.Module.Name -in 'Az.Accounts', 'Az.Resources') {
            # Keep the same prerequisite state as the other modules; only the import is isolated.
            continue
        }

        try {
            if ($item.Module.NeedsWindowsPowerShell) {
                # A session the operator deliberately kept is already isolated and may still be
                # signed in. Reuse it only when the whole allow-list is present; two core commands
                # cannot prove that later site and governance collectors remain callable.
                $missingLoadedCommand = @($item.Module.CommandName | Where-Object {
                        $null -eq (Get-Command -Name $_ -ErrorAction SilentlyContinue)
                    })
                $completeProxyLoaded = $outcome.State -notin 'Installed', 'Updated' -and
                    $missingLoadedCommand.Count -eq 0
                if ($completeProxyLoaded) {
                    $outcome.State = if ($outcome.State -eq 'Outdated') { 'OutdatedAndLoaded' } else { 'Loaded' }
                    $script:CommandCache = @{}
                    continue
                }

                # PowerShell 7 and Windows PowerShell use different CurrentUser module folders.
                # Pass the discovered manifest path into the isolated session so a module installed
                # only under PowerShell\Modules is still found without copying or reinstalling it.
                $available = @(Get-Module -ListAvailable -Name $item.Module.Name |
                        Sort-Object Version -Descending | Select-Object -First 1)
                if ($available.Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$available[0].Path)) {
                    throw "No installed manifest was found for $($item.Module.Name)."
                }
                $null = Import-PurviewSharePointModule -Path $available[0].Path `
                    -CommandName $item.Module.CommandName
            }
            else {
                Import-Module -Name $item.Module.Name -ErrorAction Stop
            }
            $outcome.State = switch ($outcome.State) {
                'Installed' { 'InstalledAndLoaded' }
                'Updated' { 'UpdatedAndLoaded' }
                'Outdated' { 'OutdatedAndLoaded' }
                default { 'Loaded' }
            }
        }
        catch {
            $outcome.State = 'Failed'
            $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
        }
    }

    # Reported in the order the modules are declared, not the order they were loaded in.
    foreach ($item in $plan) { $results.Add([pscustomobject]$item.Outcome) }

    # Updated files do not replace an already loaded sign-in library; a new process may be needed.
    if (@($results | Where-Object { $_.State -eq 'UpdatedAndLoaded' }).Count -gt 0) {
        Write-Line -Style Dim -Message '    A module was updated. If sign-in misbehaves, start a new PowerShell session and run this again.'
    }

    $script:PrerequisiteModuleResult = $results.ToArray()
    return $script:PrerequisiteModuleResult
}

function Get-PurviewExchangeConnection {
    <# .SYNOPSIS Returns active REST connections for one Exchange-backed service. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][ValidateSet('All', 'Compliance', 'ExchangeOnline')][string]$Service)

    if (-not (Test-PurviewCommand -Name 'Get-ConnectionInformation')) { return @() }

    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($connection in @(Get-ConnectionInformation -ErrorAction Stop)) {
        $state = [string](Get-PurviewProperty -InputObject $connection -Name 'State')
        if ($state -ne 'Connected') { continue }

        $isEopValue = Get-PurviewProperty -InputObject $connection -Name 'IsEopSession'
        $name = [string](Get-PurviewProperty -InputObject $connection -Name 'Name')
        $uri = [string](Get-PurviewProperty -InputObject $connection -Name 'ConnectionUri')
        $isCompliance = if ($isEopValue -is [bool]) { [bool]$isEopValue }
        elseif ($name -like 'ExchangeOnlineProtection*') { $true }
        elseif ($name -like 'ExchangeOnline_*') { $false }
        elseif ($uri -match 'compliance\.protection\.outlook\.com') { $true }
        elseif ($uri -match 'outlook\.office365\.com') { $false }
        else { $null }

        if ($Service -eq 'All' -or
            ($Service -eq 'Compliance' -and $isCompliance -eq $true) -or
            ($Service -eq 'ExchangeOnline' -and $isCompliance -eq $false)) {
            $matched.Add($connection)
        }
    }

    return $matched.ToArray()
}

function Get-PurviewSessionTenantState {
    <# .SYNOPSIS Verifies that connected services can be combined into one tenant snapshot. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([switch]$ExchangeOnly)

    $tenants = [System.Collections.Generic.List[string]]::new()
    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($service in 'Compliance', 'ExchangeOnline') {
        $connections = @(Get-PurviewExchangeConnection -Service $service)
        if ($connections.Count -gt 1) {
            $problems.Add("More than one active $service connection exists, so command routing is ambiguous.")
            continue
        }
        if ($connections.Count -eq 0) { continue }

        $tenant = [string](Get-PurviewProperty -InputObject $connections[0] -Name 'TenantID')
        $tenantId = [guid]::Empty
        if (-not [guid]::TryParse($tenant, [ref]$tenantId) -or $tenantId -eq [guid]::Empty) {
            $problems.Add("The active $service connection did not report a usable tenant ID.")
            continue
        }
        $tenants.Add($tenantId.ToString('D'))
    }

    if (-not $ExchangeOnly) {
        if ($null -ne $script:AzureSession -and $script:AzureSession.Connected) {
            $azureTenantId = [guid]::Empty
            if (-not [guid]::TryParse([string]$script:AzureSession.TenantId, [ref]$azureTenantId) -or
                $azureTenantId -eq [guid]::Empty) {
                $problems.Add('The Azure session did not report a usable tenant ID.')
            }
            else { $tenants.Add($azureTenantId.ToString('D')) }
        }
        if ($script:GraphSeparate) {
            try {
                $organizations = @(Invoke-PurviewGraphGet -Uri '/v1.0/organization?$select=id')
                $graphTenant = if ($organizations.Count -eq 1) {
                    [string](Get-PurviewProperty -InputObject $organizations[0] -Name 'id')
                }
                else { '' }
                $graphTenantId = [guid]::Empty
                if (-not [guid]::TryParse($graphTenant, [ref]$graphTenantId) -or
                    $graphTenantId -eq [guid]::Empty) {
                    $problems.Add('The isolated Microsoft Graph session did not report one usable tenant ID.')
                }
                else { $tenants.Add($graphTenantId.ToString('D')) }
            }
            catch { $problems.Add('The isolated Microsoft Graph session tenant could not be verified.') }
        }
        elseif (Test-PurviewCommand -Name 'Get-MgContext') {
            try {
                $context = Get-MgContext -ErrorAction Stop
                if ($null -ne $context) {
                    $graphTenant = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
                    $graphTenantId = [guid]::Empty
                    if (-not [guid]::TryParse($graphTenant, [ref]$graphTenantId) -or
                        $graphTenantId -eq [guid]::Empty) {
                        $problems.Add('The active Microsoft Graph context did not report a usable tenant ID.')
                    }
                    else { $tenants.Add($graphTenantId.ToString('D')) }
                }
            }
            catch { $problems.Add('The active Microsoft Graph context could not be verified.') }
        }
    }

    $distinct = @($tenants | Sort-Object -Unique)
    if ($distinct.Count -gt 1) {
        $problems.Add('The active service sessions belong to different tenants.')
    }

    return [pscustomobject]@{
        Valid = $problems.Count -eq 0
        TenantId = if ($distinct.Count -eq 1) { $distinct[0] } else { '' }
        Problems = $problems.ToArray()
    }
}

function Assert-PurviewSessionTenant {
    <# .SYNOPSIS Stops collection before independently connected services can be mixed. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([switch]$ExchangeOnly)

    $state = Get-PurviewSessionTenantState -ExchangeOnly:$ExchangeOnly
    if (-not $state.Valid) {
        throw ('Connected service sessions cannot be combined safely: {0} Start a new PowerShell session, connect every service to one tenant, and try again.' -f ($state.Problems -join ' '))
    }
    if ($state.TenantId) { $script:ExpectedTenantId = [string]$state.TenantId }
    return $state
}

function Test-PurviewConnected {
    <# .SYNOPSIS Reports whether a service already has a usable session, so it is not signed in twice. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][ValidateSet('SecurityAndCompliance', 'SharePoint', 'Graph', 'ExchangeOnline')][string]$Service)

    try {
        switch ($Service) {
            'SecurityAndCompliance' { return @(Get-PurviewExchangeConnection -Service 'Compliance').Count -gt 0 }
            'ExchangeOnline' { return @(Get-PurviewExchangeConnection -Service 'ExchangeOnline').Count -gt 0 }
            'Graph' {
                if ($script:GraphSeparate) { return $true }
                if (-not (Test-PurviewCommand -Name 'Get-MgContext')) { return $false }
                $context = Get-MgContext -ErrorAction Stop
                if ($null -eq $context) { return $false }
                $tenant = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
                if ($script:ExpectedTenantId -and $tenant -ine $script:ExpectedTenantId) { return $false }

                # Reconnect only when a scope is actually missing, never merely to refresh.
                $granted = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $context -Name 'Scopes'))
                if ($granted.Count -eq 0) { return $true }
                foreach ($needed in $script:GraphScope) {
                    if ($granted -notcontains $needed) { return $false }
                }
                return $true
            }
            'SharePoint' {
                # The module exports its cmdlets on import, so only a call proves a live session.
                if (-not (Test-PurviewCommand -Name 'Get-SPOTenant')) { return $false }
                $null = Get-SPOTenant -ErrorAction Stop -WarningAction SilentlyContinue
                return $true
            }
        }
    }
    catch { return $false }

    return $false
}

function Format-PurviewAdminUrl {
    <#
    .SYNOPSIS
        Normalises common tenant and URL inputs to a SharePoint admin URL.

    .DESCRIPTION
        Accepts a tenant name, a portal URL, or the non-admin hostname. Unrecognised input is
        returned unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value)

    $text = ([string]$Value).Trim().TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }

    # A bare tenant name, which is what most people offer. Hostnames are case insensitive, and
    # SharePoint's own are lower case, so a tenant name registered with capitals is folded here
    # rather than being carried into a URL that then has to match a token audience exactly.
    if ($text -notmatch '[./]') { return ('https://{0}-admin.sharepoint.com' -f ($text -replace '-(admin|my)$', '')).ToLowerInvariant() }

    # The tenant domain and a sign-in name are the other two common answers, and the first label of
    # that domain is the SharePoint host.
    if ($text -match '^(?:https?://)?(?:[^@/]+@)?([^./@]+)\.onmicrosoft\.com/?$') {
        return "https://$($Matches[1])-admin.sharepoint.com".ToLowerInvariant()
    }

    if ($text -notmatch '^https?://') { $text = "https://$text" }

    # -my and the plain hostname both point at the same tenant; the admin host is what is needed.
    if ($text -match '^https?://([^./]+?)(-admin|-my)?\.sharepoint\.com') {
        return "https://$($Matches[1])-admin.sharepoint.com".ToLowerInvariant()
    }

    return $text
}

function Resolve-PurviewTenantAdminUrl {
    <#
    .SYNOPSIS
        Works out the SharePoint admin URL rather than asking for it.

    .DESCRIPTION
        The tenant's initial domain gives the SharePoint hostname. verifiedDomains is readable with
        only User.Read, so this costs no extra consent. Falls back to the signed-in account's own
        domain, and returns empty rather than guessing if neither is conclusive.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $build = { param($domain) ('https://{0}-admin.sharepoint.com' -f ([string]$domain).Split('.')[0]).ToLowerInvariant() }

    if (Test-PurviewCommand -Name 'Invoke-MgGraphRequest') {
        try {
            foreach ($org in @(Invoke-PurviewGraphGet -Uri 'https://graph.microsoft.com/v1.0/organization')) {
                $domains = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $org -Name 'verifiedDomains')) |
                    Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'name') -match '\.onmicrosoft\.com$' }

                $initial = @($domains | Where-Object {
                        $isInitial = Get-PurviewProperty -InputObject $_ -Name 'isInitial'
                        $isInitial -is [bool] -and [bool]$isInitial
                    })
                $pick = if ($initial.Count -gt 0) { $initial[0] } elseif (@($domains).Count -gt 0) { @($domains)[0] } else { $null }

                if ($null -ne $pick) { return (& $build (Get-PurviewProperty -InputObject $pick -Name 'name')) }
            }
        }
        catch {
            Write-Verbose "Tenant domain lookup failed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }
    }

    $accounts = [System.Collections.Generic.List[string]]::new()
    if (Test-PurviewCommand -Name 'Get-MgContext') {
        try { $accounts.Add([string](Get-PurviewProperty -InputObject (Get-MgContext -ErrorAction Stop) -Name 'Account')) }
        catch { Write-Verbose 'The Graph context did not yield an account name.' }
    }
    if (Test-PurviewCommand -Name 'Get-ConnectionInformation') {
        try {
            foreach ($connection in @(Get-ConnectionInformation -ErrorAction Stop)) {
                $accounts.Add([string](Get-PurviewProperty -InputObject $connection -Name 'UserPrincipalName'))
            }
        }
        catch { Write-Verbose 'No Exchange connection information was available.' }
    }

    foreach ($account in @($accounts | Where-Object { $_ })) {
        if ($account -match '@(.+)\.onmicrosoft\.com$') { return (& $build $Matches[1]) }
    }

    return ''
}

function Test-PurviewAssemblyClash {
    <# .SYNOPSIS Recognises the one failure two modules in one process cause, so it is not shown raw. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    # Exchange Online and Graph each ship Microsoft.Identity.Client. .NET loads one per process, so
    # the second module calls a method its loaded copy does not have.
    return ($Message -match 'Microsoft\.Identity\.Client' -or $Message -match 'Microsoft\.IdentityModel') -and
        ($Message -match '(?i)method not found' -or $Message -match '(?i)could not load file or assembly' -or
        $Message -match '(?i)missingmethod')
}

function Get-PurviewSignedInAccount {
    <# .SYNOPSIS The account already signed in, so later sign-ins do not ask for it again. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (Test-PurviewCommand -Name 'Get-MgContext') {
        try {
            $account = [string](Get-PurviewProperty -InputObject (Get-MgContext -ErrorAction Stop) -Name 'Account')
            if ($account -match '@') { return $account }
        }
        catch { Write-Verbose 'No Graph context to take an account from.' }
    }

    if (Test-PurviewCommand -Name 'Get-ConnectionInformation') {
        try {
            foreach ($connection in @(Get-ConnectionInformation -ErrorAction Stop)) {
                $account = [string](Get-PurviewProperty -InputObject $connection -Name 'UserPrincipalName')
                if ($account -match '@') { return $account }
            }
        }
        catch { Write-Verbose 'No Exchange connection to take an account from.' }
    }

    return ''
}

function Get-PurviewSignInContext {
    <#
    .SYNOPSIS
        Reports the signed-in identity and role memberships visible through the current reads.

    .DESCRIPTION
        Read with the consent the run already has. Microsoft documents User.Read as the least
        privileged permission for the signed-in user's own memberships, so the Entra roles come
        back without widening what was asked for, and no other account is ever queried.

        Purview matching requires a verified compliance command and matching Graph/session
        identities. Unavailable commands, failed reads and incomplete membership data stay
        distinct from an empty result. A PIM-eligible Entra role can appear while its temporary
        activation is active. This does not evaluate effective access or enumerate PIM eligibility.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $account = Get-PurviewSignedInAccount
    $display = ''
    $objectId = ''
    $tenant = ''
    $graphTenant = ''
    $scopes = @()

    if (Test-PurviewCommand -Name 'Get-MgContext') {
        try {
            $context = Get-MgContext -ErrorAction Stop
            $tenant = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
            if (-not $script:GraphSeparate) { $graphTenant = $tenant }
            $scopes = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $context -Name 'Scopes'))
        }
        catch { Write-Verbose 'The Graph context held no tenant or scope detail.' }
    }

    if (-not $tenant -and (Test-PurviewCommand -Name 'Get-ConnectionInformation')) {
        try {
            foreach ($connection in @(Get-ConnectionInformation -ErrorAction Stop)) {
                $tenant = [string](Get-PurviewProperty -InputObject $connection -Name 'TenantID')
                if ($tenant) { break }
            }
        }
        catch { Write-Verbose 'No Exchange connection to take a tenant from.' }
    }

    $entra = [System.Collections.Generic.List[string]]::new()
    $entraRead = $false
    $entraUnnamed = $false
    $entraDetail = 'not read; Microsoft Graph is not connected or its request command is unavailable'
    $graphAccount = ''
    if ((Test-PurviewCommand -Name 'Invoke-MgGraphRequest') -and (Test-PurviewConnected -Service 'Graph')) {
        $entraDetail = 'not read; the Microsoft Graph membership request did not complete'
        try {
            # Without this object id, no Purview role group membership can be matched.
            $me = if ($script:GraphSeparate) { Invoke-PurviewGraphInNewSession -Verb 'GET' -Uri '/v1.0/me?$select=id,displayName,userPrincipalName' }
            else {
                Invoke-MgGraphRequest -Method GET -Uri '/v1.0/me?$select=id,displayName,userPrincipalName' `
                    -OutputType PSObject -ErrorAction Stop
            }
            $display = [string](Get-PurviewProperty -InputObject $me -Name 'displayName')
            $objectId = [string](Get-PurviewProperty -InputObject $me -Name 'id')
            $graphAccount = [string](Get-PurviewProperty -InputObject $me -Name 'userPrincipalName')
            if ($graphAccount) { $account = $graphAccount }
            # The isolated Graph process may differ from the parent's cached identity.
            # User.Read already permits the organization id; Exchange's tenant is not proof.
            if (-not $graphTenant) {
                $organizations = @(Invoke-PurviewGraphGet -Uri '/v1.0/organization?$select=id')
                if ($organizations.Count -eq 1) {
                    $graphTenant = [string](Get-PurviewProperty -InputObject $organizations[0] -Name 'id')
                    if ($graphTenant) { $tenant = $graphTenant }
                }
            }
        }
        catch { Write-Verbose "The directory did not name the signed-in user: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }

        try {
            $returned = 0
            # Avoid the OData cast's advanced-query headers/count: filter object types locally.
            foreach ($role in @(Invoke-PurviewGraphGet -Uri '/v1.0/me/memberOf')) {
                $type = [string](Get-PurviewProperty -InputObject $role -Name '@odata.type')
                if ([string]::IsNullOrWhiteSpace($type)) { throw 'A membership record did not identify its directory object type.' }
                if ($type -ne '#microsoft.graph.directoryRole') { continue }
                $returned++
                $name = [string](Get-PurviewProperty -InputObject $role -Name 'displayName')
                if (-not [string]::IsNullOrWhiteSpace($name)) { $entra.Add($name) }
            }

            # Microsoft documents that a directory object the sign-in cannot read comes back anyway,
            # carrying only its type and id with every other property null. Roles arriving nameless
            # therefore means they are held but unreadable, which is not the same as holding none.
            $entraUnnamed = $entra.Count -lt $returned
            $entraRead = -not $entraUnnamed
            $entraDetail = if ($entraUnnamed) { 'some current role memberships were returned without readable names' } else { '' }
            if ($entraUnnamed) { Write-Verbose "$($returned - $entra.Count) Entra role(s) came back without a readable name." }
        }
        catch { Write-Verbose "Entra roles were not readable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
    }

    $purview = [System.Collections.Generic.List[string]]::new()
    $purviewRead = $false
    $purviewDetail = 'not read; Security & Compliance is not connected'
    $identityGuid = [guid]::Empty
    $identityValid = [guid]::TryParse($objectId, [ref]$identityGuid) -and $identityGuid -ne [guid]::Empty
    if (Test-PurviewConnected -Service 'SecurityAndCompliance') {
        $purviewDetail = 'not read; the Graph user identity or tenant could not be verified for membership matching'
    }
    if ((Test-PurviewConnected -Service 'SecurityAndCompliance') -and $identityValid -and $graphAccount -and $graphTenant) {
        $purviewDetail = 'not read; the compliance role-group command or its session identity could not be verified'
        try {
            # Never fall back to the last imported command or another account's role groups.
            $connections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
                    $isEop = Get-PurviewProperty -InputObject $_ -Name 'IsEopSession'
                    $isCompliance = if ($isEop -is [bool]) { $isEop }
                    else { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -like 'ExchangeOnlineProtection*' }
                    $isCompliance -and [string](Get-PurviewProperty -InputObject $_ -Name 'State') -eq 'Connected'
                })
            if ($connections.Count -ne 1) { throw 'A unique connected compliance session was not found.' }
            $connection = $connections[0]
            if ([string](Get-PurviewProperty -InputObject $connection -Name 'UserPrincipalName') -ine $graphAccount -or
                [string](Get-PurviewProperty -InputObject $connection -Name 'TenantID') -ine $graphTenant) {
                $purviewDetail = 'not read; Graph and Security & Compliance account or tenant identities differ'
                throw 'Graph and compliance session identities did not match.'
            }
            $path = [string](Get-PurviewProperty -InputObject $connection -Name 'ModuleName')
            $leaf = if ($path) { [System.IO.Path]::GetFileName($path) } else { '' }
            $modules = @(Get-Module | Where-Object { ($path -and $_.Path -eq $path) -or ($leaf -and $_.Name -eq $leaf) })
            if ($modules.Count -ne 1 -or -not $modules[0].ExportedCommands.ContainsKey('Get-RoleGroup')) {
                throw 'The verified compliance module did not expose Get-RoleGroup.'
            }
            $purviewDetail = 'not read; the compliance role-group request failed; check role access and service availability'
            $groups = @(& $modules[0].ExportedCommands['Get-RoleGroup'] -ResultSize Unlimited -ErrorAction Stop)
            $membershipComplete = $true

            foreach ($group in $groups) {
                # Missing/null Members is not an explicitly empty membership collection.
                $rawMembers = $null
                if ($group -is [System.Collections.IDictionary]) { $rawMembers = $group['Members'] }
                elseif ($null -ne $group -and $group.PSObject.Properties['Members']) { $rawMembers = $group.PSObject.Properties['Members'].Value }
                if ($null -eq $rawMembers) { $membershipComplete = $false; continue }
                $members = @($rawMembers)
                $held = $false
                foreach ($member in $members) {
                    # Accept a GUID or directory path ending in one. Other shapes stay unresolved:
                    # an account or display name is not an immutable directory identity.
                    $memberGuid = [guid]::Empty
                    $memberLeaf = @(([string]$member) -split '[\\/]')[-1].Trim()
                    if (-not [guid]::TryParse($memberLeaf, [ref]$memberGuid) -or $memberGuid -eq [guid]::Empty) {
                        $membershipComplete = $false
                        continue
                    }
                    if ($memberGuid -eq $identityGuid) { $held = $true }
                }
                if ($held) {
                    $name = [string](Get-PurviewProperty -InputObject $group -Name 'DisplayName')
                    if (-not $name) { $name = [string](Get-PurviewProperty -InputObject $group -Name 'Name') }
                    if (-not [string]::IsNullOrWhiteSpace($name)) { $purview.Add($name) }
                    else { $membershipComplete = $false }
                }
            }

            $purviewRead = $membershipComplete
            $purviewDetail = if ($membershipComplete) { '' } else { 'membership data was incomplete; additional direct role groups could not be determined' }
        }
        catch { Write-Verbose "Role groups were not readable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
    }

    $services = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $script:AzureSession -and $script:AzureSession.Connected) {
        $services.Add('Azure')
        if (-not $account) { $account = $script:AzureSession.AccountId }
        if (-not $tenant) { $tenant = $script:AzureSession.TenantId }
    }
    foreach ($pair in @(
            @{ Service = 'SecurityAndCompliance'; Label = 'Security & Compliance' }
            @{ Service = 'ExchangeOnline'; Label = 'Exchange Online' }
            @{ Service = 'Graph'; Label = 'Microsoft Graph' }
            @{ Service = 'SharePoint'; Label = 'SharePoint Online' }
        )) {
        if (Test-PurviewConnected -Service $pair.Service) { $services.Add($pair.Label) }
    }

    return [pscustomobject]@{
        Account = $account
        DisplayName = $display
        TenantId = $tenant
        Service = $services.ToArray()
        GraphScope = @($scopes)
        EntraRole = @($entra | Sort-Object -Unique)
        EntraRoleRead = $entraRead
        EntraRoleUnnamed = $entraUnnamed
        EntraRoleDetail = $entraDetail
        PurviewRoleGroup = @($purview | Sort-Object -Unique)
        PurviewRoleGroupRead = $purviewRead
        PurviewRoleGroupDetail = $purviewDetail
    }
}

function Test-PurviewBrokerRetry {
    <#
    .SYNOPSIS
        Recognises the MSAL broker failing before any prompt was shown.

    .DESCRIPTION
        Broker initialization can fail, including on Windows on Arm even when the native library
        is installed. Matching error text permits a retry without WAM; it does not prove the cause.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )

    if ($Message -notmatch 'RuntimeBroker|NativeInterop|Object reference not set') { return $false }

    $connect = Get-Command -Name $Command -ErrorAction SilentlyContinue
    return $null -ne $connect -and $connect.Parameters.ContainsKey('DisableWAM')
}

function Test-PurviewDisableWamFirst {
    <# .SYNOPSIS Uses the documented non-WAM path before a broker that stalls on Windows Arm. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Command)

    try {
        if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [System.Runtime.InteropServices.OSPlatform]::Windows)) {
            return $false
        }
        if ([string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
            return $false
        }
    }
    catch { return $false }

    $connect = Get-Command -Name $Command -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $connect -and $connect.Parameters.ContainsKey('DisableWAM')
}

function Invoke-PurviewExchangeSignIn {
    <#
    .SYNOPSIS
        Runs one Exchange-module interactive sign-in, retrying without WAM when appropriate.

    .DESCRIPTION
        WAM failures happen before the operator sees a prompt, so their noisy first error is hidden.
        The non-WAM call keeps every non-error stream visible because any of them can carry browser
        sign-in instructions. Success output is sent to the host rather than returned to this helper;
        no token is read or held.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateSet('Connect-IPPSSession', 'Connect-ExchangeOnline')][string]$Command,
        [hashtable]$Argument = @{},
        [switch]$DisableWamFirst
    )

    $connect = Get-Command -Name $Command -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $connect) { return "$Command is no longer available in this session." }
    if ($DisableWamFirst -and $connect.Parameters.ContainsKey('DisableWAM')) {
        try {
            & $connect @Argument -DisableWAM -ErrorAction Stop | Out-Host
            return ''
        }
        catch { return 'Sign-in without the broker could not acquire a token. ' + $_.Exception.Message }
    }

    $failure = ''
    try { & $connect @Argument -ErrorAction Stop -WarningAction SilentlyContinue *> $null }
    catch { $failure = [string]$_.Exception.Message }

    if (Test-PurviewBrokerRetry -Command $Command -Message $failure) {
        $failure = ''
        try {
            & $connect @Argument -DisableWAM -ErrorAction Stop | Out-Host
        }
        catch { $failure = 'Sign-in could not acquire a token, with and without the broker. ' + $_.Exception.Message }
    }

    return $failure
}

# Commercial cloud only. An empty value means the parameter is not passed and the module keeps
# its default. Existing sessions are not independently verified for cloud membership.
$script:CloudEndpoint = [ordered]@{
    'Commercial' = @{ Scc = ''; SccAuth = ''; Exchange = ''; Graph = ''; SpoRegion = '' }
}

function Test-PurviewSignInIncomplete {
    <#
    .SYNOPSIS
        Distinguishes an incomplete sign-in from an incorrect address.

    .DESCRIPTION
        SharePoint reports both as connection failures. An incomplete sign-in needs another
        authentication attempt; an incorrect address needs a different URL.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    return $Message -match '(?i)(no valid OAuth|authentication session|authentication failed|user cancell?ed|was cancell?ed|interaction.?required|login is required|AADSTS)'
}

function Get-PurviewVerifiedAzureContext {
    <# .SYNOPSIS Validates Azure identity and a current ARM token, not just saved context metadata. #>
    [CmdletBinding()]
    [OutputType([object])]
    param([string]$TenantId = '')

    $context = Get-AzContext -ErrorAction Stop
    if ($null -eq $context) { throw 'Azure is not connected. Run Connect-AzAccount first.' }
    $actualTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $context -Name 'Tenant') -Name 'Id')
    $subscription = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $context -Name 'Subscription') -Name 'Id')
    $account = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $context -Name 'Account') -Name 'Id')
    $cloud = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $context -Name 'Environment') -Name 'Name')
    foreach ($identity in @($actualTenant, $subscription)) {
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($identity, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
            throw 'The Azure context has no usable tenant or subscription ID. Run Connect-AzAccount first.'
        }
    }
    if ([string]::IsNullOrWhiteSpace($account)) { throw 'The Azure context has no account. Run Connect-AzAccount first.' }
    if ($cloud -ne 'AzureCloud') { throw 'Only the commercial AzureCloud environment is supported.' }
    if ($TenantId -and $actualTenant -ine $TenantId) {
        throw 'The Azure context belongs to a different tenant than the Microsoft 365 assessment.'
    }

    $token = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -TenantId $actualTenant `
        -DefaultProfile $context -ErrorAction Stop
    $value = Get-PurviewProperty -InputObject $token -Name 'Token'
    $hasToken = if ($value -is [System.Security.SecureString]) { $value.Length -gt 0 }
    else { $value -is [string] -and -not [string]::IsNullOrWhiteSpace($value) }
    $expires = Get-PurviewProperty -InputObject $token -Name 'ExpiresOn'
    if (-not $hasToken -or $null -eq $expires -or [DateTimeOffset]$expires -le [DateTimeOffset]::UtcNow) {
        throw 'Azure did not return a current ARM access token. Run Connect-AzAccount again.'
    }
    if ([string](Get-PurviewProperty -InputObject $token -Name 'TenantId') -ine $actualTenant) {
        throw 'The Azure access token does not belong to the active tenant.'
    }
    return $context
}

function Connect-PurviewAzureAccount {
    <# .SYNOPSIS Authenticates in the isolated worker and saves an explicit context for collection. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$ContextPath,
        [string]$TenantId = ''
    )

    Import-Module -Name Az.Accounts, Az.Resources -ErrorAction Stop
    Enable-AzContextAutosave -Scope Process -ErrorAction Stop | Out-Null
    $reused = $false
    try {
        $context = Get-PurviewVerifiedAzureContext -TenantId $TenantId
        $reused = $true
    }
    catch {
        Write-Verbose "Azure session reuse was not possible: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        $arguments = @{ Environment = 'AzureCloud'; ErrorAction = 'Stop' }
        if ($TenantId) { $arguments['Tenant'] = $TenantId }
        $configuration = Get-Command -Name 'Update-AzConfig' -ErrorAction SilentlyContinue
        if ($null -ne $configuration -and $configuration.Parameters.ContainsKey('LoginExperienceV2')) {
            # Collection covers every accessible subscription; a hidden console selector must not block sign-in.
            Update-AzConfig -LoginExperienceV2 Off -Scope Process -ErrorAction Stop | Out-Null
        }
        Connect-AzAccount @arguments | Out-Null
        $context = Get-PurviewVerifiedAzureContext -TenantId $TenantId
    }

    Save-AzContext -Path $ContextPath -Force -ErrorAction Stop | Out-Null
    if (-not (Test-Path -LiteralPath $ContextPath -PathType Leaf)) {
        throw 'Azure authentication completed, but its context was not saved for the collector.'
    }

    $role = @()
    $roleDetail = ''
    try {
        if ([string]$context.Account.Type -ne 'User') {
            throw 'The Azure RBAC display supports user sign-ins; this context uses another account type.'
        }
        $assignments = @(Get-AzRoleAssignment -SignInName $context.Account.Id `
            -Scope ("/subscriptions/{0}" -f $context.Subscription.Id) -DefaultProfile $context -ErrorAction Stop)
        $role = @($assignments | ForEach-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'RoleDefinitionName')
            } | Where-Object { $_ } | Sort-Object -Unique)
        $unnamed = @($assignments | Where-Object {
                [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'RoleDefinitionName'))
            })
        if ($unnamed.Count -gt 0) { $roleDetail = 'some Azure RBAC assignments did not report a role name' }
        elseif ($role.Count -eq 0) { $roleDetail = 'none currently reported for the active subscription' }
    }
    catch {
        $roleDetail = 'not read; {0}' -f (Get-PurviewSafeErrorMessage -Message $_.Exception.Message)
    }
    return [pscustomobject]@{
        Connected = $true
        Reused = $reused
        TenantId = [string]$context.Tenant.Id
        SubscriptionId = [string]$context.Subscription.Id
        AccountId = [string]$context.Account.Id
        Role = $role
        RoleDetail = $roleDetail
    }
}

function Connect-PurviewSession {
    <#
    .SYNOPSIS
        Signs in to whatever is not already connected.

    .DESCRIPTION
        This helper has no credential or token parameters. Authentication modules manage sign-in
        and token handling, including their caches. Anything left unconnected is reported rather
        than treated as a fatal error for every service.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string]$TenantAdminUrl = '',
        [ValidateSet('Commercial')][string]$Environment = 'Commercial',
        [switch]$AllowPrompt
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $script:AzureSession = $null
    $script:AzureSessionContextPath = ''
    $script:AzureRole = @()
    $script:AzureRoleDetail = 'not read; Azure is not connected'
    $initialExchangeConnections = @(Get-PurviewExchangeConnection -Service 'All')
    $initialExchangeIds = @($initialExchangeConnections | ForEach-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'ConnectionId')
        } | Where-Object { $_ })
    if (@($initialExchangeConnections | Where-Object {
                $connectionId = [string](Get-PurviewProperty -InputObject $_ -Name 'ConnectionId')
                -not $connectionId -or $connectionId -notin $script:OwnedExchangeConnectionId
            }).Count -gt 0) {
        $script:HadPreExistingExchangeConnection = $true
    }

    $record = {
        param($service, $state, $detail, $owned)
        # Track sessions opened by this run even though final cleanup also disconnects reused sessions.
        if ($owned) { $script:OwnedSession += $owned }
        # Connecting imports cmdlets, so anything previously recorded as absent may now exist.
        $script:CommandCache = @{}
        $script:ServiceModuleCache = @{}
        Write-PurviewStepResult -Status $state
        if ($detail) { Write-Line -Style Dim -Message ('             {0}' -f $detail) }
        $results.Add([pscustomobject]@{ Service = $service; State = $state; Detail = $detail })
    }

    # Connect Exchange endpoints first: Microsoft.Graph.Authentication and ExchangeOnlineManagement
    # ship different Microsoft.Identity.Client versions, and .NET keeps the first loaded. Loading
    # Graph's older MSAL first leaves Exchange's newer broker extension binding against it and
    # throwing in the broker constructor before any prompt appears.
    $account = Get-PurviewSignedInAccount
    $hint = @{}
    if ($account) { $hint['UserPrincipalName'] = $account }

    $cloud = $script:CloudEndpoint[$Environment]
    $sccArgs = @{}
    if ($cloud.Scc) { $sccArgs['ConnectionUri'] = $cloud.Scc; $sccArgs['AzureADAuthorizationEndpointUri'] = $cloud.SccAuth }
    $exoArgs = @{}
    if ($cloud.Exchange) { $exoArgs['ExchangeEnvironmentName'] = $cloud.Exchange }
    $graphArgs = @{ ContextScope = 'Process'; Environment = 'Global' }
    if ($cloud.Graph) { $graphArgs['Environment'] = $cloud.Graph }

    Write-PurviewStep -Name 'Security & Compliance'
    if (Test-PurviewConnected -Service 'SecurityAndCompliance') {
        & $record 'Security & Compliance' 'Connected' '' $null
    }
    elseif (Test-PurviewCommand -Name 'Connect-IPPSSession') {
        $arguments = @{}
        foreach ($source in @($hint, $sccArgs)) {
            foreach ($name in $source.Keys) { $arguments[$name] = $source[$name] }
        }
        $withoutWam = Test-PurviewDisableWamFirst -Command 'Connect-IPPSSession'
        $failure = Invoke-PurviewExchangeSignIn -Command 'Connect-IPPSSession' -Argument $arguments `
            -DisableWamFirst:$withoutWam

        if ($failure) {
            & $record 'Security & Compliance' 'Failed' (Get-PurviewSafeErrorMessage -Message $failure) $null
        }
        else {
            foreach ($connection in @(Get-PurviewExchangeConnection -Service 'Compliance')) {
                $id = [string](Get-PurviewProperty -InputObject $connection -Name 'ConnectionId')
                if ($id -and $id -notin $initialExchangeIds -and $id -notin $script:OwnedExchangeConnectionId) {
                    $script:OwnedExchangeConnectionId += $id
                }
            }
            & $record 'Security & Compliance' 'Connected' '' 'SecurityAndCompliance'
        }
    }
    else {
        & $record 'Security & Compliance' 'Unavailable' 'The ExchangeOnlineManagement module is not loaded.' $null
    }

    # Whoever just signed in is the hint for the rest, so the address is typed once.
    if (-not $account) {
        $account = Get-PurviewSignedInAccount
        if ($account) { $hint['UserPrincipalName'] = $account }
    }

    Write-PurviewStep -Name 'Exchange Online'
    if (Test-PurviewConnected -Service 'ExchangeOnline') {
        & $record 'Exchange Online' 'Connected' '' $null
    }
    elseif (Test-PurviewCommand -Name 'Connect-ExchangeOnline') {
        # Only Exchange Online reports whether unified audit logging is actually on.
        $arguments = @{ ShowBanner = $false }
        foreach ($source in @($hint, $exoArgs)) {
            foreach ($name in $source.Keys) { $arguments[$name] = $source[$name] }
        }
        $withoutWam = Test-PurviewDisableWamFirst -Command 'Connect-ExchangeOnline'
        $failure = Invoke-PurviewExchangeSignIn -Command 'Connect-ExchangeOnline' -Argument $arguments `
            -DisableWamFirst:$withoutWam

        if ($failure) {
            & $record 'Exchange Online' 'Failed' (Get-PurviewSafeErrorMessage -Message $failure) $null
        }
        else {
            foreach ($connection in @(Get-PurviewExchangeConnection -Service 'ExchangeOnline')) {
                $id = [string](Get-PurviewProperty -InputObject $connection -Name 'ConnectionId')
                if ($id -and $id -notin $initialExchangeIds -and $id -notin $script:OwnedExchangeConnectionId) {
                    $script:OwnedExchangeConnectionId += $id
                }
            }
            & $record 'Exchange Online' 'Connected' '' 'ExchangeOnline'
        }
    }
    else {
        & $record 'Exchange Online' 'Unavailable' 'The ExchangeOnlineManagement module is not loaded.' $null
    }

    # Bind Graph to the tenant reported by the Exchange-backed sessions when one is available.
    # A mismatch between those two sessions is unsafe even before Graph is contacted.
    $null = Assert-PurviewSessionTenant -ExchangeOnly
    if ($script:ExpectedTenantId) { $graphArgs['TenantId'] = $script:ExpectedTenantId }

    # Connect Graph last to preserve Exchange's loaded MSAL. When supported by the installed
    # Graph module, LoginHint carries forward the username already used for Exchange sign-in so
    # the browser does not ask the operator to choose a work-account type again.
    $graphConnect = Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue
    if ($hint.ContainsKey('UserPrincipalName') -and $null -ne $graphConnect -and $graphConnect.Parameters.ContainsKey('LoginHint')) {
        $graphArgs['LoginHint'] = $hint['UserPrincipalName']
    }
    Write-PurviewStep -Name 'Microsoft Graph'
    if (Test-PurviewConnected -Service 'Graph') {
        & $record 'Microsoft Graph' 'Connected' '' $null
    }
    elseif (Test-PurviewCommand -Name 'Connect-MgGraph') {
        try {
            # The module warns about hidden browser windows on every call. It lands mid-line in the
            # status column, so it is silenced here and the sign-in prompt speaks for itself.
            Connect-MgGraph -Scopes $script:GraphScope @graphArgs -NoWelcome -ErrorAction Stop -WarningAction SilentlyContinue
            & $record 'Microsoft Graph' 'Connected' '' 'Graph'
        }
        catch {
            $graphError = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
            if (Test-PurviewAssemblyClash -Message $graphError) {
                # No arrangement inside this process settles a loaded assembly, so Graph gets its own.
                $script:GraphSeparate = $true
                $probe = $null
                $sessionError = ''
                try { $probe = Invoke-PurviewGraphInNewSession -Verb 'GET' -Uri '/v1.0/me?$select=id' }
                catch { $sessionError = Get-PurviewSafeErrorMessage -Message $_.Exception.Message }

                if ($probe) {
                    # Which process signed in is not the reader's concern.
                    & $record 'Microsoft Graph' 'Connected' '' 'Graph'
                }
                else {
                    $script:GraphSeparate = $false
                    $why = if ($sessionError) { ' Its own session reported: {0}' -f $sessionError } else { '' }
                    & $record 'Microsoft Graph' 'Failed' ('The Exchange Online and Microsoft Graph modules encountered a shared-library conflict, and reading Graph in a separate session did not work either.{0} Graph-dependent directory, consent and hunting reads may be unavailable.' -f $why) $null
                }
            }
            else { & $record 'Microsoft Graph' 'Failed' $graphError $null }
        }
    }
    else {
        & $record 'Microsoft Graph' 'Unavailable' 'The Microsoft.Graph.Authentication module is not loaded.' $null
    }

    # Bind Azure to the assessed tenant before reusing a cached account. Its assemblies stay
    # isolated, and the collector imports this run's context rather than whichever default is saved later.
    $null = Assert-PurviewSessionTenant
    Write-PurviewStep -Name 'Azure'
    $azurePwsh = Get-PurviewPowerShell7Path
    if ([string]::IsNullOrWhiteSpace($azurePwsh)) {
        $script:AzureSession = [pscustomobject]@{ Connected = $false; Error = 'PowerShell 7 is required for the isolated Azure sign-in.' }
        & $record 'Azure' 'Unavailable' $script:AzureSession.Error $null
    }
    else {
        $azureOutput = Join-Path ([System.IO.Path]::GetTempPath()) ('PurviewAzureSignIn-{0}.json' -f [guid]::NewGuid())
        $azureError = "$azureOutput.err"
        $azureConsole = "$azureOutput.out"
        $contextPath = "$azureOutput.context.json"
        $script:TempArtifact += @($azureOutput, $azureError, $azureConsole, $contextPath)
        $azureArguments = @('-NoLogo', '-NoProfile', '-File', ('"{0}"' -f $PSCommandPath),
            '-AzureSignInWorker', '-AzureSignInOutputPath', ('"{0}"' -f $azureOutput),
            '-AzureContextPath', ('"{0}"' -f $contextPath))
        if ($script:ExpectedTenantId) { $azureArguments += @('-AzureTenantId', $script:ExpectedTenantId) }
        try {
            $start = @{
                FilePath = $azurePwsh
                ArgumentList = $azureArguments
                WorkingDirectory = (Get-Location).Path
                PassThru = $true
                RedirectStandardError = $azureError
                RedirectStandardOutput = $azureConsole
            }
            if ($IsWindows) { $start['NoNewWindow'] = $true }
            $azureProcess = Start-Process @start
            $script:AzureSignInProcess = $azureProcess
            # Retain the native process handle so ExitCode remains available after a short-lived worker exits.
            $null = $azureProcess.Handle
            $azureProcess.WaitForExit()
            $azureProcess.Refresh()
            $azureSignIn = if (Test-Path -LiteralPath $azureOutput -PathType Leaf) {
                Get-Content -LiteralPath $azureOutput -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
            }
            else { $null }
            $connected = Get-PurviewProperty -InputObject $azureSignIn -Name 'Connected'
            if ($azureProcess.ExitCode -notin 0, 2 -or $connected -isnot [bool] -or -not $connected) {
                $failure = [string](Get-PurviewProperty -InputObject $azureSignIn -Name 'Error')
                if (-not $failure -and (Test-Path -LiteralPath $azureError -PathType Leaf)) {
                    $failure = [string](Get-Content -LiteralPath $azureError -Raw)
                }
                if (-not $failure) { $failure = 'Azure sign-in returned no verified connection. Complete authentication and try again.' }
                throw $failure
            }
            foreach ($field in 'TenantId', 'SubscriptionId') {
                $identity = [guid]::Empty
                if (-not [guid]::TryParse([string](Get-PurviewProperty -InputObject $azureSignIn -Name $field), [ref]$identity) -or
                    $identity -eq [guid]::Empty) { throw "Azure sign-in did not return a usable $field." }
            }
            if ($script:ExpectedTenantId -and $azureSignIn.TenantId -ine $script:ExpectedTenantId) {
                throw 'Azure signed in to a different tenant than the Microsoft 365 assessment.'
            }
            if ([string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $azureSignIn -Name 'AccountId')) -or
                -not (Test-Path -LiteralPath $contextPath -PathType Leaf)) {
                throw 'Azure sign-in did not return an account and a saved context for collection.'
            }
            $script:AzureSession = $azureSignIn
            $script:AzureSessionContextPath = $contextPath
            $script:AzureRole = @(Get-PurviewProperty -InputObject $azureSignIn -Name 'Role')
            $script:AzureRoleDetail = [string](Get-PurviewProperty -InputObject $azureSignIn -Name 'RoleDetail')
            $owned = if ($azureProcess.ExitCode -eq 0) { 'Azure' } else { $null }
            & $record 'Azure' 'Connected' '' $owned
        }
        catch {
            $failure = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
            $script:AzureSession = [pscustomobject]@{ Connected = $false; Error = $failure }
            $script:AzureRoleDetail = 'not read; Azure is not connected'
            & $record 'Azure' 'Failed' $failure $null
        }
        finally {
            Remove-Item -LiteralPath $azureOutput, $azureError, $azureConsole -Force -ErrorAction SilentlyContinue
        }
    }

    Write-PurviewStep -Name 'SharePoint Online'
    if (Test-PurviewConnected -Service 'SharePoint') {
        & $record 'SharePoint Online' 'Connected' '' $null
        return $results.ToArray()
    }

    # Worked out before the module check, because a remediation script still needs the URL even
    # when this run could not sign in to SharePoint itself.
    $url = Format-PurviewAdminUrl -Value $TenantAdminUrl
    $derived = $false
    if ([string]::IsNullOrWhiteSpace($url)) {
        $url = Resolve-PurviewTenantAdminUrl
        $derived = -not [string]::IsNullOrWhiteSpace($url)
    }
    if ($url) { $script:SharePointAdminUrl = $url }

    if (-not (Test-PurviewCommand -Name 'Connect-SPOService')) {
        $moduleResult = @($script:PrerequisiteModuleResult | Where-Object { $_.Service -eq 'SharePoint Online' })
        $moduleDetail = if ($moduleResult.Count -eq 1) { [string]$moduleResult[0].Detail } else { '' }
        $message = if (-not $IsWindows) {
            'SharePoint Online PowerShell is available only on Windows.'
        }
        elseif ($moduleDetail) {
            'The SharePoint Online module did not load. {0}' -f $moduleDetail
        }
        else {
            'The SharePoint Online module did not load in this PowerShell session.'
        }
        & $record 'SharePoint Online' 'Unavailable' $message $null
        return $results.ToArray()
    }

    if ([string]::IsNullOrWhiteSpace($url) -and $AllowPrompt) {
        Write-PurviewStepResult -Status 'NeedsInput'
        Write-Line -Style Warn -Message '    Your SharePoint admin URL could not be worked out from the signed-in account.'
        Write-Line -Style Dim -Message '    Enter it, or press Enter to skip SharePoint. A tenant name on its own is enough.'
        $url = Format-PurviewAdminUrl -Value (Read-Host '    SharePoint admin URL')
        Write-PurviewStep -Name 'SharePoint Online'
    }

    if ([string]::IsNullOrWhiteSpace($url)) {
        & $record 'SharePoint Online' 'Skipped' 'No admin URL was available, so SharePoint was not assessed.' $null
        return $results.ToArray()
    }
    $script:SharePointAdminUrl = $url

    # A derived URL is a good guess, not a certainty, so a wrong one is corrected rather than fatal.
    $useSystemBrowser = $true
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            # Prefer the system browser for passkeys and platform authenticators. Keep the module
            # dialog as a fallback for machines where browser sign-in does not complete.
            $spoArgs = @{}
            if ($cloud.SpoRegion) { $spoArgs['Region'] = $cloud.SpoRegion }
            if ($useSystemBrowser) { $spoArgs['UseSystemBrowser'] = $true }
            Connect-SPOService -Url $url @spoArgs -ErrorAction Stop
            # Only interesting when it goes wrong, and the failure path already prints what it tried.
            if ($derived) { Write-Verbose "SharePoint admin URL worked out as $url" }
            & $record 'SharePoint Online' 'Connected' '' 'SharePoint'
            return $results.ToArray()
        }
        catch {
            $message = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
            $incomplete = Test-PurviewSignInIncomplete -Message $message
            Write-PurviewStepResult -Status 'Failed'
            Write-Line -Style Bad -Message ('    Could not sign in to {0}' -f $url)
            Write-Line -Style Dim -Message ('    {0}' -f $message)

            # An older SharePoint module has no -UseSystemBrowser and reports that as an address
            # failure. Retrying changes the authentication experience and may affect supported methods.
            if ($useSystemBrowser -and $message -match '(?i)parameter cannot be found' -and $message -match '(?i)UseSystemBrowser') {
                $useSystemBrowser = $false
                Write-Line -Style Warn -Message '    This SharePoint module predates system browser sign-in. Retrying with the module sign-in window.'
                Write-PurviewStep -Name 'SharePoint Online'
                continue
            }

            # An incomplete sign-in through the system browser is the one failure the module's own
            # dialog can still recover from. That dialog needs somebody in front of it, so it is
            # only tried where the run already has permission to ask.
            if ($incomplete -and $useSystemBrowser -and $AllowPrompt) {
                $useSystemBrowser = $false
                Write-Line -Style Warn -Message '    Retrying with the module sign-in window instead of the system browser.'
                Write-PurviewStep -Name 'SharePoint Online'
                continue
            }

            if ($incomplete) {
                Write-Line -Style Warn -Message '    The error matches an incomplete sign-in; this does not validate the address.'
                Write-Line -Style Warn -Message '    The browser window may have been closed, missed, or left waiting.'
            }
            elseif ($derived) {
                Write-Line -Style Warn -Message '    That URL was worked out from your tenant domain, which does not always match'
                Write-Line -Style Warn -Message '    the SharePoint hostname. Yours may simply be named differently.'
            }

            if (-not $AllowPrompt -or $attempt -eq 3) {
                & $record 'SharePoint Online' 'Failed' "$message Tried $url. Pass -TenantAdminUrl to set it directly." $null
                return $results.ToArray()
            }

            if ($incomplete) {
                Write-Line -Style Dim -Message '    Press Enter to try the sign-in again, or type skip to carry on without SharePoint.'
                $answer = ([string](Read-Host '    Enter, a different admin URL, or skip')).Trim()

                if ($answer -eq 'skip') {
                    & $record 'SharePoint Online' 'Skipped' 'Carried on without SharePoint, so those checks were not assessed.' $null
                    return $results.ToArray()
                }
                # An empty answer means try the same address again, which is the whole point here.
                if (-not [string]::IsNullOrWhiteSpace($answer)) {
                    $url = Format-PurviewAdminUrl -Value $answer
                    $script:SharePointAdminUrl = $url
                    $derived = $false
                }
                Write-PurviewStep -Name 'SharePoint Online'
                continue
            }

            Write-Line -Style Dim -Message '    Enter the correct admin URL, or press Enter to carry on without SharePoint.'
            $corrected = Format-PurviewAdminUrl -Value (Read-Host '    SharePoint admin URL')

            if ([string]::IsNullOrWhiteSpace($corrected)) {
                & $record 'SharePoint Online' 'Skipped' 'Carried on without SharePoint, so those checks were not assessed.' $null
                return $results.ToArray()
            }

            $url = $corrected
            $script:SharePointAdminUrl = $url
            $derived = $false
            Write-PurviewStep -Name 'SharePoint Online'
        }
    }

    return $results.ToArray()
}

function Disconnect-PurviewSession {
    <#
    .SYNOPSIS
        Attempts to disconnect every supported service session and removes compatibility resources.

    .DESCRIPTION
        Best-effort cleanup, not verified token revocation or cache removal. Exchange REST
        connections are disconnected through the installed module's supported sign-out command.
    #>
    [CmdletBinding()]
    param()

    if (Test-PurviewCommand -Name 'Disconnect-ExchangeOnline') {
        try {
            $disconnect = Get-Command -Name 'Disconnect-ExchangeOnline' -ErrorAction Stop
            & $disconnect -Confirm:$false -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Verbose "Sign-out from the Exchange-backed services did not complete: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }
    }

    foreach ($service in @('Azure', 'Graph', 'SharePoint')) {
        try {
            switch ($service) {
                'Azure' {
                    $pwsh = Get-PurviewPowerShell7Path
                    if ([string]::IsNullOrWhiteSpace($pwsh)) { throw 'PowerShell 7 is not installed.' }
                    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', ('"{0}"' -f $PSCommandPath), '-AzureSignOutWorker')
                    if ($script:AzureSessionContextPath) {
                        $arguments += @('-AzureContextPath', ('"{0}"' -f $script:AzureSessionContextPath))
                    }
                    $start = @{ FilePath = $pwsh; ArgumentList = $arguments; Wait = $true; PassThru = $true }
                    if ($IsWindows) { $start['WindowStyle'] = 'Hidden' }
                    $process = Start-Process @start
                    if ($process.ExitCode -ne 0) { throw "Azure sign-out worker exited with code $($process.ExitCode)." }
                }
                'Graph' {
                    if (Test-PurviewCommand -Name 'Disconnect-MgGraph') { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
                }
                'SharePoint' {
                    if (Test-PurviewCommand -Name 'Disconnect-SPOService') { Disconnect-SPOService -ErrorAction Stop }
                }
            }
        }
        catch {
            Write-Verbose "Sign-out from $service did not complete: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }
    }

    # The proxy must be removed before its runspace.
    Clear-PurviewCompatibilityModule
    $script:OwnedSession = @()
    $script:OwnedExchangeConnectionId = @()
    $script:HadPreExistingExchangeConnection = $false
    $script:ExpectedTenantId = ''
    $script:AzureSession = $null
    $script:AzureSessionContextPath = ''
    $script:AzureRole = @()
    $script:AzureRoleDetail = 'not read; Azure is not connected'
    $script:CommandCache = @{}
    $script:ServiceModuleCache = @{}
}

function Clear-PurviewTemporaryDirectory {
    <# .SYNOPSIS Removes only a one-run PDF browser profile created directly under the OS temp root. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd($separators)
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd($separators)
        $parent = [System.IO.Directory]::GetParent($fullPath)
        $leaf = [System.IO.Path]::GetFileName($fullPath)
        $prefix = 'purview-pdf-'
        [guid]$identifier = [guid]::Empty

        # Refuse anything that is not exactly the unguessable directory shape this run creates.
        # Resolving '..' before checking the direct parent prevents path traversal from widening it.
        if ($null -eq $parent -or
            -not [string]::Equals($parent.FullName.TrimEnd($separators), $tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not $leaf.StartsWith($prefix, [System.StringComparison]::Ordinal) -or
            -not [guid]::TryParseExact($leaf.Substring($prefix.Length), 'D', [ref]$identifier) -or
            $identifier -eq [guid]::Empty) {
            Write-Verbose 'Refusing to remove a directory that is not an owned PDF browser profile.'
            return $false
        }

        if (-not [System.IO.Directory]::Exists($fullPath)) { return $true }
        $rootAttributes = [System.IO.File]::GetAttributes($fullPath)
        if (($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-Verbose 'Refusing to traverse a PDF browser profile path that is a reparse point.'
            return $false
        }

        # Enumerate iteratively, delete each exact file, then remove directories deepest first.
        # Reparse-point children are removed as links and are never traversed.
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $directories = [System.Collections.Generic.List[string]]::new()
        $pending.Push($fullPath)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            $directories.Add($current)
            foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($current)) {
                $attributes = [System.IO.File]::GetAttributes($entry)
                $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
                $isReparsePoint = ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                if ($isDirectory) {
                    if ($isReparsePoint) { [System.IO.Directory]::Delete($entry, $false) }
                    else { $pending.Push($entry) }
                }
                else {
                    if (-not $isReparsePoint -and
                        ($attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                        [System.IO.File]::SetAttributes($entry, [System.IO.FileAttributes]::Normal)
                    }
                    [System.IO.File]::Delete($entry)
                }
            }
        }

        foreach ($directory in @($directories | Sort-Object Length -Descending)) {
            [System.IO.File]::SetAttributes($directory, [System.IO.FileAttributes]::Normal)
            [System.IO.Directory]::Delete($directory, $false)
        }
        return -not [System.IO.Directory]::Exists($fullPath)
    }
    catch {
        Write-Verbose "The temporary PDF browser profile is still in use: $($_.Exception.Message)"
        return $false
    }
}

function Clear-PurviewRunState {
    <# .SYNOPSIS Attempts temporary-artifact and session cleanup; reports, modules and caches can remain. #>
    [CmdletBinding()]
    param()

    Write-Progress -Activity 'Collecting Microsoft Purview configuration' -Completed

    foreach ($process in @($script:AzureSignInProcess, $script:SentinelProcess)) {
        if ($null -ne $process -and -not $process.HasExited) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
            }
            catch {
                Write-Verbose "An Azure worker did not stop cleanly: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
            }
        }
    }
    $script:AzureSignInProcess = $null
    $script:SentinelProcess = $null

    Disconnect-PurviewSession

    foreach ($path in @($script:TempArtifact | Select-Object -Unique)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            if (Test-Path -LiteralPath $path -PathType Container) {
                $null = Clear-PurviewTemporaryDirectory -Path $path
            }
            else {
                try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
                catch {
                    Write-Warning "A temporary assessment file could not be removed: $path. Treat it as sensitive and remove it when it is no longer in use."
                }
            }
        }
    }
    $script:TempArtifact = @()

}

#endregion

#region Collection plumbing

function Test-PurviewCommand {
    <# .SYNOPSIS Reports whether a cmdlet is available, so a missing session is skipped not fatal. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)

    # Cache misses too: Get-Command searches modules on disk, adding overhead per collector.
    # Connecting imports cmdlets, so every connect clears the cache.
    if ($script:CommandCache.ContainsKey($Name)) { return $script:CommandCache[$Name] }

    $found = [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
    $script:CommandCache[$Name] = $found
    return $found
}

function Get-PurviewServiceCommand {
    <#
    .SYNOPSIS
        Resolves a cmdlet to the module a named connection loaded.

    .DESCRIPTION
        Compliance and Exchange Online modules export around eighty shared cmdlet names.
        Unqualified calls use the last imported module, so each read names its owning service.

        Routing to Exchange breaks tenant policy configuration reads and returns Exchange role
        groups instead of Purview groups. UnifiedAuditLogIngestionEnabled is documented as always
        False outside Exchange Online.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Compliance', 'ExchangeOnline')][string]$Service
    )

    $module = $null
    if ($script:ServiceModuleCache.ContainsKey($Service)) { $module = $script:ServiceModuleCache[$Service] }
    else {
        $connections = @(Get-PurviewExchangeConnection -Service $Service)
        if ($connections.Count -ne 1) {
            throw "A unique connected $Service session was not found for $Name."
        }

        # The property holds a full path, which Get-Module rejects as a name.
        $path = [string](Get-PurviewProperty -InputObject $connections[0] -Name 'ModuleName')
        $leaf = if ($path) { [System.IO.Path]::GetFileName($path) } else { '' }
        $modules = @(Get-Module | Where-Object {
                ($path -and $_.Path -eq $path) -or ($leaf -and $_.Name -eq $leaf)
            })
        if ($modules.Count -ne 1) {
            throw "The module for the connected $Service session could not be identified uniquely."
        }
        $module = $modules[0]
        $script:ServiceModuleCache[$Service] = $module
    }

    if ($module -and $module.ExportedCommands.ContainsKey($Name)) { return $module.ExportedCommands[$Name] }
    throw "$Name is not exported by the connected $Service session module."
}

function Get-PurviewComplianceCommand {
    <# .SYNOPSIS Resolves a cmdlet to the compliance connection's module. #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param([Parameter(Mandatory)][string]$Name)

    return Get-PurviewServiceCommand -Name $Name -Service 'Compliance'
}

function Get-PurviewSafeErrorMessage {
    <# .SYNOPSIS Redacts selected credential patterns; review errors for other sensitive data before sharing. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    $safe = $Message -replace '[\r\n]+', ' '
    # Best-effort pattern matching, not a complete secret or tenant-data sanitizer.
    $safe = $safe -replace '(?i)(bearer\s+)[A-Za-z0-9._\-]+', '$1<redacted>'
    $safe = $safe -replace 'eyJ[A-Za-z0-9._\-]{20,}', '<redacted-token>'
    $safe = $safe -replace '(?i)((?:password|secret|client_secret|apikey|api_key)\s*[=:]\s*)\S+', '$1<redacted>'

    return $safe.Trim()
}

function Get-PurviewErrorCategory {
    <# .SYNOPSIS Classifies a failure, so a permission gap is not reported as a tenant defect. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    switch -Regex ($Message) {
        '(?i)access.?denied|insufficient privileg|unauthorized|forbidden|not authorized' { return 'Permission' }
        '(?i)throttl|too many requests|\b429\b' { return 'Throttled' }
        '(?i)timed? ?out' { return 'Timeout' }
        '(?i)no .*session|not connected|run connect-' { return 'NotConnected' }
        default { return 'Unexpected' }
    }
}

function ConvertTo-PurviewRecord {
    <# .SYNOPSIS Normalises one returned object, omitting fields the service did not return. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][object]$Map
    )

    $record = [ordered]@{}
    foreach ($key in $Map.Keys) {
        foreach ($candidate in $Map[$key]) {
            if (Test-PurviewProperty -InputObject $InputObject -Name $candidate) {
                $record[$key] = Get-PurviewProperty -InputObject $InputObject -Name $candidate
                break
            }
        }
    }

    return [pscustomobject]$record
}

function Get-PurviewUnmappedProperty {
    <#
    .SYNOPSIS
        Lists mapped fields the service did not return.

    .DESCRIPTION
        Only fields a rule could depend on count. Enrichment fields that no evaluated record needs
        are passed as -Optional so their absence does not degrade the whole collection. Callers can
        impose narrower requirements, such as ParentId on enabled labels only.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record,
        [Parameter(Mandatory)][object]$Map,
        [string[]]$Optional = @()
    )

    if ($Record.Count -eq 0) { return @() }

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $Map.Keys) {
        if ($Optional -contains $key) { continue }
        foreach ($item in $Record) {
            if (Test-PurviewProperty -InputObject $item -Name $key) { continue }
            $missing.Add($key)
            break
        }
    }

    return $missing.ToArray()
}

function Test-PurviewNotConnectedError {
    <# .SYNOPSIS Recognises a service asking to be signed in to, which is not a fault. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    # A module can be installed, so the cmdlet exists and the pre-flight check passes, while no
    # sign-in has happened. The service says so on the call, and that answer is a missing session.
    return $Message -match '(?i)(authentication needed|please call Connect-|not connected to|run Connect-|no active account|InteractiveBrowserCredential authentication failed)'
}

function Test-PurviewAbsenceError {
    <# .SYNOPSIS Matches legacy absence-like error wording; a match does not prove an unconfigured feature. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [AllowNull()][System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )

    # These broad phrases can also describe command, schema or service failures. Callers currently
    # map a match to empty success, so the associated limitation must not assert tenant absence.
    # PowerShell uses the same "cannot be found" words for a missing object property. That is a
    # coding failure, not tenant absence, and must remain visible rather than becoming empty data.
    if (($null -ne $ErrorRecord -and $ErrorRecord.FullyQualifiedErrorId -eq 'PropertyNotFoundStrict') -or
        $Message -match '(?i)\bproperty\b.+\bcannot be found on this object\b') {
        return $false
    }

    return $Message -match "(?i)(couldn't find|could not find|cannot be found|couldn't be found|can't be found|does not exist|doesn't exist|ObjectNotFound|failed to resolve table|unknown table)"
}

function Test-PurviewTransientError {
    <#
    .SYNOPSIS
        Identifies retryable service failures.

    .DESCRIPTION
        Compliance endpoints can return server errors with instructions to retry. Retry those
        failures before reporting the area as uncollected.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    return $Message -match '(?i)server.?side error|try again|temporarily unavailable|timed? ?out|throttl|too many requests|\b(429|500|502|503|504)\b'
}

function Invoke-PurviewCollector {
    <#
    .SYNOPSIS
        Runs one collector and returns a collector result, whatever happens.

    .DESCRIPTION
        Handles collector failures using the existing result categories. Some absence-like and
        positive-only failures map to empty Success results; consult limitations. Error redaction
        covers selected patterns only.

        Context is passed to the scriptblock as an argument rather than captured in a closure: a
        closure snapshots session state, and the shared helpers are not resolvable inside it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$SolutionArea,
        [Parameter(Mandatory)][string]$Interface,
        [Parameter(Mandatory)][ValidateSet('SecurityAndCompliancePowerShell', 'ExchangeOnlinePowerShell', 'SharePointOnlinePowerShell', 'MicrosoftGraph', 'AzurePowerShell')][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequiredCommand,
        [Parameter(Mandatory)][scriptblock]$Collect,
        [object]$Context = $null,
        [string]$DocumentationUrl = '',
        [string]$ConnectWith = '',
        # A prerequisite to verify, not proof that a denied read requires a new role assignment.
        [string]$RequiredRole = '',
        # Retained for caller compatibility. Licensing is advisory: a missing premium cmdlet
        # never proves that the tenant lacks a license, even with a complete subscription list.
        [AllowNull()][object]$LicensingRequirement = $null,
        [AllowNull()][object]$LicensingBlock = $null,
        # Legacy positive-only fallback. Some failures map to empty Success with this limitation;
        # that result does not establish absence of configuration or activity.
        [string]$AbsenceMeans = ''
    )

    # The legacy input remains accepted, but subscription evidence no longer gates collection.
    $null = $LicensingBlock
    $source = [ordered]@{ interface = $Interface; kind = $Kind }
    if ($DocumentationUrl) { $source['documentationUrl'] = $DocumentationUrl }

    $result = [ordered]@{
        collector = $Collector
        solutionArea = $SolutionArea
        status = 'Failed'
        source = [pscustomobject]$source
        collectedAt = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)
        data = [pscustomobject]@{}
        errors = @()
        limitations = @()
    }

    $missing = @($RequiredCommand | Where-Object { -not (Test-PurviewCommand -Name $_) })
    if ($missing.Count -gt 0) {
        # A missing cmdlet on a live compliance session is an availability gap, not proof of
        # missing tenant licensing. Keep the existing NotPermitted status for caller compatibility.
        $connected = $Kind -eq 'SecurityAndCompliancePowerShell' -and (Test-PurviewConnected -Service 'SecurityAndCompliance')
        if ($connected) {
            $named = if ($RequiredRole) { " Check access through $RequiredRole and module/service availability." } else { ' Check role access and module/service availability; the cause is not established.' }
            if ($null -ne $LicensingRequirement) {
                $named = ' Check command availability, role access and applicable licensing; subscription matching does not establish the cause.'
                if ($RequiredRole) { $named += " Check access through $RequiredRole." }
            }
            $result.status = 'NotPermitted'
            $result.errors = @([pscustomobject]@{ message = "$($missing -join ', ') is not available to this sign-in, although the Security & Compliance session is live.$named"; category = 'NotPermitted'; interface = $Interface })
            $result.limitations = @(if ($null -ne $LicensingRequirement) {
                    "$SolutionArea was not read because the required cmdlet was unavailable; the cause is not established."
                }
                else { "$SolutionArea was not read because the required cmdlet was unavailable; this does not establish a missing role." })
            return [pscustomobject]$result
        }

        $hint = if ($ConnectWith) { " Connect with $ConnectWith." } else { '' }
        if ($Collector -eq 'SentinelPurviewIntegration') {
            $hint = ' Complete Azure sign-in first, then retry the assessment.'
        }
        $result.status = 'NotConnected'
        $result.errors = @([pscustomobject]@{ message = "$($missing -join ', ') is unavailable.$hint"; category = 'NotConnected'; interface = $Interface })
        $result.limitations = @("$SolutionArea needs a connection this run did not have.")
        return [pscustomobject]$result
    }

    # Retry transient server errors up to three times with increasing delays before reporting failure.
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            # Capture module warnings for -Verbose so they do not interrupt step output.
            $emitted = @(& $Collect $Context 3>&1)
            $collected = $null
            foreach ($item in $emitted) {
                if ($item -is [System.Management.Automation.WarningRecord]) {
                    Write-Verbose "$Collector warned: $($item.Message)"
                    continue
                }
                $collected = $item
            }

            $result.data = if ($null -eq $collected) { [pscustomobject]@{} } else { $collected }
            $result.status = 'Success'

            $notReturned = Get-PurviewProperty -InputObject $result.data -Name 'PropertiesNotReturned'
            if ($null -ne $notReturned -and @($notReturned).Count -gt 0) {
                $result['propertiesNotReturned'] = @($notReturned)
                $result.limitations = @("Not returned by the service and therefore unknown: $(@($notReturned) -join ', ').")
                $result.status = 'PartialSuccess'
            }
            break
        }
        catch {
            $errorRecord = $_
            $message = Get-PurviewSafeErrorMessage -Message $errorRecord.Exception.Message

            if ($attempt -lt 3 -and (Test-PurviewTransientError -Message $message)) {
                Write-Verbose "$Collector failed transiently on attempt $attempt : $message"
                Start-Sleep -Seconds ($attempt * 3)
                continue
            }

            $retried = if ($attempt -gt 1) { " Tried $attempt times." } else { '' }

            # A local strict-mode property failure is a defect in the collector, never evidence that
            # a tenant feature is absent. Keep it visible even for positive-only collectors that use
            # AbsenceMeans to soften otherwise unclassified service failures.
            if ($errorRecord.FullyQualifiedErrorId -eq 'PropertyNotFoundStrict' -or
                $message -match '(?i)\bproperty\b.+\bcannot be found on this object\b') {
                $result.status = 'Failed'
                $result.errors = @([pscustomobject]@{ message = "$message$retried"; category = 'Unexpected'; interface = $Interface })
                $result.limitations = @("$SolutionArea could not be read because the collector failed, so nothing here was assessed.")
                break
            }

            # A service saying it needs a sign-in is a session that was never established, not a
            # fault. It reads as not connected, the same as a cmdlet that was never imported.
            if (Test-PurviewNotConnectedError -Message $message) {
                $result.status = 'NotConnected'
                $result.errors = @([pscustomobject]@{ message = $message; category = 'NotConnected'; interface = $Interface })
                $result.limitations = @("$SolutionArea needs a connection this run did not have.")
                break
            }

            # Access-related wording does not identify a missing role. Keep it ahead of absence
            # fallbacks, and distinguish hunting service onboarding from permission changes.
            if ((Get-PurviewErrorCategory -Message $message) -eq 'Permission') {
                $named = if ($RequiredRole) { " Check access through $RequiredRole; the cause is not established." } else { '' }
                $limitation = "$SolutionArea could not be read after an access-related error; this does not establish a missing role."
                if ($Kind -eq 'MicrosoftGraph' -and $Interface -eq 'POST /security/runHuntingQuery') {
                    if ($message -match '(?i)\bonboarding\b|\bprovisioning\b') {
                        $named = ' The response mentions onboarding or provisioning. Verify Microsoft Defender XDR service onboarding before changing permissions: https://learn.microsoft.com/defender-xdr/m365d-enable. Opening the Defender portal can initiate provisioning and requires separate approval.'
                        $limitation = "$SolutionArea was not read because hunting returned an onboarding-related access error. The current onboarding state and any missing permissions still need verification."
                    }
                    else {
                        $named = ' Verify ThreatHunting.Read.All consent and access to the underlying Defender data separately. A scope grant does not establish table access; a denied read does not prove that either permission is missing.'
                    }
                }
                $result.status = 'NotPermitted'
                $result.errors = @([pscustomobject]@{ message = "$message$named"; category = 'NotPermitted'; interface = $Interface })
                $result.limitations = @($limitation)
                break
            }

            # Check exhausted transient failures before AbsenceMeans: a service outage must not
            # be reported as missing tenant configuration.
            if (Test-PurviewTransientError -Message $message) {
                $result.status = 'Failed'
                $result.errors = @([pscustomobject]@{ message = "$message$retried"; category = Get-PurviewErrorCategory -Message $message; interface = $Interface })
                $result.limitations = @("$SolutionArea could not be read because the service kept failing, so nothing here was assessed.")
                break
            }

            # Preserve the legacy empty-success mapping without presenting its error heuristic
            # as proof that the tenant has never configured this feature.
            if ($Kind -ne 'AzurePowerShell' -and (Test-PurviewAbsenceError -Message $message -ErrorRecord $errorRecord)) {
                $result.status = 'Success'
                $result.data = [pscustomobject]@{}
                $result.limitations = @("$SolutionArea returned an absence-like error that this collector maps to empty success. Configuration absence is not verified.")
                break
            }

            if ($AbsenceMeans) {
                $result.status = 'Success'
                $result.data = [pscustomobject]@{}
                # Retain the service error so an unread result still has diagnostic context.
                $result.limitations = @("$AbsenceMeans The service reported: $(Get-PurviewSafeErrorMessage -Message $message)")
                break
            }

            $result.status = 'Failed'
            $result.errors = @([pscustomobject]@{ message = "$message$retried"; category = Get-PurviewErrorCategory -Message $message; interface = $Interface })
            $result.limitations = @("$SolutionArea could not be read, so nothing here was assessed.")
            break
        }
    }

    return [pscustomobject]$result
}

#endregion

#region Collectors
# Collectors use read/export cmdlets and HTTP reads, including POST for hunting queries.
# References support review; they are not proof of every response contract. No tenant configuration
# changes are intended, but local processing and normal service-side query/audit effects can occur.

$script:SccDocRoot = 'https://learn.microsoft.com/powershell/module/exchangepowershell'
$script:DeploymentModelRoot = 'https://learn.microsoft.com/purview/deploymentmodels'
$script:SpoDocRoot = 'https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell'

# Map solution areas for scoped runs. Include Classification under both Information Protection
# and DLP because sensitive information types support both auto-labelling and DLP checks.
$script:SolutionMap = [ordered]@{
    'InformationProtection' = @('SensitivityLabels', 'LabelPolicies', 'AutoLabeling', 'Classification', 'ContentExplorer', 'ActivityExplorer', 'Oversharing')
    'DataLossPrevention' = @('DataLossPrevention', 'EndpointDlp', 'Classification')
    'DataLifecycleManagement' = @('DataLifecycleManagement')
    'RecordsManagement' = @('RecordsManagement')
    'CommunicationCompliance' = @('CommunicationCompliance')
    'InsiderRisk' = @('InsiderRisk')
    'Audit' = @('Audit')
}

# Licensing provides subscription context and posture validation checks the run itself, so
# neither belongs to a solution and both run whatever is selected.
$script:AlwaysSolutionArea = @('Licensing', 'PostureValidation')

function Invoke-PurviewAzureGet {
    <# .SYNOPSIS Reads ARM JSON with explicit HTTP validation and complete list pagination. #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Context,
        [switch]$List
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    do {
        if ($Path -match '^https?://') {
            $uri = [uri]$Path
            if ($uri.Scheme -ne 'https' -or $uri.Host -ine 'management.azure.com' -or
                $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment) {
                throw 'Azure returned an unexpected ARM pagination endpoint.'
            }
            $Path = $uri.PathAndQuery
        }
        if (-not $Path.StartsWith('/') -or $Path.StartsWith('//') -or -not $visited.Add($Path)) {
            throw 'Azure returned an invalid or repeated ARM page.'
        }
        $response = Invoke-AzRestMethod -Method GET -Path $Path -DefaultProfile $Context -ErrorAction Stop
        $status = [int](Get-PurviewProperty -InputObject $response -Name 'StatusCode')
        $content = [string](Get-PurviewProperty -InputObject $response -Name 'Content')
        if ($status -lt 200 -or $status -ge 300) {
            $failure = [System.InvalidOperationException]::new(
                ("Azure ARM GET failed with HTTP {0}: {1}" -f $status, (Get-PurviewSafeErrorMessage -Message $content)))
            $failure.Data['HttpStatusCode'] = $status
            $failure.Data['ResponseContent'] = $content
            throw $failure
        }
        if ([string]::IsNullOrWhiteSpace($content)) { throw 'Azure ARM returned an empty response rather than resource evidence.' }
        $body = $content | ConvertFrom-Json -Depth 100
        if ($null -eq $body -or $body -is [string] -or $body -is [array]) {
            throw 'Azure ARM did not return a JSON resource object.'
        }
        if ($null -ne (Get-PurviewProperty -InputObject $body -Name 'error')) {
            throw ("Azure ARM returned an error: {0}" -f (Get-PurviewSafeErrorMessage -Message $content))
        }
        if (-not $List) { return $body }
        if (-not (Test-PurviewProperty -InputObject $body -Name 'value') -or $body.value -isnot [array]) {
            throw 'Azure ARM did not return the expected resource list.'
        }
        foreach ($item in $body.value) { $items.Add($item) }
        $Path = [string](Get-PurviewProperty -InputObject $body -Name 'nextLink')
    } while (-not [string]::IsNullOrWhiteSpace($Path))
    return [pscustomobject]@{ value = $items.ToArray() }
}

function Get-PurviewSentinelWorkspaceData {
    <# .SYNOPSIS Reads Sentinel onboarding independently of connector configuration or ingestion. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][object]$Context
    )

    $result = [ordered]@{ CustomerId = $null; SentinelOnboarded = $null; ErrorMessage = $null }
    try {
        $workspace = Invoke-PurviewAzureGet -Path "$($WorkspaceId)?api-version=2022-10-01" -Context $Context
        $properties = Get-PurviewProperty -InputObject $workspace -Name 'properties'
        $result.CustomerId = [string](Get-PurviewProperty -InputObject $properties -Name 'customerId')
        try {
            $onboarding = Invoke-PurviewAzureGet -Path "$WorkspaceId/providers/Microsoft.SecurityInsights/onboardingStates?api-version=2024-03-01" `
                -Context $Context -List
        }
        catch {
            $onboardingFailure = $_
            $notEnabled = $false
            if ($onboardingFailure.Exception.Data['HttpStatusCode'] -eq 404) {
                try {
                    $body = [string]$onboardingFailure.Exception.Data['ResponseContent'] | ConvertFrom-Json -Depth 20
                    $serviceError = Get-PurviewProperty -InputObject $body -Name 'error'
                    $notEnabled = [string](Get-PurviewProperty -InputObject $serviceError -Name 'code') -eq 'NotFound' -and
                        [string](Get-PurviewProperty -InputObject $serviceError -Name 'message') -match
                            '^Microsoft Sentinel was not found on the workspace\b'
                }
                catch { Write-Verbose 'The onboarding error response was not readable JSON; retaining the original ARM failure.' }
            }
            if (-not $notEnabled) { throw $onboardingFailure }
            $result.SentinelOnboarded = $false
            return [pscustomobject]$result
        }
        $result.SentinelOnboarded = @($onboarding.value).Count -gt 0
    }
    catch { $result.ErrorMessage = Get-PurviewSafeErrorMessage -Message $_.Exception.Message }
    return [pscustomobject]$result
}

function ConvertFrom-PurviewLogAnalyticsSummary {
    <# .SYNOPSIS Preserves the nested Log Analytics row array and validates the requested aggregates. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Response,
        [string]$CountColumn = 'EventCount',
        [string]$TimeColumn = 'LastEventUtc'
    )

    $errorDetail = Get-PurviewProperty -InputObject $Response -Name 'error'
    if ($null -ne $errorDetail) {
        throw ('Log Analytics returned an incomplete query result: {0}' -f
            (Get-PurviewSafeErrorMessage -Message ($errorDetail | ConvertTo-Json -Compress -Depth 20)))
    }
    $tables = @(Get-PurviewProperty -InputObject $Response -Name 'tables')
    if ($tables.Count -ne 1 -or -not (Test-PurviewProperty -InputObject $tables[0] -Name 'rows') -or
        -not (Test-PurviewProperty -InputObject $tables[0] -Name 'columns')) {
        throw 'Log Analytics did not return one summary table with columns and rows.'
    }
    # Do not pass rows through a pipeline helper: a single nested row would be unwrapped twice.
    $rows = $tables[0].rows
    $columns = @($tables[0].columns)
    if ($null -eq $rows -or @($rows).Count -ne 1 -or @($rows[0]).Count -ne $columns.Count) {
        throw 'Log Analytics did not return one summary row matching its columns.'
    }
    $names = @($columns | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'name') })
    if (@($names | Where-Object { $_ -eq $CountColumn }).Count -ne 1 -or
        @($names | Where-Object { $_ -eq $TimeColumn }).Count -ne 1) {
        throw "Log Analytics did not return the $CountColumn and $TimeColumn columns."
    }
    $count = ConvertTo-PurviewNonNegativeInteger -InputObject $rows[0][[array]::IndexOf($names, $CountColumn)]
    if (-not $count.Valid) { throw 'Log Analytics returned an invalid event count.' }
    $last = $rows[0][[array]::IndexOf($names, $TimeColumn)]
    $timestamp = [DateTimeOffset]::MinValue
    if ($count.Value -eq 0 -and $last) { throw 'Log Analytics returned a timestamp for an empty aggregate.' }
    if ($last -is [datetime] -or $last -is [DateTimeOffset]) { $timestamp = [DateTimeOffset]$last }
    elseif (($count.Value -gt 0 -or $last) -and -not [DateTimeOffset]::TryParse([string]$last,
            [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$timestamp)) {
        throw 'Log Analytics returned an invalid last-event timestamp.'
    }
    return [pscustomobject]@{
        EventCount = $count.Value
        LastEventUtc = if ($last) { $timestamp.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) } else { $null }
    }
}

function Get-PurviewSentinelM365Query {
    <# .SYNOPSIS Defines independent, aggregate-only reads of documented Microsoft 365 sources. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][guid]$TenantId,
        [ValidateRange(1, 3650)][int]$LookbackDays = 30
    )

    if ($TenantId -eq [guid]::Empty) { throw 'A Microsoft 365 tenant ID is required for Sentinel queries.' }
    $label = 'Operation in~ ("FileSensitivityLabelApplied", "FileSensitivityLabelChanged", "FileSensitivityLabelRemoved", "SensitivityLabelApplied", "SensitivityLabelUpdated", "SensitivityLabelRemoved", "SiteSensitivityLabelApplied", "SensitivityLabelChanged", "SiteSensitivityLabelRemoved")'
    $dlp = '(toint(RecordType) in (11, 13, 63) or RecordType in~ ("ComplianceDLPSharePoint", "ComplianceDLPExchange", "DLPEndpoint")) and Operation in~ ("DlpRuleMatch", "DlpRuleUndo", "DlpInfo") and UserKey == "DlpAgent"'
    $window = "TimeGenerated between (ago($($LookbackDays)d) .. now())"
    $organization = "OrganizationId =~ '$($TenantId.ToString('D'))'"
    return @(
        [pscustomobject]@{
            Name = 'Microsoft 365 audit'
            Table = 'OfficeActivity'
            Scope = 'Microsoft365Tenant'
            Query = @"
OfficeActivity
| where $window
| where $organization
| summarize EventCount=count(), LastEventUtc=max(TimeGenerated),
    LabelEventCount=countif($label), LastLabelEventUtc=maxif(TimeGenerated, $label),
    DlpEventCount=countif($dlp), LastDlpEventUtc=maxif(TimeGenerated, $dlp)
"@
            Details = @('Label', 'Dlp')
        }
        [pscustomobject]@{
            Name = 'Information Protection'
            Table = 'MicrosoftPurviewInformationProtection'
            Scope = 'Microsoft365Tenant'
            Query = @"
MicrosoftPurviewInformationProtection
| where $window
| where $organization
| summarize EventCount=count(), LastEventUtc=max(TimeGenerated),
    LabelEventCount=countif($label), LastLabelEventUtc=maxif(TimeGenerated, $label)
"@
            Details = @('Label')
        }
        [pscustomobject]@{
            Name = 'Insider Risk alerts'
            Table = 'SecurityAlert'
            Scope = 'Workspace'
            Query = @"
SecurityAlert
| where $window
| where ProductName == "Microsoft 365 Insider Risk Management"
| extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName")
| where alertWasCustomized == false
| summarize EventCount=count(), LastEventUtc=max(TimeGenerated)
"@
            Details = @()
        }
    )
}

function ConvertTo-PurviewSentinelM365Connector {
    <# .SYNOPSIS Separates native connector configuration from evidence that records were ingested. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Connector,
        [Parameter(Mandatory)][guid]$TenantId
    )

    if ($TenantId -eq [guid]::Empty) { throw 'A Microsoft 365 tenant ID is required for connector verification.' }
    foreach ($item in $Connector) {
        $kind = [string](Get-PurviewProperty -InputObject $item -Name 'kind')
        $types = switch ($kind) {
            'Office365' { @('exchange', 'sharePoint', 'teams') }
            'MicrosoftPurviewInformationProtection' { @('logs') }
            'OfficeIRM' { @('alerts') }
            'MicrosoftThreatProtection' { @('alerts', 'incidents') }
            default { @() }
        }
        if (@($types).Count -eq 0) { continue }
        $properties = Get-PurviewProperty -InputObject $item -Name 'properties'
        $sourceTenant = [string](Get-PurviewProperty -InputObject $properties -Name 'tenantId')
        $identity = [guid]::Empty
        $identityValid = [guid]::TryParse($sourceTenant, [ref]$identity) -and $identity -ne [guid]::Empty
        $dataTypes = Get-PurviewProperty -InputObject $properties -Name 'dataTypes'
        $states = @()
        $enabled = @()
        foreach ($type in $types) {
            $state = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $dataTypes -Name $type) -Name 'state')
            $states += $state
            if ($state -eq 'Enabled') { $enabled += $type }
        }
        $state = if (-not $identityValid) { 'Unknown' }
        elseif ($identity -ne $TenantId) { 'OtherTenant' }
        elseif ($enabled.Count -gt 0) { 'Enabled' }
        elseif (@($states | Where-Object { $_ -ne 'Disabled' }).Count -eq 0) { 'Disabled' }
        else { 'Unknown' }
        [pscustomobject]@{
            Kind = $kind
            Name = [string](Get-PurviewProperty -InputObject $item -Name 'name')
            SourceTenantId = if ($identityValid) { $identity.ToString('D') } else { $sourceTenant }
            State = $state
            EnabledDataTypes = $enabled
            PurviewSpecific = $kind -ne 'MicrosoftThreatProtection'
        }
    }
}

function Get-PurviewSentinelM365Data {
    <# .SYNOPSIS Reads connector configuration and independent Microsoft 365 telemetry aggregates. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][AllowEmptyString()][string]$CustomerId,
        [Parameter(Mandatory)][object]$Context,
        [ValidateRange(1, 3650)][int]$LookbackDays = 30
    )

    $tenantId = [guid]$Context.Tenant.Id
    $limitations = [System.Collections.Generic.List[string]]::new()
    $connectors = @()
    $connectorRead = 'Success'
    try {
        $response = Invoke-PurviewAzureGet -Path "$WorkspaceId/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2025-09-01" `
            -Context $Context -List
        $connectors = @(ConvertTo-PurviewSentinelM365Connector -Connector @($response.value) -TenantId $tenantId)
        if (@($connectors | Where-Object State -eq 'Unknown').Count -gt 0) {
            $limitations.Add('A relevant connector did not report a usable source tenant or data-type state.')
        }
    }
    catch {
        $connectorRead = 'Failed'
        $limitations.Add('Connector configuration was not read: {0}' -f (Get-PurviewSafeErrorMessage -Message $_.Exception.Message))
    }

    $queryFailure = ''
    $tokenValue = $null
    try {
        $workspaceGuid = [guid]::Empty
        if (-not [guid]::TryParse($CustomerId, [ref]$workspaceGuid) -or $workspaceGuid -eq [guid]::Empty) {
            throw 'The Log Analytics workspace did not return a usable query ID.'
        }
        $token = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io/' -TenantId $tenantId.ToString('D') `
            -DefaultProfile $Context -ErrorAction Stop
        $tokenValue = Get-PurviewProperty -InputObject $token -Name 'Token'
        if ($tokenValue -is [string] -and -not [string]::IsNullOrWhiteSpace($tokenValue)) {
            $tokenValue = [System.Net.NetworkCredential]::new('', $tokenValue).SecurePassword
        }
        if ($tokenValue -isnot [System.Security.SecureString] -or $tokenValue.Length -eq 0) {
            throw 'Azure did not return a Log Analytics access token.'
        }
    }
    catch { $queryFailure = Get-PurviewSafeErrorMessage -Message $_.Exception.Message }

    $sources = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in @(Get-PurviewSentinelM365Query -TenantId $tenantId -LookbackDays $LookbackDays)) {
        $source = [ordered]@{
            Name = $definition.Name
            Table = $definition.Table
            Scope = $definition.Scope
            SourceTenantId = if ($definition.Scope -eq 'Microsoft365Tenant') { $tenantId.ToString('D') } else { $null }
            QueryState = 'Failed'
            EventCount = $null
            LastEventUtc = $null
            LabelEventCount = $null
            DlpEventCount = $null
            ErrorMessage = $null
        }
        try {
            if ($queryFailure) { throw $queryFailure }
            $payload = @{ query = $definition.Query; timespan = "P$($LookbackDays)D" } | ConvertTo-Json -Compress
            $response = Invoke-RestMethod -Method POST -Uri "https://api.loganalytics.io/v1/workspaces/$CustomerId/query" `
                -Authentication Bearer -Token $tokenValue -ContentType 'application/json' -Body $payload -ErrorAction Stop
            $summary = ConvertFrom-PurviewLogAnalyticsSummary -Response $response
            foreach ($detail in $definition.Details) {
                $detailSummary = ConvertFrom-PurviewLogAnalyticsSummary -Response $response `
                    -CountColumn "$($detail)EventCount" -TimeColumn "Last$($detail)EventUtc"
                if ($detailSummary.EventCount -gt $summary.EventCount) {
                    throw "Log Analytics returned more $detail events than total source events."
                }
                $source["$($detail)EventCount"] = $detailSummary.EventCount
            }
            $source.EventCount = $summary.EventCount
            $source.LastEventUtc = $summary.LastEventUtc
            $source.QueryState = 'Success'
        }
        catch {
            $message = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
            $errorDetails = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $_ -Name 'ErrorDetails') -Name 'Message')
            $missingTable = "(?i)Failed to resolve table (?:or column )?expression named ['`"]$([regex]::Escape($definition.Table))['`"]"
            if ($errorDetails -match $missingTable -or $message -match $missingTable) {
                $source.QueryState = 'Unavailable'
                $source.ErrorMessage = 'The source table was not available to this query; it may not be collected or accessible.'
            }
            else {
                $source.ErrorMessage = if ($errorDetails) { Get-PurviewSafeErrorMessage -Message $errorDetails } else { $message }
                $limitations.Add("$($definition.Name) was not read: $($source.ErrorMessage)")
            }
        }
        $sources.Add([pscustomobject]$source)
    }

    return [pscustomobject]@{
        SentinelWorkspaceResourceId = $WorkspaceId
        SentinelWorkspaceCustomerId = $CustomerId
        SentinelOnboarded = $true
        ConnectorRead = $connectorRead
        Connectors = $connectors
        Sources = $sources.ToArray()
        LookbackDays = $LookbackDays
        Limitations = $limitations.ToArray()
    }
}

function Get-PurviewSentinelIntegrationData {
    <#
    .SYNOPSIS
        Reads Microsoft 365 audit and Purview compliance ingestion evidence from Sentinel.

    .DESCRIPTION
        Uses the verified Az context for workspace/connector discovery and independent aggregate
        Log Analytics queries. No connector, policy, subscription or tenant configuration is changed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([ValidateRange(1, 3650)][int]$LookbackDays = 30)

    if (-not $script:IsSentinelWorker) {
        $outputPath = Join-Path ([System.IO.Path]::GetTempPath()) ('PurviewSentinel-{0}.json' -f [guid]::NewGuid())
        $errorPath = Join-Path ([System.IO.Path]::GetTempPath()) ('PurviewSentinel-{0}.err' -f [guid]::NewGuid())
        $script:TempArtifact += @($outputPath, $errorPath)
        try {
            if ($null -ne $script:AzureSession -and -not $script:AzureSession.Connected) {
                throw "Azure is not connected to this assessment. $($script:AzureSession.Error)"
            }
            $pwsh = Get-PurviewPowerShell7Path
            if ([string]::IsNullOrWhiteSpace($pwsh)) {
                throw 'PowerShell 7 is required to isolate the Azure Sentinel collector.'
            }
            $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', ('"{0}"' -f $PSCommandPath), '-SentinelWorker', '-SentinelOutputPath', ('"{0}"' -f $outputPath), '-SentinelLookbackDays', $LookbackDays)
            if ($script:AzureSessionContextPath) { $arguments += @('-AzureContextPath', ('"{0}"' -f $script:AzureSessionContextPath)) }
            if ($script:ExpectedTenantId) { $arguments += @('-AzureTenantId', $script:ExpectedTenantId) }
            $start = @{ FilePath = $pwsh; ArgumentList = $arguments; PassThru = $true; RedirectStandardError = $errorPath }
            if ($IsWindows) { $start['WindowStyle'] = 'Hidden' }
            $process = Start-Process @start
            $script:SentinelProcess = $process
            $null = $process.Handle
            $process.WaitForExit()
            $process.Refresh()
            if ($process.ExitCode -ne 0) {
                $workerError = if (Test-Path -LiteralPath $errorPath -PathType Leaf) {
                    ([string](Get-Content -LiteralPath $errorPath -Raw -ErrorAction Stop)).Trim()
                }
                else { '' }
                $detail = if ($workerError) { $workerError } else { "The isolated Azure Sentinel collector exited with code $($process.ExitCode)." }
                throw $detail
            }
            if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
                throw 'The isolated Azure Sentinel collector returned no evidence.'
            }
            $evidence = Get-Content -LiteralPath $outputPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100
            if ([string](Get-PurviewProperty -InputObject $evidence -Name 'collector') -ne 'SentinelPurviewIntegration' -or
                [string](Get-PurviewProperty -InputObject $evidence -Name 'status') -notin
                    'Success', 'PartialSuccess', 'Failed', 'NotConnected', 'NotPermitted') {
                throw 'The isolated Azure Sentinel collector returned an invalid result.'
            }
            if ($evidence.status -in 'Success', 'PartialSuccess') {
                $evidenceTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $evidence -Name 'data') -Name 'TenantId')
                $identity = [guid]::Empty
                if (-not [guid]::TryParse($evidenceTenant, [ref]$identity) -or $identity -eq [guid]::Empty -or
                    ($script:ExpectedTenantId -and $evidenceTenant -ine $script:ExpectedTenantId)) {
                    throw 'Azure collector evidence belongs to a different or unverified tenant.'
                }
            }
            return $evidence
        }
        catch {
            return Invoke-PurviewCollector -Collector 'SentinelPurviewIntegration' -SolutionArea 'PostureValidation' `
                -Interface 'Azure Resource Manager GET and Log Analytics query' -Kind 'AzurePowerShell' `
                -DocumentationUrl $script:DocUrl.SentinelPurview -RequiredCommand @() `
                -Context (Get-PurviewSafeErrorMessage -Message $_.Exception.Message) `
                -Collect { param($failure) throw $failure }
        }
        finally {
            Remove-Item -LiteralPath $outputPath, $errorPath -Force -ErrorAction SilentlyContinue
        }
    }

    $result = Invoke-PurviewCollector -Collector 'SentinelPurviewIntegration' -SolutionArea 'PostureValidation' `
        -Interface 'Azure Resource Manager GET and Log Analytics query' -Kind 'AzurePowerShell' `
        -DocumentationUrl $script:DocUrl.SentinelPurview `
        -RequiredCommand @('Get-AzContext', 'Get-AzSubscription', 'Invoke-AzRestMethod', 'Get-AzAccessToken') `
        -ConnectWith 'Connect-AzAccount' -Collect {
        $context = Get-PurviewVerifiedAzureContext -TenantId $script:ExpectedTenantId
        $subscriptionId = [string]$context.Subscription.Id
        $tenantId = [string]$context.Tenant.Id

        $get = {
            param([string]$uri, [switch]$List)
            Invoke-PurviewAzureGet -Path $uri -Context $context -List:$List
        }
        $subscriptionIds = [System.Collections.Generic.List[string]]::new()
        $subscriptionLimitations = [System.Collections.Generic.List[string]]::new()
        $subscriptionDiscoveryComplete = $true
        $workspaceDiscoveryComplete = $true
        try {
            foreach ($subscription in @(Get-AzSubscription -TenantId $tenantId -DefaultProfile $context -ErrorAction Stop)) {
                $subscriptionTenant = [string](Get-PurviewProperty -InputObject $subscription -Name 'TenantId')
                if ($subscriptionTenant -ine $tenantId) {
                    $subscriptionDiscoveryComplete = $false
                    $subscriptionLimitations.Add('An enumerated subscription did not belong to the verified Azure tenant and was excluded.')
                    continue
                }
                $id = [string](Get-PurviewProperty -InputObject $subscription -Name 'Id')
                $parsedSubscription = [guid]::Empty
                if (-not [guid]::TryParse($id, [ref]$parsedSubscription) -or $parsedSubscription -eq [guid]::Empty) {
                    $subscriptionDiscoveryComplete = $false
                    $subscriptionLimitations.Add('An enumerated Azure subscription did not report a usable ID.')
                    continue
                }
                if (-not $subscriptionIds.Contains($id)) { $subscriptionIds.Add($id) }
            }
        }
        catch {
            $subscriptionDiscoveryComplete = $false
            $subscriptionLimitations.Add("Subscription discovery was incomplete; only the active subscription is assured: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)")
        }
        if (-not $subscriptionIds.Contains($subscriptionId)) { $subscriptionIds.Add($subscriptionId) }

        $workspaces = [System.Collections.Generic.List[object]]::new()
        foreach ($candidateSubscriptionId in $subscriptionIds) {
            try {
                $workspaces.Add((& $get ("/subscriptions/{0}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01" -f $candidateSubscriptionId) -List))
            }
            catch {
                $workspaceDiscoveryComplete = $false
                $subscriptionLimitations.Add("Workspaces in subscription $candidateSubscriptionId could not be read: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)")
            }
        }

        $normalizeId = {
            param([AllowNull()][string]$Id)
            if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
            return $Id.Trim().TrimEnd('/')
        }
        $workspaceById = @{}
        foreach ($workspaceResponse in $workspaces) {
            foreach ($workspace in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $workspaceResponse -Name 'value'))) {
                $id = & $normalizeId ([string](Get-PurviewProperty -InputObject $workspace -Name 'id'))
                if ($id) { $workspaceById[$id.ToLowerInvariant()] = $workspace }
                else {
                    $workspaceDiscoveryComplete = $false
                    $subscriptionLimitations.Add('A workspace discovery record did not report its resource ID.')
                }
            }
        }
        $workspaceEvidence = @{}
        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($workspaceKey in @($workspaceById.Keys | Sort-Object)) {
            $workspace = $workspaceById[$workspaceKey]
            $workspaceId = & $normalizeId ([string](Get-PurviewProperty -InputObject $workspace -Name 'id'))
            try {
                $workspaceDetails = Get-PurviewSentinelWorkspaceData -WorkspaceId $workspaceId -Context $context
                $workspaceEvidence[$workspaceId] = $workspaceDetails
                if ($workspaceDetails.ErrorMessage) { throw $workspaceDetails.ErrorMessage }
                if ($workspaceDetails.SentinelOnboarded) {
                    $telemetry = Get-PurviewSentinelM365Data -WorkspaceId $workspaceId -CustomerId ([string]$workspaceDetails.CustomerId) `
                        -Context $context -LookbackDays $LookbackDays
                    $results.Add($telemetry)
                    foreach ($limitation in $telemetry.Limitations) {
                        $subscriptionLimitations.Add("$($workspaceId.Split('/')[-1]): $limitation")
                    }
                }
            }
            catch {
                $subscriptionLimitations.Add("Sentinel configuration for workspace $workspaceId could not be read: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)")
            }
        }

        $sentinelWorkspaces = @($workspaceEvidence.Keys | Where-Object {
                $workspaceEvidence[$_].SentinelOnboarded -eq $true
            } | Sort-Object -Unique)
        $sentinelDiscoveryComplete = $subscriptionDiscoveryComplete -and $workspaceDiscoveryComplete -and
            @($workspaceEvidence.Values | Where-Object { $null -eq $_.SentinelOnboarded }).Count -eq 0
        [pscustomobject]@{
            EvidenceScope = 'Microsoft365Purview'
            Results = $results.ToArray()
            LookbackDays = $LookbackDays
            SubscriptionId = $subscriptionId
            TenantId = $tenantId
            AccountId = [string]$context.Account.Id
            SubscriptionIds = $subscriptionIds.ToArray()
            Workspaces = @($workspaceById.Values | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'id') })
            SentinelWorkspaces = $sentinelWorkspaces
            SentinelDiscoveryComplete = $sentinelDiscoveryComplete
            Limitations = $subscriptionLimitations.ToArray()
        }
    }
    if ($result.status -eq 'Success') {
        $limitations = @($result.data.Limitations)
        if ($limitations.Count -gt 0) {
            $result.status = 'PartialSuccess'
            $result.limitations = @($limitations | Select-Object -Unique)
        }
    }
    return $result
}

function Get-PurviewSolutionArea {
    <# .SYNOPSIS Expands chosen solutions to the solution areas they cover. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()][string[]]$Solution = @()
    )

    if (@($Solution).Count -eq 0) { $Solution = @($script:SolutionMap.Keys) }
    $areas = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Solution) {
        foreach ($area in $script:SolutionMap[$name]) { if (-not $areas.Contains($area)) { $areas.Add($area) } }
    }
    foreach ($area in $script:AlwaysSolutionArea) { if (-not $areas.Contains($area)) { $areas.Add($area) } }
    return $areas.ToArray()
}

function Get-PurviewSccCollectorDefinition {
    <# .SYNOPSIS Table-driven Security & Compliance collectors, one row per solution area. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @(
        @{
            Collector = 'SensitivityLabel'; Area = 'SensitivityLabels'; Cmdlet = 'Get-Label'; Key = 'Labels'
            # Encryption is a label action, and Microsoft documents actions as expanding into
            # properties only when asked. Without this a sublabel never says whether it encrypts.
            Parameter = @{ IncludeDetailedLabelActions = $true }
            RequiredParameter = @('IncludeDetailedLabelActions')
            Map = [ordered]@{
                Guid = @('Guid', 'ImmutableId', 'Identity')
                # DisplayName is what customers see. Name is the service-unique value accepted by
                # Export-ContentExplorerData, so neither can stand in for the other.
                Name = @('DisplayName', 'Name'); UniqueName = @('Name')
                Priority = @('Priority'); Disabled = @('Disabled')
                ContentType = @('ContentType'); ParentId = @('ParentId')
                IsLabelGroup = @('IsLabelGroup')
                EncryptionEnabled = @('EncryptionEnabled')
                EncryptionRights = @('EncryptionRightsDefinitions')
            }
            Optional = @('ParentId', 'ContentType', 'IsLabelGroup', 'EncryptionEnabled', 'EncryptionRights')
        }
        @{
            Collector = 'SensitivityLabelPolicy'; Area = 'LabelPolicies'; Cmdlet = 'Get-LabelPolicy'; Key = 'Policies'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Enabled = @('Enabled'); Mode = @('Mode'); Labels = @('Labels')
                # Named for the parameters that set the scope; Get-LabelPolicy documents no output.
                UserScope = @('ExchangeLocation'); GroupScope = @('ModernGroupLocation')
            }
            Optional = @('Mode', 'Labels', 'UserScope', 'GroupScope')
        }
        @{
            Collector = 'AutoLabeling'; Area = 'AutoLabeling'; Cmdlet = 'Get-AutoSensitivityLabelPolicy'; Key = 'Policies'
            Licensing = @{ capability = 'Auto-labeling'; includedIn = @('SPE_E5'); addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE') }
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Mode = @('Mode'); Enabled = @('Enabled')
            }
            Optional = @('Mode', 'Enabled')
        }
        @{
            # Policy mode and rule conditions describe configuration, not actual processing or protection.
            Collector = 'AutoLabelingRule'; Area = 'AutoLabeling'; Cmdlet = 'Get-AutoSensitivityLabelRule'; Key = 'Rules'
            Licensing = @{ capability = 'Auto-labeling'; includedIn = @('SPE_E5'); addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE') }
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                # Kept apart because either property can exist while the other is empty. Combining
                # them made an empty ParentPolicyName or direct condition hide the populated value.
                PolicyName = @('ParentPolicyName'); Policy = @('Policy'); Disabled = @('Disabled')
                DirectSensitiveTypes = @('ContentContainsSensitiveInformation')
                AdvancedRule = @('AdvancedRule')
            }
            Optional = @('PolicyName', 'Policy', 'Disabled', 'DirectSensitiveTypes', 'AdvancedRule')
            # A policy cannot exist without a condition, and a sensitive information type is one kind
            # among many. Naming the others stops a rule reading as unconfigured.
            Derive = @{
                # Presence is evidence of completeness even when the value is empty. Without these
                # markers, an older snapshot whose combined field masked AdvancedRule cannot prove
                # that no condition was lost.
                DirectSensitiveTypesReturned = {
                    param($raw)
                    Test-PurviewProperty -InputObject $raw -Name 'ContentContainsSensitiveInformation'
                }
                AdvancedRuleReturned = {
                    param($raw)
                    Test-PurviewProperty -InputObject $raw -Name 'AdvancedRule'
                }
                ConditionKinds = {
                    param($raw)
                    $kinds = [ordered]@{
                        AccessScope = 'whether the content is shared outside the organisation'
                        ContentExtensionMatchesWords = 'file extension'
                        ContentPropertyContainsWords = 'document property'
                        DocumentNameMatchesWords = 'document name'
                        DocumentCreatedBy = 'who created the document'
                        DocumentSizeOver = 'document size'
                        DocumentIsPasswordProtected = 'password-protected files'
                        DocumentIsUnsupported = 'files that cannot be scanned'
                        ProcessingLimitExceeded = 'files where scanning did not finish'
                        SubjectMatchesPatterns = 'message subject'
                        SenderDomainIs = 'sender domain'
                        RecipientDomainIs = 'recipient domain'
                        SentTo = 'named recipients'
                        FromAddressContainsWords = 'sender address'
                    }
                    $found = [System.Collections.Generic.List[string]]::new()
                    foreach ($name in $kinds.Keys) {
                        $property = $raw.PSObject.Properties[$name]
                        if (-not $property) { continue }
                        $value = $property.Value
                        if ($null -eq $value) { continue }
                        if ($value -is [bool]) { if ($value) { $found.Add($kinds[$name]) }; continue }
                        # None is what an unused AccessScope reports, and an empty list is what an
                        # unused multi-valued condition reports.
                        if ($value -isnot [string] -and $value -is [System.Collections.IEnumerable] -and @($value).Count -eq 0) { continue }
                        if ([string]$value -in '', 'None') { continue }
                        $found.Add($kinds[$name])
                    }
                    $found.ToArray()
                }
            }
        }
        @{
            Collector = 'DataLossPrevention'; Area = 'DataLossPrevention'; Cmdlet = 'Get-DlpCompliancePolicy'; Key = 'Policies'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Mode = @('Mode'); Enabled = @('Enabled'); Workload = @('Workload')
                # Microsoft documents the location as "Microsoft 365 Copilot and Copilot Chat" but
                # not the property behind it, so the candidates are tried and absence is declared.
                CopilotLocation = @('CopilotLocation', 'MicrosoftCopilotLocation', 'M365CopilotLocation')
                # Selecting the Copilot location turns every one of these off, so a policy holding
                # any of them is documented as not being a Copilot policy.
                ExchangeLocation = @('ExchangeLocation'); SharePointLocation = @('SharePointLocation')
                OneDriveLocation = @('OneDriveLocation'); TeamsLocation = @('TeamsLocation')
                EndpointDlpLocation = @('EndpointDlpLocation'); PowerBIDlpLocation = @('PowerBIDlpLocation')
                ThirdPartyAppDlpLocation = @('ThirdPartyAppDlpLocation')
                OnPremisesScannerDlpLocation = @('OnPremisesScannerDlpLocation')
            }
            Optional = @('Enabled', 'Workload', 'CopilotLocation', 'ExchangeLocation', 'SharePointLocation',
                'OneDriveLocation', 'TeamsLocation', 'EndpointDlpLocation', 'PowerBIDlpLocation',
                'ThirdPartyAppDlpLocation', 'OnPremisesScannerDlpLocation')
        }
        @{
            Collector = 'RetentionPolicy'; Area = 'DataLifecycleManagement'; Cmdlet = 'Get-RetentionCompliancePolicy'; Key = 'Policies'
            # This cmdlet returns retention policies and retention label policies together, and
            # Microsoft documents RetentionRuleTypes as the property that says which, but only when
            # the switch is passed. Without it the two cannot be told apart at all.
            Parameter = @{ RetentionRuleTypes = $true }
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Enabled = @('Enabled'); Mode = @('Mode'); Workload = @('Workload')
                RuleTypes = @('RetentionRuleTypes'); HasRules = @('HasRules')
            }
            Optional = @('Workload')
        }
        @{
            # Older combined Teams chats and Copilot policies remain in the classic cmdlet. Ask
            # only for that family: policy names and Workload do not establish its actual scope.
            Collector = 'ClassicTeamsRetentionPolicy'; Area = 'DataLifecycleManagement'; Cmdlet = 'Get-RetentionCompliancePolicy'; Key = 'Policies'
            Parameter = @{ TeamsPolicyOnly = $true; RetentionRuleTypes = $true }
            RequiredParameter = @('TeamsPolicyOnly')
            Map = [ordered]@{
                # User:TeamsChatUserInteractions is Microsoft's documented Teams-only migration
                # value. Any other or missing shape stays ambiguous rather than earning Copilot credit.
                Applications = @('Applications', 'PolicyApplications')
            }
            Optional = @()
        }
        @{
            # Current app-retention locations use App cmdlets; older combined Teams/Copilot
            # configurations can remain in the classic family and are collected separately.
            Collector = 'AppRetentionPolicy'; Area = 'DataLifecycleManagement'; Cmdlet = 'Get-AppRetentionCompliancePolicy'; Key = 'Policies'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Enabled = @('Enabled')
                # Documented location values, such as User:M365Copilot for Copilot interactions.
                Applications = @('Applications', 'PolicyApplications')
            }
            Optional = @()
        }
        @{
            # App retention rules are separate objects. A policy name and Enabled value do not
            # establish that any retention action exists until a rule links back to that policy.
            Collector = 'AppRetentionRule'; Area = 'DataLifecycleManagement'; Cmdlet = 'Get-AppRetentionComplianceRule'; Key = 'Rules'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Policy = @('Policy')
            }
            Optional = @('Guid')
        }
        @{
            Collector = 'RetentionLabel'; Area = 'RecordsManagement'; Cmdlet = 'Get-ComplianceTag'; Key = 'Labels'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                IsRecordLabel = @('IsRecordLabel'); RetentionAction = @('RetentionAction'); RetentionDuration = @('RetentionDuration')
            }
            Optional = @('IsRecordLabel', 'RetentionAction', 'RetentionDuration')
        }
        @{
            Collector = 'AuditConfiguration'; Area = 'Audit'; Cmdlet = 'Get-UnifiedAuditLogRetentionPolicy'; Key = 'RetentionPolicies'
            Licensing = @{ capability = 'Audit (Premium) log retention policies'; includedIn = @('SPE_E5'); addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE') }
            Map = [ordered]@{
                Name = @('Name', 'Identity'); Enabled = @('Enabled')
                RetentionDuration = @('RetentionDuration'); RecordTypes = @('RecordTypes'); Priority = @('Priority')
            }
            Optional = @('Enabled', 'RetentionDuration', 'RecordTypes', 'Priority')
        }
        @{
            Collector = 'CommunicationCompliance'; Area = 'CommunicationCompliance'; Cmdlet = 'Get-SupervisoryReviewPolicyV2'; Key = 'Policies'
            Licensing = @{ capability = 'Communication Compliance'; includedIn = @('SPE_E5'); addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE') }
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName'); Enabled = @('Enabled')
                IsWorkbenchPolicy = @('IsWorkbenchPolicy'); ProvisioningStatus = @('ProvisioningStatus')
            }
            Optional = @('Enabled', 'IsWorkbenchPolicy', 'ProvisioningStatus')
        }
        @{
            Collector = 'DlpRule'; Area = 'DataLossPrevention'; Cmdlet = 'Get-DlpComplianceRule'; Key = 'Rules'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                # Kept apart because an empty ParentPolicyName must not hide a populated Policy.
                # The parent policy owns Mode; the child rule owns Disabled.
                Disabled = @('Disabled'); PolicyName = @('ParentPolicyName'); Policy = @('Policy')
            }
            # Microsoft documents an action only the Copilot location offers, "Prevent Copilot from
            # processing content", but names no property for it. Reading the rule's own values is
            # used here as a candidate indicator when locations are absent, not verified scope.
            Derive = @{
                MentionsCopilot = {
                    param($raw)
                    [bool]@($raw.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^(PS|RunspaceId)$' -and "$($_.Value)" -match '(?i)copilot' }).Count
                }
            }
            Optional = @('PolicyName', 'Policy')
        }
        @{
            # Get-DataClassification is on-premises Exchange only; Security & Compliance PowerShell
            # exposes the tenant's sensitive information types under this name instead.
            Collector = 'Classification'; Area = 'Classification'; Cmdlet = 'Get-DlpSensitiveInformationType'; Key = 'SensitiveInformationTypes'
            Map = [ordered]@{
                Guid = @('Id', 'Identity', 'Guid'); Name = @('Name', 'DisplayName')
                Publisher = @('Publisher'); Type = @('Type')
            }
            # Publisher is the only thing separating the types Microsoft ships from the ones this
            # tenant built, so a rule depends on it and its absence must degrade the read.
            Optional = @('Type')
        }
    )
}

function Get-PurviewSccData {
    <# .SYNOPSIS Runs one table-driven Security & Compliance collector. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Definition,
        [AllowNull()][object]$LicensingBlock = $null
    )

    $licensingRequirement = if ($Definition.ContainsKey('Licensing')) { $Definition.Licensing } else { $null }

    return Invoke-PurviewCollector -Collector $Definition.Collector -SolutionArea $Definition.Area `
        -Interface $Definition.Cmdlet -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/$($Definition.Cmdlet.ToLowerInvariant())" `
        -RequiredCommand @($Definition.Cmdlet) -ConnectWith 'Connect-IPPSSession' `
        -LicensingRequirement $licensingRequirement -LicensingBlock $LicensingBlock `
        -Context $Definition -Collect {
        param($ctx)
        # Only switches the installed module actually has are passed, so an older one still collects
        # rather than failing on a parameter it has never heard of.
        $extra = @{}
        $command = Get-PurviewComplianceCommand -Name $ctx.Cmdlet
        $supported = $command.Parameters
        if ($ctx.ContainsKey('Parameter')) {
            foreach ($name in @($ctx.Parameter.Keys)) {
                if ($supported.ContainsKey($name)) { $extra[$name] = $ctx.Parameter[$name] }
            }
        }
        if ($ctx.ContainsKey('RequiredParameter')) {
            $missingParameter = @($ctx.RequiredParameter | Where-Object { -not $supported.ContainsKey($_) })
            if ($missingParameter.Count -gt 0) {
                throw ('The installed module cannot apply the required {0} filter, so this read was not run without it.' -f ($missingParameter -join ', '))
            }
        }
        $records = @(& $command @extra -ErrorAction Stop | ForEach-Object {
                $raw = $_
                $record = ConvertTo-PurviewRecord -InputObject $raw -Map $ctx.Map
                # Some answers are not in any one property and have to be read off the whole object.
                if ($ctx.ContainsKey('Derive')) {
                    foreach ($field in @($ctx.Derive.Keys)) {
                        $record | Add-Member -NotePropertyName $field -NotePropertyValue (& $ctx.Derive[$field] $raw) -Force
                    }
                }
                $record
            })

        if ($ctx.Collector -eq 'SensitivityLabel') {
            $hasRights = {
                param($record)
                if (-not (Test-PurviewProperty -InputObject $record -Name 'EncryptionRights')) { return $false }
                $rights = Get-PurviewProperty -InputObject $record -Name 'EncryptionRights'
                if ($null -eq $rights) { return $false }
                if ($rights -is [string]) { return -not [string]::IsNullOrWhiteSpace([string]$rights) }
                if ($rights -is [System.Collections.IDictionary]) { return $rights.Count -gt 0 }
                if ($rights -is [System.Collections.IEnumerable]) { return @($rights).Count -gt 0 }
                return -not [string]::IsNullOrWhiteSpace([string]$rights)
            }

            # The bulk call can omit expanded label actions even when they were requested. Plan all
            # recoverable reads first so the operator can see progress through a slow sequence.
            # Only exact GUIDs enter the plan: a display or service name is mutable and must never
            # be allowed to attach another label's protection settings to this record.
            $detailPlan = [System.Collections.Generic.List[object]]::new()
            $canReadDetail = $supported.ContainsKey('Identity') -and
                $supported.ContainsKey('IncludeDetailedLabelActions')
            foreach ($record in $records) {
                $encryption = ConvertTo-PurviewBoolean -InputObject (
                    Get-PurviewProperty -InputObject $record -Name 'EncryptionEnabled')
                $needState = -not $encryption.Valid
                $needRights = $encryption.Valid -and [bool]$encryption.Value -and -not (& $hasRights $record)
                if (-not $needState -and -not $needRights) { continue }

                $identity = [guid]::Empty
                $identityText = [string](Get-PurviewProperty -InputObject $record -Name 'Guid')
                if (-not $canReadDetail -or
                    -not [guid]::TryParse($identityText, [ref]$identity) -or
                    $identity -eq [guid]::Empty) {
                    continue
                }

                $detailPlan.Add([pscustomobject]@{
                        Record = $record
                        Encryption = $encryption
                        Identity = $identity
                    })
            }

            # Minimal progress must start on its own physical line. The collector heading is
            # deliberately written without a newline, and starting progress from the middle of it
            # makes ConsoleHost clear and later repaint part of the following collector rows.
            # Close that heading first, then put the result back on it once progress is cleared.
            $detailActivity = 'Reading sensitivity label protection settings'
            $steppedRun = $detailPlan.Count -gt 0 -and (Test-Path variable:script:StepIndex)
            $detailNote = 'reading {0} label details' -f $detailPlan.Count
            # The note, then a blank row keeping the bar clear of the collector list.
            $detailRows = 2
            if ($steppedRun) {
                Write-Line -Style Dim -Message $detailNote
                Write-Line -Message ''
            }
            try {
                $detailPosition = 0
                foreach ($detailRequest in $detailPlan) {
                    $detailPosition++
                    Write-Progress -Id 1639 -Activity $detailActivity `
                        -Status ('Label {0} of {1}' -f $detailPosition, $detailPlan.Count) `
                        -PercentComplete ([int][Math]::Floor(100 * $detailPosition / $detailPlan.Count))

                    $record = $detailRequest.Record
                    $encryption = $detailRequest.Encryption
                    $identity = [guid]$detailRequest.Identity

                    try {
                        $detailRecords = @(& $command -Identity $identity.ToString('D') @extra `
                                -ErrorAction Stop -WarningAction SilentlyContinue |
                            ForEach-Object { ConvertTo-PurviewRecord -InputObject $_ -Map $ctx.Map })
                        $matchingDetail = @($detailRecords | Where-Object {
                                $detailIdentity = [guid]::Empty
                                [guid]::TryParse(
                                    [string](Get-PurviewProperty -InputObject $_ -Name 'Guid'),
                                    [ref]$detailIdentity) -and $detailIdentity -eq $identity
                            })
                        if ($matchingDetail.Count -ne 1) { continue }

                        $detail = $matchingDetail[0]
                        $detailEncryption = ConvertTo-PurviewBoolean -InputObject (
                            Get-PurviewProperty -InputObject $detail -Name 'EncryptionEnabled')
                        # On the exact, unique detailed response, a present null expanded action
                        # means this label has no encryption action. A missing property still proves
                        # nothing.
                        if ((Test-PurviewProperty -InputObject $detail -Name 'EncryptionEnabled') -and
                            $null -eq (Get-PurviewProperty -InputObject $detail -Name 'EncryptionEnabled')) {
                            $detailEncryption = [pscustomobject]@{ Valid = $true; Value = $false }
                        }
                        if ($encryption.Valid -and $detailEncryption.Valid -and
                            [bool]$encryption.Value -ne [bool]$detailEncryption.Value) {
                            # Two explicit answers for the same GUID prove neither state. Remove
                            # both operands rather than choosing whichever call happened to run last.
                            $record.PSObject.Properties.Remove('EncryptionEnabled')
                            $record.PSObject.Properties.Remove('EncryptionRights')
                            continue
                        }
                        if (-not $encryption.Valid -and $detailEncryption.Valid) {
                            $record | Add-Member -NotePropertyName 'EncryptionEnabled' `
                                -NotePropertyValue ([bool]$detailEncryption.Value) -Force
                        }

                        $effectiveEncryption = ConvertTo-PurviewBoolean -InputObject (
                            Get-PurviewProperty -InputObject $record -Name 'EncryptionEnabled')
                        if ($effectiveEncryption.Valid -and [bool]$effectiveEncryption.Value -and
                            -not (& $hasRights $record) -and (& $hasRights $detail)) {
                            $record | Add-Member -NotePropertyName 'EncryptionRights' `
                                -NotePropertyValue (Get-PurviewProperty -InputObject $detail -Name 'EncryptionRights') -Force
                        }
                    }
                    catch {
                        # The bulk definition is still useful. Keep this label's action fields
                        # absent so report consumers say not read instead of losing every label.
                        Write-Verbose ('Detailed Get-Label failed for {0}: {1}' -f $identity.ToString('D'),
                            (Get-PurviewSafeErrorMessage -Message $_.Exception.Message))
                    }
                }
            }
            finally {
                if ($detailPlan.Count -gt 0) {
                    Write-Progress -Id 1639 -Activity $detailActivity -Completed
                }
                if ($steppedRun -and
                    -not (Clear-PurviewStepScaffold -Rows $detailRows -FirstRowLength $detailNote.Length)) {
                    # Nothing could be erased, so the result is aligned under the row instead.
                    Write-PurviewStep -Name ''
                }
            }
        }

        $data = [ordered]@{}
        $data[$ctx.Key] = $records
            $notReturned = [System.Collections.Generic.List[string]]::new()
            foreach ($name in @(Get-PurviewUnmappedProperty -Record $records -Map $ctx.Map -Optional $ctx.Optional)) {
                $notReturned.Add([string]$name)
            }
            if ($ctx.Collector -eq 'SensitivityLabel') {
                foreach ($record in $records) {
                    $disabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $record -Name 'Disabled')
                    if ($disabled.Valid -and -not [bool]$disabled.Value -and
                        -not (Test-PurviewProperty -InputObject $record -Name 'ParentId')) {
                        $notReturned.Add('ParentId')
                        break
                    }
                }
                foreach ($record in $records) {
                    $encryption = ConvertTo-PurviewBoolean -InputObject (
                        Get-PurviewProperty -InputObject $record -Name 'EncryptionEnabled')
                    if (-not $encryption.Valid) {
                        $notReturned.Add('EncryptionEnabled')
                    }
                }
            }
            $data['PropertiesNotReturned'] = @($notReturned | Select-Object -Unique)
        [pscustomobject]$data
    }
}

function Get-PurviewTenantPolicyConfigData {
    <#
    .SYNOPSIS
        Reads the organization-wide policy configuration object.

    .DESCRIPTION
        Microsoft documents a single such object per organization, named Settings. It carries
        tenant-wide switches rather than any one solution's policies, and this report reads two of
        them: co-authoring for labelled files, and whether Teams DLP policies extend to the copies
        those chats leave in SharePoint and OneDrive.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'TenantPolicyConfig' -SolutionArea 'DataLossPrevention' `
        -Interface 'Get-PolicyConfig' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/get-policyconfig" `
        -RequiredCommand @('Get-PolicyConfig') -ConnectWith 'Connect-IPPSSession' `
        -RequiredRole 'View-Only DLP Compliance Management, which Microsoft documents as granting sight of the settings and reports for data loss prevention policies' `
        -AbsenceMeans 'The tenant-wide policy configuration could not be read this run, so co-authoring and the Teams DLP extension to SharePoint and OneDrive go unreported.' -Collect {
        # An empty response does not establish whether settings have ever been written.
        $config = & (Get-PurviewComplianceCommand -Name 'Get-PolicyConfig') -ErrorAction Stop -WarningAction SilentlyContinue
        if ($null -eq $config) {
            return [pscustomobject]@{ Settings = @(); Limitation = 'No tenant-wide policy configuration was returned. Settings and configuration history are unknown.' }
        }

        $settings = @($config.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^(PS|RunspaceId)' } |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })

        [pscustomobject]@{ Settings = $settings }
    }
}

function Get-PurviewOcrConfigurationData {
    <#
    .SYNOPSIS
        Reads whether optical character recognition is set to scan images for sensitive information.

    .DESCRIPTION
        Reads returned OCR state and location fields. Review current licensing and billing
        requirements separately. The inventory maps an empty configuration list to off; that
        legacy mapping is not a verified response contract or proof of image-detection coverage.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'OcrConfiguration' -SolutionArea 'Classification' `
        -Interface 'Get-OcrConfiguration' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl 'https://learn.microsoft.com/purview/ocr-learn-about' `
        -RequiredCommand @('Get-OcrConfiguration') -ConnectWith 'Connect-IPPSSession' `
        -RequiredRole 'Compliance Administrator, which Microsoft documents as the role that configures optical character recognition' `
        -AbsenceMeans 'Whether optical character recognition is scanning images for sensitive information could not be read this run.' -Collect {
        $responses = @(& (Get-PurviewComplianceCommand -Name 'Get-OcrConfiguration') -ErrorAction Stop -WarningAction SilentlyContinue)

        # The cmdlet can return the configuration directly or wrap it in ResultData, including as
        # JSON text. A malformed wrapper is incomplete evidence, never proof that OCR is off.
        $configs = [System.Collections.Generic.List[object]]::new()
        $incomplete = [System.Collections.Generic.List[string]]::new()
        $unwrap = $null
        $unwrap = {
            param($node, [int]$depth)

            if ($depth -gt 4) { $incomplete.Add('nested too deeply'); return }
            if ($null -eq $node) { $incomplete.Add('contained null'); return }

            # A response or any nested ResultData layer can itself be JSON text. Parse it before
            # looking for another wrapper; a primitive or malformed string is not a configuration.
            if ($node -is [string]) {
                if ([string]::IsNullOrWhiteSpace([string]$node)) {
                    $incomplete.Add('contained empty text')
                    return
                }
                try { $node = ConvertFrom-Json -InputObject ([string]$node) -Depth 20 }
                catch { $incomplete.Add('contained invalid JSON'); return }
                & $unwrap $node ($depth + 1)
                return
            }

            if (Test-PurviewProperty -InputObject $node -Name 'ResultData') {
                $payload = Get-PurviewProperty -InputObject $node -Name 'ResultData'
                foreach ($item in @(ConvertTo-PurviewArray -InputObject $payload)) {
                    & $unwrap $item ($depth + 1)
                }
                if ($null -eq $payload) { $incomplete.Add('contained null') }
                return
            }

            $stateFields = @('Enabled', 'Mode', 'OcrMode', 'IsValid', 'IsOcrUsageBlocked')
            if (@($stateFields | Where-Object { Test-PurviewProperty -InputObject $node -Name $_ }).Count -eq 0) {
                $incomplete.Add('contained no recognized configuration state')
                return
            }
            $configs.Add($node)
        }
        foreach ($response in $responses) { & $unwrap $response 0 }

        # The five locations Microsoft documents OCR as covering, named as the cmdlet names them.
        $locations = [ordered]@{
            ExchangeLocation    = 'Exchange'
            SharePointLocation  = 'SharePoint'
            OneDriveLocation    = 'OneDrive'
            TeamsLocation       = 'Teams'
            EndpointDlpLocation = 'Devices'
        }

        $read = [System.Collections.Generic.List[object]]::new()
        foreach ($config in $configs) {
            # Keep only state needed for the verdict. Configuration names and scoped location
            # values are unnecessary tenant metadata and never enter the snapshot.
            $record = [ordered]@{}
            foreach ($stateField in @('Enabled', 'Mode', 'OcrMode', 'IsValid', 'IsOcrUsageBlocked')) {
                if (Test-PurviewProperty -InputObject $config -Name $stateField) {
                    $record[$stateField] = Get-PurviewProperty -InputObject $config -Name $stateField
                }
            }

            $locationFieldsReturned = $false
            $covered = @(foreach ($key in $locations.Keys) {
                    if (-not (Test-PurviewProperty -InputObject $config -Name $key)) { continue }
                    $locationFieldsReturned = $true
                    $values = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $config -Name $key)
                    if (@($values | Where-Object { $_ }).Count -gt 0) { $locations[$key] }
                })
            if ($locationFieldsReturned) { $record['Locations'] = @($covered) }

            $read.Add([pscustomobject]$record)
        }

        [pscustomobject]@{
            Configurations = $read.ToArray()
            PropertiesNotReturned = @(if ($incomplete.Count -gt 0) { 'CompleteConfigurationSet' })
        }
    }
}

function Get-PurviewLegacyRetentionData {
    <#
    .SYNOPSIS
        Reads the Exchange messaging records management policies and tags.

    .DESCRIPTION
        These legacy definitions can configure deletion and archiving alongside Purview retention.
        Mailbox assignments, processing, applicable tags and effective retention are not assessed.

        Read from the Exchange Online session rather than the compliance one, which is where
        Microsoft exposes them.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'LegacyRetention' -SolutionArea 'DataLifecycleManagement' `
        -Interface 'Get-RetentionPolicy' -Kind 'ExchangeOnlinePowerShell' `
        -DocumentationUrl 'https://learn.microsoft.com/exchange/security-and-compliance/messaging-records-management/messaging-records-management' `
        -RequiredCommand @('Get-RetentionPolicy') -ConnectWith 'Connect-ExchangeOnline' `
        -RequiredRole 'A role that can read Exchange recipient configuration, such as View-Only Recipients or Retention Management' `
        -AbsenceMeans 'The Exchange messaging records management policies could not be read this run, so retention happening outside Purview goes unreported.' -Collect {
        $missing = [System.Collections.Generic.List[string]]::new()
        $policies = @(& (Get-PurviewServiceCommand -Name 'Get-RetentionPolicy' -Service 'ExchangeOnline') -ErrorAction Stop -WarningAction SilentlyContinue | ForEach-Object {
                $record = [ordered]@{}
                if (Test-PurviewProperty -InputObject $_ -Name 'Name') {
                    $record['Name'] = [string](Get-PurviewProperty -InputObject $_ -Name 'Name')
                }
                else { $missing.Add('Policy.Name') }
                if (Test-PurviewProperty -InputObject $_ -Name 'RetentionPolicyTagLinks') {
                    $record['TagCount'] = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'RetentionPolicyTagLinks')).Count
                }
                else { $missing.Add('Policy.TagCount') }
                [pscustomobject]$record
            })

        $tags = @()
        if (Test-PurviewCommand -Name 'Get-RetentionPolicyTag') {
            $tags = @(& (Get-PurviewServiceCommand -Name 'Get-RetentionPolicyTag' -Service 'ExchangeOnline') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | ForEach-Object {
                    $record = [ordered]@{}
                    foreach ($field in @(
                            @{ Source = 'Name'; Target = 'Name' }
                            @{ Source = 'Type'; Target = 'Type' }
                            @{ Source = 'RetentionAction'; Target = 'Action' }
                        )) {
                        if (Test-PurviewProperty -InputObject $_ -Name $field.Source) {
                            $record[$field.Target] = [string](Get-PurviewProperty -InputObject $_ -Name $field.Source)
                        }
                        else { $missing.Add("Tag.$($field.Target)") }
                    }
                    [pscustomobject]$record
                })
        }
        else { $missing.Add('Tags') }

        [pscustomobject]@{
            Policies = @($policies)
            Tags = @($tags)
            PropertiesNotReturned = @($missing | Select-Object -Unique)
        }
    }
}

function Get-PurviewAuditIngestionData {
    <#
    .SYNOPSIS
        Reads whether unified audit logging is on.

    .DESCRIPTION
        Read through Exchange Online, not Security & Compliance: Microsoft documents that
        UnifiedAuditLogIngestionEnabled is always False in the compliance session even when auditing
        is on, so reading it there would report every tenant as unaudited.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'AuditIngestion' -SolutionArea 'Audit' `
        -Interface 'Get-AdminAuditLogConfig' -Kind 'ExchangeOnlinePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/get-adminauditlogconfig" `
        -RequiredCommand @('Get-AdminAuditLogConfig', 'Get-ConnectionInformation') -ConnectWith 'Connect-ExchangeOnline' -Collect {

        # The compliance session reports False regardless, so without Exchange Online this is unknown.
        $exchange = @(Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -like 'ExchangeOnline*' -and
                [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -notlike 'ExchangeOnlineProtection*' })

        if ($exchange.Count -eq 0) {
            return [pscustomobject]@{ Settings = @(); PropertiesNotReturned = @('Enabled') }
        }

        # Microsoft documents this as always False outside Exchange Online, so reading it from the
        # compliance session would report every audited tenant as unaudited.
        $config = & (Get-PurviewServiceCommand -Name 'Get-AdminAuditLogConfig' -Service 'ExchangeOnline') -ErrorAction Stop -WarningAction SilentlyContinue
        $enabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $config -Name 'UnifiedAuditLogIngestionEnabled')
        if (-not $enabled.Valid) {
            return [pscustomobject]@{ Settings = @(); PropertiesNotReturned = @('Enabled') }
        }

        [pscustomobject]@{
            Settings = @([pscustomobject]@{
                    Name = 'UnifiedAuditLogIngestionEnabled'
                    Enabled = [bool]$enabled.Value
                    Capability = 'Unified audit logging'
                })
        }
    }
}

function Get-PurviewProtectionActivityData {
    <#
    .SYNOPSIS
        Summarises recent activity explorer events by workload and activity.

    .DESCRIPTION
        Rows name users, files, devices and IP addresses, so they are counted and discarded. Only
        the tallies reach the snapshot.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$Days = 30,
        [int]$PageLimit = 10
    )

    return Invoke-PurviewCollector -Collector 'ProtectionActivity' -SolutionArea 'ActivityExplorer' `
        -Interface 'Export-ActivityExplorerData' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/export-activityexplorerdata" `
        -RequiredCommand @('Export-ActivityExplorerData') -ConnectWith 'Connect-IPPSSession' `
        -Context ([pscustomobject]@{ Days = $Days; PageLimit = $PageLimit }) -Collect {
        param($ctx)

        # The service rejects a window that reaches the future or touches 30 days exactly. Keep one
        # minute inside each boundary, which gives a 30-day request 29 days, 23 hours and 59 minutes
        # rather than dropping the oldest day altogether. Local DateTime values avoid a UTC value
        # being re-read as local and shifted into the future west of Greenwich.
        $windowDays = [Math]::Min([Math]::Max([int]$ctx.Days, 1), 30)
        $now = Get-PurviewTimestamp
        $endInstant = $now.AddMinutes(-1)
        $startInstant = $now.AddDays(-$windowDays).AddMinutes(1)
        $end = $endInstant.LocalDateTime
        $start = $startInstant.LocalDateTime
        $byActivity = @{}
        $byWorkload = @{}
        $total = 0
        $pages = 0
        $cookie = ''
        $truncated = $false
        $scanComplete = $false
        $sawActivity = $false
        $sawWorkload = $false
        $scanMissingActivity = 0
        $scanLabelTable = @{}
        $scanAmbiguous = @{}

        $readBoolean = {
            param($value)
            if ($value -is [bool]) { return $value }
            $parsed = $false
            if ($null -ne $value -and [bool]::TryParse([string]$value, [ref]$parsed)) { return $parsed }
            return $null
        }

        $hasValue = {
            param($row, [string[]]$names)
            foreach ($name in $names) {
                $value = Get-PurviewProperty -InputObject $row -Name $name
                if ($null -eq $value) { continue }
                if ($value -is [string]) {
                    $text = $value.Trim()
                    if (-not $text -or $text -in 'None', 'null', '[]') { continue }
                    return $true
                }
                if ($value -is [System.Collections.IEnumerable] -and $value -isnot [System.Collections.IDictionary]) {
                    if (@($value).Count -eq 0) { continue }
                }
                return $true
            }
            return $false
        }

        # LabelApplied, LabelChanged and LabelRemoved cover both sensitivity and retention labels.
        # A generic event counts only when the returned label fields establish which kind it is.
        # If both kinds are named, neither kind is inferred: the row may describe an item carrying
        # both labels rather than identify which label the activity changed.
        $getLabelEvent = {
            param($row, [string]$activity)

            # Filter input uses compact tokens such as LabelApplied, while returned rows can use
            # friendly text such as "Label applied". Remove only presentation separators, then
            # require an exact known token so unrelated activity is never matched fuzzily.
            $activityToken = $activity.Trim() -replace '[\s_-]+', ''
            $canonical = switch ($activityToken) {
                { $_ -in 'LabelApplied', 'SensitivityLabelApplied', 'RetentionLabelApplied' } { 'LabelApplied'; break }
                { $_ -in 'LabelChanged', 'SensitivityLabelChanged', 'SensitivityLabelUpdated', 'RetentionLabelChanged' } { 'LabelChanged'; break }
                { $_ -in 'LabelRemoved', 'SensitivityLabelRemoved', 'RetentionLabelRemoved' } { 'LabelRemoved'; break }
                default { '' }
            }
            if (-not $canonical) { return $null }

            if ($activityToken -like 'SensitivityLabel*') {
                return [pscustomobject]@{ Activity = $canonical; Kind = 'Sensitivity' }
            }
            if ($activityToken -like 'RetentionLabel*') {
                return [pscustomobject]@{ Activity = $canonical; Kind = 'Retention' }
            }

            $sensitivityFields = if ($canonical -eq 'LabelApplied') { @('SensitivityLabel') }
            else { @('SensitivityLabel', 'OldSensitivityLabel') }
            $retentionFields = if ($canonical -eq 'LabelApplied') { @('RetentionLabel') }
            else { @('RetentionLabel', 'OldRetentionLabel') }
            $hasSensitivity = & $hasValue $row $sensitivityFields
            $hasRetention = & $hasValue $row $retentionFields

            $kind = if ($hasSensitivity -and -not $hasRetention) { 'Sensitivity' }
            elseif ($hasRetention -and -not $hasSensitivity) { 'Retention' }
            else { 'Ambiguous' }
            return [pscustomobject]@{ Activity = $canonical; Kind = $kind }
        }

        $recordLabelEvent = {
            param($table, $ambiguous, $row, [string]$activity)
            $labelEvent = & $getLabelEvent $row $activity
            if ($null -eq $labelEvent) { return $false }
            $name = [string]$labelEvent.Activity
            if ([string]$labelEvent.Kind -eq 'Sensitivity') {
                $table[$name] = 1 + $(if ($table.ContainsKey($name)) { $table[$name] } else { 0 })
            }
            elseif ([string]$labelEvent.Kind -eq 'Ambiguous') {
                $ambiguous[$name] = 1 + $(if ($ambiguous.ContainsKey($name)) { $ambiguous[$name] } else { 0 })
            }
            return $true
        }

        while ($pages -lt $ctx.PageLimit) {
            $arguments = @{
                StartTime = $start; EndTime = $end
                OutputFormat = 'Json'; PageSize = 5000; ErrorAction = 'Stop'
            }
            if ($cookie) { $arguments['PageCookie'] = $cookie }

            $page = Export-ActivityExplorerData @arguments
            $pages++

            $payload = Get-PurviewProperty -InputObject $page -Name 'ResultData'
            $rows = @(if ($payload -is [string] -and -not [string]::IsNullOrWhiteSpace($payload)) {
                @($payload | ConvertFrom-Json -Depth 20)
            }
            else { ConvertTo-PurviewArray -InputObject $payload })

            foreach ($row in $rows) {
                $total++
                $activity = [string](Get-PurviewProperty -InputObject $row -Name 'Activity', 'activity', 'Operation')
                $workload = [string](Get-PurviewProperty -InputObject $row -Name 'Workload', 'workload')
                if ($activity) {
                    $sawActivity = $true
                    $byActivity[$activity] = 1 + $(if ($byActivity.ContainsKey($activity)) { $byActivity[$activity] } else { 0 })
                    $null = & $recordLabelEvent $scanLabelTable $scanAmbiguous $row $activity
                }
                else { $scanMissingActivity++ }
                if ($workload) { $sawWorkload = $true; $byWorkload[$workload] = 1 + $(if ($byWorkload.ContainsKey($workload)) { $byWorkload[$workload] } else { 0 }) }
            }

            $last = & $readBoolean (Get-PurviewProperty -InputObject $page -Name 'LastPage')
            $cookie = [string](Get-PurviewProperty -InputObject $page -Name 'Watermark')
            if ($last -eq $true) { $scanComplete = $true; break }
            if ($last -ne $false -or $rows.Count -eq 0 -or -not $cookie) { break }
            if ($pages -ge $ctx.PageLimit) { $truncated = $true; break }
        }

        $notReturned = [System.Collections.Generic.List[string]]::new()
        if ($total -gt 0 -and -not $sawActivity) { $notReturned.Add('Activity') }
        if ($total -gt 0 -and -not $sawWorkload) { $notReturned.Add('Workload') }

        $count = { param($table, $names)
            $sum = 0
            foreach ($name in $names) { if ($table.ContainsKey($name)) { $sum += $table[$name] } }
            $sum
        }

        # Counting label events out of a scan of everything depends on paging the whole window and
        # on the Activity column coming back. Microsoft documents a filter for exactly these three,
        # so they are asked for directly and the scan is only the fallback.
        $labelTable = @{}
        $labelAmbiguous = @{}
        $labelFiltered = $false
        $labelQuerySucceeded = $false
        $labelQueryComplete = $false
        $labelQueryTruncated = $false
        $labelMissingActivity = 0
        $labelUnknownActivity = 0
        try {
            $labelCookie = ''
            for ($labelPage = 0; $labelPage -lt $ctx.PageLimit; $labelPage++) {
                $labelArguments = @{
                    StartTime = $start; EndTime = $end
                    OutputFormat = 'Json'; PageSize = 5000; ErrorAction = 'Stop'
                    Filter1 = @('Activity', 'LabelApplied', 'LabelChanged', 'LabelRemoved')
                }
                if ($labelCookie) { $labelArguments['PageCookie'] = $labelCookie }

                $labelResponse = Export-ActivityExplorerData @labelArguments
                $labelPayload = Get-PurviewProperty -InputObject $labelResponse -Name 'ResultData'
                $labelRows = @(if ($labelPayload -is [string] -and -not [string]::IsNullOrWhiteSpace($labelPayload)) {
                    @($labelPayload | ConvertFrom-Json -Depth 20)
                }
                else { ConvertTo-PurviewArray -InputObject $labelPayload })

                foreach ($labelRow in $labelRows) {
                    $name = [string](Get-PurviewProperty -InputObject $labelRow -Name 'Activity', 'activity', 'Operation')
                    if (-not $name) { $labelMissingActivity++; continue }
                    if (-not (& $recordLabelEvent $labelTable $labelAmbiguous $labelRow $name)) {
                        $labelUnknownActivity++
                    }
                }

                $labelLast = & $readBoolean (Get-PurviewProperty -InputObject $labelResponse -Name 'LastPage')
                $labelCookie = [string](Get-PurviewProperty -InputObject $labelResponse -Name 'Watermark')
                if ($labelLast -eq $true) { $labelQueryComplete = $true; break }
                if ($labelLast -ne $false -or $labelRows.Count -eq 0 -or -not $labelCookie) { break }
                if (($labelPage + 1) -ge $ctx.PageLimit) { $labelQueryTruncated = $true; break }
            }
            $labelQuerySucceeded = $true
        }
        catch {
            Write-Verbose "The label activity filter was refused, so the scan is used instead: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }

        $readCount = {
            param($table, [string]$name)
            if ($table.ContainsKey($name)) { return [int]$table[$name] }
            return 0
        }
        $filteredBaseReliable = $labelQuerySucceeded -and $labelQueryComplete -and
            $labelMissingActivity -eq 0 -and $labelUnknownActivity -eq 0
        $scanBaseReliable = $scanComplete -and $scanMissingActivity -eq 0
        $filteredApplyReliable = $filteredBaseReliable -and (& $readCount $labelAmbiguous 'LabelApplied') -eq 0
        $scanApplyReliable = $scanBaseReliable -and (& $readCount $scanAmbiguous 'LabelApplied') -eq 0

        # Prefer the narrow query; fall back only to a complete full scan to avoid understated totals.
        $source = @{}
        $sourceAmbiguous = @{}
        $sourceBaseReliable = $false
        if ($filteredApplyReliable) {
            $labelFiltered = $true
            $source = $labelTable
            $sourceAmbiguous = $labelAmbiguous
            $sourceBaseReliable = $filteredBaseReliable
        }
        elseif ($scanApplyReliable) {
            $source = $scanLabelTable
            $sourceAmbiguous = $scanAmbiguous
            $sourceBaseReliable = $scanBaseReliable
        }

        $applyReliable = $filteredApplyReliable -or $scanApplyReliable
        $changeReliable = $sourceBaseReliable -and (& $readCount $sourceAmbiguous 'LabelChanged') -eq 0
        $removeReliable = $sourceBaseReliable -and (& $readCount $sourceAmbiguous 'LabelRemoved') -eq 0

        $reason = if ($filteredApplyReliable) { 'The filtered query completed and every application event identified both its activity and label type.' }
        elseif ($scanApplyReliable) { 'The complete full scan was used because the filtered query was unavailable or unsuitable, and every application event identified both its activity and label type.' }
        elseif ($labelQuerySucceeded -and -not $labelQueryComplete) {
            if ($labelQueryTruncated) { 'The sensitivity-label application count was not used because the filtered Activity Explorer query reached its page limit before the last page.' }
            else { 'The sensitivity-label application count was not used because the filtered Activity Explorer query did not confirm that its last page was returned.' }
        }
        elseif ($labelMissingActivity -gt 0) { 'The sensitivity-label application count was not used because filtered rows did not identify their activity.' }
        elseif ($labelUnknownActivity -gt 0) { 'The sensitivity-label application count was not used because filtered rows returned an unrecognized label activity name.' }
        elseif ((& $readCount $labelAmbiguous 'LabelApplied') -gt 0) { 'The sensitivity-label application count was not used because some application events could not be distinguished from retention-label events.' }
        elseif (-not $labelQuerySucceeded -and -not $scanComplete) { 'The filtered label query failed and the full Activity Explorer scan did not complete, so neither source can supply a total.' }
        elseif ($scanMissingActivity -gt 0) { 'The full Activity Explorer scan returned rows without an activity name, so it cannot supply a label-application total.' }
        elseif ((& $readCount $scanAmbiguous 'LabelApplied') -gt 0) { 'The full Activity Explorer scan contained application events that could not be distinguished from retention-label events.' }
        else { 'Activity Explorer did not return enough pagination and event detail to establish a sensitivity-label application total.' }

        [pscustomobject]@{
            WindowDays = $windowDays
            WindowStart = Format-PurviewTimestamp -Timestamp $startInstant
            WindowEnd = Format-PurviewTimestamp -Timestamp $endInstant
            TotalEvents = $total
            Truncated = $truncated
            ActivityScanComplete = $scanComplete
            # Counts use canonical filter tokens even when returned rows used friendly names.
            LabelApplyEvents = (& $count $source @('LabelApplied', 'SensitivityLabelApplied'))
            LabelChangeEvents = (& $count $source @('LabelChanged', 'SensitivityLabelUpdated'))
            LabelRemoveEvents = (& $count $source @('LabelRemoved', 'SensitivityLabelRemoved'))
            # Whether the label counts came from a query that asked only for them, or from the scan,
            # which the report needs so it never presents a truncated scan as a total.
            LabelEventsFiltered = $labelFiltered
            LabelEventsSource = if ($labelFiltered) { 'FilteredQuery' } elseif ($applyReliable) { 'FullScan' } else { 'None' }
            LabelQuerySucceeded = $labelQuerySucceeded
            LabelQueryComplete = $labelQueryComplete
            LabelQueryTruncated = $labelQueryTruncated
            LabelRowsMissingActivity = $labelMissingActivity
            LabelRowsUnknownActivity = $labelUnknownActivity
            LabelApplyRowsAmbiguous = (& $readCount $labelAmbiguous 'LabelApplied')
            LabelApplyEventsReliable = $applyReliable
            LabelChangeEventsReliable = $changeReliable
            LabelRemoveEventsReliable = $removeReliable
            LabelEventCountReason = $reason
            DlpRuleMatchEvents = (& $count $byActivity @('DLPRuleMatch', 'DlpRuleMatch'))
            CopilotEvents = (& $count $byWorkload @('Copilot'))
            EndpointEvents = (& $count $byWorkload @('Endpoint'))
            ByActivity = @($byActivity.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Name = $_; Count = $byActivity[$_] } })
            ByWorkload = @($byWorkload.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Name = $_; Count = $byWorkload[$_] } })
            PropertiesNotReturned = $notReturned.ToArray()
        }
    }
}

function Get-PurviewClassificationCoverageData {
    <#
    .SYNOPSIS
        Reads the indexed total for each explicitly requested sensitive information type.

    .DESCRIPTION
        Omits Workload deliberately, which Microsoft documents as returning TotalCount across the
        supported Exchange, SharePoint, OneDrive and Teams locations. Each type stays separate
        because one item can match several types. Records name files and mailboxes, so PageSize is
        held at one, only TotalCount is accessed and no record is kept.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()][object[]]$Tag = @(),
        # Zero means all requested types; limit results only when the caller supplies a ceiling.
        [int]$TagLimit = 0
    )

    $coverageResult = Invoke-PurviewCollector -Collector 'ClassificationCoverage' -SolutionArea 'ContentExplorer' `
        -Interface 'Export-ContentExplorerData' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/export-contentexplorerdata" `
        -RequiredCommand @('Export-ContentExplorerData') -ConnectWith 'Connect-IPPSSession' `
        -RequiredRole 'membership of the Content Explorer List Viewer role group, under Settings, then Roles and scopes, then Role groups in the Purview portal. It reads item counts and locations, not file contents' `
        -Context ([pscustomobject]@{ Tag = @($Tag); TagLimit = $TagLimit }) -Collect {
        param($ctx)

        $counts = [System.Collections.Generic.List[object]]::new()
        $requests = [System.Collections.Generic.List[object]]::new()
        $failed = [System.Collections.Generic.List[string]]::new()
        $unavailable = [System.Collections.Generic.List[string]]::new()
        $invalidCount = [System.Collections.Generic.List[string]]::new()
        # Sensitivity-label TagName identity is not documented. Reject those objects even if an
        # older caller supplies them; only explicit sensitive information type names are queried.
        $entries = @($ctx.Tag | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'Type') -eq 'SensitiveInformationType'
            })
        $limit = [Math]::Max([int]$ctx.TagLimit, 0)

        $planned = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $index = 0
        foreach ($entry in $entries) {
            $queryName = ([string](Get-PurviewProperty -InputObject $entry -Name 'UniqueName')).Trim()
            if (-not $queryName) { $queryName = ([string](Get-PurviewProperty -InputObject $entry -Name 'Name')).Trim() }
            $displayName = ([string](Get-PurviewProperty -InputObject $entry -Name 'Name')).Trim()
            if (-not $displayName) { $displayName = $queryName }
            if (-not $displayName) { $displayName = '(unnamed sensitive information type)' }
            $key = if ($queryName) { $queryName } else { '__invalid__:' + $index }
            if ($seen.Add($key)) {
                $planned.Add([pscustomobject]@{ QueryName = $queryName; DisplayName = $displayName })
            }
            $index++
        }

        $plannedEntries = @($planned.ToArray())
        $attempted = @(if ($limit -gt 0) { @($plannedEntries | Select-Object -First $limit) } else { $plannedEntries })
        $omitted = @(if ($limit -gt 0) { @($plannedEntries | Select-Object -Skip $limit) } else { @() })

        foreach ($entry in $attempted) {
            $queryName = [string]$entry.QueryName
            $displayName = [string]$entry.DisplayName
            if ([string]::IsNullOrWhiteSpace($queryName)) {
                $failed.Add($displayName)
                $unavailable.Add($displayName)
                $requests.Add([pscustomobject]@{ Tag = $displayName; TagType = 'SensitiveInformationType'; Status = 'Unavailable'; TotalCount = $null })
                continue
            }

            try {
                # No Workload means the aggregate for this tag across every supported location;
                # passing one would silently turn the number into a workload-specific subtotal.
                $response = @(Export-ContentExplorerData -TagType 'SensitiveInformationType' -TagName $queryName -PageSize 1 -ErrorAction Stop)
                $summary = if ($response.Count -gt 0) { $response[0] } else { $null }
                $rawCount = Get-PurviewProperty -InputObject $summary -Name 'TotalCount'
                $totalCount = [long]0
                $validCount = $null -ne $rawCount -and [long]::TryParse(
                    [string]$rawCount,
                    [System.Globalization.NumberStyles]::Integer,
                    [cultureinfo]::InvariantCulture,
                    [ref]$totalCount)
                if (-not $validCount -or $totalCount -lt 0) {
                    $failed.Add($displayName)
                    $invalidCount.Add($displayName)
                    $requests.Add([pscustomobject]@{ Tag = $displayName; TagType = 'SensitiveInformationType'; Status = 'InvalidTotalCount'; TotalCount = $null })
                    continue
                }
                $counts.Add([pscustomobject]@{
                        Tag = $displayName
                        TagType = 'SensitiveInformationType'
                        TotalCount = $totalCount
                    })
                $requests.Add([pscustomobject]@{ Tag = $displayName; TagType = 'SensitiveInformationType'; Status = 'Success'; TotalCount = $totalCount })
            }
            catch {
                # One unreadable tag must not discard the tags that did resolve.
                $failed.Add($displayName)
                $unavailable.Add($displayName)
                $requests.Add([pscustomobject]@{ Tag = $displayName; TagType = 'SensitiveInformationType'; Status = 'Unavailable'; TotalCount = $null })
            }
        }

        $omittedNames = @($omitted | ForEach-Object { [string]$_.DisplayName })
        foreach ($name in $omittedNames) {
            $requests.Add([pscustomobject]@{ Tag = $name; TagType = 'SensitiveInformationType'; Status = 'OmittedByLimit'; TotalCount = $null })
        }

        [pscustomobject]@{
            RequestKind = 'ExplicitSensitiveInformationType'
            Tags = $counts.ToArray()
            Requests = $requests.ToArray()
            TagsRequested = $planned.Count
            TagsAttempted = $attempted.Count
            TagsUnreadable = $failed.ToArray()
            TagsUnavailable = $unavailable.ToArray()
            TagsWithInvalidTotalCount = $invalidCount.ToArray()
            TagsOmittedByLimit = $omittedNames
            PropertiesNotReturned = @(if ($failed.Count -gt 0) { 'TotalCount' })
        }
    }

    if ([string](Get-PurviewProperty -InputObject $coverageResult -Name 'status') -notin 'Success', 'PartialSuccess') {
        $requestedNames = [System.Collections.Generic.List[string]]::new()
        $seenRequested = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @($Tag | Where-Object {
                    [string](Get-PurviewProperty -InputObject $_ -Name 'Type') -eq 'SensitiveInformationType'
                })) {
            $name = ([string](Get-PurviewProperty -InputObject $entry -Name 'Name')).Trim()
            if (-not $name) { $name = ([string](Get-PurviewProperty -InputObject $entry -Name 'UniqueName')).Trim() }
            if ($name -and $seenRequested.Add($name)) { $requestedNames.Add($name) }
        }
        if ($requestedNames.Count -gt 0) {
            $coverageResult.data = [pscustomobject]@{
                RequestKind = 'ExplicitSensitiveInformationType'
                Tags = @()
                Requests = @($requestedNames | ForEach-Object {
                    [pscustomobject]@{ Tag = $_; TagType = 'SensitiveInformationType'; Status = 'CollectorUnavailable'; TotalCount = $null }
                    })
                TagsRequested = $requestedNames.Count
                TagsAttempted = 0
                TagsUnreadable = $requestedNames.ToArray()
                TagsUnavailable = $requestedNames.ToArray()
                TagsWithInvalidTotalCount = @()
                TagsOmittedByLimit = @()
            }
        }
    }

    return $coverageResult
}

function Get-PurviewSharePointReadinessData {
    <# .SYNOPSIS Collects the tenant opt-ins that SharePoint and OneDrive labeling depends on. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Expected is not always $true: the mismatch email is kept by leaving its Block switch off,
    # default library labeling by leaving its Disable switch off, and one gate is not a switch at all.
    $gates = @(
        @{ Name = 'EnableAIPIntegration'; Expected = $true; Capability = 'Labels processed for Office files in SharePoint and OneDrive' }
        @{ Name = 'EnableSensitivityLabelforPDF'; Expected = $true; Capability = 'Labels on PDF files' }
        @{ Name = 'EnableSensitivityLabelforOneNote'; Expected = $true; Capability = 'Labels on OneNote sections' }
        @{ Name = 'EnableSensitivityLabelForVideoFiles'; Expected = $true; Capability = 'Labels on MP4 video files' }
        @{ Name = 'BlockSendLabelMismatchEmail'; Expected = $false; Capability = 'Label mismatch email to uploader and site owners' }
        @{ Name = 'DisableDocumentLibraryDefaultLabeling'; Expected = $false; Capability = 'Default labels on document libraries' }
        @{ Name = 'MarkNewFilesSensitiveByDefault'; Expected = 'BlockExternalSharing'; Capability = 'Sensitive by default for new files' }
    )

    return Invoke-PurviewCollector -Collector 'SharePointLabelingReadiness' -SolutionArea 'SensitivityLabels' `
        -Interface 'Get-SPOTenant' -Kind 'SharePointOnlinePowerShell' `
        -DocumentationUrl "$script:SpoDocRoot/get-spotenant" `
        -RequiredCommand @('Get-SPOTenant') -ConnectWith 'Connect-SPOService' -Context $gates -Collect {
        param($ctx)
        $tenant = Get-SPOTenant -ErrorAction Stop -WarningAction SilentlyContinue

        $settings = [System.Collections.Generic.List[object]]::new()
        $missing = [System.Collections.Generic.List[string]]::new()

        foreach ($gate in $ctx) {
            if (-not (Test-PurviewProperty -InputObject $tenant -Name $gate.Name)) {
                $missing.Add($gate.Name)
                continue
            }
            $raw = Get-PurviewProperty -InputObject $tenant -Name $gate.Name
            $isSwitch = $gate.Expected -is [bool]
            if ($isSwitch) {
                $parsed = ConvertTo-PurviewBoolean -InputObject $raw
                if (-not $parsed.Valid) {
                    $missing.Add($gate.Name)
                    continue
                }
                $enabled = [bool]$parsed.Value
                $value = [string]$enabled
                $asRecommended = $enabled -eq [bool]$gate.Expected
            }
            else {
                $value = ([string]$raw).Trim()
                if ($null -eq $raw -or [string]::IsNullOrWhiteSpace($value)) {
                    $missing.Add($gate.Name)
                    continue
                }
                $enabled = $value -eq [string]$gate.Expected
                $asRecommended = $enabled
            }

            $settings.Add([pscustomobject]@{
                    Name = $gate.Name
                    Enabled = $enabled
                    Value = $value
                    Expected = [string]$gate.Expected
                    AsRecommended = $asRecommended
                    Capability = $gate.Capability
                })
        }

        # Rules test the normalized verdict fields, while prerequisites need the setting name.
        # Listing both keeps either consumer from judging a partial set as complete.
        if ($missing.Count -gt 0) {
            $missing.Add('Enabled')
            $missing.Add('AsRecommended')
        }
        [pscustomobject]@{ Settings = $settings.ToArray(); PropertiesNotReturned = @($missing | Select-Object -Unique) }
    }
}

function Get-PurviewContainerLabelData {
    <#
    .SYNOPSIS
        Collects the directory setting that lets sensitivity labels apply to groups, Teams and sites.

    .DESCRIPTION
        Container labelling is switched on in Entra rather than in Purview, so a tenant can publish
        container-scoped labels that never appear to anyone until this is set.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'ContainerLabel' -SolutionArea 'SensitivityLabels' `
        -Interface 'GET /groupSettings' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/graph/api/group-list-settings?view=graph-rest-1.0' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -ConnectWith 'Connect-MgGraph -Scopes GroupSettings.Read.All' -Collect {
        $settings = [System.Collections.Generic.List[object]]::new()
        $states = [System.Collections.Generic.List[bool]]::new()
        $found = $false
        $invalid = $false

        foreach ($group in @(Invoke-PurviewGraphGet -Uri '/v1.0/groupSettings')) {
            if ([string](Get-PurviewProperty -InputObject $group -Name 'displayName') -ne 'Group.Unified') { continue }

            foreach ($value in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $group -Name 'values'))) {
                if ([string](Get-PurviewProperty -InputObject $value -Name 'name') -ne 'EnableMIPLabels') { continue }

                # The directory stores this as the string "true", not a boolean.
                $found = $true
                if (-not (Test-PurviewProperty -InputObject $value -Name 'value')) {
                    $invalid = $true
                    continue
                }
                $parsed = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $value -Name 'value')
                if (-not $parsed.Valid) {
                    $invalid = $true
                    continue
                }
                $states.Add([bool]$parsed.Value)
            }
        }

        # Microsoft documents that a directory with no settings object of its own is running the
        # template defaults, and that EnableMIPLabels defaults to False. A tenant that has never
        # written the setting is therefore switched off, which is an answer rather than a gap.
        if (-not $found) {
            $settings.Add([pscustomobject]@{
                    Name = 'EnableMIPLabels'
                    Enabled = $false
                    Value = 'False'
                    Expected = 'True'
                    AsRecommended = $false
                    Capability = 'Sensitivity labels on Microsoft 365 groups, Teams and SharePoint sites'
                    Detail = 'No Group.Unified directory setting has been created, so the tenant is on the template default of False'
                })
        }
        else {
            $distinct = @($states | Select-Object -Unique)
            if ($invalid -or $distinct.Count -ne 1) {
                return [pscustomobject]@{
                    Settings = @()
                    PropertiesNotReturned = @('EnableMIPLabels', 'Enabled', 'AsRecommended')
                }
            }

            $enabled = [bool]$distinct[0]
            $settings.Add([pscustomobject]@{
                    Name = 'EnableMIPLabels'
                    Enabled = $enabled
                    Value = [string]$enabled
                    Expected = 'True'
                    AsRecommended = $enabled
                    Capability = 'Sensitivity labels on Microsoft 365 groups, Teams and SharePoint sites'
                })
        }

        [pscustomobject]@{ Settings = $settings.ToArray() }
    }
}

function Get-PurviewSharePointSiteData {
    <#
    .SYNOPSIS
        Collects per-site sensitivity labelling and sharing posture.

    .DESCRIPTION
        Container labels are a Purview control applied at site level, so they are read here even
        though the interface belongs to SharePoint.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int]$Limit = 200)

    $context = @{
        Limit = $Limit
        Map = [ordered]@{
            Url = @('Url'); Title = @('Title')
            SensitivityLabel = @('SensitivityLabel'); SharingCapability = @('SharingCapability')
        }
        Optional = @('Title', 'SensitivityLabel', 'SharingCapability')
    }

    return Invoke-PurviewCollector -Collector 'SharePointSite' -SolutionArea 'SensitivityLabels' `
        -Interface 'Get-SPOSite' -Kind 'SharePointOnlinePowerShell' `
        -DocumentationUrl "$script:SpoDocRoot/get-sposite" `
        -RequiredCommand @('Get-SPOSite') -ConnectWith 'Connect-SPOService' -Context $context -Collect {
        param($ctx)
        $sites = @(Get-SPOSite -Limit $ctx.Limit -ErrorAction Stop -WarningAction SilentlyContinue |
            ForEach-Object { ConvertTo-PurviewRecord -InputObject $_ -Map $ctx.Map })

        [pscustomobject]@{
            Sites = $sites
            SiteLimit = $ctx.Limit
            PropertiesNotReturned = Get-PurviewUnmappedProperty -Record $sites -Map $ctx.Map -Optional $ctx.Optional
        }
    }
}

function Get-PurviewDataAccessGovernanceData {
    <#
    .SYNOPSIS
        Reads the metadata of the oversharing reports a tenant has already generated.

    .DESCRIPTION
        Existing data access governance report metadata can inform an oversharing review, but is
        subject to report age, filters and thresholds and is not complete Copilot exposure evidence.
        Only the listing cmdlet is called: Start- generates a report, which is an expensive tenant
        action, and Export- downloads a CSV of sites and users. Neither belongs in a read-only run,
        so this reports what exists rather than producing it.

        Each entity is asked for separately because the cmdlet takes one at a time, and one refusing
        is recorded rather than losing the rest.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # The oversharing entities a Copilot licence covers. PermissionsReport is deliberately absent:
    # it is the per-user report and is built from a list of named people.
    $context = @{
        Entities = @(
            'PermissionedUsers'
            'EveryoneExceptExternalUsers'
            'EveryoneExceptExternalUsersAtSite'
            'EveryoneExceptExternalUsersForItems'
            'SharingLinks_Anyone'
            'SharingLinks_PeopleInYourOrg'
            'SharingLinks_Guests'
            'SensitivityLabelForFiles'
        )
    }

    return Invoke-PurviewCollector -Collector 'DataAccessGovernance' -SolutionArea 'Oversharing' `
        -Interface 'Get-SPODataAccessGovernanceInsight' -Kind 'SharePointOnlinePowerShell' `
        -DocumentationUrl "$script:SpoDocRoot/get-spodataaccessgovernanceinsight" `
        -RequiredCommand @('Get-SPODataAccessGovernanceInsight') -ConnectWith 'Connect-SPOService' `
        -Context $context -Collect {
        param($ctx)

        $reports = [System.Collections.Generic.List[object]]::new()
        $refused = [System.Collections.Generic.List[string]]::new()
        $notReturned = [System.Collections.Generic.List[string]]::new()

        foreach ($entity in $ctx.Entities) {
            try {
                # The cmdlet announces its own preview status on every call, which would land in the
                # middle of the step line.
                foreach ($row in @(Get-SPODataAccessGovernanceInsight -ReportEntity $entity -ErrorAction Stop -WarningAction SilentlyContinue)) {
                    # Counts and status only. ReportName is admin-chosen text and the rest of the
                    # object names sites and people, so none of it is carried into the snapshot.
                    $status = [string](Get-PurviewProperty -InputObject $row -Name 'Status')
                    $record = [ordered]@{
                        Entity = $entity
                        Status = $status
                        Workload = [string](Get-PurviewProperty -InputObject $row -Name 'Workload')
                        ReportType = [string](Get-PurviewProperty -InputObject $row -Name 'ReportType')
                        CreatedAt = [string](Get-PurviewProperty -InputObject $row -Name 'CreatedDateTime')
                    }
                    # SharePoint projects each report family through a different response class:
                    # permission reports expose CountOfSites*, EEEU and sharing-link reports expose
                    # SitesFound, detailed EEEU exposes only CountOfSitesInReport, and label reports
                    # expose none of them. Match that schema by entity rather than property presence,
                    # because compatibility remoting can preserve an inapplicable property as null.
                    foreach ($field in @(
                            @{
                                Source = 'CountOfSitesInReport'; Target = 'SitesInReport'
                                AppliesTo = @('PermissionedUsers', 'EveryoneExceptExternalUsersAtSite', 'EveryoneExceptExternalUsersForItems')
                            }
                            @{
                                Source = 'CountOfSitesInTenant'; Target = 'SitesInTenant'
                                AppliesTo = @('PermissionedUsers', 'EveryoneExceptExternalUsersAtSite')
                            }
                            @{
                                Source = 'SitesFound'; Target = 'SitesFound'
                                AppliesTo = @('EveryoneExceptExternalUsers', 'SharingLinks_Anyone', 'SharingLinks_PeopleInYourOrg', 'SharingLinks_Guests')
                            }
                        )) {
                        if ($field.AppliesTo -notcontains $entity) { continue }

                        $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $row -Name $field.Source)
                        if ($parsed.Valid) { $record[$field.Target] = [long]$parsed.Value }
                        elseif ($status -eq 'Completed') { $notReturned.Add($field.Target) }
                    }
                    $reports.Add([pscustomobject]$record)
                }
            }
            catch {
                $refused.Add($entity)
                Write-Verbose "$entity was not readable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
            }
        }

        # Failed entity reads are not empty reports; their cause is not established by this result.
        [pscustomobject]@{
            Reports = $reports.ToArray()
            EntitiesNotRead = $refused.ToArray()
            EntitiesAsked = $ctx.Entities.Count
            PropertiesNotReturned = @($notReturned | Select-Object -Unique)
        }
    }
}

function Invoke-PurviewGraphInNewSession {
    <#
    .SYNOPSIS
        Runs one Graph read in a new process, where no other module has loaded a sign-in library.

    .DESCRIPTION
        Exchange Online and Graph ship different builds of Microsoft.Identity.Client. .NET loads one
        per process, on first use, so where the two versions are incompatible only one can work. This
        gives Graph a process of its own. Module-managed caches may allow reuse, but later calls
        can still require authentication and parent-session cleanup does not verify child caches.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Verb,
        [Parameter(Mandatory)][string]$Uri,
        [string]$BodyJson = '',
        [switch]$Paged,
        [int]$MaxPage = 20
    )

    $quote = ${function:ConvertTo-PurviewPowerShellLiteral}
    # Not every host reports a path for its own process, so fall back to whatever pwsh is on PATH.
    $shell = [string](Get-Process -Id $PID).Path
    if (-not $shell) {
        $shell = [string](Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty Source)
    }
    if (-not $shell) { throw 'PowerShell 7 could not be located to run the Graph session.' }
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ('purview-graph-{0}.ps1' -f [guid]::NewGuid())
    $scopes = (@($script:GraphScope) | ForEach-Object { & $quote $_ }) -join ', '
    $body = if ($BodyJson) { '-Body {0} -ContentType ''application/json'' ' -f (& $quote $BodyJson) } else { '' }
    $tenant = if ($script:ExpectedTenantId) { ' -TenantId {0}' -f (& $quote $script:ExpectedTenantId) } else { '' }

    # A process per page would mean twenty sign-ins for one read, so paging happens in there.
    $work = if ($Paged) {
        @(
            '$items = @()'
            ('$next = {0}' -f (& $quote $Uri))
            ('$page = 0')
            ('while ($next -and $page -lt {0}) {{' -f [int]$MaxPage)
            '    $answer = Invoke-MgGraphRequest -Method $verb -Uri $next -OutputType PSObject -ErrorAction Stop'
            '    if ($null -eq $answer) { throw ''Graph returned no response.'' }'
            '    $page++'
            '    $value = $answer.value'
            '    if ($null -eq $value) { $items += $answer; $next = ''''; break }'
            '    $items += @($value)'
            '    $next = [string]$answer.''@odata.nextLink'''
            '}'
            'if ($next) { throw ''Graph pagination did not complete within the page limit.'' }'
            'ConvertTo-Json -InputObject @($items) -Depth 20 -Compress'
        )
    }
    else {
        @(
            ('$answer = Invoke-MgGraphRequest -Method $verb -Uri {0} {1}-OutputType PSObject -ErrorAction Stop' -f (& $quote $Uri), $body)
            '$answer | ConvertTo-Json -Depth 20 -Compress'
        )
    }

    Set-Content -LiteralPath $file -Encoding utf8 -Value (@(
            '$ErrorActionPreference = ''Stop'''
            'Import-Module Microsoft.Graph.Authentication -ErrorAction Stop'
            ('Connect-MgGraph -Scopes {0} -Environment Global{1} -NoWelcome -ErrorAction Stop' -f $scopes, $tenant)
            ('$verb = {0}' -f (& $quote $Verb))
        ) + $work)

    try {
        $output = & $shell -NoLogo -NoProfile -File $file 2>&1
        if ($LASTEXITCODE -ne 0) {
            # This text reaches the report, so redact it like any other error.
            $tail = @($output | ForEach-Object { "$_" } | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' '
            throw ('exit {0}: {1}' -f $LASTEXITCODE, (Get-PurviewSafeErrorMessage -Message $tail))
        }
        # The sign-in prints before the payload, so the last JSON-looking line is the answer.
        $json = @($output | Where-Object { "$_" -match '^\s*[\{\[]' } | Select-Object -Last 1)
        if ($json.Count -eq 0) { throw 'The Graph session did not return a readable JSON response.' }
        # Graph can return two properties differing only in case, which ConvertFrom-Json rejects
        # unless asked for a hashtable. Every reader here takes either shape.
        try { return ($json[0] | ConvertFrom-Json) }
        catch { return ($json[0] | ConvertFrom-Json -AsHashtable) }
    }
    finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PurviewGraphHunt {
    <# .SYNOPSIS Runs one read-only advanced hunting query, in this process or a fresh one. #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][string]$Kql)

    $bodyJson = @{ Query = $Kql } | ConvertTo-Json -Depth 5
    if ($script:GraphSeparate) {
        return Invoke-PurviewGraphInNewSession -Verb 'POST' -Uri '/v1.0/security/runHuntingQuery' -BodyJson $bodyJson
    }
    return Invoke-MgGraphRequest -Method POST -Uri '/v1.0/security/runHuntingQuery' `
        -Body $bodyJson -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
}

function Invoke-PurviewGraphGet {
    <#
    .SYNOPSIS
        Issues a read-only Graph request and returns the value collection.

    .DESCRIPTION
        The method is fixed to GET here rather than passed in, so no caller can turn this into a
        write. Paging is followed so a truncated first page is never mistaken for the whole answer.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxPage = 20
    )

    $items = [System.Collections.Generic.List[object]]::new()

    if ($script:GraphSeparate) {
        foreach ($item in @(Invoke-PurviewGraphInNewSession -Verb 'GET' -Uri $Uri -Paged -MaxPage $MaxPage)) {
            if ($null -ne $item) { $items.Add($item) }
        }
        return $items.ToArray()
    }

    $next = $Uri
    $page = 0

    while ($next -and $page -lt $MaxPage) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($null -eq $response) { throw 'Graph returned no response.' }
        $page++

        # A helper streams an empty array as no output. Read value directly so an empty
        # collection stays empty instead of turning its response envelope into a fake SKU.
        $value = $null
        if ($response -is [System.Collections.IDictionary]) { $value = $response['value'] }
        elseif ($response.PSObject.Properties['value']) { $value = $response.PSObject.Properties['value'].Value }
        if ($null -eq $value) {
            $items.Add($response)
            $next = ''
            break
        }
        foreach ($item in @($value)) { $items.Add($item) }

        $next = [string](Get-PurviewProperty -InputObject $response -Name '@odata.nextLink')
    }

    if ($next) { throw 'Graph pagination did not complete within the page limit.' }
    return $items.ToArray()
}

function Get-PurviewEndpointDeviceHealthData {
    <#
    .SYNOPSIS
        Counts historical device-state indicators from the hunting window.

    .DESCRIPTION
        Reads DlpInfo from the advanced hunting DeviceInfo table. These aggregate indicators do
        not verify current device health, policy applicability or effective enforcement.

        Onboarding is read from OnboardingStatus, which Microsoft documents as whether the device
        is onboarded to Microsoft Defender for Endpoint. Microsoft documents enabling device
        monitoring and onboarding endpoints as two separate steps. This query does not read the
        current monitoring switch, so the count is named for the service it describes.

        Each device is reduced to its latest available row before DlpInfo is read. Counts use
        independent conditions; their overlaps are not returned and cannot be inferred by subtraction.

        The query aggregates in the service and returns counts alone. DlpInfo carries the signed-in
        user's principal name, so it is never projected: no device name and no user reaches the
        snapshot.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'EndpointDeviceHealth' -SolutionArea 'EndpointDlp' `
        -Interface 'POST /security/runHuntingQuery' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/graph/api/security-security-runhuntingquery' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -ConnectWith 'Connect-MgGraph -Scopes ThreatHunting.Read.All' -Collect {

        $kql = @'
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| where isnotempty(DlpInfo)
| extend d = parse_json(DlpInfo)
| summarize Devices = count(),
            DefenderOnboarded = countif(OnboardingStatus =~ "Onboarded"),
            DlpEnabled = countif(tobool(d.IsDlpEnabled) == true),
            ConfigurationValid = countif(tobool(d.IsDlpConfigurationValid) == true),
            RealTimeProtectionOff = countif(tobool(d.IsDefenderRealTimeProtectionEnabled) == false),
            BehaviorMonitoringOff = countif(tobool(d.IsDefenderBehaviorMonitoringEnabled) == false),
            BandwidthExceeded = countif(tobool(d.HasDlpACBandwidthExceeded) == true),
            InvalidUser = countif(tobool(d.HasDlpValidUpn) == false)
'@

        $response = Invoke-PurviewGraphHunt -Kql $kql

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))

        # Defender for Endpoint populates this table. Without exactly one aggregate row, nothing is
        # known about devices rather than that none are onboarded.
        if ($rows.Count -ne 1) {
            return [pscustomobject]@{ Devices = @(); PropertiesNotReturned = @('DeviceHealth') }
        }

        $values = [ordered]@{}
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($field in ([ordered]@{
                Devices = 'Reporting'
                DefenderOnboarded = 'DefenderOnboarded'
                DlpEnabled = 'DlpEnabled'
                ConfigurationValid = 'ConfigurationValid'
                RealTimeProtectionOff = 'RealTimeProtectionOff'
                BehaviorMonitoringOff = 'BehaviorMonitoringOff'
                BandwidthExceeded = 'BandwidthExceeded'
                InvalidUser = 'InvalidUser'
            }).GetEnumerator()) {
            $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $rows[0] -Name $field.Key)
            if ($parsed.Valid) { $values[$field.Value] = [long]$parsed.Value }
            else { $missing.Add($field.Value) }
        }

        if ($missing.Count -gt 0) {
            return [pscustomobject]@{
                Devices = @()
                PropertiesNotReturned = @($missing | Select-Object -Unique)
            }
        }

        [pscustomobject]@{
            Devices = @([pscustomobject]$values)
        }
    }
}

function Get-PurviewInsiderRiskSharingData {
    <#
    .SYNOPSIS
        Looks for evidence that insider risk detail is being shared with Defender.

    .DESCRIPTION
        Microsoft documents that this table returns nothing unless the organisation has opted in to
        share insider risk alerts with Defender. Rows prove detail reached Defender during the query
        window, not that the opt-in remains on now. None is not proof it is off, because an opted-in
        tenant may simply have no behaviours.

        Counted in the service. The table names users, devices, sites and recipients, so nothing but
        the total is read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'InsiderRiskSharing' -SolutionArea 'InsiderRisk' `
        -Interface 'POST /security/runHuntingQuery' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/defender-xdr/advanced-hunting-datasecuritybehaviors-table' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -AbsenceMeans 'Insider risk detail could not be read; neither historical activity nor the current sharing opt-in is established.' `
        -ConnectWith 'Connect-MgGraph -Scopes ThreatHunting.Read.All' -Collect {

        $kql = 'DataSecurityBehaviors | where Timestamp > ago(30d) | summarize Behaviors = count()'

        $response = Invoke-PurviewGraphHunt -Kql $kql

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))
        if ($rows.Count -ne 1) {
            return [pscustomobject]@{ Behaviors = @(); PropertiesNotReturned = @('Behaviors') }
        }

        $count = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $rows[0] -Name 'Behaviors')
        if (-not $count.Valid) {
            return [pscustomobject]@{ Behaviors = @(); PropertiesNotReturned = @('Behaviors') }
        }

        # An empty result is the same shape as never having opted in, so it carries no entry at all
        # rather than an entry saying zero.
        [pscustomobject]@{ Behaviors = @(if ($count.Value -gt 0) { [pscustomobject]@{ Count = [long]$count.Value } }) }
    }
}

function Get-PurviewCloudAppConnectorData {
    <#
    .SYNOPSIS
        Looks for evidence that a Defender for Cloud Apps app connector is ingesting Microsoft 365 activity.

    .DESCRIPTION
        Microsoft documents CloudAppEvents as populated by Defender for Cloud Apps. AuditSource and
        application filters isolate Microsoft 365 app-connector rows. They prove ingestion during the
        query window, not current status or health. None is not proof the connector is off, because an
        idle or undeployed tenant looks the same.

        Counted in the service. The table names users, files, objects and IP addresses, so nothing but
        the totals is read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'CloudAppConnector' -SolutionArea 'PostureValidation' `
        -Interface 'POST /security/runHuntingQuery' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -AbsenceMeans 'Microsoft 365 cloud app activity could not be read; connector ingestion and current health are not established.' `
        -ConnectWith 'Connect-MgGraph -Scopes ThreatHunting.Read.All' -Collect {

        # Access and session controls also populate CloudAppEvents. AuditSource is documented and
        # keeps those rows from being mistaken for evidence that an app connector is ingesting.
        $kql = @(
            'CloudAppEvents'
            '| where Timestamp > ago(30d) and AuditSource == "Defender for Cloud Apps app connector"'
            '| where Application in~ ("Exchange Online", "SharePoint Online", "Microsoft Teams", "Dynamics 365", "Skype for Business", "Viva Engage", "Power Automate", "Power BI")'
            '| summarize Events = count(), Apps = dcount(Application), ConnectorEvents = count()'
        ) -join [Environment]::NewLine

        $response = Invoke-PurviewGraphHunt -Kql $kql

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))
        if ($rows.Count -ne 1) {
            return [pscustomobject]@{ Connectors = @(); PropertiesNotReturned = @('Events', 'Apps', 'ConnectorEvents') }
        }

        $record = [ordered]@{}
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($field in 'Events', 'Apps', 'ConnectorEvents') {
            $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $rows[0] -Name $field)
            if ($parsed.Valid) { $record[$field] = [long]$parsed.Value }
            else { $missing.Add($field) }
        }

        # An empty result is the same shape as never deploying Defender for Cloud Apps, so it carries
        # no entry rather than an entry saying zero. ConnectorEvents is the proof-bearing operand;
        # an event from access or session control cannot satisfy it.
        $connectorKnown = $record.Contains('ConnectorEvents')
        [pscustomobject]@{
            Connectors = @(if ($connectorKnown -and $record['ConnectorEvents'] -gt 0) { [pscustomobject]$record })
            PropertiesNotReturned = $missing.ToArray()
        }
    }
}

function Get-PurviewProtectedFilesConsentData {
    <#
    .SYNOPSIS
        Looks for candidate protected-file inspection app-role assignments.

    .DESCRIPTION
        Granting "Inspect protected files" in the portal provisions the "Microsoft Cloud App Security
        (Internal)" service principal and gives it the Azure Rights Management super-user app role.
        This implementation matches a display name and Content.SuperUser role value without pinning
        the documented application and resource identities. A positive result is candidate evidence,
        not fully validated consent; absence or an unavailable read does not prove consent is absent.

        Application.Read.All is the least-privileged read for a service principal's app-role
        assignments. Nothing here grants or changes consent.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'ProtectedFilesConsent' -SolutionArea 'PostureValidation' `
        -Interface 'GET /servicePrincipals' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -AbsenceMeans 'The Defender for Cloud Apps protected-file consent could not be read, so whether protected files can be inspected is confirmed in the portal.' `
        -ConnectWith 'Connect-MgGraph -Scopes Application.Read.All' -Collect {

        # The documented app identities are not pinned here. Excluding tenant-owned candidates
        # is insufficient to authenticate Microsoft ownership; preserve this as candidate evidence.
        $assessedTenant = ''
        if (Test-PurviewCommand -Name 'Get-MgContext') {
            try { $assessedTenant = [string](Get-PurviewProperty -InputObject (Get-MgContext -ErrorAction Stop) -Name 'TenantId') }
            catch { Write-Verbose 'No Graph context to take the assessed tenant from.' }
        }

        $nameFilter = "displayName eq 'Microsoft Cloud App Security (Internal)'"
        $principalCandidates = @(Invoke-PurviewGraphGet -Uri ('/v1.0/servicePrincipals?$filter={0}&$select=id,appId,appOwnerOrganizationId' -f [uri]::EscapeDataString($nameFilter)))

        $principals = @($principalCandidates | Where-Object {
                $owner = [string](Get-PurviewProperty -InputObject $_ -Name 'appOwnerOrganizationId')
                # An unknown owner is still assessed. Dropping it would hide a real grant.
                -not $assessedTenant -or -not $owner -or $owner -ne $assessedTenant
            })

        $granted = 0
        $incomplete = $false
        $resourceCache = @{}
        foreach ($sp in $principals) {
            $id = [string](Get-PurviewProperty -InputObject $sp -Name 'id')
            if (-not $id) { $incomplete = $true; continue }
            $assignments = @(Invoke-PurviewGraphGet -Uri "/v1.0/servicePrincipals/$id/appRoleAssignments")
            foreach ($assignment in $assignments) {
                $resourceId = [string](Get-PurviewProperty -InputObject $assignment -Name 'resourceId')
                $appRoleId = [string](Get-PurviewProperty -InputObject $assignment -Name 'appRoleId')
                if (-not $resourceId -or -not $appRoleId) { $incomplete = $true; continue }

                if (-not $resourceCache.ContainsKey($resourceId)) {
                    $resources = @(Invoke-PurviewGraphGet -Uri "/v1.0/servicePrincipals/$resourceId`?`$select=id,displayName,appRoles")
                    $resourceCache[$resourceId] = if ($resources.Count -eq 1) { $resources[0] } else { $null }
                }
                $resource = $resourceCache[$resourceId]
                if ($null -eq $resource) { $incomplete = $true; continue }

                # Identified by the value Microsoft gives the role, not by the name of the
                # application holding it: tenants return that as Microsoft Rights Management
                # Services or Azure Rights Management Services for the same application.
                $role = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $resource -Name 'appRoles') |
                    Where-Object {
                        [string](Get-PurviewProperty -InputObject $_ -Name 'id') -eq $appRoleId -and
                        [string](Get-PurviewProperty -InputObject $_ -Name 'value') -eq 'Content.SuperUser'
                    })
                if ($role.Count -eq 1) { $granted++; break }
            }
        }

        # Legacy positive state accepts one matching role even with other incomplete assignments.
        # It does not validate application/resource identity or effective inspection.
        [pscustomobject]@{
            Grants = @(if ($granted -gt 0) { [pscustomobject]@{ Count = $granted } })
            PropertiesNotReturned = @(if ($granted -eq 0 -and $incomplete) { 'Content.SuperUser app-role assignment' })
        }
    }
}

function Get-PurviewDataSecurityTelemetryData {
    <#
    .SYNOPSIS
        Looks for telemetry that corroborates the policies the configuration read reported.

    .DESCRIPTION
        Configuration says a policy exists. This reports whether a match was recorded during the
        query window, which is a different question. Microsoft documents that the table is populated
        by insider risk management and returns nothing unless the organisation has opted in to share
        insider risk alerts with Defender. A row is historical evidence only: it does not establish
        the present configuration, health or identity of the policy that matched. An empty result
        confirms nothing either way.

        Policy names are read as presence tests rather than parsed. DlpPolicyMatchInfo is a string
        and DlpPolicyRuleMatchInfo a dynamic array, and neither inner format is documented, so
        naming individual policies from them would be guesswork.

        The table names users, devices, files, sites and mail subjects. Only totals are read.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'DataSecurityTelemetry' -SolutionArea 'PostureValidation' `
        -Interface 'POST /security/runHuntingQuery' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/defender-xdr/advanced-hunting-datasecurityevents-table' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -AbsenceMeans 'Policy match telemetry was not available, so the configuration in this report stands on its own without it.' `
        -ConnectWith 'Connect-MgGraph -Scopes ThreatHunting.Read.All' -Collect {

        # DlpPolicyEnforcementMode 4 is Block. Blocking and DlpMatches are independent aggregates,
        # not correlated events; the downstream comparison does not establish a subset relationship.
        $kql = @'
DataSecurityEvents
| where Timestamp > ago(30d)
| summarize Events = count(),
            DlpMatches = countif(isnotempty(DlpPolicyMatchInfo)),
            CcMatches = countif(isnotempty(CcPolicyMatchInfo)),
            IrmMatches = countif(isnotempty(IrmPolicyMatchInfo)),
            Blocking = countif(DlpPolicyEnforcementMode == 4),
            Labelled = dcountif(SensitivityLabelId, isnotempty(SensitivityLabelId))
'@

        $response = Invoke-PurviewGraphHunt -Kql $kql

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))
        $fields = @('Events', 'DlpMatches', 'CcMatches', 'IrmMatches', 'Blocking', 'Labelled')
        if ($rows.Count -ne 1) {
            return [pscustomobject]@{ Signals = @(); PropertiesNotReturned = $fields }
        }

        $values = [ordered]@{}
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($field in $fields) {
            $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $rows[0] -Name $field)
            if ($parsed.Valid) { $values[$field] = [long]$parsed.Value }
            else { $missing.Add($field) }
        }

        if (-not $values.Contains('Events')) {
            return [pscustomobject]@{ Signals = @(); PropertiesNotReturned = $missing.ToArray() }
        }

        # Every derived count is drawn from the same rows and therefore cannot exceed Events.
        # Refuse an impossible service response rather than carry it into report arithmetic.
        foreach ($field in @($fields | Where-Object { $_ -ne 'Events' })) {
            if ($values.Contains($field) -and $values[$field] -gt $values['Events']) {
                $values.Remove($field)
                $missing.Add($field)
            }
        }
        if ($values.Contains('Blocking') -and $values.Contains('DlpMatches') -and
            $values['Blocking'] -gt $values['DlpMatches']) {
            $values.Remove('Blocking')
            $missing.Add('Blocking')
        }

        # No rows and zero rows look identical here, and only one of them means anything, so an
        # empty result carries no entry rather than an entry saying nothing matched.
        [pscustomobject]@{
            Signals = @(if ($values['Events'] -gt 0) { [pscustomobject]$values })
            PropertiesNotReturned = @($missing | Select-Object -Unique)
        }
    }
}

# Product identities: https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference
# These Microsoft 365 suite variants satisfy the same assessed Purview tier; Office 365,
# component-only and unverified products must not inherit a suite from an E3/E5 name fragment.
$script:PurviewLicensingProduct = @(
    [pscustomobject]@{
        SkuPartNumber = 'SPE_E3'
        SkuId = '05e9a617-0261-4cee-bb44-138d3ef5d965'
        DisplayName = 'Microsoft 365 E3'
        ProductType = 'Suite'
        Grants = @('SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'SPE_E5'
        SkuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'
        DisplayName = 'Microsoft 365 E5'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'Microsoft_365_E3_(no_Teams)'
        SkuId = 'dcf0408c-aaec-446c-afd4-43e3683943ea'
        DisplayName = 'Microsoft 365 E3 (no Teams)'
        ProductType = 'Suite'
        Grants = @('SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'Microsoft_365_E3'
        SkuId = '0c21030a-7e60-4ec7-9a0f-0042e0e0211a'
        DisplayName = 'Microsoft 365 E3 (500 seats min)_HUB'
        ProductType = 'Suite'
        Grants = @('SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'Microsoft_365_E5_(no_Teams)'
        SkuId = '18a4bd3f-0b5b-4887-b04f-61dd0ee15f5e'
        DisplayName = 'Microsoft 365 E5 (no Teams)'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'O365_w/o_Teams_Bundle_M5'
        SkuId = '3271cf8e-2be5-4a09-a549-70fd05baaa17'
        DisplayName = 'Microsoft 365 E5 EEA (no Teams)'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'Microsoft_365_E5'
        SkuId = 'db684ac5-c0e7-4f92-8284-ef9ebde75d33'
        DisplayName = 'Microsoft 365 E5 (500 seats min)_HUB'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'SPE_E5_CALLINGMINUTES'
        SkuId = 'a91fc4e0-65e5-4266-aa76-4037509c1626'
        DisplayName = 'Microsoft 365 E5 with Calling Minutes'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'SPE_E5_NOPSTNCONF'
        SkuId = 'cd2925a3-5076-4233-8931-638a8c94f773'
        DisplayName = 'Microsoft 365 E5 without Audio Conferencing'
        ProductType = 'Suite'
        Grants = @('SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'MICROSOFT_365_E7'
        SkuId = '9a18296a-025f-4e37-9ffa-30bf8d1ce775'
        DisplayName = 'Microsoft 365 E7'
        ProductType = 'Suite'
        Grants = @('MICROSOFT_365_E7', 'SPE_E5', 'SPE_E3')
    }
    [pscustomobject]@{
        SkuPartNumber = 'INFORMATION_PROTECTION_COMPLIANCE'
        SkuId = '184efa21-98c3-4e5d-95ab-d07053a96e67'
        DisplayName = 'Microsoft 365 E5 Compliance'
        ProductType = 'Add-on'
        Grants = @('INFORMATION_PROTECTION_COMPLIANCE', 'CAPABILITY_PURVIEW_E5_COMPLIANCE')
    }
    [pscustomobject]@{
        SkuPartNumber = 'Microsoft_365_Copilot'
        SkuId = '639dec6b-bb19-468b-871c-c5c441c4b0cb'
        DisplayName = 'Microsoft 365 Copilot'
        ProductType = 'Add-on'
        Grants = @('Microsoft_365_Copilot')
    }
    [pscustomobject]@{
        SkuPartNumber = '10_ALR_ADDON'
        SkuId = 'c2e41e49-e2a2-4c55-832a-cf13ffba1d6a'
        DisplayName = 'Microsoft Purview Audit 10-year retention add-on'
        ProductType = 'Add-on'
        Grants = @('10_ALR_ADDON', 'CAPABILITY_AUDIT_10_YEAR_RETENTION')
    }
)

function Get-PurviewLicensingProductRegistry {
    <# .SYNOPSIS Returns the exact Microsoft Graph product identities this version can classify. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @($script:PurviewLicensingProduct)
}

function Get-PurviewGrantDisplayName {
    <#
    .SYNOPSIS
        Names a licensing grant token as the product a customer would recognise.

    .DESCRIPTION
        A grant token is an internal identifier, so it is resolved against the same verified
        registry the classification uses. An identity match wins because the lower suite tokens are
        also granted by the higher suites that include them. Anything unrecognised or ambiguous is
        returned unchanged rather than renamed into a product the evidence does not establish.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Grant)

    $token = ([string]$Grant).Trim()
    if (-not $token) { return '' }

    $registry = @(Get-PurviewLicensingProductRegistry)

    $identity = @($registry | Where-Object { [string]$_.SkuPartNumber -ieq $token })
    if ($identity.Count -eq 1) { return [string]$identity[0].DisplayName }

    $granting = @($registry | Where-Object {
            @($_.Grants | Where-Object { [string]$_ -ieq $token }).Count -gt 0
        })
    if ($granting.Count -eq 1) { return [string]$granting[0].DisplayName }

    return $token
}

function Join-PurviewPhrase {
    <# .SYNOPSIS Joins names as prose, because a comma-spliced list hides whether it means any or all. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Item,
        [ValidateSet('and', 'or')][string]$Conjunction = 'and'
    )

    $values = @($Item | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($values.Count -eq 0) { return '' }
    if ($values.Count -eq 1) { return [string]$values[0] }

    return '{0} {1} {2}' -f (($values[0..($values.Count - 2)]) -join ', '), $Conjunction, $values[-1]
}

function Format-PurviewGrantList {
    <# .SYNOPSIS Lists the products that would unlock a capability, without repeating one. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Grant,
        # Any one of them unlocks the capability, so these are alternatives rather than a set.
        [ValidateSet('and', 'or')][string]$Conjunction = 'or'
    )

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Grant) {
        # One product answers to both its part number and its capability token, so it can arrive twice.
        $name = Get-PurviewGrantDisplayName -Grant ([string]$item)
        if ($name -and -not $names.Contains($name)) { $names.Add($name) }
    }

    return Join-PurviewPhrase -Item $names.ToArray() -Conjunction $Conjunction
}

function Get-PurviewSkuEvidence {
    <# .SYNOPSIS Classifies one SKU only when its part number and GUID form a verified pair. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Sku)

    $rawPart = Get-PurviewProperty -InputObject $Sku -Name 'skuPartNumber'
    $rawId = Get-PurviewProperty -InputObject $Sku -Name 'skuId'
    $rawStatus = Get-PurviewProperty -InputObject $Sku -Name 'capabilityStatus'
    $part = if ($rawPart -is [string]) { [string]$rawPart } else { '' }
    $partValid = $rawPart -is [string] -and -not [string]::IsNullOrWhiteSpace($part) -and
        $part -ceq $part.Trim()

    $id = ''
    $idValid = $false
    $parsedId = [guid]::Empty
    if ($rawId -is [guid]) {
        $id = ([guid]$rawId).ToString('D')
        $idValid = $true
    }
    elseif ($rawId -is [string] -and [string]$rawId -ceq ([string]$rawId).Trim() -and
        [guid]::TryParse([string]$rawId, [ref]$parsedId)) {
        $id = $parsedId.ToString('D')
        $idValid = $true
    }

    $status = if ($rawStatus -is [string]) { [string]$rawStatus } else { '' }
    $statusPresent = (Test-PurviewProperty -InputObject $Sku -Name 'capabilityStatus') -and
        $rawStatus -is [string] -and $status -ceq $status.Trim() -and
        -not [string]::IsNullOrWhiteSpace($status)
    $statusKnown = $statusPresent -and
        @('Enabled', 'Warning', 'Suspended', 'Deleted', 'LockedOut') -ccontains $status

    $partMatch = @()
    $idMatch = @()
    if ($partValid) {
        $partMatch = @($script:PurviewLicensingProduct | Where-Object {
                [string]$_.SkuPartNumber -ceq $part
            })
    }
    if ($idValid) {
        $idMatch = @($script:PurviewLicensingProduct | Where-Object {
                [string]$_.SkuId -ieq $id
            })
    }

    $classification = 'Unclassified'
    $product = $null
    if (-not $partValid -or -not $idValid) {
        $classification = 'Malformed'
    }
    elseif ($partMatch.Count -eq 1 -and $idMatch.Count -eq 1 -and
        [string]$partMatch[0].SkuPartNumber -ceq [string]$idMatch[0].SkuPartNumber) {
        $classification = 'Recognized'
        $product = $partMatch[0]
    }
    elseif ($partMatch.Count -gt 0 -or $idMatch.Count -gt 0) {
        $classification = 'Conflict'
    }

    $related = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in @($partMatch) + @($idMatch)) {
        $null = $related.Add([string]$candidate.SkuPartNumber)
    }

    $enabledSeats = ConvertTo-PurviewNonNegativeInteger -InputObject (
        Get-PurviewProperty -InputObject $Sku -Name 'prepaidUnitsEnabled')
    $consumedSeats = ConvertTo-PurviewNonNegativeInteger -InputObject (
        Get-PurviewProperty -InputObject $Sku -Name 'consumedUnits')

    return [pscustomobject]@{
        Input = $Sku
        Classification = $classification
        Product = $product
        RelatedProduct = @($related)
        PartNumber = $part
        SkuId = $id
        CapabilityStatus = $status
        StatusPresent = $statusPresent
        StatusKnown = $statusKnown
        Enabled = $statusKnown -and $status -ceq 'Enabled'
        SeatCountsKnown = $enabledSeats.Valid -and $consumedSeats.Valid
        EnabledSeats = if ($enabledSeats.Valid) { [long]$enabledSeats.Value } else { $null }
        ConsumedSeats = if ($consumedSeats.Valid) { [long]$consumedSeats.Value } else { $null }
    }
}

function Resolve-PurviewSkuEvidence {
    <# .SYNOPSIS Resolves exact products, grants and conflicts across a subscribed-SKU list. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Sku)

    $entries = [System.Collections.Generic.List[object]]::new()
    $productStatus = @{}
    $productConflict = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in $Sku) {
        $entry = Get-PurviewSkuEvidence -Sku $item
        $entries.Add($entry)

        if ($entry.Classification -eq 'Conflict') {
            foreach ($key in @($entry.RelatedProduct)) { $null = $productConflict.Add([string]$key) }
            continue
        }
        if ($entry.Classification -ne 'Recognized') { continue }

        $key = [string]$entry.Product.SkuPartNumber
        if (-not $productStatus.ContainsKey($key)) {
            $productStatus[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        }
        $signature = if ($entry.StatusPresent) { [string]$entry.CapabilityStatus } else { '<missing>' }
        $null = $productStatus[$key].Add($signature)
    }

    foreach ($key in @($productStatus.Keys)) {
        if ($productStatus[$key].Count -gt 1) { $null = $productConflict.Add([string]$key) }
    }

    $enabledGrants = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $potentialGrants = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $knownGrants = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($registered in $script:PurviewLicensingProduct) {
        foreach ($grant in @($registered.Grants)) { $null = $knownGrants.Add([string]$grant) }
    }

    foreach ($entry in $entries) {
        if ($entry.Classification -ne 'Recognized') { continue }
        $key = [string]$entry.Product.SkuPartNumber
        foreach ($grant in @($entry.Product.Grants)) {
            $null = $potentialGrants.Add([string]$grant)
            if ($entry.Enabled -and -not $productConflict.Contains($key)) {
                $null = $enabledGrants.Add([string]$grant)
            }
        }
    }

    $unclassifiedCount = @($entries | Where-Object { $_.Classification -eq 'Unclassified' }).Count
    $malformedCount = @($entries | Where-Object { $_.Classification -eq 'Malformed' }).Count
    $conflictCount = @($entries | Where-Object { $_.Classification -eq 'Conflict' }).Count
    $unknownStatusCount = @($entries | Where-Object {
            $_.Classification -eq 'Recognized' -and -not $_.StatusKnown
        }).Count

    return [pscustomobject]@{
        Entries = $entries.ToArray()
        EnabledGrants = @($enabledGrants | Sort-Object)
        PotentialGrants = @($potentialGrants | Sort-Object)
        KnownGrants = @($knownGrants | Sort-Object)
        ProductConflicts = @($productConflict | Sort-Object)
        UnclassifiedCount = $unclassifiedCount
        MalformedCount = $malformedCount
        ConflictCount = $conflictCount
        UnknownStatusCount = $unknownStatusCount
        Classifiable = $unclassifiedCount -eq 0 -and $malformedCount -eq 0 -and
            $conflictCount -eq 0 -and $unknownStatusCount -eq 0 -and $productConflict.Count -eq 0
    }
}

function Resolve-PurviewLicensingEvidence {
    <# .SYNOPSIS Resolves collection completeness separately from product entitlement. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Licensing)

    $collectedValue = Get-PurviewProperty -InputObject $Licensing -Name 'collected'
    $completeValue = Get-PurviewProperty -InputObject $Licensing -Name 'complete'
    $conflictedValue = Get-PurviewProperty -InputObject $Licensing -Name 'conflicted'
    $collected = $collectedValue -is [bool] -and [bool]$collectedValue
    $complete = $completeValue -is [bool] -and [bool]$completeValue
    $blockConflict = $conflictedValue -is [bool] -and [bool]$conflictedValue

    $hasList = Test-PurviewProperty -InputObject $Licensing -Name 'subscribedSkus'
    $rawList = $null
    if ($hasList) {
        if ($Licensing -is [System.Collections.IDictionary]) { $rawList = $Licensing['subscribedSkus'] }
        else { $rawList = $Licensing.PSObject.Properties['subscribedSkus'].Value }
    }
    $listReadable = $hasList -and $null -ne $rawList
    $skus = @(if ($listReadable) { @($rawList) })
    $resolved = Resolve-PurviewSkuEvidence -Sku $skus

    return [pscustomobject]@{
        Collected = $collected
        Complete = $complete
        ListReadable = $listReadable
        BlockConflict = $blockConflict
        Skus = $skus
        Entries = @($resolved.Entries)
        EnabledGrants = @($resolved.EnabledGrants)
        PotentialGrants = @($resolved.PotentialGrants)
        KnownGrants = @($resolved.KnownGrants)
        ProductConflicts = @($resolved.ProductConflicts)
        UnclassifiedCount = $resolved.UnclassifiedCount
        MalformedCount = $resolved.MalformedCount
        ConflictCount = $resolved.ConflictCount
        UnknownStatusCount = $resolved.UnknownStatusCount
        CanProveExclusion = $collected -and $complete -and $listReadable -and
            -not $blockConflict -and $resolved.Classifiable
    }
}

function Get-PurviewLicensingPayloadSignature {
    <# .SYNOPSIS Canonicalizes identity and availability when duplicate collectors are compared. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Sku)

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Sku) {
        $isRecord = $null -ne $item -and (
            (Test-PurviewProperty -InputObject $item -Name 'skuPartNumber') -or
            (Test-PurviewProperty -InputObject $item -Name 'skuId') -or
            (Test-PurviewProperty -InputObject $item -Name 'capabilityStatus'))
        if ($isRecord) {
            $rows.Add([pscustomobject]@{
                    Part = [string](Get-PurviewProperty -InputObject $item -Name 'skuPartNumber')
                    Id = [string](Get-PurviewProperty -InputObject $item -Name 'skuId')
                    Status = [string](Get-PurviewProperty -InputObject $item -Name 'capabilityStatus')
                    Shape = 'record'
                })
        }
        else {
            $rows.Add([pscustomobject]@{
                    Part = ''; Id = ''; Status = ''
                    Shape = if ($null -eq $item) { '<null>' } else { [string]$item }
                })
        }
    }

    $ordered = @($rows | Sort-Object Part, Id, Status, Shape)
    return ([pscustomobject]@{ Rows = $ordered } | ConvertTo-Json -Depth 5 -Compress)
}

function Get-PurviewLicensingData {
    <# .SYNOPSIS Collects subscribed SKUs. Least-privilege permission: LicenseAssignment.Read.All. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'Licensing' -SolutionArea 'Licensing' `
        -Interface 'GET /subscribedSkus' -Kind 'MicrosoftGraph' `
        -DocumentationUrl $script:DocUrl.GraphSubscribedSku `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -ConnectWith 'Connect-MgGraph -Scopes LicenseAssignment.Read.All' -Collect {
        $notReturned = [System.Collections.Generic.List[string]]::new()
        $skus = @(Invoke-PurviewGraphGet -Uri '/v1.0/subscribedSkus' | ForEach-Object {
                $plans = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'servicePlans') |
                    ForEach-Object {
                        # Legacy snapshots can carry names alone; never discard those names.
                        $name = if ($_ -is [string]) { [string]$_ }
                        else { [string](Get-PurviewProperty -InputObject $_ -Name 'servicePlanName') }
                        $id = [string](Get-PurviewProperty -InputObject $_ -Name 'servicePlanId')
                        $status = [string](Get-PurviewProperty -InputObject $_ -Name 'provisioningStatus')
                        [pscustomobject]@{ servicePlanName = $name; servicePlanId = $id; provisioningStatus = $status }
                    })
                $units = Get-PurviewProperty -InputObject $_ -Name 'prepaidUnits'
                $capabilityStatus = [string](Get-PurviewProperty -InputObject $_ -Name 'capabilityStatus')
                $partNumber = Get-PurviewProperty -InputObject $_ -Name 'skuPartNumber'
                $skuId = Get-PurviewProperty -InputObject $_ -Name 'skuId'
                if ($partNumber -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$partNumber)) {
                    $notReturned.Add('skuPartNumber')
                }
                if ($null -eq $skuId -or [string]::IsNullOrWhiteSpace([string]$skuId)) {
                    $notReturned.Add('skuId')
                }
                if (-not (Test-PurviewProperty -InputObject $_ -Name 'capabilityStatus') -or
                    [string]::IsNullOrWhiteSpace($capabilityStatus)) {
                    $notReturned.Add('capabilityStatus')
                }

                $record = [ordered]@{
                    skuPartNumber = [string]$partNumber
                    skuId = [string]$skuId
                    capabilityStatus = $capabilityStatus
                    servicePlans = $plans
                }

                foreach ($field in @(
                        @{ Name = 'prepaidUnitsEnabled'; Raw = Get-PurviewProperty -InputObject $units -Name 'enabled' }
                        @{ Name = 'consumedUnits'; Raw = Get-PurviewProperty -InputObject $_ -Name 'consumedUnits' }
                    )) {
                    $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject $field.Raw
                    if ($parsed.Valid) { $record[$field.Name] = [long]$parsed.Value }
                }
                [pscustomobject]$record
            })

        [pscustomobject]@{
            SubscribedSkus = $skus
            PropertiesNotReturned = @($notReturned | Select-Object -Unique)
        }
    }
}

function Get-PurviewInsightTag {
    <#
    .SYNOPSIS
        Builds Content Explorer requests from explicitly supplied sensitive information types.

    .DESCRIPTION
        The cmdlet documentation does not define which sensitivity-label identity TagName accepts,
        so collected labels are deliberately ignored. Repeated explicit names are collapsed without
        changing their spelling for the service call.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        # Retained for callers from older versions, but never read: labels are not query inputs.
        [AllowEmptyCollection()][object[]]$CollectorResult = @(),
        [AllowEmptyCollection()][string[]]$ExtraTag = @()
    )

    $tags = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $null = $CollectorResult

    foreach ($extra in @($ExtraTag | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $name = ([string]$extra).Trim()
        $key = "SensitiveInformationType`n$name"
        if ($seen.Add($key)) {
            $tags.Add([pscustomobject]@{ Name = $name; UniqueName = $name; Guid = ''; Type = 'SensitiveInformationType' })
        }
    }

    return $tags.ToArray()
}

function Test-PurviewContentExplorerRequest {
    <# .SYNOPSIS Reports whether this run explicitly requested Content Explorer SIT counts. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [switch]$SkipInsights,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Tag,
        [AllowEmptyCollection()][string[]]$SolutionArea = @()
    )

    if ($SkipInsights -or $Tag.Count -eq 0) { return $false }
    return $SolutionArea.Count -eq 0 -or $SolutionArea -contains 'ContentExplorer'
}

function Get-PurviewTenantIdentity {
    <# .SYNOPSIS Reads the connected tenant identity for the snapshot header. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()][object[]]$CollectorResult = @())

    $name = ''
    $tenant = ''

    if (Test-PurviewCommand -Name 'Get-MgContext') {
        try {
            $context = Get-MgContext -ErrorAction Stop
            $name = [string](Get-PurviewProperty -InputObject $context -Name 'Account')
            $tenant = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
        }
        catch { Write-Verbose "Tenant identity unavailable from Graph: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
    }

    # The tenant is what decides whether an earlier record describes this same tenant, so it is
    # worth asking a second service rather than recording a run that can never be compared.
    if (-not $tenant -and (Test-PurviewCommand -Name 'Get-ConnectionInformation')) {
        try {
            foreach ($connection in @(Get-ConnectionInformation -ErrorAction Stop)) {
                if (-not $name) { $name = [string](Get-PurviewProperty -InputObject $connection -Name 'UserPrincipalName') }
                $tenant = [string](Get-PurviewProperty -InputObject $connection -Name 'TenantID')
                if ($tenant) { break }
            }
        }
        catch { Write-Verbose 'No Exchange connection to take a tenant from.' }
    }

    if (-not $tenant -and $null -ne $script:AzureSession -and $script:AzureSession.Connected) {
        $tenant = $script:AzureSession.TenantId
        if (-not $name) { $name = $script:AzureSession.AccountId }
    }
    if (-not $tenant) {
        $azure = @($CollectorResult | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'SentinelPurviewIntegration' -and
                [string](Get-PurviewProperty -InputObject $_ -Name 'status') -in 'Success', 'PartialSuccess'
            })
        if ($azure.Count -eq 1) {
            $data = Get-PurviewProperty -InputObject $azure[0] -Name 'data'
            $identity = [guid]::Empty
            if ([guid]::TryParse([string](Get-PurviewProperty -InputObject $data -Name 'TenantId'), [ref]$identity) -and
                $identity -ne [guid]::Empty) {
                $tenant = $identity.ToString('D')
                if (-not $name) { $name = [string](Get-PurviewProperty -InputObject $data -Name 'AccountId') }
            }
        }
    }
    if (-not $name) { $name = 'Unknown' }
    return [pscustomobject]@{ displayName = $name; tenantId = $tenant; redacted = $false }
}

function Get-PurviewTenantSnapshot {
    <#
    .SYNOPSIS
        Runs every collector against sessions you have already established and returns a snapshot.

    .DESCRIPTION
        Makes no tenant configuration changes. Normally uses established sessions, but the isolated
        Graph fallback can authenticate. Partial runs retain available evidence and limitations.
        IncludeInsights gates explorer and oversharing reads, not all historical telemetry.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$IncludeSites,
        [int]$SiteLimit = 200,
        [switch]$RedactTenant,
        [switch]$IncludeInsights,
        [int]$InsightDays = 30,
        [AllowEmptyCollection()][string[]]$InsightTag = @(),
        [AllowEmptyCollection()][string[]]$SolutionArea = @()
    )

    $wanted = @($SolutionArea)
    $inScope = { param($area) $wanted.Count -eq 0 -or $wanted -contains $area }

    $results = [System.Collections.Generic.List[object]]::new()
    $definitions = @(Get-PurviewSccCollectorDefinition | Where-Object { & $inScope $_.Area })

    $extras = @(
        @{ Name = 'TenantPolicyConfig'; Area = 'DataLossPrevention'; Call = { Get-PurviewTenantPolicyConfigData } }
        @{ Name = 'OcrConfiguration'; Area = 'Classification'; Call = { Get-PurviewOcrConfigurationData } }
        @{ Name = 'LegacyRetention'; Area = 'DataLifecycleManagement'; Call = { Get-PurviewLegacyRetentionData } }
        @{ Name = 'AuditIngestion'; Area = 'Audit'; Call = { Get-PurviewAuditIngestionData } }
        @{ Name = 'SharePointLabelingReadiness'; Area = 'SensitivityLabels'; Call = { Get-PurviewSharePointReadinessData } }
        @{ Name = 'ContainerLabel'; Area = 'SensitivityLabels'; Call = { Get-PurviewContainerLabelData } }
        @{ Name = 'EndpointDeviceHealth'; Area = 'EndpointDlp'; Call = { Get-PurviewEndpointDeviceHealthData } }
        @{ Name = 'InsiderRiskSharing'; Area = 'InsiderRisk'; Call = { Get-PurviewInsiderRiskSharingData } }
        @{ Name = 'CloudAppConnector'; Area = 'PostureValidation'; Call = { Get-PurviewCloudAppConnectorData } }
        @{ Name = 'DataSecurityTelemetry'; Area = 'PostureValidation'; Call = { Get-PurviewDataSecurityTelemetryData } }
        @{ Name = 'ProtectedFilesConsent'; Area = 'PostureValidation'; Call = { Get-PurviewProtectedFilesConsentData } }
        @{ Name = 'SentinelPurviewIntegration'; Area = 'PostureValidation'; Call = { Get-PurviewSentinelIntegrationData -LookbackDays $LookbackDays } }
        @{ Name = 'DataAccessGovernance'; Area = 'Oversharing'; Insight = $true; Call = { Get-PurviewDataAccessGovernanceData } }
        @{ Name = 'Licensing'; Area = 'Licensing'; First = $true; Call = { Get-PurviewLicensingData } }
    ) | Where-Object {
        (& $inScope $_.Area) -and ($IncludeInsights -or -not $_.ContainsKey('Insight'))
    }
    $extras = @($extras)

    # Read subscriptions first as advisory context. A missing cmdlet does not establish its cause,
    # and subscription evidence does not suppress configuration checks.
    $licensingFirst = @($extras | Where-Object { $_.ContainsKey('First') })
    $extras = @($extras | Where-Object { -not $_.ContainsKey('First') })

    $coverageTags = @(Get-PurviewInsightTag -ExtraTag $InsightTag)
    $wantActivity = $IncludeInsights -and (& $inScope 'ActivityExplorer')
    $wantCoverage = (Test-PurviewContentExplorerRequest -SkipInsights:(-not $IncludeInsights) `
            -Tag $coverageTags -SolutionArea $wanted) -and -not $script:SkipContentExplorer
    $wantSites = $IncludeSites -and (& $inScope 'SensitivityLabels')

    $total = $definitions.Count + $extras.Count + $licensingFirst.Count
    if ($wantActivity) { $total++ }
    if ($wantCoverage) { $total++ }
    if ($wantSites) { $total++ }
    $index = 0

    # Announce each call before it starts and complete the step when it returns. Pass arguments
    # explicitly: a closure snapshots session state and prevents shared helpers from resolving.
    $run = {
        param($name, $call, $argument)
        $script:StepIndex++
        Write-PurviewStep -Name $name -Position ("[{0}/{1}]" -f $script:StepIndex, $script:StepTotal)
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $outcome = & $call $argument
        $clock.Stop()
        Write-PurviewStepResult -Status ([string](Get-PurviewProperty -InputObject $outcome -Name 'status')) -Seconds $clock.Elapsed.TotalSeconds
        $outcome
    }

    $script:StepIndex = $index
    $script:StepTotal = $total

    # Stays null when licensing was not collected, which keeps the conservative permission wording.
    $licensingBlock = $null
    foreach ($extra in $licensingFirst) {
        $licensingResult = & $run $extra.Name $extra.Call $null
        $results.Add($licensingResult)
        $licensingBlock = Get-PurviewLicensingBlock -CollectorResult @($licensingResult)
    }

    foreach ($definition in $definitions) {
        $context = [pscustomobject]@{ Definition = $definition; LicensingBlock = $licensingBlock }
        $results.Add((& $run $definition.Collector {
                    param($c)
                    Get-PurviewSccData -Definition $c.Definition -LicensingBlock $c.LicensingBlock
                } $context))
    }

    foreach ($extra in $extras) {
        $results.Add((& $run $extra.Name $extra.Call $null))
    }

    if ($wantActivity) {
        $results.Add((& $run 'ProtectionActivity' { param($d) Get-PurviewProtectionActivityData -Days $d } $InsightDays))
    }

    if ($wantCoverage) {
        $results.Add((& $run 'ClassificationCoverage' { param($t) Get-PurviewClassificationCoverageData -Tag $t } $coverageTags))
    }

    if ($wantSites) {
        $results.Add((& $run 'SharePointSite' { param($l) Get-PurviewSharePointSiteData -Limit $l } $SiteLimit))
    }

    $tenant = if ($RedactTenant) {
        [pscustomobject]@{ displayName = 'Redacted'; tenantId = ''; redacted = $true }
    }
    else {
        Get-PurviewTenantIdentity -CollectorResult $results.ToArray()
    }

    $zone = Get-PurviewTimeZoneContext

    return [pscustomobject]@{
        snapshotVersion = '1.0'
        toolVersion = $script:ToolVersion
        capturedAt = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)
        captureTimeZone = [pscustomobject]@{ id = $zone.Id; offsetAtCapture = $zone.CurrentOffset }
        mode = 'LiveTenant'
        tenant = $tenant
        licensing = Get-PurviewLicensingBlock -CollectorResult $results.ToArray()
        collectorResults = $results.ToArray()
    }
}

function Get-PurviewLicensingBlock {
    <# .SYNOPSIS Lifts collected SKUs to the snapshot header, where rules look for them. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CollectorResult)

    $licensing = @($CollectorResult | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'Licensing'
        })
    if ($licensing.Count -eq 0) {
        return [pscustomobject]@{
            collected = $false
            complete = $false
            conflicted = $false
            subscribedSkus = @()
            issues = @('No licensing collector result was recorded.')
        }
    }

    $payloads = [System.Collections.Generic.List[object]]::new()
    $issues = [System.Collections.Generic.List[string]]::new()
    $collected = $false
    $allComplete = $true

    foreach ($result in $licensing) {
        $status = [string](Get-PurviewProperty -InputObject $result -Name 'status')
        if ($status -in 'Success', 'PartialSuccess') { $collected = $true }
        if ($status -ne 'Success') {
            $allComplete = $false
            $issues.Add("A licensing collector returned $status.")
        }
        if ($status -notin 'Success', 'PartialSuccess') { continue }

        if (-not (Test-PurviewProperty -InputObject $result -Name 'data')) {
            $allComplete = $false
            $issues.Add('A readable licensing result omitted its data object.')
            continue
        }
        $data = Get-PurviewProperty -InputObject $result -Name 'data'
        if ($null -eq $data -or -not (Test-PurviewProperty -InputObject $data -Name 'SubscribedSkus')) {
            $allComplete = $false
            $issues.Add('A readable licensing result omitted its subscribed SKU list.')
            continue
        }

        $rawList = $null
        if ($data -is [System.Collections.IDictionary]) {
            $rawList = $data['SubscribedSkus']
        }
        else {
            $rawList = $data.PSObject.Properties['SubscribedSkus'].Value
        }
        if ($null -eq $rawList) {
            $allComplete = $false
            $issues.Add('A readable licensing result returned a null subscribed SKU list.')
            continue
        }

        $items = @($rawList)
        $payloads.Add([pscustomobject]@{
                Items = $items
                Signature = Get-PurviewLicensingPayloadSignature -Sku $items
            })
    }

    $signatures = @($payloads | ForEach-Object { $_.Signature } | Select-Object -Unique)
    $conflicted = $signatures.Count -gt 1
    if ($conflicted) {
        $allComplete = $false
        $issues.Add('Duplicate licensing collector results disagreed on product identity or availability.')
    }

    $skus = @()
    if ($payloads.Count -gt 0) {
        if ($conflicted) { $skus = @($payloads | ForEach-Object { @($_.Items) }) }
        else { $skus = @($payloads[0].Items) }
    }

    return [pscustomobject]@{
        collected = $collected
        complete = $collected -and $allComplete -and $payloads.Count -gt 0
        conflicted = $conflicted
        subscribedSkus = $skus
        issues = @($issues | Select-Object -Unique)
    }
}

#endregion

#region Rules engine
# Deterministic and side-effect free. Reads the snapshot only, never a tenant, and never evaluates
# rule content as code.

function Test-PurviewPredicate {
    <# .SYNOPSIS Applies one declarative comparison to one object. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][object]$Predicate
    )

    $negateValue = Get-PurviewProperty -InputObject $Predicate -Name 'negate'
    if ((Test-PurviewProperty -InputObject $Predicate -Name 'negate') -and $negateValue -isnot [bool]) {
        throw 'Predicate negate must be a Boolean.'
    }
    $negate = $negateValue -is [bool] -and [bool]$negateValue

    # Compound predicates keep rules declarative while allowing a claim such as "enabled,
    # enforcing, classic retention with a rule" to require every piece of that evidence.
    if (Test-PurviewProperty -InputObject $Predicate -Name 'all') {
        $parts = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Predicate -Name 'all'))
        if ($parts.Count -eq 0) { throw 'A compound predicate must contain at least one condition.' }
        $result = @($parts | Where-Object {
                -not (Test-PurviewPredicate -InputObject $InputObject -Predicate $_)
            }).Count -eq 0
        if ($negate) { return (-not $result) }
        return [bool]$result
    }

    $field = Get-PurviewProperty -InputObject $Predicate -Name 'field'
    $operator = Get-PurviewProperty -InputObject $Predicate -Name 'operator'
    $expected = Get-PurviewProperty -InputObject $Predicate -Name 'value'

    $present = Test-PurviewProperty -InputObject $InputObject -Name $field
    $actual = Get-PurviewProperty -InputObject $InputObject -Name $field

    $result = & {
        switch ($operator) {
            'exists' { return $present }
            'isNullOrEmpty' { return (-not $present) -or $null -eq $actual -or ('' -eq [string]$actual) }
            'isNotNullOrEmpty' { return $present -and $null -ne $actual -and -not [string]::IsNullOrWhiteSpace([string]$actual) }
        }

        # An absent property cannot satisfy a value comparison; saying so beats inventing a default.
        if (-not $present) { return $false }

        switch ($operator) {
            'eq' { return $actual -eq $expected }
            'ne' { return $actual -ne $expected }
            'gt' { return $actual -gt $expected }
            'lt' { return $actual -lt $expected }
            'ge' { return $actual -ge $expected }
            'le' { return $actual -le $expected }
            'contains' { return ([string]$actual).Contains([string]$expected, [StringComparison]::OrdinalIgnoreCase) }
            'notContains' { return -not ([string]$actual).Contains([string]$expected, [StringComparison]::OrdinalIgnoreCase) }
            'startsWith' { return ([string]$actual).StartsWith([string]$expected, [StringComparison]::OrdinalIgnoreCase) }
            default { throw "Unsupported predicate operator '$operator'." }
        }
    }

    # Negate the comparison, not the operator, to retain records whose field is missing.
    # Dropping them would misrepresent missing evidence as an empty tenant.
    if ($negate) { return (-not $result) }
    return [bool]$result
}

function Format-PurviewPredicate {
    <# .SYNOPSIS Describes a predicate in words, so a finding can be checked against the facts. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$Predicate)

    if ($null -eq $Predicate) { return 'the condition' }

    if (Test-PurviewProperty -InputObject $Predicate -Name 'all') {
        $parts = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Predicate -Name 'all') |
            ForEach-Object { Format-PurviewPredicate -Predicate $_ })
        return ($parts -join ' and ')
    }

    $field = [string](Get-PurviewProperty -InputObject $Predicate -Name 'field')
    $operator = [string](Get-PurviewProperty -InputObject $Predicate -Name 'operator')
    $value = Get-PurviewProperty -InputObject $Predicate -Name 'value'

    $words = @{
        eq = 'is'; ne = 'is not'; gt = 'is greater than'; lt = 'is less than'
        ge = 'is at least'; le = 'is at most'; contains = 'contains'; notContains = 'does not contain'
        startsWith = 'starts with'; exists = 'is present'; isNullOrEmpty = 'is empty'
        isNotNullOrEmpty = 'is present and not empty'
    }
    $phrase = if ($words.ContainsKey($operator)) { $words[$operator] } else { $operator }

    if ($operator -in 'exists', 'isNullOrEmpty', 'isNotNullOrEmpty') { return "$field $phrase" }
    return "$field $phrase $value"
}

function Get-PurviewPredicateField {
    <# .SYNOPSIS Lists every property a scalar or compound predicate reads. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Predicate)

    if ($null -eq $Predicate) { return @() }

    $fields = [System.Collections.Generic.List[string]]::new()
    if (Test-PurviewProperty -InputObject $Predicate -Name 'all') {
        foreach ($part in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Predicate -Name 'all'))) {
            foreach ($field in @(Get-PurviewPredicateField -Predicate $part)) { $fields.Add($field) }
        }
    }
    else {
        $field = [string](Get-PurviewProperty -InputObject $Predicate -Name 'field')
        if (-not [string]::IsNullOrWhiteSpace($field)) { $fields.Add($field) }
    }

    return @($fields | Select-Object -Unique)
}

function Get-PurviewConditionField {
    <# .SYNOPSIS Lists the property names a condition depends on. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Condition)

    $fields = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Condition) { return $fields.ToArray() }

    $where = Get-PurviewProperty -InputObject $Condition -Name 'where'
    $assert = Get-PurviewProperty -InputObject $Condition -Name 'assert'

    foreach ($field in @(Get-PurviewPredicateField -Predicate $where)) { $fields.Add($field) }
    foreach ($field in @(Get-PurviewPredicateField -Predicate (Get-PurviewProperty -InputObject $assert -Name 'where'))) { $fields.Add($field) }
    foreach ($name in 'field', 'within') {
        $field = [string](Get-PurviewProperty -InputObject $assert -Name $name)
        if (-not [string]::IsNullOrWhiteSpace($field)) { $fields.Add($field) }
    }

    return @($fields | Select-Object -Unique)
}

function Get-PurviewItemLabel {
    <# .SYNOPSIS Names one collected item well enough for a reader to go and find it. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    foreach ($candidate in 'Name', 'DisplayName', 'Title', 'Tag', 'Url', 'Identity', 'Guid') {
        $value = [string](Get-PurviewProperty -InputObject $InputObject -Name $candidate)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }

    return 'an unnamed item'
}

function Format-PurviewCount {
    <# .SYNOPSIS Pairs a count with its noun, so a report never reads "1 label(s)". #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][long]$Count,
        [Parameter(Mandatory)][string]$Singular,
        [string]$Plural = ''
    )

    if ($Count -eq 1) { return "$Count $Singular" }
    if ($Plural) { return "$Count $Plural" }
    return "$Count ${Singular}s"
}

function Format-PurviewChangeKind {
    <# .SYNOPSIS Names a change the way the paragraph above it does, so no internal token is shown. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Change,
        [switch]$CrossTenant
    )

    # Against another tenant there is no before and after, so visibility is a matter of which side
    # could be read rather than something gained or lost.
    if ($CrossTenant) {
        switch ($Change) {
            'NewlyAssessed' { return 'Assessed here only' }
            'CouldNotAssess' { return 'Assessed there only' }
        }
    }

    switch ($Change) {
        'NewlyAssessed' { 'Newly assessed' }
        'CouldNotAssess' { 'Could not assess this run' }
        'RuleChanged' { 'Rule changed' }
        default { $Change }
    }
}

function Format-PurviewItemList {
    <# .SYNOPSIS Lists offending items by name, capped to keep large results readable. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Item,
        [int]$Limit = 10
    )

    $names = @($Item | ForEach-Object { Get-PurviewItemLabel -InputObject $_ })
    if ($names.Count -le $Limit) { return $names }

    return @($names | Select-Object -First $Limit) + @("and $($names.Count - $Limit) more")
}

function Format-PurviewPredicateFailure {
    <# .SYNOPSIS Identifies each failing item and the value that failed the check. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Item,
        [Parameter(Mandatory)][AllowNull()][object]$Predicate,
        [int]$Limit = 10
    )

    $field = [string](Get-PurviewProperty -InputObject $Predicate -Name 'field')
    $lines = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in @($Item | Select-Object -First $Limit)) {
        $label = Get-PurviewItemLabel -InputObject $entry

        # A setting carries its own recommended value, which reads far better than the name of the
        # field the rule happened to test.
        if ((Test-PurviewProperty -InputObject $entry -Name 'Value') -and (Test-PurviewProperty -InputObject $entry -Name 'Expected')) {
            $actualValue = Get-PurviewProperty -InputObject $entry -Name 'Value'
            $wantedValue = Get-PurviewProperty -InputObject $entry -Name 'Expected'
            $lines.Add("$label is reported as $actualValue. The report reference value is $wantedValue")
            continue
        }

        $actual = Get-PurviewProperty -InputObject $entry -Name $field
        $shown = if ($null -eq $actual -or '' -eq [string]$actual) { 'not set' } else { "'$actual'" }

        # A derived single-object check has no name, so the value alone is the useful part.
        if ($label -eq 'an unnamed item') { $lines.Add("$field is $shown") }
        else { $lines.Add("$label - $field is $shown") }
    }

    if (@($Item).Count -gt $Limit) { $lines.Add("and $(@($Item).Count - $Limit) more") }
    return $lines.ToArray()
}

function Test-PurviewAssertion {
    <# .SYNOPSIS Applies a rule's assertion to the filtered set, returning the outcome, why, and what. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][object]$Assertion
    )

    $type = Get-PurviewProperty -InputObject $Assertion -Name 'type'
    $value = Get-PurviewProperty -InputObject $Assertion -Name 'value'
    $field = Get-PurviewProperty -InputObject $Assertion -Name 'field'
    $where = Get-PurviewProperty -InputObject $Assertion -Name 'where'
    $count = $Items.Count
    # Optional nouns make a finding self-contained. External rules written before these fields
    # keep their exact legacy wording, and neither noun participates in the assertion itself.
    $itemSingular = [string](Get-PurviewProperty -InputObject $Assertion -Name 'itemSingular')
    $itemPlural = [string](Get-PurviewProperty -InputObject $Assertion -Name 'itemPlural')
    $namedItems = -not [string]::IsNullOrWhiteSpace($itemSingular) -and
        -not [string]::IsNullOrWhiteSpace($itemPlural)
    $countedItems = if ($namedItems) {
        Format-PurviewCount -Count $count -Singular $itemSingular -Plural $itemPlural
    }
    else { [string]$count }

    switch ($type) {
        'countEquals' {
            return [pscustomobject]@{
                Passed = ($count -eq $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($namedItems) { "$countedItems found; exactly $value was expected." }
                else { "$count found, where exactly $value was expected." }
            }
        }
        'countGreaterThan' {
            return [pscustomobject]@{
                Passed = ($count -gt $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($namedItems) { "$countedItems found; more than $value was expected." }
                else { "$count found, where more than $value was expected." }
            }
        }
        'countLessThan' {
            return [pscustomobject]@{
                Passed = ($count -lt $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($namedItems) { "$countedItems found; fewer than $value was expected." }
                else { "$count found, where fewer than $value was expected." }
            }
        }
        'isEmpty' {
            return [pscustomobject]@{
                Passed = ($count -eq 0); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($namedItems) {
                    if ($count -eq 0) { "No $itemPlural were found, as expected." }
                    else { "$countedItems found; none was expected." }
                }
                elseif ($count -eq 0) { 'None found, as expected.' }
                else { "$count found, where none was expected." }
            }
        }
        'isNotEmpty' {
            return [pscustomobject]@{
                Passed = ($count -gt 0); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($namedItems) {
                    if ($count -gt 0) { "$countedItems found." }
                    else { "No $itemPlural were found; at least one was expected." }
                }
                elseif ($count -gt 0) { "$count found." }
                else { 'None found, where at least one was expected.' }
            }
        }

        'noDuplicatesOf' {
            # Uniqueness can be scoped to a label group: the documented default taxonomy repeats a
            # sublabel name under two tiers, and only names competing in the same picker clash.
            $within = [string](Get-PurviewProperty -InputObject $Assertion -Name 'within')
            $groups = @(if ($within) {
                    @($Items | Group-Object -Property { '{0}<>{1}' -f (Get-PurviewProperty -InputObject $_ -Name $within), (Get-PurviewProperty -InputObject $_ -Name $field) } |
                            Where-Object { $_.Count -gt 1 })
                }
                else {
                    @($Items | Group-Object -Property $field | Where-Object { $_.Count -gt 1 })
                })

            if ($groups.Count -eq 0) {
                $scope = if ($within) { " within their $([string](Get-PurviewProperty -InputObject $Assertion -Name 'withinLabel'))" } else { '' }
                return [pscustomobject]@{
                    Passed = $true; Observed = @(); Vacuous = ($count -eq 0)
                    Reason = if ($count -eq 0) { 'There is nothing here to check.' } else { "All $count have a distinct $field$scope." }
                }
            }

            $clashes = [System.Collections.Generic.List[string]]::new()
            foreach ($group in $groups) {
                $value = [string](Get-PurviewProperty -InputObject $group.Group[0] -Name $field)
                # Listing the items says nothing when the duplicated field is their own name.
                if ($field -in @('Name', 'DisplayName')) {
                    $clashes.Add("$field $value is used by $($group.Count) of them")
                }
                else {
                    $names = @(Format-PurviewItemList -Item $group.Group -Limit 6) -join ', '
                    $clashes.Add("$field $value is shared by: $names")
                }
            }
            $subject = if ($groups.Count -eq 1) { "1 $field value is" } else { "$($groups.Count) $field values are" }
            return [pscustomobject]@{
                Passed = $false; Observed = $clashes.ToArray(); Vacuous = $false
                Reason = "$subject used more than once, out of $count checked."
            }
        }

        'allHave' {
            $failing = @($Items | Where-Object { -not (Test-PurviewPredicate -InputObject $_ -Predicate $where) })
            # A rule may name what it is judging, for cases where the field it tests is an internal
            # verdict and repeating it back at the reader explains nothing.
            $subject = [string](Get-PurviewProperty -InputObject $Assertion -Name 'subject')
            $expected = if ($subject) { $subject } else { Format-PurviewPredicate -Predicate $where }
            return [pscustomobject]@{
                Passed = ($failing.Count -eq 0)
                Observed = @(Format-PurviewPredicateFailure -Item $failing -Predicate $where)
                Vacuous = ($count -eq 0)
                Reason = if ($namedItems) {
                    if ($count -eq 0) { "No $itemPlural were available to check." }
                    elseif ($failing.Count -eq 0 -and $count -eq 1) {
                        "The $itemSingular matched the expected state: $expected."
                    }
                    elseif ($failing.Count -eq 0) {
                        "All $count $itemPlural matched the expected state: $expected."
                    }
                    elseif ($count -eq 1) {
                        "The $itemSingular did not match the expected state: $expected."
                    }
                    else { "$($failing.Count) of $count $itemPlural did not match the expected state: $expected." }
                }
                elseif ($count -eq 0) { 'There is nothing here to check.' }
                elseif ($failing.Count -eq 0) { "All $count checked matched. Expected: $expected." }
                else { "$($failing.Count) of $count checked did not match. Expected: $expected." }
            }
        }

        'anyHave' {
            $matching = @($Items | Where-Object { Test-PurviewPredicate -InputObject $_ -Predicate $where })
            $subject = [string](Get-PurviewProperty -InputObject $Assertion -Name 'subject')
            $expected = if ($subject) { $subject } else { Format-PurviewPredicate -Predicate $where }
            return [pscustomobject]@{
                Passed = ($matching.Count -gt 0)
                Observed = @(Format-PurviewItemList -Item $matching)
                Vacuous = ($count -eq 0)
                Reason = if ($namedItems) {
                    if ($count -eq 0) { "No $itemPlural were available to check." }
                    elseif ($matching.Count -gt 0) {
                        "$($matching.Count) of $count $itemPlural matched the expected state: $expected."
                    }
                    else { "None of the $count $itemPlural matched the expected state: $expected." }
                }
                elseif ($count -eq 0) { 'There is nothing here to check.' }
                elseif ($matching.Count -gt 0) { "$($matching.Count) of $count checked matched. Expected: $expected." }
                else { "None of the $count checked matched. At least one must. Expected: $expected." }
            }
        }

        'noneHave' {
            $matching = @($Items | Where-Object { Test-PurviewPredicate -InputObject $_ -Predicate $where })
            $subject = [string](Get-PurviewProperty -InputObject $Assertion -Name 'subject')
            $unwanted = if ($subject) { $subject } else { Format-PurviewPredicate -Predicate $where }
            return [pscustomobject]@{
                Passed = ($matching.Count -eq 0)
                Observed = @(Format-PurviewPredicateFailure -Item $matching -Predicate $where)
                Vacuous = ($count -eq 0)
                Reason = if ($namedItems) {
                    if ($count -eq 0) { "No $itemPlural were available to check." }
                    elseif ($matching.Count -eq 0) { "No $itemPlural matched the disallowed state: $unwanted." }
                    else { "$($matching.Count) of $count $itemPlural matched the disallowed state: $unwanted." }
                }
                elseif ($count -eq 0) { 'There is nothing here to check.' }
                elseif ($matching.Count -eq 0) { "None of the $count checked matched, as required. Condition: $unwanted." }
                else { "$($matching.Count) of $count checked matched. None should. Condition: $unwanted." }
            }
        }

        default { throw "Unsupported assertion type '$type'." }
    }
}

function Get-PurviewLicenceTier {
    <#
    .SYNOPSIS
        Returns grants from coherent products this version recognizes exactly.

    .DESCRIPTION
        Both skuPartNumber and skuId must match one registry row. Service plans, friendly names and
        substrings never identify a marketed product. IncludeUnavailable returns possible grants
        from coherent products without treating them as current entitlement.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Sku,
        [switch]$IncludeUnavailable
    )

    $resolved = Resolve-PurviewSkuEvidence -Sku $Sku
    if ($IncludeUnavailable) { return @($resolved.PotentialGrants) }
    return @($resolved.EnabledGrants)
}

function Get-PurviewLicensingState {
    <#
    .SYNOPSIS
        Returns advisory positive licensing evidence for a rule's capability.

    .DESCRIPTION
        Licensed retains the historical API's positive match; it is not a configuration gate.
        No match returns Unknown, even for a complete empty or E3-only subscription list.
        UnlockedBy retains documented requirement examples, not an exhaustive product catalog.
        Neither state suppresses configuration checks or proves user-level license assignment.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Licensing,
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot
    )

    $capability = Get-PurviewProperty -InputObject $Licensing -Name 'capability'
    if ($null -eq $Licensing -or [string]::IsNullOrWhiteSpace([string]$capability)) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $null; UnlockedBy = @() }
    }

    $block = Get-PurviewProperty -InputObject $Snapshot -Name 'licensing'
    $includedIn = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'includedIn'))
    $addOns = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'addOns'))
    $accepted = @(@($includedIn) + @($addOns) | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    if ($null -eq $block -or $accepted.Count -eq 0) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
    }

    $evidence = Resolve-PurviewLicensingEvidence -Licensing $block
    if (-not $evidence.Collected -or -not $evidence.ListReadable -or $evidence.BlockConflict) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
    }

    foreach ($grant in $accepted) {
        if (@($evidence.EnabledGrants | Where-Object { [string]$_ -ieq $grant }).Count -gt 0) {
            return [pscustomobject]@{ State = 'Licensed'; Capability = $capability; UnlockedBy = @() }
        }
    }

    return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
}

function Get-PurviewSolutionWorkload {
    <# .SYNOPSIS Names the Purview solution a rule belongs to, or empty where none grades it. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SolutionArea)

    if ($script:SolutionWorkload.Contains($SolutionArea)) { return [string]$script:SolutionWorkload[$SolutionArea] }
    return ''
}

function Get-PurviewLicenceTierLabel {
    <#
    .SYNOPSIS
        A display tier derived from the rule's licensing examples, used for sorting.

    .DESCRIPTION
        Not an exhaustive licensing catalog, a universal minimum tier or proof of user entitlement.
        Applicability and current product terms require separate review.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$Licensing)

    $accepted = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'includedIn')) +
    @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'addOns'))

    if ($accepted -contains 'SPE_E3') { return 'E3' }
    if ($accepted -contains 'SPE_E5') { return 'E5' }
    if ($accepted.Count -gt 0) { return 'Add-on' }
    return 'Any'
}

function Get-PurviewSeverityOrder {
    <# .SYNOPSIS Ranks severity, because sorting the words alphabetically puts Low above Medium. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Severity)

    switch ($Severity) {
        'Critical' { return 0 }
        'High' { return 1 }
        'Medium' { return 2 }
        'Low' { return 3 }
        default { return 9 }
    }
}

function Get-PurviewTierOrder {
    <# .SYNOPSIS Sorts tiers so a customer works from what they already own outwards. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Tier)

    switch ($Tier) {
        'Any' { return 0 }
        'E3' { return 1 }
        'E5' { return 2 }
        'Add-on' { return 3 }
        default { return 4 }
    }
}

function Get-PurviewEndpointDlpScopeSignal {
    <# .SYNOPSIS Determines whether one DLP policy includes the Devices location. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Policy)

    $positive = $false
    $negative = $false
    $unreadable = $false
    $sources = [System.Collections.Generic.List[string]]::new()

    # EndpointDlpLocation is the dedicated policy scope. A populated value names the included
    # users, or All. A present empty value excludes the location; an absent property proves nothing.
    if (Test-PurviewProperty -InputObject $Policy -Name 'EndpointDlpLocation') {
        $hasLocation = $false
        foreach ($value in @(ConvertTo-PurviewArray -InputObject (
                    Get-PurviewProperty -InputObject $Policy -Name 'EndpointDlpLocation'))) {
            if ($null -eq $value) { continue }
            if ($value -isnot [string]) { $unreadable = $true; continue }
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $hasLocation = $true
        }
        if ($hasLocation) {
            $positive = $true
            $sources.Add('EndpointDlpLocation')
        }
        else { $negative = $true }
    }

    # Older snapshots and some summary responses expose only the service workload token. Keep it
    # as a positive fallback, but never let an absent or empty Workload become evidence of absence.
    if (Test-PurviewProperty -InputObject $Policy -Name 'Workload') {
        $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($value in @(ConvertTo-PurviewArray -InputObject (
                    Get-PurviewProperty -InputObject $Policy -Name 'Workload'))) {
            if ($null -eq $value) { continue }
            if ($value -isnot [string] -and $value -isnot [System.Enum]) {
                $unreadable = $true
                continue
            }
            foreach ($token in @(([string]$value) -split '[,;]')) {
                $trimmed = $token.Trim()
                if ($trimmed) { $null = $tokens.Add($trimmed) }
            }
        }
        if ($tokens.Contains('EndpointDevices')) {
            $positive = $true
            $sources.Add('Workload')
        }
        elseif ($tokens.Count -gt 0) {
            $unknownTokens = @($tokens | Where-Object {
                    $_ -notin 'Exchange', 'SharePoint', 'OneDrive', 'OneDriveForBusiness',
                        'Teams', 'MicrosoftTeams', 'ModernGroup', 'PublicFolder', 'Skype', 'PowerBI',
                        'PowerBIDlp', 'OnPremisesScanner', 'ThirdPartyApp', 'M365Copilot', 'Applications'
                })
            if ($unknownTokens.Count -gt 0) { $unreadable = $true }
            else { $negative = $true }
        }
    }

    $state = if ($positive) { 'Included' } elseif ($unreadable) { 'Unknown' } elseif ($negative) { 'Excluded' } else { 'Unknown' }
    return [pscustomobject]@{ State = $state; Sources = $sources.ToArray() }
}

function Get-PurviewDlpPolicyRuleAnalysis {
    <#
    .SYNOPSIS
        Correlates DLP rules to exactly one parent policy and keeps their states authoritative.

    .DESCRIPTION
        Get-DlpCompliancePolicy.Mode reports configured mode, not verified enforcement.
        Get-DlpComplianceRule.Disabled reports child-rule state. A rule is linked when the intersection
        of all matching name, GUID and structured-reference tokens identifies exactly one policy.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $answer = [ordered]@{
        PolicyRead = $false
        PolicyComplete = $false
        RuleRead = $false
        RuleComplete = $false
        PolicyCount = 0
        RuleCount = 0
        PolicyIdentityGapCount = 0
        EnforcingPolicyIdentityGapCount = 0
        UnknownPolicyModeCount = 0
        EnforcingPolicyCount = 0
        MissingRuleReferenceCount = 0
        UnmatchedRuleReferenceCount = 0
        AmbiguousRuleReferenceCount = 0
        UnresolvedRuleCount = 0
        EligibleRuleCount = 0
        EnabledRuleCount = 0
        DisabledRuleCount = 0
        UnknownRuleStateCount = 0
        Policies = @()
        LinkedRules = @()
    }

    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $policyResults = @($results | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'DataLossPrevention'
        })
    $ruleResults = @($results | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'DlpRule'
        })

    $policies = @()
    if ($policyResults.Count -eq 1 -and
        [string](Get-PurviewProperty -InputObject $policyResults[0] -Name 'status') -in 'Success', 'PartialSuccess') {
        $policyData = Get-PurviewProperty -InputObject $policyResults[0] -Name 'data'
        if (Test-PurviewProperty -InputObject $policyData -Name 'Policies') {
            $answer.PolicyRead = $true
            $answer.PolicyComplete = [string](Get-PurviewProperty -InputObject $policyResults[0] -Name 'status') -eq 'Success'
            $policies = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policyData -Name 'Policies'))
        }
    }
    $answer.PolicyCount = $policies.Count

    $rules = @()
    if ($ruleResults.Count -eq 1 -and
        [string](Get-PurviewProperty -InputObject $ruleResults[0] -Name 'status') -in 'Success', 'PartialSuccess') {
        $ruleData = Get-PurviewProperty -InputObject $ruleResults[0] -Name 'data'
        if (Test-PurviewProperty -InputObject $ruleData -Name 'Rules') {
            $answer.RuleRead = $true
            $answer.RuleComplete = [string](Get-PurviewProperty -InputObject $ruleResults[0] -Name 'status') -eq 'Success'
            $rules = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $ruleData -Name 'Rules'))
        }
    }
    $answer.RuleCount = $rules.Count

    if (-not $answer.PolicyRead) { return [pscustomobject]$answer }

    $modes = [string[]]::new($policies.Count)
    $modeKnown = [bool[]]::new($policies.Count)
    $identityKnown = [bool[]]::new($policies.Count)
    $linkedCounts = [int[]]::new($policies.Count)
    $enabledCounts = [int[]]::new($policies.Count)
    $disabledCounts = [int[]]::new($policies.Count)
    $unknownStateCounts = [int[]]::new($policies.Count)
    $lookup = @{}

    for ($index = 0; $index -lt $policies.Count; $index++) {
        $policy = $policies[$index]
        $mode = ([string](Get-PurviewProperty -InputObject $policy -Name 'Mode')).Trim()
        $modes[$index] = $mode
        if ((Test-PurviewProperty -InputObject $policy -Name 'Mode') -and
            $mode -in 'Enable', 'Disable', 'TestWithNotifications', 'TestWithoutNotifications') {
            $modeKnown[$index] = $true
            if ($mode -eq 'Enable') { $answer.EnforcingPolicyCount++ }
        }
        else { $answer.UnknownPolicyModeCount++ }

        $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($field in 'Name', 'Guid') {
            foreach ($identityPart in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $policy -Name $field))) {
                if (-not [string]::IsNullOrWhiteSpace([string]$identityPart)) { $null = $tokens.Add(([string]$identityPart).Trim()) }
            }
        }
        $identityKnown[$index] = $tokens.Count -gt 0
        if ($tokens.Count -eq 0) {
            $answer.PolicyIdentityGapCount++
            if ($modeKnown[$index] -and $modes[$index] -eq 'Enable') {
                $answer.EnforcingPolicyIdentityGapCount++
            }
        }
        foreach ($token in $tokens) {
            $key = $token.ToLowerInvariant()
            if (-not $lookup.ContainsKey($key)) { $lookup[$key] = @() }
            $lookup[$key] = @($lookup[$key]) + $index
        }
    }

    $linked = [System.Collections.Generic.List[object]]::new()
    if ($answer.RuleRead) {
        foreach ($rule in $rules) {
            $references = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($field in 'PolicyName', 'Policy', 'ParentPolicyName', 'PolicyGuid') {
                if (-not (Test-PurviewProperty -InputObject $rule -Name $field)) { continue }
                foreach ($identityPart in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $rule -Name $field))) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$identityPart)) { $null = $references.Add(([string]$identityPart).Trim()) }
                }
            }

            if ($references.Count -eq 0) {
                $answer.MissingRuleReferenceCount++
                continue
            }

            $owners = $null
            $unmatchedReference = $false
            foreach ($reference in $references) {
                $key = $reference.ToLowerInvariant()
                if (-not $lookup.ContainsKey($key)) {
                    $unmatchedReference = $true
                    continue
                }
                $candidatePolicyIndexes = @($lookup[$key])
                if ($null -eq $owners) {
                    $owners = [System.Collections.Generic.HashSet[int]]::new()
                    foreach ($candidate in $candidatePolicyIndexes) { $null = $owners.Add([int]$candidate) }
                    continue
                }

                $intersection = [System.Collections.Generic.HashSet[int]]::new()
                foreach ($candidate in $owners) {
                    if ($candidatePolicyIndexes -contains $candidate) { $null = $intersection.Add([int]$candidate) }
                }
                $owners = $intersection
            }

            # Every populated identity token must agree. Accepting one matching token while a
            # second name or GUID does not match would turn conflicting evidence into a parent.
            if ($unmatchedReference -or $null -eq $owners) {
                $answer.UnmatchedRuleReferenceCount++
                continue
            }
            if ($owners.Count -ne 1) {
                $answer.AmbiguousRuleReferenceCount++
                continue
            }

            $owner = [int]@($owners)[0]
            $linkedCounts[$owner]++
            $disabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $rule -Name 'Disabled')
            $isEnforcing = $modeKnown[$owner] -and $modes[$owner] -eq 'Enable'
            if ($isEnforcing) {
                $answer.EligibleRuleCount++
                if (-not (Test-PurviewProperty -InputObject $rule -Name 'Disabled') -or -not $disabled.Valid) {
                    $unknownStateCounts[$owner]++
                    $answer.UnknownRuleStateCount++
                }
                elseif ([bool]$disabled.Value) {
                    $disabledCounts[$owner]++
                    $answer.DisabledRuleCount++
                }
                else {
                    $enabledCounts[$owner]++
                    $answer.EnabledRuleCount++
                }
            }

            $linked.Add([pscustomobject]@{
                    Rule = $rule
                    Policy = $policies[$owner]
                    PolicyIndex = $owner
                    PolicyMode = $modes[$owner]
                    PolicyModeKnown = $modeKnown[$owner]
                    IsEnforcing = $isEnforcing
                    DisabledKnown = (Test-PurviewProperty -InputObject $rule -Name 'Disabled') -and $disabled.Valid
                    Disabled = if ((Test-PurviewProperty -InputObject $rule -Name 'Disabled') -and $disabled.Valid) { [bool]$disabled.Value } else { $null }
                })
        }
    }

    $answer.UnresolvedRuleCount = $answer.MissingRuleReferenceCount +
        $answer.UnmatchedRuleReferenceCount + $answer.AmbiguousRuleReferenceCount
    $facts = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $policies.Count; $index++) {
        $facts.Add([pscustomobject]@{
                Policy = $policies[$index]
                Index = $index
                Name = Get-PurviewItemLabel -InputObject $policies[$index]
                Mode = $modes[$index]
                ModeKnown = $modeKnown[$index]
                IsEnforcing = $modeKnown[$index] -and $modes[$index] -eq 'Enable'
                IdentityKnown = $identityKnown[$index]
                LinkedRuleCount = $linkedCounts[$index]
                EnabledRuleCount = $enabledCounts[$index]
                DisabledRuleCount = $disabledCounts[$index]
                UnknownRuleStateCount = $unknownStateCounts[$index]
            })
    }

    $answer.Policies = $facts.ToArray()
    $answer.LinkedRules = $linked.ToArray()
    return [pscustomobject]$answer
}

function Get-PurviewEndpointDlpAnalysis {
    <# .SYNOPSIS Correlates Devices scope with the authoritative policy mode. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $dlp = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $answer = [ordered]@{
        PolicyRead = $dlp.PolicyRead
        PolicyComplete = $dlp.PolicyComplete
        PolicyCount = $dlp.PolicyCount
        ScopedCount = 0
        UnknownScopeCount = 0
        EnforcingScopedCount = 0
        TestingScopedCount = 0
        DisabledScopedCount = 0
        UnknownModeScopedCount = 0
        EnforcingUnknownScopeCount = 0
        UnknownModeUnknownScopeCount = 0
        Policies = @()
    }
    if (-not $dlp.PolicyRead) { return [pscustomobject]$answer }

    $facts = [System.Collections.Generic.List[object]]::new()
    foreach ($fact in @($dlp.Policies)) {
        $scope = Get-PurviewEndpointDlpScopeSignal -Policy $fact.Policy
        $entry = [pscustomobject]@{
            Policy = $fact.Policy
            Name = $fact.Name
            Mode = $fact.Mode
            ModeKnown = $fact.ModeKnown
            IsEnforcing = $fact.IsEnforcing
            Scope = $scope.State
            ScopeSources = @($scope.Sources)
        }
        $facts.Add($entry)

        if ($scope.State -eq 'Included') {
            $answer.ScopedCount++
            if (-not $fact.ModeKnown) { $answer.UnknownModeScopedCount++ }
            elseif ($fact.IsEnforcing) { $answer.EnforcingScopedCount++ }
            elseif ($fact.Mode -like 'Test*') { $answer.TestingScopedCount++ }
            elseif ($fact.Mode -eq 'Disable') { $answer.DisabledScopedCount++ }
        }
        elseif ($scope.State -eq 'Unknown') {
            $answer.UnknownScopeCount++
            if ($fact.IsEnforcing) { $answer.EnforcingUnknownScopeCount++ }
            elseif (-not $fact.ModeKnown) { $answer.UnknownModeUnknownScopeCount++ }
        }
    }

    $answer.Policies = $facts.ToArray()
    return [pscustomobject]$answer
}

function Get-PurviewEndpointDlpFindingOutcome {
    <# .SYNOPSIS Produces an evidence-accurate Endpoint DLP coverage outcome. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $state = Get-PurviewEndpointDlpAnalysis -Snapshot $Snapshot
    $outcome = [ordered]@{
        Status = 'NeedsReview'
        Reason = ''
        Observed = @()
        Control = 'Get-DlpCompliancePolicy, Mode and EndpointDlpLocation (Workload fallback)'
        Recommended = 'At least one Devices-scoped DLP policy is in Enable mode'
        LowConfidence = $false
    }

    if (-not $state.PolicyRead) {
        $outcome.Status = 'NotCollected'
        $outcome.Reason = 'Could not assess this run because DLP policy scope and mode were not read. ' +
            (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DataLossPrevention')
        return [pscustomobject]$outcome
    }

    $enforcing = @($state.Policies | Where-Object { $_.Scope -eq 'Included' -and $_.IsEnforcing })
    if ($enforcing.Count -gt 0) {
        $outcome.Status = 'Pass'
        $outcome.Observed = @($enforcing | ForEach-Object { $_.Name })
        $outcome.Reason = if ($state.PolicyComplete) {
            '{0} the Devices location in Enable mode. Rules, user/device applicability, onboarding and effective enforcement are not tested by this check.' -f
                (Format-PurviewCount -Count $enforcing.Count -Singular 'DLP policy targets' -Plural 'DLP policies target')
        }
        else {
            'At least {0} the Devices location in Enable mode; the policy read was partial. Effective enforcement is not tested.' -f
                (Format-PurviewCount -Count $enforcing.Count -Singular 'DLP policy targets' -Plural 'DLP policies target')
        }
        return [pscustomobject]$outcome
    }

    $gaps = [System.Collections.Generic.List[string]]::new()
    if (-not $state.PolicyComplete) { $gaps.Add('the DLP policy read was partial') }
    if ($state.EnforcingUnknownScopeCount -gt 0) {
        $gaps.Add(('{0} no readable Devices scope' -f
                (Format-PurviewCount -Count $state.EnforcingUnknownScopeCount -Singular 'enforcing policy has' -Plural 'enforcing policies have')))
    }
    if ($state.UnknownModeScopedCount -gt 0) {
        $gaps.Add(('{0} the Devices location but has no recognized Mode' -f
                (Format-PurviewCount -Count $state.UnknownModeScopedCount -Singular 'policy targets' -Plural 'policies target')))
    }
    if ($state.UnknownModeUnknownScopeCount -gt 0) {
        $gaps.Add(('{0} neither readable scope nor a recognized Mode' -f
                (Format-PurviewCount -Count $state.UnknownModeUnknownScopeCount -Singular 'policy has' -Plural 'policies have')))
    }
    if ($gaps.Count -gt 0) {
        $outcome.Status = 'NeedsReview'
        $outcome.LowConfidence = $true
        $outcome.Observed = @($state.Policies | Where-Object {
                $_.Scope -eq 'Included' -or ($_.Scope -eq 'Unknown' -and ($_.IsEnforcing -or -not $_.ModeKnown))
            } | ForEach-Object { $_.Name })
        $outcome.Reason = 'Could not establish whether an enforcing DLP policy targets the Devices location because {0}.' -f
            ($gaps -join '; ')
        return [pscustomobject]$outcome
    }

    if ($state.ScopedCount -gt 0) {
        $outcome.Status = 'Warning'
        $outcome.Observed = @($state.Policies | Where-Object { $_.Scope -eq 'Included' } |
            ForEach-Object { $_.Name })
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($state.TestingScopedCount -gt 0) { $parts.Add("$($state.TestingScopedCount) in simulation") }
        if ($state.DisabledScopedCount -gt 0) { $parts.Add("$($state.DisabledScopedCount) disabled") }
        $outcome.Reason = '{0} the Devices location, but none is in Enable mode. These policies are configured, not absent. In Endpoint simulation, Block becomes Block with override with policy tips, or Audit without them.' -f
            (Format-PurviewCount -Count $state.ScopedCount -Singular 'DLP policy targets' -Plural 'DLP policies target')
        if ($parts.Count -gt 0) { $outcome.Reason += ' Current state: {0}.' -f ($parts -join ', ') }
        return [pscustomobject]$outcome
    }

    $outcome.Status = 'Warning'
    $outcome.Reason = if ($state.PolicyCount -eq 0) {
        'No DLP policy is configured, so none targets the Devices location.'
    }
    else {
        '{0}, but none targets the Devices location.' -f
            (Format-PurviewCount -Count $state.PolicyCount -Singular 'DLP policy is configured' -Plural 'DLP policies are configured')
    }
    return [pscustomobject]$outcome
}

function Get-PurviewDlpFindingOutcome {
    <# .SYNOPSIS Produces evidence-accurate outcomes for the specialized DLP checks. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('EndpointCoverage', 'PolicyRuleCoverage', 'DisabledRulesInEnforcingPolicies')][string]$Analysis,
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot
    )

    if ($Analysis -eq 'EndpointCoverage') {
        return Get-PurviewEndpointDlpFindingOutcome -Snapshot $Snapshot
    }

    $state = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $outcome = [ordered]@{
        Status = 'NeedsReview'
        Reason = ''
        Observed = @()
        Control = 'Get-DlpCompliancePolicy Mode and Get-DlpComplianceRule Disabled'
        Recommended = 'Every DLP policy in Enable mode has an enabled rule'
        LowConfidence = $false
    }

    if (-not $state.PolicyRead) {
        $outcome.Status = 'NotCollected'
        $outcome.Reason = 'Could not assess this run because DLP policy mode was not read. ' +
            (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DataLossPrevention')
        return [pscustomobject]$outcome
    }

    if ($state.PolicyCount -eq 0) {
        if (-not $state.PolicyComplete) {
            $outcome.Status = 'NeedsReview'
            $outcome.LowConfidence = $true
            $outcome.Reason = 'Could not assess this run because the DLP policy read was partial and returned no policy records.'
            return [pscustomobject]$outcome
        }
        if ($Analysis -eq 'DisabledRulesInEnforcingPolicies') {
            $outcome.Status = 'NotApplicable'
            $outcome.Reason = 'No DLP policy is configured, so there is no enforcing policy whose rules can be checked for a disabled state.'
        }
        else {
            $outcome.Status = 'Fail'
            $outcome.Reason = 'No DLP policy was returned, so this check found no policy/rule configuration to assess.'
        }
        return [pscustomobject]$outcome
    }

    if (-not $state.RuleRead) {
        if ($state.PolicyComplete -and $state.EnforcingPolicyCount -eq 0 -and $state.UnknownPolicyModeCount -eq 0) {
            if ($Analysis -eq 'DisabledRulesInEnforcingPolicies') {
                $outcome.Status = 'NotApplicable'
                $outcome.Reason = 'No DLP policy is in Enable mode, so no rule is eligible for this disabled-rule check.'
            }
            else {
                $outcome.Status = 'Fail'
                $outcome.Reason = '{0} configured, but none is in Enable mode. Simulation behaviour depends on workload and policy tips.' -f
                    (Format-PurviewCount -Count $state.PolicyCount -Singular 'DLP policy is' -Plural 'DLP policies are')
            }
            return [pscustomobject]$outcome
        }
        $outcome.Status = 'NotCollected'
        $outcome.Reason = 'Could not assess this run because DLP rules were not read. ' +
            (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DlpRule')
        return [pscustomobject]$outcome
    }

    $linkGaps = $state.UnresolvedRuleCount -gt 0
    if ($Analysis -eq 'DisabledRulesInEnforcingPolicies') {
        $outcome.Recommended = 'Review disabled rules in DLP policies in Enable mode'
        $disabled = @($state.LinkedRules | Where-Object { $_.IsEnforcing -and $_.DisabledKnown -and $_.Disabled })
        if ($disabled.Count -gt 0) {
            $outcome.Status = 'Warning'
            $outcome.Observed = @($disabled | ForEach-Object { Get-PurviewItemLabel -InputObject $_.Rule })
            $disabledText = Format-PurviewCount -Count $disabled.Count -Singular 'DLP rule' -Plural 'DLP rules'
            $eligibleText = Format-PurviewCount -Count $state.EligibleRuleCount -Singular 'eligible rule' -Plural 'eligible rules'
            $verb = if ($disabled.Count -eq 1) { 'reports' } else { 'report' }
            $outcome.Reason = "$disabledText linked to a policy in Enable mode $verb a disabled state, out of $eligibleText."
            if ($linkGaps -or $state.UnknownRuleStateCount -gt 0 -or
                $state.UnknownPolicyModeCount -gt 0 -or $state.EnforcingPolicyIdentityGapCount -gt 0 -or
                -not $state.PolicyComplete -or -not $state.RuleComplete) {
                $outcome.LowConfidence = $true
                $outcome.Reason += ' Other rule linkage or state evidence was incomplete, but it does not negate the disabled rules observed.'
            }
            return [pscustomobject]$outcome
        }

        if ($state.PolicyComplete -and $state.EnforcingPolicyCount -eq 0 -and $state.UnknownPolicyModeCount -eq 0) {
            $outcome.Status = 'NotApplicable'
            $outcome.Reason = 'No DLP policy is in Enable mode, so no rule is eligible for this disabled-rule check.'
            return [pscustomobject]$outcome
        }

        if (-not $state.PolicyComplete -or -not $state.RuleComplete -or
            $state.UnknownPolicyModeCount -gt 0 -or $state.EnforcingPolicyIdentityGapCount -gt 0 -or
            $linkGaps -or $state.UnknownRuleStateCount -gt 0) {
            $gaps = [System.Collections.Generic.List[string]]::new()
            if (-not $state.PolicyComplete) { $gaps.Add('the DLP policy read was partial') }
            if (-not $state.RuleComplete) { $gaps.Add('the DLP rule read was partial') }
            if ($state.UnknownPolicyModeCount -gt 0) { $gaps.Add("$($state.UnknownPolicyModeCount) policies did not return a recognized Mode") }
            if ($state.EnforcingPolicyIdentityGapCount -gt 0) { $gaps.Add("$($state.EnforcingPolicyIdentityGapCount) enforcing policies have no usable name or identifier") }
            if ($linkGaps) { $gaps.Add("$($state.UnresolvedRuleCount) rules did not identify exactly one collected policy") }
            if ($state.UnknownRuleStateCount -gt 0) { $gaps.Add("$($state.UnknownRuleStateCount) eligible rules did not return a usable Disabled value") }
            $outcome.Status = 'NeedsReview'
            $outcome.LowConfidence = $true
            $outcome.Reason = 'Could not assess this run because {0}. Confirm rule state in the Purview portal.' -f ($gaps -join '; ')
            return [pscustomobject]$outcome
        }

        if ($state.EligibleRuleCount -eq 0) {
            $outcome.Status = 'NotApplicable'
            $outcome.Reason = 'No rule is linked to an enforcing DLP policy, so there is no eligible disabled-rule state to report.'
            return [pscustomobject]$outcome
        }

        $outcome.Status = 'Pass'
        $outcome.Reason = if ($state.EligibleRuleCount -eq 1) {
            'The eligible DLP rule linked to a policy in Enable mode reports an enabled state.'
        }
        else { "All $($state.EligibleRuleCount) eligible DLP rules linked to policies in Enable mode report an enabled state." }
        return [pscustomobject]$outcome
    }

    if ($state.EnforcingPolicyCount -eq 0) {
        if (-not $state.PolicyComplete -or $state.UnknownPolicyModeCount -gt 0) {
            $outcome.Status = 'NeedsReview'
            $outcome.LowConfidence = $true
            $outcome.Reason = if (-not $state.PolicyComplete) {
                'Could not assess this run because the DLP policy read was partial and no returned policy was known to be enforcing.'
            }
            else {
                'Could not assess this run because {0} of {1} DLP policies did not return a recognized Mode. Confirm their operating state in the Purview portal.' -f
                    $state.UnknownPolicyModeCount, $state.PolicyCount
            }
        }
        else {
            $outcome.Status = 'Fail'
            $outcome.Reason = '{0} configured, but none is in Enable mode. Simulation behaviour depends on workload and policy tips.' -f
                (Format-PurviewCount -Count $state.PolicyCount -Singular 'DLP policy is' -Plural 'DLP policies are')
        }
        return [pscustomobject]$outcome
    }

    if ($state.RuleCount -eq 0) {
        if (-not $state.RuleComplete) {
            $outcome.Status = 'NeedsReview'
            $outcome.LowConfidence = $true
            $outcome.Reason = 'Could not assess this run because the partial DLP rule read returned no rules for the enforcing policy set.'
        }
        else {
            $outcome.Status = 'Fail'
            $outcome.Reason = '{0}, but no DLP rule is defined.' -f
                (Format-PurviewCount -Count $state.EnforcingPolicyCount -Singular 'DLP policy is enforcing' -Plural 'DLP policies are enforcing')
        }
        return [pscustomobject]$outcome
    }

    $enforcing = @($state.Policies | Where-Object { $_.IsEnforcing })
    $withoutEnabled = @($enforcing | Where-Object { $_.EnabledRuleCount -eq 0 })
    if ($withoutEnabled.Count -eq 0) {
        if (-not $state.PolicyComplete -or $state.UnknownPolicyModeCount -gt 0) {
            $gaps = [System.Collections.Generic.List[string]]::new()
            if (-not $state.PolicyComplete) { $gaps.Add('the DLP policy read was partial') }
            if ($state.UnknownPolicyModeCount -gt 0) { $gaps.Add("$($state.UnknownPolicyModeCount) policies did not return a recognized Mode") }
            $outcome.Status = 'NeedsReview'
            $outcome.LowConfidence = $true
            $outcome.Reason = 'Could not assess this run because {0}. Confirm that every enforcing policy has an enabled rule.' -f ($gaps -join '; ')
            return [pscustomobject]$outcome
        }
        $outcome.Status = 'Pass'
        $outcome.Reason = if ($state.EnforcingPolicyCount -eq 1) {
            'The DLP policy in Enable mode has at least one enabled linked rule; {0} in total. Rule effectiveness is not tested.' -f
                (Format-PurviewCount -Count $state.EnabledRuleCount -Singular 'enabled linked rule was found' -Plural 'enabled linked rules were found')
        }
        else { "All $($state.EnforcingPolicyCount) DLP policies in Enable mode have at least one enabled linked rule; $($state.EnabledRuleCount) are enabled in total. Rule effectiveness is not tested." }
        return [pscustomobject]$outcome
    }

    if (-not $state.RuleComplete -or $state.EnforcingPolicyIdentityGapCount -gt 0 -or $linkGaps -or
        @($withoutEnabled | Where-Object { $_.UnknownRuleStateCount -gt 0 }).Count -gt 0) {
        $gaps = [System.Collections.Generic.List[string]]::new()
        if (-not $state.RuleComplete) { $gaps.Add('the DLP rule read was partial') }
        if ($state.EnforcingPolicyIdentityGapCount -gt 0) { $gaps.Add("$($state.EnforcingPolicyIdentityGapCount) enforcing policies have no usable name or identifier") }
        if ($linkGaps) { $gaps.Add("$($state.UnresolvedRuleCount) rules did not identify exactly one collected policy") }
        if ($state.UnknownRuleStateCount -gt 0) { $gaps.Add("$($state.UnknownRuleStateCount) rules in enforcing policies did not return a usable Disabled value") }
        $outcome.Status = 'NeedsReview'
        $outcome.LowConfidence = $true
        $outcome.Reason = 'Could not assess this run because {0}. Confirm that each enforcing policy has an enabled rule.' -f ($gaps -join '; ')
        return [pscustomobject]$outcome
    }

    $outcome.Status = 'Fail'
    $outcome.Observed = @($withoutEnabled | ForEach-Object { $_.Name })
    if ($state.EligibleRuleCount -eq 0) {
        $outcome.Reason = '{0}, but none of the {1} defined is linked to one of them.' -f
            (Format-PurviewCount -Count $state.EnforcingPolicyCount -Singular 'DLP policy is enforcing' -Plural 'DLP policies are enforcing'),
            (Format-PurviewCount -Count $state.RuleCount -Singular 'DLP rule' -Plural 'DLP rules')
    }
    elseif ($state.EnabledRuleCount -eq 0) {
        $outcome.Reason = '{0} linked to {1}, but none is enabled.' -f
            (Format-PurviewCount -Count $state.EligibleRuleCount -Singular 'DLP rule is' -Plural 'DLP rules are'),
            (Format-PurviewCount -Count $state.EnforcingPolicyCount -Singular 'an enforcing policy' -Plural 'enforcing policies')
    }
    else {
        $outcome.Reason = '{0} of {1} have no enabled linked rule.' -f $withoutEnabled.Count,
            (Format-PurviewCount -Count $state.EnforcingPolicyCount -Singular 'enforcing DLP policy' -Plural 'enforcing DLP policies')
    }
    return [pscustomobject]$outcome
}

function Get-PurviewRetentionListEvidence {
    <# .SYNOPSIS Validates a retention definition list without converting missing data into absence. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][ValidateSet('RetentionLabel', 'RetentionPolicy')][string]$Collector
    )

    $key = if ($Collector -eq 'RetentionLabel') { 'Labels' } else { 'Policies' }
    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $matched = @($results | Where-Object { (Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })
    $answer = [ordered]@{
        Status = 'NotCollected'; Complete = $false; NamedRecords = @()
        MalformedCount = 0; DuplicateCount = 0; Reason = "$Collector did not return a non-null $key list."
    }
    $gaps = [System.Collections.Generic.List[string]]::new()
    if ($matched.Count -gt 1) { $gaps.Add('duplicate collector results') }
    $named = [System.Collections.Generic.List[object]]::new()
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ids = [System.Collections.Generic.HashSet[guid]]::new()
    $readable = $false
    foreach ($result in $matched) {
        $status = [string](Get-PurviewProperty -InputObject $result -Name 'status')
        if ($status -notin 'Success', 'PartialSuccess') {
            $gaps.Add('an unavailable collector result')
            continue
        }
        if ($status -ne 'Success') { $gaps.Add('a partial collector read') }
        $data = Get-PurviewProperty -InputObject $result -Name 'data'
        if (-not (Test-PurviewProperty -InputObject $data -Name $key)) { continue }
        # Direct property access preserves [] versus null and rejects scalar/dictionary impostors.
        $raw = $null
        if ($data -is [System.Collections.IDictionary]) { $raw = $data[$key] }
        else { $raw = $data.PSObject.Properties[$key].Value }
        if ($null -eq $raw) { continue }
        if ($raw -isnot [System.Collections.IList]) { $gaps.Add('a malformed definition list'); continue }
        $readable = $true
        foreach ($source in @($result, $data)) {
            $optionalFields = @('Workload')
            if ($Collector -eq 'RetentionLabel') { $optionalFields = @('IsRecordLabel', 'RetentionAction', 'RetentionDuration') }
            $missingRequired = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $source -Name 'PropertiesNotReturned') |
                Where-Object { $_ -notin $optionalFields })
            if ($missingRequired.Count -gt 0) {
                $gaps.Add('reported missing properties')
            }
        }
        foreach ($record in $raw) {
            $name = $null
            if ($record -is [System.Collections.IDictionary]) { $name = $record['Name'] }
            elseif ($null -ne $record -and $record -is [pscustomobject] -and $record.PSObject.Properties['Name']) {
                $name = $record.PSObject.Properties['Name'].Value
            }
            if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) {
                $answer.MalformedCount++
                continue
            }
            $duplicate = -not $names.Add($name.Trim())
            $rawId = $null
            if ($record -is [System.Collections.IDictionary]) { $rawId = $record['Guid'] }
            elseif ($record.PSObject.Properties['Guid']) { $rawId = $record.PSObject.Properties['Guid'].Value }
            $id = [guid]::Empty
            if (($rawId -is [string] -or $rawId -is [guid]) -and
                [guid]::TryParse([string]$rawId, [ref]$id) -and $id -ne [guid]::Empty) {
                if (-not $ids.Add($id)) { $duplicate = $true }
            }
            if ($duplicate) { $answer.DuplicateCount++ }
            $named.Add($record)
        }
    }
    $answer.NamedRecords = $named.ToArray()
    if ($answer.MalformedCount -gt 0) { $gaps.Add("$($answer.MalformedCount) malformed or unnamed records") }
    if ($answer.DuplicateCount -gt 0) { $gaps.Add("$($answer.DuplicateCount) repeated names or identifiers") }
    if ($matched.Count -gt 1 -or ($readable -and $gaps.Count -gt 0) -or
        $gaps.Contains('a malformed definition list')) {
        $answer.Status = 'NeedsReview'
        $answer.Reason = 'No exact definition total or absence can be established: {0}.' -f (@($gaps | Select-Object -Unique) -join '; ')
    }
    elseif ($readable) {
        $answer.Status = 'Pass'
        $answer.Complete = $true
        $answer.Reason = 'A complete, readable definition list was returned.'
    }
    return [pscustomobject]$answer
}

function Get-PurviewRetentionLabelEvidence {
    <# .SYNOPSIS Shares the limited definition verdict and plain-text inventory evidence. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $state = Get-PurviewRetentionListEvidence -Snapshot $Snapshot -Collector 'RetentionLabel'
    $labels = @($state.NamedRecords)
    $optional = 'Retention labels are optional: use retention policies, labels or both. This does not establish that retention needs are satisfied.'
    $limits = 'Configured values only; the retention start, disposition review, per-label publication, content application and suitability of the retention schedule are not established here.'
    $details = [System.Collections.Generic.List[string]]::new()
    $recordCount = 0
    $nonRecordCount = 0
    $unknownCount = 0
    foreach ($label in $labels) {
        $rawRecordState = $null
        if ($label -is [System.Collections.IDictionary]) { $rawRecordState = $label['IsRecordLabel'] }
        elseif ($label.PSObject.Properties['IsRecordLabel']) { $rawRecordState = $label.PSObject.Properties['IsRecordLabel'].Value }
        if ($rawRecordState -isnot [bool] -and $rawRecordState -isnot [string]) { $rawRecordState = $null }
        $recordState = ConvertTo-PurviewBoolean -InputObject $rawRecordState
        if (-not $recordState.Valid) { $unknownCount++ }
        elseif ($recordState.Value) { $recordCount++ }
        else { $nonRecordCount++ }
        if ($details.Count -ge 6) { continue }
        $parts = [System.Collections.Generic.List[string]]::new()
        $parts.Add([string](Get-PurviewProperty -InputObject $label -Name 'Name'))
        foreach ($field in 'RetentionAction', 'RetentionDuration') {
            $raw = $null
            if ($label -is [System.Collections.IDictionary]) { $raw = $label[$field] }
            elseif ($label.PSObject.Properties[$field]) { $raw = $label.PSObject.Properties[$field].Value }
            $displayName = if ($field -eq 'RetentionAction') { 'configured action' } else { 'duration' }
            if ($null -eq $raw -or ($raw -is [string] -and [string]::IsNullOrWhiteSpace($raw))) {
                $parts.Add("${displayName}: unknown (not reported)")
                continue
            }
            $displayValue = 'unknown (unrecognized value)'
            if ($field -eq 'RetentionAction') {
                if ($raw -is [string]) {
                    $displayValue = switch ($raw.Trim()) {
                        'Keep' { 'Retain' }
                        'Delete' { 'Delete' }
                        'KeepAndDelete' { 'Retain then delete' }
                        default { 'unknown (unrecognized value)' }
                    }
                }
            }
            elseif ($raw -is [string] -and $raw.Trim() -ieq 'unlimited') { $displayValue = 'indefinitely' }
            elseif ($raw -is [string] -or $raw -is [byte] -or $raw -is [sbyte] -or
                $raw -is [int16] -or $raw -is [uint16] -or $raw -is [int32] -or
                $raw -is [uint32] -or $raw -is [int64] -or $raw -is [uint64]) {
                $days = ConvertTo-PurviewNonNegativeInteger -InputObject $raw
                if ($days.Valid -and $days.Value -gt 0) {
                    $displayValue = if ($days.Value -eq 1) { '1 day' } else { "$($days.Value) days" }
                }
            }
            $parts.Add("${displayName}: $displayValue")
        }
        $parts.Add($(if (-not $recordState.Valid) { 'record designation: unknown' }
            elseif ($recordState.Value) { 'record designation: record' }
            else { 'record designation: non-record' }))
        $details.Add(($parts -join '; '))
    }
    if ($labels.Count -gt 6) { $details.Add("$($labels.Count - 6) more returned named records omitted") }
    $status = $state.Status
    $value = 'Not checked'
    $reason = $state.Reason
    if ($state.Complete) {
        $value = [string]$labels.Count
        if ($labels.Count -eq 0) {
            $status = 'NotApplicable'
            $reason = "No retention label definitions were returned by the complete read. $optional"
        }
        else { $reason = "$($labels.Count) retention label definitions exist. Pass is limited to definition existence." }
    }
    $detail = if ($state.Complete) { "$($labels.Count) retention label definitions returned." }
        else { 'The label inventory could not be fully assessed.' }
    if (-not $state.Complete) {
        $detail += " Returned named records: $($labels.Count); malformed or unnamed records: $($state.MalformedCount). These are observations, not a tenant total."
    }
    if ($labels.Count -gt 0) {
        $detail += " Record designation among returned named records: $recordCount record, $nonRecordCount non-record, $unknownCount unknown. Details: $($details -join ' | ')."
    }
    $detail += " $limits"
    return [pscustomobject]@{
        Status = $status; Reason = $reason; Observed = $details.ToArray()
        Control = 'Get-ComplianceTag, readable retention label definitions'
        Recommended = 'Labels are optional; definition existence alone is assessed'
        LowConfidence = $status -eq 'NeedsReview'
        Value = $value; Detail = $detail
    }
}

function Format-PurviewRetentionEvidenceGap {
    <# .SYNOPSIS Names unavailable policy evidence without claiming retention settings are absent. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string[]]$Field)

    $names = @($Field | Select-Object -Unique | ForEach-Object {
            switch ($_) {
                'RuleTypes' { 'policy type (RetentionRuleTypes)' }
                'HasRules' { 'rule presence (HasRules)' }
                'Enabled' { 'enabled state (Enabled)' }
                'Mode' { 'policy mode (Mode)' }
                default { [string]$_ }
            }
        })
    return 'Retention policy details could not be fully reported. Unavailable in the collected data: {0}. This check cannot establish whether the relevant retention settings are configured; review the policy and its rules in Purview.' -f ($names -join ', ')
}

function Get-PurviewSentinelIntegrationOutcome {
    <# .SYNOPSIS Shares the same configuration, ingestion and unknown states across report surfaces. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $outcome = [ordered]@{
        Status = 'NotCollected'
        Value = 'not checked'
        SentinelValue = 'not checked'
        SentinelReason = 'Sentinel workspace discovery was not available.'
        Reason = ''
        Observed = @()
        Control = 'Microsoft 365 audit, Information Protection and Insider Risk telemetry in Sentinel'
        Recommended = 'Observed Microsoft 365 audit or compliance events in an accessible Sentinel workspace'
        LowConfidence = $false
    }
    $collectors = @(Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($collectors | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'SentinelPurviewIntegration' })
    if ($matched.Count -ne 1) {
        $outcome.Reason = Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'SentinelPurviewIntegration'
        if ($matched.Count -gt 1) { $outcome.Status = 'NeedsReview'; $outcome.LowConfidence = $true }
        return [pscustomobject]$outcome
    }
    $collector = $matched[0]
    $status = [string](Get-PurviewProperty -InputObject $collector -Name 'status')
    if ($status -notin 'Success', 'PartialSuccess') {
        $outcome.Reason = Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'SentinelPurviewIntegration'
        $outcome.Observed = @($outcome.Reason)
        return [pscustomobject]$outcome
    }

    $data = Get-PurviewProperty -InputObject $collector -Name 'data'
    $sentinelWorkspaces = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $data -Name 'SentinelWorkspaces'))
    $discoveryComplete = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $data -Name 'SentinelDiscoveryComplete')
    if ($sentinelWorkspaces.Count -gt 0) {
        $outcome.SentinelValue = [string]$sentinelWorkspaces.Count
        $outcome.SentinelReason = 'Sentinel detected in: {0}. Workspace presence alone does not establish Microsoft 365 ingestion.' -f
            (@($sentinelWorkspaces | ForEach-Object { ([string]$_).TrimEnd('/').Split('/')[-1] }) -join ', ')
        if (-not ($discoveryComplete.Valid -and $discoveryComplete.Value)) {
            $outcome.SentinelReason += ' Workspace discovery was incomplete; additional Sentinel workspaces may exist.'
        }
    }
    elseif ($discoveryComplete.Valid -and $discoveryComplete.Value) {
        $outcome.SentinelValue = '0'
        $outcome.SentinelReason = 'No Sentinel-enabled workspaces were found in the accessible subscriptions.'
    }
    else { $outcome.SentinelReason = 'Sentinel workspace discovery was incomplete; absence is not established.' }
    if ([string](Get-PurviewProperty -InputObject $data -Name 'EvidenceScope') -ne 'Microsoft365Purview') {
        $outcome.Status = 'NeedsReview'
        $outcome.LowConfidence = $true
        $outcome.Reason = 'This snapshot predates Microsoft 365 telemetry verification. Run a new collection; earlier governance evidence does not establish Microsoft 365 ingestion.'
        return [pscustomobject]$outcome
    }
    $tenantId = [guid]::Empty
    if (-not [guid]::TryParse([string](Get-PurviewProperty -InputObject $data -Name 'TenantId'), [ref]$tenantId) -or
        $tenantId -eq [guid]::Empty -or -not (Test-PurviewProperty -InputObject $data -Name 'Results')) {
        $outcome.Reason = 'Microsoft 365 source-tenant or workspace telemetry evidence was not returned.'
        return [pscustomobject]$outcome
    }
    $workspaces = @(Get-PurviewProperty -InputObject $data -Name 'Results')
    $limitations = @(
        @(Get-PurviewProperty -InputObject $collector -Name 'limitations')
        @(Get-PurviewProperty -InputObject $data -Name 'Limitations')
    ) | Where-Object { $_ } | Select-Object -Unique
    $details = [System.Collections.Generic.List[string]]::new()
    $observed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $configured = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $irmObserved = $false
    $incomplete = $status -eq 'PartialSuccess' -or @($limitations).Count -gt 0
    foreach ($workspace in $workspaces) {
        $onboarded = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $workspace -Name 'SentinelOnboarded')
        if (-not ($onboarded.Valid -and $onboarded.Value)) { $incomplete = $true; continue }
        $id = [string](Get-PurviewProperty -InputObject $workspace -Name 'SentinelWorkspaceResourceId')
        $name = $id.TrimEnd('/').Split('/')[-1]
        if (-not $name) { $incomplete = $true; continue }
        foreach ($connector in @(Get-PurviewProperty -InputObject $workspace -Name 'Connectors')) {
            $kind = [string](Get-PurviewProperty -InputObject $connector -Name 'Kind')
            $state = [string](Get-PurviewProperty -InputObject $connector -Name 'State')
            if ($state -eq 'Unknown') { $incomplete = $true }
            if ($kind -in 'Office365', 'MicrosoftPurviewInformationProtection', 'OfficeIRM' -and $state -eq 'Enabled' -and
                [string](Get-PurviewProperty -InputObject $connector -Name 'SourceTenantId') -ieq $tenantId.ToString('D')) {
                $null = $configured.Add($kind)
            }
        }
        if ([string](Get-PurviewProperty -InputObject $workspace -Name 'ConnectorRead') -ne 'Success') { $incomplete = $true }
        $sources = @(Get-PurviewProperty -InputObject $workspace -Name 'Sources')
        if ($sources.Count -eq 0) { $incomplete = $true }
        $sourceDetails = [System.Collections.Generic.List[string]]::new()
        foreach ($source in $sources) {
            $table = [string](Get-PurviewProperty -InputObject $source -Name 'Table')
            if ($table -notin 'OfficeActivity', 'MicrosoftPurviewInformationProtection', 'SecurityAlert') {
                $incomplete = $true
                continue
            }
            $sourceName = [string](Get-PurviewProperty -InputObject $source -Name 'Name')
            $queryState = [string](Get-PurviewProperty -InputObject $source -Name 'QueryState')
            if ($queryState -ne 'Success') {
                $sourceDetails.Add("$sourceName`: not read")
                if ($queryState -ne 'Unavailable') { $incomplete = $true }
                continue
            }
            $count = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $source -Name 'EventCount')
            $last = [string](Get-PurviewProperty -InputObject $source -Name 'LastEventUtc')
            $timestamp = [DateTimeOffset]::MinValue
            if (-not $count.Valid -or ($count.Value -gt 0 -and -not [DateTimeOffset]::TryParse($last, [ref]$timestamp))) {
                $incomplete = $true
                $sourceDetails.Add("$sourceName`: invalid summary")
                continue
            }
            $sourceScope = [string](Get-PurviewProperty -InputObject $source -Name 'Scope')
            if ($table -eq 'SecurityAlert' -and $sourceName -eq 'Insider Risk alerts' -and $sourceScope -eq 'Workspace') {
                if ($count.Value -gt 0) { $irmObserved = $true }
                $sourceDetails.Add("Insider Risk: $($count.Value) alert(s), workspace scope; source tenant not verified")
            }
            elseif ($table -in 'OfficeActivity', 'MicrosoftPurviewInformationProtection' -and $sourceScope -eq 'Microsoft365Tenant' -and
                [string](Get-PurviewProperty -InputObject $source -Name 'SourceTenantId') -ieq $tenantId.ToString('D')) {
                if ($count.Value -gt 0) { $null = $observed.Add($sourceName) }
                $line = "$sourceName`: $($count.Value) event(s)"
                if ($last) { $line += ", last $last" }
                foreach ($pair in @(@{ Key = 'LabelEventCount'; Label = 'label changes' }, @{ Key = 'DlpEventCount'; Label = 'DLP events' })) {
                    $value = Get-PurviewProperty -InputObject $source -Name $pair.Key
                    if ($null -ne $value) { $line += "; $($pair.Label) $value" }
                }
                $sourceDetails.Add($line)
            }
            else {
                $incomplete = $true
                $sourceDetails.Add("$sourceName`: source tenant not verified")
            }
        }
        $details.Add("$name`: $($sourceDetails -join '; ').")
    }

    if ($observed.Count -gt 0) {
        $outcome.Status = 'Pass'
        $outcome.Value = 'Events observed'
        $outcome.Reason = 'Microsoft 365 telemetry observed in Sentinel: {0}. This confirms the observed sources, not every Purview workload or continuous ingestion.' -f (@($observed | Sort-Object) -join ', ')
    }
    elseif ($irmObserved) {
        $outcome.Status = 'NeedsReview'
        $outcome.Value = 'IRM alerts observed'
        $outcome.Reason = 'Insider Risk alerts were observed in Sentinel, but their source tenant cannot be verified from the documented alert schema.'
        $outcome.LowConfidence = $true
    }
    elseif ($configured.Count -gt 0) {
        $outcome.Status = 'NeedsReview'
        $outcome.Value = 'Configured; ingestion not confirmed'
        $outcome.Reason = 'A Microsoft 365/Purview connector is enabled for the assessed tenant, but no tenant-attributed events were confirmed in the lookback window.'
    }
    elseif ($incomplete -or -not ($discoveryComplete.Valid -and $discoveryComplete.Value)) {
        $outcome.Status = 'NeedsReview'
        $outcome.Reason = 'Microsoft 365 ingestion could not be verified because some workspace, connector or query evidence was unavailable.'
        $outcome.LowConfidence = $true
    }
    else {
        $outcome.Status = 'Warning'
        $outcome.Value = 'Not observed'
        $outcome.Reason = 'No relevant Microsoft 365/Purview connector or matching events were observed in accessible Sentinel workspaces. An empty window does not prove the integration is broken.'
    }
    if ($incomplete) {
        $outcome.LowConfidence = $true
        $outcome.Reason += ' Some reads were incomplete; see the evidence.'
    }
    if ($configured.Count -gt 0) { $details.Add('Enabled connectors for this tenant: {0}.' -f (@($configured | Sort-Object) -join ', ')) }
    $outcome.Observed = @($details | Select-Object -First 5)
    if ($details.Count -gt 5) { $outcome.Observed += 'Additional workspace details are retained in the snapshot.' }
    if (@($limitations).Count -gt 0) {
        $outcome.Observed += @($limitations | Select-Object -First 2)
        if (@($limitations).Count -gt 2) { $outcome.Observed += 'Additional read limitations are retained in the snapshot.' }
    }
    return [pscustomobject]$outcome
}

function ConvertTo-PurviewFinding {
    <# .SYNOPSIS Evaluates one rule using collector evidence, with advisory licensing metadata. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CollectorResults,
        [Parameter(Mandatory)][string]$Stamp
    )

    $condition = Get-PurviewProperty -InputObject $Rule -Name 'condition'
    $collectorName = [string](Get-PurviewProperty -InputObject $condition -Name 'collector')

    $finding = [ordered]@{
        ruleId = [string](Get-PurviewProperty -InputObject $Rule -Name 'id')
        ruleVersion = [string](Get-PurviewProperty -InputObject $Rule -Name 'version')
        title = [string](Get-PurviewProperty -InputObject $Rule -Name 'title')
        solutionArea = [string](Get-PurviewProperty -InputObject $Rule -Name 'solutionArea')
        solution = Get-PurviewSolutionWorkload -SolutionArea ([string](Get-PurviewProperty -InputObject $Rule -Name 'solutionArea'))
        status = 'NotCollected'
        severity = [string](Get-PurviewProperty -InputObject $Rule -Name 'severity')
        confidence = [string](Get-PurviewProperty -InputObject $Rule -Name 'confidence')
        reason = ''
        rationale = [string](Get-PurviewProperty -InputObject $Rule -Name 'rationale')
        recommendation = [string](Get-PurviewProperty -InputObject $Rule -Name 'recommendation')
        evidence = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Rule -Name 'evidence'))
        zeroTrust = [string](Get-PurviewProperty -InputObject $Rule -Name 'zeroTrust')
        deploymentModel = [string](Get-PurviewProperty -InputObject $Rule -Name 'deploymentModel')
        tier = Get-PurviewLicenceTierLabel -Licensing (Get-PurviewProperty -InputObject $Rule -Name 'licensing')
        control = ''
        recommended = ''
        observed = @()
        evaluatedAt = $Stamp
    }

    $remediation = Get-PurviewProperty -InputObject $Rule -Name 'remediationCommand'
    if (-not [string]::IsNullOrWhiteSpace([string]$remediation)) { $finding.remediationCommand = [string]$remediation }

    $licensing = Get-PurviewLicensingState -Licensing (Get-PurviewProperty -InputObject $Rule -Name 'licensing') -Snapshot $Snapshot
    $finding.licensing = [ordered]@{
        mode = 'Advisory'
        capability = $licensing.Capability
        state = $licensing.State
        unlockedBy = @($licensing.UnlockedBy)
    }

    $namedAnalysis = [string](Get-PurviewProperty -InputObject $condition -Name 'analysis')
    if (-not [string]::IsNullOrWhiteSpace($namedAnalysis)) {
        $outcome = if ($namedAnalysis -eq 'RetentionLabelConfiguration') {
            Get-PurviewRetentionLabelEvidence -Snapshot $Snapshot
        }
        elseif ($namedAnalysis -eq 'SentinelPurviewIntegration') {
            Get-PurviewSentinelIntegrationOutcome -Snapshot $Snapshot
        }
        else { Get-PurviewDlpFindingOutcome -Analysis $namedAnalysis -Snapshot $Snapshot }
        $finding.status = $outcome.Status
        $finding.reason = $outcome.Reason
        $finding.observed = @($outcome.Observed)
        $finding.control = $outcome.Control
        $finding.recommended = $outcome.Recommended
        if ($outcome.LowConfidence) { $finding.confidence = 'Low' }
        return [pscustomobject]$finding
    }

    # Indexing [0] on an empty result throws under StrictMode, so match the count first.
    $matched = @($CollectorResults | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $collectorName })
    if ($matched.Count -gt 1) {
        $finding.status = 'NeedsReview'
        $finding.confidence = 'Low'
        $finding.reason = "$collectorName returned duplicate collector results, so no single result is authoritative."
        return [pscustomobject]$finding
    }
    $result = if ($matched.Count -eq 1) { $matched[0] } else { $null }

    if ($null -eq $result) {
        $finding.reason = "$collectorName was not part of this run, so it was not checked."
        return [pscustomobject]$finding
    }

    $status = [string](Get-PurviewProperty -InputObject $result -Name 'status')
    if ($status -eq 'Unsupported') {
        $finding.status = 'Unsupported'
        $finding.reason = "'$collectorName' is not collected by this script. Assess it separately."
        return [pscustomobject]$finding
    }
    if ($status -notin 'Success', 'PartialSuccess') {
        $errors = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $result -Name 'errors'))
        $why = if ($errors.Count -gt 0) { [string](Get-PurviewProperty -InputObject $errors[0] -Name 'message') } else { $status }
        # Attribute the service error and state that missing evidence is not a tenant verdict.
        $finding.reason = if ($status -eq 'NotConnected' -and $collectorName -eq 'SentinelPurviewIntegration') {
            "The isolated Azure worker could not read the Az context or required Azure commands, so this check was not read. $why"
        }
        else {
            "$collectorName could not be checked, so nothing here says whether it is configured, one way or the other. Reason given: $why"
        }
        $finding.observed = @($why)
        return [pscustomobject]$finding
    }

    $data = Get-PurviewProperty -InputObject $result -Name 'data'
    $select = [string](Get-PurviewProperty -InputObject $condition -Name 'select')

    # An absent key means the service never reported that shape, which is different from reporting
    # an empty one. An empty one is a real answer and is assessed below.
    if (-not [string]::IsNullOrWhiteSpace($select) -and -not (Test-PurviewProperty -InputObject $data -Name $select)) {
        $finding.reason = "$collectorName did not report any $select, so this was not checked."
        return [pscustomobject]$finding
    }

    $source = if ([string]::IsNullOrWhiteSpace($select)) { $data } else { Get-PurviewProperty -InputObject $data -Name $select }
    # Re-wrap: a function returning an empty collection yields $null at the call site, and a tenant
    # with nothing configured yields exactly that. It must be assessed, not skipped.
    $items = @(ConvertTo-PurviewArray -InputObject $source)

    # A property the service never returned cannot be judged. Evaluating anyway would report a gap
    # in collection as a defect in the tenant.
    $notReturned = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $result -Name 'propertiesNotReturned'))
    if ($notReturned.Count -gt 0) {
        $blocked = @(Get-PurviewConditionField -Condition $condition | Where-Object { $notReturned -contains $_ })
        if ($blocked.Count -gt 0) {
            $finding.status = 'NeedsReview'
            $finding.confidence = 'Low'
            $finding.reason = if ($collectorName -eq 'RetentionPolicy') { Format-PurviewRetentionEvidenceGap -Field $blocked }
            else { "$($blocked -join ', ') is not visible here, so this check could not be made. Confirm it in the portal." }
            return [pscustomobject]$finding
        }
    }

    $where = Get-PurviewProperty -InputObject $condition -Name 'where'
    if ($null -ne $where) {
        $whereFields = @(Get-PurviewPredicateField -Predicate $where)
        $missingWhere = @($whereFields | Where-Object {
                $field = $_
                @($items | Where-Object {
                        -not (Test-PurviewProperty -InputObject $_ -Name $field) -or
                        $null -eq (Get-PurviewProperty -InputObject $_ -Name $field)
                    }).Count -gt 0
            })
        if ($missingWhere.Count -gt 0) {
            $finding.status = 'NeedsReview'
            $finding.confidence = 'Low'
            $finding.reason = if ($collectorName -eq 'RetentionPolicy') { Format-PurviewRetentionEvidenceGap -Field $missingWhere }
            else { "$($missingWhere -join ', ') was missing from one or more records, so this check could not be made." }
            return [pscustomobject]$finding
        }
    }
    if ($null -ne $where) {
        $items = @($items | Where-Object { Test-PurviewPredicate -InputObject $_ -Predicate $where })
    }

    $assertion = Get-PurviewProperty -InputObject $condition -Name 'assert'
    $assertFields = [System.Collections.Generic.List[string]]::new()
    foreach ($field in @(Get-PurviewPredicateField -Predicate (Get-PurviewProperty -InputObject $assertion -Name 'where'))) {
        $assertFields.Add($field)
    }
    $withinField = [string](Get-PurviewProperty -InputObject $assertion -Name 'within')
    foreach ($name in 'field', 'within') {
        $field = [string](Get-PurviewProperty -InputObject $assertion -Name $name)
        if ($field) { $assertFields.Add($field) }
    }
    $missingAssertion = @($assertFields | Select-Object -Unique | Where-Object {
            $field = $_
            @($items | Where-Object {
                    -not (Test-PurviewProperty -InputObject $_ -Name $field) -or
                    ($field -ine $withinField -and $null -eq (Get-PurviewProperty -InputObject $_ -Name $field))
                }).Count -gt 0
        })
    if ($missingAssertion.Count -gt 0) {
        $finding.status = 'NeedsReview'
        $finding.confidence = 'Low'
        $finding.reason = if ($collectorName -eq 'RetentionPolicy') { Format-PurviewRetentionEvidenceGap -Field $missingAssertion }
        else { "$($missingAssertion -join ', ') was missing from one or more records, so this check could not be made." }
        return [pscustomobject]$finding
    }

    $outcome = Test-PurviewAssertion -Items @($items) -Assertion $assertion

    # An empty eligible set is not proof of either effective protection or no tenant configuration.
    if ($outcome.Passed -and [bool](Get-PurviewProperty -InputObject $outcome -Name 'Vacuous')) {
        $finding.status = 'NotApplicable'
        $finding.reason = "No collected items were eligible for this assertion after filtering. This does not establish that the tenant has no related configuration."
        return [pscustomobject]$finding
    }

    if ($outcome.Passed) {
        $finding.status = 'Pass'
    }
    elseif ([string](Get-PurviewProperty -InputObject $Rule -Name 'guidanceStatus') -eq 'Preview') {
        # Preview guidance changes, so a breach of it is surfaced for review rather than asserted.
        $finding.status = 'NeedsReview'
    }
    else {
        $finding.status = if ($finding.severity -in 'Critical', 'High') { 'Fail' } else { 'Warning' }
    }

    $finding.reason = $outcome.Reason
    $finding.observed = @($outcome.Observed)

    # Name the control in the reader's terms: the interface it is read from and the field tested.
    # A finding that says only what is wrong leaves the reader to work out where to go and look.
    $assert = Get-PurviewProperty -InputObject $condition -Name 'assert'
    $field = [string](Get-PurviewProperty -InputObject $assert -Name 'field')
    if (-not $field) { $field = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $assert -Name 'where') -Name 'field') }

    $interface = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'source') -Name 'interface')
    $finding.control = if ($field) { "$interface, $field" } else { $interface }

    $expected = [string](Get-PurviewProperty -InputObject $assert -Name 'subject')
    if (-not $expected) {
        $predicate = Get-PurviewProperty -InputObject $assert -Name 'where'
        if ($null -ne $predicate) { $expected = Format-PurviewPredicate -Predicate $predicate }
    }
    if ($expected) { $finding.recommended = $expected }

    if ($status -eq 'PartialSuccess') {
        $finding.confidence = 'Low'
        $finding.reason += ' Collection was partial, so this finding rests on incomplete data.'
    }

    return [pscustomobject]$finding
}

function Invoke-PurviewRuleEngine {
    <# .SYNOPSIS Evaluates rules against a snapshot and returns findings. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [AllowEmptyCollection()][object[]]$Rule = $script:Rules,
        [DateTimeOffset]$EvaluatedAt = (Get-PurviewTimestamp)
    )

    $stamp = Format-PurviewTimestamp -Timestamp $EvaluatedAt
    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $findings = [System.Collections.Generic.List[object]]::new()

    # Sorting by id keeps output order independent of rule declaration order.
    foreach ($definition in @($Rule | Sort-Object -Property { [string](Get-PurviewProperty -InputObject $_ -Name 'id') })) {
        $findings.Add((ConvertTo-PurviewFinding -Rule $definition -Snapshot $Snapshot -CollectorResults $results -Stamp $stamp))
    }

    return $findings.ToArray()
}

function Get-PurviewCustomerFinding {
    <# .SYNOPSIS Applies the evidence boundary for every customer-facing finding population. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    # NotApplicable remains rule-engine bookkeeping. A proven licensing exclusion is copied to a
    # customer-only status so it cannot look like a collection failure, while every other
    # inapplicable rule remains hidden.
    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Finding) {
        $status = [string](Get-PurviewProperty -InputObject $item -Name 'status')
        if ($status -eq 'NotApplicable') {
            $licensingState = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $item -Name 'licensing') -Name 'state')
            if ($licensingState -ne 'NotLicensed') { continue }

            $licensedCopy = [ordered]@{}
            if ($item -is [System.Collections.IDictionary]) {
                foreach ($key in $item.Keys) { $licensedCopy[[string]$key] = $item[$key] }
            }
            else {
                foreach ($property in $item.PSObject.Properties) { $licensedCopy[[string]$property.Name] = $property.Value }
            }
            $licensedCopy['status'] = 'NotLicensed'
            $null = $licensedCopy.Remove('remediationCommand')
            $output.Add([pscustomobject]$licensedCopy)
            continue
        }
        if ($status -ne 'NeedsReview') {
            $output.Add($item)
            continue
        }

        # NeedsReview means the change is unproven or the guidance provisional. Suppress the
        # rule's fix and command in a copy, preserving the internal finding for inspection.
        $safe = [ordered]@{}
        $hasRecommendation = $false
        if ($item -is [System.Collections.IDictionary]) {
            foreach ($key in $item.Keys) {
                $name = [string]$key
                if ($name -ieq 'remediationCommand') { continue }
                if ($name -ieq 'recommendation') {
                    $safe[$name] = 'Review the evidence and current state before taking action. This result does not establish that a configuration change is needed.'
                    $hasRecommendation = $true
                }
                else { $safe[$name] = $item[$key] }
            }
        }
        else {
            foreach ($property in $item.PSObject.Properties) {
                $name = [string]$property.Name
                if ($name -ieq 'remediationCommand') { continue }
                if ($name -ieq 'recommendation') {
                    $safe[$name] = 'Review the evidence and current state before taking action. This result does not establish that a configuration change is needed.'
                    $hasRecommendation = $true
                }
                else { $safe[$name] = $property.Value }
            }
        }
        if (-not $hasRecommendation) {
            $safe['recommendation'] = 'Review the evidence and current state before taking action. This result does not establish that a configuration change is needed.'
        }
        $output.Add([pscustomobject]$safe)
    }

    return $output.ToArray()
}

#endregion

#region Posture analysis
# Derived from a snapshot only. Nothing here contacts a tenant, so the same snapshot always yields
# the same analysis.

# The documented default tiers. A reference to compare against, never a target to score against:
# organisations classify to their own risk model, and a different taxonomy is a design choice.
$script:ReferenceTaxonomy = @(
    @{ Tier = 'Personal'; Purpose = 'Non-business data' }
    @{ Tier = 'Public'; Purpose = 'Approved for public consumption' }
    @{ Tier = 'General'; Purpose = 'Business data, shareable with partners as required' }
    @{ Tier = 'Confidential'; Purpose = 'Damaging if shared with unauthorised people' }
    @{ Tier = 'Highly Confidential'; Purpose = 'Seriously damaging if shared with unauthorised people' }
)

function Get-PurviewLabelTaxonomy {
    <# .SYNOPSIS Describes the sensitivity label taxonomy a tenant actually has. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'SensitivityLabel' })

    if ($matched.Count -ne 1 -or [string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') {
        return [pscustomobject]@{ Collected = $false; StateKnown = $false; Enabled = @(); TopLevel = @(); TopLevelItems = @(); SubLabels = @(); HierarchyKnown = $false }
    }

    $labels = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name 'Labels')
    $enabledList = [System.Collections.Generic.List[object]]::new()
    $stateKnown = $true
    foreach ($label in $labels) {
        $disabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $label -Name 'Disabled')
        if (-not $disabled.Valid) { $stateKnown = $false; continue }
        if (-not [bool]$disabled.Value) { $enabledList.Add($label) }
    }
    $enabled = @($enabledList.ToArray())
    if (-not $stateKnown) {
        return [pscustomobject]@{ Collected = $true; StateKnown = $false; Enabled = @(); TopLevel = @(); TopLevelItems = @(); SubLabels = @(); HierarchyKnown = $false }
    }

    # A present null ParentId is a real top-level root. A missing property is unknown hierarchy,
    # and one known label cannot make the remaining enabled labels safe to classify as roots.
    $hierarchyKnown = @($enabled | Where-Object { -not (Test-PurviewProperty -InputObject $_ -Name 'ParentId') }).Count -eq 0
    $sub = @(if ($hierarchyKnown) {
            $enabled | Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')) }
        })
    $top = if ($hierarchyKnown) {
        @($enabled | Where-Object { [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')) })
    }
    else { @() }

    # Modern groups organize labels but are not themselves publishable/applicable labels.
    # Only the returned marker identifies the type; a name or parent relationship does not.
    # Older snapshots and missing/malformed optional values retain an unknown type.
    $groupFlag = {
        param($label)
        $raw = $null
        # Read directly so a malformed singleton collection cannot unroll to a Boolean.
        if ($label -is [System.Collections.IDictionary]) {
            if ($label.Contains('IsLabelGroup')) { $raw = $label['IsLabelGroup'] }
        }
        elseif ($null -ne $label) {
            $property = $label.PSObject.Properties['IsLabelGroup']
            if ($null -ne $property) { $raw = $property.Value }
        }
        if ($raw -isnot [bool] -and $raw -isnot [string]) { return $null }
        $parsed = ConvertTo-PurviewBoolean -InputObject $raw
        if ($parsed.Valid) { return [bool]$parsed.Value }
        return $null
    }

    # The default taxonomy repeats a sublabel name under more than one tier, so a leaf name alone
    # reads as a duplicate row. The parent is resolved by Guid to name each one the way a picker does.
    $byGuid = @{}
    $groupByGuid = @{}
    $duplicateGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($label in $enabled) {
        $guid = [string](Get-PurviewProperty -InputObject $label -Name 'Guid')
        if ($guid) {
            if ($byGuid.ContainsKey($guid)) { $null = $duplicateGuids.Add($guid) }
            $byGuid[$guid] = [string](Get-PurviewProperty -InputObject $label -Name 'Name')
            # A duplicated identifier cannot establish which parent's type applies.
            $groupByGuid[$guid] = if ($groupByGuid.ContainsKey($guid)) { $null } else { & $groupFlag $label }
        }
    }

    return [pscustomobject]@{
        Collected = $true
        StateKnown = $true
        Enabled = @($enabled | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        TopLevel = @($top | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        TopLevelItems = @($top | ForEach-Object {
                [pscustomobject]@{
                    Guid = [string](Get-PurviewProperty -InputObject $_ -Name 'Guid')
                    Name = [string](Get-PurviewProperty -InputObject $_ -Name 'Name')
                    IsLabelGroup = (& $groupFlag $_)
                }
            })
        SubLabels = @($sub | ForEach-Object {
                $name = [string](Get-PurviewProperty -InputObject $_ -Name 'Name')
                $parentId = [string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')
                $parentResolved = $byGuid.ContainsKey($parentId) -and -not $duplicateGuids.Contains($parentId)
                $parent = if ($parentResolved) { [string]$byGuid[$parentId] } else { '' }
                # Only an explicit path separator establishes an already-qualified display name.
                # Equality or a shared prefix must not hide a same-named child beneath its group.
                $prefix = "$parent \ "
                $qualified = $parent -and $name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
                [pscustomobject]@{
                    Name = $name
                    LeafName = if ($qualified) { $name.Substring($prefix.Length) } else { $name }
                    Parent = $parent
                    ParentId = $parentId
                    ParentResolved = $parentResolved
                    IsLabelGroup = (& $groupFlag $_)
                    ParentIsLabelGroup = if ($parentResolved) { $groupByGuid[$parentId] } else { $null }
                    Path = if ($parent -and -not $qualified) { "$parent \ $name" } else { $name }
                    # Absent is not the same as off: Get-Label does not always return the property.
                    Encrypted = if (Test-PurviewProperty -InputObject $_ -Name 'EncryptionEnabled') {
                        $encryption = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $_ -Name 'EncryptionEnabled')
                        if ($encryption.Valid) { [bool]$encryption.Value } else { $null }
                    }
                    else { $null }
                }
            })
        HierarchyKnown = $hierarchyKnown
    }
}

function Get-PurviewTaxonomyComparison {
    <#
    .SYNOPSIS
        Compares the tenant's label tiers against the documented default taxonomy.

    .DESCRIPTION
        Reports where names coincide and where they do not. A tier with no counterpart is recorded
        as an observation, not a gap: organisations classify to their own risk model, and only an
        exact name is checkable without inventing synonyms.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $taxonomy = Get-PurviewLabelTaxonomy -Snapshot $Snapshot
    $output = [System.Collections.Generic.List[object]]::new()

    if (-not $taxonomy.Collected) {
        $output.Add([pscustomobject]@{ Tier = 'Not collected'; Type = 'Unknown'; Match = 'Unknown'; Detail = 'Sensitivity labels were not collected, so the taxonomy could not be compared.' })
        return $output.ToArray()
    }
    if (-not $taxonomy.StateKnown) {
        $output.Add([pscustomobject]@{ Tier = 'Not checked'; Type = 'Unknown'; Match = 'Unknown'; Detail = 'One or more labels did not return a usable Disabled state, so the active taxonomy could not be established.' })
        return $output.ToArray()
    }
    if (-not $taxonomy.HierarchyKnown) {
        $output.Add([pscustomobject]@{ Tier = 'Not checked'; Type = 'Unknown'; Match = 'Unknown'; Detail = 'One or more enabled labels did not return ParentId, so top-level entries and their relationships could not be established.' })
        return $output.ToArray()
    }

    $typeName = {
        param($isGroup)
        if ($isGroup -isnot [bool]) { return 'Not recorded' }
        if ($isGroup) { return 'Label group' }
        return 'Sensitivity label'
    }

    $children = @($taxonomy.SubLabels | Sort-Object -Property Path | ForEach-Object {
            $sub = $_
            $detail = if ($sub.IsLabelGroup -eq $true) { 'This entry is reported as a label group with a parent. Confirm the hierarchy in the portal; a group is not an applicable sensitivity label.' }
            elseif ($null -eq $sub.Encrypted) { 'This label''s encryption configuration could not be established from the returned data.' }
            elseif ($sub.Encrypted) { 'This label is configured to apply encryption. Application and effective protection of individual files are not assessed here.' }
            else { 'This label is not configured to apply encryption. File permissions and any other encryption are not assessed here.' }
            if (-not $sub.ParentResolved) {
                $detail = 'The parent is absent or ambiguous in the returned label list. ' + $detail
            }
            elseif ($sub.ParentIsLabelGroup -eq $true -and $sub.IsLabelGroup -eq $false -and $sub.LeafName -eq $sub.Parent) {
                $detail = 'This label shares its group''s name; the group and this child label are separate entries. ' + $detail
            }
            $relationship = if (-not $sub.ParentResolved) { 'Parent not resolved' }
            elseif ($sub.IsLabelGroup -eq $true) { 'Parented group - review' }
            elseif ($sub.ParentIsLabelGroup -eq $true) { 'Label in group' }
            else { 'Sublabel' }
            [pscustomobject]@{
                ParentId = $sub.ParentId; ParentResolved = $sub.ParentResolved; Emitted = $false
                Row = [pscustomobject]@{ Tier = $sub.Path; Type = (& $typeName $sub.IsLabelGroup); Match = $relationship; Detail = $detail; Depth = 0 }
            }
        })

    # Place each child below its uniquely identified parent, never under a name match alone.
    $addTop = {
        param($entry, [string]$match, [string]$detail)
        $output.Add([pscustomobject]@{ Tier = $entry.Name; Type = (& $typeName $entry.IsLabelGroup); Match = $match; Detail = $detail; Depth = 0 })
        if (-not $entry.Guid) { return }
        foreach ($child in $children) {
            if ($child.Emitted -or -not $child.ParentResolved -or $child.ParentId -ine $entry.Guid) { continue }
            $child.Row.Depth = 1
            $output.Add($child.Row)
            $child.Emitted = $true
        }
    }

    $top = @($taxonomy.TopLevelItems)
    foreach ($reference in $script:ReferenceTaxonomy) {
        $hits = @($top | Where-Object { $_.Name -eq $reference.Tier })
        if ($hits.Count -eq 0) {
            $output.Add([pscustomobject]@{ Tier = $reference.Tier; Type = 'Reference only'; Match = 'No label or group of this name'; Detail = $reference.Purpose; Depth = 0 })
            continue
        }
        # Preserve each returned entry when a group and a label share a display name.
        foreach ($hit in $hits) {
            & $addTop $hit 'Same name' $reference.Purpose
        }
    }

    $names = @($script:ReferenceTaxonomy | ForEach-Object { $_.Tier })
    foreach ($own in @($top | Where-Object { $_.Name -notin $names } | Sort-Object Name)) {
        & $addTop $own 'Organisation-specific' 'No counterpart in the default taxonomy. Compared by name only, so a differently named equivalent reads the same way.'
    }

    # Unresolved or deeper relationships remain visible without inventing a top-level parent.
    foreach ($child in @($children | Where-Object { -not $_.Emitted })) { $output.Add($child.Row) }

    return $output.ToArray()
}

function Get-PurviewLabelSchemeSignal {
    <#
    .SYNOPSIS
        Identifies the reported label scheme or typed parent/group evidence from a snapshot.

    .DESCRIPTION
        Uses complete reads only. Legacy and Modern have been observed from Get-PolicyConfig;
        other values are not guessed. All returned labels, including disabled definitions, are
        considered. Neither hierarchy alone nor a lack of groups establishes the scheme.
        This does not read migration availability, readiness, completion or history.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $answer = [pscustomobject]@{
        State = 'Confirm in portal'; Scheme = 'Unknown'
        Detail = 'Label scheme could not be established from complete configuration evidence. Confirm it in the portal.'
    }
    # Wrap raw fields so PowerShell cannot unroll a singleton array into scalar evidence.
    $readState = [pscustomobject]@{ Ambiguous = $false }
    $field = {
        param($record, [string]$name)
        $present = $false; $value = $null
        if ($record -is [System.Collections.IDictionary]) {
            # JSON replay preserves key casing. Match known field names case-insensitively,
            # but never choose one of two case-distinct keys carrying competing evidence.
            $keys = @($record.Keys | Where-Object { $_ -is [string] -and $_ -eq $name })
            $present = $keys.Count -gt 0
            if ($keys.Count -eq 1) { $value = $record[$keys[0]] }
            elseif ($keys.Count -gt 1) { $readState.Ambiguous = $true }
        }
        elseif ($null -ne $record) {
            $property = $record.PSObject.Properties[$name]
            if ($null -ne $property) { $present = $true; $value = $property.Value }
        }
        [pscustomobject]@{ Present = $present; Value = $value }
    }
    $rawResults = & $field $Snapshot 'collectorResults'
    if ($rawResults.Value -isnot [System.Collections.IList]) { return $answer }
    $proof = @{}
    foreach ($definition in @(
            @{ Collector = 'TenantPolicyConfig'; Key = 'Settings'; Interface = 'Get-PolicyConfig' }
            @{ Collector = 'SensitivityLabel'; Key = 'Labels'; Interface = 'Get-Label' }
        )) {
        $matched = @($rawResults.Value | Where-Object {
                $name = & $field $_ 'collector'
                $name.Value -is [string] -and $name.Value -eq $definition.Collector
            })
        if ($matched.Count -gt 1) {
            $answer.Detail = 'Duplicate label or tenant-policy collector results prevent a reliable scheme decision. Confirm in the portal.'
            return $answer
        }
        if ($matched.Count -ne 1) { continue }
        $status = & $field $matched[0] 'status'
        if ($status.Value -isnot [string] -or $status.Value -ne 'Success') { continue }
        $data = & $field $matched[0] 'data'
        $list = & $field $data.Value $definition.Key
        if ($list.Value -isnot [System.Collections.IList]) { continue }
        $complete = $true
        foreach ($record in @($matched[0], $data.Value)) {
            foreach ($name in 'PropertiesNotReturned', 'errors') {
                $gap = & $field $record $name
                if ($null -ne $gap.Value -and ($gap.Value -isnot [System.Collections.IList] -or $gap.Value.Count -gt 0)) { $complete = $false }
            }
        }
        $source = & $field $matched[0] 'source'
        foreach ($expected in @(
                @{ Name = 'kind'; Value = 'SecurityAndCompliancePowerShell' }
                @{ Name = 'interface'; Value = $definition.Interface }
            )) {
            $observed = & $field $source.Value $expected.Name
            if ($observed.Present -and ($observed.Value -isnot [string] -or $observed.Value -ne $expected.Value)) { $complete = $false }
        }
        if ($complete) { $proof[$definition.Collector] = $list.Value }
    }

    $reported = ''
    if ($proof.ContainsKey('TenantPolicyConfig')) {
        $settings = [System.Collections.Generic.List[object]]::new()
        foreach ($setting in $proof['TenantPolicyConfig']) {
            $name = & $field $setting 'Name'
            if ($name.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($name.Value)) {
                $answer.Detail = 'Tenant-policy setting names are incomplete or malformed, so the label scheme is unknown.'
                return $answer
            }
            if ($name.Value -eq 'LabelScheme') { $settings.Add($setting) }
        }
        if ($settings.Count -gt 1) {
            $answer.Detail = 'More than one LabelScheme setting was returned. Confirm the scheme in the portal.'
            return $answer
        }
        if ($settings.Count -eq 1) {
            $value = & $field $settings[0] 'Value'
            if (($value.Value -isnot [string] -and $value.Value -isnot [System.Enum]) -or
                ([string]$value.Value).Trim() -notin 'Modern', 'Legacy') {
                $answer.Detail = 'LabelScheme returned an unreadable or unrecognized value. It is not treated as Legacy or Modern; confirm in the portal.'
                return $answer
            }
            $reported = ([string]$value.Value).Trim()
        }
    }

    $groupCount = 0; $legacyCount = 0; $unknownTypes = 0
    $nodes = @{}
    if ($proof.ContainsKey('SensitivityLabel')) {
        $structureKnown = $true
        foreach ($label in $proof['SensitivityLabel']) {
            $identity = & $field $label 'Guid'
            $parent = & $field $label 'ParentId'
            $marker = & $field $label 'IsLabelGroup'
            $id = [guid]::Empty; $parentId = [guid]::Empty; $parentKey = ''
            if (($identity.Value -isnot [string] -and $identity.Value -isnot [guid]) -or
                -not [guid]::TryParse([string]$identity.Value, [ref]$id) -or $id -eq [guid]::Empty -or
                $nodes.ContainsKey($id.ToString('D')) -or -not $parent.Present) { $structureKnown = $false; break }
            if ($null -ne $parent.Value -and -not ($parent.Value -is [string] -and [string]::IsNullOrWhiteSpace($parent.Value))) {
                if (($parent.Value -isnot [string] -and $parent.Value -isnot [guid]) -or
                    -not [guid]::TryParse([string]$parent.Value, [ref]$parentId) -or $parentId -eq [guid]::Empty) { $structureKnown = $false; break }
                $parentKey = $parentId.ToString('D')
            }
            $isGroup = $null; $parsed = $false
            if (($marker.Value -is [bool] -or $marker.Value -is [string]) -and
                [bool]::TryParse(([string]$marker.Value).Trim(), [ref]$parsed)) { $isGroup = $parsed }
            else { $unknownTypes++ }
            if ($isGroup -eq $true) {
                $groupCount++
                if ($parentKey) { $structureKnown = $false; break }
            }
            $nodes[$id.ToString('D')] = [pscustomobject]@{ Parent = $parentKey; IsGroup = $isGroup }
        }
        $parents = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($node in $nodes.Values) {
            if (-not $node.Parent) { continue }
            if (-not $nodes.ContainsKey($node.Parent) -or $nodes[$node.Parent].Parent) { $structureKnown = $false; break }
            $null = $parents.Add($node.Parent)
        }
        if (-not $structureKnown) {
            $answer.Detail = 'Label identities or parent relationships are incomplete, duplicated or inconsistent. Confirm the scheme in the portal.'
            return $answer
        }
        foreach ($parentId in $parents) { if ($nodes[$parentId].IsGroup -eq $false) { $legacyCount++ } }
    }

    if ($readState.Ambiguous) {
        $answer.Detail = 'Case-variant duplicate fields make the label-scheme evidence ambiguous. Confirm in the portal.'
        return $answer
    }
    if (($groupCount -gt 0 -and $legacyCount -gt 0) -or ($reported -eq 'Modern' -and $legacyCount -gt 0) -or
        ($reported -eq 'Legacy' -and $groupCount -gt 0)) {
        $answer.Detail = 'The reported scheme and label-group metadata conflict, or both legacy parents and label groups were returned. Confirm current state in the portal before planning migration.'
        return $answer
    }
    if ($reported -eq 'Modern') {
        $answer.State = 'As recommended'; $answer.Scheme = 'Modern'
        $answer.Detail = 'The tenant reports the modern label scheme. This does not establish a migration history.'
    }
    elseif ($reported -eq 'Legacy') {
        $answer.State = 'Needs attention'; $answer.Scheme = 'Legacy'
        $answer.Detail = 'The tenant reports LabelScheme = Legacy. Review migration availability and the proposed new scheme in the portal; this is not an automatic fix.'
    }
    elseif ($nodes.Count -gt 0 -and $unknownTypes -eq 0 -and $legacyCount -gt 0) {
        $answer.State = 'Needs attention'; $answer.Scheme = 'Legacy'
        $answer.Detail = 'Legacy parent labels detected: {0} GUID-linked parents are explicitly not label groups. Review migration availability and the proposed new scheme in the portal.' -f $legacyCount
    }
    elseif ($nodes.Count -gt 0 -and $unknownTypes -eq 0 -and $groupCount -gt 0) {
        $answer.State = 'As recommended'; $answer.Scheme = 'Modern'
        $answer.Detail = 'Label groups are explicitly identified in the complete label list, with no legacy parent labels. This does not establish migration history.'
    }
    elseif ($nodes.Count -gt 0) {
        $answer.Detail = 'The returned labels do not establish the scheme. Standalone labels and missing group markers do not prove Legacy or Modern; confirm in the portal.'
    }
    return $answer
}

function Get-PurviewLabelActivitySignal {
    <#
    .SYNOPSIS
        Validates the count and completion metadata behind the recent label-application signal.

    .DESCRIPTION
        Snapshot files can be old, hand-edited or damaged. PowerShell casts a missing number to
        zero and the string "False" to True, so neither is accepted here. A count is usable only
        when its value, window, source and source-specific completion fields agree.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Data)

    $reportedReason = [string](Get-PurviewProperty -InputObject $Data -Name 'LabelEventCountReason')
    $filteredValue = Get-PurviewProperty -InputObject $Data -Name 'LabelEventsFiltered'
    $truncatedValue = Get-PurviewProperty -InputObject $Data -Name 'Truncated'
    $notReturned = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Data -Name 'PropertiesNotReturned'))

    $legacyReason = ''
    if ($filteredValue -is [bool] -and -not [bool]$filteredValue -and $notReturned -contains 'Activity') {
        $legacyReason = 'Activity Explorer returned events without naming the activity, and no complete filtered count was available.'
    }
    elseif ($filteredValue -is [bool] -and -not [bool]$filteredValue -and
        $truncatedValue -is [bool] -and [bool]$truncatedValue) {
        $legacyReason = 'More activity was available than the full scan read, and no complete filtered count was available, so any number would be only a fraction of the real one.'
    }

    $answer = [ordered]@{
        Reliable = $false
        Count = [long]0
        WindowDays = 0
        Filtered = $false
        Source = 'None'
        Reason = if ($legacyReason) { $legacyReason }
        elseif ($reportedReason) { $reportedReason }
        else { 'The snapshot does not establish that pagination and sensitivity-label classification completed.' }
    }

    if ($null -eq $Data) { return [pscustomobject]$answer }

    $readNonNegative = {
        param($inputObject, [string]$name)
        $raw = Get-PurviewProperty -InputObject $inputObject -Name $name
        $parsed = [long]0
        $valid = (Test-PurviewProperty -InputObject $inputObject -Name $name) -and $null -ne $raw -and
            [long]::TryParse([string]$raw, [System.Globalization.NumberStyles]::Integer,
                [cultureinfo]::InvariantCulture, [ref]$parsed)
        if ($valid -and $parsed -lt 0) { $valid = $false }
        [pscustomobject]@{ Valid = $valid; Value = $parsed }
    }

    # The window describes what was requested and remains useful even when the count itself is
    # withheld. Validate it independently so an incomplete query still keeps its truthful heading.
    $window = & $readNonNegative $Data 'WindowDays'
    if ($window.Valid -and $window.Value -ge 1 -and $window.Value -le 30) {
        $answer.WindowDays = [int]$window.Value
    }

    $reliableValue = Get-PurviewProperty -InputObject $Data -Name 'LabelApplyEventsReliable'
    if ($reliableValue -isnot [bool]) {
        $answer.Reason = 'The snapshot has no valid Boolean reliability marker for the sensitivity-label application count.'
        return [pscustomobject]$answer
    }
    if (-not [bool]$reliableValue) { return [pscustomobject]$answer }

    $count = & $readNonNegative $Data 'LabelApplyEvents'
    if (-not $count.Valid) {
        $answer.Reason = 'The snapshot marks the sensitivity-label application count reliable, but the count is missing, malformed or negative.'
        return [pscustomobject]$answer
    }

    if (-not $window.Valid -or $window.Value -lt 1 -or $window.Value -gt 30) {
        $answer.Reason = 'The snapshot marks the sensitivity-label application count reliable, but its activity window is missing, malformed or outside 1 to 30 days.'
        return [pscustomobject]$answer
    }

    $source = [string](Get-PurviewProperty -InputObject $Data -Name 'LabelEventsSource')
    $metadataValid = $false
    if ($source -eq 'FilteredQuery') {
        $querySucceeded = Get-PurviewProperty -InputObject $Data -Name 'LabelQuerySucceeded'
        $queryComplete = Get-PurviewProperty -InputObject $Data -Name 'LabelQueryComplete'
        $queryTruncated = Get-PurviewProperty -InputObject $Data -Name 'LabelQueryTruncated'
        $missingActivity = & $readNonNegative $Data 'LabelRowsMissingActivity'
        $ambiguous = & $readNonNegative $Data 'LabelApplyRowsAmbiguous'
        $metadataValid = $filteredValue -is [bool] -and [bool]$filteredValue -and
            $querySucceeded -is [bool] -and [bool]$querySucceeded -and
            $queryComplete -is [bool] -and [bool]$queryComplete -and
            $queryTruncated -is [bool] -and -not [bool]$queryTruncated -and
            $missingActivity.Valid -and $missingActivity.Value -eq 0 -and
            $ambiguous.Valid -and $ambiguous.Value -eq 0
    }
    elseif ($source -eq 'FullScan') {
        $scanComplete = Get-PurviewProperty -InputObject $Data -Name 'ActivityScanComplete'
        $metadataValid = $filteredValue -is [bool] -and -not [bool]$filteredValue -and
            $scanComplete -is [bool] -and [bool]$scanComplete -and
            $truncatedValue -is [bool] -and -not [bool]$truncatedValue -and
            $notReturned -notcontains 'Activity'
    }

    if (-not $metadataValid) {
        $answer.Reason = 'The snapshot marks the sensitivity-label application count reliable, but its source or completion metadata is missing, malformed or inconsistent.'
        return [pscustomobject]$answer
    }

    $answer.Reliable = $true
    $answer.Count = [long]$count.Value
    $answer.WindowDays = [int]$window.Value
    $answer.Filtered = ($source -eq 'FilteredQuery')
    $answer.Source = $source
    return [pscustomobject]$answer
}

#endregion

#region Posture history
# Posture records include tenant/run metadata, finding summaries and prerequisite states, but not
# the full snapshot. Treat them as sensitive and apply an appropriate retention/access policy.

$script:PostureRank = @{ Fail = 0; Warning = 1; Pass = 2 }
$script:PostureUndetermined = @('NeedsReview', 'NotCollected', 'Unsupported', 'NotLicensed')
# Opt-ins are not rules and carry their own vocabulary, but they move the same way. Without them a
# switch someone turned on reads as nothing having moved, because no finding covers it.
$script:PostureOptInRank = @{ 'Needs attention' = 0; 'Granted' = 2; 'As recommended' = 2 }
$script:PostureOptInUndetermined = @('Confirm in portal', 'Not read', 'Seen recently', 'Evidence found', 'In use')

function ConvertTo-PurviewPostureRecord {
    <# .SYNOPSIS Reduces a run to the outcomes needed to compare it with another run. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $Finding = @(Get-PurviewCustomerFinding -Finding $Finding)
    $zone = Get-PurviewTimeZoneContext
    $summary = [ordered]@{}
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotCollected', 'Unsupported', 'NotLicensed') {
        $summary[$status] = @($Finding | Where-Object { $_.status -eq $status }).Count
    }

    return [pscustomobject]@{
        postureVersion = '1.0'
        recordedAt = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)
        toolVersion = $script:ToolVersion
        recordedTimeZone = [pscustomobject]@{ id = $zone.Id; offsetAtCapture = $zone.CurrentOffset }
        mode = [string](Get-PurviewProperty -InputObject $Snapshot -Name 'mode')
        tenant = Get-PurviewProperty -InputObject $Snapshot -Name 'tenant'
        snapshotCapturedAt = [string](Get-PurviewProperty -InputObject $Snapshot -Name 'capturedAt')
        summary = [pscustomobject]$summary
        maturity = @(Get-PurviewDeploymentMaturity -Finding $Finding | ForEach-Object {
                [pscustomobject]@{ model = $_.Model; passingSteps = $_.PassingSteps; checkedSteps = $_.CheckedSteps }
            })
        findings = @($Finding | ForEach-Object {
                [pscustomobject]@{
                    ruleId = [string](Get-PurviewProperty -InputObject $_ -Name 'ruleId')
                    ruleVersion = [string](Get-PurviewProperty -InputObject $_ -Name 'ruleVersion')
                    title = [string](Get-PurviewProperty -InputObject $_ -Name 'title')
                    solutionArea = [string](Get-PurviewProperty -InputObject $_ -Name 'solutionArea')
                    status = [string](Get-PurviewProperty -InputObject $_ -Name 'status')
                    severity = [string](Get-PurviewProperty -InputObject $_ -Name 'severity')
                }
            })
        prerequisites = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding | ForEach-Object {
                [pscustomobject]@{ name = [string]$_.Name; state = [string]$_.State }
            })
    }
}

function Get-PurviewDefaultRecordFolder {
    <# .SYNOPSIS Where posture records go when you have not said. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # Per-user application data, so a comparison works wherever the script is run from.
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    return (Join-Path $base 'PurviewAdvisor/posture')
}

function Save-PurviewPostureRecord {
    <# .SYNOPSIS Writes a posture record into the history folder. #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$Folder
    )

    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
        if (-not $PSCmdlet.ShouldProcess($Folder, 'Create posture history folder')) { return '' }
        $null = New-Item -ItemType Directory -Path $Folder -Force
    }

    $stamp = (ConvertFrom-PurviewTimestamp -Value $Record.recordedAt | ConvertTo-PurviewLocalTimestamp).ToString('yyyyMMdd-HHmmss')
    $json = $Record | ConvertTo-Json -Depth 100
    $encoding = [System.Text.UTF8Encoding]::new($false)

    # A timestamp has one-second precision. Reserve the destination atomically so concurrent or
    # rapid runs never overwrite an earlier posture record carrying the same timestamp.
    for ($counter = 0; $counter -lt 1000; $counter++) {
        $suffix = if ($counter -eq 0) { '' } else { '-{0:D3}' -f $counter }
        $path = Join-Path $Folder "posture-$stamp$suffix.json"
        if (-not $PSCmdlet.ShouldProcess($path, 'Write posture record')) { return '' }

        $stream = $null
        try {
            $stream = [System.IO.FileStream]::new(
                $path,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            if (Test-Path -LiteralPath $path) { continue }
            throw
        }

        $writer = $null
        $failure = $null
        try {
            $writer = [System.IO.StreamWriter]::new($stream, $encoding)
            $writer.WriteLine($json)
            $writer.Flush()
        }
        catch { $failure = $_ }
        finally {
            if ($null -ne $writer) {
                try { $writer.Dispose() }
                catch { if ($null -eq $failure) { $failure = $_ } }
            }
            if ($null -ne $stream) {
                try { $stream.Dispose() }
                catch { if ($null -eq $failure) { $failure = $_ } }
            }
        }

        if ($null -ne $failure) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $path) {
                throw "Writing the posture record failed, and the partial file could not be removed: $path"
            }
            throw $failure
        }
        return $path
    }

    throw "Could not reserve a unique posture record name for $stamp."
}

function Get-PurviewPostureHistory {
    <# .SYNOPSIS Reads saved posture records oldest first, skipping any that will not parse. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][string]$Folder)

    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return @() }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -Filter 'posture-*.json' -File | Sort-Object Name)) {
        try {
            $record = Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100
            $record | Add-Member -NotePropertyName 'sourcePath' -NotePropertyValue $file.FullName -Force
            $records.Add($record)
        }
        catch {
            Write-Verbose "Skipping unreadable posture record $($file.Name): $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }
    }

    return $records.ToArray()
}

function Test-PurviewBaselineMatch {
    <# .SYNOPSIS Reports whether an earlier record describes the same thing as this run. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Candidate,
        [Parameter(Mandatory)][object]$Current
    )

    if ($null -eq $Candidate) { return $false }

    $mode = [string](Get-PurviewProperty -InputObject $Current -Name 'mode')
    if ([string](Get-PurviewProperty -InputObject $Candidate -Name 'mode') -ne $mode) { return $false }

    $tenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Current -Name 'tenant') -Name 'tenantId')
    $candidateTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Candidate -Name 'tenant') -Name 'tenantId')

    # A live run describes a real tenant, so an earlier record has to prove it describes the same
    # one: a record that names no tenant could have come from any of them. Synthetic and replayed
    # runs never name a tenant, and holding them to this would leave them unable to compare at all.
    if ($mode -eq 'LiveTenant') {
        return [bool]($tenant -and $candidateTenant -and $tenant -eq $candidateTenant)
    }
    return -not ($tenant -and $candidateTenant -and $tenant -ne $candidateTenant)
}

function Find-PurviewBaselineRecord {
    <#
    .SYNOPSIS
        Finds the most recent comparable record without reading the whole history.

    .DESCRIPTION
        Read files newest first and stop at the first comparable record to avoid parsing the
        whole history on each run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][object]$Current
    )

    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return $null }

    # The name carries the timestamp, so sorting it descending is newest first without reading any.
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -Filter 'posture-*.json' -File | Sort-Object Name -Descending)) {
        try {
            $record = Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100
            $record | Add-Member -NotePropertyName 'sourcePath' -NotePropertyValue $file.FullName -Force
            if (Test-PurviewBaselineMatch -Candidate $record -Current $Current) { return $record }
        }
        catch {
            Write-Verbose "Skipping unreadable posture record $($file.Name): $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        }
    }

    return $null
}

function Get-PurviewComparableBaseline {
    <#
    .SYNOPSIS
        Selects the most recent earlier record comparable with this run.

    .DESCRIPTION
        History may include demo runs and other tenants. Skip incompatible records rather than
        rejecting the comparison because the newest record is unsuitable.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$History,
        [Parameter(Mandatory)][object]$Current
    )

    for ($index = $History.Count - 1; $index -ge 0; $index--) {
        if (Test-PurviewBaselineMatch -Candidate $History[$index] -Current $Current) { return $History[$index] }
    }

    return $null
}

function Compare-PurviewPosture {
    <#
    .SYNOPSIS
        Separates assessed outcome changes from changes in evidence or rule versions.

    .DESCRIPTION
        Only changes between assessed outcomes count as progress or regression. Unread rules,
        new rules and rule-version changes are classified separately and excluded from the score.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Baseline,
        [Parameter(Mandatory)][object]$Current,
        [switch]$AcrossTenants
    )

    $comparable = $true
    $blocker = ''
    $crossTenant = $false

    if ($null -eq $Baseline) {
        $comparable = $false
        $blocker = 'No earlier posture record was found. This run can be a future baseline if it is saved.'
    }
    else {
        $baseMode = [string](Get-PurviewProperty -InputObject $Baseline -Name 'mode')
        $thisMode = [string](Get-PurviewProperty -InputObject $Current -Name 'mode')
        $baseTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Baseline -Name 'tenant') -Name 'tenantId')
        $thisTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Current -Name 'tenant') -Name 'tenantId')
        $differentTenant = $baseTenant -and $thisTenant -and $baseTenant -ne $thisTenant
        # Between two live runs, not knowing the tenant is as disqualifying as knowing it differs.
        $unproven = $thisMode -eq 'LiveTenant' -and (-not $baseTenant -or -not $thisTenant)

        if ($baseMode -ne $thisMode) {
            $comparable = $false
            $blocker = "The baseline was captured in $baseMode mode and this run is $thisMode, so the two describe different things."
        }
        elseif ($unproven -and -not $AcrossTenants) {
            $comparable = $false
            $blocker = 'The baseline does not say which tenant it came from, so there is no way to tell whether it describes this one.'
        }
        elseif ($differentTenant -and -not $AcrossTenants) {
            $comparable = $false
            $blocker = 'The baseline belongs to a different tenant, so comparing them would be meaningless.'
        }
        elseif ($differentTenant) {
            $crossTenant = $true
        }
    }

    $ruleChanges = [System.Collections.Generic.List[object]]::new()
    $optInChanges = [System.Collections.Generic.List[object]]::new()
    $ignoredBaselineRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($comparable) {
        $before = @{}
        foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Baseline -Name 'findings'))) {
            $id = [string](Get-PurviewProperty -InputObject $item -Name 'ruleId')
            if ([string](Get-PurviewProperty -InputObject $item -Name 'status') -eq 'NotApplicable') {
                if ($id) { $null = $ignoredBaselineRuleIds.Add($id) }
                continue
            }
            $before[$id] = $item
        }

        foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Current -Name 'findings'))) {
            $id = [string](Get-PurviewProperty -InputObject $item -Name 'ruleId')
            $now = [string](Get-PurviewProperty -InputObject $item -Name 'status')
            $title = [string](Get-PurviewProperty -InputObject $item -Name 'title')
            if ($now -eq 'NotApplicable') { continue }

            if (-not $before.ContainsKey($id)) {
                # Older records persisted this internal outcome. A later visible result has no
                # comparable earlier verdict, so the applicability transition is omitted entirely.
                if ($ignoredBaselineRuleIds.Contains($id)) { continue }
                $ruleChanges.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = ''; To = $now; Change = 'New'; Detail = 'This rule has no finding in the selected baseline; it is not necessarily a newly introduced rule.' })
                continue
            }

            $previous = $before[$id]
            $was = [string](Get-PurviewProperty -InputObject $previous -Name 'status')
            $before.Remove($id)

            $wasVersion = [string](Get-PurviewProperty -InputObject $previous -Name 'ruleVersion')
            $nowVersion = [string](Get-PurviewProperty -InputObject $item -Name 'ruleVersion')
            if ($wasVersion -ne $nowVersion) {
                $ruleChanges.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = $was; To = $now; Change = 'RuleChanged'; Detail = "The rule moved from version $wasVersion to $nowVersion, so a difference in outcome may be the rule rather than the tenant." })
                continue
            }

            $change = 'Unchanged'
            $detail = ''

            if ($was -in $script:PostureUndetermined -and $now -in $script:PostureUndetermined) {
                $change = 'Unavailable'
                $detail = 'Could not assess this run.'
            }
            elseif ($now -in $script:PostureUndetermined) {
                $change = 'CouldNotAssess'
                $detail = 'Could not assess this run.'
            }
            elseif ($was -in $script:PostureUndetermined) {
                $change = 'NewlyAssessed'
                $detail = 'This could not be assessed before, so the outcome is new information rather than movement.'
            }
            elseif ($was -eq $now) { $detail = '' }
            elseif ($script:PostureRank[$now] -gt $script:PostureRank[$was]) {
                $change = 'Improved'
            }
            else {
                $change = 'Regressed'
            }

            $ruleChanges.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = $was; To = $now; Change = $change; Detail = $detail })
        }

        foreach ($id in @($before.Keys | Sort-Object)) {
            $previous = $before[$id]
            # A rule still present in this version was omitted from the customer population rather
            # than retired. Do not turn internal applicability or a narrowed run into movement.
            if (@($script:Rules | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'id') -eq $id }).Count -gt 0) { continue }
                $ruleChanges.Add([pscustomobject]@{
                    RuleId = $id
                    Title = [string](Get-PurviewProperty -InputObject $previous -Name 'title')
                    From = [string](Get-PurviewProperty -InputObject $previous -Name 'status')
                    To = ''
                    Change = 'Removed'
                    Detail = 'This rule is no longer evaluated by the script.'
                })
        }

        # A baseline written before opt-ins were recorded holds none, and reporting every one of
        # them as new would bury whatever actually moved.
        $ignoredBaselinePrerequisites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($definition in $script:Prerequisite) {
            if ($definition.ContainsKey('RuleId') -and $ignoredBaselineRuleIds.Contains([string]$definition.RuleId)) {
                $null = $ignoredBaselinePrerequisites.Add([string]$definition.Name)
            }
        }
        $baseOptIn = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Baseline -Name 'prerequisites') |
                Where-Object { -not $ignoredBaselinePrerequisites.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'name')) })
        if ($baseOptIn.Count -gt 0) {
            # A state this comparison cannot rank is undetermined, not a regression.
            $undetermined = {
                param($state)
                $state -in $script:PostureOptInUndetermined -or -not $script:PostureOptInRank.ContainsKey($state)
            }

            $beforeOptIn = @{}
            foreach ($item in $baseOptIn) {
                $beforeOptIn[[string](Get-PurviewProperty -InputObject $item -Name 'name')] = [string](Get-PurviewProperty -InputObject $item -Name 'state')
            }

            foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Current -Name 'prerequisites'))) {
                $name = [string](Get-PurviewProperty -InputObject $item -Name 'name')
                $now = [string](Get-PurviewProperty -InputObject $item -Name 'state')

                if (-not $beforeOptIn.ContainsKey($name)) {
                    $optInChanges.Add([pscustomobject]@{ Name = $name; From = ''; To = $now; Change = 'New'; Detail = 'This opt-in was not tracked when the baseline was taken.' })
                    continue
                }

                $was = $beforeOptIn[$name]
                $beforeOptIn.Remove($name)

                $change = 'Unchanged'
                $detail = ''
                if ((& $undetermined $was) -and (& $undetermined $now)) {
                    $change = 'Unavailable'
                    $detail = 'Could not assess this run.'
                }
                elseif (& $undetermined $now) {
                    $change = 'CouldNotAssess'
                    $detail = 'Could not assess this run.'
                }
                elseif (& $undetermined $was) {
                    $change = 'NewlyAssessed'
                    $detail = 'This could not be read before, so the state is new information rather than movement.'
                }
                elseif ($was -eq $now) { $detail = '' }
                elseif ($script:PostureOptInRank[$now] -gt $script:PostureOptInRank[$was]) { $change = 'Improved' }
                else { $change = 'Regressed' }

                $optInChanges.Add([pscustomobject]@{ Name = $name; From = $was; To = $now; Change = $change; Detail = $detail })
            }

            foreach ($name in @($beforeOptIn.Keys | Sort-Object)) {
                $optInChanges.Add([pscustomobject]@{ Name = $name; From = $beforeOptIn[$name]; To = ''; Change = 'Removed'; Detail = 'This opt-in is no longer reported by the script.' })
            }
        }
    }

    $summarise = {
        param([AllowEmptyCollection()][object[]]$Item)
        $count = { param($name) @($Item | Where-Object { $_.Change -eq $name }).Count }
        [pscustomobject]@{
            Improved = (& $count 'Improved')
            Regressed = (& $count 'Regressed')
            Unchanged = (& $count 'Unchanged')
            CouldNotAssess = (& $count 'CouldNotAssess')
            Unavailable = (& $count 'Unavailable')
            NewlyAssessed = (& $count 'NewlyAssessed')
            RuleChanged = (& $count 'RuleChanged')
            New = (& $count 'New')
            Removed = (& $count 'Removed')
            Changes = @($Item)
        }
    }

    return [pscustomobject]@{
        Comparable = $comparable
        Blocker = $blocker
        CrossTenant = $crossTenant
        BaselineRecordedAt = if ($null -eq $Baseline) { '' } else { [string](Get-PurviewProperty -InputObject $Baseline -Name 'recordedAt') }
        CurrentRecordedAt = [string](Get-PurviewProperty -InputObject $Current -Name 'recordedAt')
        RuleMovement = & $summarise @($ruleChanges)
        OptInMovement = & $summarise @($optInChanges)
        Maturity = @(Compare-PurviewMaturity -Baseline $Baseline -Current $Current)
    }
}

function Compare-PurviewMaturity {
    <# .SYNOPSIS Compares deployment coverage, refusing to compare over a different set of checks. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Baseline,
        [Parameter(Mandatory)][object]$Current
    )

    if ($null -eq $Baseline) { return @() }

    $before = @{}
    foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Baseline -Name 'maturity'))) {
        $before[[string](Get-PurviewProperty -InputObject $item -Name 'model')] = $item
    }

    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Current -Name 'maturity'))) {
        $model = [string](Get-PurviewProperty -InputObject $item -Name 'model')
        if (-not $before.ContainsKey($model)) { continue }

        # History is persisted JSON and can be old, edited or truncated. Direct casts would turn
        # null into zero and some malformed strings into numbers, fabricating a maturity change.
        $nowValue = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $item -Name 'passingSteps')
        $wasValue = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $before[$model] -Name 'passingSteps')
        $nowCheckedValue = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $item -Name 'checkedSteps')
        $wasCheckedValue = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $before[$model] -Name 'checkedSteps')

        $now = if ($nowValue.Valid) { [long]$nowValue.Value } else { $null }
        $was = if ($wasValue.Valid) { [long]$wasValue.Value } else { $null }
        $nowChecked = if ($nowCheckedValue.Valid) { [long]$nowCheckedValue.Value } else { $null }
        $wasChecked = if ($wasCheckedValue.Valid) { [long]$wasCheckedValue.Value } else { $null }

        # Steps passing means nothing across a different number of checked steps.
        $detail = if ($null -eq $now -or $null -eq $was -or $null -eq $nowChecked -or $null -eq $wasChecked) {
            'Not measured with usable counts in both runs.'
        }
        elseif ($now -gt $nowChecked -or $was -gt $wasChecked) {
            'A passing-step total exceeded its checked-step total, so the two runs are not comparable.'
        }
        elseif ($nowChecked -ne $wasChecked) { "Checked steps changed from $wasChecked to $nowChecked, so the two are not comparable." }
        else { '' }

        $output.Add([pscustomobject]@{
                Model = $model
                From = $was
                To = $now
                Delta = if ($detail) { $null } else { $now - $was }
                Detail = $detail
            })
    }

    return $output.ToArray()
}

#endregion

#region Reporting

function ConvertTo-PurviewEncodedText {
    <# .SYNOPSIS HTML-encodes a value so tenant data can never become markup. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Value)
}

function Get-PurviewDeploymentMaturity {
    <#
    .SYNOPSIS
        Reports how far the checks that exist get through each Microsoft Purview deployment model.

    .DESCRIPTION
        Reports steps checked and passing, not a model-completion percentage: most steps have
        one rule or none. Steps with only uncollectable or unlicensed rules do not pass;
        missing evidence or licensing does not establish implementation.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    # Step counts and titles confirmed from the deployment model pages on 2026-08-21. The two models
    # no rule maps to yet carry counts only, so a rule tagged against them still finds a home, and
    # no Url because Microsoft has not published one under the slug the others follow.
    $models = [ordered]@{
        'secure-by-default' = @{
            Name = 'Secure by default with Microsoft Purview'; Steps = 4
            Url = "$script:DeploymentModelRoot/depmod-secure-by-default-intro"
            Titles = @(
                'Start with default labeling'
                'Address files with the highest sensitivity'
                'Expand protection to your entire Microsoft 365 data estate'
                'Operate, expand, and retroactive actions'
            )
        }
        'shadow-ai' = @{ Name = 'Prevent data leak to shadow AI'; Steps = 4; Url = ''; Titles = @() }
        'copilot-agents' = @{ Name = 'Secure and govern Microsoft 365 Copilot agents'; Steps = 4; Url = ''; Titles = @() }
        'dspm' = @{
            Name = 'Deploy and use Data Security Posture Management'; Steps = 4
            Url = "$script:DeploymentModelRoot/depmod-dspm-intro"
            Titles = @(
                'Establish foundational elements'
                'Configure access and analytics'
                'Understand data landscape and risks'
                'Take action and investigate with Security Copilot'
            )
        }
        'lightweight-dlp' = @{
            Name = 'Lightweight guide to mitigate data leakage'; Steps = 3
            Url = "$script:DeploymentModelRoot/depmod-lightweight-dlp-intro"
            Titles = @(
                'Establish foundational data security'
                'Expand protection to endpoints'
                'Continuous improvement'
            )
        }
    }

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($id in $models.Keys) {
        # Omit models with no mapped rules; they describe assessment scope, not tenant posture.
        $mapped = @($script:Rules | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'deploymentModel') -like "$id step *" })
        if ($mapped.Count -eq 0) { continue }

        $steps = [System.Collections.Generic.List[object]]::new()
        $passing = 0
        $checked = 0
        $currentStep = $null

        for ($number = 1; $number -le $models[$id].Steps; $number++) {
            $tag = "$id step $number"
            $contributing = @($Finding | Where-Object {
                    [string](Get-PurviewProperty -InputObject $_ -Name 'status') -ne 'NotApplicable' -and
                    [string](Get-PurviewProperty -InputObject $_ -Name 'deploymentModel') -eq $tag
                })

            $passed = @($contributing | Where-Object { $_.status -eq 'Pass' }).Count
            $failed = @($contributing | Where-Object { $_.status -eq 'Fail' }).Count
            $warned = @($contributing | Where-Object { $_.status -eq 'Warning' }).Count
            $assessed = $passed + $failed + $warned

            # Keep warning-only steps distinct from failures to preserve rule severity.
            $unlicensed = @($contributing | Where-Object { $_.status -eq 'NotLicensed' }).Count
            $state = if ($contributing.Count -eq 0) { 'NoChecks' }
            elseif ($unlicensed -eq $contributing.Count) { 'NotLicensed' }
            elseif ($assessed -eq 0) { 'NotAssessed' }
            elseif ($passed -eq $assessed) { 'ChecksPass' }
            elseif ($passed -gt 0) { 'Partial' }
            elseif ($failed -eq 0) { 'ChecksWarn' }
            else { 'ChecksFail' }

            $plural = if ($assessed -eq 1) { 'check' } else { 'checks' }
            $verdict = switch ($state) {
                'NoChecks' { 'No check covers this step' }
                'NotLicensed' { 'Not available with current licensing' }
                'NotAssessed' { 'Not assessed, the data was not collected' }
                'ChecksPass' { "$assessed $plural passed" }
                'Partial' { "$passed of $assessed checks passed" }
                'ChecksWarn' { "$assessed $plural to review" }
                default { "$assessed $plural failed" }
            }

            if ($state -in 'ChecksPass', 'Partial', 'ChecksWarn', 'ChecksFail') {
                $checked++
                if ($state -eq 'ChecksPass') { $passing++ }
                elseif ($null -eq $currentStep) { $currentStep = $number }
            }

            $titles = @($models[$id].Titles)
            $steps.Add([pscustomobject]@{
                    Step = $number
                    Title = if ($number -le $titles.Count) { $titles[$number - 1] } else { '' }
                    State = $state
                    Verdict = $verdict
                    # Named so a reader can join a step back to the checks it was scored from.
                    RuleIds = @($contributing | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'ruleId') } | Sort-Object)
                    RuleCount = $contributing.Count
                    Passed = $passed
                    Assessed = $assessed
                })
        }

        $output.Add([pscustomobject]@{
                Model = $id
                Name = $models[$id].Name
                Url = [string]$models[$id].Url
                CheckedSteps = $checked
                PassingSteps = $passing
                TotalSteps = $models[$id].Steps
                CurrentStep = $currentStep
                Steps = $steps.ToArray()
            })
    }

    return $output.ToArray()
}

function Get-PurviewChecklist {
    <#
    .SYNOPSIS
        Turns findings into a checklist of what is done and what is left.

    .DESCRIPTION
        Ordered so the list can be worked top down: outstanding items first, highest severity first,
        and one-command fixes ahead of the rest at equal severity. Items that cannot be judged are
        kept separate from items that are done, so progress is never overstated.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Finding) {
        $status = [string](Get-PurviewProperty -InputObject $item -Name 'status')
        if ($status -eq 'NotApplicable') { continue }
        $hasCommand = [bool]$item.PSObject.Properties['remediationCommand']

        $group, $marker, $action = switch ($status) {
            'Pass' { 'Done', 'x', 'This check passed for the collected evidence.'; break }
            'Fail' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'Warning' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'NeedsReview' { 'To check by hand', '?', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'NotLicensed' { 'Not available - licensing', '-', [string](Get-PurviewProperty -InputObject $item -Name 'reason'); break }
            default { 'Not checked', '?', [string](Get-PurviewProperty -InputObject $item -Name 'reason') }
        }

        $severity = [string](Get-PurviewProperty -InputObject $item -Name 'severity')
        $tier = [string](Get-PurviewProperty -InputObject $item -Name 'tier')
        $output.Add([pscustomobject]@{
                Group = $group
                Marker = $marker
                RuleId = [string](Get-PurviewProperty -InputObject $item -Name 'ruleId')
                Title = [string](Get-PurviewProperty -InputObject $item -Name 'title')
                SolutionArea = [string](Get-PurviewProperty -InputObject $item -Name 'solutionArea')
                Solution = [string](Get-PurviewProperty -InputObject $item -Name 'solution')
                Severity = $severity
                Tier = $tier
                Action = $action
                # Suppress fixes for passing checks to avoid recommending unnecessary changes.
                Command = if ($hasCommand -and $group -eq 'To do') { [string]$item.remediationCommand } else { '' }
                GroupOrder = switch ($group) { 'To do' { 0 } 'To check by hand' { 1 } 'Done' { 2 } 'Not available - licensing' { 3 } 'Not checked' { 4 } default { 5 } }
                SeverityOrder = Get-PurviewSeverityOrder -Severity $severity
                # Within a severity, work from the licence the customer already owns outwards.
                TierOrder = Get-PurviewTierOrder -Tier $tier
                CommandOrder = if ($hasCommand) { 0 } else { 1 }
            })
    }

    return @($output | Sort-Object GroupOrder, SeverityOrder, TierOrder, CommandOrder, RuleId)
}

function Get-PurviewChecklistProgress {
    <# .SYNOPSIS Counts progress over the items that could actually be judged. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Checklist)

    # Count only items with a verdict so unchecked items cannot inflate progress.
    $done = @($Checklist | Where-Object { $_.Group -eq 'Done' }).Count
    $todo = @($Checklist | Where-Object { $_.Group -eq 'To do' }).Count
    $manual = @($Checklist | Where-Object { $_.Group -eq 'To check by hand' }).Count
    $judged = $done + $todo + $manual

    return [pscustomobject]@{
        Done = $done
        ToDo = $todo
        ToCheck = $manual
        Judged = $judged
        NotChecked = @($Checklist | Where-Object { $_.Group -eq 'Not checked' }).Count
        NotLicensed = @($Checklist | Where-Object { $_.Group -eq 'Not available - licensing' }).Count
        Percent = if ($judged -gt 0) { [math]::Round(($done / $judged) * 100) } else { $null }
    }
}

function Get-PurviewCollectorItem {
    <# .SYNOPSIS Returns one collector's items, or an empty set if no single usable result exists. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Select
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    if ($matched.Count -ne 1) { return @() }
    if ([string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') { return @() }

    return @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name $Select))
}

function Get-PurviewCollectorValue {
    <# .SYNOPSIS Returns one scalar from a collector's data, or null if no single usable result exists. #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Select
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    if ($matched.Count -ne 1) { return $null }
    if ([string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') { return $null }

    return Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name $Select
}

function Test-PurviewCollectorRan {
    <# .SYNOPSIS Reports whether exactly one collector result returned usable data. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    return ($matched.Count -eq 1 -and [string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -in 'Success', 'PartialSuccess')
}

function Get-PurviewCollectorReason {
    <# .SYNOPSIS Says why a collector produced nothing, in the words the service used. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    if ($matched.Count -eq 0) {
        # Optional reads are absent by choice rather than by failure, and saying which switch would
        # have collected them is more use than reporting the area as out of scope.
        switch ($Collector) {
            'ProtectionActivity' { return 'Activity was not read this run. Include the relevant solution scope and omit -SkipInsights to request it.' }
            'ClassificationCoverage' { return 'No explicitly requested sensitive information type count was included in this run.' }
            'SharePointSite' { return 'Sites were not enumerated. Pass -IncludeSites to walk them.' }
            default { return 'No result was recorded for this area in this run.' }
        }
    }
    if ($matched.Count -gt 1) {
        return "$Collector returned duplicate collector results, so no single result is authoritative."
    }

    $errors = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'errors'))
    if ($errors.Count -gt 0) { return [string](Get-PurviewProperty -InputObject $errors[0] -Name 'message') }

    $limitations = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'limitations'))
    if ($limitations.Count -gt 0) { return [string]$limitations[0] }

    return 'No detail was returned.'
}

function Get-PurviewWorkloadCoverage {
    <#
    .SYNOPSIS
        Reports configured workload locations named by the returned policies.

    .DESCRIPTION
        Policy counts and workload names do not verify effective coverage. Missing workload
        fields limit completeness; other policies or controls may apply outside these locations.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policy)

    $evidence = @($Policy | ForEach-Object {
            [pscustomobject]@{
                Policy = $_
                Endpoint = Get-PurviewEndpointDlpScopeSignal -Policy $_
            }
        })
    $known = @($evidence | Where-Object {
            (Test-PurviewProperty -InputObject $_.Policy -Name 'Workload') -or $_.Endpoint.State -ne 'Unknown'
        })
    if ($known.Count -eq 0) {
        return [pscustomobject]@{ Known = $false; Covered = @(); Detail = '' }
    }

    # The service answers with its own identifiers. DynamicScope is not a workload at all, it marks
    # a policy scoped adaptively, so counting it would overstate what the policies actually reach.
    $friendly = @{
        'OneDriveForBusiness' = 'OneDrive'
        'ModernGroup' = 'Microsoft 365 Groups'
        'PublicFolder' = 'Exchange public folders'
        'MicrosoftTeams' = 'Teams'
        'EndpointDevices' = 'Devices'
    }
    # DynamicScope marks a policy scoped adaptively rather than a workload it reaches, and Skype for
    # Business Online is retired, so neither belongs in a count of what the policies cover today.
    $notAWorkload = @('DynamicScope', 'Skype')

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $known) {
        $item = $entry.Policy
        $raw = Get-PurviewProperty -InputObject $item -Name 'Workload'
        # The service returns this as a comma-separated string in some shapes and a list in others.
        $names = if ($raw -is [string]) { $raw -split ',' } else { @(ConvertTo-PurviewArray -InputObject $raw) }
        foreach ($name in $names) {
            $trimmed = ([string]$name).Trim()
            if (-not $trimmed -or $trimmed -in $notAWorkload) { continue }
            $null = $seen.Add($(if ($friendly.ContainsKey($trimmed)) { $friendly[$trimmed] } else { $trimmed }))
        }
        if ($entry.Endpoint.State -eq 'Included') { $null = $seen.Add('Devices') }
    }

    $covered = @($seen | Sort-Object)
    return [pscustomobject]@{
        Known = $true
        Covered = $covered
        Detail = if ($covered.Count -gt 0) { 'Configured locations: ' + ($covered -join ', ') } else { 'No workload was named on any of them' }
    }
}

function Get-PurviewOcrConfigurationSignal {
    <# .SYNOPSIS Classifies one privacy-safe OCR configuration record without guessing. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Configuration,
        [switch]$AllowLegacy
    )

    if ($null -eq $Configuration) {
        return [pscustomobject]@{ State = 'unknown'; Locations = @() }
    }

    $signals = [System.Collections.Generic.List[string]]::new()
    $usable = $true

    # These fields were added after the original snapshot shape. If any is present, all are needed:
    # Enabled says what was requested, while validity and usage blockage say whether it is usable.
    $modernFields = @('Enabled', 'IsValid', 'IsOcrUsageBlocked')
    $modern = @($modernFields | Where-Object { Test-PurviewProperty -InputObject $Configuration -Name $_ }).Count -gt 0
    if (-not $modern -and -not $AllowLegacy) { $usable = $false }
    if ($modern) {
        $booleans = @{}
        foreach ($name in $modernFields) {
            if (-not (Test-PurviewProperty -InputObject $Configuration -Name $name)) {
                $usable = $false
                continue
            }

            $raw = Get-PurviewProperty -InputObject $Configuration -Name $name
            $parsed = $false
            if ($null -eq $raw -or -not [bool]::TryParse([string]$raw, [ref]$parsed)) {
                $usable = $false
                continue
            }
            $booleans[$name] = $parsed
        }

        if ($booleans.Count -eq $modernFields.Count) {
            if (-not $booleans['IsValid'] -or $booleans['IsOcrUsageBlocked']) { $usable = $false }
            if ($booleans['Enabled']) { $signals.Add('on') } else { $signals.Add('off') }
        }
    }

    # Current records use the values observed behind the portal and through its PowerShell cmdlet.
    # The direct cmdlet can project OcrMode as None for the same enabled record the portal projects
    # as Active. None is therefore neutral, never an on or off signal: Enabled and Mode must still
    # agree, and the validity, blockage and workload checks still apply. Pre-1.61.0 snapshots retained
    # only these two fields and used Enabled/Disabled for OcrMode. Unknown text is always uncertainty;
    # substring matching would turn future modes into lies.
    $modes = if ($modern) {
        @(
            [pscustomobject]@{ Name = 'Mode'; On = @('Enable'); Off = @('Disable'); Neutral = @() }
            [pscustomobject]@{ Name = 'OcrMode'; On = @('Active'); Off = @('Inactive'); Neutral = @('None') }
        )
    }
    else {
        @(
            [pscustomobject]@{ Name = 'Mode'; On = @('Enable'); Off = @('Disable'); Neutral = @() }
            [pscustomobject]@{ Name = 'OcrMode'; On = @('Active', 'Enabled'); Off = @('Inactive', 'Disabled'); Neutral = @() }
        )
    }
    foreach ($definition in $modes) {
        $present = Test-PurviewProperty -InputObject $Configuration -Name $definition.Name
        if (-not $present) {
            $usable = $false
            continue
        }

        $text = ([string](Get-PurviewProperty -InputObject $Configuration -Name $definition.Name)).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) {
            $usable = $false
            continue
        }

        if ($definition.On -contains $text) { $signals.Add('on') }
        elseif ($definition.Off -contains $text) { $signals.Add('off') }
        elseif ($definition.Neutral -contains $text) { continue }
        else { $usable = $false }
    }

    $states = @($signals | Sort-Object -Unique)
    $state = if ($usable -and $states.Count -eq 1) { $states[0] } else { 'unknown' }

    # Only the five friendly workload groups emitted by the collector may reach report text.
    $friendly = @('Exchange', 'SharePoint', 'OneDrive', 'Teams', 'Devices')
    $locations = @(if ($state -eq 'on' -and (Test-PurviewProperty -InputObject $Configuration -Name 'Locations')) {
        ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Configuration -Name 'Locations') |
            ForEach-Object {
                $name = [string]$_
                @($friendly | Where-Object { $_ -eq $name } | Select-Object -First 1)
            } | Where-Object { $_ } | Sort-Object -Unique
    })

    # Enabled without a usable scope does not establish that any image is actually being scanned.
    # This also rejects a present-but-empty list and future location names this version cannot map.
    if ($state -eq 'on' -and $locations.Count -eq 0) { $state = 'unknown' }

    return [pscustomobject]@{ State = $state; Locations = @($locations) }
}

function Get-PurviewAppRetentionAnalysis {
    <# .SYNOPSIS Correlates app-retention policy state with its separately collected rules. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [AllowEmptyString()][string]$ApplicationPattern = ''
    )

    $answer = [ordered]@{
        PolicyRead = $false
        PolicyComplete = $false
        RuleRead = $false
        ScopeComplete = $true
        RuleComplete = $false
        ConfiguredCount = 0
        InScopeCount = 0
        ActiveCount = 0
        DisabledCount = 0
        RulelessCount = 0
        UnknownCount = 0
    }

    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $policyResults = @($results | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'AppRetentionPolicy'
        })
    $policyStatus = if ($policyResults.Count -eq 1) {
        [string](Get-PurviewProperty -InputObject $policyResults[0] -Name 'status')
    }
    else { '' }
    if ($policyResults.Count -ne 1 -or
        $policyStatus -notin 'Success', 'PartialSuccess') {
        return [pscustomobject]$answer
    }

    $policyData = Get-PurviewProperty -InputObject $policyResults[0] -Name 'data'
    if ($null -eq $policyData -or -not (Test-PurviewProperty -InputObject $policyData -Name 'Policies')) {
        return [pscustomobject]$answer
    }
    if ($policyData -is [System.Collections.IDictionary]) {
        if ($null -eq $policyData['Policies']) { return [pscustomobject]$answer }
        $policies = @($policyData['Policies'])
    }
    else {
        $policyProperty = $policyData.PSObject.Properties['Policies']
        if ($null -eq $policyProperty.Value) { return [pscustomobject]$answer }
        $policies = @($policyProperty.Value)
    }

    $answer.PolicyRead = $true
    $answer.PolicyComplete = $policyStatus -eq 'Success'
    $answer.ConfiguredCount = $policies.Count

    $inScope = [System.Collections.Generic.HashSet[int]]::new()
    $enabled = [System.Collections.Generic.HashSet[int]]::new()
    $disabled = [System.Collections.Generic.HashSet[int]]::new()
    $unknown = [System.Collections.Generic.HashSet[int]]::new()

    for ($index = 0; $index -lt $policies.Count; $index++) {
        $policy = $policies[$index]
        if ($ApplicationPattern) {
            if (-not (Test-PurviewProperty -InputObject $policy -Name 'Applications')) {
                $answer.ScopeComplete = $false
                $null = $unknown.Add($index)
                continue
            }
            $scope = ConvertTo-PurviewApplicationScope -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Applications')
            if (-not $scope.Complete) {
                $answer.ScopeComplete = $false
                $null = $unknown.Add($index)
                continue
            }
            $applications = @($scope.Tokens)
            if (@($applications | Where-Object { [string]$_ -match $ApplicationPattern }).Count -eq 0) { continue }
        }

        $null = $inScope.Add($index)
        if (-not (Test-PurviewProperty -InputObject $policy -Name 'Enabled')) {
            $null = $unknown.Add($index)
            continue
        }
        $state = Get-PurviewProperty -InputObject $policy -Name 'Enabled'
        if ($state -isnot [bool]) {
            $null = $unknown.Add($index)
            continue
        }
        if ([bool]$state) { $null = $enabled.Add($index) }
        else { $null = $disabled.Add($index) }
    }

    $answer.InScopeCount = $inScope.Count
    $answer.DisabledCount = $disabled.Count

    if ($enabled.Count -gt 0) {
        $ruleResults = @($results | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'AppRetentionRule'
            })
        $ruleResult = if ($ruleResults.Count -eq 1) { $ruleResults[0] } else { $null }
        $ruleStatus = [string](Get-PurviewProperty -InputObject $ruleResult -Name 'status')
        $ruleData = Get-PurviewProperty -InputObject $ruleResult -Name 'data'
        $hasRuleList = $null -ne $ruleData -and (Test-PurviewProperty -InputObject $ruleData -Name 'Rules')
        $answer.RuleRead = $ruleStatus -in 'Success', 'PartialSuccess' -and $hasRuleList
        $answer.RuleComplete = $ruleStatus -eq 'Success' -and $hasRuleList

        $policyByToken = @{}
        for ($index = 0; $index -lt $policies.Count; $index++) {
            $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($field in 'Name', 'Guid') {
                foreach ($token in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $policies[$index] -Name $field))) {
                    $null = $tokens.Add($token)
                }
            }
            if ($tokens.Count -eq 0) {
                if ($enabled.Contains($index)) { $null = $unknown.Add($index) }
                continue
            }
            foreach ($token in $tokens) {
                $key = $token.Trim().ToLowerInvariant()
                if (-not $policyByToken.ContainsKey($key)) { $policyByToken[$key] = @() }
                $policyByToken[$key] = @($policyByToken[$key]) + $index
            }
        }

        $linked = [System.Collections.Generic.HashSet[int]]::new()
        $unresolvedRule = $false
        if ($answer.RuleRead) {
            foreach ($rule in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $ruleData -Name 'Rules'))) {
                if (-not (Test-PurviewProperty -InputObject $rule -Name 'Policy')) {
                    $unresolvedRule = $true
                    continue
                }
                $owners = [System.Collections.Generic.HashSet[int]]::new()
                foreach ($reference in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $rule -Name 'Policy'))) {
                    $key = $reference.Trim().ToLowerInvariant()
                    if (-not $policyByToken.ContainsKey($key)) { continue }
                    foreach ($owner in @($policyByToken[$key])) { $null = $owners.Add([int]$owner) }
                }
                if ($owners.Count -eq 1) { $null = $linked.Add([int]@($owners)[0]) }
                else { $unresolvedRule = $true }
            }
        }

        foreach ($index in $enabled) {
            if ($linked.Contains($index)) { continue }
            if (-not $answer.RuleComplete -or $unresolvedRule) { $null = $unknown.Add($index) }
        }

        $answer.ActiveCount = @($enabled | Where-Object { $linked.Contains($_) }).Count
        $answer.RulelessCount = @($enabled | Where-Object {
                -not $linked.Contains($_) -and -not $unknown.Contains($_)
            }).Count
    }

    $answer.UnknownCount = $unknown.Count
    return [pscustomobject]$answer
}

function Get-PurviewClassicCopilotRetentionAnalysis {
    <# .SYNOPSIS Determines only whether the classic Teams policy family proves Copilot absence. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $answer = [ordered]@{
        Read = $false
        PolicyCount = 0
        TeamsOnlyCount = 0
        AmbiguousCount = 0
        AbsenceProven = $false
    }

    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $classicPolicyResults = @($results | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'ClassicTeamsRetentionPolicy'
        })
    if ($classicPolicyResults.Count -ne 1 -or
        [string](Get-PurviewProperty -InputObject $classicPolicyResults[0] -Name 'status') -ne 'Success') {
        return [pscustomobject]$answer
    }

    $data = Get-PurviewProperty -InputObject $classicPolicyResults[0] -Name 'data'
    if ($null -eq $data -or -not (Test-PurviewProperty -InputObject $data -Name 'Policies')) {
        return [pscustomobject]$answer
    }

    # Read the value directly so a genuine empty array remains distinguishable from a missing or
    # null list. Only the former proves that no classic Teams policy exists.
    if ($data -is [System.Collections.IDictionary]) {
        if ($null -eq $data['Policies']) { return [pscustomobject]$answer }
        $policies = @($data['Policies'])
    }
    else {
        $policyProperty = $data.PSObject.Properties['Policies']
        if ($null -eq $policyProperty.Value) { return [pscustomobject]$answer }
        $policies = @($policyProperty.Value)
    }

    $answer.Read = $true
    $answer.PolicyCount = $policies.Count

    foreach ($policy in $policies) {
        if ($null -eq $policy -or -not (Test-PurviewProperty -InputObject $policy -Name 'Applications')) {
            $answer.AmbiguousCount++
            continue
        }

        $scope = ConvertTo-PurviewApplicationScope -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Applications')
        $tokens = @($scope.Tokens)
        if ($scope.Complete -and $tokens.Count -eq 1 -and
            [string]$tokens[0] -match '(?i)^User:TeamsChatUserInteractions$') {
            $answer.TeamsOnlyCount++
        }
        else { $answer.AmbiguousCount++ }
    }

    # Zero classic Teams policies, or only policies explicitly migrated to Teams-only scope,
    # settles absence. No undocumented value is interpreted as positive Copilot coverage.
    $answer.AbsenceProven = $answer.AmbiguousCount -eq 0
    return [pscustomobject]$answer
}

function Get-PurviewRetentionPolicyKind {
    <# .SYNOPSIS Matches only supported normalized retention rule-type combinations. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$Policy)

    if (-not (Test-PurviewProperty -InputObject $Policy -Name 'RuleTypes')) { return 'unknown' }
    $raw = $null
    if ($Policy -is [System.Collections.IDictionary]) { $raw = $Policy['RuleTypes'] }
    else { $raw = $Policy.PSObject.Properties['RuleTypes'].Value }
    if ($null -eq $raw -or ($raw -isnot [string] -and $raw -isnot [System.Enum] -and
        $raw -isnot [System.Collections.IList])) { return 'unknown' }
    $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $raw) {
        if ($value -isnot [string] -and $value -isnot [System.Enum]) { return 'unknown' }
        foreach ($part in ([string]$value -split '[,;]')) {
            if ([string]::IsNullOrWhiteSpace($part)) { return 'unknown' }
            $null = $tokens.Add($part.Trim())
        }
    }
    if ($tokens.Count -eq 1) {
        if ($tokens.Contains('Default')) { return 'retention' }
        if ($tokens.Contains('Apply')) { return 'auto-applied' }
        if ($tokens.Contains('Publish')) { return 'published' }
    }
    if ($tokens.Count -eq 2 -and $tokens.Contains('Apply') -and $tokens.Contains('ProactiveDataRetention')) { return 'system' }
    return 'unknown'
}

function Get-PurviewInventory {
    <#
    .SYNOPSIS
        Summarises configuration and qualified activity and inventory signals without judging them.

    .DESCRIPTION
        Findings compare evidence with rule expectations; this supplies supporting observations.
        Missing or ambiguous evidence should not be read as absence. Some legacy empty-success
        and partial-read paths still need stronger validation before their totals can be trusted.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $output = [System.Collections.Generic.List[object]]::new()

    $add = {
        param($area, $metric, $collector, $value, $detail)
        $ran = Test-PurviewCollectorRan -Snapshot $Snapshot -Collector $collector
        $output.Add([pscustomobject]@{
                Area = $area
                Metric = $metric
                Collector = $collector
                Value = if ($ran) { [string]$value } else { 'not checked' }
                Detail = if ($ran) { [string]$detail } else { Get-PurviewCollectorReason -Snapshot $Snapshot -Collector $collector }
            })
    }

    $sentinel = Get-PurviewSentinelIntegrationOutcome -Snapshot $Snapshot
    & $add 'Microsoft Sentinel integration' 'Microsoft 365 audit and compliance data' 'SentinelPurviewIntegration' `
        $sentinel.Value $sentinel.Reason

    $allLabels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
    # Count enabled definitions separately. Disabled definitions do not establish whether labels
    # remain applied to content or whether their protection is still effective.
    $labelList = [System.Collections.Generic.List[object]]::new()
    $retiredLabels = 0
    $unknownLabelStates = 0
    foreach ($label in $allLabels) {
        $disabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $label -Name 'Disabled')
        if (-not $disabled.Valid) { $unknownLabelStates++; continue }
        if ([bool]$disabled.Value) { $retiredLabels++ } else { $labelList.Add($label) }
    }
    $labels = @($labelList.ToArray())
    $labelDetail = if ($unknownLabelStates -gt 0) {
        '{0} of {1} labels did not return a usable Disabled state, so the number currently available could not be established' -f $unknownLabelStates, $allLabels.Count
    }
    elseif ($retiredLabels -gt 0) {
        'Exist in the tenant, whether or not anyone can use them. {0} disabled and not counted.' -f $retiredLabels
    }
    else { 'Exist in the tenant, whether or not anyone can use them' }
    & $add 'Sensitivity labels' 'Labels defined' 'SensitivityLabel' $(if ($unknownLabelStates -gt 0) { 'Not checked' } else { $labels.Count }) $labelDetail

    # Secure by default asks for 5x5 whenever possible. Reported as shape rather than as a verdict:
    # the guidance is hedged, and a taxonomy is a design choice rather than something to score.
    $taxonomy = Get-PurviewLabelTaxonomy -Snapshot $Snapshot
    if ($taxonomy.Collected -and $taxonomy.StateKnown -and $taxonomy.HierarchyKnown) {
        $widest = @($taxonomy.SubLabels | Group-Object -Property Parent | Sort-Object Count -Descending)
        $deepest = if ($widest.Count -gt 0) { $widest[0].Count } else { 0 }
        $shape = if ($deepest -gt 0) { '{0} top level, at most {1} under one' -f $taxonomy.TopLevel.Count, $deepest }
        else { '{0} top level, no sublabels' -f $taxonomy.TopLevel.Count }
        $detail = if ($taxonomy.TopLevel.Count -gt 5 -or $deepest -gt 5) {
            'Exceeds the five-by-five design guideline. This is a design choice to review, not a mandatory limit'
        }
        else { 'Within the five-by-five design guideline; structure alone does not validate the taxonomy' }
        & $add 'Sensitivity labels' 'Taxonomy shape' 'SensitivityLabel' $shape $detail
    }

    $labelPolicies = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabelPolicy' -Select 'Policies')
    $publishedList = [System.Collections.Generic.List[object]]::new()
    $unknownPolicyStates = 0
    foreach ($policy in $labelPolicies) {
        $enabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Enabled')
        if (-not $enabled.Valid) { $unknownPolicyStates++; continue }
        if ([bool]$enabled.Value) { $publishedList.Add($policy) }
    }
    $publishedPolicies = @($publishedList.ToArray())
    $policyDetail = if ($unknownPolicyStates -gt 0) {
        '{0} of {1} policies did not return a usable Enabled state, so the enabled total could not be established' -f $unknownPolicyStates, $labelPolicies.Count
    }
    elseif ($labelPolicies.Count -eq $publishedPolicies.Count) { 'All of them are enabled' }
    else { "$($labelPolicies.Count - $publishedPolicies.Count) more defined but not enabled" }
    & $add 'Sensitivity labels' 'Sensitivity label publishing policies enabled' 'SensitivityLabelPolicy' $(if ($unknownPolicyStates -gt 0) { 'Not checked' } else { $publishedPolicies.Count }) $policyDetail

    # Count distinct links from enabled publishing policies, not delivered policies or applied
    # labels. The same label often sits in several policies.
    $published = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $labelsKnown = $unknownPolicyStates -eq 0 -and $unknownLabelStates -eq 0

    foreach ($policy in $publishedPolicies) {
        if (-not (Test-PurviewProperty -InputObject $policy -Name 'Labels')) { $labelsKnown = $false; continue }
        foreach ($name in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Labels'))) {
            $null = $published.Add([string]$name)
        }
    }

    if ($labelsKnown) {
        $reach = @($labels | Where-Object {
                $published.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'Name')) -or
                $published.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'UniqueName')) -or
                $published.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'Guid'))
            })
        $reachDetail = if ($reach.Count -lt $labels.Count) { "Of $($labels.Count) defined; $($labels.Count - $reach.Count) have no matched enabled publishing policy. Availability and application are not verified" }
        else { "All $($labels.Count) defined labels have matched enabled publishing policies; delivery and application are not verified" }
        & $add 'Sensitivity labels' 'Labels published to users' 'SensitivityLabelPolicy' $reach.Count $reachDetail
    }

    # Reach is reported as the scope the policies declare. Turning that into a share of users would
    # mean expanding every group, which needs directory permissions this assessment does not take.
    $scoped = @($publishedPolicies | Where-Object { (Test-PurviewProperty -InputObject $_ -Name 'UserScope') -or (Test-PurviewProperty -InputObject $_ -Name 'GroupScope') })
    if ($unknownPolicyStates -eq 0 -and $publishedPolicies.Count -gt 0 -and $scoped.Count -gt 0) {
        $everyone = @($scoped | Where-Object {
                $targets = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'UserScope')) +
                @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'GroupScope'))
                @($targets | Where-Object { [string]$_ -eq 'All' }).Count -gt 0
            })

        if ($everyone.Count -gt 0) {
            & $add 'Sensitivity labels' 'Who the labels reach' 'SensitivityLabelPolicy' 'Everyone' "$($everyone.Count) of $($scoped.Count) enabled policies declare an All scope. This does not verify exclusions, delivery, app support or effective availability to every user"
        }
        else {
            $named = 0
            foreach ($policy in $scoped) {
                $named += @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name 'UserScope')).Count
                $named += @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name 'GroupScope')).Count
            }
            & $add 'Sensitivity labels' 'Who the labels reach' 'SensitivityLabelPolicy' 'Named groups only' "No enabled policy is published to all users. $(Format-PurviewCount -Count $named -Singular 'user or group is' -Plural 'users or groups are') named across them; the share of people that covers needs group membership, which this assessment does not read"
        }
    }

    $autoSignal = Get-PurviewAutoLabelSensitiveTypeSignal -Snapshot $Snapshot
    if ($autoSignal.PolicyReliable) {
        & $add 'Auto-labeling' 'Auto-labeling policies turned on' 'AutoLabeling' $autoSignal.ActivePolicyCount $autoSignal.PolicyDetail
    }
    else {
        & $add 'Auto-labeling' 'Auto-labeling policies turned on' 'AutoLabeling' 'Not checked' $autoSignal.PolicyDetail
    }

    # A rule count is not useful here: one policy can be stored as one rule per location. The value
    # is the distinct set of SIT names in enabled rules linked to policies known to be turned on.
    # This row deliberately bypasses $add because complete policy data can prove zero active
    # policies even when no rule read was needed.
    $output.Add([pscustomobject]@{
            Area = 'Auto-labeling'
            Metric = 'Sensitive information these policies look for'
            Collector = 'AutoLabelingRule'
            Value = if ($autoSignal.Reliable) { [string]$autoSignal.Count } else { 'Not checked' }
            Detail = [string]$autoSignal.Detail
        })

    # Every mode has to be accounted for. Reporting only enforcing and test leaves the remainder to
    # be inferred, and a disabled policy then reads as missing from one section and absent from another.
    $dlpState = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $dlpFacts = @($dlpState.Policies)
    $dlp = @($dlpFacts | ForEach-Object { $_.Policy })
    $modeKnown = @($dlpFacts | Where-Object { $_.ModeKnown })
    $unknownDlpModes = $dlpState.UnknownPolicyModeCount
    $enforcingFacts = @($modeKnown | Where-Object { $_.IsEnforcing })
    $enforcing = @($enforcingFacts | ForEach-Object { $_.Policy })
    $testing = @($modeKnown | Where-Object { $_.Mode -like 'Test*' })
    $disabledDlp = @($modeKnown | Where-Object { $_.Mode -eq 'Disable' })
    $otherDlp = $modeKnown.Count - $enforcingFacts.Count - $testing.Count - $disabledDlp.Count

    # The reader is checking one number against a portal, so the sentence shows its own arithmetic
    # rather than listing every mode except the one being counted and leaving the subtraction to them.
    $dlpOther = [System.Collections.Generic.List[string]]::new()
    if ($testing.Count -gt 0) { $dlpOther.Add("$($testing.Count) in test mode") }
    if ($disabledDlp.Count -gt 0) { $dlpOther.Add("$($disabledDlp.Count) disabled") }
    if ($otherDlp -gt 0) { $dlpOther.Add("$otherDlp in another mode") }
    if ($unknownDlpModes -gt 0) { $dlpOther.Add("$unknownDlpModes with no readable mode") }

    $dlpDetail = if (-not $dlpState.PolicyRead) { 'The DLP policy collector did not return its policy list' }
    elseif (-not $dlpState.PolicyComplete) {
        'The partial read returned {0}; {1} are in Enable mode, but tenant totals could not be established' -f
            (Format-PurviewCount -Count $dlp.Count -Singular 'policy record'), $enforcingFacts.Count
    }
    elseif ($dlp.Count -eq 0) { 'None defined' }
    elseif ($unknownDlpModes -gt 0) { 'The number of policies in Enable mode could not be established because {0} of {1} policies did not return a readable mode' -f $unknownDlpModes, $dlp.Count }
    else { '{0} of {1} policies in Enable mode' -f $enforcingFacts.Count, $dlp.Count }
    # One reason stands on its own; several need a total in front of them to add up.
    if ($dlpOther.Count -eq 1) { $dlpDetail += '; {0}' -f $dlpOther[0] }
    elseif ($dlpOther.Count -gt 1) {
        $dlpDetail += '; other policies: {0}' -f ($dlpOther -join ', ')
    }

    # Keep rule counts in the policy detail, not a separate row that could look like a policy count.
    if ($dlpState.RuleRead -and $dlp.Count -gt 0) {
        if ($dlpState.RuleCount -eq 0) {
            $dlpDetail += if ($dlpState.RuleComplete) { '. No rules found' }
            else { '. Rule data is incomplete; no rules were returned' }
        }
        else {
            $linkedRules = @($dlpState.LinkedRules)
            $enabledLinked = @($linkedRules | Where-Object { $_.DisabledKnown -and -not $_.Disabled })
            $unknownLinked = @($linkedRules | Where-Object { -not $_.DisabledKnown })
            $dlpDetail += '. Rules: {0} found; {1} matched to a policy' -f $dlpState.RuleCount, $linkedRules.Count
            if ($enabledLinked.Count -gt 0) {
                $dlpDetail += ' ({0} enabled)' -f $enabledLinked.Count
            }
            if (-not $dlpState.RuleComplete) { $dlpDetail += '. Rule data is incomplete; these counts cover only the rules returned' }
            if ($unknownLinked.Count -gt 0) {
                $dlpDetail += '. Enabled/disabled status is unknown for {0} of the matched rules' -f $unknownLinked.Count
            }
            if ($dlpState.UnresolvedRuleCount -gt 0) {
                $dlpDetail += '. {0} could not be matched unambiguously to a policy' -f
                    (Format-PurviewCount -Count $dlpState.UnresolvedRuleCount -Singular 'rule')
            }
        }
    }
    elseif ((Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DlpRule') -and $dlp.Count -gt 0) {
        $dlpDetail += '. The rule collector did not return its rule list, so rule state was not assessed'
    }

    & $add 'Data loss prevention' 'DLP policies in Enable mode' 'DataLossPrevention' $(if (-not $dlpState.PolicyComplete -or $unknownDlpModes -gt 0) { 'Not checked' } else { $enforcingFacts.Count }) $dlpDetail

    # Keep simulation visible as configuration. Endpoint simulation with policy tips can apply
    # Block with override; mode alone is not a test of actual device behaviour.
    $endpointDlp = Get-PurviewEndpointDlpAnalysis -Snapshot $Snapshot
    $endpointExact = $endpointDlp.PolicyComplete -and $endpointDlp.UnknownScopeCount -eq 0
    $endpointValue = if ($endpointExact) { [string]$endpointDlp.ScopedCount }
    elseif ($endpointDlp.ScopedCount -gt 0) { "At least $($endpointDlp.ScopedCount)" }
    else { 'Not checked' }

    $endpointDetail = if (-not $endpointDlp.PolicyRead) {
        'The DLP policy collector did not return its policy list'
    }
    elseif ($endpointDlp.ScopedCount -eq 0 -and $endpointExact) {
        'No returned DLP policy targets the Devices location'
    }
    else {
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($endpointDlp.EnforcingScopedCount -gt 0) { $parts.Add("$($endpointDlp.EnforcingScopedCount) in Enable mode") }
        if ($endpointDlp.TestingScopedCount -gt 0) { $parts.Add("$($endpointDlp.TestingScopedCount) in simulation") }
        if ($endpointDlp.DisabledScopedCount -gt 0) { $parts.Add("$($endpointDlp.DisabledScopedCount) disabled") }
        if ($endpointDlp.UnknownModeScopedCount -gt 0) { $parts.Add("$($endpointDlp.UnknownModeScopedCount) with no readable mode") }
        if ($parts.Count -gt 0) { 'Policies whose scope includes Devices: {0}' -f ($parts -join ', ') }
        else { 'No Devices-scoped policy was confirmed; scope could not be established from the returned data' }
    }
    if (-not $endpointDlp.PolicyComplete) { $endpointDetail += '. The policy read was partial, so this is not a tenant total' }
    if ($endpointDlp.UnknownScopeCount -gt 0) {
        $endpointDetail += '. Devices scope was not readable for {0}' -f
            (Format-PurviewCount -Count $endpointDlp.UnknownScopeCount -Singular 'other policy' -Plural 'other policies')
    }
    $endpointDetail += '. Policy configuration does not prove effective protection on every device; verify applicable rules, user and device scope, onboarding and device health'
    & $add 'Data loss prevention' 'DLP policies covering Devices' 'DataLossPrevention' $endpointValue $endpointDetail

    # Coverage is per workload, not per policy: ten policies over one workload leave the rest open.
    $dlpWorkloads = Get-PurviewWorkloadCoverage -Policy $enforcing
    if ($dlpState.PolicyComplete -and $unknownDlpModes -eq 0 -and $dlpWorkloads.Known) {
        & $add 'Data loss prevention' 'Workloads an enforcing policy covers' 'DataLossPrevention' $dlpWorkloads.Covered.Count ($dlpWorkloads.Detail)
    }

    $retentionEvidence = Get-PurviewRetentionListEvidence -Snapshot $Snapshot -Collector 'RetentionPolicy'
    $retention = @($retentionEvidence.NamedRecords)
    $retentionQualifier = 'Enabled status and rule-type metadata do not verify a retention action or period, distribution or content application. No per-label policy association is established by this read.'

    # Unknown kinds never become classic retention, and unknown states never become zero.
    $enforcingRetention = {
        param($set)

        $live = [System.Collections.Generic.List[object]]::new()
        $unknown = 0
        foreach ($policy in $set) {
            $rawStates = @{}
            foreach ($field in 'Enabled', 'Mode', 'HasRules') {
                $rawStates[$field] = $null
                if ($policy -is [System.Collections.IDictionary]) { $rawStates[$field] = $policy[$field] }
                elseif ($policy.PSObject.Properties[$field]) { $rawStates[$field] = $policy.PSObject.Properties[$field].Value }
            }
            if (($rawStates.Enabled -isnot [bool] -and $rawStates.Enabled -isnot [string]) -or
                ($rawStates.HasRules -isnot [bool] -and $rawStates.HasRules -isnot [string])) { $unknown++; continue }
            $enabled = ConvertTo-PurviewBoolean -InputObject $rawStates.Enabled
            if (-not $enabled.Valid) { $unknown++; continue }
            $mode = $rawStates.Mode
            if (($mode -isnot [string] -and $mode -isnot [System.Enum]) -or
                ([string]$mode).Trim() -notin 'Enforce', 'Test', 'AuditAndNotify', 'PendingDeletion', 'TestWithNotifications', 'TestWithoutNotifications') {
                $unknown++
                continue
            }

            # An enabled policy in enforcement mode still does nothing without a rule. HasRules is
            # Boolean evidence from the policy read; missing or malformed evidence stays unknown.
            $hasRules = ConvertTo-PurviewBoolean -InputObject $rawStates.HasRules
            if (-not $hasRules.Valid) { $unknown++; continue }
            if ([bool]$enabled.Value -and ([string]$mode).Trim() -eq 'Enforce' -and [bool]$hasRules.Value) { $live.Add($policy) }
        }

        [pscustomobject]@{ Live = $live.ToArray(); Unknown = $unknown }
    }

    $unknownKinds = @($retention | Where-Object { (Get-PurviewRetentionPolicyKind -Policy $_) -eq 'unknown' })
    if ($retentionEvidence.Complete -and $unknownKinds.Count -eq 0 -and $retention.Count -gt 0) {
        foreach ($group in @(
                @{ Kind = 'retention'; Metric = 'Retention policies enforcing' }
                @{ Kind = 'auto-applied'; Metric = 'Retention label auto-apply policies enforcing' }
                @{ Kind = 'published'; Metric = 'Retention label publishing policies enforcing' }
            )) {
            $set = @($retention | Where-Object { (Get-PurviewRetentionPolicyKind -Policy $_) -eq $group.Kind })
            if ($set.Count -eq 0) { continue }
            $state = & $enforcingRetention $set
            if ($state.Unknown -gt 0) {
                $detail = '{0} of {1} policies did not return complete Enabled, Mode and HasRules evidence, so the enforcing total could not be established' -f $state.Unknown, $set.Count
                & $add 'Data lifecycle' $group.Metric 'RetentionPolicy' 'Not checked' "$detail. $retentionQualifier"
            }
            else {
                $live = @($state.Live)
                $detail = '{0} of {1} defined' -f $live.Count, $set.Count
                # Simulation is a deliberate state, not a half-finished one, so it is named.
                $simulating = @($set | Where-Object {
                        $enabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $_ -Name 'Enabled')
                        $enabled.Value -and ([string](Get-PurviewProperty -InputObject $_ -Name 'Mode')).Trim() -in 'Test', 'TestWithNotifications', 'TestWithoutNotifications'
                    })
                $short = $set.Count - $live.Count - $simulating.Count
                if ($simulating.Count -gt 0) { $detail += '. {0} running in simulation' -f $simulating.Count }
                if ($short -gt 0) { $detail += '. {0} not enabled, not enforcing, or without a rule' -f $short }
                & $add 'Data lifecycle' $group.Metric 'RetentionPolicy' $live.Count "$detail. $retentionQualifier"
            }
        }

        $system = @($retention | Where-Object { (Get-PurviewRetentionPolicyKind -Policy $_) -eq 'system' })
        if ($system.Count -gt 0) {
            & $add 'Data lifecycle' 'System-managed retention policies' 'RetentionPolicy' $system.Count "Configured Apply + ProactiveDataRetention definitions, associated with Adaptive Protection. $retentionQualifier"
        }
    }
    else {
        # A complete named list can establish definitions even when kinds or states are unknown.
        # Keep that count separate from enforcement; partial or ambiguous reads have no exact total.
        $retentionValue = if ($retentionEvidence.Complete) { [string]$retention.Count } else { 'Not checked' }
        $retentionDetail = $retentionEvidence.Reason
        if ($retentionEvidence.Complete -and $retention.Count -gt 0) {
            $retentionDetail = "$($retention.Count) policy definitions returned across retention and retention label policy kinds; not an enforcing count or a count for one portal page."
        }
        if ($retentionEvidence.Complete -and $retention.Count -eq 0) {
            $retentionDetail = 'No retention or retention label policy definitions were returned by the complete read.'
        }
        elseif ($unknownKinds.Count -gt 0) {
            $retentionDetail += " Policy type could not be determined for $($unknownKinds.Count) returned named records because RetentionRuleTypes was absent, empty or unsupported. No enforcing total is inferred; this does not establish whether their retention settings are configured."
        }
        $policyDetails = @(foreach ($policy in @($retention | Select-Object -First 6)) {
                $name = ([string](Get-PurviewProperty -InputObject $policy -Name 'Name') -replace '[\r\n\t]+', ' ')
                if ($name.Length -gt 160) { $name = $name.Substring(0, 157) + '...' }
                $kind = switch (Get-PurviewRetentionPolicyKind -Policy $policy) {
                    'retention' { 'retention policy' }
                    'auto-applied' { 'auto-apply label policy' }
                    'published' { 'label publishing policy' }
                    'system' { 'system-managed policy' }
                    default { 'policy kind unknown' }
                }
                $parts = @($name, $kind)
                foreach ($field in 'Enabled', 'Mode', 'HasRules') {
                    $rawState = $null
                    if ($policy -is [System.Collections.IDictionary]) { $rawState = $policy[$field] }
                    elseif ($policy.PSObject.Properties[$field]) { $rawState = $policy.PSObject.Properties[$field].Value }
                    if ($field -eq 'Mode') {
                        $modeText = 'mode unknown'
                        if ($rawState -is [string] -or $rawState -is [System.Enum]) {
                            $modeText = switch (([string]$rawState).Trim()) {
                                'Enforce' { 'enforcement mode' }
                                'Test' { 'test mode (no enforcement)' }
                                'AuditAndNotify' { 'audit and notify mode (no enforcement)' }
                                'PendingDeletion' { 'mode: PendingDeletion' }
                                'TestWithNotifications' { 'mode: TestWithNotifications' }
                                'TestWithoutNotifications' { 'mode: TestWithoutNotifications' }
                                default { 'mode unknown' }
                            }
                        }
                        $parts += $modeText
                        continue
                    }
                    # Validate scalars before conversion: singleton arrays are not Boolean evidence.
                    if ($rawState -isnot [bool] -and $rawState -isnot [string]) { $rawState = $null }
                    $boolean = ConvertTo-PurviewBoolean -InputObject $rawState
                    if ($field -eq 'Enabled') {
                        $parts += if (-not $boolean.Valid) { 'enabled state unknown' }
                            elseif ($boolean.Value) { 'enabled' } else { 'disabled' }
                    }
                    else {
                        $parts += if (-not $boolean.Valid) { 'rule presence unknown' }
                            elseif ($boolean.Value) { 'rules reported' } else { 'no rules reported' }
                    }
                }
                $parts -join '; '
            })
        if ($policyDetails.Count -gt 0) {
            $detailLabel = if ($retentionEvidence.Complete) { 'Configured definitions' } else { 'Returned named records (not a tenant total)' }
            $retentionDetail += " ${detailLabel}: $($policyDetails -join ' | ')."
        }
        if ($retention.Count -gt 6) { $retentionDetail += " $($retention.Count - 6) more returned named records omitted." }
        $output.Add([pscustomobject]@{
                Area = 'Data lifecycle'; Metric = 'Retention and retention label policy definitions'; Collector = 'RetentionPolicy'
                Value = $retentionValue; Detail = "$retentionDetail $retentionQualifier"
            })
    }

    # Exchange messaging records management is separate from modern Purview retention. Count only
    # policy definitions that carry a tag; a definition without one performs no retention action.
    # This collector does not read mailbox assignment, so the row makes no claim about active scope.
    $legacy = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'LegacyRetention' -Select 'Policies')
    if ($legacy.Count -gt 0) {
        $linked = 0
        $unknownLinks = 0
        foreach ($policy in $legacy) {
            $tagCount = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $policy -Name 'TagCount')
            if (-not $tagCount.Valid) { $unknownLinks++; continue }
            if ($tagCount.Value -gt 0) { $linked++ }
        }

        $policyNoun = if ($legacy.Count -eq 1) { 'policy' } else { 'policies' }
        $legacySubject = if ($legacy.Count -eq 1) { 'This older policy' } else { 'These older policies' }
        $legacyValue = if ($unknownLinks -gt 0) { 'Not checked' } else { $linked }
        $legacyDetail = if ($unknownLinks -gt 0) {
            'Whether retention tags are attached could not be read for {0} of {1} configured Exchange {2}, so the total could not be established. {3} can archive or delete mail alongside Microsoft Purview retention; mailbox assignments and processing are not assessed.' -f $unknownLinks, $legacy.Count, $policyNoun, $legacySubject
        }
        else {
            $tagVerb = if ($linked -eq 1) { 'has' } else { 'have' }
            '{0} of {1} configured Exchange {2} {3} retention tags. {4} can archive or delete mail alongside Microsoft Purview retention; mailbox assignments and processing are not assessed.' -f $linked, $legacy.Count, $policyNoun, $tagVerb, $legacySubject
        }
        & $add 'Data lifecycle' 'Exchange policies with retention tags' 'LegacyRetention' $legacyValue $legacyDetail
    }

    # The app-retention family can include Copilot, Teams and Viva Engage. Report its returned
    # application scopes separately rather than inferring coverage from the cmdlet family alone.
    $appRetention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AppRetentionPolicy' -Select 'Policies')
    if ($appRetention.Count -gt 0) {
        $appState = Get-PurviewAppRetentionAnalysis -Snapshot $Snapshot
        $appScopes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $copilotApplications = @(
            'User:M365Copilot', 'CopilotForSecurity', 'CopilotinFabricPowerBI', 'CopilotStudio',
            'CopilotinBusinessApplicationplatformsSales', 'SQLCopilot'
        )
        $scopeUnknown = 0
        foreach ($policy in $appRetention) {
            if (-not (Test-PurviewProperty -InputObject $policy -Name 'Applications')) {
                $scopeUnknown++
                continue
            }
            $scope = ConvertTo-PurviewApplicationScope -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Applications')
            if (-not $scope.Complete) {
                $scopeUnknown++
                continue
            }
            foreach ($application in @($scope.Tokens)) {
                $name = ([string]$application).Trim()
                if ($name -in $copilotApplications) { $null = $appScopes.Add('Microsoft Copilot experiences') }
                elseif ($name -match '(?i)^(?:User|Group):MicrosoftTeams(?:CallLog)?$') { $null = $appScopes.Add('Teams') }
                elseif ($name -match '(?i)^(?:User|Group):(?:Yammer|VivaEngage)$') { $null = $appScopes.Add('Viva Engage') }
                else { $null = $appScopes.Add('another application') }
            }
        }
        $scopeDetail = if ($appScopes.Count -gt 0) { 'Configured for {0}. ' -f (@($appScopes | Sort-Object) -join ', ') }
        elseif ($scopeUnknown -gt 0) { 'Application scope was not returned. ' }
        else { '' }
        if ($scopeUnknown -gt 0 -and $appScopes.Count -gt 0) {
            $scopeDetail += 'Application scope was incomplete for {0}. ' -f (Format-PurviewCount -Count $scopeUnknown -Singular 'policy')
        }
        $appDetail = $scopeDetail + 'This is the separate app-retention policy family. Enablement and linked rules do not verify actions, duration, assignments, distribution or retention of content.'
        if ($appState.ActiveCount -gt 0) {
            $appDetail = '{0} of {1} are enabled and have at least one linked rule. {2}' -f $appState.ActiveCount, $appRetention.Count, $appDetail
        }
        elseif ($appState.UnknownCount -gt 0) {
            $appDetail = 'Current application state was not established because policy enablement or linked-rule evidence was incomplete. ' + $appDetail
        }
        elseif ($appState.DisabledCount -gt 0 -or $appState.RulelessCount -gt 0) {
            $appDetail = 'None is currently active: {0} disabled and {1} enabled without a linked rule. {2}' -f $appState.DisabledCount, $appState.RulelessCount, $appDetail
        }
        & $add 'Data lifecycle' 'Retention policies for AI apps' 'AppRetentionPolicy' $appRetention.Count $appDetail
    }

    # No workload row for retention. Microsoft documents that this cmdlet's Workload property always
    # lists every workload and never the ones a policy actually applies to, so any coverage read from
    # it would be invented. The locations are accurate only with -DistributionDetail, one call per
    # policy, which this assessment does not make.

    $retentionLabelEvidence = Get-PurviewRetentionLabelEvidence -Snapshot $Snapshot
    # Keep the shared explanation even when the collector was unavailable or duplicated.
    $output.Add([pscustomobject]@{
            Area = 'Records management'; Metric = 'Retention labels'; Collector = 'RetentionLabel'
            Value = $retentionLabelEvidence.Value; Detail = $retentionLabelEvidence.Detail
        })

    $audit = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditIngestion' -Select 'Settings')
    $auditStates = [System.Collections.Generic.List[bool]]::new()
    $auditUnknown = 0
    foreach ($setting in $audit) {
        $state = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $setting -Name 'Enabled')
        if ($state.Valid) { $auditStates.Add([bool]$state.Value) } else { $auditUnknown++ }
    }
    $distinctAuditStates = @($auditStates | Select-Object -Unique)
    if ($audit.Count -eq 0 -or $auditUnknown -gt 0 -or $distinctAuditStates.Count -ne 1) {
        & $add 'Audit' 'Unified audit logging' 'AuditIngestion' 'Not checked' 'The audit setting did not return one complete Boolean state, so whether auditing is on could not be established'
    }
    else {
        & $add 'Audit' 'Unified audit logging' 'AuditIngestion' $(if ($distinctAuditStates[0]) { 'on' } else { 'off' }) 'Returned ingestion setting, not verification of every audit event or separately retained conversation content'
    }

    $auditRetention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditConfiguration' -Select 'RetentionPolicies')
    & $add 'Audit' 'Custom audit log retention policies' 'AuditConfiguration' $auditRetention.Count 'Custom policies can shorten or extend default audit retention. Defaults depend on licensed users and workloads; an empty custom-policy list can be appropriate'

    # IsWorkbenchPolicy is undocumented, and a tenant returned it set on a policy the portal lists
    # as active. Excluding on it hid a real policy.
    $comm = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'CommunicationCompliance' -Select 'Policies')
    $commNames = @($comm | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    $commDetail = if ($commNames.Count -gt 0) {
        $names = @($commNames | Select-Object -First 6 | ForEach-Object {
                if ($_.Length -gt 160) { $_.Substring(0, 157) + '...' } else { $_ }
            }) -join ', '
        if ($commNames.Count -gt 6) { $names += ", and $($commNames.Count - 6) more" }
        "Configured policies: $names."
    }
    elseif ($comm.Count -gt 0) { 'Policy definitions configured in Communication Compliance.' }
    else { 'No Communication Compliance policy was returned.' }
    $commResults = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults') |
            Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'CommunicationCompliance' })
    if ($commResults.Count -gt 0 -and [string](Get-PurviewProperty -InputObject $commResults[0] -Name 'status') -eq 'PartialSuccess') {
        $commDetail += ' Some configuration could not be retrieved; this list may be incomplete.'
    }
    & $add 'Communication compliance' 'Policies' 'CommunicationCompliance' $comm.Count $commDetail

    $classifiers = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'Classification' -Select 'SensitiveInformationTypes')
    # Purview ships hundreds of built-in types, so a type whose publisher was not returned is left
    # unread rather than counted as custom: guessing wrong inflates this by the whole catalogue.
    $unattributed = @($classifiers | Where-Object { -not (Test-PurviewProperty -InputObject $_ -Name 'Publisher') }).Count
    if ($unattributed -gt 0) {
        & $add 'Classification' 'Custom sensitive information types' 'Classification' 'Not checked' "$unattributed of $($classifiers.Count) types do not say who built them, so the ones Microsoft ships cannot be told apart from the ones built here"
    }
    else {
        $custom = @($classifiers | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Publisher') -ne 'Microsoft Corporation' })
        $customDetail = if ($custom.Count -gt 0) {
            $names = @($custom | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') } | Where-Object { $_ } | Sort-Object)
            if ($names.Count -le 6) { $names -join ', ' }
            else { (@($names | Select-Object -First 6) -join ', ') + ", and $($names.Count - 6) more" }
        }
        elseif ($classifiers.Count -gt 0) { 'No non-Microsoft type definitions returned. Built-in types or other classification methods may meet requirements' }
        else { 'No sensitive information type was returned' }
        & $add 'Classification' 'Custom sensitive information types' 'Classification' $custom.Count $customDetail
    }

    $ocrBilling = 'Review current OCR licensing, pay-as-you-go requirements and supported locations before enabling it.'
    $collectorResults = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $ocrResults = @($collectorResults | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'OcrConfiguration'
        })

    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'OcrConfiguration')) {
        & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' ''
    }
    elseif ($ocrResults.Count -ne 1 -or
        [string](Get-PurviewProperty -InputObject $ocrResults[0] -Name 'status') -ne 'Success') {
        & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' 'The OCR setting could not be confirmed because some configuration is missing or incomplete.'
    }
    else {
        $ocrData = Get-PurviewProperty -InputObject $ocrResults[0] -Name 'data'
        $hasConfigurations = Test-PurviewProperty -InputObject $ocrData -Name 'Configurations'
        $rawConfigurations = $null
        if ($hasConfigurations) {
            # Read the property value directly: returning an empty array through a helper function
            # produces no pipeline output and is otherwise indistinguishable from null here.
            if ($ocrData -is [System.Collections.IDictionary]) { $rawConfigurations = $ocrData['Configurations'] }
            else { $rawConfigurations = $ocrData.PSObject.Properties['Configurations'].Value }
        }

        if (-not $hasConfigurations -or $null -eq $rawConfigurations) {
            & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' 'The OCR configuration result did not include its configuration list, so whether images are being scanned could not be established.'
        }
        else {
            $ocr = @(ConvertTo-PurviewArray -InputObject $rawConfigurations)
            if ($ocr.Count -eq 0) {
                & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'off' ('No OCR configuration was returned. {0}' -f $ocrBilling)
            }
            else {
                # Versions before 1.61.0 retained only Mode and OcrMode. They can still be replayed
                # when both agree; a current snapshot missing the newer state is incomplete.
                [version]$snapshotVersion = $null
                $versionKnown = [version]::TryParse(
                    [string](Get-PurviewProperty -InputObject $Snapshot -Name 'toolVersion'),
                    [ref]$snapshotVersion)
                $allowLegacyOcr = $versionKnown -and $snapshotVersion -lt [version]'1.61.0'
                $ocrSignals = @($ocr | ForEach-Object {
                        Get-PurviewOcrConfigurationSignal -Configuration $_ -AllowLegacy:$allowLegacyOcr
                    })
                $ocrStates = @($ocrSignals | ForEach-Object { $_.State } | Sort-Object -Unique)

                if ($ocrStates.Count -ne 1 -or $ocrStates[0] -eq 'unknown') {
                    & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' 'The OCR configuration did not return one coherent, usable state, so whether images are being scanned could not be established.'
                }
                elseif ($ocrStates[0] -eq 'on') {
                    $ocrWhere = @($ocrSignals | ForEach-Object { @($_.Locations) } | Where-Object { $_ } | Sort-Object -Unique)
                    $ocrDetail = if ($ocrWhere.Count -gt 0) { 'Configured on for {0}.' -f ($ocrWhere -join ', ') }
                    else { 'Configured on, but no location was returned. Confirm scope and processing separately' }
                    & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'on' $ocrDetail
                }
                else {
                    & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'off' ('OCR is configured off. {0}' -f $ocrBilling)
                }
            }
        }
    }

    $activityRan = Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'ProtectionActivity'
    $activityData = $null
    if ($activityRan) {
        $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
        $activityResult = @($results | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'ProtectionActivity'
            })
        if ($activityResult.Count -gt 0) {
            $activityData = Get-PurviewProperty -InputObject $activityResult[0] -Name 'data'
        }
    }

    $signal = Get-PurviewLabelActivitySignal -Data $activityData
    if ($activityRan) {
        $activityMetric = if ($signal.WindowDays -gt 0) {
            'Sensitivity labels applied in the last {0}' -f (Format-PurviewCount -Count $signal.WindowDays -Singular 'day')
        }
        else { 'Sensitivity labels applied in the recent activity period' }
        $qualifier = 'This counts label applications, not distinct files or messages: applying a label more than once to the same item counts more than once. A zero means no application was recorded during this period, not that no items currently have labels. Recent activity can take 60 to 90 minutes to appear for core Microsoft 365 services, and some sources take longer.'

        if (-not $signal.Reliable) {
            & $add 'Sensitivity labels' $activityMetric 'ProtectionActivity' 'Not checked' ("A reliable recent count is not available because Microsoft Purview did not return a complete activity result. No partial count is shown. $qualifier")
        }
        else {
            $windowText = if ($signal.WindowDays -eq 30) { 'the rolling 30-day window' }
            else { "the rolling $(Format-PurviewCount -Count $signal.WindowDays -Singular 'day') window" }
            & $add 'Sensitivity labels' $activityMetric 'ProtectionActivity' $signal.Count ("Microsoft Purview recorded this many label applications during $windowText. $qualifier")
        }
    }
    else {
        & $add 'Sensitivity labels' 'Sensitivity labels applied in the last 30 days' 'ProtectionActivity' 'Not checked' 'Activity Explorer was not read, so no recent label-application count is available.'
    }

    $collectorResults = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $coverageResult = @($collectorResults | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'ClassificationCoverage'
        })
    $coverageData = if ($coverageResult.Count -gt 0) { Get-PurviewProperty -InputObject $coverageResult[0] -Name 'data' } else { $null }

    # Only explicit sensitive information type results are customer-visible. Older snapshots can
    # carry sensitivity-label rows and a LabelledItemTotal; neither has a documented TagName
    # identity, so both are ignored. Individual type counts are never summed because one item can
    # match more than one type.
    $coverageQualifier = 'This is a delayed current inventory, not recent activity. It covers Exchange, SharePoint, OneDrive and Teams content visible to this sign-in. Counts can take up to seven days to update, or 14 days for SharePoint files. One item can match more than one sensitive information type, so these counts are intentionally not added together.'
    $seenCoverage = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $requests = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $coverageData -Name 'Requests') | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'TagType') -eq 'SensitiveInformationType'
        })

    if ($requests.Count -gt 0) {
        foreach ($request in $requests) {
            $name = ([string](Get-PurviewProperty -InputObject $request -Name 'Tag')).Trim()
            if (-not $name -or -not $seenCoverage.Add($name)) { continue }

            $status = [string](Get-PurviewProperty -InputObject $request -Name 'Status')
            $count = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $request -Name 'TotalCount')
            $value = if ($status -eq 'Success' -and $count.Valid) { [long]$count.Value } else { 'Not checked' }
            $reason = switch ($status) {
                'Success' {
                    if ($count.Valid) { '' }
                    else { 'Microsoft Purview did not return a usable non-negative count for this requested type.' }
                }
                'InvalidTotalCount' { 'Microsoft Purview did not return a usable TotalCount for this requested type.' }
                'OmittedByLimit' { 'This requested type was not read because the caller set a collection limit.' }
                'Unavailable' { 'Microsoft Purview could not return a count for this requested type.' }
                'CollectorUnavailable' { Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'ClassificationCoverage' }
                default { 'The requested type did not return a recognized collection outcome.' }
            }
            & $add 'Classification' "Items matching $name" 'ClassificationCoverage' $value ("$reason $coverageQualifier".Trim())
        }
    }
    else {
        # Compatibility for snapshots that predate per-request outcomes. The TagType filter is the
        # boundary that keeps their unsupported sensitivity-label entries and aggregate out.
        $tags = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $coverageData -Name 'Tags') | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'TagType') -eq 'SensitiveInformationType'
            })
        foreach ($tag in $tags) {
            $name = ([string](Get-PurviewProperty -InputObject $tag -Name 'Tag')).Trim()
            if (-not $name -or -not $seenCoverage.Add($name)) { continue }
            $count = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $tag -Name 'TotalCount')
            $value = if ($count.Valid) { [long]$count.Value } else { 'Not checked' }
            $reason = if ($count.Valid) { '' } else { 'Microsoft Purview did not return a usable TotalCount for this requested type.' }
            & $add 'Classification' "Items matching $name" 'ClassificationCoverage' $value ("$reason $coverageQualifier".Trim())
        }

        if ([string](Get-PurviewProperty -InputObject $coverageData -Name 'RequestKind') -eq 'ExplicitSensitiveInformationType') {
            foreach ($field in 'TagsUnreadable', 'TagsWithInvalidTotalCount', 'TagsOmittedByLimit') {
                foreach ($rawName in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $coverageData -Name $field))) {
                    $name = ([string]$rawName).Trim()
                    if (-not $name -or -not $seenCoverage.Add($name)) { continue }
                    $reason = switch ($field) {
                        'TagsWithInvalidTotalCount' { 'Microsoft Purview did not return a usable TotalCount for this requested type.' }
                        'TagsOmittedByLimit' { 'This requested type was not read because the caller set a collection limit.' }
                        default { 'Microsoft Purview could not return a count for this requested type.' }
                    }
                    & $add 'Classification' "Items matching $name" 'ClassificationCoverage' 'Not checked' ("$reason $coverageQualifier")
                }
            }
        }
    }

    $licensingBlock = Get-PurviewProperty -InputObject $Snapshot -Name 'licensing'
    # The shared resolver rejects null array elements. Keep each as a malformed, empty identity
    # in a report-only copy; never remove a returned record or modify the snapshot.
    if (Test-PurviewProperty -InputObject $licensingBlock -Name 'subscribedSkus') {
        $rawSkus = $null
        if ($licensingBlock -is [System.Collections.IDictionary]) { $rawSkus = $licensingBlock['subscribedSkus'] }
        else { $rawSkus = $licensingBlock.PSObject.Properties['subscribedSkus'].Value }
        if ($null -ne $rawSkus) {
            $reportSkus = @($rawSkus)
            for ($i = 0; $i -lt $reportSkus.Count; $i++) {
                if ($null -eq $reportSkus[$i]) { $reportSkus[$i] = [pscustomobject]@{} }
            }
            $licensingBlock = @{
                collected = Get-PurviewProperty -InputObject $licensingBlock -Name 'collected'
                complete = Get-PurviewProperty -InputObject $licensingBlock -Name 'complete'
                conflicted = Get-PurviewProperty -InputObject $licensingBlock -Name 'conflicted'
                subscribedSkus = $reportSkus
            }
        }
    }
    $licensingEvidence = Resolve-PurviewLicensingEvidence -Licensing $licensingBlock
    if (-not $licensingEvidence.Collected -or -not $licensingEvidence.ListReadable) {
        & $add 'Licensing' 'Tenant subscriptions' 'Licensing' 'Not checked' 'The licensing result did not contain a confirmed Boolean collection state and a readable subscribed SKU list.'
    }
    elseif ($licensingEvidence.BlockConflict) {
        & $add 'Licensing' 'Tenant subscriptions' 'Licensing' 'Not checked' 'Duplicate licensing collector results disagreed. Returned records remain visible in Licensing and SKU Analysis; no tenant total is inferred.'
    }
    else {
        # Count raw SKU identities, not registry matches or active states. Missing identities and
        # contradictory metadata cannot support an exact total, even in a nominally complete read.
        $skuIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $skuMetadata = @{}
        $partSkuIds = @{}
        $identityGap = $licensingEvidence.MalformedCount -gt 0
        $metadataConflict = $licensingEvidence.ConflictCount -gt 0 -or $licensingEvidence.ProductConflicts.Count -gt 0
        foreach ($entry in $licensingEvidence.Entries) {
            $rawId = Get-PurviewProperty -InputObject $entry.Input -Name 'skuId'
            $parsedId = [guid]::Empty
            if (($rawId -isnot [string] -and $rawId -isnot [guid]) -or
                -not [guid]::TryParse([string]$rawId, [ref]$parsedId) -or $parsedId -eq [guid]::Empty) {
                $identityGap = $true
                continue
            }
            $key = $parsedId.ToString('D')
            $null = $skuIds.Add($key)
            $rawPart = Get-PurviewProperty -InputObject $entry.Input -Name 'skuPartNumber'
            if ($rawPart -is [string] -and -not [string]::IsNullOrWhiteSpace($rawPart)) {
                if ($partSkuIds.ContainsKey($rawPart) -and $partSkuIds[$rawPart] -ine $key) { $metadataConflict = $true }
                $partSkuIds[$rawPart] = $key
            }
            $signature = [ordered]@{
                Part = Get-PurviewProperty -InputObject $entry.Input -Name 'skuPartNumber'
                Status = Get-PurviewProperty -InputObject $entry.Input -Name 'capabilityStatus'
                Enabled = Get-PurviewProperty -InputObject $entry.Input -Name 'prepaidUnitsEnabled'
                Assigned = Get-PurviewProperty -InputObject $entry.Input -Name 'consumedUnits'
                Plans = Get-PurviewProperty -InputObject $entry.Input -Name 'servicePlans'
            } | ConvertTo-Json -Depth 10 -Compress
            if ($skuMetadata.ContainsKey($key) -and $skuMetadata[$key] -cne $signature) { $metadataConflict = $true }
            $skuMetadata[$key] = $signature
        }

        $detail = 'Distinct SKU GUIDs returned by Microsoft Graph, across all capability statuses; not a count of billing agreements. Observed statuses and seats are shown in Licensing and SKU Analysis.'
        $value = [string]$skuIds.Count
        if (-not $licensingEvidence.Complete -or $identityGap -or $metadataConflict) {
            $value = if ($skuIds.Count -gt 0) { "At least $($skuIds.Count)" } else { 'Not checked' }
            if (-not $licensingEvidence.Complete) { $detail += ' The subscription read was incomplete.' }
            if ($identityGap) { $detail += ' Some SKU identities were missing or malformed.' }
            if ($metadataConflict) { $detail += ' Some subscription metadata conflicted.' }
        }
        & $add 'Licensing' 'Tenant subscriptions' 'Licensing' $value $detail
    }

    # What a tenant can already reach is the exposure Copilot inherits, so this reports the reports
    # rather than the sites: a completed one carries the counts, and a missing one is the finding.
    if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DataAccessGovernance') {
        $dag = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'Reports')
        $refused = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'EntitiesNotRead')
        $asked = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewCollectorValue -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'EntitiesAsked')
        $done = @($dag | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Status') -eq 'Completed' })

        # An unreadable response does not identify its cause or prove that no report exists.
        if (-not $asked.Valid -or $asked.Value -eq 0) {
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 'Not checked' 'The data access governance read did not return how many report entities were requested, so an empty result cannot be interpreted.'
        }
        elseif ($refused.Count -ge $asked.Value) {
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 'Not checked' 'Data access governance could not be read. Review the collector error, permissions, feature-specific licensing and service availability; this result does not identify the cause'
        }
        elseif ($done.Count -gt 0) {
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' $done.Count (
                'Entities covered: {0}' -f ((@($done | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Entity') }) | Select-Object -Unique | Sort-Object) -join ', '))

            # SharePoint and OneDrive are reported separately and each counts only its own sites, so
            # the newest single report describes one workload. The latest of each is summed instead.
            $permission = @($done | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Entity') -eq 'PermissionedUsers' })
            if ($permission.Count -gt 0) {
                $latest = @($permission |
                        Group-Object -Property { [string](Get-PurviewProperty -InputObject $_ -Name 'Workload') } |
                        ForEach-Object {
                            @($_.Group | Sort-Object -Property { [string](Get-PurviewProperty -InputObject $_ -Name 'CreatedAt') } -Descending)[0]
                        })

                $inReport = [long]0
                $inTenant = [long]0
                $siteCountsKnown = $true
                foreach ($row in $latest) {
                    $reportCount = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $row -Name 'SitesInReport')
                    $tenantCount = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $row -Name 'SitesInTenant')
                    if (-not $reportCount.Valid -or -not $tenantCount.Valid) {
                        $siteCountsKnown = $false
                        break
                    }
                    try { $inReport = [long]($inReport + [long]$reportCount.Value) }
                    catch { $siteCountsKnown = $false; break }
                    # Tenant totals cover both workloads already, so the larger is the total, not the sum.
                    $tenantTotal = [long]$tenantCount.Value
                    if ($tenantTotal -gt $inTenant) { $inTenant = $tenantTotal }
                }

                $covered = @($latest | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Workload') } |
                        Where-Object { $_ } | Sort-Object -Unique)
                $when = @($latest | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'CreatedAt') } |
                        Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)

                if (-not $siteCountsKnown) {
                    & $add 'Oversharing' 'Sites and accounts with at least one permissioned user' 'DataAccessGovernance' 'Not checked' 'A completed permissioned-users report did not return both its report and tenant site counts, so coverage could not be calculated.'
                }
                else {
                    $detail = if ($inTenant -gt 0) { 'Out of {0} in the tenant.' -f $inTenant } else { '' }
                    if ($covered.Count -gt 0) { $detail = ($detail + (' Covering {0}.' -f ($covered -join ' and '))).Trim() }
                    if ($when) { $detail = ($detail + " Reported on $when.").Trim() }
                    & $add 'Oversharing' 'Sites and accounts with at least one permissioned user' 'DataAccessGovernance' $inReport (($detail + ' Existing report metadata only. Report age, filters and thresholds limit interpretation; this is not a complete measure of current Copilot exposure').Trim())
                }
            }
        }
        else {
            # Snapshot reports run on demand; the sharing links and EEEU activity reports need data
            # collection switched on first, and Microsoft documents a 24 hour wait after that.
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 0 'No completed report was returned for the requested entities. This does not establish that oversharing has never been assessed. Review existing reports and collection outcomes before deciding whether to generate a report'
        }
    }

    # These positive historical signals prove that a match was recorded in the query window. They
    # do not identify the policy that matched or establish its present configuration or health.
    # Silence proves nothing because the table also depends on sharing telemetry with Defender.
    $telemetry = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataSecurityTelemetry' -Select 'Signals')
    if ($telemetry.Count -gt 0) {
        $signal = $telemetry[0]
        $seen = { param($name) ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $signal -Name $name) }

        $dlpSignal = & $seen 'DlpMatches'
        if ($dlpSignal.Valid -and $dlpSignal.Value -gt 0) {
            $dlpSeen = [long]$dlpSignal.Value
            $blockingSignal = & $seen 'Blocking'
            $blockDetail = if ($enforcing.Count -eq 0) {
                'Matches were recorded during this 30-day window, but no returned policy has a recognized Enable mode. Collection gaps or subsequent changes may explain the difference; the historical window does not establish current policy state.'
            }
            elseif (-not $blockingSignal.Valid) {
                'Matches were recorded during this 30-day window, but the blocking count was incomplete, so how they were handled cannot be established.'
            }
            elseif ($blockingSignal.Value -eq 0) {
                'The independent blocking aggregate is zero for this window; it does not establish how these DLP matches were handled.'
            }
            elseif ($blockingSignal.Value -eq $dlpSeen) { 'The independent blocking aggregate equals the DLP-match count; the events are not correlated, so this does not mean all matches were blocked' }
            elseif ($blockingSignal.Value -eq 1) { 'One blocking event was counted independently in this window; it is not established as one of these DLP matches' }
            else { '{0} blocking events were counted independently in this window; their overlap with these DLP matches is not established' -f $blockingSignal.Value }
            & $add 'Data loss prevention' 'Activities that matched a policy in the last 30 days' 'DataSecurityTelemetry' $dlpSeen $blockDetail
        }

        $ccSignal = & $seen 'CcMatches'
        if ($ccSignal.Valid -and $ccSignal.Value -gt 0) {
            $ccDetail = if ($comm.Count -eq 0) {
                'Matches were recorded during this 30-day window, but no policy definition was returned. The historical window cannot identify which policy matched or establish its current state.'
            }
            else { 'Matches were recorded during this 30-day window. The historical signal does not identify which configured policy matched and cannot establish any policy''s present operational state.' }
            & $add 'Communication compliance' 'Activities that matched a policy in the last 30 days' 'DataSecurityTelemetry' $ccSignal.Value $ccDetail
        }

        $irmSignal = & $seen 'IrmMatches'
        if ($irmSignal.Valid -and $irmSignal.Value -gt 0) {
            & $add 'Insider risk' 'Activities that matched a policy in the last 30 days' 'DataSecurityTelemetry' $irmSignal.Value 'Matches were recorded during this 30-day window. This historical signal does not identify the policy that matched and cannot establish current policy state.'
        }

        $labelSignal = & $seen 'Labelled'
        if ($labelSignal.Valid -and $labelSignal.Value -gt 0) {
            $labelDetail = if ($labels.Count -gt 0) { 'Recorded during the 30-day window, against {0} currently defined' -f $labels.Count } else { 'Recorded during the 30-day window' }
            & $add 'Sensitivity labels' 'Distinct labels seen on content in the last 30 days' 'DataSecurityTelemetry' $labelSignal.Value $labelDetail
        }
    }

    # Grouped so every count for an area sits together, areas in alphabetical order. Within an area
    # the original order is kept, because it builds from what exists to what reaches users.
    $index = 0
    return @($output |
            ForEach-Object { [pscustomobject]@{ Row = $_; Area = [string]$_.Area; Index = $index++ } } |
            Sort-Object Area, Index |
            ForEach-Object { $_.Row })
}

function Get-PurviewPrerequisiteState {
    <#
    .SYNOPSIS
        Reports each tenant opt-in Secure by default asks for, and whether it is set.

    .DESCRIPTION
        Report unread opt-ins as unknown and requiring manual confirmation, never as off.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $script:Prerequisite) {
        $backingRule = @()
        if ($item.ContainsKey('RuleId')) {
            $backingRule = @($Finding | Where-Object { $_.ruleId -eq $item.RuleId })
            # A prerequisite inherits the applicability and scope of its rule. If that rule is not
            # customer-visible, substituting a "not read" row would put the hidden check back in.
            if ($backingRule.Count -eq 0 -or [string]$backingRule[0].status -eq 'NotApplicable') { continue }
        }

        # Distinguish settings this script does not collect from unavailable collector results.
        $state = 'Confirm in portal'
        $detail = 'Current value is not collected by this script. Confirm separately.'

        if ($item.ContainsKey('Collector')) {
            $settings = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector $item.Collector -Select 'Settings')
            $match = @($settings | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -eq $item.Setting })

            if ($match.Count -eq 0) {
                $state = 'Not read'
                $detail = Get-PurviewCollectorReason -Snapshot $Snapshot -Collector $item.Collector
            }
            elseif (Test-PurviewProperty -InputObject $match[0] -Name 'AsRecommended') {
                $asRecommendedValue = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $match[0] -Name 'AsRecommended')
                if (-not $asRecommendedValue.Valid) {
                    $state = 'Not read'
                    $detail = "$($item.Setting) did not return a usable current state."
                }
                else {
                    $asRecommended = [bool]$asRecommendedValue.Value
                    $state = if ($asRecommended) { 'As recommended' } else { 'Needs attention' }
                    $detail = '{0} is reported as {1}. The report reference value is {2}.' -f $item.Setting,
                        (Get-PurviewProperty -InputObject $match[0] -Name 'Value'),
                        (Get-PurviewProperty -InputObject $match[0] -Name 'Expected')
                    # Keep collector context that distinguishes disabled from never configured.
                    $note = [string](Get-PurviewProperty -InputObject $match[0] -Name 'Detail')
                    if ($note) { $detail = '{0} {1}.' -f $detail, $note }
                }
            }
            else {
                # Collectors that dump a configuration object wholesale carry no verdict of their
                # own, so the expected value is declared alongside the prerequisite instead.
                $actual = [string](Get-PurviewProperty -InputObject $match[0] -Name 'Value')
                $state = if ($actual -eq [string]$item.ExpectedValue) { 'As recommended' } else { 'Needs attention' }
                $detail = '{0} is reported as {1}. The report reference value is {2}.' -f $item.Setting, $actual, $item.ExpectedValue
            }
        }
        elseif ($item.ContainsKey('DeviceHealth')) {
            # Where Defender for Endpoint is not deployed the table is empty, which is unknown
            # rather than no devices.
            $devices = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'EndpointDeviceHealth' -Select 'Devices')
            if ($devices.Count -gt 0) {
                $deviceCounts = @{}
                $deviceCountComplete = $true
                foreach ($name in 'Reporting', 'DefenderOnboarded', 'DlpEnabled', 'ConfigurationValid', 'RealTimeProtectionOff') {
                    $parsed = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewProperty -InputObject $devices[0] -Name $name)
                    if (-not $parsed.Valid) { $deviceCountComplete = $false; continue }
                    $deviceCounts[$name] = [long]$parsed.Value
                }

                if (-not $deviceCountComplete) {
                    $state = 'Not read'
                    $detail = 'The endpoint device aggregate was incomplete, so monitoring and onboarding state could not be evaluated.'
                }
                else {
                    $reporting = $deviceCounts['Reporting']
                    $defenderOnboarded = $deviceCounts['DefenderOnboarded']
                    $dlpEnabled = $deviceCounts['DlpEnabled']

                    if ($dlpEnabled -gt 0) {
                        # Historical DLP-enabled records support this legacy state, not a current
                        # monitoring-switch or per-device enforcement verdict.
                        $state = 'As recommended'
                        $detail = '{0} reported as DLP-enabled in the hunting window. Current monitoring and effective enforcement are not verified.' -f (Format-PurviewCount -Count $dlpEnabled -Singular 'device was' -Plural 'devices were')
                        $invalid = $dlpEnabled - $deviceCounts['ConfigurationValid']
                        $rtpOff = $deviceCounts['RealTimeProtectionOff']
                        if ($invalid -gt 0) { $detail += ' The independent DLP-enabled and configuration-valid counts differ by {0}; this is not a count of invalid devices.' -f $invalid }
                        if ($rtpOff -gt 0) { $detail += ' {0} historical records report Defender real-time protection off; overlap with DLP-enabled devices is not established.' -f $rtpOff }
                    }
                    else {
                        # The hunting query does not read the current monitoring switch.
                        $state = 'Confirm in portal'
                        $detail = 'Check this under Settings > Device onboarding > Devices, where Windows and macOS are turned on separately.'
                        $detail += if ($defenderOnboarded -gt 0) {
                            ' {0} reported as Defender-onboarded in the hunting window; no DLP-enabled record was counted.' -f (Format-PurviewCount -Count $defenderOnboarded -Singular 'device was' -Plural 'devices were')
                        }
                        elseif ($reporting -gt 0) {
                            ' {0} endpoint DLP status in the hunting window, but no DLP-enabled record was counted.' -f (Format-PurviewCount -Count $reporting -Singular 'device reports' -Plural 'devices report')
                        }
                        else { ' No endpoint DLP status was returned in the hunting window.' }
                        $detail += ' Confirm monitoring, applicable rules, scope, onboarding and health; these aggregates do not establish that devices are unprotected.'
                    }
                }
            }
        }
        elseif ($item.ContainsKey('Evidence')) {
            # Positive only. A found artefact proves only what its own state and wording claim;
            # recent telemetry is not current configuration. Absence proves nothing, so the state
            # falls back to portal confirmation rather than reporting the setting off.
            $e = $item.Evidence
            if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector $e.Collector) {
                $candidates = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector $e.Collector -Select $e.Select)
                $hits = @(if ($e.ContainsKey('Field')) {
                        @($candidates | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name $e.Field) -match $e.Match })
                    }
                    else { $candidates })

                if ($hits.Count -gt 0) {
                    $state = if ($e.ContainsKey('FoundState')) { [string]$e.FoundState } else { 'In use' }
                    $detail = $e.Found
                }
                else { $detail = $e.NotFound }
            }
        }
        elseif ($item.ContainsKey('LabelScheme')) {
            $scheme = Get-PurviewLabelSchemeSignal -Snapshot $Snapshot
            $state = $scheme.State
            $detail = $scheme.Detail
        }
        elseif ($item.ContainsKey('RuleId')) {
            $state = switch ([string]$backingRule[0].status) {
                'Pass' { 'As recommended' }
                'Fail' { 'Needs attention' }
                'Warning' { 'Needs attention' }
                'NotLicensed' { 'Not available - licensing' }
                default { 'Not read' }
            }
            $detail = if ($state -eq 'Needs attention' -and $item.ContainsKey('Summary')) { [string]$item.Summary }
            elseif ($state -eq 'As recommended' -and $item.ContainsKey('SummaryOk')) { [string]$item.SummaryOk }
            # The engine states an assertion precisely, which reads as machinery in a list a
            # customer is meant to act on, so a plain sentence is preferred where one is given.
            else { [string]$backingRule[0].reason }

            # A failing/custom rule alone is not authority to offer an audit write. Require one
            # complete collector result and one explicitly disabled setting from the snapshot.
            if ($item.RuleId -eq 'PA-AUD-0002' -and $state -eq 'Needs attention') {
                $auditResults = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults') |
                    Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'AuditIngestion' })
                $auditSettings = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditIngestion' -Select 'Settings')
                $auditOff = $false
                if ($backingRule.Count -eq 1 -and $auditResults.Count -eq 1 -and $auditSettings.Count -eq 1 -and
                    (Test-PurviewProperty -InputObject $auditResults[0] -Name 'status') -and
                    $auditResults[0].status -is [string] -and
                    [string](Get-PurviewProperty -InputObject $auditResults[0] -Name 'status') -eq 'Success' -and
                    @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $auditResults[0] -Name 'propertiesNotReturned')).Count -eq 0 -and
                    (Test-PurviewProperty -InputObject $auditSettings[0] -Name 'Name') -and
                    $auditSettings[0].Name -is [string] -and
                    (Test-PurviewProperty -InputObject $auditSettings[0] -Name 'Enabled') -and
                    ($auditSettings[0].Enabled -is [bool] -or $auditSettings[0].Enabled -is [string]) -and
                    [string](Get-PurviewProperty -InputObject $auditSettings[0] -Name 'Name') -eq 'UnifiedAuditLogIngestionEnabled') {
                    $auditValue = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $auditSettings[0] -Name 'Enabled')
                    $auditOff = $auditValue.Valid -and -not $auditValue.Value
                }
                if (-not $auditOff) {
                    $state = 'Not read'
                    $detail = 'One complete, explicitly disabled audit setting was not established. Verify the current value in Exchange Online before changing it.'
                }
            }
        }

        $output.Add([pscustomobject]@{
                Name = $item.Name
                State = $state
                # Some opt-ins add context to an investigation rather than gating anything, and
                # listing those as though they were required overstates what is actually missing.
                Optional = $item.ContainsKey('Optional')
                Detail = $detail
                Why = $item.Why
                Action = if ($item.ContainsKey('Recommended')) { $item.Recommended } else { $item.Portal }
                Command = if ($item.ContainsKey('Command')) { [string]$item.Command } else { '' }
                Session = if ($item.ContainsKey('Session')) { [string]$item.Session } else { '' }
                Caution = if ($item.ContainsKey('Caution')) { [string]$item.Caution } else { '' }
                Url = $item.Url
                # Turning these on one at a time is a decision per policy, so the script offers the
                # list rather than assuming every one of them should go live.
                Choose = if ($item.ContainsKey('Choose')) { $item.Choose } else { $null }
                Script = if ($item.ContainsKey('Script')) { $item.Script } else { $null }
                Candidates = @(
                    if ($item.ContainsKey('Choose') -and (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector $item.Choose.Collector)) {
                        @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector $item.Choose.Collector -Select $item.Choose.Select |
                                Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name $item.Choose.Unless) -ne $item.Choose.Is } |
                                ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name $item.Choose.Field) } |
                                Where-Object { $_ })
                    })
            })
    }

    # What needs doing first, then what a person has to confirm, then what could not be read, and
    # last what is already right. An unread switch must never sort below one that is fine.
    $rank = @{ 'Needs attention' = 0; 'Confirm in portal' = 1; 'Not read' = 2; 'Not available - licensing' = 3; 'Seen recently' = 4; 'Evidence found' = 4; 'Granted' = 4; 'In use' = 4; 'As recommended' = 5 }
    return @($output | Sort-Object @{ Expression = { if ($rank.ContainsKey([string]$_.State)) { $rank[[string]$_.State] } else { 5 } } }, Name)
}

function Get-PurviewCoverageMatrix {
    <#
    .SYNOPSIS
        Reports which Purview solution areas were collected and which are actually evaluated.

    .DESCRIPTION
        Collecting an area is not the same as assessing it. Showing both makes the difference
        visible instead of letting a populated snapshot imply coverage that no rule provides.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $output = [System.Collections.Generic.List[object]]::new()

    # A collector with no rule of its own is not unused if the inventory reports what it found.
    $inInventory = @()
    try {
        $inInventory = @(Get-PurviewInventory -Snapshot $Snapshot |
                ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Collector') } |
                Where-Object { $_ } | Sort-Object -Unique)
    }
    catch { Write-Verbose 'The inventory could not be read to credit collectors that only feed it.' }

    # Credit collectors used by tenant opt-ins and Copilot controls, even without a rule id.
    $prereqCollector = @($script:Prerequisite | ForEach-Object {
            if ($_.ContainsKey('Collector')) { [string]$_.Collector }
            if ($_.ContainsKey('Evidence')) { [string]$_.Evidence.Collector }
            if ($_.ContainsKey('Choose')) { [string]$_.Choose.Collector }
            if ($_.ContainsKey('DeviceHealth')) { 'EndpointDeviceHealth' }
        } | Where-Object { $_ } | Sort-Object -Unique)
    $visibleIds = @($Finding | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'ruleId') })

    foreach ($result in $results) {
        $name = [string](Get-PurviewProperty -InputObject $result -Name 'collector')
        $ruleIds = @($script:Rules | Where-Object {
                $_.condition.collector -eq $name -and $_.id -in $visibleIds
            } | ForEach-Object { $_.id })
        $related = @($Finding | Where-Object { $_.ruleId -in $ruleIds })

        $readBy = [System.Collections.Generic.List[string]]::new()
        if ($prereqCollector -contains $name) { $readBy.Add('the tenant opt-ins') }
        if ($script:CopilotSectionCollector -contains $name) { $readBy.Add('the Copilot and AI controls') }

        # Count each outcome; the adjacent Rules column already gives the total.
        $tally = [System.Collections.Generic.List[string]]::new()
        foreach ($bucket in @(
                @{ Label = 'passed'; Match = { $_.status -eq 'Pass' } }
                @{ Label = 'need attention'; One = 'needs attention'; Match = { $_.status -eq 'Fail' } }
                @{ Label = 'to review'; Match = { $_.status -in 'Warning', 'NeedsReview' } }
                @{ Label = 'not checked'; Match = { $_.status -in 'NotCollected', 'Unsupported' } }
                @{ Label = 'not available with current licensing'; Match = { $_.status -eq 'NotLicensed' } }
            )) {
            $hit = @($related | Where-Object $bucket.Match).Count
            if ($hit -eq 0) { continue }
            $word = if ($hit -eq 1 -and $bucket.ContainsKey('One')) { $bucket.One } else { $bucket.Label }
            $tally.Add("$hit $word")
        }

        $output.Add([pscustomobject]@{
                Collector = $name
                SolutionArea = [string](Get-PurviewProperty -InputObject $result -Name 'solutionArea')
                # The raw collector status beside a verdict reads as two conflicting conclusions,
                # so this column says only whether the data was read.
                Collection = switch ([string](Get-PurviewProperty -InputObject $result -Name 'status')) {
                    'Success' { 'Collection succeeded' }
                    'PartialSuccess' { 'Read in part' }
                    'NotConnected' { 'Not connected' }
                    'NotPermitted' { 'Not permitted' }
                    'NotLicensed' { 'No available license' }
                    'Unsupported' { 'Not collected here' }
                    default { 'Not read' }
                }
                Rules = $ruleIds.Count
                Assessment = if ($ruleIds.Count -eq 0 -and $readBy.Count -gt 0) { 'Reported in {0}' -f ($readBy -join ' and ') }
                elseif ($ruleIds.Count -eq 0 -and $inInventory -contains $name) { 'Reported in the configuration inventory' }
                elseif ($ruleIds.Count -eq 0) { 'Collected as context, no check reads it' }
                elseif ($tally.Count -eq 0) { 'Not assessed' }
                else { $tally -join ', ' }
            })
    }

    return $output.ToArray()
}

function Test-PurviewSuiteSku {
    <#
    .SYNOPSIS
        Tests whether a SKU matches the optional verified product registry.

    .DESCRIPTION
        The registry is not an exhaustive catalog. This compatibility helper does not decide
        which subscriptions are displayed or whether configuration checks run.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()][object]$Sku)

    return (Get-PurviewSkuEvidence -Sku $Sku).Classification -eq 'Recognized'
}

function Get-PurviewLicensingAnalysis {
    <# .SYNOPSIS Reports all returned subscriptions and their observed Graph fields. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $block = Get-PurviewProperty -InputObject $Snapshot -Name 'licensing'
    # Preserve null records as unnamed malformed rows without changing the snapshot or resolver.
    if (Test-PurviewProperty -InputObject $block -Name 'subscribedSkus') {
        $rawSkus = $null
        if ($block -is [System.Collections.IDictionary]) { $rawSkus = $block['subscribedSkus'] }
        else { $rawSkus = $block.PSObject.Properties['subscribedSkus'].Value }
        if ($null -ne $rawSkus) {
            $reportSkus = @($rawSkus)
            for ($i = 0; $i -lt $reportSkus.Count; $i++) {
                if ($null -eq $reportSkus[$i]) { $reportSkus[$i] = [pscustomobject]@{} }
            }
            $block = @{
                collected = Get-PurviewProperty -InputObject $block -Name 'collected'
                complete = Get-PurviewProperty -InputObject $block -Name 'complete'
                conflicted = Get-PurviewProperty -InputObject $block -Name 'conflicted'
                subscribedSkus = $reportSkus
            }
        }
    }
    # Retained for caller compatibility. Licensing is advisory, not a configuration-check gate.
    $null = $Finding
    $output = [System.Collections.Generic.List[object]]::new()
    $evidence = Resolve-PurviewLicensingEvidence -Licensing $block

    if (-not $evidence.Collected -or -not $evidence.ListReadable) {
        $output.Add([pscustomobject]@{
                Sku = 'Not collected'
                State = 'Not read'
                Detail = 'No confirmed subscription read with a readable SKU list was recorded. Any returned records below are unconfirmed observations; configuration checks still run.'
                SkuPartNumber = ''; SkuId = ''
            })
    }
    elseif ($evidence.BlockConflict) {
        $output.Add([pscustomobject]@{
                Sku = 'Subscription read'
                State = 'Conflicting results'
                Detail = 'Duplicate licensing collector results disagreed. Returned records are shown separately without reconciling their statuses or seats; no tenant total is inferred.'
                SkuPartNumber = ''; SkuId = ''
            })
    }
    elseif (-not $evidence.Complete) {
        $output.Add([pscustomobject]@{
                Sku = 'Subscription read'
                State = 'Partial'
                Detail = 'The subscription read was incomplete. Returned records are shown, but an empty or partial list does not establish the tenant total. Configuration checks still run.'
                SkuPartNumber = ''; SkuId = ''
            })
    }
    elseif ($evidence.Entries.Count -eq 0) {
        $output.Add([pscustomobject]@{
                Sku = 'Tenant subscriptions'
                State = 'None returned'
                Detail = 'The complete Microsoft Graph read returned no subscribed SKU records. Configuration checks still run.'
                SkuPartNumber = ''; SkuId = ''
            })
    }

    foreach ($entry in $evidence.Entries) {
        $sku = $entry.Input
        $part = [string](Get-PurviewProperty -InputObject $sku -Name 'skuPartNumber')
        $id = [string](Get-PurviewProperty -InputObject $sku -Name 'skuId')
        $status = [string](Get-PurviewProperty -InputObject $sku -Name 'capabilityStatus')
        $productName = if ($entry.Classification -eq 'Recognized') { [string]$entry.Product.DisplayName }
        elseif (-not [string]::IsNullOrWhiteSpace($part)) { $part }
        elseif (-not [string]::IsNullOrWhiteSpace($id)) { $id }
        else { 'Unnamed subscription record' }

        # Retain every record for diagnostics; the customer summary uses the verified product set.
        $detailParts = [System.Collections.Generic.List[string]]::new()
        $notes = [System.Collections.Generic.List[string]]::new()
        $detailParts.Add("SKU part number: $(if ($part) { $part } else { 'not reported' }); SKU ID: $(if ($id) { $id } else { 'not reported' }).")
        $enabledText = if ($null -ne $entry.EnabledSeats) { [string]$entry.EnabledSeats } else { 'not reported or invalid' }
        $assignedText = if ($null -ne $entry.ConsumedSeats) { [string]$entry.ConsumedSeats } else { 'not reported or invalid' }
        $detailParts.Add("Graph enabled seats: $enabledText; assigned seats: $assignedText.")
        $plans = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $sku -Name 'servicePlans'))
        if (Test-PurviewProperty -InputObject $sku -Name 'servicePlans') {
            $detailParts.Add("Service plan records retained: $($plans.Count); see snapshot.json licensing.subscribedSkus[].servicePlans for names, IDs and provisioning statuses where returned.")
        }
        else { $detailParts.Add('Service plans not reported; see snapshot.json for retained subscription evidence.') }
        if ($entry.Classification -eq 'Malformed') {
            $detailParts.Add('SKU identity is missing or malformed; raw fields are shown without a friendly product match.')
            $notes.Add('Incomplete or invalid product identity.')
        }
        if ($entry.Classification -eq 'Conflict') {
            $detailParts.Add('SKU part number and ID conflict with the optional product registry; raw fields are shown without a friendly product match.')
            $notes.Add('Product identifiers disagree; confirm the product.')
        }
        if (-not $entry.StatusKnown -and -not [string]::IsNullOrWhiteSpace($status)) {
            $detailParts.Add('The capabilityStatus value is shown as returned, without interpreting it.')
        }
        if ($evidence.BlockConflict) { $detailParts.Add('Conflicting collector results: these are the fields from this returned record, not reconciled values.') }
        elseif ($id -and @($evidence.Entries | Where-Object {
                    [string](Get-PurviewProperty -InputObject $_.Input -Name 'skuId') -ieq $id
                }).Count -gt 1) {
            $detailParts.Add('This SKU ID occurs in multiple returned records; compare their observed fields rather than adding their seats.')
            $notes.Add('Repeated subscription record; do not add these seats together.')
        }

        $output.Add([pscustomobject]@{
                Sku = $productName
                State = if (-not [string]::IsNullOrWhiteSpace($status)) { $status } else { 'Not reported' }
                Detail = ($detailParts -join ' ')
                SkuPartNumber = $part
                SkuId = $id
                # Additive presentation fields: retain the existing diagnostic Detail for callers.
                IsSubscription = $true
                ShowInSummary = $entry.Classification -eq 'Recognized' -and $status -ine 'Deleted'
                EnabledSeats = $entry.EnabledSeats
                AssignedSeats = $entry.ConsumedSeats
                Note = ($notes -join ' ')
            })
    }

    return $output.ToArray()
}

function Get-PurviewRemediationPart {
    <#
    .SYNOPSIS
        Builds reusable parts for complete or selected remediation scripts.

    .DESCRIPTION
        The report assembles selected actions; the file on disk includes all actions. Both use
        these parts to keep generated PowerShell consistent.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Prerequisite,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TenantName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$GeneratedAt,
        [AllowEmptyString()][string]$TenantId = '',
        [AllowEmptyString()][string]$AdminUrl = ''
    )

    $nl = [Environment]::NewLine
    $parsedTenantId = [guid]::Empty
    $safeTenantId = if ([guid]::TryParse($TenantId, [ref]$parsedTenantId) -and
        $parsedTenantId -ne [guid]::Empty) { $parsedTenantId.ToString('D') } else { '' }
    # Sanitize untrusted tenant text so line breaks and terminators cannot escape the header comment.
    $safeHeader = { param($s) ((([string]$s) -replace '[\r\n]+', ' ') -replace '#>', '#').Trim() }
    # Every assembled download uses this guard before any module or service setup.
    $runtimeBootstrap = @'
# Relaunch the saved script, not an interpolated command, before any remediation can run.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    if ($MyInvocation.InvocationName -eq '.' -or [string]::IsNullOrWhiteSpace($PSCommandPath) -or
        -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        throw 'Run the saved remediation .ps1 file as a script so it can restart safely in PowerShell 7.'
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Start this remediation script in PowerShell 7 or later. No remediation was attempted.'
    }
    $bootstrapLocation = Get-Location
    if ($bootstrapLocation.Provider.Name -ne 'FileSystem') {
        throw 'Run the remediation script from a filesystem directory.'
    }
    $bootstrapCandidates = @()
    foreach ($bootstrapPair in @(
            @($env:ProgramFiles, 'PowerShell\7\pwsh.exe'),
            @(${env:ProgramFiles(x86)}, 'PowerShell\7\pwsh.exe'),
            @($env:LOCALAPPDATA, 'Microsoft\WindowsApps\pwsh.exe'))) {
        if ($bootstrapPair[0]) { $bootstrapCandidates += (Join-Path $bootstrapPair[0] $bootstrapPair[1]) }
    }
    $bootstrapOnPath = Get-Command -Name pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($bootstrapOnPath) { $bootstrapCandidates += $bootstrapOnPath.Source }
    $bootstrapPwsh = ''
    foreach ($bootstrapCandidate in @($bootstrapCandidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $bootstrapCandidate -PathType Leaf)) { continue }
        try {
            # Constant engine-only probe; no script path, tenant data or arguments enter code.
            & $bootstrapCandidate -NoLogo -NoProfile -NonInteractive -Command 'if ($PSVersionTable.PSVersion.Major -ge 7) { exit 0 }; exit 1' *> $null
            if ($LASTEXITCODE -eq 0) { $bootstrapPwsh = $bootstrapCandidate; break }
        }
        catch { continue }
    }
    if (-not $bootstrapPwsh) {
        throw 'PowerShell 7 could not be found and verified. Install PowerShell 7 through your approved software process, then rerun this file. No remediation was attempted.'
    }
    $bootstrapArguments = @('-NoLogo', '-NoProfile', '-File', $PSCommandPath)
    foreach ($bootstrapEntry in $PSBoundParameters.GetEnumerator()) {
        if ($bootstrapEntry.Value -is [switch]) {
            $bootstrapArguments += ('-{0}:${1}' -f $bootstrapEntry.Key, $bootstrapEntry.Value.IsPresent.ToString().ToLowerInvariant())
        }
        elseif ($bootstrapEntry.Value -is [array]) {
            throw 'An array-valued argument cannot be safely forwarded. Run this file directly in PowerShell 7.'
        }
        else { $bootstrapArguments += @(('-' + $bootstrapEntry.Key), [string]$bootstrapEntry.Value) }
    }
    # Windows PowerShell native splatting drops empty strings and embedded quotes. Quote each
    # Windows process argument explicitly; -File keeps every script argument as data.
    $bootstrapQuoted = foreach ($bootstrapArgument in $bootstrapArguments) {
        '"' + [regex]::Replace([regex]::Replace([string]$bootstrapArgument, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
    }
    $bootstrapStart = New-Object System.Diagnostics.ProcessStartInfo
    $bootstrapStart.FileName = $bootstrapPwsh
    $bootstrapStart.Arguments = $bootstrapQuoted -join ' '
    $bootstrapStart.WorkingDirectory = $bootstrapLocation.ProviderPath
    $bootstrapStart.UseShellExecute = $false
    $bootstrapProcess = New-Object System.Diagnostics.Process
    $bootstrapProcess.StartInfo = $bootstrapStart
    Write-Host 'Restarting this remediation script in PowerShell 7. Sign-in and change confirmations will follow.' -ForegroundColor Cyan
    try {
        if (-not $bootstrapProcess.Start()) { throw 'PowerShell 7 could not be started. No remediation was attempted.' }
        $bootstrapProcess.WaitForExit()
        $bootstrapExitCode = $bootstrapProcess.ExitCode
    }
    finally { $bootstrapProcess.Dispose() }
    exit $bootstrapExitCode
}
'@
    $moduleSetup = @'
$script:RemediationModuleCache = @{}
$script:RemediationSpoSession = $null
$script:RemediationSpoModule = $null

function Get-PurviewRemediationModule {
    param(
        [ValidateSet('ExchangeOnlineManagement', 'Microsoft.Online.SharePoint.PowerShell', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Beta.Identity.DirectoryManagement')]
        [string]$Name,
        [version]$MinimumVersion = [version]'0.0'
    )
    if ($script:RemediationModuleCache.ContainsKey($Name)) {
        $module = $script:RemediationModuleCache[$Name]
        if ($module.Version -lt $MinimumVersion) { throw "$Name does not meet the required version $MinimumVersion." }
        return $module
    }
    $available = @(Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1)
    $module = if ($available.Count) { $available[0] } else { $null }
    $required = $null -eq $module -or $module.Version -lt $MinimumVersion
    $canPrompt = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
    $latest = $null
    if ($canPrompt) {
        Assert-PurviewGalleryRepository
        try {
            $published = @(Find-Module -Name $Name -Repository PSGallery -ErrorAction Stop)
            if ($published.Count -ne 1 -or [string]$published[0].Name -ne $Name -or
                [string]$published[0].Repository -ne 'PSGallery') { throw 'The module lookup returned an unexpected result.' }
            $latest = [version]$published[0].Version
        }
        catch {
            if ($required) { throw "Required dependency $Name could not be located in PSGallery. Resolve module setup before rerunning this script." }
            Write-Warning "An update check for $Name did not complete. Keeping the installed version." -WarningAction Continue
        }
    }
    if ($required -and (-not $canPrompt -or $null -eq $latest -or $latest -lt $MinimumVersion)) {
        throw "$Name version $MinimumVersion or later is required. Run this script interactively in PowerShell 7 to approve dependency setup. No tenant change was attempted."
    }
    $newer = $null -ne $latest -and ($null -eq $module -or $latest -gt $module.Version)
    if ($required -or $newer) {
        $verb = if ($null -eq $module) { 'Install' } else { 'Update' }
        $now = if ($null -eq $module) { 'Not installed' } else { "Installed version $($module.Version)" }
        $installCommand = "Install-Module $Name -RequiredVersion $latest -Scope CurrentUser -Repository PSGallery -Force"
        if (Confirm-PurviewChange -Change "$verb $Name to $latest for the current user" -Now $now `
                -Why 'This selected remediation requires the module. Updating local modules can affect other scripts.' `
                -Command $installCommand) {
            Assert-PurviewGalleryRepository
            $loadedBefore = @(Get-Module -Name $Name)
            Install-Module -Name $Name -RequiredVersion $latest -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
            # A module install can also install dependencies. Recheck their discovered versions.
            $script:RemediationModuleCache.Clear()
            $available = @(Get-Module -ListAvailable -Name $Name | Where-Object { $_.Version -eq $latest } | Select-Object -First 1)
            if ($available.Count -ne 1) { throw "$Name was not discoverable at the approved version after installation." }
            $module = $available[0]
            if ($loadedBefore.Count -gt 0) {
                throw "$Name was updated on disk but was already loaded. Start a fresh PowerShell 7 session and rerun this script before applying changes."
            }
        }
        elseif ($required) { throw "Required dependency setup for $Name was declined. No tenant change was attempted." }
    }
    if ($null -eq $module -or $module.Version -lt $MinimumVersion -or
        [string]::IsNullOrWhiteSpace([string]$module.Path) -or -not (Test-Path -LiteralPath $module.Path -PathType Leaf)) {
        throw "$Name does not have a usable installed module file. No tenant change was attempted."
    }
    $script:RemediationModuleCache[$Name] = $module
    return $module
}

function Import-PurviewRemediationModule {
    param([string]$Name)
    $module = Get-PurviewRemediationModule -Name $Name
    $loaded = @(Get-Module -Name $Name)
    if ($loaded.Count -gt 0) {
        if ($loaded.Count -ne 1 -or $loaded[0].Version -ne $module.Version) {
            throw "$Name has a different or ambiguous loaded version. Start a fresh PowerShell 7 session and rerun this script."
        }
        return
    }
    try { Import-Module -Name $module.Path -Global -ErrorAction Stop }
    catch {
        Write-Host "$Name could not be loaded in PowerShell 7: $($_.Exception.Message)" -ForegroundColor Yellow
        throw "$Name could not be loaded; prerequisite setup stopped before tenant changes."
    }
}

function Clear-PurviewRemediationSharePoint {
    # Never disconnect or remove sessions/modules that this script did not create.
    if ($null -ne $script:RemediationSpoModule) {
        try { Remove-Module -ModuleInfo $script:RemediationSpoModule -Force -ErrorAction Stop }
        catch { Write-Warning 'The remediation SharePoint command proxy could not be removed.' -WarningAction Continue }
        $script:RemediationSpoModule = $null
    }
    if ($null -ne $script:RemediationSpoSession) {
        try { Remove-PSSession -Session $script:RemediationSpoSession -ErrorAction Stop }
        catch { Write-Warning 'The remediation SharePoint compatibility session could not be removed.' -WarningAction Continue }
        $script:RemediationSpoSession = $null
    }
}

function Import-PurviewRemediationSharePoint {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'SharePoint Online remediation requires Windows.'
    }
    $module = Get-PurviewRemediationModule -Name 'Microsoft.Online.SharePoint.PowerShell' -MinimumVersion '16.0.26914.12004'
    $modulePath = [string]$module.Path
    $commands = @('Connect-SPOService', 'Disconnect-SPOService', 'Get-SPOTenant', 'Set-SPOTenant')
    try {
        $script:RemediationSpoSession = New-PSSession -UseWindowsPowerShell `
            -Name ('PurviewRemediationSharePoint-' + [guid]::NewGuid().ToString('D')) -ErrorAction Stop
        # Discovery happens in PS7. The isolated Windows PowerShell session imports that exact
        # file, including when it was installed only in the PowerShell 7 CurrentUser directory.
        $null = Invoke-Command -Session $script:RemediationSpoSession -ErrorAction Stop -ScriptBlock {
            Import-Module -Name $using:modulePath -ErrorAction Stop
        }
        $proxy = @(Import-PSSession -Session $script:RemediationSpoSession `
            -Module Microsoft.Online.SharePoint.PowerShell -CommandName $commands `
            -AllowClobber -DisableNameChecking -ErrorAction Stop)
        if ($proxy.Count -ne 1) { throw 'The SharePoint remediation proxy was not created uniquely.' }
        $script:RemediationSpoModule = $proxy[0]
        foreach ($name in $commands) {
            if (-not $script:RemediationSpoModule.ExportedCommands.ContainsKey($name)) {
                throw "The isolated SharePoint module did not export $name."
            }
        }
        Import-Module -ModuleInfo $script:RemediationSpoModule -Global -ErrorAction Stop
    }
    catch {
        Clear-PurviewRemediationSharePoint
        throw
    }
}
'@
    $header = @(
        '<#'
        '    Remediation for Microsoft Purview tenant opt-ins.'
        '    Supported scope: Microsoft 365 commercial cloud only, including education tenants'
        '    in that cloud. GCC, GCC High, DoD and China are not supported or validated by this release.'
        '    When retained, the assessed tenant ID is verified for Graph, Security & Compliance'
        '    and Exchange Online.'
        '    SharePoint is reconnected to the reviewed admin URL. Verify the cloud independently.'
        ''
        "    Tenant:     $(& $safeHeader $TenantName)"
        "    Assessed:   $(& $safeHeader $GeneratedAt)"
        "    Generator:  Purview advisor $script:ToolVersion"
        '    Changes:    {COUNT}'
        ''
        '    Review each action and its scope through change control before running.'
        '    Tenant changes require confirmation. Module/session setup and local file'
        '    operations can occur separately from those confirmations.'
        '#>'
        ''
        '[CmdletBinding()]'
        ("param([string]`$AdminUrl = {0})" -f (ConvertTo-PurviewPowerShellLiteral -Value $AdminUrl))
        ''
        "`$ErrorActionPreference = 'Stop'"
        $runtimeBootstrap
        ''
        ('$expectedTenantId = {0}' -f (ConvertTo-PurviewPowerShellLiteral -Value $safeTenantId))
        ''
        'function Confirm-PurviewChange {'
        '    param([string]$Change, [string]$Now, [string]$Why, [string]$Caution, [string]$Reference, [string]$Command)'
        '    Write-Host ""'
        '    Write-Host $Change -ForegroundColor Cyan'
        '    if ($Now) { Write-Host "  Now:       $Now" }'
        '    if ($Why) { Write-Host "  Why:       $Why" }'
        '    if ($Caution) { Write-Host "  CAUTION:   $Caution" -ForegroundColor Yellow }'
        '    if ($Reference) { Write-Host "  Reference: $Reference" }'
        '    Write-Host "  Command:   $Command"'
        '    # This confirmation gates the associated change, not all module/session or local file'
        '    # operations. A non-interactive host skips this change rather than assuming consent.'
        '    if (-not [Environment]::UserInteractive) { Write-Host "  Skipped: no interactive session to confirm in."; return $false }'
        '    return ((Read-Host "  Apply this change? [y/N]") -match "^\s*(y|yes)\s*$")'
        '}'
        ''
        $moduleSetup
        ''
        'function Assert-PurviewGalleryRepository {'
        '    $repositories = @(Get-PSRepository -Name ''PSGallery'' -ErrorAction Stop)'
        '    if ($repositories.Count -ne 1) { throw ''Exactly one PSGallery repository must be registered.'' }'
        '    $source = [string]$repositories[0].SourceLocation'
        '    $provider = [string]$repositories[0].PackageManagementProvider'
        '    $uri = $null'
        '    $valid = [uri]::TryCreate($source, [System.UriKind]::Absolute, [ref]$uri) -and'
        '        $uri.Scheme -eq ''https'' -and $uri.IdnHost -eq ''www.powershellgallery.com'' -and $uri.IsDefaultPort -and'
        '        $uri.AbsolutePath.TrimEnd(''/'') -eq ''/api/v2'' -and -not $uri.UserInfo -and'
        '        -not $uri.Query -and -not $uri.Fragment -and (-not $provider -or $provider -eq ''NuGet'')'
        '    if (-not $valid) {'
        '        throw ''PSGallery is not the official HTTPS PowerShell Gallery feed. Restore it with Register-PSRepository -Default.'''
        '    }'
        '}'
        ''
        'function Assert-PurviewExpectedTenant {'
        '    param([Parameter(Mandatory)]$Connection, [string]$Service)'
        '    if (-not $expectedTenantId) { return }'
        '    $actual = [string]$Connection.TenantID'
        '    if (-not $actual -or $actual -ine $expectedTenantId) {'
        '        throw "$Service is connected to a different or unverified tenant. Start a new PowerShell session and try again."'
        '    }'
        '}'
        ''
        'function Test-PurviewLiveSession {'
        '    param([string]$UriPattern)'
        '    # Compliance and Exchange Online export the same cmdlet names, so a session is'
        '    # recognised by the endpoint it points at rather than by what happens to be loaded.'
        '    if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $false }'
        '    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |'
        '        Where-Object { [string]$_.ConnectionUri -match $UriPattern -and [string]$_.State -eq "Connected" })'
        '    if ($connections.Count -ne 1) { return $false }'
        '    Assert-PurviewExpectedTenant -Connection $connections[0] -Service ''Security & Compliance'''
        '    return $true'
        '}'
        ''
        'function Connect-PurviewCompliance {'
        '    Import-PurviewRemediationModule -Name "ExchangeOnlineManagement"'
        '    if (Test-PurviewLiveSession -UriPattern "compliance\.protection\.outlook\.com") {'
        '        Write-Host "Reusing the Security & Compliance session already signed in."'
        '        return $true'
        '    }'
        '    try {'
        '        Connect-IPPSSession'
        '        $connections = @(Get-ConnectionInformation -ErrorAction Stop |'
        '            Where-Object { [string]$_.ConnectionUri -match ''compliance\.protection\.outlook\.com'' -and [string]$_.State -eq ''Connected'' })'
        '        if ($connections.Count -ne 1) { throw ''A unique Security & Compliance connection was not established.'' }'
        '        Assert-PurviewExpectedTenant -Connection $connections[0] -Service ''Security & Compliance'''
        '        return $true'
        '    }'
        '    catch {'
        '        # Graph and ExchangeOnlineManagement can load incompatible MSAL versions. Matching'
        '        # error text suggests a binding conflict but does not prove which module caused it.'
        '        # Ordering inside this script cannot undo a sign-in from earlier in the same window,'
        '        # so this reports the block and lets the changes that do not need it carry on.'
        '        if ($_.Exception -is [System.MissingMethodException] -or "$($_.Exception.Message)" -match "Microsoft\.Identity\.Client") {'
        '            Write-Host ""'
        '            Write-Host "Security & Compliance cannot be reached from this PowerShell session." -ForegroundColor Yellow'
        '            Write-Host "Microsoft Graph and ExchangeOnlineManagement each ship their own copy of MSAL," -ForegroundColor Yellow'
        '            Write-Host "which can conflict. This error does not establish the precise cause." -ForegroundColor Yellow'
        '            Write-Host "Anything needing it is skipped below and listed again at the end." -ForegroundColor Yellow'
        '            return $false'
        '        }'
        '        throw'
        '    }'
        '}'
        ''
        '# Set by the Security & Compliance connect block when one is needed.'
        '$complianceReady = $false'
        '$deferred = [System.Collections.Generic.List[string]]::new()'
        ''
        'function Invoke-PurviewInNewSession {'
        '    param([string]$Command)'
        '    # A child process loads its own MSAL, so a compliance command still runs when this one'
        '    # cannot reach the service. The window stays visible because signing in needs it.'
        '    $shell = (Get-Process -Id $PID).Path'
        '    $file = Join-Path ([System.IO.Path]::GetTempPath()) ("purview-step-{0}.ps1" -f [guid]::NewGuid())'
        '    Set-Content -LiteralPath $file -Encoding utf8 -Value @('
        '        ''param([string]$ExpectedTenantId)'','
        '        ''try {'','
        '        ''    Connect-IPPSSession -ErrorAction Stop'','
        '        ''    if ($ExpectedTenantId) {'','
        '        ''        $connections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { [string]$_.ConnectionUri -match "compliance\.protection\.outlook\.com" -and [string]$_.State -eq "Connected" })'','
        '        ''        if ($connections.Count -ne 1 -or [string]$connections[0].TenantID -ine $ExpectedTenantId) { throw "Security & Compliance connected to a different or unverified tenant." }'','
        '        ''    }'','
        '        "    $Command",'
        '        ''    Write-Host "Done." -ForegroundColor Green'','
        '        ''    exit 0'','
        '        ''}'','
        '        ''catch {'','
        '        ''    Write-Host $_.Exception.Message -ForegroundColor Red'','
        '        ''    Read-Host "Press Enter to close"'','
        '        ''    exit 1'','
        '        ''}'''
        '    )'
        '    $arguments = @(''-NoLogo'', ''-NoProfile'', ''-File'', $file)'
        '    if ($expectedTenantId) { $arguments += @(''-ExpectedTenantId'', $expectedTenantId) }'
        '    $run = Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru'
        '    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue'
        '    return $run.ExitCode -eq 0'
        '}'
        ''
        'try {'
    ) -join $nl

    # Repeat deferred steps at the end so unreachable services do not leave unfinished work unnoticed.
    $footer = @(
        ''
        'if ($deferred.Count -gt 0) {'
        '    Write-Host ""'
        '    Write-Host "Not finished. Close this window, open a new PowerShell session, and run:" -ForegroundColor Yellow'
        '    foreach ($item in $deferred) { Write-Host "  $item" -ForegroundColor Yellow }'
        '}'
        ''
        '}'
        'finally { Clear-PurviewRemediationSharePoint }'
        ''
    ) -join $nl

    # Order matters and is not cosmetic. Microsoft.Graph.Authentication and ExchangeOnlineManagement
    # each ship their own copy of MSAL, and .NET keeps whichever loads first. Connecting Graph first
    # leaves Connect-IPPSSession binding its newer broker extension against Graph's older MSAL, which
    # throws a MissingMethodException before any sign-in prompt appears. Graph therefore goes last.
    $connect = [ordered]@{
        SharePoint = @(
            '# SharePoint Online, for the tenant-wide labelling switches.'
            'if (-not $AdminUrl) { $AdminUrl = Read-Host ''SharePoint admin URL, such as https://contoso-admin.sharepoint.com'' }'
            'if (-not $AdminUrl) { throw ''A SharePoint admin URL is needed to apply these changes.'' }'
            '$adminUri = $null'
            '$validAdminUrl = [uri]::TryCreate($AdminUrl, [System.UriKind]::Absolute, [ref]$adminUri) -and'
            '    $adminUri.Scheme -eq ''https'' -and $adminUri.IsDefaultPort -and -not $adminUri.UserInfo -and'
            '    -not $adminUri.Query -and -not $adminUri.Fragment -and $adminUri.AbsolutePath -eq ''/'' -and'
            '    $adminUri.IdnHost -match ''^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-admin\.sharepoint\.com$'''
            'if (-not $validAdminUrl) { throw ''AdminUrl must be an HTTPS <tenant>-admin.sharepoint.com root URL.'' }'
            'Import-PurviewRemediationSharePoint'
            '# Always bind this write session to the reviewed admin URL. The module exposes no'
            '# supported connection identity that can prove an existing session targets it.'
            'try { Connect-SPOService -Url $AdminUrl -UseSystemBrowser $true -ErrorAction Stop }'
            'catch { Connect-SPOService -Url $AdminUrl -ErrorAction Stop }'
            '$null = Get-SPOTenant -ErrorAction Stop'
            ''
        ) -join $nl
        # A new audit connection imports only its two commands with a prefix so it cannot
        # replace commands used by the existing compliance remediation steps.
        ExchangeOnline = @'
# Exchange Online only: the compliance audit read can incorrectly report False.
Import-PurviewRemediationModule -Name 'ExchangeOnlineManagement'
function Get-PurviewAuditConnection {
    $active = @(ExchangeOnlineManagement\Get-ConnectionInformation -ErrorAction Stop |
        Where-Object { [string]$_.State -eq 'Connected' })
    $exchange = @(foreach ($connection in $active) {
        if ($connection.IsEopSession -isnot [bool]) { throw 'The service identity of an active Exchange connection is unavailable. Use a clean PowerShell window.' }
        if (-not $connection.IsEopSession) { $connection }
    })
    if ($exchange.Count -gt 1) { throw 'Multiple Exchange Online connections are active. Use a clean PowerShell window.' }
    if ($exchange.Count -eq 0) { return }
    $connection = $exchange[0]
    $uri = $null
    if (-not [uri]::TryCreate([string]$connection.ConnectionUri, [System.UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or $uri.IdnHost -ne 'outlook.office365.com' -or
        -not $uri.IsDefaultPort -or $uri.UserInfo) { throw 'The Exchange Online endpoint is not supported by this script.' }
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse([string]$connection.TenantID, [ref]$tenant) -or $tenant -eq [guid]::Empty -or
        -not [string]$connection.ConnectionId) { throw 'Exchange Online did not identify its tenant and connection.' }
    Assert-PurviewExpectedTenant -Connection $connection -Service 'Exchange Online'
    return $connection
}
$auditConnection = Get-PurviewAuditConnection
if ($null -eq $auditConnection) {
    ExchangeOnlineManagement\Connect-ExchangeOnline -ExchangeEnvironmentName O365Default -Prefix PurviewAudit `
        -CommandName Get-AdminAuditLogConfig,Set-AdminAuditLogConfig -ErrorAction Stop
    $auditConnection = Get-PurviewAuditConnection
}
if ($null -eq $auditConnection) { throw 'A verified Exchange Online connection was not established.' }
$auditConnectionId = [string]$auditConnection.ConnectionId
$auditTenantId = [string]$auditConnection.TenantID
if (-not $expectedTenantId) { Write-Warning 'The assessed tenant ID is absent or redacted. Independently verify the Exchange Online tenant shown before confirming.' }

function Get-PurviewAuditCommand {
    param([ValidateSet('Get', 'Set')][string]$Verb)
    # Resolve on every call, including after confirmation; never use an unqualified audit cmdlet.
    $connection = Get-PurviewAuditConnection
    if ($null -eq $connection -or [string]$connection.ConnectionId -ne $auditConnectionId -or
        [string]$connection.TenantID -ine $auditTenantId) { throw 'The Exchange Online connection changed. No further audit operation is safe.' }
    $path = [string]$connection.ModuleName
    $leaf = [System.IO.Path]::GetFileName($path)
    $modules = @(Get-Module | Where-Object { $path -and ($_.Path -eq $path -or $_.Name -eq $leaf) })
    if ($modules.Count -ne 1) { throw 'The Exchange Online command module could not be identified uniquely.' }
    $name = '{0}-{1}AdminAuditLogConfig' -f $Verb, [string]$connection.ModulePrefix
    if (-not $modules[0].ExportedCommands.ContainsKey($name)) { throw "$name is unavailable in the verified Exchange Online session. Check Exchange RBAC and use a clean PowerShell window." }
    $command = $modules[0].ExportedCommands[$name]
    if ($Verb -eq 'Set' -and -not $command.Parameters.ContainsKey('UnifiedAuditLogIngestionEnabled')) {
        throw 'The unified audit enablement parameter is unavailable. Check the Audit Logs role in Exchange Online.'
    }
    return $command
}
function Get-PurviewAuditEnabled {
    $config = @(& (Get-PurviewAuditCommand -Verb Get) -ErrorAction Stop)
    $enabled = $false
    if ($config.Count -ne 1 -or
        ($config[0].UnifiedAuditLogIngestionEnabled -isnot [bool] -and $config[0].UnifiedAuditLogIngestionEnabled -isnot [string]) -or
        -not [bool]::TryParse([string]$config[0].UnifiedAuditLogIngestionEnabled, [ref]$enabled)) {
        throw 'Exchange Online did not return one usable audit state. The current state is unknown; no further audit change is safe.'
    }
    return $enabled
}
function Write-PurviewAuditFailureGuidance {
    param([ValidateSet('enablement command', 'verification read')][string]$Stage)
    $moduleVersions = @(Get-Module -Name ExchangeOnlineManagement | ForEach-Object { [string]$_.Version }) -join ', '
    Write-Warning (('Audit {0} failed at {1}. PowerShell {2}; ExchangeOnlineManagement {3}. The original error follows.' -f
        $Stage, [DateTimeOffset]::Now.ToString('o'), $PSVersionTable.PSVersion, $moduleVersions)) -WarningAction Continue
    Write-Warning 'No automatic enablement retry will be made. A failed response does not prove that the setting was unchanged.' -WarningAction Continue
    Write-Warning 'An error is not confirmation that a change is pending. Use the readback state below before considering another attempt.' -WarningAction Continue
    Write-Warning 'A generic server error does not identify the cause. Preserve the original error, failure time and module version for Microsoft support through an approved channel; never share tokens or credentials.' -WarningAction Continue
}
function Write-PurviewAuditFollowUp {
    param([Parameter(Mandatory)][ValidateSet('Enabled', 'NotConfirmed', 'Unknown')][string]$State)
    if ($State -eq 'Enabled') {
        Write-Host '  Audit ingestion is enabled. Do not rerun enablement. This does not verify event ingestion or search readiness.'
        return
    }
    if ($State -eq 'NotConfirmed') {
        Write-Warning 'Audit enablement is not confirmed: Exchange Online currently reports UnifiedAuditLogIngestionEnabled = False. The setting may still be propagating, or the write may not have taken effect.' -WarningAction Continue
    }
    else {
        Write-Warning 'Audit state is unknown because the read failed. Do not attempt another audit change until the state can be read.' -WarningAction Continue
    }
    Write-Host '  Read-only check: in a fresh PowerShell 7 window, connect only to Exchange Online for the same reviewed tenant, not Security & Compliance, then run:'
    Write-Host '    Get-AdminAuditLogConfig -ErrorAction Stop | Format-List UnifiedAuditLogIngestionEnabled'
    Write-Warning 'Microsoft documents up to 60 minutes for enablement to take effect; searchable events can take several hours. Recheck the setting read-only after 60 minutes from the attempt. True means do not rerun enablement.' -WarningAction Continue
    Write-Warning 'For an unexplained service error, timeout or unconfirmed change, wait 24 hours from the attempt before considering another enablement write, then check the state again first. This is conservative retry guidance, not a Microsoft requirement or a guarantee of success; read-only checks can be made sooner.' -WarningAction Continue
    Write-Warning 'Investigate sign-in, permission and connection/tenant errors immediately; waiting is not a fix. Check Microsoft 365 service health. If the state is still False or unreadable after 24 hours, use Microsoft support rather than repeated writes. This script does not wait, schedule checks or retry the change.' -WarningAction Continue
}
'@
        SecurityAndCompliance = @(
            '# Security & Compliance, before Graph so its own MSAL is the copy .NET keeps.'
            '$complianceReady = Connect-PurviewCompliance'
            ''
        ) -join $nl
        Graph = @(
            '# Microsoft Graph, for the Microsoft Entra directory setting behind container labels.'
            '# Microsoft documents these two modules for this change rather than the whole SDK.'
            '# Resolve the directory module and its dependencies before loading authentication.'
            '$null = Get-PurviewRemediationModule -Name ''Microsoft.Graph.Beta.Identity.DirectoryManagement'''
            'foreach ($module in @(''Microsoft.Graph.Authentication'', ''Microsoft.Graph.Beta.Identity.DirectoryManagement'')) {'
            '    Import-PurviewRemediationModule -Name $module'
            '}'
            '# Signing in again is only worth it when the session on hand lacks the scope to write.'
            '$graphScope = ''Directory.ReadWrite.All'''
            '$graphContext = Get-MgContext -ErrorAction SilentlyContinue'
            '$graphReady = $graphContext -and $graphScope -in @($graphContext.Scopes) -and'
            '    (-not $expectedTenantId -or [string]$graphContext.TenantId -ieq $expectedTenantId)'
            'if ($graphReady) { Write-Host ''Reusing the Microsoft Graph session already signed in.'' }'
            'else {'
            '    $graphArguments = @{ Scopes = $graphScope; Environment = ''Global''; ContextScope = ''Process'' }'
            '    if ($expectedTenantId) { $graphArguments[''TenantId''] = $expectedTenantId }'
            '    Connect-MgGraph @graphArguments'
            '}'
            '$graphContext = Get-MgContext -ErrorAction Stop'
            'if ($expectedTenantId -and [string]$graphContext.TenantId -ine $expectedTenantId) {'
            '    throw ''Microsoft Graph connected to a different or unverified tenant.'''
            '}'
            ''
        ) -join $nl
    }

    $items = [System.Collections.Generic.List[object]]::new()
    # Flatten tenant text to one line so it cannot escape a generated comment and become code.
    $comment = { param($s) (([string]$s) -replace '[\r\n]+', ' ').Trim() }
    # Single quotes around the command: one containing $true must reach the operator literally
    # rather than interpolating when it is printed for confirmation.
    $q = ${function:ConvertTo-PurviewPowerShellLiteral}
    foreach ($item in @($Prerequisite | Where-Object { ($_.State -eq 'Needs attention' -and ($_.Command -or $null -ne $_.Script)) -or @($_.Candidates).Count -gt 0 })) {
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add(('# {0}' -f (& $comment $item.Name)))
        $lines.Add(('#   Now:         {0}' -f (& $comment $item.Detail)))
        $lines.Add(('#   Why:         {0}' -f (& $comment $item.Why)))
        if ($item.Caution) { $lines.Add(('#   CAUTION:     {0}' -f (& $comment $item.Caution))) }
        $lines.Add(('#   Reference:   {0}' -f (& $comment $item.Url)))

        if ([string]$item.Session -eq 'ExchangeOnline') {
            if ($item.Command -cne 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true') {
                throw 'Only unified audit enablement is supported by the Exchange Online remediation block.'
            }
            $lines.Add('if (Get-PurviewAuditEnabled) { Write-Host ''  Unified audit ingestion is already enabled. No change made.'' }')
            $lines.Add(('elseif (Confirm-PurviewChange -Change {0} -Now ("Disabled; Exchange Online tenant: " + $auditTenantId) -Why {1} -Caution {2} -Reference {3} -Command {4}) {{' -f
                    (& $q $item.Name), (& $q $item.Why), (& $q $item.Caution), (& $q $item.Url), (& $q $item.Command)))
            $lines.Add('    if (Get-PurviewAuditEnabled) { Write-Host ''  Unified audit ingestion was enabled since the first read. No change made.'' }')
            $lines.Add('    else {')
            $lines.Add('        try {')
            $lines.Add('            & (Get-PurviewAuditCommand -Verb Set) -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop')
            $lines.Add('        }')
            $lines.Add('        catch {')
            $lines.Add('            $auditEnableError = $_')
            $lines.Add('            Write-PurviewAuditFailureGuidance -Stage ''enablement command''')
            $lines.Add('            # One read-only recovery check, still bound to the original connection and tenant.')
            $lines.Add('            # Never retry the write or conceal the original failure, even if this read is True.')
            $lines.Add('            $auditRecoveryState = ''Unknown''')
            $lines.Add('            try {')
            $lines.Add('                $auditRecoveryEnabled = Get-PurviewAuditEnabled')
            $lines.Add('                $auditRecoveryState = if ($auditRecoveryEnabled) { ''Enabled'' } else { ''NotConfirmed'' }')
            $lines.Add('                Write-Warning (''Read-only recovery check: UnifiedAuditLogIngestionEnabled = {0}. This does not verify event ingestion or establish which operation changed the setting.'' -f $auditRecoveryEnabled) -WarningAction Continue')
            $lines.Add('            }')
            $lines.Add('            catch { Write-Warning ''The read-only recovery check also failed. Current audit state is unknown; the original enablement error is retained below.'' -WarningAction Continue }')
            $lines.Add('            Write-PurviewAuditFollowUp -State $auditRecoveryState')
            $lines.Add('            throw $auditEnableError')
            $lines.Add('        }')
            $lines.Add('        Write-Host ''  Enablement command completed. It can take up to 60 minutes to take effect; searchable events can take several hours.''')
            $lines.Add('        try { $auditEnabledAfter = Get-PurviewAuditEnabled }')
            $lines.Add('        catch {')
            $lines.Add('            Write-PurviewAuditFailureGuidance -Stage ''verification read''')
            $lines.Add('            Write-Warning ''The enablement command completed, but its result could not be verified. Do not rerun the write solely because verification failed.'' -WarningAction Continue')
            $lines.Add('            Write-PurviewAuditFollowUp -State ''Unknown''')
            $lines.Add('            throw')
            $lines.Add('        }')
            $lines.Add('        Write-Host (''  Exchange Online currently reports UnifiedAuditLogIngestionEnabled = {0}. This does not verify event ingestion.'' -f $auditEnabledAfter)')
            $lines.Add('        if ($auditEnabledAfter) { Write-PurviewAuditFollowUp -State ''Enabled'' }')
            $lines.Add('        else { Write-PurviewAuditFollowUp -State ''NotConfirmed'' }')
            $lines.Add('    }')
            $lines.Add('}')
            $lines.Add('else { Write-Host ''  Skipped.'' }')
            $lines.Add('')
            $items.Add([pscustomobject]@{
                    name = [string]$item.Name
                    session = @('ExchangeOnline')
                    caution = [bool]$item.Caution
                    file = 'Set-UnifiedAuditLogIngestionEnabled.ps1'
                    block = ($lines -join $nl)
                })
            continue
        }

        if ($null -ne $item.Script) {
            if ([string]$item.Script.Builder -eq 'ContainerLabel') {
                # If group settings were never written, create Group.Unified from its template;
                # otherwise update it. Both paths set the same value without operator branching.
                $lines.Add('$grpUnifiedSetting = Get-MgBetaDirectorySetting | Where-Object { $_.Values.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1')
                $lines.Add('$currentValue = if ($grpUnifiedSetting) { [string]($grpUnifiedSetting.Values | Where-Object { $_.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1 -ExpandProperty Value) } else { '''' }')
                $lines.Add('if ($currentValue -eq ''True'') { Write-Host ''  EnableMIPLabels is already True. No change to this setting is needed.'' }')
                $lines.Add(('elseif (Confirm-PurviewChange -Change {0} -Now {1} -Why {2} -Caution {3} -Reference {4} -Command {5}) {{' -f
                        (& $q $item.Name), (& $q $item.Detail), (& $q $item.Why), (& $q $item.Caution), (& $q $item.Url),
                        (& $q 'Update-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -BodyParameter $params')))
                $lines.Add('    $params = @{ values = @(@{ name = ''EnableMIPLabels''; value = ''True'' }) }')
                $lines.Add('    if ($grpUnifiedSetting) {')
                $lines.Add('        Update-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -BodyParameter $params')
                $lines.Add('    }')
                $lines.Add('    else {')
                $lines.Add('        $templateId = [string](Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq ''Group.Unified'' }).Id')
                $lines.Add('        $null = New-MgBetaDirectorySetting -BodyParameter @{ templateId = $templateId; values = @(@{ name = ''EnableMIPLabels''; value = ''True'' }) }')
                $lines.Add('    }')
                $lines.Add('    $check = Get-MgBetaDirectorySetting | Where-Object { $_.Values.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1')
                $lines.Add('    Write-Host ("  EnableMIPLabels is now {0}." -f [string]($check.Values | Where-Object { $_.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1 -ExpandProperty Value))')
                # Turning the setting on is only half of it: a label reaches Entra through the sync,
                # and Microsoft documents up to 24 hours before it can be assigned to a group.
                $lines.Add('    if ($complianceReady) {')
                $lines.Add('        Execute-AzureAdLabelSync')
                $lines.Add('        Write-Host ''  Label sync command completed. Verify availability after propagation.''')
                $lines.Add('    }')
                $lines.Add('    else {')
                $lines.Add('        Write-Host ''  EnableMIPLabels is set, but this session cannot reach Security & Compliance.'' -ForegroundColor Yellow')
                $lines.Add('        Write-Host ''  Label sync was not completed by this step. Verify existing label availability separately.'' -ForegroundColor Yellow')
                $lines.Add('        $syncCommand = ''Connect-IPPSSession; Execute-AzureAdLabelSync''')
                $lines.Add('        if (Confirm-PurviewChange -Change ''Synchronise the labels in a new PowerShell window'' -Why ''A new process is not bound to the sign-in library this one already loaded, so the sync can still be completed now.'' -Command $syncCommand) {')
                $lines.Add('            if (Invoke-PurviewInNewSession -Command ''Execute-AzureAdLabelSync'') {')
                $lines.Add('                Write-Host ''  Label sync command completed. Verify availability after propagation.'' -ForegroundColor Green')
                $lines.Add('            }')
                $lines.Add('            else { $deferred.Add($syncCommand) }')
                $lines.Add('        }')
                $lines.Add('        else { $deferred.Add($syncCommand) }')
                $lines.Add('    }')
                $lines.Add('}')
                $lines.Add('else { Write-Host ''  Skipped.'' }')
                $lines.Add('')

                $items.Add([pscustomobject]@{
                        name = [string]$item.Name
                        session = @($item.Script.Session)
                        caution = [bool]$item.Caution
                        file = [string]$item.Script.File
                        block = ($lines -join $nl)
                    })
                continue
            }

            # Migration and post-migration unpublishing require a separate reviewed workflow.
            # Never turn an unknown builder into a label-policy write.
            throw 'Unsupported remediation script builder. Review label-scheme migration separately in the Purview portal.'
        }

        if (@($item.Candidates).Count -gt 0) {
            # Which of these should go live is a decision per policy, so the script lists them and
            # applies only what is chosen rather than turning the whole set on.
            $quoted = @($item.Candidates | ForEach-Object { & $q $_ }) -join ', '
            $lines.Add(('$candidates = @({0})' -f $quoted))
            $lines.Add(('Write-Host {0}' -f (& $q ($item.Choose.Prompt + ':'))))
            $lines.Add('for ($i = 0; $i -lt $candidates.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $candidates[$i]) }')
            $lines.Add("$('$answer') = Read-Host 'Numbers to turn on, separated by commas, or A for all'")
            $lines.Add('$picked = @(if ($answer -eq ''A'') { $candidates } else {')
            $lines.Add('        $answer -split '','' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match ''^\d+$'' } |')
            $lines.Add('            ForEach-Object { [int]$_ } | Where-Object { $_ -ge 1 -and $_ -le $candidates.Count } |')
            $lines.Add('            ForEach-Object { $candidates[$_ - 1] }')
            $lines.Add('    })')
            $lines.Add('foreach ($name in $picked) {')
            # Built by concatenation: the generated line mixes a literal $name for the run to expand
            # with quoted text of its own, which nested escaping inside one string gets wrong.
            $applyCmd = [string]$item.Choose.Apply
            $lines.Add('    if (Confirm-PurviewChange -Change "Turn on $name" -Why ' +
                (& $q $item.Why) + ' -Command "' + $applyCmd + '") {')
            $lines.Add('        ' + $applyCmd)
            $lines.Add('    }')
            $lines.Add('    else { Write-Host ''  Skipped.'' }')
            $lines.Add('}')
            $lines.Add('')

            $items.Add([pscustomobject]@{
                    name = [string]$item.Name
                    session = @($item.Choose.Session)
                    caution = [bool]$item.Caution
                    file = 'Enable-AutoLabelingPolicies.ps1'
                    block = ($lines -join $nl)
                })
            continue
        }

        $lines.Add(("if (Confirm-PurviewChange -Change {0} -Now {1} -Why {2} -Caution {3} -Reference {4} -Command {5}) {{" -f
                (& $q $item.Name), (& $q $item.Detail), (& $q $item.Why), (& $q $item.Caution), (& $q $item.Url), (& $q $item.Command)))
        # A compliance cmdlet that is not there fails with CommandNotFoundException, which reads as
        # a broken script rather than a session that could not be reached.
        if ([string]$item.Session -eq 'SecurityAndCompliance') {
            $lines.Add('    if ($complianceReady) {')
            $lines.Add(('        {0}' -f $item.Command))
            $lines.Add('    }')
            $lines.Add('    else {')
            $lines.Add('        Write-Host ''  This session cannot reach Security & Compliance, so it runs in a new window.'' -ForegroundColor Yellow')
            $lines.Add(('        if (-not (Invoke-PurviewInNewSession -Command {0})) {{ $deferred.Add({1}) }}' -f
                    (& $q $item.Command), (& $q ('Connect-IPPSSession; ' + $item.Command))))
            $lines.Add('    }')
        }
        else {
            $lines.Add(('    {0}' -f $item.Command))
        }
        $lines.Add('}')
        $lines.Add('else { Write-Host ''  Skipped.'' }')
        $lines.Add('')

        # Named for the setting it changes, so a single download says what it does from the filename.
        # Matched after whitespace, or the hyphen in the cmdlet name wins and every file is alike.
        $switch = if ($item.Command -match '\s-(\w+)') { $Matches[1] } else { 'PurviewSetting' }

        $items.Add([pscustomobject]@{
                name = [string]$item.Name
                session = @($item.Session)
                caution = [bool]$item.Caution
                file = "Set-$switch.ps1"
                block = ($lines -join $nl)
            })
    }

    return [pscustomobject]@{ header = $header; connect = $connect; items = $items.ToArray(); footer = $footer }
}

function ConvertTo-PurviewRemediationScript {
    <# .SYNOPSIS Assembles a remediation script from the parts, for every change or a chosen subset. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Part,
        [AllowEmptyCollection()][object[]]$Only = $null
    )

    $nl = [Environment]::NewLine
    # Wrap the whole conditional in @() so an empty result has .Count rather than becoming $null.
    $chosen = @(if ($null -eq $Only) { $Part.items } else { $Part.items | Where-Object { $_.name -in $Only } })
    $text = $Part.header -replace '\{COUNT\}', $chosen.Count

    if ($chosen.Count -eq 0) {
        return $text + $nl + "Write-Host 'Nothing selected to remediate.' -ForegroundColor Green" + $nl + $Part.footer
    }

    foreach ($session in @($Part.connect.Keys)) {
        if (@($chosen | Where-Object { $_.session -contains $session }).Count -gt 0) { $text += $nl + $Part.connect[$session] }
    }

    foreach ($item in $chosen) { $text += $nl + $item.block }
    return $text + $nl + $Part.footer
}

# Declared rather than derived because the section reads these inline. A test asserts this stays in
# step with the function, since a collector credited to nothing is reported as read by nothing.
$script:CopilotSectionCollector = @(
    'SensitivityLabel', 'DataLossPrevention', 'DlpRule', 'ProtectionActivity',
    'CommunicationCompliance', 'AppRetentionPolicy', 'AppRetentionRule',
    'ClassicTeamsRetentionPolicy'
)

function Get-PurviewCopilotControl {
    <#
    .SYNOPSIS
        Reports the Purview controls that govern what Microsoft 365 Copilot can reach.

    .DESCRIPTION
        Copilot answers in the user's own security context, so the controls that matter are the
        ones already in the tenant rather than a separate product. Gathered into one section
        because that is the question customers ask, and the answers otherwise sit apart.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $output = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($control, $state, $detail, $why, $url, $band = 'Copilot')
        $output.Add([pscustomobject]@{ Band = $band; Control = $control; State = $state; Detail = $detail; Why = $why; Url = $url })
    }

    # Both prefixes are fixed. DSPM for AI is current; policies created during the preview keep
    # their Microsoft AI Hub prefix.
    $isDspm = { param($name) [string]$name -match '^\s*(DSPM for AI|Microsoft AI Hub)\s*[-:]' }

    # This read retains no CC locations, so names are candidate indicators only. AI is matched
    # case-sensitively to avoid ordinary words; naming is not verified scope or origin.
    $namesAi = { param($name) [string]$name -match '(?i)copilot' -or [string]$name -cmatch '\bAI\b' }

    # Report service-processing support separately from item-level protection and Copilot controls.
    $prereq = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding |
        Where-Object { $_.Name -eq 'Labels processed for Office files in SharePoint and OneDrive' })
    if ($prereq.Count -gt 0) {
        & $add 'Labels processed in SharePoint and OneDrive' $prereq[0].State $prereq[0].Detail 'Supports processing of eligible labelled files. File type, encryption configuration and workload limitations still apply; this switch does not prove processing or Copilot protection for every item.' $script:DocUrl.SharePointLabelledFiles
    }

    # Encryption is an access-control layer, not a universal Copilot exclusion. Copilot runs as the
    # requesting user, and effective rights can be assigned per item rather than fixed on the label.
    $labels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
    $encryptingList = [System.Collections.Generic.List[object]]::new()
    $unknownEncryptionStates = 0
    foreach ($label in $labels) {
        $encryption = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $label -Name 'EncryptionEnabled')
        if (-not $encryption.Valid) { $unknownEncryptionStates++; continue }
        if ([bool]$encryption.Value) { $encryptingList.Add($label) }
    }
    $encrypting = @($encryptingList.ToArray())
    $encryptionControl = 'Sensitivity label encryption'
    $encryptionUrl = 'https://learn.microsoft.com/purview/ai-m365-copilot'
    $encryptionWhy = 'Sensitivity-label encryption can restrict access and usage. Supported Copilot scenarios generally require effective VIEW and EXTRACT rights, with documented app and scenario exceptions. Current label settings do not establish item-level rights or universal Copilot inclusion or exclusion.'

    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'SensitivityLabel')) {
        & $add $encryptionControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'SensitivityLabel') $encryptionWhy $encryptionUrl
    }
    elseif ($encrypting.Count -gt 0) {
        $count = Format-PurviewCount -Count $encrypting.Count -Singular 'label'
        $verb = if ($encrypting.Count -eq 1) { 'is configured to apply' } else { 'are configured to apply' }
        $detail = if ($unknownEncryptionStates -gt 0) { "At least $count $verb encryption." }
        else { "$count $verb encryption." }
        $detail += ' This is definition evidence, not observed use or a test of effective file protection or Copilot access.'

        if ($unknownEncryptionStates -gt 0) {
            $detail += ' Encryption state was not returned for {0} other {1}, so the encrypting-label count is a lower bound.' -f
                $unknownEncryptionStates, $(if ($unknownEncryptionStates -eq 1) { 'label' } else { 'labels' })
        }

        & $add $encryptionControl 'In use' $detail $encryptionWhy $encryptionUrl
    }
    elseif ($unknownEncryptionStates -gt 0) {
        & $add $encryptionControl 'Not read' ('No sensitivity label is proven to apply encryption, and encryption state was not returned for {0}, so encryption use could not be established.' -f (Format-PurviewCount -Count $unknownEncryptionStates -Singular 'label')) $encryptionWhy $encryptionUrl
    }
    else {
        & $add $encryptionControl 'Not configured' 'No returned sensitivity label is configured to apply encryption. File permissions and other encryption are not assessed here.' $encryptionWhy $encryptionUrl
    }

    # The Copilot DLP location is only offered in the Custom template and disables every other
    # location, so a policy carrying it is identifiable by that alone.
    $copilotWhy = 'The Copilot location supports restrictions on sensitive prompt text, web search and processing of labelled content, plus external-email exclusion in preview. Supported apps, conditions and rollout limits apply; files uploaded directly into prompts are not scanned by this DLP evaluation. The indicators here do not validate those controls.'
    $copilotUrl = 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about'
    $dlpState = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $dlpFacts = @($dlpState.Policies)
    $dlp = @($dlpFacts | ForEach-Object { $_.Policy })
    if (-not $dlpState.PolicyRead) {
        & $add 'DLP policy scoped to Copilot' 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DataLossPrevention') $copilotWhy $copilotUrl
    }
    else {
        # Name, scope and rule indicators identify candidates; a name alone does not settle scope.
        $namesCopilot = { param($policy)
            $name = [string](Get-PurviewProperty -InputObject $policy -Name 'Name')
            (& $isDspm $name) -and $name -match '(?i)copilot'
        }

        # MentionsCopilot is a heuristic over returned rule properties, not verified action semantics.
        $ruleSaysCopilot = [System.Collections.Generic.HashSet[int]]::new()
        $policyHasRule = [System.Collections.Generic.HashSet[int]]::new()
        $policyHasEnabledRule = [System.Collections.Generic.HashSet[int]]::new()
        $ruleStateUnknown = [System.Collections.Generic.HashSet[int]]::new()
        $ruleCopilotSignalUnknown = [System.Collections.Generic.HashSet[int]]::new()
        $rulesRead = $dlpState.RuleRead
        if ($rulesRead) {
            foreach ($link in @($dlpState.LinkedRules)) {
                $rule = $link.Rule
                $owner = [int]$link.PolicyIndex
                $null = $policyHasRule.Add($owner)
                $mentions = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $rule -Name 'MentionsCopilot')
                if (-not $mentions.Valid) { $null = $ruleCopilotSignalUnknown.Add($owner) }
                elseif ([bool]$mentions.Value) { $null = $ruleSaysCopilot.Add($owner) }

                if ($link.IsEnforcing -and -not $link.DisabledKnown) {
                    $null = $ruleStateUnknown.Add($owner)
                }
                elseif ($link.IsEnforcing -and -not $link.Disabled) {
                    $null = $policyHasEnabledRule.Add($owner)
                }
            }
        }
        $hasCopilotRule = { param($fact)
            $ruleSaysCopilot.Contains([int]$fact.Index)
        }

        $covering = @($dlpFacts | Where-Object {
                @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_.Policy -Name 'CopilotLocation')).Count -gt 0 -or
                (& $namesCopilot $_.Policy) -or (& $hasCopilotRule $_)
            })

        # Candidates combine scope, name and rule indicators. Enable mode plus any enabled linked
        # rule is configuration evidence, not proof that a Copilot-specific rule operates.
        $activeCovering = @($covering | Where-Object {
                $_.IsEnforcing -and $policyHasEnabledRule.Contains([int]$_.Index)
            })
        $unknownCovering = @($covering | Where-Object {
                    -not $_.ModeKnown -or ($_.IsEnforcing -and (
                        -not $_.IdentityKnown -or -not $rulesRead -or -not $dlpState.RuleComplete -or
                        $dlpState.UnresolvedRuleCount -gt 0 -or $ruleStateUnknown.Contains([int]$_.Index)
                    ))
            })

        # Workload is the third way in, and the one that settles a policy whose location arrays come
        # back empty. Only the workloads Microsoft documents for the other locations rule a policy
        # out; anything unrecognised leaves it open rather than guessing it is not Copilot.
        $knownOther = @('exchange', 'sharepoint', 'onedriveforbusiness', 'onedrive', 'teams',
            'endpointdevices', 'thirdpartyapps', 'powerbi', 'onpremisesscanner')
        $ruledOutByWorkload = {
            param($policy)
            $workload = [string](Get-PurviewProperty -InputObject $policy -Name 'Workload')
            if (-not $workload) { return $false }
            $tokens = @($workload -split '[,;]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
            if ($tokens.Count -eq 0) { return $false }
            @($tokens | Where-Object { $_ -notin $knownOther }).Count -eq 0
        }

        $undecided = @($dlpFacts | Where-Object {
            $fact = $_
            $policy = $fact.Policy
                if (& $namesCopilot $policy) { return $false }
            if (& $hasCopilotRule $fact) { return $false }
                if (& $ruledOutByWorkload $policy) { return $false }
                # The legacy heuristic rules out complete linked rules with no Copilot indicator.
                # That is not a validated exhaustive test of all supported Copilot rule shapes.
            if ($rulesRead -and $dlpState.RuleComplete -and $dlpState.UnresolvedRuleCount -eq 0 -and
                $policyHasRule.Contains([int]$fact.Index) -and
                -not $ruleCopilotSignalUnknown.Contains([int]$fact.Index)) { return $false }
                $held = @('ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation',
                    'EndpointDlpLocation', 'PowerBIDlpLocation', 'ThirdPartyAppDlpLocation',
                    'OnPremisesScannerDlpLocation') |
                    Where-Object { @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name $_)).Count -gt 0 }
                @($held).Count -eq 0
            })

        if ($activeCovering.Count -gt 0) {
            $activeDetail = if ($activeCovering.Count -eq 1) {
                '1 DLP policy matches a Copilot scope, name or rule indicator, is in Enable mode and has an enabled linked rule. This does not prove Copilot-specific rule enforcement.'
            }
            else {
                "$($activeCovering.Count) DLP policies match Copilot scope, name or rule indicators, are in Enable mode and have an enabled linked rule. This does not prove Copilot-specific rule enforcement."
            }
            & $add 'DLP policy scoped to Copilot' 'As recommended' $activeDetail $copilotWhy $copilotUrl
        }
        elseif ($covering.Count -gt 0 -and $unknownCovering.Count -gt 0) {
            & $add 'DLP policy scoped to Copilot' 'Not read' "$(Format-PurviewCount -Count $covering.Count -Singular 'DLP policy matches' -Plural 'DLP policies match') Copilot indicators, but mode or enabled linked-rule evidence was incomplete. Actual scope and protection require separate verification." $copilotWhy $copilotUrl
        }
        elseif ($covering.Count -gt 0) {
            & $add 'DLP policy scoped to Copilot' 'Needs attention' "$(Format-PurviewCount -Count $covering.Count -Singular 'DLP policy matches' -Plural 'DLP policies match') Copilot indicators, but none is both in Enable mode and backed by an enabled linked rule. Actual scope requires separate verification." $copilotWhy $copilotUrl
        }
        elseif ($dlp.Count -eq 0 -and $dlpState.PolicyComplete) {
            & $add 'DLP policy scoped to Copilot' 'Not configured' 'No DLP policy was returned. This does not assess every control applicable to Copilot.' $copilotWhy $copilotUrl
        }
        elseif ($undecided.Count -eq 0 -and $dlpState.PolicyComplete) {
            & $add 'DLP policy scoped to Copilot' 'Not configured' "None of the $($dlp.Count) returned DLP policies matched this report's Copilot indicators. Confirm actual location and rule configuration separately." $copilotWhy $copilotUrl
        }
        else {
            $uncertainDetail = if ($undecided.Count -gt 0) {
                "$(Format-PurviewCount -Count $undecided.Count -Singular 'DLP policy names no location' -Plural 'DLP policies name no location') that can be read, and carries no complete rule or workload evidence to judge it by, so whether Copilot is covered has to be confirmed in the portal."
            }
            else { 'No returned DLP policy proves Copilot coverage.' }
            if (-not $dlpState.PolicyComplete) {
                $uncertainDetail += ' The policy read was partial, so absence cannot establish that no other policy covers Copilot.'
            }
            & $add 'DLP policy scoped to Copilot' 'Not read' $uncertainDetail $copilotWhy $copilotUrl
        }
    }

    # Historical activity counts are separate from stored conversation content and its retention.
    $recordControl = 'Copilot interactions being recorded'
    $recordWhy = 'Copilot audit events record activity metadata, not the actual prompt and response text. Conversation compliance copies are stored separately for supported retention and eDiscovery scenarios. This historical event count does not verify either complete audit capture or content retention.'
    $recordUrl = 'https://learn.microsoft.com/purview/data-security-posture-management-considerations'
    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'ProtectionActivity')) {
        & $add $recordControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'ProtectionActivity') $recordWhy $recordUrl
    }
    else {
        $copilotEvents = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewCollectorValue -Snapshot $Snapshot -Collector 'ProtectionActivity' -Select 'CopilotEvents')
        $window = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewCollectorValue -Snapshot $Snapshot -Collector 'ProtectionActivity' -Select 'WindowDays')
        if (-not $copilotEvents.Valid -or -not $window.Valid -or $window.Value -eq 0) {
            & $add $recordControl 'Not read' 'The activity result did not return both a usable Copilot event count and a non-zero query window, so recent recording could not be evaluated.' $recordWhy $recordUrl
        }
        elseif ($copilotEvents.Value -gt 0) {
            & $add $recordControl 'Seen recently' ('{0} recorded in the last {1}. This historical window does not establish whether recording is operating now.' -f (Format-PurviewCount -Count $copilotEvents.Value -Singular 'Copilot activity was' -Plural 'Copilot activities were'), (Format-PurviewCount -Count $window.Value -Singular 'day')) $recordWhy $recordUrl
        }
        else {
            & $add $recordControl 'Needs review' ('No Copilot activity was returned for the last {0}. This positive-only signal cannot distinguish no use from unavailable or uncaptured interactions, so zero is not proof that recording is off.' -f (Format-PurviewCount -Count $window.Value -Singular 'day')) $recordWhy $recordUrl
        }
    }

    $commControl = 'Communication compliance covering AI prompts'
    $commWhy = 'Communication compliance policies can identify potentially risky Copilot communications for review within supported scope. Policy names alone do not establish inspection, and absence of these definitions does not rule out other controls.'
    $commUrl = 'https://learn.microsoft.com/purview/communication-compliance-policies'
    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'CommunicationCompliance')) {
        & $add $commControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'CommunicationCompliance') $commWhy $commUrl
    }
    else {
        $comm = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'CommunicationCompliance' -Select 'Policies')
        $commAi = @($comm | Where-Object {
                $name = Get-PurviewProperty -InputObject $_ -Name 'Name'
                (& $isDspm $name) -or (& $namesAi $name)
            })
        if ($commAi.Count -gt 0) {
            $commNames = @($commAi | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') } | Where-Object { $_ } | Sort-Object)
            & $add $commControl 'Needs review' ('{0} configured with a Copilot, AI or DSPM name: {1}. A name does not establish location scope, current inspection or policy health; confirm those states in the portal.' -f (Format-PurviewCount -Count $commAi.Count -Singular 'policy is' -Plural 'policies are'), ($commNames -join ', ')) $commWhy $commUrl
        }
        elseif ($comm.Count -eq 0) {
            & $add $commControl 'Not configured' 'No communication compliance policy was returned. Other inspection controls are not assessed by this check.' $commWhy $commUrl
        }
        else {
            & $add $commControl 'Needs review' ('{0}, none of them named for Copilot or AI. Location scope is not collected by this read; confirm scope, enablement and inspection separately.' -f (Format-PurviewCount -Count $comm.Count -Singular 'policy exists' -Plural 'policies exist')) $commWhy $commUrl
        }
    }

    $retControl = 'Retention covering Copilot interactions'
    $retWhy = 'Supported Copilot conversations have compliance copies in hidden Exchange mailbox folders. Applicable retention settings can retain or delete those copies, subject to holds and retention precedence. This is separate from audit-log retention; returned policy definitions do not establish effective retention of every conversation.'
    $retUrl = 'https://learn.microsoft.com/purview/retention-policies-copilot'
    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'AppRetentionPolicy')) {
        & $add $retControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'AppRetentionPolicy') $retWhy $retUrl
    }
    else {
        $appRet = Get-PurviewAppRetentionAnalysis -Snapshot $Snapshot -ApplicationPattern '(?i)^User:M365Copilot$'
        if (-not $appRet.PolicyRead) {
            & $add $retControl 'Not read' 'The current app-retention result did not contain one usable policy list, so absence could not be established.' $retWhy $retUrl
        }
        elseif ($appRet.ActiveCount -gt 0) {
            & $add $retControl 'As recommended' ('{0} enabled for the Microsoft Copilot experiences location, with linked retention rules. Actions, duration, assignments, distribution and content retention are not verified.' -f (Format-PurviewCount -Count $appRet.ActiveCount -Singular 'retention policy is' -Plural 'retention policies are')) $retWhy $retUrl
        }
        elseif (-not $appRet.PolicyComplete -or $appRet.UnknownCount -gt 0) {
            $whyUnknown = if (-not $appRet.PolicyComplete) { 'The app-retention policy read was partial.' }
            elseif (-not $appRet.ScopeComplete) { 'Not every app-retention policy returned its application scope.' }
            elseif (-not $appRet.RuleRead) { 'The app-retention rules were not read.' }
            else { 'Policy enablement or rule linkage was incomplete.' }
            & $add $retControl 'Not read' "$whyUnknown Whether Copilot retention is active could not be established." $retWhy $retUrl
        }
        elseif ($appRet.InScopeCount -gt 0) {
            & $add $retControl 'Needs attention' ('No active Copilot retention policy was established: {0} disabled and {1} enabled without a linked rule.' -f $appRet.DisabledCount, $appRet.RulelessCount) $retWhy $retUrl
        }
        else {
            # The location used to be combined with Teams chats under a different cmdlet. Only an
            # empty classic Teams result, or Microsoft's exact Teams-only migration token on every
            # returned policy, can rule that legacy model out.
            $classicRet = Get-PurviewClassicCopilotRetentionAnalysis -Snapshot $Snapshot
            if (-not $classicRet.Read) {
                & $add $retControl 'Not read' ('No current Microsoft Copilot experiences policy was found, but the older combined Teams chats and Copilot policy family was not read. {0}' -f (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'ClassicTeamsRetentionPolicy')) $retWhy $retUrl
            }
            elseif ($classicRet.AmbiguousCount -gt 0) {
                & $add $retControl 'Needs review' ('No current Microsoft Copilot experiences policy was found. {0} returned from the older Teams policy family without the exact Teams-only migration scope, so whether any still covers Copilot must be confirmed in the portal. Policy names and Workload are not used as scope evidence.' -f (Format-PurviewCount -Count $classicRet.AmbiguousCount -Singular 'classic policy was' -Plural 'classic policies were')) $retWhy $retUrl
            }
            elseif ($classicRet.AbsenceProven) {
                $classicDetail = if ($classicRet.PolicyCount -eq 0) {
                    'No policy exists in the older Teams policy family either.'
                }
                else {
                    ('{0} returned from the older family, and every one carries Microsoft''s exact Teams-only migration scope.' -f (Format-PurviewCount -Count $classicRet.TeamsOnlyCount -Singular 'policy was' -Plural 'policies were'))
                }
                & $add $retControl 'Not configured' "No retention policy names the Microsoft Copilot experiences location. $classicDetail" $retWhy $retUrl
            }
            else {
                & $add $retControl 'Not read' 'Neither the current nor classic retention evidence established whether Copilot interactions are covered.' $retWhy $retUrl
            }
        }
    }

    # Separate broader AI policy candidates; supported scopes vary by policy and workload.
    $dspmControl = 'Data Security Posture Management one-click policies'
    $dspmWhy = 'Data Security Posture Management offers policy creation across multiple solutions and supported AI scenarios. The DSPM for AI and Microsoft AI Hub name prefixes are candidate indicators, not proof of origin, complete scope or current operation.'
    $dspmUrl = 'https://learn.microsoft.com/purview/data-security-posture-management-learn-about'
    $dspmBand = 'Broader AI controls, subject to supported scope'
    $dspmRan = (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DataLossPrevention') -or
        (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'CommunicationCompliance')
    if (-not $dspmRan) {
        & $add $dspmControl 'Not read' 'Neither the data loss prevention nor the communication compliance policies were read, so none of these could be identified.' $dspmWhy $dspmUrl $dspmBand
    }
    else {
        $dspmDlp = @($dlp | Where-Object { & $isDspm (Get-PurviewProperty -InputObject $_ -Name 'Name') })
        $dspmComm = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'CommunicationCompliance' -Select 'Policies' |
                Where-Object { & $isDspm (Get-PurviewProperty -InputObject $_ -Name 'Name') })
        $dspmNamed = @($dspmDlp) + @($dspmComm)
        # This script does not collect insider risk or collection policy definitions.
        $floor = 'Only returned data loss prevention and communication compliance names are checked. Insider risk and collection policy definitions are not collected here; this is not a complete one-click policy inventory.'
        if ($dspmNamed.Count -gt 0) {
            # The same prefix is used across four solutions, so the name alone does not say which.
            $named = @(
                @($dspmDlp | ForEach-Object { '{0} (data loss prevention)' -f (Get-PurviewProperty -InputObject $_ -Name 'Name') })
                @($dspmComm | ForEach-Object { '{0} (communication compliance)' -f (Get-PurviewProperty -InputObject $_ -Name 'Name') })
            )
            $names = if ($named.Count -le 3) { $named -join ', ' }
            else { (@($named | Select-Object -First 3) -join ', ') + (', and {0} more' -f ($named.Count - 3)) }
            & $add $dspmControl 'Needs review' ('{0} configured by name: {1}. A matching name does not establish that a policy is enabled, healthy or currently operating; confirm its state in the portal. {2}' -f (Format-PurviewCount -Count $dspmNamed.Count -Singular 'policy is' -Plural 'policies are'), $names, $floor) $dspmWhy $dspmUrl $dspmBand
        }
        else {
            & $add $dspmControl 'Needs review' ('No matching policy name was returned. Renamed policies and uncollected policy families are not ruled out. {0}' -f $floor) $dspmWhy $dspmUrl $dspmBand
        }
    }

    # Copilot before the wider AI controls, then by severity: a proven gap outranks one that could
    # not be established, which outranks anything already in hand.
    $rank = @{ 'Needs attention' = 0; 'Not configured' = 1; 'Needs review' = 2; 'Not read' = 3; 'Seen recently' = 4; 'In use' = 4; 'Not in use' = 5; 'As recommended' = 6 }
    return @($output | Sort-Object @{ Expression = { if ($_.Band -eq 'Copilot') { 0 } else { 1 } } },
        @{ Expression = { if ($rank.ContainsKey([string]$_.State)) { $rank[[string]$_.State] } else { 7 } } })
}

function Get-PurviewSensitiveTypeName {
    <# .SYNOPSIS Compatibility wrapper that returns decoded names while callers needing certainty use the status-bearing functions. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Condition)

    $analysis = if ($Condition -is [string] -and
        (([string]$Condition).Trim().StartsWith('{') -or ([string]$Condition).Trim().StartsWith('['))) {
        Get-PurviewAdvancedSensitiveTypeAnalysis -AdvancedRule $Condition
    }
    else { Get-PurviewDirectSensitiveTypeAnalysis -Condition $Condition }
    return @($analysis.Names)
}

function Get-PurviewDirectSensitiveTypeAnalysis {
    <# .SYNOPSIS Decodes a direct ContentContainsSensitiveInformation value with an explicit status. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Condition)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $details = [System.Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ Status = 'Complete'; Recognised = $false }

    $mark = {
        param([string]$Status, [string]$Detail)
        if ($state.Status -eq 'Complete') { $state.Status = $Status }
        if ($Detail -and -not $details.Contains($Detail)) { $details.Add($Detail) }
    }

    $isEmpty = {
        param($Value)
        if ($null -eq $Value) { return $true }
        if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace([string]$Value) }
        if ($Value -is [System.Collections.IDictionary]) { return $false }
        if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -eq 0 }
        return $false
    }

    if (& $isEmpty $Condition) {
        return [pscustomobject]@{ Status = 'Complete'; Names = @(); Detail = '' }
    }

    $walk = $null
    $walk = {
        param($Node, [int]$Depth, [ValidateSet('Root', 'Leaf', 'Group')][string]$Context)

        if ($Depth -gt 10) {
            & $mark 'Unsupported' 'The sensitive-information-type condition is nested more deeply than the supported schema.'
            return
        }
        if ($null -eq $Node) {
            & $mark 'Malformed' 'A sensitive-information-type condition contains a null branch.'
            return
        }

        if ($Node -is [string]) {
            $text = ([string]$Node).Trim()
            if ($text.StartsWith('{') -or $text.StartsWith('[')) {
                $parsed = $null
                try { $parsed = ConvertFrom-Json -InputObject $text -Depth 30 }
                catch {
                    & $mark 'Malformed' 'The direct sensitive-information-type condition contains malformed JSON.'
                    return
                }
                & $walk $parsed ($Depth + 1) $Context
                return
            }
            if ($Context -eq 'Leaf' -and $text) {
                $state.Recognised = $true
                $null = $found.Add($text)
                return
            }
            & $mark 'Unsupported' 'The direct sensitive-information-type condition uses an unsupported string shape.'
            return
        }

        # A dictionary is enumerable too, so named fields must be handled before collections.
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
            $items = @($Node)
            if ($items.Count -eq 0) {
                & $mark 'Malformed' 'A populated sensitive-information-type condition contains an empty branch.'
                return
            }
            $next = if ($Context -eq 'Root') { 'Leaf' } else { $Context }
            foreach ($item in $items) { & $walk $item ($Depth + 1) $next }
            return
        }

        $hasTypes = (Test-PurviewProperty -InputObject $Node -Name 'sensitivetypes') -or
            (Test-PurviewProperty -InputObject $Node -Name 'SensitiveTypes')
        $hasGroups = (Test-PurviewProperty -InputObject $Node -Name 'groups') -or
            (Test-PurviewProperty -InputObject $Node -Name 'Groups')
        $hasName = (Test-PurviewProperty -InputObject $Node -Name 'name') -or
            (Test-PurviewProperty -InputObject $Node -Name 'Name')

        if ($hasTypes -or $hasGroups) {
            $state.Recognised = $true
            if ($hasTypes) {
                $types = Get-PurviewProperty -InputObject $Node -Name @('sensitivetypes', 'SensitiveTypes')
                if (& $isEmpty $types) {
                    & $mark 'Malformed' 'A sensitivetypes branch is present but contains no entries.'
                }
                else { & $walk $types ($Depth + 1) 'Leaf' }
            }
            if ($hasGroups) {
                $groups = Get-PurviewProperty -InputObject $Node -Name @('groups', 'Groups')
                if (& $isEmpty $groups) {
                    & $mark 'Malformed' 'A groups branch is present but contains no entries.'
                }
                else { & $walk $groups ($Depth + 1) 'Group' }
            }
            return
        }

        # The direct parameter also has a flat form: an array of objects whose name is the SIT. A
        # group can carry a name too, but Group context never accepts it as a leaf.
        if ($hasName -and $Context -ne 'Group') {
            $state.Recognised = $true
            $name = [string](Get-PurviewProperty -InputObject $Node -Name @('name', 'Name'))
            if ([string]::IsNullOrWhiteSpace($name)) {
                & $mark 'Malformed' 'A sensitive-information-type entry has no name.'
            }
            else { $null = $found.Add($name.Trim()) }
            return
        }

        & $mark 'Unsupported' 'The direct sensitive-information-type condition has an unsupported object shape.'
    }

    & $walk $Condition 0 'Root'
    if (-not $state.Recognised -and $state.Status -eq 'Complete') {
        & $mark 'Unsupported' 'The direct sensitive-information-type condition did not expose a supported branch.'
    }

    return [pscustomobject]@{
        Status = [string]$state.Status
        Names = @($found | Sort-Object)
        Detail = @($details | Select-Object -Unique) -join ' '
    }
}

function Get-PurviewAdvancedSensitiveTypeAnalysis {
    <# .SYNOPSIS Decodes only explicit ContentContainsSensitiveInformation leaves in AdvancedRule. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$AdvancedRule)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $details = [System.Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ Status = 'Complete'; Recognised = $false }

    $mark = {
        param([string]$Status, [string]$Detail)
        if ($state.Status -eq 'Complete') { $state.Status = $Status }
        if ($Detail -and -not $details.Contains($Detail)) { $details.Add($Detail) }
    }

    if ($null -eq $AdvancedRule -or
        ($AdvancedRule -is [string] -and [string]::IsNullOrWhiteSpace([string]$AdvancedRule)) -or
        ($AdvancedRule -is [System.Collections.IEnumerable] -and
            $AdvancedRule -isnot [string] -and $AdvancedRule -isnot [System.Collections.IDictionary] -and
            @($AdvancedRule).Count -eq 0)) {
        return [pscustomobject]@{ Status = 'Complete'; Names = @(); Detail = '' }
    }

    $root = $AdvancedRule
    if ($root -is [string]) {
        $text = ([string]$root).Trim()
        if (-not ($text.StartsWith('{') -or $text.StartsWith('['))) {
            return [pscustomobject]@{
                Status = 'Unsupported'; Names = @()
                Detail = 'AdvancedRule is populated but is not JSON, so it was not interpreted or executed.'
            }
        }
        try { $root = ConvertFrom-Json -InputObject $text -Depth 30 }
        catch {
            return [pscustomobject]@{
                Status = 'Malformed'; Names = @()
                Detail = 'AdvancedRule contains malformed JSON.'
            }
        }
    }

    $walk = $null
    $walk = {
        param($Node, [int]$Depth)

        if ($Depth -gt 12) {
            & $mark 'Unsupported' 'AdvancedRule is nested more deeply than the documented condition schema.'
            return
        }
        if ($null -eq $Node) {
            & $mark 'Malformed' 'AdvancedRule contains a null condition branch.'
            return
        }
        if ($Node -is [string]) {
            $text = ([string]$Node).Trim()
            if ($text.StartsWith('{') -or $text.StartsWith('[')) {
                try { & $walk (ConvertFrom-Json -InputObject $text -Depth 30) ($Depth + 1) }
                catch { & $mark 'Malformed' 'AdvancedRule contains malformed nested JSON.' }
            }
            else { & $mark 'Unsupported' 'AdvancedRule contains an unsupported string condition.' }
            return
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
            $items = @($Node)
            if ($items.Count -eq 0) {
                & $mark 'Malformed' 'AdvancedRule contains an empty condition collection.'
                return
            }
            foreach ($item in $items) { & $walk $item ($Depth + 1) }
            return
        }

        $hasName = (Test-PurviewProperty -InputObject $Node -Name 'ConditionName') -or
            (Test-PurviewProperty -InputObject $Node -Name 'conditionName')
        $hasCondition = (Test-PurviewProperty -InputObject $Node -Name 'Condition') -or
            (Test-PurviewProperty -InputObject $Node -Name 'condition')
        $hasSubConditions = (Test-PurviewProperty -InputObject $Node -Name 'SubConditions') -or
            (Test-PurviewProperty -InputObject $Node -Name 'subConditions')

        if ($hasName) {
            $state.Recognised = $true
            $conditionName = [string](Get-PurviewProperty -InputObject $Node -Name @('ConditionName', 'conditionName'))
            if ([string]::IsNullOrWhiteSpace($conditionName)) {
                & $mark 'Malformed' 'An AdvancedRule condition has no ConditionName.'
            }
            elseif ($conditionName -eq 'ContentContainsSensitiveInformation') {
                $hasValue = (Test-PurviewProperty -InputObject $Node -Name 'Value') -or
                    (Test-PurviewProperty -InputObject $Node -Name 'value')
                if (-not $hasValue) {
                    & $mark 'Malformed' 'A ContentContainsSensitiveInformation condition has no Value.'
                }
                else {
                    # Value is entered only for this explicit condition. Values on labels,
                    # recipients and contextual conditions can contain unrelated name fields.
                    $value = Get-PurviewProperty -InputObject $Node -Name @('Value', 'value')
                    $direct = Get-PurviewDirectSensitiveTypeAnalysis -Condition $value
                    foreach ($name in @($direct.Names)) { $null = $found.Add([string]$name) }
                    if ($direct.Status -ne 'Complete') { & $mark $direct.Status $direct.Detail }
                    elseif (@($direct.Names).Count -eq 0) {
                        & $mark 'Malformed' 'A ContentContainsSensitiveInformation condition contains no named sensitive information type.'
                    }
                }
            }
            # Other named conditions are intentionally not opened. Their Value can carry labels,
            # recipients or metadata names that are not sensitive information types.
        }

        $followed = $false
        if ($hasCondition) {
            $followed = $true
            $state.Recognised = $true
            & $walk (Get-PurviewProperty -InputObject $Node -Name @('Condition', 'condition')) ($Depth + 1)
        }
        if ($hasSubConditions) {
            $followed = $true
            $state.Recognised = $true
            & $walk (Get-PurviewProperty -InputObject $Node -Name @('SubConditions', 'subConditions')) ($Depth + 1)
        }

        if (-not $hasName -and -not $followed) {
            & $mark 'Unsupported' 'AdvancedRule contains an object outside the documented Condition and SubConditions structure.'
        }
    }

    & $walk $root 0
    if (-not $state.Recognised -and $state.Status -eq 'Complete') {
        & $mark 'Unsupported' 'AdvancedRule did not expose a documented condition structure.'
    }

    return [pscustomobject]@{
        Status = [string]$state.Status
        Names = @($found | Sort-Object)
        Detail = @($details | Select-Object -Unique) -join ' '
    }
}

function Get-PurviewAutoLabelRuleConditionAnalysis {
    <# .SYNOPSIS Combines direct and advanced rule conditions without treating an unread field as empty. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Rule)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $details = [System.Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ Status = 'Complete' }
    $mark = {
        param([string]$Status, [string]$Detail)
        if ($state.Status -eq 'Complete') { $state.Status = $Status }
        if ($Detail -and -not $details.Contains($Detail)) { $details.Add($Detail) }
    }
    $merge = {
        param($Analysis)
        foreach ($name in @($Analysis.Names)) { $null = $found.Add([string]$name) }
        if ([string]$Analysis.Status -ne 'Complete') { & $mark ([string]$Analysis.Status) ([string]$Analysis.Detail) }
    }

    if ($null -eq $Rule) {
        return [pscustomobject]@{ Status = 'Unresolved'; Names = @(); Detail = 'The auto-labeling rule is missing.' }
    }

    $hasDirect = Test-PurviewProperty -InputObject $Rule -Name 'DirectSensitiveTypes'
    $hasAdvanced = Test-PurviewProperty -InputObject $Rule -Name 'AdvancedRule'
    $hasDirectMarker = Test-PurviewProperty -InputObject $Rule -Name 'DirectSensitiveTypesReturned'
    $hasAdvancedMarker = Test-PurviewProperty -InputObject $Rule -Name 'AdvancedRuleReturned'

    if ($hasDirectMarker -or $hasAdvancedMarker) {
        foreach ($field in @(
                @{ Marker = 'DirectSensitiveTypesReturned'; Value = 'DirectSensitiveTypes'; Kind = 'direct' }
                @{ Marker = 'AdvancedRuleReturned'; Value = 'AdvancedRule'; Kind = 'advanced' }
            )) {
            if (-not (Test-PurviewProperty -InputObject $Rule -Name $field.Marker)) {
                & $mark 'Unresolved' "The rule does not record whether its $($field.Kind) condition field was returned."
                continue
            }
            $returned = Get-PurviewProperty -InputObject $Rule -Name $field.Marker
            if ($returned -isnot [bool]) {
                & $mark 'Unresolved' "The returned-state marker for the $($field.Kind) condition is malformed."
                continue
            }
            if (-not [bool]$returned) {
                & $mark 'Unresolved' "The service did not return the rule's $($field.Kind) condition field."
                continue
            }
            if (-not (Test-PurviewProperty -InputObject $Rule -Name $field.Value)) {
                & $mark 'Unresolved' "The rule marks its $($field.Kind) condition as returned but does not contain it."
                continue
            }
            if ($field.Kind -eq 'direct') {
                & $merge (Get-PurviewDirectSensitiveTypeAnalysis -Condition (Get-PurviewProperty -InputObject $Rule -Name $field.Value))
            }
            else {
                & $merge (Get-PurviewAdvancedSensitiveTypeAnalysis -AdvancedRule (Get-PurviewProperty -InputObject $Rule -Name $field.Value))
            }
        }
    }
    elseif ($hasDirect -or $hasAdvanced) {
        # Hand-authored or transitional snapshots can carry the separated fields without markers.
        # Both must be present before their union is a complete view.
        if ($hasDirect) {
            & $merge (Get-PurviewDirectSensitiveTypeAnalysis -Condition (Get-PurviewProperty -InputObject $Rule -Name 'DirectSensitiveTypes'))
        }
        else { & $mark 'Unresolved' 'The rule has no direct-condition field.' }
        if ($hasAdvanced) {
            & $merge (Get-PurviewAdvancedSensitiveTypeAnalysis -AdvancedRule (Get-PurviewProperty -InputObject $Rule -Name 'AdvancedRule'))
        }
        else { & $mark 'Unresolved' 'The rule has no AdvancedRule field.' }
    }
    elseif (Test-PurviewProperty -InputObject $Rule -Name 'SensitiveTypes') {
        # Version 1.54 and earlier combined the two source properties. A populated value is useful
        # partial evidence, but even then it cannot prove that the other property was not masked.
        $legacy = Get-PurviewProperty -InputObject $Rule -Name 'SensitiveTypes'
        if ($legacy -is [string] -and (([string]$legacy).Trim().StartsWith('{') -or ([string]$legacy).Trim().StartsWith('['))) {
            & $merge (Get-PurviewAdvancedSensitiveTypeAnalysis -AdvancedRule $legacy)
        }
        else { & $merge (Get-PurviewDirectSensitiveTypeAnalysis -Condition $legacy) }
        & $mark 'Unresolved' 'This older snapshot combined direct and advanced conditions, so decoded names are partial evidence only.'
    }
    else {
        & $mark 'Unresolved' 'The rule carries no readable direct or advanced condition field.'
    }

    return [pscustomobject]@{
        Status = [string]$state.Status
        Names = @($found | Sort-Object)
        Detail = @($details | Select-Object -Unique) -join ' '
    }
}

function Get-PurviewReferenceToken {
    <# .SYNOPSIS Extracts stable name and identifier strings from a policy reference. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $walk = $null
    $walk = {
        param($Node, [int]$Depth)
        if ($null -eq $Node -or $Depth -gt 4) { return }
        if ($Node -is [string] -or $Node -is [guid] -or $Node -is [ValueType]) {
            $text = ([string]$Node).Trim()
            if ($text) { $null = $found.Add($text) }
            return
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [System.Collections.IDictionary]) {
            foreach ($item in $Node) { & $walk $item ($Depth + 1) }
            return
        }

        $read = $false
        foreach ($name in 'Name', 'DisplayName', 'UniqueName', 'Guid', 'Identity', 'Id', 'ImmutableId') {
            if (-not (Test-PurviewProperty -InputObject $Node -Name $name)) { continue }
            $read = $true
            & $walk (Get-PurviewProperty -InputObject $Node -Name $name) ($Depth + 1)
        }
        if (-not $read) {
            $text = ([string]$Node).Trim()
            if ($text -and $text -notmatch '^System\.') { $null = $found.Add($text) }
        }
    }

    & $walk $Value 0
    return @($found | Sort-Object)
}

function Get-PurviewAutoLabelSensitiveTypeSignal {
    <# .SYNOPSIS Reports decoded SIT configuration from returned policies and linked rules; partial collector results can limit completeness. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $answer = [ordered]@{
        Reliable = $false
        PolicyReliable = $false
        Count = 0
        Names = @()
        PolicyCount = 0
        ActivePolicyCount = 0
        PolicyDetail = ''
        Detail = ''
    }

    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $policyResults = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'AutoLabeling' })
    if ($policyResults.Count -ne 1 -or
        [string](Get-PurviewProperty -InputObject $policyResults[0] -Name 'status') -notin 'Success', 'PartialSuccess') {
        $reason = Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'AutoLabeling'
        $answer.PolicyDetail = $reason
        $answer.Detail = "Auto-labeling policy state was not read completely. $reason"
        return [pscustomobject]$answer
    }

    $policyData = Get-PurviewProperty -InputObject $policyResults[0] -Name 'data'
    if (-not (Test-PurviewProperty -InputObject $policyData -Name 'Policies')) {
        $answer.PolicyDetail = 'The auto-labeling collector did not return its policy list.'
        $answer.Detail = 'The sensitive-information-type total is not checked because the auto-labeling policy list is missing.'
        return [pscustomobject]$answer
    }

    $policies = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policyData -Name 'Policies'))
    $answer.PolicyCount = $policies.Count
    $policyModes = [string[]]::new($policies.Count)
    $active = [System.Collections.Generic.List[int]]::new()
    $simulating = 0
    $disabledPolicies = 0
    $unknownModes = 0

    for ($i = 0; $i -lt $policies.Count; $i++) {
        $policy = $policies[$i]
        if (-not (Test-PurviewProperty -InputObject $policy -Name 'Mode')) {
            $unknownModes++
            continue
        }
        $mode = ([string](Get-PurviewProperty -InputObject $policy -Name 'Mode')).Trim()
        $policyModes[$i] = $mode
        if ($mode -eq 'Enable') { $active.Add($i) }
        elseif ($mode -eq 'Disable') { $disabledPolicies++ }
        elseif ($mode -like 'Test*') { $simulating++ }
        else { $unknownModes++ }
    }

    $answer.ActivePolicyCount = $active.Count
    if ($unknownModes -gt 0) {
        $answer.PolicyDetail = "$unknownModes of $($policies.Count) auto-labeling policies do not carry a recognised mode, so the turned-on total is not checked."
        $answer.Detail = 'The sensitive-information-type total is not checked because every policy must have a recognised mode before active rules can be identified.'
        return [pscustomobject]$answer
    }

    $answer.PolicyReliable = $true
    $partialWarning = ' Some configuration could not be retrieved; this list may be incomplete.'
    $policyPartial = [string](Get-PurviewProperty -InputObject $policyResults[0] -Name 'status') -eq 'PartialSuccess'
    if ($policies.Count -eq 0) {
        $answer.PolicyDetail = 'No auto-labeling policy was returned.'
    }
    else {
        $parts = [System.Collections.Generic.List[string]]::new()
        $parts.Add("$($active.Count) turned on")
        if ($simulating -gt 0) { $parts.Add("$simulating still simulating") }
        if ($disabledPolicies -gt 0) { $parts.Add("$disabledPolicies disabled") }
        $answer.PolicyDetail = "Of $($policies.Count) returned definitions: $($parts -join ', ')."
    }
    if ($policyPartial) { $answer.PolicyDetail += $partialWarning }

    # Complete policy data alone settles the active total when every policy is inactive. Rule data
    # is neither needed nor allowed to turn simulation conditions into active coverage.
    if ($active.Count -eq 0) {
        $answer.Reliable = $true
        $answer.Detail = 'No returned auto-labeling policy is in Enable mode.'
        if ($policyPartial) { $answer.Detail += $partialWarning }
        return [pscustomobject]$answer
    }

    $lookup = @{}
    $identityGaps = 0
    for ($i = 0; $i -lt $policies.Count; $i++) {
        $tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($field in 'Name', 'Guid') {
            foreach ($token in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $policies[$i] -Name $field))) {
                $null = $tokens.Add($token)
            }
        }
        if ($tokens.Count -eq 0) { $identityGaps++; continue }
        foreach ($token in $tokens) {
            $key = $token.Trim().ToLowerInvariant()
            if (-not $lookup.ContainsKey($key)) { $lookup[$key] = @() }
            $lookup[$key] = @($lookup[$key]) + $i
        }
    }

    $ruleResults = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'AutoLabelingRule' })
    if ($ruleResults.Count -ne 1 -or
        [string](Get-PurviewProperty -InputObject $ruleResults[0] -Name 'status') -notin 'Success', 'PartialSuccess') {
        $reason = Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'AutoLabelingRule'
        $answer.Detail = "The sensitive-information-type total is not checked because rules for the turned-on policies were not read. $reason"
        return [pscustomobject]$answer
    }

    $ruleData = Get-PurviewProperty -InputObject $ruleResults[0] -Name 'data'
    if (-not (Test-PurviewProperty -InputObject $ruleData -Name 'Rules')) {
        $answer.Detail = 'The sensitive-information-type total is not checked because the rule collector did not return its rule list.'
        return [pscustomobject]$answer
    }

    $rules = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $ruleData -Name 'Rules'))
    $matched = [int[]]::new($policies.Count)
    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $kinds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $missingLink = 0
    $ambiguousLink = 0
    $missingState = 0
    $conditionProblems = 0
    $disabledRules = 0
    $enabledRules = 0

    foreach ($rule in $rules) {
        $references = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($field in 'PolicyName', 'Policy', 'ParentPolicyName', 'PolicyGuid') {
            if (-not (Test-PurviewProperty -InputObject $rule -Name $field)) { continue }
            foreach ($token in @(Get-PurviewReferenceToken -Value (Get-PurviewProperty -InputObject $rule -Name $field))) {
                $null = $references.Add($token)
            }
        }
        if ($references.Count -eq 0) { $missingLink++; continue }

        $owners = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($reference in $references) {
            $key = $reference.Trim().ToLowerInvariant()
            if (-not $lookup.ContainsKey($key)) { continue }
            foreach ($index in @($lookup[$key])) { $null = $owners.Add([int]$index) }
        }
        if ($owners.Count -ne 1) { $ambiguousLink++; continue }

        $owner = @($owners)[0]
        if ($policyModes[$owner] -ne 'Enable') { continue }
        $matched[$owner]++

        if (-not (Test-PurviewProperty -InputObject $rule -Name 'Disabled') -or
            (Get-PurviewProperty -InputObject $rule -Name 'Disabled') -isnot [bool]) {
            $missingState++
            continue
        }
        if ([bool](Get-PurviewProperty -InputObject $rule -Name 'Disabled')) {
            $disabledRules++
            continue
        }

        $enabledRules++
        foreach ($kind in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $rule -Name 'ConditionKinds'))) {
            if (-not [string]::IsNullOrWhiteSpace([string]$kind)) { $null = $kinds.Add(([string]$kind).Trim()) }
        }
        $analysis = Get-PurviewAutoLabelRuleConditionAnalysis -Rule $rule
        foreach ($name in @($analysis.Names)) { $null = $found.Add([string]$name) }
        if ($analysis.Status -ne 'Complete') { $conditionProblems++ }
    }

    $unmatchedActive = 0
    foreach ($index in $active) { if ($matched[$index] -eq 0) { $unmatchedActive++ } }

    $gaps = [System.Collections.Generic.List[string]]::new()
    if ($identityGaps -gt 0) { $gaps.Add("$identityGaps collected policies have no usable name or identifier") }
    if ($missingLink -gt 0) { $gaps.Add("$missingLink rules do not identify their policy") }
    if ($ambiguousLink -gt 0) { $gaps.Add("$ambiguousLink rules do not match exactly one collected policy") }
    if ($unmatchedActive -gt 0) { $gaps.Add("$unmatchedActive turned-on policies have no collected rule") }
    if ($missingState -gt 0) { $gaps.Add("$missingState rules linked to a turned-on policy have no readable Disabled state") }
    if ($conditionProblems -gt 0) { $gaps.Add("$conditionProblems enabled rules have a malformed, unsupported or unresolved condition") }

    $names = @($found | Sort-Object)
    $answer.Names = $names
    if ($gaps.Count -gt 0) {
        $answer.Detail = 'The sensitive-information-type total is not checked because {0}.' -f ($gaps -join '; ')
        if ($names.Count -gt 0) {
            $partial = if ($names.Count -le 10) { $names -join ', ' }
            else { (@($names | Select-Object -First 10) -join ', ') + ", and $($names.Count - 10) more" }
            $answer.Detail += " Decoded so far: $partial. This is partial and is not presented as a total."
        }
        return [pscustomobject]$answer
    }

    $answer.Reliable = $true
    $answer.Count = $names.Count
    if ($names.Count -gt 0) {
        $text = if ($names.Count -le 10) { $names -join ', ' }
        else { (@($names | Select-Object -First 10) -join ', ') + ", and $($names.Count - 10) more" }
        $answer.Detail = "Configured sensitive information types: $text."
    }
    elseif ($enabledRules -eq 0) {
        $answer.Detail = 'No enabled rule was identified among the returned rules linked to policies in Enable mode.'
    }
    elseif ($kinds.Count -gt 0) {
        $answer.Detail = 'No sensitive information type was identified in the returned enabled rules. Other returned condition kinds: {0}.' -f ((@($kinds | Sort-Object)) -join ', ')
    }
    else {
        $answer.Detail = 'No sensitive information type was identified in the returned enabled rules linked to policies in Enable mode.'
    }
    if ($disabledRules -gt 0) { $answer.Detail += " $disabledRules explicitly disabled rules were excluded." }
    if ($policyPartial -or [string](Get-PurviewProperty -InputObject $ruleResults[0] -Name 'status') -eq 'PartialSuccess') {
        $answer.Detail += $partialWarning
    }
    return [pscustomobject]$answer
}

function Get-PurviewOpenRisk {
    <# .SYNOPSIS States the qualifiers a reader needs to interpret these findings correctly. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [AllowNull()][object]$Snapshot
    )

    $risks = [System.Collections.Generic.List[string]]::new()
    $risks.Add('This report reviews configuration, not live enforcement. Confirm policy delivery and detection with a controlled test before relying on protection.')

    foreach ($item in @($Finding | Where-Object { $_.status -in 'NotCollected', 'NeedsReview' })) {
        # The inner parentheses matter: inside a method call, a bare comma binds to the argument
        # list rather than to -f, leaving the format string one value short.
        $risks.Add(('{0}: {1}' -f $item.ruleId, $item.reason))
    }

    # Identify missing properties so counts from partial reads are not mistaken for complete totals.
    foreach ($result in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))) {
        $absent = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $result -Name 'propertiesNotReturned'))
        if ($absent.Count -eq 0) { continue }
        $risks.Add(('{0} returned records without {1}. Figures and conclusions depending on those fields may be incomplete or unreliable.' -f
                [string](Get-PurviewProperty -InputObject $result -Name 'collector'), ($absent -join ', ')))
    }

    $risks.Add('Recent sensitivity-label applications are not a count of distinct items. One item can be counted several times. Activity history covers at most 30 days, can still be receiving recent records, and excludes sensitivity-label activity from Power BI and Defender for Cloud Apps; zero recent applications does not mean no content is currently labelled.')
    $coverageResults = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults') | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'ClassificationCoverage'
        })
    if ($coverageResults.Count -gt 0) {
        $coverageData = Get-PurviewProperty -InputObject $coverageResults[0] -Name 'data'
        $explicitRequests = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $coverageData -Name 'Requests') | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'TagType') -eq 'SensitiveInformationType'
            })
        $explicitTags = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $coverageData -Name 'Tags') | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'TagType') -eq 'SensitiveInformationType'
            })
        if ($explicitRequests.Count -gt 0 -or $explicitTags.Count -gt 0) {
            $risks.Add('Content Explorer counts for explicitly requested sensitive information types are delayed. Counts can take seven days to update and SharePoint files 14 days; SharePoint and OneDrive files encrypted by sensitivity labels are not included, and administrative-unit role scope can narrow what this account sees. Each type is reported separately because one item can match more than one type.')
        }
    }
    $risks.Add('The label taxonomy is compared to the tiers Microsoft recommends as a secure-by-default starting point, not a standard a tenant has to meet. A tier named differently but serving the same purpose reads as organisation-specific.')
    # Both are real configuration a reader will look for, so their absence is stated rather than left blank.
    $risks.Add('Collection policy definitions and pay-as-you-go usage are not collected here. Review activity-collection scope and metered costs separately.')
    $risks.Add('This report covers selected Purview checks, not the entire Zero Trust Data pillar or a complete security assessment. It does not replace Microsoft Zero Trust Assessment: https://learn.microsoft.com/security/zero-trust/assessment/get-started')
    $risks.Add('This report names policies, labels and settings from the tenant. Treat it as sensitive and share it only with people entitled to see that configuration.')

    return $risks.ToArray()
}

function Find-PurviewBrowser {
    <#
    .SYNOPSIS
        Locates a Chromium browser that can print HTML to PDF.

    .DESCRIPTION
        PDF rendering depends on a locally installed supported browser rather than a bundled library.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = @(
        if ($env:ProgramFiles) {
            Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'
            Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
        }
        if (${env:ProgramFiles(x86)}) {
            Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
            Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'
        }
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    )

    foreach ($path in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { return $path }
    }

    foreach ($name in 'microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser') {
        $command = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command) { return $command.Source }
    }

    return ''
}

function Export-PurviewPdfReport {
    <#
    .SYNOPSIS
        Renders the HTML report to PDF, if a Chromium browser is available.

    .DESCRIPTION
        Returns the path on success, or an empty string with a warning. A missing browser is
        reported rather than silently producing nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath
    )

    $browser = Find-PurviewBrowser
    if ([string]::IsNullOrWhiteSpace($browser)) {
        Write-Warning 'No Edge, Chrome or Chromium was found, so no PDF was produced. Open the HTML report and print to PDF instead.'
        return ''
    }

    $browserProfilePath = Join-Path ([System.IO.Path]::GetTempPath()) ('purview-pdf-{0}' -f [guid]::NewGuid())
    $noise = $null
    $process = $null
    $browserExited = $false
    $complete = $false
    try {
        # A previous file cannot prove this render worked. The isolated profile also prevents an
        # already open browser from absorbing the command and returning before its child writes.
        if (Test-Path -LiteralPath $PdfPath) {
            Remove-Item -LiteralPath $PdfPath -Force -ErrorAction Stop
        }
        $null = New-Item -ItemType Directory -Path $browserProfilePath -Force -ErrorAction Stop
        $script:TempArtifact += $browserProfilePath

        # Start-Process joins this list into one command line on Windows, so quote path values in
        # their own arguments. Report folders and the system temporary folder can both contain spaces.
        $arguments = @(
            '--headless=new'
            '--disable-gpu'
            '--no-first-run'
            '--no-pdf-header-footer'
            "--user-data-dir=`"$browserProfilePath`""
            "--print-to-pdf=`"$PdfPath`""
            ([Uri]::new((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri
        )

        # Chromium writes diagnostics to stderr even on success, so keep it out of the console.
        $noise = New-TemporaryFile
        $script:TempArtifact += $noise.FullName
        $process = Start-Process -FilePath $browser -ArgumentList $arguments -PassThru -WindowStyle Hidden `
            -RedirectStandardError $noise.FullName

        $isCompletePdf = {
            $stream = $null
            try {
                if (-not (Test-Path -LiteralPath $PdfPath -PathType Leaf)) { return $false }
                # Exclusive access and boundary markers are basic completion checks, not full PDF
                # validation or proof that no browser process will write again.
                $stream = [System.IO.File]::Open(
                    $PdfPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::None)
                if ($stream.Length -lt 10) { return $false }

                $header = [byte[]]::new(5)
                if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or
                    [System.Text.Encoding]::ASCII.GetString($header) -ne '%PDF-') { return $false }

                $tailLength = [int][math]::Min(1024, $stream.Length)
                $tail = [byte[]]::new($tailLength)
                $null = $stream.Seek(-$tailLength, [System.IO.SeekOrigin]::End)
                $read = $stream.Read($tail, 0, $tail.Length)
                return [System.Text.Encoding]::ASCII.GetString($tail, 0, $read) -match '%%EOF\s*$'
            }
            catch { return $false }
            finally { if ($null -ne $stream) { $stream.Dispose() } }
        }

        # Edge may exit 0 before its child writes the PDF. Watch both output and process for up to
        # three minutes, capped at 30 seconds after a successful launcher exit for the hand-off.
        $deadline = [DateTime]::UtcNow.AddMinutes(3)
        $outputDeadline = $deadline
        while ([DateTime]::UtcNow -lt $outputDeadline) {
            $complete = & $isCompletePdf
            if ($complete) { break }

            if (-not $browserExited) {
                $remaining = [int][math]::Max(1, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                $browserExited = $process.WaitForExit([int][math]::Min(250, $remaining))
                if ($browserExited) {
                    if ($process.ExitCode -ne 0) {
                        Write-Warning "The browser did not produce a PDF (exit code $($process.ExitCode)). The HTML report is still available."
                        return ''
                    }
                    $handoffDeadline = [DateTime]::UtcNow.AddSeconds(30)
                    if ($handoffDeadline -lt $outputDeadline) { $outputDeadline = $handoffDeadline }
                }
            }
            else { Start-Sleep -Milliseconds 100 }
        }

        if (-not $complete) { $complete = & $isCompletePdf }
        if (-not $complete) {
            if (-not $browserExited) {
                try { $process.Kill() } catch { Write-Verbose 'The browser had already exited.' }
                Write-Warning 'The browser did not finish rendering within three minutes, so no PDF was produced. The HTML report is still available.'
            }
            else {
                Write-Warning "The browser did not produce a PDF (exit code $($process.ExitCode)). The HTML report is still available."
            }
            return ''
        }

        # A complete, closed PDF is the useful outcome. Do not leave an isolated browser running
        # only because its launcher stayed alive after finishing the print operation.
        if (-not $browserExited) {
            try { $process.Kill() } catch { Write-Verbose 'The browser had already exited.' }
        }
        return $PdfPath
    }
    catch {
        Write-Warning "PDF rendering failed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return ''
    }
    finally {
        if ($null -ne $noise) {
            Remove-Item -LiteralPath $noise.FullName -Force -ErrorAction SilentlyContinue
        }
        # Chromium fills even a one-run profile with subdirectories, so recursive cleanup is
        # required. A detached child can hold its final lock briefly after closing the PDF, so retry
        # for five seconds; Clear-PurviewRunState gets a second chance if it takes longer.
        for ($attempt = 0; $attempt -lt 50 -and (Test-Path -LiteralPath $browserProfilePath); $attempt++) {
            $null = Clear-PurviewTemporaryDirectory -Path $browserProfilePath
            if (Test-Path -LiteralPath $browserProfilePath) { Start-Sleep -Milliseconds 100 }
        }
        if (-not $complete -and (Test-Path -LiteralPath $PdfPath)) {
            Remove-Item -LiteralPath $PdfPath -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $process -and $process -is [System.IDisposable]) { $process.Dispose() }
    }
}

function Find-PurviewQpdf {
    <#
    .SYNOPSIS
        Locates qpdf, which is what can encrypt a PDF that already exists.

    .DESCRIPTION
        This script uses qpdf after browser rendering. It passes password arguments through
        standard input rather than the process command line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # The Windows installer puts qpdf in a folder named for its version, so the location is matched
    # rather than assumed, and a freshly installed copy is found without opening a new session.
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ([string]::IsNullOrWhiteSpace([string]$root)) { continue }
        $pattern = Join-Path $root 'qpdf*\bin\qpdf.exe'
        $hit = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        if ($hit.Count -gt 0) { return [string]$hit[0].FullName }
    }

    foreach ($path in @('/opt/homebrew/bin/qpdf', '/usr/local/bin/qpdf', '/usr/bin/qpdf')) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }

    # PATH remains a compatibility fallback, but fixed system locations win. This reduces the
    # chance that a process-local path override receives the PDF and its password input.
    $command = Get-Command -Name 'qpdf' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) { return [string]$command.Source }

    return ''
}

function Install-PurviewQpdf {
    <#
    .SYNOPSIS
        Returns a usable qpdf, installing it through the platform's package manager if need be.

    .DESCRIPTION
        If qpdf is missing, this tries winget on Windows or Homebrew on macOS unless installation
        is skipped. This changes the local machine and relies on the configured package source;
        the script does not independently verify package provenance. Elsewhere it offers guidance.

        The result is checked by finding the tool afterwards rather than by believing the installer.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$SkipInstall)

    $found = Find-PurviewQpdf
    if ($found) { return $found }

    if ($SkipInstall) {
        Write-Line -Style Warn -Message '    qpdf is not installed, and -SkipModuleInstall means nothing will be installed for you.'
        return ''
    }

    $winget = if ($IsWindows) {
        Get-Command -Name 'winget' -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    else { $null }
    $brew = if ($IsMacOS) {
        Get-Command -Name 'brew' -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    else { $null }
    $plan = if ($null -ne $winget) {
        @{
            Source = 'QPDF.QPDF through the winget community source, published by the qpdf project under Apache-2.0'
            Command = [string]$winget.Source
            Argument = @('install', '--exact', '--id', 'QPDF.QPDF', '--source', 'winget', '--silent', '--accept-package-agreements', '--accept-source-agreements')
        }
    }
    elseif ($null -ne $brew) {
        @{ Source = 'the qpdf formula through Homebrew'; Command = [string]$brew.Source; Argument = @('install', 'qpdf') }
    }
    else { $null }

    if ($null -eq $plan) {
        Write-Line -Style Warn -Message '    This script needs qpdf for PDF encryption; no supported automatic installation route was found.'
        Write-Line -Style Dim -Message '    Install it with apt install qpdf, dnf install qpdf, or from https://qpdf.sourceforge.io'
        return ''
    }

    Write-Line -Style Dim -Message ('    Installing qpdf: {0}.' -f $plan.Source)
    Write-Line -Style Dim -Message '    This may ask you to allow the install.'
    try {
        $installer = [string]$plan.Command
        $installArguments = @($plan.Argument)
        & $installer @installArguments *> $null
    }
    catch { Write-Verbose "Installing qpdf did not complete: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }

    # The environment this process started with predates the install, so the path is re-read.
    if ($IsWindows) {
        $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $user = [Environment]::GetEnvironmentVariable('Path', 'User')
        # Keep process-only entries supplied by the caller; replacing PATH here can break tools
        # that were available when the assessment started.
        $env:Path = (@($env:Path, $machine, $user) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ';'
    }

    $found = Find-PurviewQpdf
    if (-not $found) {
        Write-Line -Style Warn -Message '    qpdf still could not be found after installing, so the PDF was not encrypted.'
    }
    return $found
}

function Test-PurviewSecretMatch {
    <#
    .SYNOPSIS
        Says whether two secure strings hold the same value.

    .DESCRIPTION
        Compares unmanaged copies that can be cleared afterward, avoiding managed plaintext
        strings that cannot be overwritten.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Security.SecureString]$First,
        [Parameter(Mandatory)][System.Security.SecureString]$Second
    )

    $a = [IntPtr]::Zero
    $b = [IntPtr]::Zero
    try {
        $a = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)

        # A BSTR keeps its length in the four bytes before the data it points at.
        $lengthA = [Runtime.InteropServices.Marshal]::ReadInt32($a, -4)
        $lengthB = [Runtime.InteropServices.Marshal]::ReadInt32($b, -4)
        if ($lengthA -ne $lengthB) { return $false }

        for ($offset = 0; $offset -lt $lengthA; $offset += 2) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($a, $offset) -ne [Runtime.InteropServices.Marshal]::ReadInt16($b, $offset)) {
                return $false
            }
        }
        return $true
    }
    finally {
        if ($a -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a) }
        if ($b -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
}

function Read-PurviewSecret {
    <#
    .SYNOPSIS
        Asks for a password twice and hands back the agreed value as a secure string.

    .DESCRIPTION
        Secure input avoids displaying the password and returns SecureString values. Comparison
        and encryption require temporary plaintext buffers; this does not guarantee memory erasure.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param([Parameter(Mandatory)][string]$Prompt)

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $first = Read-Host -Prompt $Prompt -AsSecureString
        if ($first.Length -eq 0) {
            $first.Dispose()
            Write-Line -Style Warn -Message '    An empty password protects nothing.'
            continue
        }

        $second = Read-Host -Prompt '    Type it again' -AsSecureString
        $same = Test-PurviewSecretMatch -First $first -Second $second
        $second.Dispose()
        if ($same) { return $first }

        $first.Dispose()
        Write-Line -Style Warn -Message '    Those did not match.'
    }

    return $null
}

function Write-PurviewSecretArgument {
    <#
    .SYNOPSIS
        Writes one qpdf argument, ending in a secret, straight to a stream.

    .DESCRIPTION
        Uses character and byte arrays instead of a managed string so owned buffers can be
        cleared on exit, along with the BSTR. Copies in stream buffers, the runtime or qpdf
        are outside this cleanup guarantee.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Stream]$Stream,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][System.Security.SecureString]$Secret
    )

    $bstr = [IntPtr]::Zero
    $secretChars = $null
    $line = $null
    $bytes = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        $count = [Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4) / 2
        $secretChars = [char[]]::new($count)
        [Runtime.InteropServices.Marshal]::Copy($bstr, $secretChars, 0, $count)

        $prefixChars = $Prefix.ToCharArray()
        $line = [char[]]::new($prefixChars.Length + $count + 1)
        [Array]::Copy($prefixChars, 0, $line, 0, $prefixChars.Length)
        [Array]::Copy($secretChars, 0, $line, $prefixChars.Length, $count)
        # qpdf reads one argument per line from standard input.
        $line[$line.Length - 1] = [char]10

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush()
    }
    finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($null -ne $line) { [Array]::Clear($line, 0, $line.Length) }
        if ($null -ne $secretChars) { [Array]::Clear($secretChars, 0, $secretChars.Length) }
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

function Protect-PurviewPdf {
    <#
    .SYNOPSIS
        Encrypts a PDF in place so it cannot be opened without the password.

    .DESCRIPTION
        qpdf documents reading its arguments from standard input as the way to avoid passing
        passwords on a command line. This script uses that route rather than a password file;
        it does not guarantee absence from memory, paging, dumps or external monitoring.

        The owner password is a fresh random value that is discarded. The PDF format allows an
        empty one, and qpdf documents both an empty owner password and one equal to the user
        password as insecure. Nobody needs to know it, since its only use is lifting the
        restrictions being applied here.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$PdfPath,
        [Parameter(Mandatory)][System.Security.SecureString]$Password,
        [Parameter(Mandatory)][AllowEmptyString()][string]$QpdfPath
    )

    if ([string]::IsNullOrWhiteSpace($QpdfPath)) { return $false }
    $qpdf = $QpdfPath

    $encrypted = "$PdfPath.protected"
    $owner = [byte[]]::new(32)
    $process = $null
    $errorRead = $null
    $outputRead = $null
    try {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($owner)

        $info = [System.Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $qpdf
        foreach ($argument in @($PdfPath, '@-', $encrypted)) { $null = $info.ArgumentList.Add($argument) }
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($info)
        # Drain both redirected streams concurrently. Reading either one synchronously before the
        # timed wait can deadlock when the other pipe fills, making the timeout ineffective.
        $errorRead = $process.StandardError.ReadToEndAsync()
        $outputRead = $process.StandardOutput.ReadToEndAsync()
        $stream = $process.StandardInput.BaseStream

        $preamble = [System.Text.Encoding]::UTF8.GetBytes("--encrypt`n")
        $stream.Write($preamble, 0, $preamble.Length)
        Write-PurviewSecretArgument -Stream $stream -Prefix '--user-password=' -Secret $Password
        $tail = [System.Text.Encoding]::UTF8.GetBytes(('--owner-password={0}{1}--bits=256{1}--{1}' -f [Convert]::ToBase64String($owner), "`n"))
        $stream.Write($tail, 0, $tail.Length)
        [Array]::Clear($tail, 0, $tail.Length)
        $stream.Flush()
        $process.StandardInput.Close()

        if (-not $process.WaitForExit(120000)) {
            try { $process.Kill() } catch { Write-Verbose 'qpdf had already exited.' }
            try { $null = $process.WaitForExit(5000) } catch { Write-Verbose 'qpdf did not confirm exit after it was stopped.' }
            Write-Warning 'qpdf did not finish within two minutes, so the PDF was left unencrypted.'
            return $false
        }
        # The process has closed both pipes, so the asynchronous reads now complete without a
        # parent/child dependency. Exit status and file existence are checked before replacement,
        # not full PDF validity.
        $process.WaitForExit()
        $problem = $errorRead.GetAwaiter().GetResult()
        $null = $outputRead.GetAwaiter().GetResult()

        # qpdf exits 0 clean and 3 for warnings without errors; anything else did not produce a file.
        if ($process.ExitCode -notin 0, 3 -or -not (Test-Path -LiteralPath $encrypted)) {
            Write-Warning "qpdf could not encrypt the PDF: $(Get-PurviewSafeErrorMessage -Message $problem)"
            return $false
        }

        Move-Item -LiteralPath $encrypted -Destination $PdfPath -Force
        return $true
    }
    catch {
        Write-Warning "Encrypting the PDF failed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return $false
    }
    finally {
        [Array]::Clear($owner, 0, $owner.Length)
        if ($process) { $process.Dispose() }
        if (Test-Path -LiteralPath $encrypted) { Remove-Item -LiteralPath $encrypted -Force -ErrorAction SilentlyContinue }
    }
}

function Export-PurviewWordReport {
    <#
    .SYNOPSIS
        Converts the HTML report to .docx using Word, if Word is installed.

    .DESCRIPTION
        Word automation is Windows only and needs Word present. Where it is not, that is reported
        rather than failing the run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$WordPath
    )

    # A requested export must never leave an older document looking like this run produced it.
    try {
        if (Test-Path -LiteralPath $WordPath) {
            Remove-Item -LiteralPath $WordPath -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "The previous Word report could not be removed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return ''
    }

    if (-not $IsWindows) {
        Write-Warning 'Word export needs Word on Windows, so no .docx was produced.'
        return ''
    }

    $word = $null
    $document = $null
    $failure = ''
    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $document = $word.Documents.Open((Resolve-Path -LiteralPath $HtmlPath).Path, $false, $true)
        # 16 is wdFormatDocumentDefault, the .docx format.
        $document.SaveAs2($WordPath, 16)
    }
    catch {
        $failure = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
    }
    finally {
        if ($null -ne $document) {
            try { $document.Close($false) }
            catch { Write-Verbose "The Word document could not be closed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
            try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($document) }
            catch { Write-Verbose "The Word document COM object could not be released: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
        }
        if ($null -ne $word) {
            try { $word.Quit() }
            catch { Write-Verbose "Word could not be closed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
            try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) }
            catch { Write-Verbose "The Word application COM object could not be released: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
        }
    }

    if ($failure) {
        Remove-Item -LiteralPath $WordPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Word export was unavailable: $failure"
        return ''
    }
    return $WordPath
}

function Test-PurviewEvidence {
    <#
    .SYNOPSIS
        Checks evidence-registry URLs and compares available stored fingerprints.

    .DESCRIPTION
        Cited pages can become unavailable or change. Compare fetched text with stored fingerprints
        and flag differences for review. Report missing fingerprints rather than assuming currency.
        This does not check every URL in the script or prove that a source supports the associated claim.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [int]$TimeoutSeconds = 20
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($id in ($script:Evidence.Keys | Sort-Object)) {
        $record = $script:Evidence[$id]
        $baseline = [string](Get-PurviewProperty -InputObject $record -Name 'ContentHash')
        $outcome = [ordered]@{
            Id = $id; Url = $record.Url; RetrievedAt = $record.RetrievedAt
            State = 'Unknown'; Detail = ''; ContentHash = ''
        }

        try {
            $response = Invoke-WebRequest -Uri $record.Url -Method Get -MaximumRedirection 5 `
                -TimeoutSec $TimeoutSeconds -SkipHttpErrorCheck -ErrorAction Stop

            if ($response.StatusCode -ge 400) {
                $outcome.State = 'Unreachable'
                $outcome.Detail = "HTTP $($response.StatusCode)"
            }
            else {
                $outcome.ContentHash = Get-PurviewContentFingerprint -Content ([string]$response.Content)

                if ([string]::IsNullOrWhiteSpace($baseline)) {
                    $outcome.State = 'NoBaseline'
                    $outcome.Detail = "HTTP $($response.StatusCode). No fingerprint recorded, so a change cannot be detected."
                }
                elseif ($baseline -eq $outcome.ContentHash) {
                    $outcome.State = 'Unchanged'
                    $outcome.Detail = "HTTP $($response.StatusCode)"
                }
                else {
                    $outcome.State = 'Changed'
                    $outcome.Detail = 'The page differs from the text this rule was written against. Re-read it.'
                }
            }
        }
        catch {
            $outcome.State = 'Unreachable'
            $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
        }

        $results.Add([pscustomobject]$outcome)
    }

    return $results.ToArray()
}

function Export-PurviewRuleSet {
    <# .SYNOPSIS Writes the built-in rules and citations out as JSON, as a starting point to edit. #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write rule set')) { return '' }

    [pscustomobject]@{
        ruleSetVersion = '1.0'
        exportedAt = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)
        evidence = $script:Evidence
        rules = $script:Rules
    } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding utf8

    return $Path
}

function Import-PurviewRuleSet {
    <#
    .SYNOPSIS
        Replaces or extends the built-in rules from a file.

    .DESCRIPTION
        Conditions are declarative data, not executable code. Validate imported rules because
        malformed or over-reaching checks can still mislead. A supplied rule replaces the built-in
        rule with the same id; other rules remain unchanged.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Rule file not found: $Path" }

    $document = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20

    $knownAssertions = @('countEquals', 'countGreaterThan', 'countLessThan', 'isEmpty', 'isNotEmpty', 'noDuplicatesOf', 'allHave', 'anyHave', 'noneHave')
    $knownOperators = @('eq', 'ne', 'gt', 'lt', 'ge', 'le', 'contains', 'notContains', 'startsWith', 'exists', 'isNullOrEmpty', 'isNotNullOrEmpty')
    $knownCollectors = @(
        @((Get-PurviewSccCollectorDefinition) | ForEach-Object { [string]$_.Collector })
        'TenantPolicyConfig', 'OcrConfiguration', 'LegacyRetention', 'AuditIngestion'
        'SharePointLabelingReadiness', 'ContainerLabel', 'EndpointDeviceHealth'
        'InsiderRiskSharing', 'CloudAppConnector', 'ProtectedFilesConsent'
        'DataSecurityTelemetry', 'DataAccessGovernance', 'Licensing'
        'SentinelPurviewIntegration'
        'ProtectionActivity', 'ClassificationCoverage', 'SharePointSite'
    ) | Where-Object { $_ } | Sort-Object -Unique

    $evidence = @{}
    foreach ($key in $script:Evidence.Keys) { $evidence[$key] = $script:Evidence[$key] }

    # A file may supply rules only, citing entries that already exist.
    $supplied = Get-PurviewProperty -InputObject $document -Name 'evidence'
    if ($null -ne $supplied) {
        foreach ($property in @($supplied.PSObject.Properties)) {
            $entry = @{}
            foreach ($field in $property.Value.PSObject.Properties) { $entry[$field.Name] = $field.Value }
            foreach ($required in 'Title', 'Url') {
                if (-not $entry.ContainsKey($required)) { throw "Evidence '$($property.Name)' is missing $required." }
            }
            if ([string]$entry['Url'] -notmatch '^https://') { throw "Evidence '$($property.Name)' must cite an https source." }
            $evidence[$property.Name] = $entry
        }
    }

    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($existing in $script:Rules) { $rules.Add($existing) }

    foreach ($rule in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $document -Name 'rules'))) {
        $id = [string](Get-PurviewProperty -InputObject $rule -Name 'id')
        if ([string]::IsNullOrWhiteSpace($id)) { throw 'Every rule needs an id.' }

        foreach ($required in 'title', 'severity', 'recommendation', 'condition') {
            if (-not (Test-PurviewProperty -InputObject $rule -Name $required)) { throw "Rule '$id' is missing $required." }
        }

        $condition = Get-PurviewProperty -InputObject $rule -Name 'condition'
        $collector = [string](Get-PurviewProperty -InputObject $condition -Name 'collector')
        if ([string]::IsNullOrWhiteSpace($collector)) {
            throw "Rule '$id' does not say which collector it reads."
        }
        if ($collector -notin $knownCollectors) {
            throw "Rule '$id' names unknown collector '$collector'."
        }

        $analysis = [string](Get-PurviewProperty -InputObject $condition -Name 'analysis')
        if ($analysis) {
            if ($analysis -notin 'EndpointCoverage', 'PolicyRuleCoverage', 'DisabledRulesInEnforcingPolicies', 'RetentionLabelConfiguration', 'SentinelPurviewIntegration') {
                throw "Rule '$id' uses an unknown analysis '$analysis'."
            }
            $analysisCollector = switch ($analysis) {
                'EndpointCoverage' { 'DataLossPrevention' }
                'RetentionLabelConfiguration' { 'RetentionLabel' }
                'SentinelPurviewIntegration' { 'SentinelPurviewIntegration' }
                default { 'DlpRule' }
            }
            if ([string](Get-PurviewProperty -InputObject $condition -Name 'collector') -ne $analysisCollector) {
                throw "Rule '$id' can use analysis '$analysis' only with the $analysisCollector collector."
            }
            $assert = $null
        }
        else {
            $assert = Get-PurviewProperty -InputObject $condition -Name 'assert'
            $type = [string](Get-PurviewProperty -InputObject $assert -Name 'type')
            if ($type -notin $knownAssertions) { throw "Rule '$id' uses an unknown assertion '$type'." }
        }

        $validatePredicate = $null
        $validatePredicate = {
            param($predicate)
            if ($null -eq $predicate) { return }
            if (Test-PurviewProperty -InputObject $predicate -Name 'all') {
                $parts = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $predicate -Name 'all'))
                if ($parts.Count -eq 0) { throw "Rule '$id' has an empty compound predicate." }
                foreach ($part in $parts) { & $validatePredicate $part }
                return
            }
            if ((Test-PurviewProperty -InputObject $predicate -Name 'negate') -and
                (Get-PurviewProperty -InputObject $predicate -Name 'negate') -isnot [bool]) {
                throw "Rule '$id' has a predicate whose negate value is not Boolean."
            }
            $operator = [string](Get-PurviewProperty -InputObject $predicate -Name 'operator')
            if ($operator -notin $knownOperators) { throw "Rule '$id' uses an unknown operator '$operator'." }
        }
        & $validatePredicate (Get-PurviewProperty -InputObject $condition -Name 'where')
        & $validatePredicate (Get-PurviewProperty -InputObject $assert -Name 'where')

        foreach ($citation in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $rule -Name 'evidence'))) {
            if (-not $evidence.ContainsKey([string]$citation)) { throw "Rule '$id' cites '$citation', which no evidence entry defines." }
        }

        $replaced = @($rules | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'id') -eq $id })
        foreach ($old in $replaced) { $null = $rules.Remove($old) }
        $rules.Add($rule)
    }

    $script:Evidence = $evidence
    $script:Rules = $rules.ToArray()

    return [pscustomobject]@{
        Path = $Path
        RuleCount = $script:Rules.Count
        Supplied = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $document -Name 'rules')).Count
    }
}

function Get-PurviewRecommendedAction {
    <#
    .SYNOPSIS
        Selects up to five planning actions supported by complete configuration evidence.

    .DESCRIPTION
        This is a working order, not a risk or effort score. Only unchanged built-in rules receive
        the advice below. Re-evaluation is snapshot-only; no service or remediation is invoked.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    # Investigation visibility first, then label foundations, then policy rollout. Related DLP
    # and auto-labeling checks share one action rather than occupying several shortlist slots.
    $plans = @(
        @{
            RuleIds = @('PA-AUD-0002')
            Action = 'Plan unified audit enablement'
            Benefit = 'Establish activity evidence for investigations; missed activity is not backfilled.'
            Impact = 'Records supported activity metadata; this change does not introduce a content-blocking policy.'
            Preparation = 'Verify the current state in Exchange Online and the Audit Logs role. Review any recent attempt before another write; verify ingestion and search separately after propagation.'
            Url = $script:DocUrl.AuditLogEnable
        }
        @{
            RuleIds = @('PA-IP-0005')
            Action = 'Design the sensitivity-label set'
            Benefit = 'Provide classification choices before publishing labels or building label-based controls.'
            Impact = 'Design work first; later publishing and protection settings can change user workflows.'
            Preparation = 'Confirm classification needs, licensing, supported apps and protection settings. Keep the set small and pilot it before broad deployment.'
            Url = 'https://learn.microsoft.com/purview/create-sensitivity-labels'
        }
        @{
            RuleIds = @('PA-IP-0003')
            Action = 'Pilot a label publishing policy'
            Benefit = 'Make approved labels available to the intended users in supported apps.'
            Impact = 'Defaults, mandatory labelling and protection settings can change how users work.'
            Preparation = 'Agree the label design first. Review target groups and policy settings, test with a pilot group, and allow for propagation before expanding.'
            Url = 'https://learn.microsoft.com/purview/create-sensitivity-labels'
        }
        @{
            RuleIds = @('PA-IP-0004')
            Action = 'Review Office-file label processing'
            Benefit = 'Enable supported search, eDiscovery, DLP and collaboration on eligible labelled Office files in SharePoint and OneDrive.'
            Impact = 'Changes service-side file processing; file, encryption and client limitations still apply.'
            Preparation = 'Review existing policies, encryption and library IRM. Test representative files and clients, review each geo, and consider the mixed processing state if later disabled.'
            Url = $script:DocUrl.SharePointLabelledFiles
        }
        @{
            RuleIds = @('PA-DLP-0004', 'PA-DLP-0001', 'PA-DLP-0002', 'PA-DLP-0005')
            Action = 'Validate DLP coverage before enforcement'
            Benefit = 'Address the observed policy or rule gap against the intended data-loss controls.'
            Impact = 'Enforcement can block sharing and other activities. Simulation effects vary by workload and policy tips.'
            Preparation = 'Review scope, conditions, actions, exclusions and replacement coverage. Tune false positives and pilot in simulation before approving enforcement; do not enable every policy or rule.'
            Url = 'https://learn.microsoft.com/purview/dlp-create-deploy-policy'
        }
        @{
            RuleIds = @('PA-IP-0006', 'PA-IP-0008')
            Action = 'Plan and validate service-side auto-labeling'
            Benefit = 'Reduce reliance on manual labelling where automatic classification meets an identified need.'
            Impact = 'Activated policies can label content and apply the selected label protection settings.'
            Preparation = 'Confirm applicability and licensing, select labels and scope, then review simulation matches before activation. Existing manual or default labelling may already meet the requirement.'
            Url = $script:DocUrl.AutoLabelling
        }
    )
    $listKeys = @{
        AuditIngestion = 'Settings'; SharePointLabelingReadiness = 'Settings'
        SensitivityLabel = 'Labels'; SensitivityLabelPolicy = 'Policies'
        DataLossPrevention = 'Policies'; DlpRule = 'Rules'; AutoLabeling = 'Policies'
    }
    # Read raw values inside the object so a singleton array cannot masquerade as a Boolean.
    $readBoolean = {
        param($record, $field)
        $raw = $null
        if ($record -is [System.Collections.IDictionary]) { $raw = $record[$field] }
        elseif ($null -ne $record -and $record.PSObject.Properties[$field]) { $raw = $record.PSObject.Properties[$field].Value }
        if ($raw -isnot [bool] -and $raw -isnot [string]) { $raw = $null }
        ConvertTo-PurviewBoolean -InputObject $raw
    }
    $results = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))
    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($plan in $plans) {
        foreach ($id in $plan.RuleIds) {
            $hits = @($Finding | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'ruleId') -eq $id })
            if ($hits.Count -ne 1) { continue }
            $item = $hits[0]
            if ([string](Get-PurviewProperty -InputObject $item -Name 'status') -notin 'Fail', 'Warning' -or
                [string](Get-PurviewProperty -InputObject $item -Name 'confidence') -notin 'High', 'Medium') { continue }
            $definitions = @($script:BuiltInRules | Where-Object { $_.id -eq $id })
            $active = @($script:Rules | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'id') -eq $id })
            if ($definitions.Count -ne 1 -or $active.Count -ne 1 -or
                -not [object]::ReferenceEquals($definitions[0], $active[0])) { continue }
            $definition = $definitions[0]
            if ([string](Get-PurviewProperty -InputObject $item -Name 'ruleVersion') -cne $definition.version -or
                [string](Get-PurviewProperty -InputObject $item -Name 'title') -cne $definition.title -or
                [string](Get-PurviewProperty -InputObject $item -Name 'recommendation') -cne $definition.recommendation) { continue }

            $collectors = @($definition.condition.collector)
            if ($id -in 'PA-DLP-0004', 'PA-DLP-0005') { $collectors = @('DataLossPrevention', 'DlpRule') }
            $complete = $true
            $lists = @{}
            foreach ($collectorName in $collectors) {
                $collected = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $collectorName })
                if ($collected.Count -ne 1 -or [string](Get-PurviewProperty -InputObject $collected[0] -Name 'status') -ne 'Success') { $complete = $false; break }
                $data = Get-PurviewProperty -InputObject $collected[0] -Name 'data'
                foreach ($source in @($collected[0], $data)) {
                    if (@(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $source -Name 'PropertiesNotReturned')).Count -gt 0 -or
                        @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $source -Name 'errors')).Count -gt 0) { $complete = $false }
                }
                $key = $listKeys[$collectorName]
                $rawList = $null
                if ($data -is [System.Collections.IDictionary]) { $rawList = $data[$key] }
                elseif ($null -ne $data -and $data.PSObject.Properties[$key]) { $rawList = $data.PSObject.Properties[$key].Value }
                # An explicit empty list is evidence; a missing/null/scalar list is not absence.
                if ($rawList -isnot [System.Collections.IList]) { $complete = $false; break }
                $lists[$collectorName] = $rawList
                $settingNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($record in $rawList) {
                    $name = $null
                    if ($record -is [System.Collections.IDictionary]) { $name = $record['Name'] }
                    elseif ($null -ne $record -and $record.PSObject.Properties['Name']) { $name = $record.PSObject.Properties['Name'].Value }
                    if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) { $complete = $false; break }
                    if ($key -eq 'Settings' -and -not $settingNames.Add($name)) { $complete = $false; break }
                    $flag = switch ($collectorName) {
                        'SensitivityLabel' { 'Disabled' }
                        'DlpRule' { 'Disabled' }
                        'DataLossPrevention' { '' }
                        'AutoLabeling' { '' }
                        default { 'Enabled' }
                    }
                    if ($flag) {
                        if (-not (& $readBoolean $record $flag).Valid) { $complete = $false; break }
                    }
                    else {
                        $modeValue = $null
                        if ($record -is [System.Collections.IDictionary]) { $modeValue = $record['Mode'] }
                        elseif ($record.PSObject.Properties['Mode']) { $modeValue = $record.PSObject.Properties['Mode'].Value }
                        if ($modeValue -isnot [string] -or $modeValue -notin 'Enable', 'Disable', 'TestWithNotifications', 'TestWithoutNotifications') { $complete = $false; break }
                    }
                }
            }
            if (-not $complete) { continue }
            if ($id -in 'PA-AUD-0002', 'PA-IP-0004') {
                $settingName = if ($id -eq 'PA-AUD-0002') { 'UnifiedAuditLogIngestionEnabled' } else { 'EnableAIPIntegration' }
                $settings = @($lists[$collectors[0]] | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -eq $settingName })
                if ($settings.Count -ne 1 -or (& $readBoolean $settings[0] 'Enabled').Value) { continue }
                if ($id -eq 'PA-AUD-0002') {
                    $source = Get-PurviewProperty -InputObject $collected[0] -Name 'source'
                    if ($lists['AuditIngestion'].Count -ne 1 -or [string](Get-PurviewProperty -InputObject $source -Name 'kind') -ne 'ExchangeOnlinePowerShell') { continue }
                }
                else {
                    foreach ($field in 'Value', 'AsRecommended') {
                        if (-not (Test-PurviewProperty -InputObject $settings[0] -Name $field)) { continue }
                        $state = & $readBoolean $settings[0] $field
                        if (-not $state.Valid -or $state.Value) { $complete = $false }
                    }
                    if (-not $complete) { continue }
                }
            }

            # Do not promote a stale or independently supplied finding whose verdict disagrees
            # with the unchanged built-in rule on this snapshot. This does not recollect data.
            $verified = @(Invoke-PurviewRuleEngine -Snapshot $Snapshot -Rule @($definition))
            if ($verified.Count -ne 1 -or $verified[0].status -ne [string](Get-PurviewProperty -InputObject $item -Name 'status') -or
                $verified[0].confidence -notin 'High', 'Medium') { continue }
            $output.Add([pscustomobject]@{
                    RuleId = $id; Action = $plan.Action; Reason = $verified[0].reason
                    Benefit = $plan.Benefit; Impact = $plan.Impact; Preparation = $plan.Preparation; Url = $plan.Url
                })
            break
        }
    }
    return [pscustomobject[]]@($output | Select-Object -First 5)
}

function Get-PurviewContentFingerprint {
    <#
    .SYNOPSIS
        Fingerprints documentation text so a later fetch can be compared with it.

    .DESCRIPTION
        Markup, scripts and whitespace change constantly without the guidance changing, so they are
        stripped before hashing. Text is lowercased and whitespace normalized; the first 32 SHA-256
        hex characters are compared. A match does not prove unchanged guidance or claim support.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    $text = $Content -replace '(?is)<script.*?</script>', ' '
    $text = $text -replace '(?is)<style.*?</style>', ' '
    $text = $text -replace '(?s)<[^>]+>', ' '
    $text = ($text -replace '\s+', ' ').Trim().ToLowerInvariant()

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').Substring(0, 32) }
    finally { $sha.Dispose() }
}

function Show-EvidenceCheck {
    <# .SYNOPSIS Prints which cited sources still resolve, and which have changed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result)

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Evidence check'

    foreach ($item in $Result) {
        $style = switch ($item.State) {
            'Unchanged' { 'Good' }
            'NoBaseline' { 'Dim' }
            'Changed' { 'Warn' }
            default { 'Bad' }
        }
        Write-Line -Style $style -Message ('    {0,-12} {1,-22} {2}' -f $item.State, $item.Id, $item.Url)
        if ($item.State -notin 'Unchanged') { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
    }

    $changed = @($Result | Where-Object { $_.State -eq 'Changed' }).Count
    $broken = @($Result | Where-Object { $_.State -eq 'Unreachable' }).Count
    $unknown = @($Result | Where-Object { $_.State -eq 'NoBaseline' }).Count

    Write-Line -Message ''
    if ($changed -gt 0) {
        Write-Line -Style Warn -Message "    $changed page(s) have changed since the rule citing them was written. Re-read those before relying on the finding."
    }
    if ($broken -gt 0) {
        Write-Line -Style Bad -Message "    $broken source(s) could not be reached."
    }
    if ($unknown -gt 0) {
        Write-Line -Style Dim -Message "    $unknown source(s) carry no fingerprint, so a change in wording cannot be detected for them."
    }
    if ($changed -eq 0 -and $broken -eq 0 -and $unknown -eq 0) {
        Write-Line -Style Dim -Message '    No difference or reachability failure was reported for the checked registry entries. Fingerprints do not validate claim support or every citation.'
    }
}

function ConvertTo-PurviewHtmlReport {
    <#
    .SYNOPSIS
        Renders the assessment as HTML, in the fixed section order.

    .DESCRIPTION
        Every tenant-supplied string is HTML-encoded. A label or policy named with markup is data
        arriving from a system this script does not control, so it must render as text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [AllowNull()][object]$Snapshot = $null,
        [AllowNull()][object]$Delta = $null,
        [string]$Title = 'Microsoft Purview assessment',
        [switch]$DarkMode,
        [switch]$Brief
    )

    $Finding = @(Get-PurviewCustomerFinding -Finding $Finding)
    $generated = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp) -Friendly
    $builder = [System.Text.StringBuilder]::new()

    function Add-Row { param($Cells) $null = $builder.AppendLine("<tr>$(($Cells | ForEach-Object { "<td>$_</td>" }) -join '')</tr>") }
    function Enc { param($Value) ConvertTo-PurviewEncodedText -Value ([string]$Value) }

    $null = $builder.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $builder.AppendLine("<title>$(Enc $Title)</title>")
    # One stylesheet, two palettes: the rules below read from custom properties so a dark run
    # cannot drift from a light one.
    $palette = if ($DarkMode) {
        ':root{color-scheme:dark;--bg:#1b1b1b;--fg:#e8e8e8;--line:#3f3f3f;--head:#262626;--rule:#333;--fail:#ff7b72;--warn:#e3b341;--pass:#7ee787;--dim:#9aa0a6;--info:#79c0ff;--link:#79c0ff;--code:#262626;}'
    }
    else {
        ':root{color-scheme:light;--bg:#fff;--fg:#1b1b1b;--line:#ccc;--head:#f3f3f3;--rule:#eee;--fail:#a80000;--warn:#8a6100;--pass:#0b6a0b;--dim:#666;--info:#0b4a8a;--link:#0645ad;--code:#f5f5f5;}'
    }

    $null = $builder.AppendLine("<style>$palette" + 'body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;max-width:100rem;background:var(--bg);color:var(--fg);}a{color:var(--link);}code{background:var(--code);padding:.1rem .2rem;}table{border-collapse:collapse;width:100%;margin-bottom:1.5rem;}th,td{border:1px solid var(--line);padding:.4rem;text-align:left;vertical-align:top;font-size:.9rem;}th{background:var(--head);}h2{border-bottom:2px solid var(--rule);padding-bottom:.3rem;margin-top:2rem;}.fail{color:var(--fail);font-weight:600;}.warn{color:var(--warn);}.pass{color:var(--pass);}.dim{color:var(--dim);}.info{color:var(--info);font-weight:600;}.mark{white-space:nowrap;width:2.5rem;text-align:center;}.tight{white-space:nowrap;width:6rem;}.wide{width:32%;}</style>')
    # Keep written states and native controls usable without color, at high zoom and by keyboard.
    # Unlike anywhere, break-word preserves whole-word minimum widths in automatic table layout.
    $null = $builder.AppendLine(@'
<style>
body{line-height:1.5;overflow-wrap:break-word;}
a{text-decoration:underline;text-underline-offset:.12em;}
button{font:inherit;min-height:2rem;max-width:100%;padding:.35rem .6rem;}
.rem-pick{width:1.5rem;height:1.5rem;vertical-align:middle;}
.table-scroll{max-width:100%;overflow-x:auto;margin-bottom:1.5rem;}
.table-scroll table{margin-bottom:0;}
@media screen{
.table-scroll table{min-width:60rem;}
.table-scroll th,.table-scroll td{min-width:8rem;}
.table-scroll .mark{min-width:2.5rem;}
.table-scroll .tight{min-width:6rem;}
.table-scroll .wide{min-width:16rem;}
.inventory-table th:nth-child(2),.inventory-table td:nth-child(2){min-width:14rem;}
.inventory-table th:last-child,.inventory-table td:last-child{min-width:24rem;}
.optin-table th:nth-child(n+3),.optin-table td:nth-child(n+3){min-width:18rem;}
.copilot-table th:nth-child(n+2),.copilot-table td:nth-child(n+2){min-width:22rem;}
.taxonomy-table th:first-child,.taxonomy-table td:first-child{min-width:18rem;}
}
a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible,.table-scroll:focus-visible{outline:3px solid var(--link);outline-offset:3px;}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
@media screen and (max-width:40rem){body{margin:1rem;}}
@media (forced-colors:active){a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible,.table-scroll:focus-visible{outline-color:Highlight;}}
@media print{.table-scroll{overflow:visible;}.table-scroll table{table-layout:fixed;}.table-scroll th,.table-scroll td{white-space:normal;overflow-wrap:anywhere;}}
</style>
'@)
    $null = $builder.AppendLine('</head><body><main>')
    $null = $builder.AppendLine("<h1>$(Enc $Title)</h1>")
    $null = $builder.AppendLine("<p class=""dim"">Generated $(Enc $generated) by version $(Enc $script:ToolVersion).</p>")

    # A narrowed run must never read as a full one: an unassessed solution is not a passing solution.
    if ((Test-Path variable:script:ActiveSolution) -and @($script:ActiveSolution).Count -gt 0) {
        $null = $builder.AppendLine("<p class=""info"">Scope: $(Enc ($script:ActiveSolution -join ', ')) only. Every other Purview solution was neither collected nor scored, and its absence from this report says nothing about it.</p>")
    }

    # Everything was still assessed, so say what was left out rather than let the reader assume this
    # is all there was to find.
    if ($Brief) {
        $null = $builder.AppendLine('<p class="dim">Condensed report of the requested assessment scope. Prerequisites, Copilot and AI controls, taxonomy comparison, remediation checklist, coverage matrix, blueprint coverage and per-finding detail are omitted here. Run without -Brief for those.</p>')
    }

    $counts = @{}
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotCollected', 'Unsupported', 'NotLicensed') {
        $counts[$status] = @($Finding | Where-Object { $_.status -eq $status }).Count
    }

    $null = $builder.AppendLine('<h2>Tenant at a Glance</h2>')
    $null = $builder.AppendLine('<p class="dim">Configuration and available usage information observed in this run. Where a row reads not checked, a reliable value was unavailable and the detail explains why.</p>')
    $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Tenant at a Glance" tabindex="0"><table class="inventory-table"><thead><tr><th scope="col">Area</th><th scope="col">Measure</th><th scope="col">Value</th><th scope="col">Detail</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewInventory -Snapshot $Snapshot)) {
        Add-Row @((Enc $row.Area), (Enc $row.Metric), (Enc $row.Value), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table></div>')

    $null = $builder.AppendLine('<h2>Executive Summary</h2>')
    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add("<span class=""pass"">$($counts.Pass) passed</span>")
    if ($counts.Fail -gt 0) { $summary.Add("<span class=""fail"">$($counts.Fail) areas for improvement</span>") }
    if ($counts.Warning -gt 0) { $summary.Add("$($counts.Warning) warnings") }
    if ($counts.NeedsReview -gt 0) { $summary.Add("$($counts.NeedsReview) to review") }
    $unread = $counts.NotCollected + $counts.Unsupported
    if ($unread -gt 0) { $summary.Add("$unread not checked") }
    if ($counts.NotLicensed -gt 0) { $summary.Add("$($counts.NotLicensed) not available with current licensing") }
    $null = $builder.AppendLine("<p>$($Finding.Count) checks: $($summary -join ', ').</p>")
    # Rule titles name the state a check asserts, so listing them bare under a heading about gaps
    # reads as though the desired state were the problem. The finding goes underneath to fix that.
    $failing = @($Finding | Where-Object { $_.status -eq 'Fail' } |
        Sort-Object @{ Expression = { Get-PurviewSeverityOrder -Severity ([string](Get-PurviewProperty -InputObject $_ -Name 'severity')) } }, ruleId)
    $top = @($failing | Select-Object -First 5)
    if ($top.Count -gt 0) {
        $lead = if ($failing.Count -gt $top.Count) { "Checks that did not pass, most significant first, showing $($top.Count) of $($failing.Count):" }
        else { 'Checks that did not pass, most significant first:' }
        $null = $builder.AppendLine("<p>$lead</p><ul>")
        foreach ($item in $top) {
            $null = $builder.AppendLine("<li>$(Enc $item.title)<br><span class=""dim"">$(Enc $item.reason)</span></li>")
        }
        $null = $builder.AppendLine('</ul>')
    }

    # 3 - only on a re-run that has something real to compare against. On a first assessment the
    # section can say nothing but "no baseline", which reads as a gap in the tenant rather than a
    # gap in the record.
    if ($null -ne $Delta -and $Delta.Comparable) {
        # Two tenants differing is not one tenant progressing, so the same numbers need other words.
        $cross = (Test-PurviewProperty -InputObject $Delta -Name 'CrossTenant') -and $Delta.CrossTenant
        if ($cross) {
            $null = $builder.AppendLine('<h2>Comparison With Another Tenant</h2>')
            $null = $builder.AppendLine("<p>Compared against a record from a different tenant, taken $(Enc $Delta.BaselineRecordedAt).</p>")
            $null = $builder.AppendLine('<p class="dim">The two tenants may be licensed or scoped differently, so a difference is a question to ask rather than a fault to fix.</p>')
        }
        else {
            $null = $builder.AppendLine('<h2>Progress Since Last Assessment</h2>')
            $null = $builder.AppendLine("<p>Compared against the run of $(Enc $Delta.BaselineRecordedAt).</p>")
        }

        # Rules and tenant opt-ins have different state vocabularies and are never added together.
        foreach ($group in @(
                [pscustomobject]@{ Heading = 'Rule outcomes'; Movement = $Delta.RuleMovement; IsRule = $true }
                [pscustomobject]@{ Heading = 'Tenant opt-ins'; Movement = $Delta.OptInMovement; IsRule = $false }
            )) {
            $movement = $group.Movement
            $better = if ($cross) { 'stronger here' } else { 'improved' }
            $worse = if ($cross) { 'weaker here' } else { 'regressed' }
            $null = $builder.AppendLine("<h3>$(Enc $group.Heading)</h3>")
            $null = $builder.AppendLine("<p><span class=""pass"">$($movement.Improved) $better</span>, <span class=""fail"">$($movement.Regressed) $worse</span>, $($movement.Unchanged) unchanged.</p>")
            if (-not $group.IsRule) {
                $null = $builder.AppendLine('<p class="dim">Portal-only checks and unassessed states stay outside movement and unchanged totals; confirm them separately.</p>')
            }
            elseif ($movement.Removed -gt 0) {
                $null = $builder.AppendLine("<p class=""dim"">$($movement.Removed) checks are no longer evaluated. Removed checks are not tenant improvements.</p>")
            }
            if ($movement.CouldNotAssess -gt 0) {
                $null = $builder.AppendLine("<p class=""dim"">$($movement.CouldNotAssess) could not be assessed this run. Kept out of movement because missing evidence does not establish whether the tenant changed.</p>")
            }
            if ($movement.NewlyAssessed -gt 0) {
                $null = $builder.AppendLine("<p class=""dim"">$($movement.NewlyAssessed) newly assessed. New evidence is not movement.</p>")
            }

            $moved = @($movement.Changes | Where-Object { $_.Change -in 'Improved', 'Regressed', 'CouldNotAssess' })
            if ($moved.Count -eq 0) {
                $null = $builder.AppendLine('<p class="dim">No assessed outcome moved.</p>')
                continue
            }

            $sides = if ($cross) { '<th scope="col">There</th><th scope="col">Here</th>' } else { '<th scope="col">Was</th><th scope="col">Now</th>' }
            $null = $builder.AppendLine("<div class=""table-scroll"" role=""region"" aria-label=""$(Enc $group.Heading) changes"" tabindex=""0""><table><thead><tr><th scope=""col"">Item</th>$sides<th scope=""col"">Change</th><th scope=""col"">Note</th></tr></thead><tbody>")
            foreach ($row in ($moved | Sort-Object Change, RuleId, Name)) {
                $class = switch ($row.Change) { 'Improved' { 'pass' } 'Regressed' { 'fail' } 'CouldNotAssess' { 'warn' } default { 'dim' } }
                $was = if ($row.From) { Enc $row.From } else { '<span class="dim">&mdash;</span>' }
                $now = if ($row.To) { Enc $row.To } else { '<span class="dim">&mdash;</span>' }
                $what = if ($group.IsRule) { '{0} &mdash; {1}' -f (Enc $row.RuleId), (Enc $row.Title) } else { Enc $row.Name }
                $kind = Format-PurviewChangeKind -Change $row.Change -CrossTenant:$cross
                $null = $builder.AppendLine("<tr><td>$what</td><td>$was</td><td>$now</td><td class=""$class"">$(Enc $kind)</td><td>$(Enc $row.Detail)</td></tr>")
            }
            $null = $builder.AppendLine('</tbody></table></div>')
        }
    }

    # Omit these seven detail sections in Brief mode; planning actions remain below the block.
    if (-not $Brief) {

    # Every finding is rendered below, either in full or in the Everything else table, so a rule id
    # can be linked to it. Ids that were never evaluated stay as plain text rather than dead links.
    $anchored = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($seen in $Finding) { $null = $anchored.Add([string]$seen.ruleId) }
    $link = {
        param($id)
        if ($anchored.Contains([string]$id)) { '<a href="#{0}">{1}</a>' -f (Enc $id), (Enc $id) } else { Enc $id }
    }

    $null = $builder.AppendLine('<h2>Prerequisites and Tenant Opt-ins</h2>')
    $prereq = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding)
    # Share the eligibility predicate between buttons and checkboxes. Separate predicates once
    # left Script-based actions downloadable but unselectable, unlike single-Command actions.
    $canRemediate = {
        param($row)
        ($row.State -eq 'Needs attention' -and ($row.Command -or $null -ne $row.Script)) -or @($row.Candidates).Count -gt 0
    }
    $remediable = @($prereq | Where-Object { & $canRemediate $_ })

    $attention = @($prereq | Where-Object { $_.State -eq 'Needs attention' }).Count
    $good = @($prereq | Where-Object { $_.State -in 'As recommended', 'Granted' }).Count
    $inUse = @($prereq | Where-Object { $_.State -eq 'In use' }).Count
    $seenRecently = @($prereq | Where-Object { $_.State -eq 'Seen recently' }).Count
    $evidenceFound = @($prereq | Where-Object { $_.State -eq 'Evidence found' }).Count
    $portal = @($prereq | Where-Object { $_.State -eq 'Confirm in portal' }).Count
    $notLicensed = @($prereq | Where-Object { $_.State -eq 'Not available - licensing' }).Count
    # Counted by state, not as a residual: evidence states must never be tallied as not read.
    $unread = @($prereq | Where-Object { $_.State -eq 'Not read' }).Count

    $summary = "<span class=""fail""><strong>$attention need attention</strong></span> &middot; <span class=""pass"">$good as recommended</span>"
    if ($inUse -gt 0) { $summary += " &middot; <span class=""pass"">$inUse in use</span>" }
    if ($seenRecently -gt 0) { $summary += " &middot; $seenRecently seen recently" }
    if ($evidenceFound -gt 0) { $summary += " &middot; $evidenceFound evidence found" }
    $summary += " &middot; $portal to confirm in the portal"
    if ($unread -gt 0) { $summary += " &middot; $unread not read this run" }
    if ($notLicensed -gt 0) { $summary += " &middot; $notLicensed not available with current licensing" }
    $null = $builder.AppendLine("<p>$summary</p>")
    $null = $builder.AppendLine('<p class="dim">Selected supporting settings and signals, compared with this report''s reference values. Defaults, applicability and deployment needs differ. Review scope and impact before changing a setting; a positive state does not verify processing or effective protection.</p>')

    if ($remediable.Count -gt 0) {
        $null = $builder.AppendLine('<p><button type="button" id="rem-all">Select all</button> <button type="button" id="rem-none">Clear</button> <button type="button" id="rem-get">Download script for selected</button> <span class="dim" id="rem-count" role="status" aria-live="polite" aria-atomic="true"></span></p>')
        $null = $builder.AppendLine('<p class="dim">Select actions to review. The generated script requests confirmation for tenant changes; local setup, recording and session operations can occur separately.</p>')
        # Download marking and execution policy can affect whether the generated script runs.
        $null = $builder.AppendLine('<p class="dim">Review the downloaded script and follow organisational execution policy. If an Internet-zone mark prevents execution and policy permits removal, use <code>Unblock-File</code> only after that review.</p>')
    }

    $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Prerequisites and Tenant Opt-ins" tabindex="0"><table class="optin-table"><thead><tr><th scope="col" class="mark">Take</th><th scope="col">Status</th><th scope="col">Opt-in</th><th scope="col">Why it matters</th><th scope="col">Recommended state</th></tr></thead><tbody>')
    foreach ($row in $prereq) {
        $class = switch ($row.State) { 'As recommended' { 'pass' } 'Granted' { 'pass' } 'Needs attention' { 'fail' } 'In use' { 'pass' } 'Not available - licensing' { 'info' } default { 'dim' } }
        $name = if ($row.Url) { "<a href=""$(Enc $row.Url)"">$(Enc $row.Name)</a>" } else { Enc $row.Name }
        if ($row.Optional) { $name += ' <span class="dim">(optional)</span>' }
        $action = Enc $row.Action
        if ($row.Action -match '^(Set|Leave)') { $action = "<code>$action</code>" }

        $pick = if (& $canRemediate $row) {
            "<input type=""checkbox"" class=""rem-pick"" data-name=""$(Enc $row.Name)"" aria-label=""Select $(Enc $row.Name)"">"
        }
        else { '' }

        $null = $builder.AppendLine("<tr><td class=""mark"">$pick</td><td class=""$class""><strong>$(Enc $row.State)</strong></td><td>$name<br><span class=""dim"">$(Enc $row.Detail)</span></td><td>$(Enc $row.Why)</td><td>$action</td></tr>")
    }
    $null = $builder.AppendLine('</tbody></table></div>')

    # The parts are embedded rather than linked so selection still works when this report is emailed
    # on its own. Base64 keeps PowerShell syntax away from the HTML parser.
    if ($remediable.Count -gt 0) {
        $tenant = Get-PurviewProperty -InputObject $Snapshot -Name 'tenant'
        $tenantName = [string](Get-PurviewProperty -InputObject $tenant -Name 'displayName')
        $tenantId = [string](Get-PurviewProperty -InputObject $tenant -Name 'tenantId')
        # The same URL the run worked out, so a script downloaded from here does not ask again for
        # something the copy written beside the report already knows.
        $adminUrl = if (Test-Path variable:script:SharePointAdminUrl) { [string]$script:SharePointAdminUrl } else { '' }
        $parts = Get-PurviewRemediationPart -Prerequisite $prereq -TenantName $tenantName `
            -TenantId $tenantId -GeneratedAt $generated -AdminUrl $adminUrl
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($parts | ConvertTo-Json -Depth 10 -Compress)))
        $null = $builder.AppendLine("<script>(function(){var P=JSON.parse(decodeURIComponent(escape(atob('$encoded'))));var picks=function(){return Array.prototype.slice.call(document.querySelectorAll('.rem-pick'));};var count=function(){var n=picks().filter(function(c){return c.checked;}).length;document.getElementById('rem-count').textContent=n+' selected';};picks().forEach(function(c){c.addEventListener('change',count);});document.getElementById('rem-all').addEventListener('click',function(){picks().forEach(function(c){c.checked=true;});count();});document.getElementById('rem-none').addEventListener('click',function(){picks().forEach(function(c){c.checked=false;});count();});document.getElementById('rem-get').addEventListener('click',function(){var names=picks().filter(function(c){return c.checked;}).map(function(c){return c.getAttribute('data-name');});var chosen=P.items.filter(function(i){return names.indexOf(i.name)>=0;});var t=P.header.replace('{COUNT}',chosen.length);if(chosen.length===0){t+='\r\nWrite-Host \'Nothing selected to remediate.\'\r\n';}else{Object.keys(P.connect).forEach(function(s){if(chosen.some(function(i){return i.session.indexOf(s)>=0;})){t+='\r\n'+P.connect[s];}});chosen.forEach(function(i){t+='\r\n'+i.block;});}t+='\r\n'+P.footer;var u=URL.createObjectURL(new Blob([t],{type:'text/plain'}));var l=document.createElement('a');l.href=u;l.download=(chosen.length===1&&chosen[0].file)?chosen[0].file:'Set-PurviewTenantOptIns.ps1';l.click();URL.revokeObjectURL(u);});count();})();</script>")
    }

    $null = $builder.AppendLine('<h2>Copilot and AI Controls</h2>')
    $copilot = @(Get-PurviewCopilotControl -Snapshot $Snapshot -Finding $Finding)

    $intro = 'Selected Purview configuration and historical signals relevant to Microsoft 365 Copilot. Effective access also depends on permissions, item rights, scope and supported scenarios; these checks do not test every interaction or control.'
    # Only promise the second group when there is one, or the sentence points at nothing.
    if (@($copilot | Where-Object { $_.Band -ne 'Copilot' }).Count -gt 0) {
        $intro += ' Copilot-specific rows come first, followed by broader AI policy candidates whose supported scope must be verified separately.'
    }
    $null = $builder.AppendLine("<p class=""dim"">$intro</p>")

    # The table states each control, but a reader scanning the section should not have to assemble
    # the conclusion from it.
    $copilotGaps = @($copilot | Where-Object { $_.State -eq 'Needs attention' })
    if ($copilotGaps.Count -gt 0) {
        $names = ($copilotGaps | ForEach-Object { Enc $_.Control }) -join ', '
        $null = $builder.AppendLine("<p class=""fail""><strong>Needs attention: $names.</strong></p>")
    }

    $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Copilot and AI Controls" tabindex="0"><table class="copilot-table"><thead><tr><th scope="col">State</th><th scope="col">Control</th><th scope="col">Why it matters</th></tr></thead><tbody>')
    $band = ''
    foreach ($row in $copilot) {
        if ($row.Band -ne $band) {
            $band = [string]$row.Band
            $label = if ($band -eq 'Copilot') { 'Microsoft 365 Copilot' } else { $band }
            $null = $builder.AppendLine("<tr><td colspan=""3"" class=""dim""><strong>$(Enc $label)</strong></td></tr>")
        }
        $class = switch ($row.State) { 'As recommended' { 'pass' } 'Needs attention' { 'fail' } 'Needs review' { 'warn' } 'In use' { 'pass' } default { 'dim' } }
        $name = if ($row.Url) { "<a href=""$(Enc $row.Url)"">$(Enc $row.Control)</a>" } else { Enc $row.Control }
        $null = $builder.AppendLine("<tr><td class=""$class""><strong>$(Enc $row.State)</strong></td><td>$name<br><span class=""dim"">$(Enc $row.Detail)</span></td><td>$(Enc $row.Why)</td></tr>")
    }
    $null = $builder.AppendLine('</tbody></table></div>')

    $null = $builder.AppendLine('<h2>Label Taxonomy Comparison</h2>')
    $taxonomyRows = @(Get-PurviewTaxonomyComparison -Snapshot $Snapshot)
    $null = $builder.AppendLine('<p class="dim">Child labels appear beneath their group or parent, with the full path. "Same name" means a match to the reference tier, not a duplicate-label warning.</p>')
    $null = $builder.AppendLine('<style>.taxonomy-child{display:block;padding-left:1.25rem;}</style>')
    $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Label Taxonomy Comparison" tabindex="0"><table class="taxonomy-table"><thead><tr><th scope="col">Label, group or reference tier</th><th scope="col">Type</th><th scope="col">In this tenant</th><th scope="col">Note</th></tr></thead><tbody>')
    foreach ($row in $taxonomyRows) {
        $name = Enc $row.Tier
        if ((Get-PurviewProperty -InputObject $row -Name 'Depth') -eq 1) { $name = '<span class="taxonomy-child">{0}</span>' -f $name }
        elseif ($row.Type -eq 'Label group') { $name = '<strong>{0}</strong>' -f $name }
        Add-Row @($name, (Enc $row.Type), (Enc $row.Match), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table></div>')
    $null = $builder.AppendLine('<p class="dim">Label groups organize labels; groups themselves cannot be published or applied to content. The documented default taxonomy is compared by name against top-level labels and groups. Organisations classify to their own risk model, so a reference tier with no counterpart is a design decision to confirm rather than a gap to close.</p>')
    if (@($taxonomyRows | Where-Object { $_.Type -eq 'Not recorded' }).Count -gt 0) {
        $null = $builder.AppendLine('<p class="dim">Type not recorded means the source did not identify a label or label group. Type is not inferred from its name or hierarchy; older snapshots may lack this field.</p>')
    }

    $checklist = @(Get-PurviewChecklist -Finding $Finding)
    $progress = Get-PurviewChecklistProgress -Checklist $checklist

    $null = $builder.AppendLine('<h2>Remediation Checklist</h2>')
    if ($null -ne $progress.Percent) {
        $null = $builder.AppendLine("<p><strong>$($progress.Done) of $($progress.Judged) done</strong> ($($progress.Percent)%). $($progress.ToDo) to do, $($progress.ToCheck) to check by hand.</p>")
    }

    foreach ($group in 'To do', 'To check by hand', 'Done', 'Not available - licensing', 'Not checked') {
        $rows = @($checklist | Where-Object { $_.Group -eq $group })
        if ($rows.Count -eq 0) { continue }

        $null = $builder.AppendLine("<h3>$(Enc $group) ($($rows.Count))</h3>")
        $null = $builder.AppendLine("<div class=""table-scroll"" role=""region"" aria-label=""Remediation checklist: $(Enc $group)"" tabindex=""0""><table><thead><tr><th scope=""col"" class=""mark"">State</th><th scope=""col"" class=""wide"">Check</th><th scope=""col"" class=""tight"">Licence</th><th scope=""col"" class=""tight"">Purview solution</th><th scope=""col"" class=""tight"">Severity</th><th scope=""col"">What it takes</th></tr></thead><tbody>")
        foreach ($row in $rows) {
            $action = Enc $row.Action
            if ($row.Command) { $action += "<br><code>$(Enc $row.Command)</code>" }
            $null = $builder.AppendLine("<tr><td class=""mark""><span aria-hidden=""true"">[$(Enc $row.Marker)]</span><span class=""sr-only"">$(Enc $row.Group)</span></td><td>$(& $link $row.RuleId) $(Enc $row.Title)</td><td>$(Enc $row.Tier)</td><td>$(Enc $row.Solution)</td><td>$(Enc $row.Severity)</td><td>$action</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table></div>')
    }
    $null = $builder.AppendLine('<p class="dim">Ordered for working top down: highest severity first, and within that the licence tier the organisation is most likely to already hold. Progress counts only checks that returned a verdict, so items that could not be checked do not inflate it.</p>')

    $null = $builder.AppendLine('<h2>Purview Solution Coverage Matrix</h2>')
    $null = $builder.AppendLine('<p class="dim">Every area this run read, and what became of it: judged by a check, reported in one of the tables above, or collected only as context. Use it to trace any verdict in this report back to the data behind it, and to see which areas were read but not judged.</p>')
    $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Purview Solution Coverage Matrix" tabindex="0"><table><thead><tr><th scope="col">Collector</th><th scope="col">Solution area</th><th scope="col">Data read</th><th scope="col">Rules</th><th scope="col">Assessment</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewCoverageMatrix -Snapshot $Snapshot -Finding $Finding)) {
        Add-Row @((Enc $row.Collector), (Enc $row.SolutionArea), (Enc $row.Collection), $row.Rules, (Enc $row.Assessment))
    }
    $null = $builder.AppendLine('</tbody></table></div>')

    $null = $builder.AppendLine('<h2>Blueprint Coverage</h2>')
    $null = $builder.AppendLine('<p class="dim">This tenant measured against Microsoft''s published Purview deployment blueprints, each heading linking to the guide it scores against. Only steps with a corresponding check are listed. This reports current configuration, not progress through a deployment programme.</p>')
    foreach ($model in (Get-PurviewDeploymentMaturity -Finding $Finding)) {
        $steps = @($model.Steps | Where-Object { $_.State -ne 'NoChecks' })
        if ($steps.Count -eq 0) { continue }

        # The heading names a published Microsoft guide, so it links to it rather than leaving the
        # reader to search for a title they can see but not follow.
        $heading = if ($model.Url) { "<a href=""$(Enc $model.Url)"">$(Enc $model.Name)</a>" } else { Enc $model.Name }
        $null = $builder.AppendLine("<h3>$heading</h3>")
        $null = $builder.AppendLine("<div class=""table-scroll"" role=""region"" aria-label=""Blueprint coverage: $(Enc $model.Name)"" tabindex=""0""><table><thead><tr><th scope=""col"">Step</th><th scope=""col"">What it covers</th><th scope=""col"">State</th></tr></thead><tbody>")
        foreach ($step in $steps) {
            $class = switch ($step.State) { 'ChecksPass' { 'pass' } 'ChecksFail' { 'fail' } 'Partial' { 'warn' } 'ChecksWarn' { 'warn' } default { 'dim' } }
            $title = if ($step.Title) { $step.Title } else { 'Not covered by this assessment' }
            $covers = Enc $title
            $ids = @(@($step.RuleIds) | ForEach-Object { & $link $_ }) -join ', '
            if ($ids) { $covers += "<br><span class=""dim"">Scored from $ids</span>" }
            $null = $builder.AppendLine("<tr><td>$($step.Step)</td><td>$covers</td><td class=""$class"">$(Enc $step.Verdict)</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table></div>')
    }

    $null = $builder.AppendLine('<h2>Findings by Severity</h2>')
    foreach ($item in ($Finding | Where-Object { $_.status -in 'Fail', 'Warning', 'NeedsReview' } |
            Sort-Object @{ Expression = { Get-PurviewSeverityOrder -Severity ([string](Get-PurviewProperty -InputObject $_ -Name 'severity')) } }, ruleId)) {
        $class = switch ($item.status) { 'Fail' { 'fail' } 'Pass' { 'pass' } default { 'warn' } }
        $null = $builder.AppendLine("<h3 id=""$(Enc $item.ruleId)""><span class=""$class"">$(Enc (Get-PurviewStatusLabel -Status $item.status))</span> $(Enc $item.ruleId) &mdash; $(Enc $item.title)</h3>")
        $null = $builder.AppendLine("<p class=""dim"">Severity $(Enc $item.severity) &middot; confidence $(Enc $item.confidence) &middot; $(Enc $item.zeroTrust)</p>")
        $null = $builder.AppendLine("<p><strong>What we found.</strong> $(Enc $item.reason)</p>")

        $observed = @(Get-PurviewProperty -InputObject $item -Name 'observed')
        if ($observed.Count -gt 0) {
            $null = $builder.AppendLine('<ul>')
            foreach ($line in $observed) { $null = $builder.AppendLine("<li>$(Enc $line)</li>") }
            $null = $builder.AppendLine('</ul>')
        }

        $null = $builder.AppendLine("<p><strong>Why it matters.</strong> $(Enc (Get-PurviewProperty -InputObject $item -Name 'rationale'))</p>")
        $null = $builder.AppendLine("<p><strong>What to do.</strong> $(Enc $item.recommendation)</p>")

        if ($item.PSObject.Properties['remediationCommand']) {
            $null = $builder.AppendLine("<p>Review the impact, then run this yourself: <code>$(Enc $item.remediationCommand)</code></p>")
        }

        $links = @()
        foreach ($id in @($item.evidence)) {
            if ($script:Evidence.ContainsKey($id)) {
                $links += ('<a href="{0}">{1}</a>' -f (Enc $script:Evidence[$id].Url), (Enc $script:Evidence[$id].Title))
            }
        }
        if ($links.Count -gt 0) {
            $null = $builder.AppendLine("<p class=""dim"">Read more: $($links -join ' &middot; ')</p>")
        }
    }

    $healthy = @($Finding | Where-Object { $_.status -in 'Pass', 'NotCollected', 'NotLicensed' })
    if ($healthy.Count -gt 0) {
        $null = $builder.AppendLine('<h3>Everything else</h3>')
        $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Other findings" tabindex="0"><table><thead><tr><th scope="col">Rule</th><th scope="col">Title</th><th scope="col">Status</th><th scope="col">What we found</th></tr></thead><tbody>')
        foreach ($item in ($healthy | Sort-Object status, ruleId)) {
            $class = if ($item.status -eq 'Pass') { 'pass' } elseif ($item.status -eq 'NotLicensed') { 'info' } else { 'dim' }
            $null = $builder.AppendLine("<tr><td id=""$(Enc $item.ruleId)"">$(Enc $item.ruleId)</td><td>$(Enc $item.title)</td><td class=""$class"">$(Enc (Get-PurviewStatusLabel -Status $item.status))</td><td>$(Enc $item.reason)</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table></div>')
    }

    } # end of detail sections

    $null = $builder.AppendLine('<h2>Recommended next actions</h2>')
    $null = $builder.AppendLine('<p class="dim">Up to five planning actions supported by complete configuration reads: audit visibility, label foundations, then policy rollout. This is a suggested working order, not a risk or effort score. Expected impact is a planning estimate; confirm applicability, licensing and scope before approving any change.</p>')
    $nextActions = @(Get-PurviewRecommendedAction -Snapshot $Snapshot -Finding $Finding)
    if ($nextActions.Count -eq 0) {
        $null = $builder.AppendLine('<p class="dim">No supported action met the evidence requirements for this shortlist. This does not mean the tenant has no gaps; review the other findings and unresolved checks.</p>')
    }
    else {
        $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Recommended next actions" tabindex="0"><table><thead><tr><th scope="col">Action</th><th scope="col">Why now / benefit</th><th scope="col">Expected user impact</th><th scope="col">Preparation</th></tr></thead><tbody>')
        foreach ($row in $nextActions) {
            # Brief omits finding anchors. Keep the ID as text there, with public guidance in both.
            $reference = if ($Brief) { Enc $row.RuleId } else { '<a href="#{0}">{0}</a>' -f (Enc $row.RuleId) }
            $action = '<strong>{0}</strong><br>{1} &middot; <a href="{2}">Guidance</a>' -f (Enc $row.Action), $reference, (Enc $row.Url)
            $benefit = '{0}<br><span class="dim">{1}</span>' -f (Enc $row.Reason), (Enc $row.Benefit)
            Add-Row @($action, $benefit, (Enc $row.Impact), (Enc $row.Preparation))
        }
        $null = $builder.AppendLine('</tbody></table></div>')
    }

    $null = $builder.AppendLine('<h2>Strategic Improvements</h2>')
    $null = $builder.AppendLine('<p class="dim">Other findings to plan or review, grouped by severity. Inclusion here does not establish rollout readiness.</p>')
    $shortlistedIds = @($nextActions | ForEach-Object { $_.RuleId })
    $planned = @($Finding | Where-Object { $_.status -in 'Fail', 'Warning' -and $_.ruleId -notin $shortlistedIds })
    $higher = @($planned | Where-Object { $_.severity -in 'Critical', 'High' })
    $lower = @($planned | Where-Object { $_.severity -in 'Medium', 'Low' })
    $null = $builder.AppendLine('<h3>Critical and high severity</h3><ul>')
    if ($higher.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">No findings in this category.</li>') }
    foreach ($item in $higher) {
        $command = [string](Get-PurviewProperty -InputObject $item -Name 'remediationCommand')
        $detail = "$(Enc $item.title) - $(Enc $item.recommendation)"
        if ($command) { $detail += "<br><code>$(Enc $command)</code>" }
        $null = $builder.AppendLine("<li>$detail</li>")
    }
    $null = $builder.AppendLine('</ul><h3>Medium and low severity</h3><ul>')
    if ($lower.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">No findings in this category.</li>') }
    foreach ($item in $lower) {
        $command = [string](Get-PurviewProperty -InputObject $item -Name 'remediationCommand')
        $detail = "$(Enc $item.title) - $(Enc $item.recommendation)"
        if ($command) { $detail += "<br><code>$(Enc $command)</code>" }
        $null = $builder.AppendLine("<li>$detail</li>")
    }
    $null = $builder.AppendLine('</ul>')

    $toVerify = @($Finding | Where-Object { $_.status -eq 'NeedsReview' })
    if ($toVerify.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Checks to Verify</h2>')
        $null = $builder.AppendLine('<p class="dim">These results need evidence or human confirmation. They are not configuration changes to make.</p><ul>')
        foreach ($item in $toVerify) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
        $null = $builder.AppendLine('</ul>')
    }

    $null = $builder.AppendLine('<h2>Licensing and SKU Analysis</h2>')
    $null = $builder.AppendLine('<p class="dim">Recognized Purview-related subscriptions, excluding deleted records. Other products remain in Technical details; this is not a complete license catalog. Licensing does not limit configuration checks or confirm individual feature rights.</p>')
    $licensingRows = @(Get-PurviewLicensingAnalysis -Snapshot $Snapshot -Finding $Finding)
    $allSubscriptions = @($licensingRows | Where-Object { Get-PurviewProperty -InputObject $_ -Name 'IsSubscription' })
    $subscriptions = @($allSubscriptions | Where-Object { Get-PurviewProperty -InputObject $_ -Name 'ShowInSummary' })
    # Collection warnings stay above the table, never behind a disclosure or counted as products.
    foreach ($row in @($licensingRows | Where-Object { -not (Get-PurviewProperty -InputObject $_ -Name 'IsSubscription') })) {
        $null = $builder.AppendLine("<p><strong>$(Enc $row.State).</strong> $(Enc $row.Detail)</p>")
    }
    if (@($allSubscriptions | Where-Object { -not $_.ShowInSummary -and $_.State -ine 'Deleted' -and $_.Note }).Count -gt 0) {
        $null = $builder.AppendLine('<p class="warn">Some other subscription records have identity or duplicate-record warnings. Review Technical details.</p>')
    }
    if ($allSubscriptions.Count -gt 0) {
        $null = $builder.AppendLine('<style>.licensing-table{table-layout:fixed;}.licensing-table th:first-child{width:46%;}.licensing-table td{overflow-wrap:anywhere;}.licensing-table .seats{text-align:right;font-variant-numeric:tabular-nums;}.licensing-technical summary{cursor:pointer;margin-bottom:.75rem;}.licensing-technical td{overflow-wrap:anywhere;}@media print{.licensing-technical{display:none;}}</style>')
    }
    if ($subscriptions.Count -gt 0) {
        $null = $builder.AppendLine('<div class="table-scroll" role="region" aria-label="Licensing and SKU Analysis" tabindex="0"><table class="licensing-table"><thead><tr><th scope="col">Subscription</th><th scope="col">Status</th><th scope="col" class="seats">Enabled seats</th><th scope="col" class="seats">Assigned seats</th></tr></thead><tbody>')
        foreach ($row in $subscriptions) {
            $name = Enc $row.Sku
            if ($row.Note) { $name += "<br><span class=""warn"">$(Enc $row.Note)</span>" }
            $enabled = if ($null -ne $row.EnabledSeats) { Enc $row.EnabledSeats } else { '<span class="dim">Unknown</span>' }
            $assigned = if ($null -ne $row.AssignedSeats) { Enc $row.AssignedSeats } else { '<span class="dim">Unknown</span>' }
            $null = $builder.AppendLine("<tr><td>$name</td><td>$(Enc $row.State)</td><td class=""seats"">$enabled</td><td class=""seats"">$assigned</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table></div>')
        if (@($subscriptions | Where-Object { $null -eq $_.EnabledSeats -or $null -eq $_.AssignedSeats }).Count -gt 0) {
            $null = $builder.AppendLine('<p class="dim">Unknown means the seat count was missing or invalid, not zero.</p>')
        }
    }
    elseif ($allSubscriptions.Count -gt 0) {
        $null = $builder.AppendLine('<p class="dim">No returned subscription matched this summary. This does not establish that Purview licensing is absent.</p>')
    }
    if ($allSubscriptions.Count -gt 0) {
        # Native disclosure works without JavaScript. Print keeps the concise summary and warnings;
        # the HTML and snapshot retain the diagnostics for follow-up.
        $null = $builder.AppendLine('<details class="licensing-technical"><summary>Technical details</summary><p class="dim">All returned records, including deleted and unrecognized products. Retained service-plan fields are in snapshot.json under licensing.subscribedSkus[].servicePlans. Technical details are omitted from print.</p><div class="table-scroll" role="region" aria-label="Subscription technical details" tabindex="0"><table><thead><tr><th scope="col">Subscription</th><th scope="col">Status</th><th scope="col">Observed details</th></tr></thead><tbody>')
        foreach ($row in $allSubscriptions) { Add-Row @((Enc $row.Sku), (Enc $row.State), (Enc $row.Detail)) }
        $null = $builder.AppendLine('</tbody></table></div></details>')
    }

    $null = $builder.AppendLine('<h2>Limitations of This Assessment</h2>')
    $null = $builder.AppendLine('<p class="dim">What this run could not establish, and the qualifiers required to interpret the findings above. These describe the assessment, not the tenant.</p><ul>')
    foreach ($risk in (Get-PurviewOpenRisk -Finding $Finding -Snapshot $Snapshot)) { $null = $builder.AppendLine("<li>$(Enc $risk)</li>") }
    $null = $builder.AppendLine('</ul>')

    $null = $builder.AppendLine('<p class="dim">Built-in checks reference Microsoft guidance where cited; externally supplied rules can use other sources. Review each claim and its applicability. This script is not a Microsoft product or a compliance certification; it reports selected configuration and historical evidence from this run.</p>')
    $null = $builder.AppendLine('</main></body></html>')

    return $builder.ToString()
}

#endregion

#region Sample data
# Fabricated fixture used by -Demo and offline checks. It does not test live collection behaviour.

function Get-PurviewDemoSnapshot {
    <# .SYNOPSIS Fabricated snapshot for trying the script without a tenant. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $demoNow = Get-PurviewTimestamp
    $stamp = Format-PurviewTimestamp -Timestamp $demoNow
    $activityEnd = $demoNow.AddMinutes(-1)
    $activityStart = $demoNow.AddDays(-30).AddMinutes(1)
    $analyticsPolicyName = 'RiskSpotlighting-{0}' -f $demoNow.AddDays(-7).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    # This is the documented AdvancedRule condition shape. Adjacent conditions deliberately carry
    # other name fields so the sample also proves that only sensitivetypes are reported as SITs.
    $activeAutoLabelAdvanced = @'
{
    "Condition": {
        "Operator": "And",
        "SubConditions": [
            {
                "ConditionName": "ContentContainsSensitiveInformation",
                "Value": {
                    "operator": "And",
                    "groups": [
                        {
                            "name": "Default",
                            "operator": "Or",
                            "sensitivetypes": [
                                { "name": "Credit Card Number", "mincount": 1 },
                                { "name": "ABA Routing Number", "mincount": 1 }
                            ]
                        }
                    ]
                }
            },
            {
                "ConditionName": "ContentContainsSensitivityLabel",
                "Value": { "labels": [ { "name": "Confidential" } ] }
            }
        ]
    }
}
'@

    return [pscustomobject]@{
        snapshotVersion = '1.0'
        toolVersion = $script:ToolVersion
        capturedAt = $stamp
        mode = 'SyntheticSample'
        tenant = [pscustomobject]@{ displayName = 'Contoso Sample (fabricated)'; tenantId = ''; redacted = $true }
        licensing = [pscustomobject]@{
            collected = $true
            complete = $true
            subscribedSkus = @([pscustomobject]@{ skuPartNumber = 'SPE_E5'; skuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; capabilityStatus = 'Enabled'; servicePlans = @(); prepaidUnitsEnabled = 120; consumedUnits = 112 })
        }
        collectorResults = @(
            [pscustomobject]@{
                collector = 'SensitivityLabel'; solutionArea = 'SensitivityLabels'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-Label'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Labels = @(
                        [pscustomobject]@{ Guid = '5ac7e1b5-fa4f-4df6-8f4a-02731221d47c'; Name = 'Public'; UniqueName = '5ac7e1b5-fa4f-4df6-8f4a-02731221d47c'; ParentId = $null; Priority = 0; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = '8c629e92-39dc-4f78-baf3-e31522b06dc9'; Name = 'General'; UniqueName = '8c629e92-39dc-4f78-baf3-e31522b06dc9'; ParentId = $null; Priority = 1; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = '1854dd97-5860-4af7-87e0-46e2d729e822'; Name = 'General \ Anyone (unrestricted)'; UniqueName = '1854dd97-5860-4af7-87e0-46e2d729e822'; ParentId = '8c629e92-39dc-4f78-baf3-e31522b06dc9'; Priority = 2; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = '76ca4345-a8dc-490b-a9a0-4c33ff409610'; Name = 'Confidential'; UniqueName = '76ca4345-a8dc-490b-a9a0-4c33ff409610'; ParentId = $null; Priority = 3; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = '467e3282-5c01-4284-8791-0d2902ab4f60'; Name = 'Confidential \ All Employees'; UniqueName = '467e3282-5c01-4284-8791-0d2902ab4f60'; ParentId = '76ca4345-a8dc-490b-a9a0-4c33ff409610'; Priority = 4; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EXTRACT, EDIT, PRINT' }
                        # Encryption on a label that has sublabels is what a label group cannot hold,
                        # so this one stands for a taxonomy still on the older scheme.
                        [pscustomobject]@{ Guid = '46a0e922-db10-4480-a8ba-310a12e86296'; Name = 'Highly Confidential'; UniqueName = '46a0e922-db10-4480-a8ba-310a12e86296'; ParentId = $null; Priority = 5; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EDIT' }
                        [pscustomobject]@{ Guid = '37e88e8a-6806-4936-85e4-77eeae1e27be'; Name = 'Highly Confidential \ Specific People'; UniqueName = '37e88e8a-6806-4936-85e4-77eeae1e27be'; ParentId = '46a0e922-db10-4480-a8ba-310a12e86296'; Priority = 6; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EDIT' }
                        [pscustomobject]@{ Guid = 'dca36009-c6fa-49ae-b4f5-1c42fabdcfea'; Name = 'Board Material'; UniqueName = 'dca36009-c6fa-49ae-b4f5-1c42fabdcfea'; ParentId = $null; Priority = 7; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'SensitivityLabelPolicy'; solutionArea = 'LabelPolicies'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-LabelPolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        [pscustomobject]@{ Guid = '8caa6f37-6b12-4cbf-b9bd-ea002c24508d'; Name = 'All staff'; Enabled = $true; Labels = @('Public', 'General', 'Confidential'); UserScope = @('All'); GroupScope = @('All') }
                        [pscustomobject]@{ Guid = '156b7918-c1cd-48a9-b23c-b1529a661693'; Name = 'Legal and finance'; Enabled = $true; Labels = @('Confidential'); UserScope = @('legal@contoso.example', 'finance@contoso.example'); GroupScope = @() }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AutoLabeling'; solutionArea = 'AutoLabeling'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-AutoSensitivityLabelPolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        [pscustomobject]@{ Guid = '83fa11e7-9d85-426a-b6b1-047e7ec295ef'; Name = 'Financial records'; Mode = 'Enable'; Enabled = $true }
                        [pscustomobject]@{ Guid = 'e35570ec-5444-4d28-9d52-07f7aa15b40b'; Name = 'Customer records'; Mode = 'TestWithoutNotifications'; Enabled = $true }
                        [pscustomobject]@{ Guid = 'c9f97d35-6319-4c86-b1d8-b4cc8e44b1f0'; Name = 'Legacy records'; Mode = 'Disable'; Enabled = $false }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AutoLabelingRule'; solutionArea = 'AutoLabeling'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-AutoSensitivityLabelRule'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Rules = @(
                        # The empty direct field and populated advanced field reproduce the service
                        # shape that was previously masked during normalisation.
                        [pscustomobject]@{
                            Guid = '2a113e2f-8a4e-4cc3-9b75-1a40542108e8'; Name = 'Financial records rule'
                            PolicyName = ''; Policy = 'Financial records'; Disabled = $false
                            DirectSensitiveTypes = $null; AdvancedRule = $activeAutoLabelAdvanced
                            DirectSensitiveTypesReturned = $true; AdvancedRuleReturned = $true
                            ConditionKinds = @()
                        }
                        # Conditions on simulation and disabled policies are retained in the
                        # snapshot but excluded from the active-policy total.
                        [pscustomobject]@{
                            Guid = 'b52d5faf-3cdc-458f-b87b-49c6b69f5b47'; Name = 'Customer records rule'
                            PolicyName = 'Customer records'; Policy = ''; Disabled = $false
                            DirectSensitiveTypes = @([pscustomobject]@{ name = 'U.S. Social Security Number (SSN)'; mincount = 1 })
                            AdvancedRule = $null
                            DirectSensitiveTypesReturned = $true; AdvancedRuleReturned = $true
                            ConditionKinds = @()
                        }
                        [pscustomobject]@{
                            Guid = '636357f0-4049-4b34-b6be-87b71c89d6cb'; Name = 'Legacy records rule'
                            PolicyName = 'Legacy records'; Policy = ''; Disabled = $false
                            DirectSensitiveTypes = @([pscustomobject]@{ name = 'International Banking Account Number (IBAN)'; mincount = 1 })
                            AdvancedRule = $null
                            DirectSensitiveTypesReturned = $true; AdvancedRuleReturned = $true
                            ConditionKinds = @()
                        }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'SharePointLabelingReadiness'; solutionArea = 'SensitivityLabels'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-SPOTenant'; kind = 'SharePointOnlinePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Settings = @(
                        [pscustomobject]@{ Name = 'EnableAIPIntegration'; Enabled = $false; Value = 'False'; Expected = 'True'; AsRecommended = $false; Capability = 'Labels processed for Office files in SharePoint and OneDrive' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelforPDF'; Enabled = $true; Value = 'True'; Expected = 'True'; AsRecommended = $true; Capability = 'Labels on PDF files' }
                        [pscustomobject]@{ Name = 'BlockSendLabelMismatchEmail'; Enabled = $true; Value = 'True'; Expected = 'False'; AsRecommended = $false; Capability = 'Label mismatch email to uploader and site owners' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelforOneNote'; Enabled = $true; Value = 'True'; Expected = 'True'; AsRecommended = $true; Capability = 'Labels on OneNote sections' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelForVideoFiles'; Enabled = $false; Value = 'False'; Expected = 'True'; AsRecommended = $false; Capability = 'Labels on MP4 video files' }
                        [pscustomobject]@{ Name = 'DisableDocumentLibraryDefaultLabeling'; Enabled = $false; Value = 'False'; Expected = 'False'; AsRecommended = $true; Capability = 'Default labels on document libraries' }
                        [pscustomobject]@{ Name = 'MarkNewFilesSensitiveByDefault'; Enabled = $false; Value = 'AllowExternalSharing'; Expected = 'BlockExternalSharing'; AsRecommended = $false; Capability = 'Sensitive by default for new files' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'TenantPolicyConfig'; solutionArea = 'DataLossPrevention'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-PolicyConfig'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Settings = @(
                        [pscustomobject]@{ Name = 'EnableLabelCoauth'; Value = 'True' }
                        [pscustomobject]@{ Name = 'ExtendTeamsDlpToSpoOdbConsent'; Value = 'False' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'ContainerLabel'; solutionArea = 'SensitivityLabels'; status = 'Success'
                source = [pscustomobject]@{ interface = 'GET /groupSettings'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Settings = @(
                        [pscustomobject]@{ Name = 'EnableMIPLabels'; Enabled = $true; Value = 'True'; Expected = 'True'; AsRecommended = $true; Capability = 'Sensitivity labels on Microsoft 365 groups, Teams and SharePoint sites' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'DataLossPrevention'; solutionArea = 'DataLossPrevention'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-DlpCompliancePolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        [pscustomobject]@{ Guid = '7afb0f5d-8911-4394-a054-be38f821cd27'; Name = 'Financial data'; Mode = 'Enable'; Workload = 'Exchange, SharePoint, OneDriveForBusiness'; ExchangeLocation = @('All'); SharePointLocation = @('All') }
                        [pscustomobject]@{ Guid = 'e0777239-3dbc-4876-8bed-73b44a4226f1'; Name = 'Pilot'; Mode = 'TestWithoutNotifications'; Workload = 'EndpointDevices'; EndpointDlpLocation = @('All') }
                        # Exercises the analytics name indicator, not proof that analytics ran.
                        [pscustomobject]@{ Guid = '3b05363a-72f8-4bbd-8a43-7e91a61c7cbd'; Name = $analyticsPolicyName; Mode = 'TestWithoutNotifications'; Workload = 'Exchange'; ExchangeLocation = @('All') }
                        # The documented name of the Copilot policy posture management creates in one click.
                        [pscustomobject]@{ Guid = '4b05e218-69f4-461f-9567-5458ca3882c4'; Name = 'DSPM for AI - Protect sensitive data from Copilot processing'; Mode = 'Enable'; Workload = 'M365Copilot' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AppRetentionPolicy'; solutionArea = 'DataLifecycleManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-AppRetentionCompliancePolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        # The service returns the documented Copilot experiences as one
                        # comma-delimited value, which the analyzer normalizes before exact matching.
                        [pscustomobject]@{ Guid = '269f0ff6-79f5-452e-96bf-980a532a80c4'; Name = 'Copilot interactions'; Enabled = $true; Applications = 'User:M365Copilot,CopilotForSecurity,CopilotinFabricPowerBI,CopilotStudio,CopilotinBusinessApplicationplatformsSales,SQLCopilot' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AppRetentionRule'; solutionArea = 'DataLifecycleManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-AppRetentionComplianceRule'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Rules = @(
                        [pscustomobject]@{ Guid = '187879b2-bf52-429b-967b-3580c45eb853'; Name = 'Copilot interactions rule'; Policy = 'Copilot interactions' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                # A complete empty result proves that no older combined Teams policy remains.
                collector = 'ClassicTeamsRetentionPolicy'; solutionArea = 'DataLifecycleManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-RetentionCompliancePolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Policies = @() }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'EndpointDeviceHealth'; solutionArea = 'EndpointDlp'; status = 'Success'
                source = [pscustomobject]@{ interface = 'POST /security/runHuntingQuery'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Devices = @([pscustomobject]@{
                            Reporting = 13; DefenderOnboarded = 13; DlpEnabled = 13; ConfigurationValid = 9
                            RealTimeProtectionOff = 2; BehaviorMonitoringOff = 1
                            BandwidthExceeded = 0; InvalidUser = 4
                        })
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'InsiderRiskSharing'; solutionArea = 'InsiderRisk'; status = 'Success'
                source = [pscustomobject]@{ interface = 'POST /security/runHuntingQuery'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Behaviors = @([pscustomobject]@{ Count = 42 }) }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'CloudAppConnector'; solutionArea = 'PostureValidation'; status = 'Success'
                source = [pscustomobject]@{ interface = 'POST /security/runHuntingQuery'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Connectors = @([pscustomobject]@{ Events = 1543; Apps = 5; ConnectorEvents = 1543 }) }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'DataSecurityTelemetry'; solutionArea = 'PostureValidation'; status = 'Success'
                source = [pscustomobject]@{ interface = 'POST /security/runHuntingQuery'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Signals = @([pscustomobject]@{
                            Events = 318; DlpMatches = 274; CcMatches = 0; IrmMatches = 61; Blocking = 33; Labelled = 4
                        })
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'ProtectedFilesConsent'; solutionArea = 'PostureValidation'; status = 'Success'
                source = [pscustomobject]@{ interface = 'GET /servicePrincipals'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Grants = @([pscustomobject]@{ Count = 1 }) }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'SentinelPurviewIntegration'; solutionArea = 'PostureValidation'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Azure Resource Manager GET'; kind = 'AzurePowerShell'; documentationUrl = $script:DocUrl.SentinelPurview }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    EvidenceScope = 'Microsoft365Purview'
                    TenantId = '11111111-1111-1111-1111-111111111111'
                    LookbackDays = 30
                    SentinelWorkspaces = @('/subscriptions/demo/resourceGroups/security/providers/Microsoft.OperationalInsights/workspaces/sentinel')
                    SentinelDiscoveryComplete = $true
                    Results = @(
                        [pscustomobject]@{
                            SentinelWorkspaceResourceId = '/subscriptions/demo/resourceGroups/security/providers/Microsoft.OperationalInsights/workspaces/sentinel'
                            SentinelOnboarded = $true
                            ConnectorRead = 'Success'
                            Connectors = @([pscustomobject]@{ Kind = 'Office365'; State = 'Enabled'; SourceTenantId = '11111111-1111-1111-1111-111111111111' })
                            Sources = @(
                                [pscustomobject]@{
                                    Name = 'Microsoft 365 audit'; Table = 'OfficeActivity'; Scope = 'Microsoft365Tenant'
                                    SourceTenantId = '11111111-1111-1111-1111-111111111111'; QueryState = 'Success'
                                    EventCount = 318; LastEventUtc = $stamp; LabelEventCount = 4; DlpEventCount = 0
                                }
                                [pscustomobject]@{
                                    Name = 'Information Protection'; Table = 'MicrosoftPurviewInformationProtection'; Scope = 'Microsoft365Tenant'
                                    SourceTenantId = '11111111-1111-1111-1111-111111111111'; QueryState = 'Success'
                                    EventCount = 0; LastEventUtc = $null; LabelEventCount = 0
                                }
                                [pscustomobject]@{
                                    Name = 'Insider Risk alerts'; Table = 'SecurityAlert'; Scope = 'Workspace'
                                    SourceTenantId = $null; QueryState = 'Success'; EventCount = 0; LastEventUtc = $null
                                }
                            )
                        }
                    )
                    Limitations = @()
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'DlpRule'; solutionArea = 'DataLossPrevention'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-DlpComplianceRule'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Rules = @(
                        [pscustomobject]@{ Guid = '1f50b06b-6b3f-411f-a02c-fcd6dbe3e097'; Name = 'Credit card numbers'; Policy = 'Financial data'; Disabled = $false; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = '48fada42-9e98-471e-a5e0-a997b806c9df'; Name = 'Bank account numbers'; Policy = 'Financial data'; Disabled = $false; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = '0cc7b946-a03e-48c5-bc55-5fa0cf00934b'; Name = 'Passport numbers'; Policy = 'Pilot'; Disabled = $true; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = '64c916e7-d056-4792-9a1e-ba2411020bb7'; Name = 'Copilot processing'; Policy = 'DSPM for AI - Protect sensitive data from Copilot processing'; Disabled = $false; MentionsCopilot = $true }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'RetentionPolicy'; solutionArea = 'DataLifecycleManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-RetentionCompliancePolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        [pscustomobject]@{ Guid = '5946e516-db91-4e40-91f5-45174ce6bbdd'; Name = 'Mailbox retention'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; RuleTypes = 'Default'; HasRules = $true }
                        [pscustomobject]@{ Guid = '6c283fe0-257f-48df-abf1-bbaf6adee47f'; Name = 'Teams chat retention'; Enabled = $false; Mode = 'Enforce'; Workload = 'MicrosoftTeams'; RuleTypes = 'Default'; HasRules = $true }
                        [pscustomobject]@{ Guid = '01e8a90c-15df-4643-a695-7751daded879'; Name = 'Auto-apply contracts label'; Enabled = $true; Mode = 'Enforce'; Workload = 'SharePoint'; RuleTypes = 'Apply'; HasRules = $true }
                        [pscustomobject]@{ Guid = '15255c2a-944a-4de4-8def-1587e4f9438b'; Name = 'Auto-apply invoices label'; Enabled = $true; Mode = 'TestWithoutNotifications'; Workload = 'SharePoint'; RuleTypes = 'Apply'; HasRules = $true }
                        [pscustomobject]@{ Guid = 'ac7200db-bf5e-4ec0-aec7-3e9df7c64cbf'; Name = 'Publish records labels'; Enabled = $true; Mode = 'Enforce'; Workload = 'SharePoint'; RuleTypes = 'Publish'; HasRules = $true }
                        # Adaptive Protection writes this one itself, and the portal keeps it apart.
                        [pscustomobject]@{ Guid = 'af9dfd15-4393-4411-8373-746d5e6b2a88'; Name = 'Proactive data retention for risky users'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; RuleTypes = 'Apply, ProactiveDataRetention'; HasRules = $true }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'RetentionLabel'; solutionArea = 'RecordsManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-ComplianceTag'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Labels = @(
                        [pscustomobject]@{ Guid = '3be02da6-35f7-4be8-9839-be48f962528a'; Name = 'Keep 7 years'; IsRecordLabel = $true; RetentionAction = 'Keep'; RetentionDuration = 2555 }
                        [pscustomobject]@{ Guid = 'ae1f6898-377b-403d-bf16-05791efaae68'; Name = 'Delete after 1 year'; IsRecordLabel = $false; RetentionAction = 'Delete'; RetentionDuration = 365 }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                # Collected and empty, which is a real answer of zero rather than an unread area.
                collector = 'CommunicationCompliance'; solutionArea = 'CommunicationCompliance'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-SupervisoryReviewPolicyV2'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Policies = @() }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'OcrConfiguration'; solutionArea = 'Classification'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-OcrConfiguration'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Configurations = @() }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'LegacyRetention'; solutionArea = 'DataLifecycleManagement'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-RetentionPolicy'; kind = 'ExchangeOnlinePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Policies = @(
                        [pscustomobject]@{ Name = 'Default MRM Policy'; TagCount = 12 }
                        [pscustomobject]@{ Name = 'Legal hold policy'; TagCount = 3 }
                    )
                    Tags = @(
                        [pscustomobject]@{ Name = '1 Year Delete'; Type = 'Personal'; Action = 'DeleteAndAllowRecovery' }
                        [pscustomobject]@{ Name = 'Default 2 year move to archive'; Type = 'All'; Action = 'MoveToArchive' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'DataAccessGovernance'; solutionArea = 'Oversharing'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-SPODataAccessGovernanceInsight'; kind = 'SharePointOnlinePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Reports = @(
                        [pscustomobject]@{
                            Entity = 'EveryoneExceptExternalUsersAtSite'; Status = 'Completed'; Workload = 'SharePoint'
                            ReportType = 'Permission'; CreatedAt = $stamp
                            SitesInReport = 12; SitesInTenant = 40
                        }
                    )
                    EntitiesNotRead = @()
                    EntitiesAsked = 1
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AuditIngestion'; solutionArea = 'Audit'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-AdminAuditLogConfig'; kind = 'ExchangeOnlinePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Settings = @([pscustomobject]@{ Name = 'UnifiedAuditLogIngestionEnabled'; Enabled = $true; Capability = 'Unified audit logging' })
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'Licensing'; solutionArea = 'Licensing'; status = 'Success'
                source = [pscustomobject]@{ interface = 'GET /subscribedSkus'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    SubscribedSkus = @([pscustomobject]@{ skuPartNumber = 'SPE_E5'; skuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; capabilityStatus = 'Enabled'; servicePlans = @(); prepaidUnitsEnabled = 120; consumedUnits = 112 })
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AuditConfiguration'; solutionArea = 'Audit'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-UnifiedAuditLogRetentionPolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    RetentionPolicies = @(
                        [pscustomobject]@{ Name = 'Keep Exchange admin activity for ten years'; Enabled = $true; RetentionDuration = 'TenYears'; RecordTypes = 'ExchangeAdmin'; Priority = 100 }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'ProtectionActivity'; solutionArea = 'ActivityExplorer'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Export-ActivityExplorerData'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    WindowDays = 30
                    WindowStart = Format-PurviewTimestamp -Timestamp $activityStart
                    WindowEnd = Format-PurviewTimestamp -Timestamp $activityEnd
                    TotalEvents = 1840; Truncated = $false; ActivityScanComplete = $true
                    LabelEventsFiltered = $true; LabelEventsSource = 'FilteredQuery'
                    LabelQuerySucceeded = $true; LabelQueryComplete = $true; LabelQueryTruncated = $false
                    LabelRowsMissingActivity = 0; LabelRowsUnknownActivity = 0; LabelApplyRowsAmbiguous = 0
                    LabelApplyEventsReliable = $true; LabelChangeEventsReliable = $true; LabelRemoveEventsReliable = $true
                    LabelEventCountReason = 'The filtered query completed and every application event identified both its activity and label type.'
                    LabelApplyEvents = 0; LabelChangeEvents = 0; LabelRemoveEvents = 0
                    DlpRuleMatchEvents = 96; CopilotEvents = 412; EndpointEvents = 1332
                    ByActivity = @([pscustomobject]@{ Name = 'DLPRuleMatch'; Count = 96 })
                    ByWorkload = @(
                        [pscustomobject]@{ Name = 'Copilot'; Count = 412 }
                        [pscustomobject]@{ Name = 'Endpoint'; Count = 1332 }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'ClassificationCoverage'; solutionArea = 'ContentExplorer'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Export-ContentExplorerData'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    RequestKind = 'ExplicitSensitiveInformationType'
                    Tags = @(
                        [pscustomobject]@{ Tag = 'Credit Card Number'; TagType = 'SensitiveInformationType'; TotalCount = 17 }
                        [pscustomobject]@{ Tag = 'ABA Routing Number'; TagType = 'SensitiveInformationType'; TotalCount = 9 }
                    )
                    Requests = @(
                        [pscustomobject]@{ Tag = 'Credit Card Number'; TagType = 'SensitiveInformationType'; Status = 'Success'; TotalCount = 17 }
                        [pscustomobject]@{ Tag = 'ABA Routing Number'; TagType = 'SensitiveInformationType'; Status = 'Success'; TotalCount = 9 }
                    )
                    TagsRequested = 2; TagsAttempted = 2
                    TagsUnreadable = @(); TagsUnavailable = @()
                    TagsWithInvalidTotalCount = @(); TagsOmittedByLimit = @()
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'Classification'; solutionArea = 'Classification'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-DlpSensitiveInformationType'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    SensitiveInformationTypes = @(
                        [pscustomobject]@{ Guid = '422259b9-3086-4dce-aa43-1f3301567a30'; Name = 'Credit Card Number'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
                        [pscustomobject]@{ Guid = 'a544a9ce-f1e5-4b5b-8404-1ea499992f64'; Name = 'U.S. Social Security Number (SSN)'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
                        [pscustomobject]@{ Guid = '375582b7-a8b0-45f3-bba7-7294c0b18dfd'; Name = 'ABA Routing Number'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
                        [pscustomobject]@{ Guid = 'ef41e820-4d3d-4f5d-873d-f6da64bf3f54'; Name = 'International Banking Account Number (IBAN)'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
                    )
                }
                errors = @(); limitations = @()
            }
        )
    }
}

#endregion

#region Presentation

function Show-Usage {
    <# .SYNOPSIS Explains what a bare run is about to do, and the ways out of it. #>
    [CmdletBinding()]
    param()

    Write-Line -Message '  Assessing your tenant.'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  Missing modules install to CurrentUser scope, and you are signed in for anything'
    Write-Line -Style Dim -Message '  you are not already connected to. Authentication modules manage tenant sign-in'
    Write-Line -Style Dim -Message '  and tokens. PDF protection separately prompts for an encryption password.'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  -ReportFolder     write the report somewhere other than the current directory'
    Write-Line -Style Dim -Message '  -Demo             render a report from fabricated data, with no tenant or sign-in'
    Write-Line -Style Dim -Message '  -PdfReport        also render the report to PDF'
    Write-Line -Style Dim -Message '  -ProtectPdf       encrypt that PDF with a password you are asked for. Needs qpdf'
    Write-Line -Style Dim -Message '  -SkipInsights     skip explorer and oversharing reads; other telemetry reads remain'
    Write-Line -Style Dim -Message '  -SkipConnect      use only sessions you established yourself'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  -Help             show the full list of options without running an assessment'
}

function Show-ModuleStatus {
    <# .SYNOPSIS Reports what happened to each prerequisite module. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Module)

    Write-Line -Style Head -Message '  Modules'
    $usable = 0

    foreach ($item in @($Module | Sort-Object Service | Group-Object Service | ForEach-Object {
                $items = @($_.Group)
                $state = if (@($items | Where-Object State -in 'Failed', 'Missing', 'Unavailable').Count -gt 0) { 'Unavailable' }
                elseif (@($items | Where-Object State -in 'Outdated', 'OutdatedAndLoaded').Count -gt 0) { 'Outdated' }
                elseif (@($items | Where-Object State -in 'Updated', 'UpdatedAndLoaded').Count -gt 0) { 'Updated' }
                elseif (@($items | Where-Object State -in 'Installed', 'InstalledAndLoaded').Count -gt 0) { 'Installed' }
                else { 'Ready' }
                [pscustomobject]@{
                    Service = [string]$_.Name
                    State = $state
                    Detail = (@($items | Where-Object Detail | Select-Object -ExpandProperty Detail) -join '; ')
                }
            })) {
        switch ($item.State) {
            'Ready' { $usable++; Write-Line -Style Good -Message ('    ready        {0}' -f $item.Service) }
            'Installed' { $usable++; Write-Line -Style Good -Message ('    installed    {0}' -f $item.Service) }
            'InstalledAndLoaded' { $usable++; Write-Line -Style Good -Message ('    installed    {0}' -f $item.Service) }
            'Updated' { $usable++; Write-Line -Style Good -Message ('    updated      {0}' -f $item.Service) }
            'UpdatedAndLoaded' { $usable++; Write-Line -Style Good -Message ('    updated      {0}' -f $item.Service) }
            # Usable, but the version is behind what the settings it reads are documented to need.
            'Outdated' {
                $usable++
                Write-Line -Style Warn -Message ('    out of date  {0}' -f $item.Service)
                if ($item.Detail) { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
            }
            'OutdatedAndLoaded' {
                $usable++
                Write-Line -Style Warn -Message ('    out of date  {0}' -f $item.Service)
                if ($item.Detail) { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
            }
            default {
                Write-Line -Style Warn -Message ('    unavailable  {0}' -f $item.Service)
                if ($item.Detail) { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
            }
        }
    }

    return $usable
}

function Show-SignIn {
    <# .SYNOPSIS Prints who signed in and what they hold, before anything is collected. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)

    $line = { param($label, $value, $style) Write-Line -Style $style -Message ('    {0,-10} {1}' -f $label, $value) }

    $who = if ($Context.DisplayName -and $Context.Account) { '{0} ({1})' -f $Context.Account, $Context.DisplayName }
    elseif ($Context.Account) { $Context.Account }
    else { 'not reported by any connected service' }
    & $line 'Account' $who 'Dim'

    if ($Context.TenantId) { & $line 'Tenant' $Context.TenantId 'Dim' }
    if (@($Context.Service).Count -gt 0) { & $line 'Connected' (@($Context.Service) -join ', ') 'Dim' }
    $azure = (@((@($script:AzureRole) -join ', '), $script:AzureRoleDetail) | Where-Object { $_ }) -join '; '
    if ($null -ne $script:AzureSession -and $script:AzureSession.Connected -and
        $script:AzureSession.AccountId -ine $Context.Account) {
        & $line 'Azure user' $script:AzureSession.AccountId 'Dim'
    }
    & $line 'Azure' $azure 'Dim'

    # Keep readable names beside any qualification, not hidden by an unread companion.
    $entraDetail = [string](Get-PurviewProperty -InputObject $Context -Name 'EntraRoleDetail')
    if (-not $entraDetail -and [bool](Get-PurviewProperty -InputObject $Context -Name 'EntraRoleUnnamed')) {
        $entraDetail = 'some current role memberships were returned without readable names'
    }
    if (-not $entraDetail -and -not $Context.EntraRoleRead) { $entraDetail = 'not read; current Entra memberships could not be determined' }
    $entra = if (@($Context.EntraRole).Count -gt 0) { @($Context.EntraRole) -join ', ' }
    elseif ($Context.EntraRoleRead) { 'none currently reported' }
    else { '' }
    if ($entraDetail) { $entra = (@($entra, $entraDetail) | Where-Object { $_ }) -join '; ' }
    & $line 'Entra' $entra 'Dim'

    $purviewDetail = [string](Get-PurviewProperty -InputObject $Context -Name 'PurviewRoleGroupDetail')
    if (-not $purviewDetail -and -not $Context.PurviewRoleGroupRead) { $purviewDetail = 'not read; direct Purview role groups could not be determined' }
    $purview = if (@($Context.PurviewRoleGroup).Count -gt 0) { @($Context.PurviewRoleGroup) -join ', ' }
    elseif ($Context.PurviewRoleGroupRead) { 'none held directly' }
    else { '' }
    if ($purviewDetail) { $purview = (@($purview, $purviewDetail) | Where-Object { $_ }) -join '; ' }
    & $line 'Purview' $purview 'Dim'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '    Current memberships are shown; Entra roles activated through PIM can appear while active.'
    Write-Line -Style Dim -Message '    This is not an effective-permissions or PIM eligibility audit.'
}

function Invoke-PurviewContentExplorerGate {
    <#
    .SYNOPSIS
        Offers the content explorer role while it can still be used, rather than reporting it
        missing once the run is over.

    .DESCRIPTION
        Returns whether delayed counts for explicitly requested sensitive information types stay in
        scope. A role granted part way through is only surfaced to a new session, so accepting the
        offer signs in again rather than retrying a session built before the membership existed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [switch]$AllowPrompt,
        [string]$TenantAdminUrl = '',
        [ValidateSet('Commercial')][string]$Environment = 'Commercial'
    )

    # Nothing to offer if the cmdlet is there, and nothing a role would fix if the session is not.
    if (Test-PurviewCommand -Name 'Export-ContentExplorerData') { return $true }
    if (-not (Test-PurviewConnected -Service 'SecurityAndCompliance')) { return $true }

    Write-Line -Message ''
    Write-Line -Style Warn -Message '    The requested Content Explorer sensitive-information-type counts are not available to this sign-in.'
    Write-Line -Style Dim -Message '    They need the Content Explorer List Viewer role group. That role can expose item'
    Write-Line -Style Dim -Message '    locations, though this run keeps only aggregate counts and no file detail. It has to be'
    Write-Line -Style Dim -Message '    added: no Entra role carries it, Global Administrator included.'
    Write-Line -Style Dim -Message '    Purview portal > Settings > Roles and scopes > Role groups. Everything else in this'
    Write-Line -Style Dim -Message '    run is unaffected either way.'

    if (-not $AllowPrompt) {
        Write-Line -Style Dim -Message '    Nothing is asked of an unattended run, so it carries on without them.'
        return $true
    }

    while ($true) {
        Write-Line -Message ''
        Write-Line -Style Dim -Message '    [W] wait while the role is added   [S] skip requested counts   [C] carry on regardless'
        $answer = ''
        try { $answer = ([string](Read-Host '    W, S or C')).Trim().ToUpperInvariant() }
        catch {
            Write-Line -Style Dim -Message '    No answer could be read, so the run carries on.'
            return $true
        }

        switch ($answer) {
            'S' {
                Write-Line -Style Dim -Message '    Skipped. The requested counts are left out rather than reported as unreadable.'
                return $false
            }
            'C' { return $true }
            'W' {
                Write-Line -Message ''
                Write-Line -Style Dim -Message '    Add the account to Content Explorer List Viewer, then come back here.'
                try { $null = Read-Host '    Press Enter once the membership is saved' }
                catch { return $true }

                Write-Line -Style Dim -Message '    Signing in again, because a new membership only reaches a new session.'
                # Disconnecting the compliance session closes Exchange Online with it, so both are
                # re-established by the same call rather than left half connected.
                if (Test-PurviewCommand -Name 'Disconnect-ExchangeOnline') {
                    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null }
                    catch { Write-Verbose "Sign-out before the retry did not complete: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
                }
                $script:CommandCache = @{}
                $script:ServiceModuleCache = @{}
                $null = Connect-PurviewSession -TenantAdminUrl $TenantAdminUrl -Environment $Environment -AllowPrompt

                if (Test-PurviewCommand -Name 'Export-ContentExplorerData') {
                    Write-Line -Style Good -Message '    Content explorer is readable now.'
                    return $true
                }
                Write-Line -Style Warn -Message '    Still not available. A new membership does not always reach a new session at once.'
            }
            default { Write-Line -Style Dim -Message '    Answer W, S or C.' }
        }
    }
}

function Show-Prerequisite {
    <# .SYNOPSIS Prints the tenant opt-ins Secure by default asks for, and where each one stands. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $rows = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding)
    if ($rows.Count -eq 0) { return }

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Prerequisites and tenant opt-ins'

    $attention = @($rows | Where-Object { $_.State -eq 'Needs attention' })
    $good = @($rows | Where-Object { $_.State -in 'As recommended', 'Granted' })
    $inUse = @($rows | Where-Object { $_.State -eq 'In use' })
    $seenRecently = @($rows | Where-Object { $_.State -eq 'Seen recently' })
    $evidenceFound = @($rows | Where-Object { $_.State -eq 'Evidence found' })
    $portal = @($rows | Where-Object { $_.State -eq 'Confirm in portal' })
    $notLicensed = @($rows | Where-Object { $_.State -eq 'Not available - licensing' })
    # Counted by state, not as a residual: evidence states must never be tallied as not read.
    $unread = @($rows | Where-Object { $_.State -eq 'Not read' }).Count

    $summary = '    {0} need attention, {1} as recommended' -f $attention.Count, $good.Count
    if ($inUse.Count -gt 0) { $summary += ", $($inUse.Count) in use" }
    if ($seenRecently.Count -gt 0) { $summary += ", $($seenRecently.Count) seen recently" }
    if ($evidenceFound.Count -gt 0) { $summary += ", $($evidenceFound.Count) evidence found" }
    $summary += ", $($portal.Count) to confirm in the portal"
    if ($unread -gt 0) { $summary += ", $unread not read this run" }
    if ($notLicensed.Count -gt 0) { $summary += ", $($notLicensed.Count) not available with current licensing" }
    Write-Line -Style Dim -Message $summary

    foreach ($row in $rows) {
        $style = switch ($row.State) { 'As recommended' { 'Good' } 'Granted' { 'Good' } 'In use' { 'Good' } 'Needs attention' { 'Bad' } default { 'Dim' } }
        $marker = switch ($row.State) { 'As recommended' { 'ok    ' } 'Granted' { 'grant ' } 'Seen recently' { 'recent' } 'Evidence found' { 'found ' } 'In use' { 'in use' } 'Needs attention' { 'FIX   ' } 'Confirm in portal' { 'portal' } 'Not available - licensing' { 'licence' } default { '?     ' } }
        $label = if ($row.Optional) { '{0} (optional)' -f $row.Name } else { [string]$row.Name }
        Write-Line -Style $style -Message ('    {0} {1}' -f $marker, $label)
        if ($row.State -ne 'As recommended' -and $row.Action) {
            Write-Line -Style Dim -Message ('             {0}' -f $row.Action)
        }
    }

    Write-Line -Style Dim -Message '    Defaults and applicability differ. Portal-marked values are not collected here.'
    Write-Line -Style Dim -Message '    Review report details: positive states do not verify deployment or protection.'
}

function Show-Copilot {
    <# .SYNOPSIS Prints the Purview controls that govern what Copilot can reach. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $rows = @(Get-PurviewCopilotControl -Snapshot $Snapshot -Finding $Finding)
    if ($rows.Count -eq 0) { return }

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Copilot and AI controls'

    $band = ''
    foreach ($row in $rows) {
        if ($row.Band -ne $band) {
            $band = [string]$row.Band
            Write-Line -Style Dim -Message ('    -- {0}' -f $(if ($band -eq 'Copilot') { 'Microsoft 365 Copilot' } else { $band }))
        }
        $style = switch ($row.State) { 'As recommended' { 'Good' } 'Needs attention' { 'Bad' } 'Needs review' { 'Warn' } 'In use' { 'Good' } default { 'Dim' } }
        Write-Line -Style $style -Message ('    {0,-22} {1}' -f $row.State, $row.Control)
        Write-Line -Style Dim -Message ('                           {0}' -f $row.Detail)
    }
}

function Show-Maturity {
    <# .SYNOPSIS Prints how far the checks that exist get through each deployment model. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Blueprint coverage'

    foreach ($model in Get-PurviewDeploymentMaturity -Finding $Finding) {
        $steps = @($model.Steps | Where-Object { $_.State -ne 'NoChecks' })
        if ($steps.Count -eq 0) { continue }

        Write-Line -Style Head -Message ('    {0}' -f $model.Name)
        foreach ($step in $steps) {
            $stepStyle = switch ($step.State) { 'ChecksPass' { 'Good' } 'ChecksFail' { 'Bad' } 'Partial' { 'Warn' } 'ChecksWarn' { 'Warn' } default { 'Dim' } }
            $title = if ($step.Title) { $step.Title } else { 'Not covered by this assessment' }
            Write-Line -Style $stepStyle -Message ('      {0}. {1,-52} {2}' -f $step.Step, $title, $step.Verdict)
        }
    }

    Write-Line -Style Dim -Message '    Only steps this tool can check are shown. A step with no check would say'
    Write-Line -Style Dim -Message '    nothing about the tenant, only about the tool.'
}

function Show-Taxonomy {
    <# .SYNOPSIS Prints the taxonomy comparison, framed as observation rather than judgement. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $rows = @(Get-PurviewTaxonomyComparison -Snapshot $Snapshot)
    if ($rows.Count -eq 0) { return }

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Label taxonomy against the documented default'

    foreach ($row in $rows) {
        $style = if ($row.Match -eq 'Same name') { 'Good' } else { 'Dim' }
        $name = if ((Get-PurviewProperty -InputObject $row -Name 'Depth') -eq 1) { '  ' + $row.Tier } else { $row.Tier }
        Write-Line -Style $style -Message ('    {0,-42} {1,-18} {2}' -f $name, $row.Type, $row.Match)
    }

    Write-Line -Style Dim -Message '    Label groups organize labels; they are not themselves labels to publish or apply.'
    Write-Line -Style Dim -Message '    Child paths are indented beneath their parent; Same name means a reference-tier match.'
    if (@($rows | Where-Object { $_.Type -eq 'Not recorded' }).Count -gt 0) {
        Write-Line -Style Dim -Message '    Type not recorded: the source lacks a usable group marker; type is not inferred.'
    }
    Write-Line -Style Dim -Message '    A reference to compare against, not a target. A different taxonomy is a'
    Write-Line -Style Dim -Message '    design choice; only exact names are matched, so equivalents read as their own.'
}

function Show-Delta {
    <# .SYNOPSIS Prints what moved since the baseline, and what must not be counted as movement. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Delta)

    $cross = (Test-PurviewProperty -InputObject $Delta -Name 'CrossTenant') -and $Delta.CrossTenant

    Write-Line -Message ''
    Write-Line -Style Head -Message $(if ($cross) { '  Comparison with another tenant' } else { '  Progress since the last assessment' })

    if (-not $Delta.Comparable) {
        Write-Line -Style Dim -Message ('    {0}' -f $Delta.Blocker)
        return
    }

    Write-Line -Style Dim -Message ('    Baseline   {0}' -f $Delta.BaselineRecordedAt)
    foreach ($group in @(
            [pscustomobject]@{ Heading = 'Rule outcomes'; Movement = $Delta.RuleMovement; IsRule = $true }
            [pscustomobject]@{ Heading = 'Tenant opt-ins'; Movement = $Delta.OptInMovement; IsRule = $false }
        )) {
        $movement = $group.Movement
        Write-Line -Message ''
        Write-Line -Style Head -Message ('    {0}' -f $group.Heading)
        if ($movement.Improved -gt 0) { Write-Line -Style Good -Message ('      {0} {1}' -f $(if ($cross) { 'stronger here ' } else { 'improved      ' }), $movement.Improved) }
        if ($movement.Regressed -gt 0) { Write-Line -Style Bad -Message ('      {0} {1}' -f $(if ($cross) { 'weaker here   ' } else { 'regressed     ' }), $movement.Regressed) }
        Write-Line -Style Dim -Message ('      {0} {1}' -f $(if ($cross) { 'the same      ' } else { 'unchanged     ' }), $movement.Unchanged)

        foreach ($row in @($movement.Changes | Where-Object { $_.Change -in 'Improved', 'Regressed' })) {
            $style = if ($row.Change -eq 'Improved') { 'Good' } else { 'Bad' }
            $what = if ($group.IsRule) { [string]$row.RuleId } else { 'opt-in' }
            $name = if ($group.IsRule) { [string]$row.Title } else { [string]$row.Name }
            Write-Line -Style $style -Message ('        {0,-12} {1} -> {2}  {3}' -f $what, $row.From, $row.To, $name)
        }

        if ($movement.CouldNotAssess -gt 0) {
            Write-Line -Style Warn -Message ('      Could not assess this run: {0}. Kept out of movement.' -f $movement.CouldNotAssess)
            foreach ($row in @($movement.Changes | Where-Object { $_.Change -eq 'CouldNotAssess' })) {
                $what = if ($group.IsRule) { [string]$row.RuleId } else { 'opt-in' }
                $name = if ($group.IsRule) { [string]$row.Title } else { [string]$row.Name }
                Write-Line -Style Warn -Message ('        {0,-12} {1}' -f $what, $name)
            }
        }
    }
}

function Show-Inventory {
    <# .SYNOPSIS Prints what the tenant has configured, before any judgement about it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Tenant at a glance'

    $area = ''
    foreach ($row in Get-PurviewInventory -Snapshot $Snapshot) {
        if ($row.Area -ne $area) {
            $area = $row.Area
            Write-Line -Style Dim -Message ('    {0}' -f $area)
        }
        $style = if ($row.Value -eq 'not checked') { 'Dim' } elseif ($row.Value -in '0', 'off') { 'Warn' } else { 'Good' }
        Write-Line -Style $style -Message ('      {0,-38} {1}' -f $row.Metric, $row.Value)
        if ($row.Value -eq 'not checked') { Write-Line -Style Dim -Message ('        {0}' -f $row.Detail) }
    }
}

function Show-Checklist {
    <# .SYNOPSIS Prints what is done and what is left, in the order it should be worked. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $checklist = @(Get-PurviewChecklist -Finding $Finding)
    $progress = Get-PurviewChecklistProgress -Checklist $checklist

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Checklist'

    if ($null -ne $progress.Percent) {
        $style = if ($progress.Percent -ge 80) { 'Good' } elseif ($progress.Percent -ge 40) { 'Warn' } else { 'Bad' }
        Write-Line -Style $style -Message ('    {0} of {1} done ({2}%)' -f $progress.Done, $progress.Judged, $progress.Percent)
    }

    foreach ($group in 'To do', 'To check by hand', 'Done', 'Not available - licensing', 'Not checked') {
        $rows = @($checklist | Where-Object { $_.Group -eq $group })
        if ($rows.Count -eq 0) { continue }

        $style = switch ($group) { 'To do' { 'Bad' } 'To check by hand' { 'Warn' } 'Done' { 'Good' } default { 'Dim' } }
        Write-Line -Message ''
        Write-Line -Style Dim -Message ('    {0} ({1})' -f $group, $rows.Count)

        foreach ($row in $rows) {
            Write-Line -Style $style -Message ('      [{0}] {1,-12} {2}' -f $row.Marker, $row.RuleId, $row.Title)
            if ($group -eq 'To do' -and $row.Command) {
                Write-Line -Style Dim -Message ('            one command: {0}' -f $row.Command)
            }
        }
    }

}

function Show-Summary {
    <# .SYNOPSIS Prints the status tally, worst first. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Summary'

    $styles = @{
        Fail = 'Bad'; Warning = 'Warn'; NeedsReview = 'Warn'; Pass = 'Good'
        NotCollected = 'Dim'; Unsupported = 'Dim'; NotLicensed = 'Dim'
    }

    $notAssessed = 0
    foreach ($status in 'Fail', 'Warning', 'NeedsReview', 'Pass', 'NotLicensed', 'NotCollected', 'Unsupported') {
        $count = @($Finding | Where-Object { $_.status -eq $status }).Count
        if ($status -in 'NotCollected', 'Unsupported') { $notAssessed += $count }
        if ($count -eq 0) { continue }
        Write-Line -Style $styles[$status] -Message ('    {0,-22} {1}' -f (Get-PurviewStatusLabel -Status $status), $count)
    }

    if ($notAssessed -gt 0) {
        Write-Line -Message ''
        Write-Line -Style Dim -Message "    $notAssessed rule(s) lacked usable evidence. Review scope and collector details;"
        Write-Line -Style Dim -Message '    connection, permissions, modules or unsupported collection may need attention.'
    }
}

function Get-PurviewStatusLabel {
    <#
    .SYNOPSIS
        The wording a reader sees for a status.

    .DESCRIPTION
        Change display labels only. Keep stored values such as 'Fail' stable so existing posture
        records remain comparable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Status)

    switch ($Status) {
        'Fail' { return 'Area for improvement' }
        'NotCollected' { return 'Not collected' }
        'NotLicensed' { return 'Not available - licensing' }
        'NeedsReview' { return 'Needs review' }
        default { return $Status }
    }
}

function Show-Finding {
    <# .SYNOPSIS Prints the findings that need a human, with their source and recommendation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $actionable = @($Finding | Where-Object { $_.status -in 'Fail', 'Warning', 'NeedsReview' })
    if ($actionable.Count -eq 0) {
        Write-Line -Message ''
        Write-Line -Style Good -Message '  No findings needing attention were returned for the assessed checks; unassessed areas remain unknown.'
        return
    }

    Write-Line -Message ''
    Write-Line -Style Head -Message '  Findings needing attention'

    foreach ($item in $actionable | Sort-Object @{ Expression = { Get-PurviewSeverityOrder -Severity ([string](Get-PurviewProperty -InputObject $_ -Name 'severity')) } }, ruleId) {
        $style = if ($item.status -eq 'Fail') { 'Bad' } else { 'Warn' }
        Write-Line -Message ''
        Write-Line -Style $style -Message ('    [{0}] {1} - {2}' -f (Get-PurviewStatusLabel -Status $item.status), $item.ruleId, $item.title)
        Write-Line -Style Dim -Message ('      Severity {0}, confidence {1}, {2}' -f $item.severity, $item.confidence, $item.zeroTrust)
        Write-Line -Message ('      What we found: {0}' -f $item.reason)

        foreach ($observed in @(Get-PurviewProperty -InputObject $item -Name 'observed')) {
            Write-Line -Style $style -Message ('        - {0}' -f $observed)
        }

        Write-Line -Message ('      Why it matters: {0}' -f $item.rationale)
        Write-Line -Message ('      What to do:     {0}' -f $item.recommendation)

        if ($item.PSObject.Properties['remediationCommand']) {
            Write-Line -Style Warn -Message ('      Review the impact, then run this yourself:')
            Write-Line -Style Warn -Message ('        {0}' -f $item.remediationCommand)
        }

        foreach ($id in @($item.evidence)) {
            if ($script:Evidence.ContainsKey($id)) {
                Write-Line -Style Dim -Message ('      Read more:      {0}' -f $script:Evidence[$id].Title)
                Write-Line -Style Dim -Message ('                      {0}' -f $script:Evidence[$id].Url)
            }
        }
    }
}

#endregion

# The Azure collector runs in its own process because Az.Accounts and the Microsoft 365 sign-in
# modules can load incompatible identity assemblies. The worker writes only serialized collector
# evidence; it never signs in or changes Azure configuration.
if ($AzureSignOutWorker) {
    try {
        Import-Module -Name Az.Accounts -ErrorAction Stop
        if ($AzureContextPath) {
            Import-AzContext -Path $AzureContextPath -Scope Process -ErrorAction Stop | Out-Null
        }
        Disconnect-AzAccount -ErrorAction Stop | Out-Null
        exit 0
    }
    catch {
        Write-Error $_
        exit 1
    }
}

if ($AzureSignInWorker) {
    try {
        if (-not $AzureSignInOutputPath -or -not $AzureContextPath) {
            throw 'The Azure sign-in worker requires result and context paths.'
        }
        $connection = Connect-PurviewAzureAccount -ContextPath $AzureContextPath -TenantId $AzureTenantId
        $connection | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $AzureSignInOutputPath -Encoding utf8
        if ($connection.Reused) { exit 2 }
        exit 0
    }
    catch {
        $failure = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
        if ($AzureSignInOutputPath) {
            [pscustomobject]@{ Connected = $false; Error = $failure } |
                ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $AzureSignInOutputPath -Encoding utf8
        }
        else { Write-Error -Message $failure -ErrorAction Continue }
        exit 1
    }
}

if ($script:IsSentinelWorker) {
    try {
        if ([string]::IsNullOrWhiteSpace($SentinelOutputPath)) {
            throw 'The isolated Azure Sentinel collector was not given an output path.'
        }
        Import-Module -Name Az.Accounts, Az.Resources -ErrorAction Stop
        if ($AzureContextPath) {
            if (-not (Test-Path -LiteralPath $AzureContextPath -PathType Leaf)) {
                throw 'Azure is not connected: the context saved for this run is unavailable.'
            }
            Import-AzContext -Path $AzureContextPath -Scope Process -ErrorAction Stop | Out-Null
        }
        $script:ExpectedTenantId = $AzureTenantId
        $evidence = Get-PurviewSentinelIntegrationData -LookbackDays $SentinelLookbackDays
        $evidence | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $SentinelOutputPath -Encoding utf8
        exit 0
    }
    catch {
        Write-Error -Message (Get-PurviewSafeErrorMessage -Message $_.Exception.Message) -ErrorAction Continue
        exit 1
    }
}

#region Main

# Dot-sourcing this script exposes its functions without running an assessment, which is how the
# tests exercise it.
if ($MyInvocation.InvocationName -eq '.') { return }

try {

Write-Line -Message ''
Write-Line -Style Head -Message ('  Microsoft Purview advisor {0}' -f $script:ToolVersion)
Write-Line -Style Dim -Message '  Evidence-based assessment. No tenant configuration changes; local setup and report writes may occur.'
Write-Line -Message ''

if (-not [string]::IsNullOrWhiteSpace($ExportRules)) {
    $written = Export-PurviewRuleSet -Path $ExportRules
    Write-Line -Style Good -Message ('  {0} rules and {1} citations written to {2}' -f $script:Rules.Count, $script:Evidence.Count, $written)
    Write-Line -Style Dim -Message '  Edit it and pass it back with -RuleFile.'
    Write-Line -Message ''
    return
}

if (-not [string]::IsNullOrWhiteSpace($RuleFile)) {
    $loaded = Import-PurviewRuleSet -Path $RuleFile
    Write-Line -Style Warn -Message ('  Using rules from {0}: {1} supplied, {2} in force.' -f $loaded.Path, $loaded.Supplied, $loaded.RuleCount)
    Write-Line -Message ''
}

# Solutions are resolved once, after any rule file has replaced the built-in set, so a narrowed run
# and the rules it scores can never disagree.
$script:ActiveArea = @(Get-PurviewSolutionArea -Solution $Solution)
$script:ActiveSolution = @($Solution)
$script:ActiveRule = @($script:Rules | Where-Object { $script:ActiveArea -contains [string]$_.solutionArea })
$requestedInsightTags = @(Get-PurviewInsightTag -ExtraTag $InsightTag)
$contentExplorerRequested = Test-PurviewContentExplorerRequest -SkipInsights:$SkipInsights `
    -Tag $requestedInsightTags -SolutionArea $script:ActiveArea
if (@($Solution).Count -gt 0) {
    Write-Line -Style Warn -Message ('  Scope      {0} only. Everything else is neither collected nor scored.' -f ($Solution -join ', '))
    Write-Line -Message ''
}

# Collecting is the default, so the script does something useful with no arguments at all.
$bare = -not $Collect -and -not $Demo -and [string]::IsNullOrWhiteSpace($SnapshotPath)
if ($bare) {
    Show-Usage
    Write-Line -Message ''
}

# Reuse the report folder, overwriting only the paths written by this run. Other files, including
# optional exports from earlier runs, remain; saved posture records provide comparison history.
if ([string]::IsNullOrWhiteSpace($ReportFolder)) {
    $ReportFolder = Join-Path (Get-Location).Path 'PurviewReport'
}
if (-not (Test-Path -LiteralPath $ReportFolder -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $ReportFolder -Force
}

$snapshot = $null

if ($Demo) {
    # Fabricated throughout, so the report can be shown and the rules exercised without a tenant,
    # a sign-in or a licence. Nothing here came from anywhere real.
    Write-Line -Style Warn -Message '  Demo mode. Every figure below is fabricated and describes no tenant.'
    Write-Line -Message ''
    $snapshot = Get-PurviewDemoSnapshot
}
elseif ($Collect -or $bare) {
    $modules = @(Install-PurviewPrerequisite -SkipInstall:$SkipModuleInstall -AllowPrompt:(Test-PurviewCanPrompt))
    $usable = Show-ModuleStatus -Module $modules
    Write-Line -Message ''

    $updatedModules = @($modules | Where-Object {
            $_.State -eq 'Updated' -and $_.LoadedBeforeUpdate
        })
    if ($updatedModules.Count -gt 0 -and $env:PURVIEW_ADVISOR_MODULE_RELAUNCHED -ne '1') {
        $shell = [string](Get-Process -Id $PID).Path
        if ([string]::IsNullOrWhiteSpace($shell)) {
            $shell = [string](Get-Command -Name 'pwsh' -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty Source)
        }
        if ([string]::IsNullOrWhiteSpace($shell)) {
            throw 'A module was updated, but the current PowerShell executable could not be located for the required fresh-session restart.'
        }

        Write-Line -Style Good -Message '  Module updates completed. Restarting in a fresh PowerShell session.'
        $forward = @()
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Value -is [switch]) {
                if ($entry.Value.IsPresent) { $forward += "-$($entry.Key)" }
            }
            elseif ($entry.Value -is [array]) {
                $forward += "-$($entry.Key)"
                $forward += @($entry.Value | ForEach-Object { [string]$_ })
            }
            else {
                $forward += "-$($entry.Key)"
                $forward += [string]$entry.Value
            }
        }

        $previousRelaunchMarker = $env:PURVIEW_ADVISOR_MODULE_RELAUNCHED
        try {
            $env:PURVIEW_ADVISOR_MODULE_RELAUNCHED = '1'
            & $shell -NoLogo -NoProfile -File $PSCommandPath @forward
            $relaunchExitCode = $LASTEXITCODE
        }
        finally {
            $env:PURVIEW_ADVISOR_MODULE_RELAUNCHED = $previousRelaunchMarker
        }
        exit $relaunchExitCode
    }

    if ($usable -eq 0) {
        Write-Line -Style Bad -Message '  No collection module is available, so there is nothing to collect.'
        Write-Line -Style Dim -Message '  Install them yourself, or run again without -SkipModuleInstall.'
        Write-Line -Message ''
        return
    }

    if (-not $SkipConnect) {
        Write-Line -Style Head -Message '  Signing in'
        $null = Connect-PurviewSession -TenantAdminUrl $TenantAdminUrl -Environment $Environment -AllowPrompt:(Test-PurviewCanPrompt)
        Write-Line -Message ''

        $null = Assert-PurviewSessionTenant
        Write-Line -Style Head -Message '  Signed in as'
        Show-SignIn -Context (Get-PurviewSignInContext)

        # Asked before anything is collected, because a role granted now still counts for this run
        # and a role granted after it does not.
        if ($contentExplorerRequested) {
            $keep = Invoke-PurviewContentExplorerGate -AllowPrompt:([Environment]::UserInteractive) `
                -TenantAdminUrl $TenantAdminUrl -Environment $Environment
            $script:SkipContentExplorer = -not $keep
        }
        Write-Line -Message ''
    }

    # A report must never combine independently authenticated services from different tenants.
    # This also rejects multiple active connections whose command module cannot be chosen safely.
    $null = Assert-PurviewSessionTenant

    Write-Line -Style Head -Message '  Collecting'
    Write-Line -Style Dim -Message '    A large tenant can take a few minutes.'
    if (-not $SkipInsights -and $script:ActiveArea -contains 'ActivityExplorer') {
        Write-Line -Style Dim -Message ('    Reading a rolling {0}-day activity window. Only totals are kept.' -f $InsightDays)
    }
    if ($contentExplorerRequested -and -not $script:SkipContentExplorer) {
        Write-Line -Style Dim -Message ('    Reading delayed indexed counts for {0} explicitly requested sensitive information type(s).' -f $requestedInsightTags.Count)
    }
    Write-Line -Message ''
    $collectionClock = [System.Diagnostics.Stopwatch]::StartNew()
    $snapshot = Get-PurviewTenantSnapshot -IncludeSites:$IncludeSites -SiteLimit $SiteLimit -RedactTenant:$RedactTenant `
        -IncludeInsights:(-not $SkipInsights) -InsightDays $InsightDays -InsightTag $InsightTag -SolutionArea $script:ActiveArea
    $collectionClock.Stop()
    Write-Line -Style Dim -Message ('    Collected in {0:N0}s.' -f $collectionClock.Elapsed.TotalSeconds)

    if ([string]::IsNullOrWhiteSpace($SnapshotOutputPath)) {
        $SnapshotOutputPath = Join-Path $ReportFolder 'snapshot.json'
    }

    $snapshot | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $SnapshotOutputPath -Encoding utf8
}
else {
    if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
        throw "Snapshot not found: $SnapshotPath"
    }
    $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 100
    Write-Line -Style Dim -Message ('  Snapshot   {0}' -f $SnapshotPath)
}

$evaluatedFindings = @(Invoke-PurviewRuleEngine -Snapshot $snapshot -Rule $script:ActiveRule)
$findings = @(Get-PurviewCustomerFinding -Finding $evaluatedFindings)

Write-Line -Message ''
Write-Line -Style Dim -Message ('  Mode       {0}' -f $snapshot.mode)
Write-Line -Style Dim -Message ('  Checks     {0}' -f $findings.Count)
Write-Line -Style Dim -Message ('  Time zone  {0}' -f (Get-PurviewTimeZoneContext).Id)

Show-Summary -Finding $findings
Show-Inventory -Snapshot $snapshot
Show-Checklist -Finding $findings
Show-Prerequisite -Snapshot $snapshot -Finding $findings
Show-Copilot -Snapshot $snapshot -Finding $findings
Show-Maturity -Finding $findings
Show-Taxonomy -Snapshot $snapshot

$delta = $null
$recordFolder = if ($NoRecord) { '' }
elseif (-not [string]::IsNullOrWhiteSpace($BaselineFolder)) { $BaselineFolder }
else { Get-PurviewDefaultRecordFolder }

# Comparing two tenants is only ever deliberate, so it needs the record named outright. Picking one
# from history could silently compare a customer against whoever was assessed before them.
if ($AcrossTenants -and [string]::IsNullOrWhiteSpace($BaselinePath)) {
    throw 'AcrossTenants needs -BaselinePath naming the record to compare against.'
}

$record = ConvertTo-PurviewPostureRecord -Snapshot $snapshot -Finding $findings
$baseline = $null

if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
        throw "Posture record not found: $BaselinePath"
    }
    $baseline = Get-Content -LiteralPath $BaselinePath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100
}
elseif (-not [string]::IsNullOrWhiteSpace($recordFolder)) {
    $baseline = Find-PurviewBaselineRecord -Folder $recordFolder -Current $record
}

$delta = Compare-PurviewPosture -Baseline $baseline -Current $record -AcrossTenants:$AcrossTenants
# Nothing to compare on a first assessment, and an empty progress heading reads as a finding.
if ($null -ne $delta -and $delta.Comparable) { Show-Delta -Delta $delta }

if (-not [string]::IsNullOrWhiteSpace($recordFolder)) {
    $saved = Save-PurviewPostureRecord -Record $record -Folder $recordFolder
    if ($saved) {
        Write-Line -Message ''
        Write-Line -Style Good -Message ('  Run recorded at {0}' -f $saved)
        Write-Line -Style Dim -Message '  Tenant/run metadata, findings and prerequisite states saved for comparison. Treat as sensitive; -NoRecord skips saving.'
    }
}

Show-Finding -Finding $findings

$htmlPath = Join-Path $ReportFolder 'report.html'
$jsonPath = Join-Path $ReportFolder 'findings.json'

ConvertTo-PurviewHtmlReport -Finding $findings -Snapshot $snapshot -Delta $delta -DarkMode:$DarkMode -Brief:$Brief | Set-Content -LiteralPath $htmlPath -Encoding utf8
$findings | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $jsonPath -Encoding utf8

$remediationPath = Join-Path $ReportFolder 'Set-PurviewTenantOptIns.ps1'
$remediationParts = Get-PurviewRemediationPart `
    -Prerequisite @(Get-PurviewPrerequisiteState -Snapshot $snapshot -Finding $findings) `
    -TenantName ([string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $snapshot -Name 'tenant') -Name 'displayName')) `
    -TenantId ([string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $snapshot -Name 'tenant') -Name 'tenantId')) `
    -GeneratedAt ([string](Get-PurviewProperty -InputObject $snapshot -Name 'capturedAt')) `
    -AdminUrl $(if (Test-Path variable:script:SharePointAdminUrl) { $script:SharePointAdminUrl } else { '' })
ConvertTo-PurviewRemediationScript -Part $remediationParts | Set-Content -LiteralPath $remediationPath -Encoding utf8

Write-Line -Message ''
Write-Line -Style Head -Message '  Report'
Write-Line -Style Good -Message ('    {0}' -f $htmlPath)
Write-Line -Style Dim -Message ('    {0}' -f $remediationPath)
Write-Line -Style Dim -Message '    Review the remediation script: tenant changes require confirmation; local setup and recording are separate.'

if ($PdfReport -or $ProtectPdf) {
    $pdfTarget = Join-Path $ReportFolder 'report.pdf'
    # Clear a previous requested output before prerequisites are checked. Otherwise a failed
    # protected export can leave an older, possibly unencrypted PDF looking current.
    if (Test-Path -LiteralPath $pdfTarget) {
        Remove-Item -LiteralPath $pdfTarget -Force -ErrorAction Stop
    }
    $secret = $null
    $qpdfPath = ''

    if ($ProtectPdf) {
        if (-not [Environment]::UserInteractive) {
            Write-Line -Style Warn -Message '    A password cannot be asked for in an unattended run, so no PDF was written.'
        }
        else {
            $qpdfPath = Install-PurviewQpdf -SkipInstall:$SkipModuleInstall
            if ([string]::IsNullOrWhiteSpace($qpdfPath)) {
                Write-Line -Style Warn -Message '    No PDF was written, because an unprotected one is not what was asked for.'
            }
            else {
                Write-Line -Message ''
                Write-Line -Style Dim -Message '    Keep the PDF password securely; this script offers no password recovery.'
                Write-Line -Style Dim -Message '    Other report formats remain unencrypted. Memory-copy erasure is not guaranteed.'
                $secret = Read-PurviewSecret -Prompt '    Password for the PDF'
                if ($null -eq $secret) { Write-Line -Style Warn -Message '    No password was set, so no PDF was written.' }
            }
        }
    }

    if (-not $ProtectPdf -or $null -ne $secret) {
        $pdf = Export-PurviewPdfReport -HtmlPath $htmlPath -PdfPath $pdfTarget
        if ($pdf -and $ProtectPdf) {
            if (Protect-PurviewPdf -PdfPath $pdf -Password $secret -QpdfPath $qpdfPath) {
                Write-Line -Style Good -Message ('    {0}' -f $pdf)
                Write-Line -Style Dim -Message '    Encrypted. Opening it needs the password you just set.'
            }
            else {
                Remove-Item -LiteralPath $pdf -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $pdf) {
                    Write-Line -Style Bad -Message '    PDF encryption failed, and the unprotected PDF could not be removed. Do not share it.'
                }
                else {
                    Write-Line -Style Bad -Message '    PDF encryption failed. The unprotected PDF was removed.'
                }
            }
        }
        elseif ($pdf) { Write-Line -Style Good -Message ('    {0}' -f $pdf) }
    }

    if ($null -ne $secret) { $secret.Dispose() }
}

if ($WordReport) {
    $docx = Export-PurviewWordReport -HtmlPath $htmlPath -WordPath (Join-Path $ReportFolder 'report.docx')
    if ($docx) { Write-Line -Style Good -Message ('    {0}' -f $docx) }
}

Write-Line -Style Dim -Message ('    {0}   the findings as data' -f $jsonPath)
if ($SnapshotOutputPath -and (Test-Path -LiteralPath $SnapshotOutputPath)) {
    Write-Line -Style Dim -Message ('    {0}   what was collected, for re-analysis' -f $SnapshotOutputPath)
}
Write-Line -Style Dim -Message '    Files written by this run overwrite the same paths; other files remain. Use a different -ReportFolder to preserve earlier output.'
if ($Demo) { Write-Line -Style Dim -Message '    Every figure in these is fabricated. Nothing here came from a tenant.' }
else { Write-Line -Style Dim -Message '    These describe real configuration. Treat them as customer data.' }

if (-not $NoOpen -and [Environment]::UserInteractive) {
    try { Invoke-Item -LiteralPath $htmlPath }
    catch { Write-Verbose "Could not open the report: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
}

if ($CheckEvidence) {
    Show-EvidenceCheck -Result @(Test-PurviewEvidence)
}

Write-Line -Message ''
Write-Line -Style Dim -Message '  No tenant configuration changes were made by the assessment. Review any suggested commands before running them yourself.'
Write-Line -Message ''

if ($PassThru) { $findings }

}
finally {
    # Best-effort cleanup on exits that reach finally; reports, installed modules and caches may remain.
    $signedIn = @($script:OwnedSession).Count -gt 0
    Clear-PurviewRunState
    if ($signedIn) {
        Write-Line -Style Dim -Message '  Cleanup attempted for all supported service sessions; token revocation and cache removal are not verified.'
        Write-Line -Message ''
    }
}

#endregion
