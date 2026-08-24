<#
.SYNOPSIS
    Assesses Microsoft Purview configuration against evidence-based rules and reports the result.

.DESCRIPTION
    A single self-contained script. Collects Microsoft Purview configuration from a tenant,
    evaluates it against built-in deterministic rules, and prints a summary with optional HTML and
    JSON reports.

    Collection is read-only. Only Get-* cmdlets and HTTP GET operations are ever called, and every
    interface used was verified against its Microsoft Learn reference page. Anything you are not
    connected to is reported as not collected, so a partial run still tells you what it could reach.

    Collection and analysis are separate. Collection produces a snapshot; analysis reads only that
    snapshot. The same snapshot always yields the same findings, so a result can be re-examined long
    after the tenant has moved on.

    Every recommendation carries the Microsoft source it came from, the date that source was
    retrieved, and a confidence level. Where a fix exists, the command is printed for you to review
    and run yourself. This script never runs it.

.PARAMETER Collect
    Collect from the tenant, then assess what was collected. This is what happens by default.

.PARAMETER TenantAdminUrl
    Your SharePoint admin URL, https://<tenant>-admin.sharepoint.com. Only needed to sign in to
    SharePoint; you are asked for it otherwise, and skipping it just omits the SharePoint checks.

.PARAMETER Environment
    The cloud the tenant is in: Commercial (the default), GCC, GCCHigh, DoD or China. GCC uses the
    commercial endpoints, which is what Microsoft documents for it.

.PARAMETER Solution
    Assess only the named Purview solutions instead of all of them. Anything not named is neither
    collected nor scored, and the report says which solutions were in scope.

.PARAMETER Brief
    Write the condensed report: what is configured, the summary, what to do, and the limitations.
    The same assessment runs either way; only how much of it is written out changes.

.PARAMETER SkipConnect
    Do not sign in to anything. Use only sessions you established yourself.

.PARAMETER KeepSignedIn
    Leave the sessions this run opened signed in. By default the run signs out of them, so the
    tokens it obtained do not outlive the assessment. Keeping them lets the next run start without
    asking you to sign in again.

.PARAMETER SnapshotPath
    Assess a snapshot already on disk.

.PARAMETER SnapshotOutputPath
    Where -Collect writes the snapshot. Defaults to a timestamped file in the current folder.

.PARAMETER SkipModuleInstall
    Do not install missing modules; use only what is already present.

.PARAMETER IncludeSites
    Also enumerate SharePoint sites. Slow on a large tenant.

.PARAMETER SiteLimit
    Maximum sites to enumerate with -IncludeSites.

.PARAMETER RedactTenant
    Blank the tenant name and id in the snapshot, for sharing outside the customer.

.PARAMETER SkipInsights
    Skip the activity, indexed-content and oversharing reads. Without them the run reports
    configuration only; it does not report recent sensitivity-label application events or any
    explicitly requested Content Explorer counts.

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
    Compare against this specific posture record instead of the most recent. Used on its own, it
    compares without saving anything.

.PARAMETER AcrossTenants
    Allow the -BaselinePath record to belong to a different tenant, for comparing a lab against
    production. The report says the comparison is across tenants and does not call a difference
    progress. Refused without -BaselinePath, so one customer is never silently compared to another.

.PARAMETER ReportFolder
    Where to write the report. Defaults to a PurviewReport folder in the current directory, which
    is refreshed on each run. The report describes real configuration, so treat it as customer data.

.PARAMETER NoOpen
    Do not open the report when it is finished.

.PARAMETER DarkMode
    Render the report on a dark background. Affects the HTML and any PDF made from it.

.PARAMETER PdfReport
    Also render the report to PDF. Needs Edge, Chrome or Chromium installed.

.PARAMETER ProtectPdf
    Encrypt the PDF so it cannot be opened without a password, which you are asked for. Needs qpdf,
    because a browser can print a PDF but cannot encrypt one. If the PDF cannot be encrypted it is
    deleted rather than left unprotected.

.PARAMETER WordReport
    Also convert the report to .docx. Needs Word on Windows.

.PARAMETER CheckEvidence
    Check that every cited Microsoft source still resolves, and whether it has changed since the
    rule citing it was written.

.PARAMETER RuleFile
    Assess using rules from this JSON file. Rules sharing an id with a built-in replace it, so one
    check can be corrected without restating the rest.

.PARAMETER ExportRules
    Write the built-in rules and citations to this path and stop. Edit that file and pass it back
    with -RuleFile.

.PARAMETER PassThru
    Returns the findings as objects so you can filter or pipe them.

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
    Microsoft guidance, and every check here links the page it came from. This script is not a
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
    [ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD', 'China')][string]$Environment = 'Commercial',
    [ValidateSet('InformationProtection', 'DataLossPrevention', 'DataLifecycleManagement', 'RecordsManagement', 'CommunicationCompliance', 'InsiderRisk', 'Audit')][string[]]$Solution = @(),
    [switch]$Brief,
    [switch]$SkipConnect,
    [switch]$KeepSignedIn,
    [switch]$SkipModuleInstall,
    [switch]$IncludeSites,
    [int]$SiteLimit = 200,
    [switch]$RedactTenant,
    [switch]$SkipInsights,
    [ValidateRange(1, 30)][int]$InsightDays = 30,
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
    [switch]$PassThru
)

# Windows PowerShell parses this whole file before running any of it, so everything here must stay
# 5.1-parseable for the relaunch below to be reachable at all.
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

    $pwsh = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1

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

# Recorded in the snapshot, the findings and every posture record, so a report kept for months can
# still be traced to the checks that produced it and a delta can tell a rule change from a tenant one.
$script:ToolVersion = '1.63.10'

# Anything the run creates and must undo before it exits.
$script:OwnedSession = @()
$script:OwnedCompatibilitySession = @()
$script:OwnedCompatibilityModule = @()
$script:TempArtifact = @()

# Kept so a connection failure can report the actual module load result rather than replacing it
# with a generic platform message.
$script:PrerequisiteModuleResult = @()

# Whether a cmdlet exists, remembered for the run. Emptied whenever a connect could change it.
$script:CommandCache = @{}

# Which loaded module belongs to which connection. Resolving it walks every connection and every
# module, and every collector asks, so the answer is kept until a connect can change it.
$script:ServiceModuleCache = @{}

# The Microsoft pages cited from more than one place. Held once so a page that moves is corrected
# once, rather than in whichever copies someone remembers to look for.
$script:DocUrl = [ordered]@{
    SharePointLabelledFiles = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    AutoLabelling = 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically'
    AuditLogEnable = 'https://learn.microsoft.com/purview/audit-log-enable-disable'
    GraphSubscribedSku = 'https://learn.microsoft.com/graph/api/subscribedsku-list?view=graph-rest-1.0'
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

    $colour = switch ($Style) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad' { 'Red' }
        'Head' { 'Cyan' }
        'Dim' { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host $Message -ForegroundColor $colour -NoNewline:$NoNewline
}

function Write-PurviewStep {
    <#
    .SYNOPSIS
        Names the step before it runs, then completes the line when it finishes.

    .DESCRIPTION
        A tenant call can take a minute with nothing to show for it, so the name is written before
        the call rather than after. Without that the console looks hung.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Position = ''
    )

    Write-Line -Style Dim -Message ('    {0,-8}{1,-34}' -f $Position, $Name) -NoNewline
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
        'AlreadyConnected' { 'Good' }
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
# Instants are stored ISO 8601 with an explicit offset, which keeps them absolute and comparable.
# They are displayed in the time zone of whoever runs the script, resolved at runtime, because an
# assessment captured by one person is routinely read by another in a different region.

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
            # Invariant rather than current culture: the report is written in English throughout,
            # and a date rendered in the operator's locale reads as a defect inside it.
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
# A Purview cmdlet does not return an identical property set in every tenant, and strict mode turns
# a missing property into a terminating error. Absence is reported as absence, never defaulted to a
# value that would imply a finding the tenant never exhibited.

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
        Note = 'Each cmdlet used was confirmed by fetching its reference page and matching the page heading to the cmdlet name.'
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
        Note = 'Global Reader is the read-only counterpart of Global Administrator.'
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
        Note = 'Microsoft Graph PowerShell caches the token and stays signed in across PowerShell sessions until this is called, which is why a run signs out of what it signed in to. Disconnect-ExchangeOnline is documented as closing Connect-IPPSSession connections, and Disconnect-SPOService closes the SharePoint connection.'
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
        Note = 'Auto-labeling applies labels without relying on users, including to content already at rest.'
    }
    'EV-RETENTION-001' = @{
        Title = 'Retention cmdlets'
        Url = 'https://learn.microsoft.com/purview/retention-cmdlets'
        RetrievedAt = '2026-08-20'
        ContentHash = 'B19E14C670FD7736551985EE5DFD9509'
        Status = 'GA'
        Note = 'Reference for the retention policy and retention label cmdlets used to read lifecycle configuration.'
    }
    'EV-AUDIT-001' = @{
        Title = 'Manage audit log retention policies'
        Url = 'https://learn.microsoft.com/purview/audit-log-retention-policies'
        RetrievedAt = '2026-08-20'
        ContentHash = 'C06D2CB6959C7AE35744AE56929F3FED'
        Status = 'GA'
        Note = 'Audit log retention policies control how long audit records are kept beyond the default.'
    }
    'EV-COMMCOMP-001' = @{
        Title = 'Communication compliance reports and audits'
        Url = 'https://learn.microsoft.com/purview/communication-compliance-reports-audits'
        RetrievedAt = '2026-08-20'
        ContentHash = '35C08E35B5955097AB576922B433671C'
        Status = 'GA'
        Note = 'Communication compliance policies detect regulatory and conduct violations across communication channels.'
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
        Note = 'Site permission state reports quantify Copilot exposure. The first report takes up to five days and can be regenerated only every 30 days, so this script reads results rather than requesting them.'
    }
    'EV-DSPM-PORTAL-001' = @{
        Title = 'Prevent oversharing with data risk assessments from Data Security Posture Management'
        Url = 'https://learn.microsoft.com/purview/data-security-posture-management-oversharing'
        RetrievedAt = '2026-08-21'
        ContentHash = '8532B62962FD203929119B81099CD0DB'
        Status = 'GA'
        Note = 'Data risk assessments are reached through the Microsoft Purview portal. No cmdlet or Graph endpoint for them is documented, so their results are not collected.'
    }
    'EV-SBD-PREREQ-001' = @{
        Title = 'Secure by default: turn on data security prerequisites and advanced analytics'
        Url = 'https://learn.microsoft.com/purview/deploymentmodels/depmod-secure-by-default-step1'
        RetrievedAt = '2026-08-21'
        ContentHash = 'FE53E5E83F31BD6F838D59EB83DB4B2F'
        Status = 'GA'
        Note = 'Lists the tenant opt-ins that are off by default. It states explicitly that the label mismatch email is kept by verifying BlockSendLabelMismatchEmail is set to False, which is why that setting is checked for False rather than True.'
    }
    'EV-PURVIEW-REPORTS-001' = @{
        Title = 'Microsoft Purview posture reports overview'
        Url = 'https://learn.microsoft.com/purview/purview-reports'
        RetrievedAt = '2026-08-21'
        ContentHash = 'CF15EBB77C2FBB15DDEB93C6E9B0B18C'
        Status = 'Preview'
        Note = 'Posture reports are portal-only and in preview. They draw on activity explorer and content explorer, which this script reads directly instead.'
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
        Note = 'Assigning at least one Microsoft Copilot license grants the Copilot-supporting capabilities, and the oversharing controls are among them: permission state reports, Everyone except external users insights, sharing links, and sensitivity labels for files. Others, restricted site creation by apps being the documented example, need the SharePoint Advanced Management Plan 1 add-on. An E5 base subscription alone does not unlock it.'
    }
    'EV-DEFAULT-TAXONOMY-001' = @{
        Title = 'Default sensitivity labels and policies to protect your data'
        Url = 'https://learn.microsoft.com/purview/default-sensitivity-labels-policies'
        RetrievedAt = '2026-08-21'
        ContentHash = 'CF11AFC417A880654B4F848366E9C7E4'
        Status = 'GA'
        Note = 'Documents the default tiers Personal, Public, General, Confidential and Highly Confidential. Used as a reference to compare against, not a target: a different taxonomy is a design choice, not a defect.'
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
        id = 'PA-IP-0001'
        version = '1.0.0'
        title = 'Sensitivity label priority'
        solutionArea = 'SensitivityLabels'
        severity = 'High'
        rationale = 'Labels are evaluated by their position in the list, with the most restrictive at the bottom, and where more than one could apply the last one wins. That same order defines what counts as a downgrade, which is what triggers a justification prompt. Two labels sharing a priority leave both outcomes undefined.'
        recommendation = 'Give each label a distinct priority so precedence is deterministic.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{ type = 'noDuplicatesOf'; field = 'Priority' }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-IP-0002'
        version = '1.1.0'
        title = 'Sensitivity label naming'
        solutionArea = 'SensitivityLabels'
        severity = 'Medium'
        rationale = 'A label is presented to users by its display name. Two labels competing in the same picker under the same name are indistinguishable at the point of choosing one, and in any report of what was applied afterwards. Sublabels are compared only against their siblings, because the documented default taxonomy repeats a name under more than one label group and Confidential\All Employees is distinct from Highly Confidential\All Employees.'
        recommendation = 'Rename all but one within each label group so that label pickers and reports stay unambiguous.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{ type = 'noDuplicatesOf'; field = 'Name'; within = 'ParentId'; withinLabel = 'label group' }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'secure-by-default step 1'
    }
    @{
        id = 'PA-IP-0003'
        version = '1.0.0'
        title = 'Label publishing policies'
        solutionArea = 'LabelPolicies'
        severity = 'Critical'
        rationale = 'A label does nothing until a label policy publishes it to users or groups. The policy is also what sets a default label, whether justification is required to downgrade, and whether labelling is mandatory. Changes to it reach users within 24 hours.'
        recommendation = 'Publish at least one label publishing policy to the users or groups who should be able to apply labels.'
        condition = @{
            collector = 'SensitivityLabelPolicy'
            select = 'Policies'
            where = @{ field = 'Enabled'; operator = 'eq'; value = $true }
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Until this tenant opt-in is enabled, SharePoint and OneDrive cannot process the contents of a file that a label encrypted. Search does not index it, eDiscovery cannot full-text search it, DLP cannot inspect it, and it cannot be co-authored or opened in Office for the web. The encryption itself still holds; what stops is every service that needs to read inside the file.'
        recommendation = 'Turn on EnableAIPIntegration for the tenant. Files labelled and encrypted before that only gain the capability once they are edited, or downloaded and uploaded again.'
        remediationCommand = 'Set-SPOTenant -EnableAIPIntegration $true'
        condition = @{
            collector = 'SharePointLabelingReadiness'
            select = 'Settings'
            where = @{ field = 'Name'; operator = 'eq'; value = 'EnableAIPIntegration' }
            assert = @{ type = 'allHave'; where = @{ field = 'Enabled'; operator = 'eq'; value = $true } }
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
        rationale = 'Several Purview capabilities are deliberately off until a tenant turns them on, so that adopting Purview does not change behaviour for users overnight. The consequence is that a tenant can look configured while labels are never processed for PDFs, no owner is told when a document is more sensitive than the site holding it, and new uploads are treated as safe before they have been scanned.'
        recommendation = 'Work through the Prerequisites and Tenant Opt-ins section of this report, which lists each switch with its current value, the value Microsoft recommends, and the consequence of leaving it as it stands.'
        condition = @{
            collector = 'SharePointLabelingReadiness'
            select = 'Settings'
            assert = @{ type = 'allHave'; subject = 'the value Microsoft recommends'; where = @{ field = 'AsRecommended'; operator = 'eq'; value = $true } }
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
        rationale = 'Microsoft documents four states for a policy: on, simulation without policy tips, simulation with policy tips, and off. In simulation a Block action is downgraded to Audit at runtime, so the policy records what it would have done and does none of it. All four appear the same way in the policy list.'
        recommendation = 'Review the policies still in test mode and move the validated ones into enforcement.'
        condition = @{
            collector = 'DataLossPrevention'
            select = 'Policies'
            where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' }
            assert = @{ type = 'isNotEmpty' }
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
        version = '1.1.0'
        title = 'Endpoint DLP coverage'
        solutionArea = 'EndpointDlp'
        severity = 'Medium'
        rationale = 'Endpoint DLP is what covers copying to a USB device or network share, printing, pasting into a browser, uploading to an unapproved cloud service, and access by restricted apps. A policy scoped to Exchange, SharePoint and Teams reaches none of those, because those locations govern content held in the service rather than what someone does with it on a device.'
        recommendation = 'Extend at least one DLP policy to the Devices location, and onboard the devices it should reach.'
        condition = @{
            collector = 'DataLossPrevention'
            select = 'Policies'
            where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' }
            assert = @{
                type = 'anyHave'
                subject = 'an enforcing policy that reaches the Devices location'
                where = @{ field = 'Workload'; operator = 'eq'; value = 'EndpointDevices' }
            }
        }
        licensing = @{
            capability = 'Endpoint DLP'
            includedIn = @('SPE_E5')
            addOns = @('CAPABILITY_PURVIEW_E5_COMPLIANCE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-M365MAPS-001')
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
        rationale = 'Audit (Premium) retains Exchange, SharePoint, OneDrive and Microsoft Entra records for one year by default and all other activity for 180 days, and that default applies only to users holding an E5 or Purview Suite licence. A custom policy is how a longer period, or a specific record type, is retained beyond that. Microsoft documents retention of up to 10 years, and a custom policy always takes priority over the default.'
        recommendation = 'Create an audit log retention policy covering the record types and duration your investigations require.'
        condition = @{
            collector = 'AuditConfiguration'
            select = 'RetentionPolicies'
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Sensitivity labels are what auto-labeling policies apply, what a DLP policy can use as a condition, and what a container label attaches to a site, Team or group. With none defined, none of those can reference a classification.'
        recommendation = 'Create a label taxonomy, starting with the default set, before configuring policies that depend on labels.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Labelling that depends entirely on users is applied inconsistently, and content already at rest stays unlabelled until somebody opens it and chooses a label. Auto-labeling policies classify existing and incoming content on the service side, which is what makes coverage predictable rather than best-effort.'
        recommendation = 'Create auto-labeling policies for the sensitive information types that matter most, starting in simulation to assess the impact.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Simulation is a required stage rather than a fault, but a tenant where every policy is still simulating applies no labels at all. The policy list appears identical either way, so a rollout that stalled after the pilot appears complete until each policy''s mode is examined.'
        recommendation = 'Review the simulation results and turn on the policies that are labelling what you expected.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{ type = 'anyHave'; where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' } }
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
        rationale = 'A policy in the off state is inactive: it evaluates nothing and takes no action, while still appearing in the policy list beside policies that are enforcing. The list alone does not distinguish the two.'
        recommendation = 'Re-enable the policies that are still needed and delete the ones that are not, so the policy list reflects actual coverage.'
        condition = @{
            collector = 'DataLossPrevention'
            select = 'Policies'
            assert = @{ type = 'noneHave'; where = @{ field = 'Mode'; operator = 'eq'; value = 'Disable' } }
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
        rationale = 'A retention policy applies retention or deletion across an entire location, such as all Exchange mailboxes or all SharePoint sites. Retention policies are also the only mechanism covering Teams, Viva Engage and public folders. Without one, what is kept and what is deleted is left to each user. A policy that is enabled is not necessarily acting: one left in test mode reports matches without retaining or deleting anything. Policies covering Copilot and other AI apps are created and read separately, and retain nothing in these locations, so they do not count towards this.'
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
            assert = @{ type = 'isNotEmpty' }
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
        version = '1.0.0'
        title = 'Retention labels'
        solutionArea = 'RecordsManagement'
        severity = 'Medium'
        rationale = 'A retention policy applies to a whole location; a retention label applies to an individual item and travels with it when it moves inside the tenant. Only labels support event-based retention, disposition review, marking an item as a record, and proof of disposition once it is deleted.'
        recommendation = 'Create retention labels for the document types your retention schedule treats differently, and publish them.'
        condition = @{
            collector = 'RetentionLabel'
            select = 'Labels'
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{ capability = 'Retention labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001')
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
        rationale = 'A standard retention label still permits an item to be edited, moved, relabelled or deleted. Declaring it a record blocks editing, deletion and label changes, and records proof of disposition when it is finally deleted. A regulatory record goes further: contents, properties and the label itself cannot be changed by anyone, including a global administrator.'
        recommendation = 'If your obligations include immutable retention, mark the relevant retention labels as records. If they do not, this finding can be dismissed.'
        condition = @{
            collector = 'RetentionLabel'
            select = 'Labels'
            where = @{ field = 'IsRecordLabel'; operator = 'eq'; value = $true }
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Communication compliance helps detect messages that breach policy, covering regulatory obligations such as FINRA Rule 3110 along with harassment, threats, profanity and sensitive information shared in messages. It covers Teams, Exchange Online, Viva Engage and third-party sources, and generative AI interactions including Microsoft 365 Copilot. This check establishes only that a policy is configured; the available policy object does not establish current inspection, health or last scan.'
        recommendation = 'If you are subject to supervision obligations or want conduct detection, configure at least one communication compliance policy and confirm its current state in the portal. Otherwise dismiss this finding.'
        condition = @{
            collector = 'CommunicationCompliance'
            select = 'Policies'
            assert = @{ type = 'isNotEmpty' }
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
        rationale = 'Classification needs at least two tiers to carry meaning, because a single label divides nothing. This is judged on structure rather than names: the documented default tiers are a reference to compare against, and an organisation naming or shaping its taxonomy differently is making a design choice, not a mistake.'
        recommendation = 'Publish at least two sensitivity labels so content can be separated by sensitivity. Compare your tiers against the default taxonomy in the report, treating differences as choices to confirm rather than gaps to close.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{ type = 'countGreaterThan'; value = 1 }
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
        rationale = 'Unified audit logging is the record every other solution reads from. With it off, activity explorer, insider risk, eDiscovery and Copilot interaction history have nothing to draw on, and the gap is not retrospective: activity during the period it was off is never recorded and cannot be recovered later.'
        recommendation = 'Turn on auditing in the Microsoft Purview portal, or run Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true in Exchange Online PowerShell.'
        condition = @{
            collector = 'AuditIngestion'
            select = 'Settings'
            assert = @{ type = 'allHave'; where = @{ field = 'Enabled'; operator = 'eq'; value = $true } }
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
        rationale = 'A DLP policy holds no conditions or actions of its own; its rules do. A policy with no rules appears in the Purview portal as though it were protecting content while matching nothing at all.'
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
        rationale = 'A disabled rule inside an enforcing policy leaves no visible trace: the policy still reports as on, while the specific condition that rule covered is no longer evaluated.'
        recommendation = 'Enable the rule, or delete it if it is no longer wanted, so the policy and its behaviour agree.'
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
        rationale = 'The types Microsoft ships cover regulated identifiers that look the same everywhere, and every tenant has them, so their presence says nothing about this organisation. They do not know your contract numbers, customer identifiers or product code names, so data that is sensitive specifically here stays invisible to every policy that relies on classification.'
        recommendation = 'Build custom sensitive information types, exact data match schemas or trainable classifiers for the data that is sensitive to this organisation specifically.'
        condition = @{
            collector = 'Classification'
            select = 'SensitiveInformationTypes'
            # Anything Microsoft published is out of scope: it is identical in every tenant.
            where = @{ field = 'Publisher'; operator = 'ne'; value = 'Microsoft Corporation' }
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{ capability = 'Classification'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'Low'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know Your Data'
        deploymentModel = 'dspm step 1'
    }
)

# The tenant opt-ins Secure by default step 1 asks for. These are deliberately off until somebody
# turns them on, so a tenant can look configured while labels are never processed. Items with a
# collector are read; items with only a portal path cannot be read by any documented interface, and
# saying so beats leaving them out and implying they were checked.
$script:Prerequisite = @(
    @{
        Name = 'Devices onboarded to Microsoft Purview'
        DeviceHealth = $true
        Portal = 'Purview portal > Settings > Device onboarding > Devices, then turn on Windows or macOS device monitoring'
        Why = 'Endpoint DLP and Insider Risk Management both need a device onboarded before either receives any data from it. Once onboarded, the device reports copying to removable media or a network share, printing, pasting into a browser and uploading to restricted domains. Onboarding is shared with Defender for Endpoint, so devices already there need none, but Microsoft documents turning device monitoring on as its own step.'
        Url = 'https://learn.microsoft.com/purview/device-onboarding-overview'
    }
    @{
        Name = 'Labels processed for Office files in SharePoint and OneDrive'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableAIPIntegration'
        Recommended = 'Set-SPOTenant -EnableAIPIntegration $true'
        Command = 'Set-SPOTenant -EnableAIPIntegration $true'; Session = 'SharePoint'
        Why = 'This lets SharePoint process the contents of labelled and encrypted files in SharePoint and OneDrive. Until it is on, those files are stored but not processed, so search, eDiscovery, DLP and co-authoring cannot act on them. The label still applies in Outlook and the desktop apps.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on PDF files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforPDF'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it adds PDF support for applying a label in Office for the web, extracting and displaying the label on an uploaded file, search, eDiscovery and data loss prevention, and auto-labeling policies and default document library labels. Without it, none of those apply to a PDF.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on OneNote sections'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforOneNote'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it allows a sensitivity label to be applied manually to a OneNote section across endpoints. Without it, OneNote content cannot carry a sensitivity label.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Labels on MP4 video files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelForVideoFiles'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it allows a sensitivity label to be applied to video files in SharePoint, and the label on an uploaded file to be extracted and displayed. Meeting recordings are stored as ordinary files and cannot carry a label without it.'
        Url = $script:DocUrl.SharePointLabelledFiles
    }
    @{
        Name = 'Label mismatch email to uploader and site owners'
        Collector = 'SharePointLabelingReadiness'; Setting = 'BlockSendLabelMismatchEmail'
        Recommended = 'Leave off: Set-SPOTenant -BlockSendLabelMismatchEmail $false'
        Command = 'Set-SPOTenant -BlockSendLabelMismatchEmail $false'; Session = 'SharePoint'
        Why = 'Where a document carries a higher-priority label than the site holding it, SharePoint records a mismatch audit event and emails the uploader and the site owners. That notification is what brings a mismatch to someone who can act on it rather than leaving it in the audit log.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites'
    }
    @{
        Name = 'Default labels on document libraries'
        Collector = 'SharePointLabelingReadiness'; Setting = 'DisableDocumentLibraryDefaultLabeling'
        Recommended = 'Leave off: Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'
        Command = 'Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'; Session = 'SharePoint'
        Why = 'A document library can carry a default sensitivity label, so every file added is labelled on arrival instead of waiting for someone to choose. That is the difference between new content protected by default and protected only when a user remembers. Turning this off removes the option from library settings.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-default-label'
    }
    @{
        Name = 'Sensitive by default for new files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'MarkNewFilesSensitiveByDefault'
        Recommended = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'
        Command = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'; Session = 'SharePoint'
        Why = 'Where external sharing is on, sensitive content can be shared and accessed by guests before the Office DLP rule finishes processing the file. BlockExternalSharing prevents guests from accessing a newly added file until at least one Office DLP policy has scanned its content. AllowExternalSharing disables that protection.'
        Url = 'https://learn.microsoft.com/sharepoint/sensitive-by-default'
    }
    @{
        Name = 'Co-authoring for files encrypted with sensitivity labels'
        Collector = 'TenantPolicyConfig'; Setting = 'EnableLabelCoauth'; ExpectedValue = 'True'
        Recommended = 'Purview portal > Settings > Information Protection > Co-authoring for files with sensitivity labels, then select "Turn on co-authoring for files with sensitivity labels"'
        Command = 'Set-PolicyConfig -EnableLabelCoauth $true'; Session = 'SecurityAndCompliance'
        Caution = 'One way in the portal: once on, it can only be turned off with Set-PolicyConfig -EnableLabelCoauth:$false, and Microsoft documents that doing so loses the newer labelling metadata for unencrypted Word, Excel and PowerPoint files. Turning it on also enables sensitivity labels for Office files in SharePoint and OneDrive if that is not already on.'
        Why = 'Co-authoring allows multiple users to edit a file encrypted by a sensitivity label simultaneously, in the desktop, web and mobile applications, with AutoSave available. Without it, such files can be edited by one user at a time and AutoSave does not function.'
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
        Why = 'Container labels protect a Team, Microsoft 365 group, SharePoint site, Viva Engage community or Loop workspace through privacy, external user access, external sharing, access from unmanaged devices, authentication contexts and private team discovery. Items inside do not inherit the label, so nothing in the container is encrypted or marked by it. Until this directory setting is on, those settings are visible on a label but cannot be configured, and containers keep using the older Microsoft Entra classification property instead.'
        Url = 'https://learn.microsoft.com/entra/identity/users/groups-assign-sensitivity-labels'
    }
    @{
        Name = 'Unified audit logging'
        RuleId = 'PA-AUD-0002'
        Summary = 'Auditing is off, so the activity record every other Purview solution reads from is not being written.'
        SummaryOk = 'Auditing is on, so user and admin activity is being recorded.'
        Recommended = 'Purview portal > Audit, then select "Start recording user and admin activity"'
        Why = 'Auditing is on by default for enterprise tenants, but not for Small and Medium Business licences or unmanaged trials. Where it is off, audit search returns nothing and that period is never recorded and cannot be recovered. Audit (Standard) keeps records for 180 days; Audit (Premium) keeps one year, extendable to 10.'
        Url = $script:DocUrl.AuditLogEnable
    }
    @{
        Name = 'Teams DLP policies extended to SharePoint and OneDrive'
        # The property read back is not the parameter that sets it: Get-PolicyConfig returns
        # ExtendTeamsDlpToSpoOdbConsent, while Set-PolicyConfig takes the longer name below.
        Collector = 'TenantPolicyConfig'; Setting = 'ExtendTeamsDlpToSpoOdbConsent'; ExpectedValue = 'True'
        Recommended = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'
        Command = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'; Session = 'SecurityAndCompliance'
        Why = 'A file shared in a Teams chat is stored in the sender''s OneDrive account and linked from the message. A DLP policy scoped only to Teams therefore evaluates the message but not the stored copy. Extending Teams policies to SharePoint and OneDrive brings that copy within the same policy scope.'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-policyconfig'
    }
    @{
        Name = 'DLP analytics'
        Evidence = @{
            Collector = 'DataLossPrevention'; Select = 'Policies'; Field = 'Name'; Match = '^RiskSpotlighting-'
            FoundState = 'Evidence found'
            Found = 'At least one DLP analytics recommendation was found. This proves analytics produced evidence, but not that it is currently on; recommendations take seven days to appear.'
            NotFound = 'No analytics recommendation was found. That does not mean analytics is off, since recommendations take seven days and need not be accepted. Confirm in the portal.'
        }
        Portal = 'Purview portal > Settings > Data Loss Prevention > Analytics, then turn on "Activate analytics"'
        Why = 'DLP analytics reports the top oversharing risks, blind spots and policy improvements from the last 30 days, and can create or refine a policy from what it finds. It is off by default. Recommendations appear seven days after it is turned on, then refresh weekly.'
        Url = 'https://learn.microsoft.com/purview/dlp-analytics-get-started'
    }
    @{
        Name = 'Insider risk analytics'
        Portal = 'Purview portal > Settings > Insider Risk Management > Analytics, then turn on "Show insights at tenant level"'
        Why = 'Analytics scores insider risk before any policy exists, and the results say which policy types to configure and how widely to scope them. Findings come back aggregated and anonymised, so no individual is identifiable. First insights take up to 48 hours.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-analytics'
    }
    @{
        Name = 'Insider risk data shared with other security solutions'
        Evidence = @{
            Collector = 'InsiderRiskSharing'; Select = 'Behaviors'
            FoundState = 'Seen recently'
            Found = 'Insider risk detail reached the Defender alert queues during the last 30 days. This does not establish the sharing setting''s present state.'
            NotFound = 'No insider risk detail was recorded in Defender during the last 30 days. That does not mean sharing is off, since a tenant with nothing to report looks the same. Confirm in the portal.'
        }
        Optional = $true
        Portal = 'Purview portal > Settings > Insider Risk Management > Data sharing, then turn on "Share user risk details with other security solutions"'
        Why = 'This makes the insider risk severity already calculated for a user visible in the alert queues of Defender XDR, Communication Compliance and DLP, so an analyst sees that user''s recent exfiltration activity beside the alert. Where it is off, those queues report the data as unavailable. It enforces nothing.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-share-data'
    }
    # Three Microsoft Defender for Cloud Apps settings, not Purview ones, but they decide how far
    # Purview labelling and DLP reach SaaS files. Only the connector leaves a documented read-only
    # signal, the CloudAppEvents hunting table; file monitoring and the label integration are
    # portal-only.
    @{
        Name = 'Defender for Cloud Apps: Microsoft 365 app connector'
        Evidence = @{
            Collector = 'CloudAppConnector'; Select = 'Connectors'
            FoundState = 'Seen recently'
            Found = 'Microsoft 365 activity from the Defender for Cloud Apps app connector was recorded during the last 30 days. This does not establish the connector''s present status or health.'
            NotFound = 'No Microsoft 365 app-connector activity was recorded during the last 30 days. That does not mean the connector is off, since an idle or undeployed tenant looks the same. Confirm in the portal.'
        }
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > App Connectors, then confirm the Microsoft 365 connector reads Connected'
        Why = 'Connecting Microsoft 365 to Defender for Cloud Apps is what gives it visibility over SharePoint, OneDrive, Teams and Exchange, and it is the prerequisite for file monitoring and file policies over that content. The connector status and last health check appear only in the Defender portal. CloudAppEvents can show that the app connector ingested Microsoft 365 activity during the measured period, but cannot establish its status or health now.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/connect-office-365'
    }
    @{
        Name = 'Defender for Cloud Apps: file monitoring'
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Files, then confirm "Enable file monitoring" is selected'
        Why = 'File monitoring grants Defender for Cloud Apps access to the files in connected apps so its file policies can scan them. It is off until enabled, and Microsoft documents it as switching itself off after seven days with no enabled file policy. It underpins Defender for Cloud Apps file policies rather than the native SharePoint and OneDrive scanning Purview already performs.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/data-protection-policies'
    }
    @{
        Name = 'Defender for Cloud Apps: sensitivity label integration'
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Microsoft Information Protection'
        Why = 'These settings let Defender for Cloud Apps scan new files for Purview sensitivity labels, and optionally disregard labels applied by external tenants. This is Defender for Cloud Apps consuming Purview Information Protection, and the two checkboxes are configured and read only in the Defender portal.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/content-inspection'
    }
    @{
        Name = 'Defender for Cloud Apps: inspect protected files'
        Evidence = @{
            Collector = 'ProtectedFilesConsent'; Select = 'Grants'
            FoundState = 'Granted'
            Found = 'The Microsoft Cloud App Security service principal holds the protected-content app role, so the inspect-protected-files consent has been granted.'
            NotFound = 'No protected-content grant was found on the Microsoft Cloud App Security service principal. That does not prove it is ungranted, since a tenant without Defender for Cloud Apps deployed looks the same. Confirm in the portal.'
        }
        Portal = 'Microsoft Defender portal > Settings > Cloud apps > Microsoft Information Protection > Inspect protected files, then select Grant permission'
        Why = 'Inspecting protected files lets Defender for Cloud Apps file policies read labels and content inside files a sensitivity label has encrypted. It needs a one-time Global Administrator consent that grants the Microsoft Cloud App Security app the Azure Rights Management super-user right, which is highly privileged because it can decrypt protected content. The consent is granted only in the portal; this assessment only reads whether it is in place.'
        Url = 'https://learn.microsoft.com/defender-cloud-apps/content-inspection'
    }
    @{
        Name = 'Modern label scheme'
        LabelScheme = $true
        Script = @{
            Builder = 'ParentLabelPublishing'
            File = 'Export-ParentLabelPublishing.ps1'
            Session = 'SecurityAndCompliance'
            Prompt = 'Run this before starting the migration in the portal'
        }
        Portal = 'Purview portal > Solutions > Information Protection > Sensitivity labels, then select "Get started" on the "Migrate to the modern label scheme" banner'
        Why = 'Parent labels built a two-tier hierarchy. Label groups replace them and hold nothing but a name, description, colour and priority. Where a parent label carried settings, migration also creates a sublabel of the same name so existing use keeps working. It runs from the portal in minutes and cannot be undone.'
        Caution = 'Migration is irreversible. Microsoft recommends testing it first in a tenant with the same label configuration.'
        Url = 'https://learn.microsoft.com/purview/migrate-sensitivity-label-scheme'
    }
)

#endregion

#region Prerequisites
# Installing a module changes this machine, not the tenant. The read-only guarantee concerns tenant
# configuration and is unaffected: these modules only supply the Get-* cmdlets collection calls.

function Get-PurviewRequiredModule {
    <# .SYNOPSIS The modules live collection depends on, and how each must be loaded. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject]@{
            Name = 'ExchangeOnlineManagement'
            Service = 'Security & Compliance'
            Connect = 'Connect-IPPSSession'
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
        [pscustomobject]@{
            Name = 'Microsoft.Graph.Authentication'
            Service = 'Microsoft Graph'
            Connect = 'Connect-MgGraph -Scopes LicenseAssignment.Read.All, GroupSettings.Read.All'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
            MinimumVersion = ''
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

    # Hides PowerShellGet's progress bar and its warning that PackageManagement is already loaded.
    $quiet = {
        param([scriptblock]$Action)
        $was = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { & $Action } finally { $ProgressPreference = $was }
    }

    foreach ($module in Get-PurviewRequiredModule) {
        $outcome = [ordered]@{ Name = $module.Name; Service = $module.Service; Connect = $module.Connect; State = 'Unknown'; Detail = ''; Version = '' }

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

            if (-not $PSCmdlet.ShouldProcess($module.Name, 'Install from PSGallery for the current user')) {
                $outcome.State = 'Missing'
                $outcome.Detail = 'Installation was declined.'
                $plan.Add([pscustomobject]@{ Module = $module; Outcome = $outcome; Import = $false })
                continue
            }

            try {
                & $quiet { Install-Module -Name $module.Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue }
                $outcome.State = 'Installed'
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

            # An old module fails by lacking a parameter, which reads like a tenant fault rather than
            # a machine one. So check the version, not just that something is installed.
            $floor = if ($module.MinimumVersion) { [version]$module.MinimumVersion } else { $null }
            $stale = $null -ne $floor -and $installed -lt $floor

            # No point asking the gallery when this run cannot offer the update.
            $canAsk = $AllowPrompt -and -not [Console]::IsInputRedirected
            $latest = $null
            if (-not $SkipInstall -and $canAsk) {
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
                Write-Line -Style Dim -Message ('    Updating {0}.' -f $module.Name)
                try {
                    & $quiet { Update-Module -Name $module.Name -Force -ErrorAction Stop -WarningAction SilentlyContinue }
                    $outcome.State = 'Updated'
                }
                catch {
                    # A copy installed from the Download Center cannot be updated in place, so
                    # install the gallery version alongside it.
                    try {
                        & $quiet { Install-Module -Name $module.Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue }
                        $outcome.State = 'Updated'
                    }
                    catch {
                        if ($stale) { $outcome.State = 'Outdated' }
                        $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
                    }
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

    # Import order does not decide which sign-in library loads: .NET loads one on first use, which
    # is a connect, not an import. Graph goes first only so its files are in place beforehand.
    $order = @($plan | Sort-Object @{ Expression = { if ($_.Module.Name -eq 'Microsoft.Graph.Authentication') { 0 } else { 1 } } })
    foreach ($item in $order) {
        $outcome = $item.Outcome
        if (-not $item.Import) { continue }

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

    # Updating replaces files that a later import loads, and a sign-in library loads once per
    # process. Cheaper to say so than to leave someone reading an assembly error.
    if (@($results | Where-Object { $_.State -eq 'UpdatedAndLoaded' }).Count -gt 0) {
        Write-Line -Style Dim -Message '    A module was updated. If sign-in misbehaves, start a new PowerShell session and run this again.'
    }

    $script:PrerequisiteModuleResult = $results.ToArray()
    return $script:PrerequisiteModuleResult
}

function Test-PurviewConnected {
    <# .SYNOPSIS Reports whether a service already has a usable session, so it is not signed in twice. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][ValidateSet('SecurityAndCompliance', 'SharePoint', 'Graph', 'ExchangeOnline')][string]$Service)

    try {
        switch ($Service) {
            # Connect-IPPSSession imports its cmdlets on success, so their presence is the signal.
            'SecurityAndCompliance' { return (Test-PurviewCommand -Name 'Get-Label') }
            'ExchangeOnline' {
                if (-not (Test-PurviewCommand -Name 'Get-ConnectionInformation')) { return $false }
                # The connection name distinguishes Exchange Online from the compliance session.
                return @(Get-ConnectionInformation -ErrorAction Stop |
                        Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -like 'ExchangeOnline_*' }).Count -gt 0
            }
            'Graph' {
                if ($script:GraphSeparate) { return $true }
                if (-not (Test-PurviewCommand -Name 'Get-MgContext')) { return $false }
                $context = Get-MgContext -ErrorAction Stop
                if ($null -eq $context) { return $false }

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
        Turns what people actually type into a SharePoint admin URL.

    .DESCRIPTION
        Accepts a tenant name, a portal URL, or the non-admin hostname, because those are the
        answers a prompt for an "admin URL" reliably gets. Anything unrecognised is returned as
        given rather than mangled.
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
        Who signed in, and what they hold across Entra and Purview.

    .DESCRIPTION
        Read with the consent the run already has. Microsoft documents User.Read as the least
        privileged permission for the signed-in user's own memberships, so the Entra roles come
        back without widening what was asked for, and no other account is ever queried.

        Purview role groups sit behind the Role management role. Where the sign-in does not hold
        it the cmdlet is not surfaced at all, and that absence is reported as unread rather than
        as holding nothing, because the two are not the same thing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $account = Get-PurviewSignedInAccount
    $display = ''
    $objectId = ''
    $tenant = ''
    $scopes = @()

    if (Test-PurviewCommand -Name 'Get-MgContext') {
        try {
            $context = Get-MgContext -ErrorAction Stop
            $tenant = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
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
    if ((Test-PurviewCommand -Name 'Invoke-MgGraphRequest') -and (Test-PurviewConnected -Service 'Graph')) {
        try {
            # Without this object id, no Purview role group membership can be matched.
            $me = if ($script:GraphSeparate) { Invoke-PurviewGraphInNewSession -Verb 'GET' -Uri '/v1.0/me?$select=id,displayName,userPrincipalName' }
            else {
                Invoke-MgGraphRequest -Method GET -Uri '/v1.0/me?$select=id,displayName,userPrincipalName' `
                    -OutputType PSObject -ErrorAction Stop
            }
            $display = [string](Get-PurviewProperty -InputObject $me -Name 'displayName')
            $objectId = [string](Get-PurviewProperty -InputObject $me -Name 'id')
            if (-not $account) { $account = [string](Get-PurviewProperty -InputObject $me -Name 'userPrincipalName') }
        }
        catch { Write-Verbose "The directory did not name the signed-in user: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }

        try {
            $returned = 0
            foreach ($role in @(Invoke-PurviewGraphGet -Uri '/v1.0/me/memberOf/microsoft.graph.directoryRole')) {
                $returned++
                $name = [string](Get-PurviewProperty -InputObject $role -Name 'displayName')
                if ($name) { $entra.Add($name) }
            }

            # Microsoft documents that a directory object the sign-in cannot read comes back anyway,
            # carrying only its type and id with every other property null. Roles arriving nameless
            # therefore means they are held but unreadable, which is not the same as holding none.
            $entraUnnamed = $entra.Count -eq 0 -and $returned -gt 0
            $entraRead = -not $entraUnnamed
            if ($entraUnnamed) { Write-Verbose "$returned Entra role(s) came back without a name, so they are held but not readable." }
        }
        catch { Write-Verbose "Entra roles were not readable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
    }

    $purview = [System.Collections.Generic.List[string]]::new()
    $purviewRead = $false
    if ((Test-PurviewCommand -Name 'Get-RoleGroup') -and $objectId) {
        try {
            $groups = @(& (Get-PurviewComplianceCommand -Name 'Get-RoleGroup') -ResultSize Unlimited -ErrorAction Stop)

            foreach ($group in $groups) {
                $members = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $group -Name 'Members'))
                foreach ($member in $members) {
                    # Membership is written as a directory path whose last element is the object id.
                    # Nothing in it carries a name, and two directory objects can share a display
                    # name, so the id is both the only thing that matches and the only exact one.
                    if (@(([string]$member) -split '[\\/]')[-1].Trim() -ne $objectId) { continue }
                    $name = [string](Get-PurviewProperty -InputObject $group -Name 'DisplayName')
                    if (-not $name) { $name = [string](Get-PurviewProperty -InputObject $group -Name 'Name') }
                    if ($name) { $purview.Add($name) }
                    break
                }
            }

            $purviewRead = $true
        }
        catch { Write-Verbose "Role groups were not readable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }
    }

    $services = [System.Collections.Generic.List[string]]::new()
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
        PurviewRoleGroup = @($purview | Sort-Object -Unique)
        PurviewRoleGroupRead = $purviewRead
    }
}

function Test-PurviewBrokerRetry {
    <#
    .SYNOPSIS
        Recognises the MSAL broker failing before any prompt was shown.

    .DESCRIPTION
        The broker's native runtime is absent on some platforms, notably Windows on Arm, and its
        constructor throws a bare NullReferenceException. Nothing was asked of the operator at that
        point, so the sign-in can be tried again without the broker at no cost to them.
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

# Endpoints per cloud, taken from the reference page of each Connect cmdlet. GCC deliberately
# carries the commercial values throughout: Microsoft documents it as using the default endpoint,
# and no module offers a GCC-specific name. ITAR covers both GCC High and DoD, as SharePoint
# documents it. An empty value means the parameter is not passed and the module keeps its default.
$script:CloudEndpoint = [ordered]@{
    'Commercial' = @{ Scc = ''; SccAuth = ''; Exchange = ''; Graph = ''; SpoRegion = '' }
    'GCC' = @{ Scc = ''; SccAuth = ''; Exchange = ''; Graph = ''; SpoRegion = '' }
    'GCCHigh' = @{
        Scc = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
        SccAuth = 'https://login.microsoftonline.us/organizations'
        Exchange = 'O365USGovGCCHigh'; Graph = 'USGov'; SpoRegion = 'ITAR'
    }
    'DoD' = @{
        Scc = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
        SccAuth = 'https://login.microsoftonline.us/organizations'
        Exchange = 'O365USGovDoD'; Graph = 'USGovDoD'; SpoRegion = 'ITAR'
    }
    'China' = @{
        Scc = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
        SccAuth = 'https://login.chinacloudapi.cn/organizations'
        Exchange = 'O365China'; Graph = 'China'; SpoRegion = 'China'
    }
}

function Test-PurviewSignInIncomplete {
    <#
    .SYNOPSIS
        Recognises a sign-in that never finished, as opposed to an address that was wrong.

    .DESCRIPTION
        SharePoint reports both the same way, as a failure to connect. Telling them apart matters
        because the remedies are opposite: one is answered by signing in again, and the other by a
        different URL. Offering the wrong one sends somebody hunting for a hostname that was right.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    return $Message -match '(?i)(no valid OAuth|authentication session|authentication failed|user cancell?ed|was cancell?ed|interaction.?required|login is required|AADSTS)'
}

function Connect-PurviewSession {
    <#
    .SYNOPSIS
        Signs in to whatever is not already connected.

    .DESCRIPTION
        Interactive sign-in only. No credential, secret or token is ever accepted as a parameter,
        held in a variable or written anywhere: each module runs its own browser sign-in and this
        script never sees the result. Anything left unconnected is reported, not fatal.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string]$TenantAdminUrl = '',
        [ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD', 'China')][string]$Environment = 'Commercial',
        [switch]$AllowPrompt
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $record = {
        param($service, $state, $detail, $owned)
        # Only sessions this run opened are ours to close again on the way out.
        if ($owned) { $script:OwnedSession += $owned }
        # Connecting imports cmdlets, so anything previously recorded as absent may now exist.
        $script:CommandCache = @{}
        $script:ServiceModuleCache = @{}
        Write-PurviewStepResult -Status $state
        if ($detail) { Write-Line -Style Dim -Message ('             {0}' -f $detail) }
        $results.Add([pscustomobject]@{ Service = $service; State = $state; Detail = $detail })
    }

    # Order is load-bearing, not cosmetic. Microsoft.Graph.Authentication and
    # ExchangeOnlineManagement each ship their own Microsoft.Identity.Client, and .NET keeps only
    # the first one loaded into the process. Connecting Graph first leaves the Exchange modules
    # binding their newer broker extension against Graph's older MSAL, which throws inside the
    # broker constructor before any prompt appears. The Exchange endpoints therefore go first.
    $account = Get-PurviewSignedInAccount
    $hint = @{}
    if ($account) { $hint['UserPrincipalName'] = $account }

    $cloud = $script:CloudEndpoint[$Environment]
    $sccArgs = @{}
    if ($cloud.Scc) { $sccArgs['ConnectionUri'] = $cloud.Scc; $sccArgs['AzureADAuthorizationEndpointUri'] = $cloud.SccAuth }
    $exoArgs = @{}
    if ($cloud.Exchange) { $exoArgs['ExchangeEnvironmentName'] = $cloud.Exchange }
    $graphArgs = @{}
    if ($cloud.Graph) { $graphArgs['Environment'] = $cloud.Graph }
    if ($Environment -ne 'Commercial') { Write-Line -Style Dim -Message ('    Connecting to the {0} cloud.' -f $Environment) }

    Write-PurviewStep -Name 'Security & Compliance'
    if (Test-PurviewConnected -Service 'SecurityAndCompliance') {
        & $record 'Security & Compliance' 'AlreadyConnected' '' $null
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
        & $record 'Exchange Online' 'AlreadyConnected' '' $null
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
            & $record 'Exchange Online' 'Connected' '' 'ExchangeOnline'
        }
    }
    else {
        & $record 'Exchange Online' 'Unavailable' 'The ExchangeOnlineManagement module is not loaded.' $null
    }

    # Graph is last of the token-based sign-ins: it must not win the MSAL load race. It takes no
    # account hint, but by this point the browser has a session to reuse and rarely asks again.
    Write-PurviewStep -Name 'Microsoft Graph'
    if (Test-PurviewConnected -Service 'Graph') {
        & $record 'Microsoft Graph' 'AlreadyConnected' '' $null
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
                    & $record 'Microsoft Graph' 'Failed' ('The Exchange Online and Microsoft Graph modules disagree on the sign-in library they share, and reading Graph in a separate session did not work either.{0} Everything outside Microsoft Entra is unaffected.' -f $why) $null
                }
            }
            else { & $record 'Microsoft Graph' 'Failed' $graphError $null }
        }
    }
    else {
        & $record 'Microsoft Graph' 'Unavailable' 'The Microsoft.Graph.Authentication module is not loaded.' $null
    }

    Write-PurviewStep -Name 'SharePoint Online'
    if (Test-PurviewConnected -Service 'SharePoint') {
        & $record 'SharePoint Online' 'AlreadyConnected' '' $null
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
            # The system browser is what makes passkeys and other platform authenticators available,
            # but it does not complete on every machine, and the module's own dialog still works
            # where it does not. So it is preferred, not insisted on.
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
            # failure. Which browser signs you in is not a security decision, so retry without it.
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
                Write-Line -Style Warn -Message '    That is a sign-in that did not complete, not an address that was wrong.'
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
        Signs out of the sessions this run opened, leaving any you opened alone.

    .DESCRIPTION
        Done by default, so a read-only assessment does not leave a signed-in session behind it.
        Each module caches its token, and -KeepSignedIn keeps that cache for the next run.
    #>
    [CmdletBinding()]
    param()

    foreach ($service in @($script:OwnedSession | Select-Object -Unique)) {
        try {
            switch ($service) {
                'SecurityAndCompliance' {
                    if (Test-PurviewCommand -Name 'Disconnect-ExchangeOnline') {
                        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    }
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

    # The proxy must be removed before its runspace. This is independent of whether SharePoint
    # connected: a skipped or failed sign-in still leaves the local compatibility process alive.
    Clear-PurviewCompatibilityModule
    $script:OwnedSession = @()
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
    <# .SYNOPSIS Leaves the console and the machine as the run found them. #>
    [CmdletBinding()]
    param([switch]$SignOut)

    Write-Progress -Activity 'Collecting Microsoft Purview configuration' -Completed

    foreach ($path in @($script:TempArtifact | Select-Object -Unique)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            if (Test-Path -LiteralPath $path -PathType Container) {
                $null = Clear-PurviewTemporaryDirectory -Path $path
            }
            else { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    }
    $script:TempArtifact = @()

    if ($SignOut) { Disconnect-PurviewSession }
    else {
        # -KeepSignedIn transfers connected sessions back to the caller. A skipped or failed
        # SharePoint sign-in has no connection to preserve, so its otherwise orphaned compatibility
        # process is still removed. A connected proxy and runspace must remain together.
        $keepSharePoint = @($script:OwnedSession) -contains 'SharePoint'
        $script:OwnedSession = @()
        if ($keepSharePoint) {
            $script:OwnedCompatibilitySession = @()
            $script:OwnedCompatibilityModule = @()
        }
        else { Clear-PurviewCompatibilityModule }
    }
}

#endregion

#region Collection plumbing

function Test-PurviewCommand {
    <# .SYNOPSIS Reports whether a cmdlet is available, so a missing session is skipped not fatal. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)

    # A miss is the expensive answer: Get-Command searches every module on disk before conceding,
    # which costs a third of a second each time and is asked repeatedly per collector. Connecting
    # imports cmdlets and so invalidates a miss, which is why the cache is cleared on every connect.
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
        The compliance and Exchange Online connections each load their own module, and the two
        export around eighty of the same cmdlet names. Whichever was imported last wins an
        unqualified call, so which service answers is left to chance.

        It is not a cosmetic difference. The tenant policy configuration fails outright when the
        call lands on Exchange, role group membership comes back describing Exchange rather than
        Purview, and UnifiedAuditLogIngestionEnabled is documented as always False anywhere but
        Exchange Online. Each read therefore names the service that owns it.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Compliance', 'ExchangeOnline')][string]$Service
    )

    $uriPattern = if ($Service -eq 'Compliance') { 'compliance\.protection\.outlook\.com' } else { 'outlook\.office365\.com' }

    $module = $null
    if ($script:ServiceModuleCache.ContainsKey($Service)) { $module = $script:ServiceModuleCache[$Service] }
    elseif (Test-PurviewCommand -Name 'Get-ConnectionInformation') {
        try {
            $connection = Get-ConnectionInformation -ErrorAction Stop |
                Where-Object { [string]$_.ConnectionUri -match $uriPattern } |
                Select-Object -First 1
            if ($connection) {
                # The property holds a full path, which Get-Module rejects as a name.
                $path = [string]$connection.ModuleName
                $leaf = if ($path) { [System.IO.Path]::GetFileName($path) } else { '' }
                $module = Get-Module |
                    Where-Object { ($path -and $_.Path -eq $path) -or ($leaf -and $_.Name -eq $leaf) } |
                    Select-Object -First 1
            }
            # Cached even when nothing was found, so a run without the connection stops looking.
            $script:ServiceModuleCache[$Service] = $module
        }
        catch { Write-Verbose "No connection information to pick a $Service module from." }
    }

    if ($module -and $module.ExportedCommands.ContainsKey($Name)) { return $module.ExportedCommands[$Name] }
    return Get-Command -Name $Name -ErrorAction Stop
}

function Get-PurviewComplianceCommand {
    <# .SYNOPSIS Resolves a cmdlet to the compliance connection's module. #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param([Parameter(Mandatory)][string]$Name)

    return Get-PurviewServiceCommand -Name $Name -Service 'Compliance'
}

function Get-PurviewSafeErrorMessage {
    <# .SYNOPSIS Strips anything credential-like before an error is recorded. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    $safe = $Message -replace '[\r\n]+', ' '
    # A failure carrying a token must never reach a log, a report or a shared snapshot.
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
    <# .SYNOPSIS Tells an unconfigured feature apart from a read that failed. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [AllowNull()][System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )

    # Deliberately narrow. A read that genuinely failed must keep saying so, so only phrasings that
    # can mean nothing else are treated as the feature never having been set up. An advanced hunting
    # table that will not resolve is one of them: the Purview tables are documented as returning
    # nothing until the tenant opts in to share insider risk detail with Defender.
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
        Recognises a failure that is worth trying again rather than reporting.

    .DESCRIPTION
        The compliance endpoints intermittently answer with a server-side error and an instruction
        to try later. Reporting that as an uncollected area makes a healthy tenant look unreadable,
        and the operator has no way to tell the difference from the report.
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
        Never throws. An unavailable service becomes NotConnected, a failure becomes Failed with a
        sanitised message, and success carries the normalised data.

        Context is passed to the scriptblock as an argument rather than captured in a closure: a
        closure snapshots session state, and the shared helpers are not resolvable inside it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$SolutionArea,
        [Parameter(Mandatory)][string]$Interface,
        [Parameter(Mandatory)][ValidateSet('SecurityAndCompliancePowerShell', 'ExchangeOnlinePowerShell', 'SharePointOnlinePowerShell', 'MicrosoftGraph')][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequiredCommand,
        [Parameter(Mandatory)][scriptblock]$Collect,
        [object]$Context = $null,
        [string]$DocumentationUrl = '',
        [string]$ConnectWith = '',
        # Named so a reader is told which role to assign rather than that some role is missing.
        [string]$RequiredRole = '',
        # For a signal where finding something proves a point and finding nothing proves none: any
        # failure to read it is simply absence, so reporting it as a fault sends the reader after
        # something that changes no conclusion in the report.
        [string]$AbsenceMeans = ''
    )

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
        # A compliance session only surfaces the cmdlets the sign-in is entitled to, so a missing
        # cmdlet on a live session is a role that was not granted, not a connection that was missed.
        $connected = $Kind -eq 'SecurityAndCompliancePowerShell' -and (Test-PurviewConnected -Service 'SecurityAndCompliance')
        if ($connected) {
            $named = if ($RequiredRole) { " Assign $RequiredRole." } else { ' The cmdlet appears once the role that grants it is assigned.' }
            $result.status = 'NotPermitted'
            $result.errors = @([pscustomobject]@{ message = "$($missing -join ', ') is not available to this sign-in, although the Security & Compliance session is live.$named"; category = 'NotPermitted'; interface = $Interface })
            $result.limitations = @("$SolutionArea needs a role this sign-in did not hold.")
            return [pscustomobject]$result
        }

        $hint = if ($ConnectWith) { " Connect with $ConnectWith." } else { '' }
        $result.status = 'NotConnected'
        $result.errors = @([pscustomobject]@{ message = "$($missing -join ', ') is unavailable.$hint"; category = 'NotConnected'; interface = $Interface })
        $result.limitations = @("$SolutionArea needs a connection this run did not have.")
        return [pscustomobject]$result
    }

    # Three attempts with a widening pause. A transient server-side error is common enough on the
    # compliance endpoints that reporting the first one would misdescribe a readable tenant.
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            # Modules emit chatty warnings mid-call, which would break up the step output. They are
            # captured and shown only under -Verbose rather than discarded blind.
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

            # A role that was never granted is not an absence, and no retry will fix it. Checked
            # ahead of every absence path so a missing object message cannot soften a permission gap.
            if ((Get-PurviewErrorCategory -Message $message) -eq 'Permission') {
                $named = if ($RequiredRole) { " Assign $RequiredRole." } else { '' }
                $result.status = 'NotPermitted'
                $result.errors = @([pscustomobject]@{ message = "$message$named"; category = 'NotPermitted'; interface = $Interface })
                $result.limitations = @("$SolutionArea needs a role this sign-in did not hold.")
                break
            }

            # A transient that outlived every retry is the service failing, not a feature nobody set
            # up. Checked ahead of AbsenceMeans so a collector that declares one cannot turn an
            # outage into a tenant that has nothing configured.
            if (Test-PurviewTransientError -Message $message) {
                $result.status = 'Failed'
                $result.errors = @([pscustomobject]@{ message = "$message$retried"; category = Get-PurviewErrorCategory -Message $message; interface = $Interface })
                $result.limitations = @("$SolutionArea could not be read because the service kept failing, so nothing here was assessed.")
                break
            }

            # Never configured is not the same as could not be read, and reporting the first as a
            # failure invites someone to go looking for a fault that was never there. The error
            # record keeps PowerShell coding failures out even when their prose says "cannot be found".
            if (Test-PurviewAbsenceError -Message $message -ErrorRecord $errorRecord) {
                $result.status = 'Success'
                $result.data = [pscustomobject]@{}
                $result.limitations = @("$SolutionArea has not been configured in this tenant, so there was nothing to read.")
                break
            }

            if ($AbsenceMeans) {
                $result.status = 'Success'
                $result.data = [pscustomobject]@{}
                # What the service actually said is kept. A blanket sentence with the error dropped
                # tells a reader something went unread without telling them what to do about it.
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
# Every interface below is a Get-* cmdlet or an HTTP read, each verified against its Microsoft
# Learn reference page. The advanced hunting query is a POST because Microsoft documents no GET for
# it; it runs a read-only KQL query and returns aggregates. Nothing here changes tenant state.

$script:SccDocRoot = 'https://learn.microsoft.com/powershell/module/exchangepowershell'
$script:DeploymentModelRoot = 'https://learn.microsoft.com/purview/deploymentmodels'
$script:SpoDocRoot = 'https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell'

# Which solution area belongs to which Purview solution, so a run can be narrowed to the ones a
# customer actually uses. Classification sits under both: sensitive information types feed
# auto-labelling and DLP alike, and dropping them would gut whichever half was chosen.
$script:SolutionMap = [ordered]@{
    'InformationProtection' = @('SensitivityLabels', 'LabelPolicies', 'AutoLabeling', 'Classification', 'ContentExplorer', 'ActivityExplorer', 'Oversharing')
    'DataLossPrevention' = @('DataLossPrevention', 'EndpointDlp', 'Classification')
    'DataLifecycleManagement' = @('DataLifecycleManagement')
    'RecordsManagement' = @('RecordsManagement')
    'CommunicationCompliance' = @('CommunicationCompliance')
    'InsiderRisk' = @('InsiderRisk')
    'Audit' = @('Audit')
}

# Licensing decides what a finding may recommend and posture validation checks the run itself, so
# neither belongs to a solution and both run whatever is selected.
$script:AlwaysSolutionArea = @('Licensing', 'PostureValidation')

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
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Mode = @('Mode'); Enabled = @('Enabled')
            }
            Optional = @('Mode', 'Enabled')
        }
        @{
            # The policy says whether labelling runs; the rule says what it looks for. Both are
            # needed to report what a policy actually protects.
            Collector = 'AutoLabelingRule'; Area = 'AutoLabeling'; Cmdlet = 'Get-AutoSensitivityLabelRule'; Key = 'Rules'
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
            # Copilot and AI prompt retention is not in Get-RetentionCompliancePolicy: Microsoft
            # documents the newer locations as belonging to the App cmdlets instead.
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
            Map = [ordered]@{
                Name = @('Name', 'Identity'); Enabled = @('Enabled')
                RetentionDuration = @('RetentionDuration'); RecordTypes = @('RecordTypes'); Priority = @('Priority')
            }
            Optional = @('Enabled', 'RetentionDuration', 'RecordTypes', 'Priority')
        }
        @{
            Collector = 'CommunicationCompliance'; Area = 'CommunicationCompliance'; Cmdlet = 'Get-SupervisoryReviewPolicyV2'; Key = 'Policies'
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
            # what settles a policy whose locations come back empty.
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
    param([Parameter(Mandatory)][object]$Definition)

    return Invoke-PurviewCollector -Collector $Definition.Collector -SolutionArea $Definition.Area `
        -Interface $Definition.Cmdlet -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/$($Definition.Cmdlet.ToLowerInvariant())" `
        -RequiredCommand @($Definition.Cmdlet) -ConnectWith 'Connect-IPPSSession' `
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

            # The collector row stays open until its result is known. A leading progress-only line
            # break adds visual separation without closing that row and moving its result elsewhere.
            $detailActivity = [Environment]::NewLine + 'Reading sensitivity label protection settings'
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
        # Get-PolicyConfig returns a single configuration object rather than a collection, and a
        # tenant that has never had one written has nothing behind it to return.
        $config = & (Get-PurviewComplianceCommand -Name 'Get-PolicyConfig') -ErrorAction Stop -WarningAction SilentlyContinue
        if ($null -eq $config) {
            return [pscustomobject]@{ Settings = @(); Limitation = 'No tenant-wide policy configuration has been written in this tenant, so there are no settings to read.' }
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
        Microsoft documents OCR as an optional tenant-level feature configured in the portal and
        billed per image scanned, but publishes no reference page for the cmdlets behind it. The
        object is therefore read defensively: only properties the tenant actually returns are
        reported, and nothing is inferred from one that is missing.

        A tenant that has never configured OCR returns no object at all. That is the off state, not
        a failed read, so it is reported as a count rather than a limitation.
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
        These predate retention policies and the portal keeps them under Exchange (legacy). They
        still delete and archive mail wherever they are linked to a mailbox, so a tenant can be
        retaining on two systems at once without either naming the other.

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

        # Prefer the narrow query. A complete full scan is the only acceptable fallback: a partial
        # scan can contain real events and still understate the total, which is worse than no number.
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
        # Zero means all. A default ceiling can turn many requested types into an avoidably
        # incomplete result, so a limit applies only when a caller deliberately supplies one.
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
        Data access governance quantifies who can reach what, which is the exposure Copilot inherits.
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

        # Every entity refusing is the licence or the role talking rather than an empty tenant, and
        # the caller needs to tell those apart, so it is reported rather than thrown.
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
        gives Graph a process of its own. Its token is cached, so only the first call prompts.
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

    $quote = { param($text) "'" + ([string]$text -replace "'", "''") + "'" }
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

    # A process per page would mean twenty sign-ins for one read, so paging happens in there.
    $work = if ($Paged) {
        @(
            '$items = @()'
            ('$next = {0}' -f (& $quote $Uri))
            ('$page = 0')
            ('while ($next -and $page -lt {0}) {{' -f [int]$MaxPage)
            '    $answer = Invoke-MgGraphRequest -Method $verb -Uri $next -OutputType PSObject -ErrorAction Stop'
            '    $page++'
            '    $value = $answer.value'
            '    if ($null -eq $value) { $items += $answer; break }'
            '    $items += @($value)'
            '    $next = [string]$answer.''@odata.nextLink'''
            '}'
            '$items | ConvertTo-Json -Depth 20 -Compress'
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
            ('Connect-MgGraph -Scopes {0} -NoWelcome -ErrorAction Stop' -f $scopes)
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
        if ($json.Count -eq 0) { return $null }
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
        $page++

        $value = Get-PurviewProperty -InputObject $response -Name 'value'
        if ($null -eq $value) {
            $items.Add($response)
            break
        }
        foreach ($item in @($value)) { $items.Add($item) }

        $next = [string](Get-PurviewProperty -InputObject $response -Name '@odata.nextLink')
    }

    return $items.ToArray()
}

function Get-PurviewEndpointDeviceHealthData {
    <#
    .SYNOPSIS
        Counts how many onboarded devices are actually fit to enforce endpoint DLP.

    .DESCRIPTION
        The only documented read for this. Microsoft exposes device configuration and policy sync
        state through the DlpInfo column of the advanced hunting DeviceInfo table, which replaced
        exporting the device onboarding page by hand.

        Onboarding is read from OnboardingStatus, which Microsoft documents as whether the device
        is onboarded to Microsoft Defender for Endpoint. Microsoft documents enabling device
        monitoring and onboarding endpoints as two separate steps, and no documented interface
        reports the monitoring switch, so the count is named for the service it describes.

        Each device is reduced to its latest row before DlpInfo is read, because the table keeps
        every update and filtering first would report a device on a state it has since left.

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
        -AbsenceMeans 'No insider risk detail reached Defender, so nothing here confirms the sharing opt-in either way.' `
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
        -AbsenceMeans 'No Microsoft 365 cloud app activity reached Defender for Cloud Apps, so nothing here confirms the connector either way.' `
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
        Looks for the admin consent that lets Defender for Cloud Apps inspect label-encrypted files.

    .DESCRIPTION
        Granting "Inspect protected files" in the portal provisions the "Microsoft Cloud App Security
        (Internal)" service principal and gives it the Azure Rights Management super-user app role.
        Reading that app-role assignment back is how the grant is confirmed. Its presence proves the
        consent was given; absence is not proof it was not, since a tenant without Defender for Cloud
        Apps deployed, or one this account cannot read applications in, looks the same.

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

        # The documented app id differs by cloud. The allow-list prevents a tenant-created service
        # principal with the same display name from being mistaken for Microsoft's application.
        $knownAppIds = @(
            '25a6a87d-1e19-4c71-9cb0-16e88ff608f1'
            'bd5667e4-0484-4262-a9db-93faa0893899'
            '23105e90-1dfc-497a-bb5d-8b18a44ba061'
        )
        $nameFilter = "displayName eq 'Microsoft Cloud App Security (Internal)'"
        $principalCandidates = @(Invoke-PurviewGraphGet -Uri ('/v1.0/servicePrincipals?$filter={0}&$select=id,appId' -f [uri]::EscapeDataString($nameFilter)))
        $principals = @($principalCandidates | Where-Object {
                [string](Get-PurviewProperty -InputObject $_ -Name 'appId') -in $knownAppIds
            })

        $granted = 0
        $incomplete = @($principalCandidates | Where-Object {
                -not (Test-PurviewProperty -InputObject $_ -Name 'appId') -or
                [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'appId'))
            }).Count -gt 0
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
                if ([string](Get-PurviewProperty -InputObject $resource -Name 'displayName') -ne 'Azure Rights Management Services') { continue }

                $role = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $resource -Name 'appRoles') |
                    Where-Object {
                        [string](Get-PurviewProperty -InputObject $_ -Name 'id') -eq $appRoleId -and
                        [string](Get-PurviewProperty -InputObject $_ -Name 'value') -eq 'Content.SuperUser'
                    })
                if ($role.Count -eq 1) { $granted++; break }
            }
        }

        # A confirmed role is sufficient even if another assignment was malformed. Without one,
        # incomplete assignment metadata is unknown rather than evidence that consent is absent.
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

        # DlpPolicyEnforcementMode 4 is Block, as documented on the table reference.
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
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Sku)

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
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Sku)

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
                        $name = [string](Get-PurviewProperty -InputObject $_ -Name 'servicePlanName')
                        $status = [string](Get-PurviewProperty -InputObject $_ -Name 'provisioningStatus')
                        [pscustomobject]@{ servicePlanName = $name; provisioningStatus = $status }
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
    param()

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

    if (-not $name) { $name = 'Unknown' }
    return [pscustomobject]@{ displayName = $name; tenantId = $tenant; redacted = $false }
}

function Get-PurviewTenantSnapshot {
    <#
    .SYNOPSIS
        Runs every collector against sessions you have already established and returns a snapshot.

    .DESCRIPTION
        Read-only throughout. Does not authenticate and never handles credentials. Any service that
        is not connected is recorded as NotConnected, so a partial run still returns what it reached.
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
        @{ Name = 'ProtectedFilesConsent'; Area = 'PostureValidation'; Call = { Get-PurviewProtectedFilesConsentData } }
        @{ Name = 'DataSecurityTelemetry'; Area = 'PostureValidation'; Call = { Get-PurviewDataSecurityTelemetryData } }
        @{ Name = 'DataAccessGovernance'; Area = 'Oversharing'; Insight = $true; Call = { Get-PurviewDataAccessGovernanceData } }
        @{ Name = 'Licensing'; Area = 'Licensing'; Call = { Get-PurviewLicensingData } }
    ) | Where-Object {
        (& $inScope $_.Area) -and ($IncludeInsights -or -not $_.ContainsKey('Insight'))
    }
    $extras = @($extras)

    $coverageTags = @(Get-PurviewInsightTag -ExtraTag $InsightTag)
    $wantActivity = $IncludeInsights -and (& $inScope 'ActivityExplorer')
    $wantCoverage = (Test-PurviewContentExplorerRequest -SkipInsights:(-not $IncludeInsights) `
            -Tag $coverageTags -SolutionArea $wanted) -and -not $script:SkipContentExplorer
    $wantSites = $IncludeSites -and (& $inScope 'SensitivityLabels')

    $total = $definitions.Count + $extras.Count
    if ($wantActivity) { $total++ }
    if ($wantCoverage) { $total++ }
    if ($wantSites) { $total++ }
    $index = 0

    # Each step is announced before it runs and closed when it returns, so a slow tenant call shows
    # what it is waiting on instead of looking hung. Arguments are passed rather than captured: a
    # closure snapshots session state and the shared helpers stop resolving inside it.
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

    foreach ($definition in $definitions) {
        $results.Add((& $run $definition.Collector { param($d) Get-PurviewSccData -Definition $d } $definition))
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
        Get-PurviewTenantIdentity
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

    # Negation wraps the comparison rather than inverting the operator, so a record missing the
    # field still fails the inner test and is kept. Excluding what was never returned would read
    # a silent service as an empty tenant.
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
    <# .SYNOPSIS Lists offending items by name, capped so a wide breach stays readable. #>
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
    <# .SYNOPSIS Describes each offending item by name and by the value that offended. #>
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
            $lines.Add("$label is currently set to $actualValue. The expected value is $wantedValue")
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

    switch ($type) {
        'countEquals' {
            return [pscustomobject]@{
                Passed = ($count -eq $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = "$count found, where exactly $value was expected."
            }
        }
        'countGreaterThan' {
            return [pscustomobject]@{
                Passed = ($count -gt $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = "$count found, where more than $value was expected."
            }
        }
        'countLessThan' {
            return [pscustomobject]@{
                Passed = ($count -lt $value); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = "$count found, where fewer than $value was expected."
            }
        }
        'isEmpty' {
            return [pscustomobject]@{
                Passed = ($count -eq 0); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($count -eq 0) { 'None found, as expected.' } else { "$count found, where none was expected." }
            }
        }
        'isNotEmpty' {
            return [pscustomobject]@{
                Passed = ($count -gt 0); Observed = @(Format-PurviewItemList -Item $Items)
                Reason = if ($count -gt 0) { "$count found." } else { 'None found, where at least one was expected.' }
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
                Reason = if ($count -eq 0) { 'There is nothing here to check.' }
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
                Reason = if ($count -eq 0) { 'There is nothing here to check.' }
                elseif ($matching.Count -gt 0) { "$($matching.Count) of $count checked matched. Expected: $expected." }
                else { "None of the $count checked matched. At least one must. Expected: $expected." }
            }
        }

        'noneHave' {
            $matching = @($Items | Where-Object { Test-PurviewPredicate -InputObject $_ -Predicate $where })
            $unwanted = Format-PurviewPredicate -Predicate $where
            return [pscustomobject]@{
                Passed = ($matching.Count -eq 0)
                Observed = @(Format-PurviewPredicateFailure -Item $matching -Predicate $where)
                Vacuous = ($count -eq 0)
                Reason = if ($count -eq 0) { 'There is nothing here to check.' }
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
        Decides whether a rule's capability is licensed for the tenant.

    .DESCRIPTION
        Uncertainty resolves to Unknown, which lets the rule run. Treating an unrecognised SKU as
        unlicensed would silently suppress real findings, which is the more damaging mistake: a
        missing check reads as nothing wrong.
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

    foreach ($grant in $accepted) {
        if (@($evidence.PotentialGrants | Where-Object { [string]$_ -ieq $grant }).Count -gt 0) {
            return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
        }
    }

    $unknownGrant = @($accepted | Where-Object {
            $candidate = $_
            @($evidence.KnownGrants | Where-Object { [string]$_ -ieq $candidate }).Count -eq 0
        }).Count -gt 0
    if ($unknownGrant -or -not $evidence.CanProveExclusion) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
    }

    return [pscustomobject]@{ State = 'NotLicensed'; Capability = $capability; UnlockedBy = $accepted }
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
        The lowest tier that unlocks a capability, which is the order to work through it in.

    .DESCRIPTION
        A customer works from what they already own outwards. Anything E3 covers is available to
        nearly everyone and should be done first; E5 items are a decision about what they have
        bought; forward-looking items are not purchasable today and are kept clearly apart.
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

function Get-PurviewDlpPolicyRuleAnalysis {
    <#
    .SYNOPSIS
        Correlates DLP rules to exactly one parent policy and keeps their states authoritative.

    .DESCRIPTION
        Get-DlpCompliancePolicy.Mode says whether a policy is enforcing. Get-DlpComplianceRule
        .Disabled says whether a child rule is enabled. A rule is linked only when the intersection
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

function Get-PurviewDlpFindingOutcome {
    <# .SYNOPSIS Produces evidence-accurate outcomes for the two DLP rule checks. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('PolicyRuleCoverage', 'DisabledRulesInEnforcingPolicies')][string]$Analysis,
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot
    )

    $state = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $outcome = [ordered]@{
        Status = 'NeedsReview'
        Reason = ''
        Observed = @()
        Control = 'Get-DlpCompliancePolicy Mode and Get-DlpComplianceRule Disabled'
        Recommended = 'Every enforcing DLP policy has an enabled rule'
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
            $outcome.Reason = 'No DLP policy is configured, so no DLP rule can operate.'
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
                $outcome.Reason = '{0} configured, but none is in Enable mode, so no policy is enforcing its rules.' -f
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
        $outcome.Recommended = 'No rule in an enforcing DLP policy is disabled'
        $disabled = @($state.LinkedRules | Where-Object { $_.IsEnforcing -and $_.DisabledKnown -and $_.Disabled })
        if ($disabled.Count -gt 0) {
            $outcome.Status = 'Warning'
            $outcome.Observed = @($disabled | ForEach-Object { Get-PurviewItemLabel -InputObject $_.Rule })
            $disabledText = Format-PurviewCount -Count $disabled.Count -Singular 'DLP rule' -Plural 'DLP rules'
            $eligibleText = Format-PurviewCount -Count $state.EligibleRuleCount -Singular 'eligible rule' -Plural 'eligible rules'
            $verb = if ($disabled.Count -eq 1) { 'reports' } else { 'report' }
            $outcome.Reason = "$disabledText linked to an enforcing policy $verb Disabled as True, out of $eligibleText."
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
            'The eligible DLP rule linked to an enforcing policy reports Disabled as False.'
        }
        else { "All $($state.EligibleRuleCount) eligible DLP rules linked to enforcing policies report Disabled as False." }
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
            $outcome.Reason = '{0} configured, but none is in Enable mode, so no policy is enforcing its rules.' -f
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
            'The enforcing DLP policy has at least one enabled linked rule; {0} in total.' -f
                (Format-PurviewCount -Count $state.EnabledRuleCount -Singular 'enabled linked rule was found' -Plural 'enabled linked rules were found')
        }
        else { "All $($state.EnforcingPolicyCount) enforcing DLP policies have at least one enabled linked rule; $($state.EnabledRuleCount) are enabled in total." }
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

function ConvertTo-PurviewFinding {
    <# .SYNOPSIS Evaluates one rule, resolving collector availability and licensing first. #>
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
        capability = $licensing.Capability
        state = $licensing.State
        unlockedBy = @($licensing.UnlockedBy)
    }

    # An unlicensed capability is not a misconfiguration, so it must never reach Fail.
    if ($licensing.State -eq 'NotLicensed') {
        $finding.status = 'NotApplicable'
        $unlock = @($licensing.UnlockedBy) -join ', '
        $finding.reason = "$($licensing.Capability) is not licensed for this tenant." + $(if ($unlock) { " It would be unlocked by: $unlock." } else { '' })
        return [pscustomobject]$finding
    }

    $namedAnalysis = [string](Get-PurviewProperty -InputObject $condition -Name 'analysis')
    if (-not [string]::IsNullOrWhiteSpace($namedAnalysis)) {
        $outcome = Get-PurviewDlpFindingOutcome -Analysis $namedAnalysis -Snapshot $Snapshot
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
    $result = if ($matched.Count -gt 0) { $matched[0] } else { $null }

    if ($null -eq $result) {
        $finding.reason = "$collectorName was not part of this run, so it was not checked."
        return [pscustomobject]$finding
    }

    $status = [string](Get-PurviewProperty -InputObject $result -Name 'status')
    if ($status -eq 'Unsupported') {
        $finding.status = 'Unsupported'
        $finding.reason = "No documented read-only interface exists for '$collectorName'. Assess this manually."
        return [pscustomobject]$finding
    }
    if ($status -notin 'Success', 'PartialSuccess') {
        $errors = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $result -Name 'errors'))
        $why = if ($errors.Count -gt 0) { [string](Get-PurviewProperty -InputObject $errors[0] -Name 'message') } else { $status }
        # An unread check is silence, not evidence, and the raw service text reads like a verdict on
        # the tenant unless it is attributed and the silence is spelled out.
        $finding.reason = "$collectorName could not be checked, so nothing here says whether it is configured, one way or the other. Reason given: $why"
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
            $finding.reason = "$($blocked -join ', ') is not visible here, so this check could not be made. Confirm it in the portal."
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
            $finding.reason = "$($missingWhere -join ', ') was missing from one or more records, so this check could not be made."
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
        $finding.reason = "$($missingAssertion -join ', ') was missing from one or more records, so this check could not be made."
        return [pscustomobject]$finding
    }

    $outcome = Test-PurviewAssertion -Items @($items) -Assertion $assertion

    # Passing over an empty set is a vacuous truth, not a control that works. Reporting it green
    # would tell a customer something is right when nothing is configured at all.
    if ($outcome.Passed -and [bool](Get-PurviewProperty -InputObject $outcome -Name 'Vacuous')) {
        $finding.status = 'NotApplicable'
        $finding.reason = "There is nothing configured for this yet, so there was nothing to check."
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

    # NotApplicable is rule-engine bookkeeping. It is not a finding, and exposing it as a skipped
    # check or a licensing gap makes a report say something the customer did not ask to assess.
    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Finding) {
        $status = [string](Get-PurviewProperty -InputObject $item -Name 'status')
        if ($status -eq 'NotApplicable') { continue }
        if ($status -ne 'NeedsReview') {
            $output.Add($item)
            continue
        }

        # A rule carries its normal fix and sometimes a runnable command before its evidence is
        # evaluated. NeedsReview means that evidence did not prove the change is needed, or that
        # the guidance itself is provisional. Copy the finding so the internal outcome remains
        # inspectable, but never turn uncertainty into a customer-facing instruction to change it.
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

    if ($matched.Count -eq 0 -or [string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') {
        return [pscustomobject]@{ Collected = $false; StateKnown = $false; Enabled = @(); TopLevel = @(); SubLabels = @(); HierarchyKnown = $false }
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
        return [pscustomobject]@{ Collected = $true; StateKnown = $false; Enabled = @(); TopLevel = @(); SubLabels = @(); HierarchyKnown = $false }
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

    # The default taxonomy repeats a sublabel name under more than one tier, so a leaf name alone
    # reads as a duplicate row. The parent is resolved by Guid to name each one the way a picker does.
    $byGuid = @{}
    foreach ($label in $enabled) {
        $guid = [string](Get-PurviewProperty -InputObject $label -Name 'Guid')
        if ($guid) { $byGuid[$guid] = [string](Get-PurviewProperty -InputObject $label -Name 'Name') }
    }

    return [pscustomobject]@{
        Collected = $true
        StateKnown = $true
        Enabled = @($enabled | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        TopLevel = @($top | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        SubLabels = @($sub | ForEach-Object {
                $name = [string](Get-PurviewProperty -InputObject $_ -Name 'Name')
                $parent = [string]$byGuid[[string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')]
                [pscustomobject]@{
                    Name = $name
                    Parent = $parent
                    # Already qualified in some shapes, so the parent is only prefixed when it is not.
                    Path = if ($parent -and $name -notlike "$parent*") { "$parent \ $name" } else { $name }
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
        $output.Add([pscustomobject]@{ Tier = 'Not collected'; Match = 'Unknown'; Detail = 'Sensitivity labels were not collected, so the taxonomy could not be compared.' })
        return $output.ToArray()
    }
    if (-not $taxonomy.StateKnown) {
        $output.Add([pscustomobject]@{ Tier = 'Not checked'; Match = 'Unknown'; Detail = 'One or more labels did not return a usable Disabled state, so the active taxonomy could not be established.' })
        return $output.ToArray()
    }
    if (-not $taxonomy.HierarchyKnown) {
        $output.Add([pscustomobject]@{ Tier = 'Not checked'; Match = 'Unknown'; Detail = 'One or more enabled labels did not return ParentId, so top-level labels and sibling groups could not be established.' })
        return $output.ToArray()
    }

    $top = @($taxonomy.TopLevel)
    foreach ($reference in $script:ReferenceTaxonomy) {
        $hit = @($top | Where-Object { $_ -eq $reference.Tier })
        $output.Add([pscustomobject]@{
                Tier = $reference.Tier
                Match = if ($hit.Count -gt 0) { 'Same name' } else { 'No label of this name' }
                Detail = $reference.Purpose
            })
    }

    $names = @($script:ReferenceTaxonomy | ForEach-Object { $_.Tier })
    foreach ($own in @($top | Where-Object { $_ -notin $names } | Sort-Object)) {
        $output.Add([pscustomobject]@{ Tier = $own; Match = 'Organisation-specific'; Detail = 'No counterpart in the default taxonomy. Compared by name only, so a differently named equivalent reads the same way.' })
    }

    # The comparison above is of top-level tiers, so sublabels would otherwise never appear.
    foreach ($sub in @($taxonomy.SubLabels | Sort-Object -Property Path)) {
        $detail = if ($null -eq $sub.Encrypted) { 'Whether this label encrypts is not visible here.' }
        elseif ($sub.Encrypted) { 'Applies encryption, so the protection stays with the file wherever it is copied or sent.' }
        else { 'Applies markings only. Content keeps the label but is not encrypted.' }
        $output.Add([pscustomobject]@{ Tier = $sub.Path; Match = 'Sublabel'; Detail = $detail })
    }

    return $output.ToArray()
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
# A posture record is rule outcomes, not tenant content: no policy names, no reasons, no counts of
# anything a customer owns. That makes it far less sensitive than a snapshot and safe to retain for
# as long as the trend is useful.

$script:PostureRank = @{ Fail = 0; Warning = 1; Pass = 2 }
$script:PostureUndetermined = @('NeedsReview', 'NotCollected', 'Unsupported')
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
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotCollected', 'Unsupported') {
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
    $path = Join-Path $Folder "posture-$stamp.json"
    if (-not $PSCmdlet.ShouldProcess($path, 'Write posture record')) { return '' }

    $Record | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
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
        Only one record is ever used, and it is nearly always the newest. Reading every file to
        find it costs the whole history on each run, so files are taken newest first and parsing
        stops at the first match.
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
        Picks the most recent earlier record that can honestly be compared with this run.

    .DESCRIPTION
        Records accumulate from demo runs and from different tenants. Taking the newest one
        regardless would refuse the comparison and report nothing useful, so the newest comparable
        one is chosen instead.
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
        Reports what moved between two runs, and what cannot honestly be called movement.

    .DESCRIPTION
        Only a change between two assessed outcomes counts as progress or regression. Losing sight
        of a rule, gaining a new one, or a rule changing version all look like movement in a naive
        diff, so each is classified separately and kept out of the score.
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
        $blocker = 'No earlier posture record was found, so this run becomes the baseline.'
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
                $ruleChanges.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = ''; To = $now; Change = 'New'; Detail = 'This rule did not exist when the baseline was taken.' })
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
        Reported as steps checked and steps passing, never as a percentage of the model. Most steps
        have one rule or none, so a percentage would read as "this model is done" on the strength of
        a single check. A step whose rules were all uncollectable or unlicensed is not counted as
        passing: absence of evidence is not evidence of absence, and an unlicensed capability is not
        an implemented one.
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
        # A model no rule maps to is not reported at all: listing it with nothing against it says
        # only that this tool does not cover it, which belongs in the docs rather than the report.
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

            # A step held up only by warnings is not a failed step. Severity already decides which
            # checks are worth failing over, and a blueprint that calls both the same undoes it.
            $state = if ($contributing.Count -eq 0) { 'NoChecks' }
            elseif ($assessed -eq 0) { 'NotAssessed' }
            elseif ($passed -eq $assessed) { 'ChecksPass' }
            elseif ($passed -gt 0) { 'Partial' }
            elseif ($failed -eq 0) { 'ChecksWarn' }
            else { 'ChecksFail' }

            $plural = if ($assessed -eq 1) { 'check' } else { 'checks' }
            $verdict = switch ($state) {
                'NoChecks' { 'No check covers this step' }
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
        Ordered so the list can be worked top down: outstanding items first, worst severity first,
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
            'Pass' { 'Done', 'x', 'Nothing to do.'; break }
            'Fail' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'Warning' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'NeedsReview' { 'To check by hand', '?', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
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
                # A rule carries its fix whatever the outcome, so offering it beside a check that
                # passed would invite someone to change a setting that is already right.
                Command = if ($hasCommand -and $group -eq 'To do') { [string]$item.remediationCommand } else { '' }
                GroupOrder = switch ($group) { 'To do' { 0 } 'To check by hand' { 1 } 'Done' { 2 } 'Not checked' { 3 } default { 4 } }
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

    # Only items with a verdict count towards progress; unchecked ones would flatter it.
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
        Percent = if ($judged -gt 0) { [math]::Round(($done / $judged) * 100) } else { $null }
    }
}

function Get-PurviewCollectorItem {
    <# .SYNOPSIS Returns one collector's items, or an empty set if it did not run. #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Select
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    if ($matched.Count -eq 0) { return @() }
    if ([string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') { return @() }

    return @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name $Select))
}

function Get-PurviewCollectorValue {
    <# .SYNOPSIS Returns one scalar from a collector's data, or null if it did not run. #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Select
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    if ($matched.Count -eq 0) { return $null }
    if ([string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -notin 'Success', 'PartialSuccess') { return $null }

    return Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name $Select
}

function Test-PurviewCollectorRan {
    <# .SYNOPSIS Reports whether a collector returned usable data, so absent is not shown as zero. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][string]$Collector
    )

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $matched = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $Collector })

    return ($matched.Count -gt 0 -and [string](Get-PurviewProperty -InputObject $matched[0] -Name 'status') -in 'Success', 'PartialSuccess')
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
            'ProtectionActivity' { return 'Activity was not read this run. Drop -SkipInsights to include it.' }
            'ClassificationCoverage' { return 'No explicitly requested sensitive information type count was included in this run.' }
            'SharePointSite' { return 'Sites were not enumerated. Pass -IncludeSites to walk them.' }
            default { return 'No result was recorded for this area in this run.' }
        }
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
        Reports which workloads a set of policies covers between them.

    .DESCRIPTION
        Counting policies says nothing about reach: ten policies over one workload leave every
        other workload open. Workload is enrichment and may be absent, in which case coverage is
        reported as unknown rather than as nothing covered.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policy)

    $known = @($Policy | Where-Object { Test-PurviewProperty -InputObject $_ -Name 'Workload' })
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
    foreach ($item in $known) {
        $raw = Get-PurviewProperty -InputObject $item -Name 'Workload'
        # The service returns this as a comma-separated string in some shapes and a list in others.
        $names = if ($raw -is [string]) { $raw -split ',' } else { @(ConvertTo-PurviewArray -InputObject $raw) }
        foreach ($name in $names) {
            $trimmed = ([string]$name).Trim()
            if (-not $trimmed -or $trimmed -in $notAWorkload) { continue }
            $null = $seen.Add($(if ($friendly.ContainsKey($trimmed)) { $friendly[$trimmed] } else { $trimmed }))
        }
    }

    $covered = @($seen | Sort-Object)
    return [pscustomobject]@{
        Known = $true
        Covered = $covered
        Detail = if ($covered.Count -gt 0) { 'Covers ' + ($covered -join ', ') } else { 'No workload was named on any of them' }
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

function Get-PurviewInventory {
    <#
    .SYNOPSIS
        Summarises configuration and qualified activity and inventory signals without judging them.

    .DESCRIPTION
        Findings say what is wrong; this gives the observations a reader needs first. A collector
        that did not run, a query that did not complete and an ambiguous result all report as not
        checked rather than as zero, because none is evidence of absence.
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

    $allLabels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
    # A disabled label is one that was removed. It sits in no picker and protects nothing, so
    # counting it would put the tenant ahead of where it is.
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
            'The taxonomy Microsoft ships has five top level labels and no more than five under any one of them. More than that is a choice to confirm rather than a fault'
        }
        else { 'Within the five of each the taxonomy Microsoft ships stays inside' }
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

    # A label reaches users only through a publishing policy that includes it, and the same label
    # often sits in several, so this is the distinct union rather than a sum across policies.
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
        $reachDetail = if ($reach.Count -lt $labels.Count) { "Of $($labels.Count) defined; $($labels.Count - $reach.Count) in no publishing policy, so nobody can apply them" }
        else { "All $($labels.Count) defined labels are published" }
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
            & $add 'Sensitivity labels' 'Who the labels reach' 'SensitivityLabelPolicy' 'Everyone' "$($everyone.Count) of $($scoped.Count) enabled policies are published to all users, so every licensed user can apply a label"
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
        'The partial read returned {0}; {1} are known to be enforcing, but tenant totals could not be established' -f
            (Format-PurviewCount -Count $dlp.Count -Singular 'policy record'), $enforcingFacts.Count
    }
    elseif ($dlp.Count -eq 0) { 'None defined' }
    elseif ($unknownDlpModes -gt 0) { 'The enforcing total could not be established because {0} of {1} policies did not return a readable mode' -f $unknownDlpModes, $dlp.Count }
    else { '{0} of {1} defined' -f $enforcingFacts.Count, $dlp.Count }
    # One reason stands on its own; several need a total in front of them to add up.
    if ($dlpOther.Count -eq 1) { $dlpDetail += '. {0}' -f $dlpOther[0] }
    elseif ($dlpOther.Count -gt 1) {
        $dlpDetail += '. The other {0}: {1}' -f ($dlp.Count - $enforcingFacts.Count), ($dlpOther -join ', ')
    }

    # Rules ride in this sentence rather than getting a row. The portal lists policies, so a rule
    # count standing on its own gets read as a policy count and read as a discrepancy.
    if ($dlpState.RuleRead -and $dlp.Count -gt 0) {
        if ($dlpState.RuleCount -eq 0) {
            $dlpDetail += if ($dlpState.RuleComplete) { '. No rules are defined on them, so nothing is being matched' }
            else { '. The partial rule read returned no rule records' }
        }
        else {
            $linkedRules = @($dlpState.LinkedRules)
            $enabledLinked = @($linkedRules | Where-Object { $_.DisabledKnown -and -not $_.Disabled })
            $unknownLinked = @($linkedRules | Where-Object { -not $_.DisabledKnown })
            $dlpDetail += '. The rule read returned {0}; {1} linked to exactly one policy' -f
                (Format-PurviewCount -Count $dlpState.RuleCount -Singular 'rule'), $linkedRules.Count
            if (-not $dlpState.RuleComplete) { $dlpDetail += '. This was a partial rule read, so those are returned records rather than tenant totals' }
            if ($enabledLinked.Count -gt 0) {
                $dlpDetail += ', and {0} report Disabled as False' -f $enabledLinked.Count
            }
            if ($unknownLinked.Count -gt 0) {
                $dlpDetail += '. Disabled state was not usable for {0} of the linked rules' -f $unknownLinked.Count
            }
            if ($dlpState.UnresolvedRuleCount -gt 0) {
                $dlpDetail += '. {0} did not identify exactly one collected policy and was not attributed' -f
                    (Format-PurviewCount -Count $dlpState.UnresolvedRuleCount -Singular 'rule')
            }
        }
    }
    elseif ((Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DlpRule') -and $dlp.Count -gt 0) {
        $dlpDetail += '. The rule collector did not return its rule list, so rule state was not assessed'
    }

    & $add 'Data loss prevention' 'DLP policies enforcing' 'DataLossPrevention' $(if (-not $dlpState.PolicyComplete -or $unknownDlpModes -gt 0) { 'Not checked' } else { $enforcingFacts.Count }) $dlpDetail

    # Coverage is per workload, not per policy: ten policies over one workload leave the rest open.
    $dlpWorkloads = Get-PurviewWorkloadCoverage -Policy $enforcing
    if ($dlpState.PolicyComplete -and $unknownDlpModes -eq 0 -and $dlpWorkloads.Known) {
        & $add 'Data loss prevention' 'Workloads an enforcing policy covers' 'DataLossPrevention' $dlpWorkloads.Covered.Count ($dlpWorkloads.Detail)
    }

    $retention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'RetentionPolicy' -Select 'Policies')

    # One cmdlet returns three different things, which the portal keeps on separate pages, so they
    # are separated here too rather than summed into a total no page will ever agree with. Publish
    # sends labels out for people to apply, Apply puts them on content automatically, and anything
    # else retains or deletes directly.
    $kindOf = {
        param($policy)
        $types = ([string](Get-PurviewProperty -InputObject $policy -Name 'RuleTypes'))
        # Microsoft documents Adaptive Protection as automatically creating an auto-apply label
        # policy to preserve what elevated-risk users delete, so it is counted apart from the ones
        # an admin made rather than inflating them.
        if ($types -match '(?i)proactivedataretention') { 'system' }
        elseif ($types -match '(?i)publish') { 'published' }
        elseif ($types -match '(?i)apply') { 'auto-applied' }
        else { 'retention' }
    }

    # Enabled alone is not enforcing. Microsoft documents Test as tested but not enforced, and
    # AuditAndNotify as notifying without enforcing, so neither is retaining anything yet.
    $enforcingRetention = {
        param($set)

        $live = [System.Collections.Generic.List[object]]::new()
        $unknown = 0
        foreach ($policy in $set) {
            $enabled = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Enabled')
            if (-not $enabled.Valid) { $unknown++; continue }
            if (-not [bool]$enabled.Value) { continue }

            $mode = [string](Get-PurviewProperty -InputObject $policy -Name 'Mode')
            if (-not (Test-PurviewProperty -InputObject $policy -Name 'Mode') -or
                [string]::IsNullOrWhiteSpace($mode)) {
                $unknown++
                continue
            }
            if ($mode -ne 'Enforce') { continue }

            # An enabled policy in enforcement mode still does nothing without a rule. HasRules is
            # Boolean evidence from the policy read; missing or malformed evidence stays unknown.
            $hasRules = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $policy -Name 'HasRules')
            if (-not $hasRules.Valid) { $unknown++; continue }
            if ([bool]$hasRules.Value) { $live.Add($policy) }
        }

        [pscustomobject]@{ Live = $live.ToArray(); Unknown = $unknown }
    }

    $typed = @($retention | Where-Object { Test-PurviewProperty -InputObject $_ -Name 'RuleTypes' })
    if ($typed.Count -eq $retention.Count -and $retention.Count -gt 0) {
        foreach ($group in @(
                @{ Kind = 'retention'; Metric = 'Retention policies enforcing' }
                @{ Kind = 'auto-applied'; Metric = 'Retention label auto-apply policies enforcing' }
                @{ Kind = 'published'; Metric = 'Retention label publishing policies enforcing' }
            )) {
            $set = @($retention | Where-Object { (& $kindOf $_) -eq $group.Kind })
            if ($set.Count -eq 0) { continue }
            $state = & $enforcingRetention $set
            if ($state.Unknown -gt 0) {
                $detail = '{0} of {1} policies did not return complete Enabled, Mode and HasRules evidence, so the enforcing total could not be established' -f $state.Unknown, $set.Count
                & $add 'Data lifecycle' $group.Metric 'RetentionPolicy' 'Not checked' $detail
            }
            else {
                $live = @($state.Live)
                $detail = '{0} of {1} defined' -f $live.Count, $set.Count
                # Simulation is a deliberate state, not a half-finished one, so it is named.
                $simulating = @($set | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -match '(?i)^test' })
                $short = $set.Count - $live.Count - $simulating.Count
                if ($simulating.Count -gt 0) { $detail += '. {0} running in simulation' -f $simulating.Count }
                if ($short -gt 0) { $detail += '. {0} not enabled, not enforcing, or without a rule' -f $short }
                & $add 'Data lifecycle' $group.Metric 'RetentionPolicy' $live.Count $detail
            }
        }

        $system = @($retention | Where-Object { (& $kindOf $_) -eq 'system' })
        if ($system.Count -gt 0) {
            & $add 'Data lifecycle' 'System-managed retention policies' 'RetentionPolicy' $system.Count 'Created automatically by Adaptive Protection to preserve content deleted by elevated-risk users for 120 days. Turned on and off through the Adaptive protection setting in Data Lifecycle Management rather than edited as an ordinary policy'
        }
    }
    else {
        # Older snapshots predate the property that tells the three apart, so the combined figure is
        # still reported rather than dropped, with the reason it will not match a portal page.
        $retentionState = & $enforcingRetention $retention
        $liveRetention = @($retentionState.Live)
        $retentionValue = if ($retentionState.Unknown -gt 0) { 'Not checked' } else { $liveRetention.Count }
        $retentionDetail = if ($retention.Count -eq 0) { 'None defined' }
        elseif ($retentionState.Unknown -gt 0) { 'Enabled, Mode or HasRules evidence was incomplete for {0} of {1} policies, so the enforcing total could not be established' -f $retentionState.Unknown, $retention.Count }
        else { '{0} of {1} defined' -f $liveRetention.Count, $retention.Count }
        $retentionDetail += '. Retention policies, retention label auto-apply policies and retention label publishing policies counted together, because what tells them apart was not collected'
        & $add 'Data lifecycle' 'Retention and retention label policies enforcing' 'RetentionPolicy' $retentionValue $retentionDetail
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
            'Whether retention tags are attached could not be read for {0} of {1} configured Exchange {2}, so the total could not be established. {3} can archive or delete mail alongside Microsoft Purview retention.' -f $unknownLinks, $legacy.Count, $policyNoun, $legacySubject
        }
        else {
            $tagVerb = if ($linked -eq 1) { 'has' } else { 'have' }
            '{0} of {1} configured Exchange {2} {3} retention tags. {4} can archive or delete mail alongside Microsoft Purview retention.' -f $linked, $legacy.Count, $policyNoun, $tagVerb, $legacySubject
        }
        & $add 'Data lifecycle' 'Exchange policies with retention tags' 'LegacyRetention' $legacyValue $legacyDetail
    }

    # Retention for Copilot and other AI apps has its own cmdlet, so a tenant can hold one of these
    # and no ordinary retention policy. Reported apart because it covers neither the same locations
    # nor the same obligations.
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
        $appDetail = $scopeDetail + 'These are managed apart from policies covering Exchange, SharePoint, OneDrive and Teams, and do not retain anything in those locations.'
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

    $retentionLabels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'RetentionLabel' -Select 'Labels')
    $records = 0
    $unknownRecordStates = 0
    foreach ($label in $retentionLabels) {
        $recordState = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $label -Name 'IsRecordLabel')
        if (-not $recordState.Valid) { $unknownRecordStates++; continue }
        if ([bool]$recordState.Value) { $records++ }
    }
    $recordDetail = if ($unknownRecordStates -gt 0) {
        '{0} declare content as a record; record status was not returned for {1}' -f $records, $unknownRecordStates
    }
    else { "$records declare content as a record" }
    & $add 'Records management' 'Retention labels' 'RetentionLabel' $retentionLabels.Count $recordDetail

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
        & $add 'Audit' 'Unified audit logging' 'AuditIngestion' $(if ($distinctAuditStates[0]) { 'on' } else { 'off' }) 'The record every other solution reads from'
    }

    $auditRetention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditConfiguration' -Select 'RetentionPolicies')
    & $add 'Audit' 'Custom audit log retention policies' 'AuditConfiguration' $auditRetention.Count 'Beyond the Audit (Premium) default of one year for Exchange, SharePoint, OneDrive and Entra, and 180 days for everything else'

    # IsWorkbenchPolicy is undocumented, and a tenant returned it set on a policy the portal lists
    # as active. Excluding on it hid a real policy.
    $comm = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'CommunicationCompliance' -Select 'Policies')
    & $add 'Communication compliance' 'Policies' 'CommunicationCompliance' $comm.Count 'Configured policy definitions. This read does not establish whether any policy is currently inspecting content, healthy or recently scanned; confirm operational state in the portal.'

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
        elseif ($classifiers.Count -gt 0) { 'None built here, so classification matches only the patterns Microsoft ships' }
        else { 'No sensitive information type was returned' }
        & $add 'Classification' 'Custom sensitive information types' 'Classification' $custom.Count $customDetail
    }

    $ocrBilling = 'Turning it on needs Microsoft Syntex pay-as-you-go billing in place first, and every image scanned is charged.'
    $collectorResults = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
    $ocrResults = @($collectorResults | Where-Object {
            [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'OcrConfiguration'
        })

    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'OcrConfiguration')) {
        & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' ''
    }
    elseif ($ocrResults.Count -ne 1 -or
        [string](Get-PurviewProperty -InputObject $ocrResults[0] -Name 'status') -ne 'Success') {
        & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'Not checked' 'The OCR configuration result was incomplete, so whether images are being scanned could not be established.'
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
                & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'off' ('No configuration exists, so sensitive information inside images goes undetected everywhere. {0}' -f $ocrBilling)
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
                    $ocrDetail = if ($ocrWhere.Count -gt 0) { 'Scanning images in {0}. Only images added after it was turned on are scanned' -f ($ocrWhere -join ', ') }
                    else { 'Turned on, but no location was returned, so where it scans needs confirming in the portal. Only images added after it was turned on are scanned' }
                    & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'on' $ocrDetail
                }
                else {
                    & $add 'Classification' 'OCR scanning' 'OcrConfiguration' 'off' ('Configured but disabled, so images are not being scanned. {0}' -f $ocrBilling)
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
    $licensingEvidence = Resolve-PurviewLicensingEvidence -Licensing $licensingBlock
    if (-not $licensingEvidence.Collected -or -not $licensingEvidence.ListReadable) {
        & $add 'Licensing' 'Subscriptions that affect Purview' 'Licensing' 'Not checked' 'The licensing result did not contain a confirmed Boolean collection state and a readable subscribed SKU list.'
    }
    elseif ($licensingEvidence.BlockConflict) {
        & $add 'Licensing' 'Subscriptions that affect Purview' 'Licensing' 'Not checked' 'Duplicate licensing collector results disagreed. No product entitlement or absence is inferred.'
    }
    else {
        $recognizedProducts = @($licensingEvidence.Entries | Where-Object {
                $_.Classification -eq 'Recognized'
            } | ForEach-Object { $_.Product } | Sort-Object SkuPartNumber -Unique)
        $recognizedNames = @($recognizedProducts | ForEach-Object { [string]$_.DisplayName })
        $detail = if ($recognizedNames.Count -gt 0) {
            'Verified Purview-affecting products: {0}.' -f ($recognizedNames -join ', ')
        }
        else {
            'No product in this version''s verified Purview registry was identified. Only exact verified products appear here.'
        }

        & $add 'Licensing' 'Subscriptions that affect Purview' 'Licensing' $recognizedProducts.Count $detail
    }

    # What a tenant can already reach is the exposure Copilot inherits, so this reports the reports
    # rather than the sites: a completed one carries the counts, and a missing one is the finding.
    if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DataAccessGovernance') {
        $dag = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'Reports')
        $refused = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'EntitiesNotRead')
        $asked = ConvertTo-PurviewNonNegativeInteger -InputObject (Get-PurviewCollectorValue -Snapshot $Snapshot -Collector 'DataAccessGovernance' -Select 'EntitiesAsked')
        $done = @($dag | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Status') -eq 'Completed' })

        # Nothing readable is the licence or the role, and saying no report exists would read as a
        # tenant that never ran one.
        if (-not $asked.Valid -or $asked.Value -eq 0) {
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 'Not checked' 'The data access governance read did not return how many report entities were requested, so an empty result cannot be interpreted.'
        }
        elseif ($refused.Count -ge $asked.Value) {
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 'Not checked' 'Data access governance could not be read. It needs SharePoint Advanced Management, which one assigned Microsoft Copilot licence anywhere in the tenant provides, and the SharePoint Advanced Management Administrator role to read'
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
                    & $add 'Oversharing' 'Sites and accounts with at least one permissioned user' 'DataAccessGovernance' $inReport (($detail + ' The data behind it can be up to 48 hours older than that. A report can be regenerated every 30 days, so an older one describes the tenant as it was').Trim())
                }
            }
        }
        else {
            # Snapshot reports run on demand; the sharing links and EEEU activity reports need data
            # collection switched on first, and Microsoft documents a 24 hour wait after that.
            & $add 'Oversharing' 'Oversharing reports available' 'DataAccessGovernance' 0 'No data access governance report has completed, so how far content reaches has not been measured. Generate one from the SharePoint admin center, under Reports then Data access governance. The site permission and sensitivity label reports run on demand; the sharing links and Everyone except external users reports first need data collection turned on, and become available 24 hours later'
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
                'Matches were recorded during this 30-day window, but no policy is now read as enforcing. A policy might since have changed; the historical window does not establish current policy state.'
            }
            elseif (-not $blockingSignal.Valid) {
                'Matches were recorded during this 30-day window, but the blocking count was incomplete, so how they were handled cannot be established.'
            }
            elseif ($blockingSignal.Value -eq 0) {
                'None of the matching events was blocked during this 30-day window; they may instead have been audited, warned or allowed.'
            }
            elseif ($blockingSignal.Value -eq $dlpSeen) { 'Every one of them was blocked outright during this 30-day window' }
            elseif ($blockingSignal.Value -eq 1) { 'One of them was blocked outright during this 30-day window; the rest were audited or warned' }
            else { '{0} of them were blocked outright during this 30-day window; the rest were audited or warned' -f $blockingSignal.Value }
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
        An opt-in that could not be read is never reported as off. A customer being told a switch is
        off when nobody looked is worse than being told plainly that it needs checking by hand.
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

        # Two different kinds of unknown. One is a gap in what Microsoft exposes and will not close
        # by connecting to anything; the other is this run not having looked.
        $state = 'Confirm in portal'
        $detail = 'Current value cannot be read outside the portal.'

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
                    $detail = '{0} is currently set to {1}. The expected value is {2}.' -f $item.Setting,
                        (Get-PurviewProperty -InputObject $match[0] -Name 'Value'),
                        (Get-PurviewProperty -InputObject $match[0] -Name 'Expected')
                    # A collector that knows why a value reads as it does says so, which is the
                    # difference between a setting turned off and one nobody has ever written.
                    $note = [string](Get-PurviewProperty -InputObject $match[0] -Name 'Detail')
                    if ($note) { $detail = '{0} {1}.' -f $detail, $note }
                }
            }
            else {
                # Collectors that dump a configuration object wholesale carry no verdict of their
                # own, so the expected value is declared alongside the prerequisite instead.
                $actual = [string](Get-PurviewProperty -InputObject $match[0] -Name 'Value')
                $state = if ($actual -eq [string]$item.ExpectedValue) { 'As recommended' } else { 'Needs attention' }
                $detail = '{0} is currently set to {1}. The expected value is {2}.' -f $item.Setting, $actual, $item.ExpectedValue
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
                        # Endpoint DLP cannot be enabled on a device the tenant never onboarded, so this
                        # is the one reading that settles the switch without opening the portal.
                        $state = 'As recommended'
                        $detail = '{0} onboarded with endpoint DLP enabled, so device monitoring is on.' -f (Format-PurviewCount -Count $dlpEnabled -Singular 'device is' -Plural 'devices are')
                        $invalid = $dlpEnabled - $deviceCounts['ConfigurationValid']
                        $rtpOff = $deviceCounts['RealTimeProtectionOff']
                        if ($invalid -gt 0) { $detail += ' {0} not holding a valid configuration.' -f $invalid }
                        if ($rtpOff -gt 0) { $detail += ' {0} report Defender real-time protection off.' -f $rtpOff }
                    }
                    else {
                        # No documented interface reports the monitoring switch: turning it on left the
                        # advanced hunting rows, the device cmdlets and the policy configuration identical.
                        $state = 'Confirm in portal'
                        $detail = 'Check this under Settings > Device onboarding > Devices, where Windows and macOS are turned on separately.'
                        $detail += if ($defenderOnboarded -gt 0) {
                            ' {0} already onboarded through Defender for Endpoint and ready to be monitored, but none is enforcing endpoint DLP.' -f (Format-PurviewCount -Count $defenderOnboarded -Singular 'device is' -Plural 'devices are')
                        }
                        elseif ($reporting -gt 0) {
                            ' {0} endpoint DLP status, but none is enforcing it.' -f (Format-PurviewCount -Count $reporting -Singular 'device reports' -Plural 'devices report')
                        }
                        else { ' No device is reporting endpoint DLP status.' }
                        $detail += ' Devices stay unprotected until monitoring is on and a DLP policy covers the Devices location.'
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
            # The tenant reports the scheme outright, which settles it. Only Modern has been seen, so
            # any other value falls through to the signals below rather than being read as a verdict.
            $reported = [string](@(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'TenantPolicyConfig' -Select 'Settings') |
                    Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -eq 'LabelScheme' } |
                    Select-Object -First 1 | ForEach-Object { Get-PurviewProperty -InputObject $_ -Name 'Value' })

            # Positive only, on two signals. A label group holds nothing but a name, description,
            # colour and priority, so a label that has sublabels and carries encryption cannot be
            # one; and Microsoft migrates a published parent into a sublabel of the same name
            # precisely because a group is not selectable in its own right. Neither signal firing
            # leaves the scheme unread rather than modern.
            $labels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
            $groups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($label in $labels) {
                $parentRef = [string](Get-PurviewProperty -InputObject $label -Name 'ParentId')
                if (-not [string]::IsNullOrWhiteSpace($parentRef)) { $null = $groups.Add($parentRef) }
            }

            $publishedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($policy in @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabelPolicy' -Select 'Policies')) {
                foreach ($name in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Labels'))) {
                    $null = $publishedNames.Add([string]$name)
                }
            }

            $encrypting = [System.Collections.Generic.List[string]]::new()
            $publishedGroups = [System.Collections.Generic.List[string]]::new()
            foreach ($label in $labels) {
                if (-not $groups.Contains([string](Get-PurviewProperty -InputObject $label -Name 'Guid'))) { continue }
                $name = [string](Get-PurviewProperty -InputObject $label -Name 'Name')
                $encryption = ConvertTo-PurviewBoolean -InputObject (Get-PurviewProperty -InputObject $label -Name 'EncryptionEnabled')
                if ($encryption.Valid -and [bool]$encryption.Value) { $encrypting.Add($name) }
                elseif ($publishedNames.Contains($name)) { $publishedGroups.Add($name) }
            }

            if ($reported -eq 'Modern') {
                $state = 'As recommended'
                $detail = 'The tenant reports the modern label scheme, so the migration has already been done.'
            }
            elseif ($groups.Count -eq 0) {
                if ($labels.Count -gt 0) {
                    $state = 'As recommended'
                    $detail = 'No label has sublabels, so there is no parent label to migrate.'
                }
            }
            elseif ($encrypting.Count -gt 0 -or $publishedGroups.Count -gt 0) {
                $state = 'Needs attention'
                $reasons = [System.Collections.Generic.List[string]]::new()
                if ($encrypting.Count -gt 0) {
                    $reasons.Add($(if ($encrypting.Count -eq 1) { 'one label with sublabels carries encryption, which a label group cannot hold' }
                            else { '{0} labels with sublabels carry encryption, which a label group cannot hold' -f $encrypting.Count }))
                }
                if ($publishedGroups.Count -gt 0) {
                    $reasons.Add($(if ($publishedGroups.Count -eq 1) { 'one label with sublabels is published in its own right' }
                            else { '{0} labels with sublabels are published in their own right' -f $publishedGroups.Count }))
                }
                $detail = 'Still on parent labels: {0}. Migrating turns them into label groups.' -f ($reasons -join ', and ')
            }
            else {
                $detail = 'Labels are organised in two tiers, but nothing separates a parent label from a label group here, so which scheme is in use cannot be read outside the portal.'
            }
        }
        elseif ($item.ContainsKey('RuleId')) {
            $state = switch ([string]$backingRule[0].status) {
                'Pass' { 'As recommended' }
                'Fail' { 'Needs attention' }
                'Warning' { 'Needs attention' }
                default { 'Not read' }
            }
            $detail = if ($state -eq 'Needs attention' -and $item.ContainsKey('Summary')) { [string]$item.Summary }
            elseif ($state -eq 'As recommended' -and $item.ContainsKey('SummaryOk')) { [string]$item.SummaryOk }
            # The engine states an assertion precisely, which reads as machinery in a list a
            # customer is meant to act on, so a plain sentence is preferred where one is given.
            else { [string]$backingRule[0].reason }
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
    $rank = @{ 'Needs attention' = 0; 'Confirm in portal' = 1; 'Not read' = 2; 'Seen recently' = 3; 'Evidence found' = 3; 'Granted' = 3; 'In use' = 3; 'As recommended' = 4 }
    return @($output | Sort-Object @{ Expression = { if ($rank.ContainsKey([string]$_.State)) { $rank[[string]$_.State] } else { 4 } } }, Name)
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

    # A tenant opt-in is a check even though it carries no rule id, and the Copilot section reads
    # collectors of its own. Crediting rules alone reports both of those as read by nothing.
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

        # A verdict word cannot separate one failure from four, so the outcomes are counted out.
        # The total is not repeated here; the Rules column beside it already carries that.
        $tally = [System.Collections.Generic.List[string]]::new()
        foreach ($bucket in @(
                @{ Label = 'passed'; Match = { $_.status -eq 'Pass' } }
                @{ Label = 'need attention'; One = 'needs attention'; Match = { $_.status -eq 'Fail' } }
                @{ Label = 'to review'; Match = { $_.status -in 'Warning', 'NeedsReview' } }
                @{ Label = 'not checked'; Match = { $_.status -in 'NotCollected', 'Unsupported' } }
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
                    'Success' { 'Read in full' }
                    'PartialSuccess' { 'Read in part' }
                    'NotConnected' { 'Not connected' }
                    'NotPermitted' { 'Not permitted' }
                    'Unsupported' { 'No documented interface' }
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
        Decides whether a SKU is one that changes what Purview can do.

    .DESCRIPTION
        A tenant buys plenty that has no bearing here. Listing every subscription turns the
        licensing section into a procurement report and buries the two or three lines that decide
        which capabilities are available at all.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()][object]$Sku)

    return (Get-PurviewSkuEvidence -Sku $Sku).Classification -eq 'Recognized'
}

function Get-PurviewLicensingAnalysis {
    <# .SYNOPSIS Reports which capabilities the tenant's SKUs unlock and which they block. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $block = Get-PurviewProperty -InputObject $Snapshot -Name 'licensing'
    # Retained for compatibility with callers from earlier versions; applicability is now withheld
    # before customer rendering, so licensing rows no longer derive anything from finding status.
    $null = $Finding
    $output = [System.Collections.Generic.List[object]]::new()
    $evidence = Resolve-PurviewLicensingEvidence -Licensing $block

    if (-not $evidence.Collected) {
        $output.Add([pscustomobject]@{
                Sku = 'Not collected'
                State = 'Unknown'
                Detail = 'Subscribed SKUs were not collected, so licensing could not be assessed. Connect Microsoft Graph with LicenseAssignment.Read.All.'
            })
        return $output.ToArray()
    }

    if (-not $evidence.ListReadable) {
        $output.Add([pscustomobject]@{
                Sku = 'Not collected'
                State = 'Unknown'
                Detail = 'The licensing result did not include its subscribed SKU list, so licensing could not be assessed.'
            })
        return $output.ToArray()
    }

    $currentProducts = @($evidence.Entries | Where-Object {
            $_.Classification -eq 'Recognized' -and $_.Enabled -and
            $evidence.ProductConflicts -notcontains [string]$_.Product.SkuPartNumber
        } | ForEach-Object { $_.Product } | Sort-Object SkuPartNumber -Unique)
    $currentNames = @($currentProducts | ForEach-Object { [string]$_.DisplayName })

    $detail = if ($evidence.BlockConflict) {
        'Duplicate licensing collector results disagreed, so neither current entitlement nor absence is inferred.'
    }
    elseif ($currentNames.Count -gt 0) {
        'Current entitlement established from coherent skuPartNumber and skuId pairs with exact capabilityStatus Enabled: {0}.' -f
            ($currentNames -join ', ')
    }
    elseif ($evidence.CanProveExclusion -and $evidence.Entries.Count -eq 0) {
        'The complete licensing collection returned no subscribed products.'
    }
    elseif ($evidence.CanProveExclusion) {
        'No product in the verified registry reported exact capabilityStatus Enabled.'
    }
    else {
        'Current entitlement could not be established from the available product evidence. Checks are evaluated rather than suppressed.'
    }

    $output.Add([pscustomobject]@{
            Sku = 'Entitlement recognised'
            State = if ($currentNames.Count -gt 0 -and -not $evidence.BlockConflict) { 'Recognised' } else { 'Unknown' }
            Detail = $detail
        })

    foreach ($entry in @($evidence.Entries | Where-Object { $_.Classification -eq 'Recognized' })) {
        $productName = [string]$entry.Product.DisplayName
        $productConflict = $evidence.ProductConflicts -contains [string]$entry.Product.SkuPartNumber

        if ($evidence.BlockConflict) {
            $output.Add([pscustomobject]@{
                    Sku = $productName
                    State = 'Unknown'
                    Detail = 'This exact product appeared in licensing collector results that disagreed, so it grants and denies nothing.'
                })
            continue
        }
        if ($productConflict) {
            $output.Add([pscustomobject]@{
                    Sku = $productName
                    State = 'Unknown'
                    Detail = 'Conflicting duplicate identity or capabilityStatus evidence affects this product, so it grants and denies nothing.'
                })
            continue
        }
        if (-not $entry.Enabled) {
            $reportedStatus = if ($entry.StatusKnown) { [string]$entry.CapabilityStatus } else { 'Unknown' }
            $output.Add([pscustomobject]@{
                    Sku = $productName
                    State = $reportedStatus
                    Detail = 'The product identity is recognized, but only exact case-sensitive capabilityStatus Enabled establishes current entitlement. Checks are still evaluated.'
                })
            continue
        }

        $seatState = 'Seats not reported'
        $seatDetail = 'Seat assignment was unavailable. This does not alter the entitlement established by product identity and capabilityStatus.'
        if ($entry.SeatCountsKnown) {
            $enabled = [long]$entry.EnabledSeats
            $consumed = [long]$entry.ConsumedSeats
            $spare = $enabled - $consumed
            $seatState = "$consumed of $enabled assigned"
            $seatDetail = if ($spare -gt 0) {
                "$(Format-PurviewCount -Count $spare -Singular 'seat') $(if ($spare -eq 1) { 'is' } else { 'are' }) paid for and assigned to nobody."
            }
            elseif ($spare -lt 0) {
                "$(Format-PurviewCount -Count ([math]::Abs($spare)) -Singular 'more seat') $(if ($spare -eq -1) { 'is' } else { 'are' }) assigned than the subscription lists as enabled."
            }
            elseif ($enabled -eq 0) { 'No enabled seats were reported.' }
            else { 'Every seat is assigned.' }
            $seatDetail += ' Seat arithmetic is diagnostic and does not determine entitlement.'
        }

        $output.Add([pscustomobject]@{
                Sku = $productName
                State = $seatState
                Detail = $seatDetail
            })
    }

    return $output.ToArray()
}

function Get-PurviewRemediationPart {
    <#
    .SYNOPSIS
        The pieces a remediation script is assembled from, so any subset can be built.

    .DESCRIPTION
        The report lets an operator pick which changes to take, and the file on disk takes all of
        them. Both assemble from these pieces rather than each formatting PowerShell separately,
        which is how the two would drift apart.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Prerequisite,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TenantName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$GeneratedAt,
        [AllowEmptyString()][string]$AdminUrl = ''
    )

    $nl = [Environment]::NewLine
    # The tenant names itself, so it cannot be trusted to stay inside a block comment: a line break
    # or a comment terminator in it would leave the rest of the header as code.
    $safeHeader = { param($s) ((([string]$s) -replace '[\r\n]+', ' ') -replace '#>', '#').Trim() }
    $header = @(
        '<#'
        '    Remediation for Microsoft Purview tenant opt-ins.'
        ''
        "    Tenant:     $(& $safeHeader $TenantName)"
        "    Assessed:   $(& $safeHeader $GeneratedAt)"
        "    Generator:  Purview advisor $script:ToolVersion"
        '    Changes:    {COUNT}'
        ''
        '    Every change here is tenant-wide. Each one is explained as it comes up and'
        '    applied only if you answer yes, so nothing changes while you read. Put them'
        '    through change control before you start.'
        '#>'
        ''
        '[CmdletBinding()]'
        ("param([string]`$AdminUrl = '{0}')" -f ($AdminUrl -replace "'", "''"))
        ''
        "`$ErrorActionPreference = 'Stop'"
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
        '    # Nothing is applied without a person answering. A non-interactive host cannot answer,'
        '    # so it skips rather than blocking a pipeline or, worse, taking silence for consent.'
        '    if (-not [Environment]::UserInteractive) { Write-Host "  Skipped: no interactive session to confirm in."; return $false }'
        '    return ((Read-Host "  Apply this change? [y/N]") -match "^\s*(y|yes)\s*$")'
        '}'
        ''
        'function Test-PurviewLiveSession {'
        '    param([string]$UriPattern)'
        '    # Compliance and Exchange Online export the same cmdlet names, so a session is'
        '    # recognised by the endpoint it points at rather than by what happens to be loaded.'
        '    if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $false }'
        '    return [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue |'
        '        Where-Object { [string]$_.ConnectionUri -match $UriPattern -and [string]$_.State -eq "Connected" })'
        '}'
        ''
        'function Connect-PurviewCompliance {'
        '    if (Test-PurviewLiveSession -UriPattern "compliance\.protection\.outlook\.com") {'
        '        Write-Host "Reusing the Security & Compliance session already signed in."'
        '        return $true'
        '    }'
        '    try { Connect-IPPSSession; return $true }'
        '    catch {'
        '        # Graph and ExchangeOnlineManagement each ship their own MSAL and .NET keeps the one'
        '        # loaded first, so a session that already reached Graph cannot then reach compliance.'
        '        # Ordering inside this script cannot undo a sign-in from earlier in the same window,'
        '        # so this reports the block and lets the changes that do not need it carry on.'
        '        if ($_.Exception -is [System.MissingMethodException] -or "$($_.Exception.Message)" -match "Microsoft\.Identity\.Client") {'
        '            Write-Host ""'
        '            Write-Host "Security & Compliance cannot be reached from this PowerShell session." -ForegroundColor Yellow'
        '            Write-Host "Microsoft Graph and ExchangeOnlineManagement each ship their own copy of MSAL," -ForegroundColor Yellow'
        '            Write-Host "and .NET keeps whichever loaded first. Something here reached Graph already." -ForegroundColor Yellow'
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
        '        ''try {'','
        '        ''    Connect-IPPSSession -ErrorAction Stop'','
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
        '    $run = Start-Process -FilePath $shell -ArgumentList ''-NoLogo'', ''-NoProfile'', ''-File'', $file -Wait -PassThru'
        '    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue'
        '    return $run.ExitCode -eq 0'
        '}'
        ''
    ) -join $nl

    # A step skipped because a service was unreachable is not done, and saying so once at the end is
    # what stops it being lost in the scroll.
    $footer = @(
        ''
        'if ($deferred.Count -gt 0) {'
        '    Write-Host ""'
        '    Write-Host "Not finished. Close this window, open a new PowerShell session, and run:" -ForegroundColor Yellow'
        '    foreach ($item in $deferred) { Write-Host "  $item" -ForegroundColor Yellow }'
        '}'
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
            'if (-not (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue)) {'
            '    # UseWindowsPowerShell exists only on PowerShell 7, and this script is often run'
            '    # from Windows PowerShell where the module loads natively.'
            '    if ($PSVersionTable.PSVersion.Major -ge 6) { Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell }'
            '    else { Import-Module Microsoft.Online.SharePoint.PowerShell }'
            '}'
            '# The module exposes no session test, so a read that only a live session can answer is one.'
            '$spoLive = $false'
            'try { $null = Get-SPOTenant -ErrorAction Stop; $spoLive = $true } catch { $spoLive = $false }'
            'if ($spoLive) { Write-Host ''Reusing the SharePoint session already signed in.'' }'
            'else {'
            '    # The system browser is what makes passkeys and other platform authenticators usable.'
            '    # Without it the module shows its own dialog, which can only take a password, and an'
            '    # older module has no such parameter, so the fallback covers both.'
            '    try { Connect-SPOService -Url $AdminUrl -UseSystemBrowser $true -ErrorAction Stop }'
            '    catch { Connect-SPOService -Url $AdminUrl -ErrorAction Stop }'
            '}'
            ''
        ) -join $nl
        SecurityAndCompliance = @(
            '# Security & Compliance, before Graph so its own MSAL is the copy .NET keeps.'
            '$complianceReady = Connect-PurviewCompliance'
            ''
        ) -join $nl
        Graph = @(
            '# Microsoft Graph, for the Microsoft Entra directory setting behind container labels.'
            '# Microsoft documents these two modules for this change rather than the whole SDK.'
            'foreach ($module in @(''Microsoft.Graph.Authentication'', ''Microsoft.Graph.Beta.Identity.DirectoryManagement'')) {'
            '    if (Get-Module -ListAvailable -Name $module) { continue }'
            '    if (Confirm-PurviewChange -Change "Install $module on this machine" -Why ''The Entra directory setting is read and written through this module.'' -Command "Install-Module $module -Scope CurrentUser") {'
            '        Install-Module $module -Scope CurrentUser'
            '    }'
            '    else { throw "$module is needed to enable container labels." }'
            '}'
            '# Signing in again is only worth it when the session on hand lacks the scope to write.'
            '$graphScope = ''Directory.ReadWrite.All'''
            '$graphContext = Get-MgContext -ErrorAction SilentlyContinue'
            'if ($graphContext -and $graphScope -in @($graphContext.Scopes)) { Write-Host ''Reusing the Microsoft Graph session already signed in.'' }'
            'else { Connect-MgGraph -Scopes $graphScope }'
            ''
        ) -join $nl
    }

    $items = [System.Collections.Generic.List[object]]::new()
    # A line break in tenant text would close the comment and leave whatever follows as code in a
    # script an operator runs, so anything written into one is flattened to a single line first.
    $comment = { param($s) (([string]$s) -replace '[\r\n]+', ' ').Trim() }
    # Single quotes around the command: one containing $true must reach the operator literally
    # rather than interpolating when it is printed for confirmation.
    $q = { param($s) "'" + (([string]$s) -replace "'", "''") + "'" }
    foreach ($item in @($Prerequisite | Where-Object { ($_.State -eq 'Needs attention' -and ($_.Command -or $null -ne $_.Script)) -or @($_.Candidates).Count -gt 0 })) {
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add(('# {0}' -f (& $comment $item.Name)))
        $lines.Add(('#   Now:         {0}' -f (& $comment $item.Detail)))
        $lines.Add(('#   Why:         {0}' -f (& $comment $item.Why)))
        if ($item.Caution) { $lines.Add(('#   CAUTION:     {0}' -f (& $comment $item.Caution))) }
        $lines.Add(('#   Reference:   {0}' -f (& $comment $item.Url)))

        if ($null -ne $item.Script) {
            if ([string]$item.Script.Builder -eq 'ContainerLabel') {
                # A tenant that has never had group settings written has no Group.Unified object at
                # all, so there is nothing to update and it has to be created from the template
                # first. Both paths end at the same value, which is why the script decides rather
                # than asking the operator which case they are in.
                $lines.Add('$grpUnifiedSetting = Get-MgBetaDirectorySetting | Where-Object { $_.Values.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1')
                $lines.Add('$currentValue = if ($grpUnifiedSetting) { [string]($grpUnifiedSetting.Values | Where-Object { $_.Name -eq ''EnableMIPLabels'' } | Select-Object -First 1 -ExpandProperty Value) } else { '''' }')
                $lines.Add('if ($currentValue -eq ''True'') { Write-Host ''  EnableMIPLabels is already True. Nothing to change.'' }')
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
                $lines.Add('        Write-Host ''  Labels synchronised. Allow up to 24 hours before they can be assigned to a group.''')
                $lines.Add('    }')
                $lines.Add('    else {')
                $lines.Add('        Write-Host ''  EnableMIPLabels is set, but this session cannot reach Security & Compliance.'' -ForegroundColor Yellow')
                $lines.Add('        Write-Host ''  Until the labels are synchronised, none can be applied to a group, Team or site.'' -ForegroundColor Yellow')
                $lines.Add('        $syncCommand = ''Connect-IPPSSession; Execute-AzureAdLabelSync''')
                $lines.Add('        if (Confirm-PurviewChange -Change ''Synchronise the labels in a new PowerShell window'' -Why ''A new process is not bound to the sign-in library this one already loaded, so the sync can still be completed now.'' -Command $syncCommand) {')
                $lines.Add('            if (Invoke-PurviewInNewSession -Command ''Execute-AzureAdLabelSync'') {')
                $lines.Add('                Write-Host ''  Labels synchronised. Allow up to 24 hours before they can be assigned to a group.'' -ForegroundColor Green')
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

            # Migration itself runs in the portal and cannot be scripted. What can be is Microsoft's
            # own before and after pair: record which policies publish a parent label, then unpublish
            # the sublabels migration creates from those same policies.
            $lines.Add('$path = Join-Path (Get-Location) ''ParentLabelPublishing.csv''')
            # Which half of Microsoft's pair to run is decided by whether the record exists yet,
            # rather than by a switch the operator has to remember on the second run.
            $lines.Add('if (Test-Path -Path $path) {')
            $lines.Add('    foreach ($row in @(Import-Csv -Path $path)) {')
            $lines.Add('        $change = "Unpublish {0} from {1}" -f $row.ParentLabel, $row.Policy')
            $lines.Add('        $cmd = "Set-LabelPolicy -Identity ''{0}'' -RemoveLabels ''{1}''" -f $row.Policy, $row.ParentLabel')
            $lines.Add('        if (Confirm-PurviewChange -Change $change -Why ''Migration created this sublabel from a parent label of the same name, and left it published.'' -Command $cmd) {')
            $lines.Add('            Set-LabelPolicy -Identity $row.Policy -RemoveLabels $row.ParentLabel')
            $lines.Add('        }')
            $lines.Add('        else { Write-Host ''  Skipped.'' }')
            $lines.Add('    }')
            $lines.Add('}')
            $lines.Add('else {')
            $lines.Add('    $parentIds = @(Get-Label | Where-Object { $_.ParentId } | ForEach-Object { [string]$_.ParentId } | Sort-Object -Unique)')
            $lines.Add('    $parentNames = @(Get-Label | Where-Object { $parentIds -contains [string]$_.Guid } | ForEach-Object { [string]$_.Name })')
            $lines.Add('    $record = foreach ($policy in Get-LabelPolicy) {')
            $lines.Add('        foreach ($name in @($policy.Labels)) {')
            $lines.Add('            if ($parentNames -contains [string]$name) { [pscustomobject]@{ Policy = $policy.Name; ParentLabel = [string]$name } }')
            $lines.Add('        }')
            $lines.Add('    }')
            $lines.Add('    @($record) | Export-Csv -Path $path -NoTypeInformation')
            $lines.Add('    Write-Host ("Recorded {0} publishing pairs to {1}. Nothing was changed." -f @($record).Count, $path)')
            $lines.Add('    Write-Host ''Migrate in the portal, then run this again to unpublish the sublabels migration created.''')
            $lines.Add('}')
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

        if (@($item.Candidates).Count -gt 0) {
            # Which of these should go live is a decision per policy, so the script lists them and
            # applies only what is chosen rather than turning the whole set on.
            $quoted = @($item.Candidates | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
            $lines.Add(('$candidates = @({0})' -f $quoted))
            $lines.Add(("Write-Host '{0}:'" -f ($item.Choose.Prompt -replace "'", "''")))
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
            $lines.Add('    if (Confirm-PurviewChange -Change "Turn on $name" -Why ''' +
                (([string]$item.Why) -replace "'", "''") + ''' -Command "' + $applyCmd + '") {')
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
    # The @() wraps the whole conditional: assigning an empty result from inside one yields $null,
    # and reading .Count off that throws rather than reporting nothing to do.
    $chosen = @(if ($null -eq $Only) { $Part.items } else { $Part.items | Where-Object { $_.name -in $Only } })
    $text = $Part.header -replace '\{COUNT\}', $chosen.Count

    if ($chosen.Count -eq 0) {
        return $text + $nl + "Write-Host 'Nothing selected to remediate.' -ForegroundColor Green" + $nl
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

    # Get-SupervisoryReviewPolicyV2 reports no locations, so the name is the only signal, and a
    # policy cannot be renamed once created. AI is case-sensitive so it misses ordinary words.
    $namesAi = { param($name) [string]$name -match '(?i)copilot' -or [string]$name -cmatch '\bAI\b' }

    # Setup before recommendations: labels reach Copilot content only once SharePoint and OneDrive
    # process them, so the rest of this section is theoretical until this one is on.
    $prereq = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding |
        Where-Object { $_.Name -eq 'Labels processed for Office files in SharePoint and OneDrive' })
    if ($prereq.Count -gt 0) {
        & $add 'Labels processed in SharePoint and OneDrive' $prereq[0].State $prereq[0].Detail 'Until this is on, SharePoint and OneDrive cannot process the contents of a file that a label encrypted, so search, eDiscovery, data loss prevention and co-authoring all stop working on it. The encryption still travels with the file; what fails is every service that has to read inside it, DLP for Copilot included.' $script:DocUrl.SharePointLabelledFiles
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
    $encryptionWhy = 'Sensitivity-label encryption adds identity and usage-right enforcement to Microsoft 365 permissions. Copilot works as the requesting user: anyone not authorized by the encryption policy cannot decrypt the content, while an authorized user needs effective VIEW and EXTRACT rights for Copilot to summarize it. Label-wide rights alone cannot prove every item is included or excluded because permissions can be assigned or changed for the item.'

    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'SensitivityLabel')) {
        & $add $encryptionControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'SensitivityLabel') $encryptionWhy $encryptionUrl
    }
    elseif ($encrypting.Count -gt 0) {
        $count = Format-PurviewCount -Count $encrypting.Count -Singular 'label'
        $verb = if ($encrypting.Count -eq 1) { 'applies' } else { 'apply' }
        $detail = if ($unknownEncryptionStates -gt 0) { "At least $count $verb encryption." }
        else { "$count $verb encryption." }
        $detail += ' Copilot works as the requesting user: anyone not authorized by the encryption policy cannot decrypt the content, and an authorized user needs effective VIEW and EXTRACT rights for Copilot to summarize it.'

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
        & $add $encryptionControl 'Not configured' 'No sensitivity label applies encryption.' $encryptionWhy $encryptionUrl
    }

    # The Copilot DLP location is only offered in the Custom template and disables every other
    # location, so a policy carrying it is identifiable by that alone.
    $copilotWhy = 'The Copilot location is what lets DLP keep sensitive prompts out of web search, stop labelled files being summarised, and exclude untrusted external mail from grounding. Microsoft documents that DLP alerts raised only by the Copilot location are not evaluated by the insider risk DLP alert indicator, so this protects content without feeding user risk.'
    $copilotUrl = 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about'
    $dlpState = Get-PurviewDlpPolicyRuleAnalysis -Snapshot $Snapshot
    $dlpFacts = @($dlpState.Policies)
    $dlp = @($dlpFacts | ForEach-Object { $_.Policy })
    if (-not $dlpState.PolicyRead) {
        & $add 'DLP policy scoped to Copilot' 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DataLossPrevention') $copilotWhy $copilotUrl
    }
    else {
        # Two ways to settle it. No property names the Copilot location, but Microsoft documents
        # selecting it as disabling every other location, which makes a policy holding one of them
        # provably not a Copilot policy; and it documents by name the Copilot policy posture
        # creates, which settles that policy whatever its locations read as.
        $namesCopilot = { param($policy)
            $name = [string](Get-PurviewProperty -InputObject $policy -Name 'Name')
            (& $isDspm $name) -and $name -match '(?i)copilot'
        }

        # The rules are where the answer actually is. Microsoft documents an action only this
        # location offers, so a rule naming Copilot settles the policy that owns it.
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

        # Configuration proves scope; exact policy mode plus an enabled linked rule proves that the
        # configured scope is operating. Neither a generated name nor simulation earns that credit.
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
                # A policy whose rules were read and name Copilot nowhere is not a Copilot policy,
                # because the action that location offers would have to appear in one of them.
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
                '1 enforcing DLP policy targets the Microsoft 365 Copilot and Copilot Chat location and has an enabled linked rule.'
            }
            else {
                "$($activeCovering.Count) enforcing DLP policies target the Microsoft 365 Copilot and Copilot Chat location and have an enabled linked rule."
            }
            & $add 'DLP policy scoped to Copilot' 'As recommended' $activeDetail $copilotWhy $copilotUrl
        }
        elseif ($covering.Count -gt 0 -and $unknownCovering.Count -gt 0) {
            & $add 'DLP policy scoped to Copilot' 'Not read' "$(Format-PurviewCount -Count $covering.Count -Singular 'DLP policy is configured' -Plural 'DLP policies are configured') for Copilot, but exact enforcement mode and enabled linked-rule evidence were incomplete, so current protection could not be established." $copilotWhy $copilotUrl
        }
        elseif ($covering.Count -gt 0) {
            & $add 'DLP policy scoped to Copilot' 'Needs attention' "$(Format-PurviewCount -Count $covering.Count -Singular 'DLP policy is configured' -Plural 'DLP policies are configured') for Copilot, but none is both in Enable mode and backed by an enabled linked rule." $copilotWhy $copilotUrl
        }
        elseif ($dlp.Count -eq 0 -and $dlpState.PolicyComplete) {
            & $add 'DLP policy scoped to Copilot' 'Not configured' 'No DLP policy exists in this tenant, so nothing covers Copilot.' $copilotWhy $copilotUrl
        }
        elseif ($undecided.Count -eq 0 -and $dlpState.PolicyComplete) {
            & $add 'DLP policy scoped to Copilot' 'Not configured' "None of the $($dlp.Count) DLP policies targets the Microsoft 365 Copilot and Copilot Chat location. Each one covers another location, which that location cannot be combined with." $copilotWhy $copilotUrl
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

    # Whether anything is watching Copilot, not just what it can reach. Prompts and responses land
    # in the audit record, which is what posture management, insider risk and eDiscovery read from.
    $recordControl = 'Copilot interactions being recorded'
    $recordWhy = 'Prompts and responses are written to the audit record and surface in Activity Explorer as AI interaction events. That record is what Data Security Posture Management, insider risk and eDiscovery all read from, so without it there is nothing showing what was asked or what came back.'
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
    $commWhy = 'Communication compliance is what reviews prompts and responses for unethical or risky content. Microsoft ships a Copilot interactions template for it, and Data Security Posture Management creates one in a single click. Without a policy like that, nothing inspects what people are actually asking.'
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
            & $add $commControl 'Not configured' 'No communication compliance policy exists, so nothing reviews what is being asked of Copilot.' $commWhy $commUrl
        }
        else {
            & $add $commControl 'Needs review' ('{0}, none of them named for Copilot or AI. Communication compliance does not report which locations a policy covers, so if one of these does reach prompts it has to be confirmed in the portal.' -f (Format-PurviewCount -Count $comm.Count -Singular 'policy exists' -Plural 'policies exist')) $commWhy $commUrl
        }
    }

    $retControl = 'Retention covering Copilot interactions'
    $retWhy = 'Copilot prompts and responses are already stored in a hidden folder in each user''s mailbox, where eDiscovery can find them without any policy. A retention policy is what puts you in control of them: keeping them for a set period even if someone deletes their Copilot history, or disposing of them on a schedule. Without one, how long they survive is not your decision.'
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
            & $add $retControl 'As recommended' ('{0} enabled for the Microsoft Copilot experiences location and has a linked retention rule.' -f (Format-PurviewCount -Count $appRet.ActiveCount -Singular 'retention policy is' -Plural 'retention policies are')) $retWhy $retUrl
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

    # Everything above governs Microsoft 365 Copilot alone. These policies span Copilot, agents and
    # third-party AI sites together, so they are banded apart rather than filed under either one.
    $dspmControl = 'Data Security Posture Management one-click policies'
    $dspmWhy = 'Data Security Posture Management creates policies in one click across data loss prevention, insider risk, communication compliance and collection, covering third-party AI sites and agents as well as Copilot. Fixed names beginning "DSPM for AI", or "Microsoft AI Hub" for policies created during preview, identify configured definitions only; the names do not establish current operation.'
    $dspmUrl = 'https://learn.microsoft.com/purview/data-security-posture-management-learn-about'
    $dspmBand = 'All AI apps, Copilot included'
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
        # Four of the twelve one-click policies are insider risk or collection policies, and neither
        # is reachable from PowerShell, so what is found here is a floor rather than the total.
        $floor = 'Insider risk and collection policies are not readable outside the portal, so this counts only the data loss prevention and communication compliance ones.'
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
            & $add $dspmControl 'Needs review' ('No matching data loss prevention or communication compliance policy name was returned. That does not rule out insider risk or collection policies, which are portal-only; confirm the complete one-click policy set there. {0}' -f $floor) $dspmWhy $dspmUrl $dspmBand
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
    <# .SYNOPSIS Reports distinct SITs only when every turned-on policy rule is accounted for. #>
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
    if ($policies.Count -eq 0) {
        $answer.PolicyDetail = 'No auto-labeling policy is defined.'
    }
    else {
        $parts = [System.Collections.Generic.List[string]]::new()
        $parts.Add("$($active.Count) turned on")
        if ($simulating -gt 0) { $parts.Add("$simulating still simulating") }
        if ($disabledPolicies -gt 0) { $parts.Add("$disabledPolicies disabled") }
        $answer.PolicyDetail = "Of $($policies.Count) defined: $($parts -join ', ')."
    }

    # Complete policy data alone settles the active total when every policy is inactive. Rule data
    # is neither needed nor allowed to turn simulation conditions into active coverage.
    if ($active.Count -eq 0) {
        $answer.Reliable = $true
        $answer.Detail = 'No auto-labeling policy is turned on, so no active policy is currently evaluating a sensitive-information-type condition.'
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
        $answer.Detail = $text
    }
    elseif ($enabledRules -eq 0) {
        $answer.Detail = 'No enabled rule remains in the turned-on policies, so no active rule is evaluating a sensitive-information-type condition.'
    }
    elseif ($kinds.Count -gt 0) {
        $answer.Detail = 'None. The enabled rules instead match on {0}.' -f ((@($kinds | Sort-Object)) -join ', ')
    }
    else {
        $answer.Detail = 'None. No enabled rule linked to a turned-on policy contains a sensitive-information-type condition; auto-labeling can instead use classifiers, metadata, sharing or contextual conditions.'
    }
    if ($disabledRules -gt 0) { $answer.Detail += " $disabledRules explicitly disabled rules were excluded." }
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

    foreach ($item in @($Finding | Where-Object { $_.status -in 'NotCollected', 'NeedsReview' })) {
        # The inner parentheses matter: inside a method call, a bare comma binds to the argument
        # list rather than to -f, leaving the format string one value short.
        $risks.Add(('{0} could not be checked. {1}' -f $item.ruleId, $item.reason))
    }

    # A source that returned only some of its properties still yields counts, and a count reads as
    # complete whether or not it is. Naming the gap is what keeps a partial read from passing for a total.
    foreach ($result in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults'))) {
        $absent = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $result -Name 'propertiesNotReturned'))
        if ($absent.Count -eq 0) { continue }
        $risks.Add(('{0} returned records without {1}. Any figure here that depends on those values may be understated.' -f
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
    $risks.Add('Collection policies and the pay-as-you-go usage report are configured and shown only in the portal. Neither which activities are being collected nor what the metered features are costing could be read here.')
    $risks.Add('Only the data pillar of Zero Trust is covered here. Identity, devices and network are assessed by Microsoft own Zero Trust Assessment, which this does not replace: https://learn.microsoft.com/security/zero-trust/assessment/get-started')
    $risks.Add('This report names policies, labels and settings from the tenant. Treat it as sensitive and share it only with people entitled to see that configuration.')

    return $risks.ToArray()
}

function Find-PurviewBrowser {
    <#
    .SYNOPSIS
        Locates a Chromium browser that can print HTML to PDF.

    .DESCRIPTION
        Edge and Chrome can render to PDF from the command line, which keeps PDF output dependency
        free rather than pulling a rendering library into a script meant to be a single file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    )

    foreach ($path in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { return $path }
    }

    foreach ($name in 'microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser') {
        $command = Get-Command -Name $name -ErrorAction SilentlyContinue
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
                # Exclusive read means Chromium has closed the file. Both boundary markers are
                # required so a partly written file is never handed to qpdf or reported as usable.
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

        # Edge can hand rendering to a child and let the launcher exit 0 before the file appears.
        # Watch the output as well as the process, within the same three-minute ceiling. Once the
        # launcher exits successfully, 30 seconds is enough for that hand-off without making a bad
        # browser invocation stall the presentation for the full timeout.
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
        Chromium prints PDFs but has no way to encrypt one, so protecting the output needs a second
        tool. qpdf is the one Microsoft-independent tool with a documented way to take a password
        without putting it on the command line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $command = Get-Command -Name 'qpdf' -ErrorAction SilentlyContinue
    if ($command) { return [string]$command.Source }

    # The Windows installer puts qpdf in a folder named for its version, so the location is matched
    # rather than assumed, and a freshly installed copy is found without opening a new session.
    foreach ($pattern in @("$env:ProgramFiles\qpdf*\bin\qpdf.exe", "${env:ProgramFiles(x86)}\qpdf*\bin\qpdf.exe")) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        $hit = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        if ($hit.Count -gt 0) { return [string]$hit[0].FullName }
    }

    foreach ($path in @('/opt/homebrew/bin/qpdf', '/usr/local/bin/qpdf', '/usr/bin/qpdf')) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }

    return ''
}

function Install-PurviewQpdf {
    <#
    .SYNOPSIS
        Returns a usable qpdf, installing it through the platform's package manager if need be.

    .DESCRIPTION
        Encrypting a PDF needs a tool no operating system ships. Rather than fetching a binary
        itself, this asks the package manager the machine already trusts, so the download is the one
        that manager has pinned and verified: winget on Windows, Homebrew on macOS. Elsewhere the
        command is named rather than run, because installing there needs sudo and a read-only
        assessment should not be asking for that.

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

    $plan = if ($IsWindows -and (Get-Command -Name 'winget' -ErrorAction SilentlyContinue)) {
        @{
            Source = 'QPDF.QPDF through winget, published by the qpdf project under Apache-2.0'
            Run = { winget install --exact --id QPDF.QPDF --silent --accept-package-agreements --accept-source-agreements }
        }
    }
    elseif ($IsMacOS -and (Get-Command -Name 'brew' -ErrorAction SilentlyContinue)) {
        @{ Source = 'the qpdf formula through Homebrew'; Run = { brew install qpdf } }
    }
    else { $null }

    if ($null -eq $plan) {
        Write-Line -Style Warn -Message '    qpdf is needed to encrypt a PDF, and no package manager here can install it.'
        Write-Line -Style Dim -Message '    Install it with apt install qpdf, dnf install qpdf, or from https://qpdf.sourceforge.io'
        return ''
    }

    Write-Line -Style Dim -Message ('    Installing qpdf: {0}.' -f $plan.Source)
    Write-Line -Style Dim -Message '    This may ask you to allow the install.'
    try { & $plan.Run *> $null }
    catch { Write-Verbose "Installing qpdf did not complete: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)" }

    # The environment this process started with predates the install, so the path is re-read.
    if ($IsWindows) {
        $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $user = [Environment]::GetEnvironmentVariable('Path', 'User')
        $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
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
        Compared through the unmanaged copies. Turning either into a managed string to compare them
        would create something that cannot be wiped afterwards, which is the whole thing a secure
        string exists to avoid.
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
        Asked for twice because a password mistyped once is a file nobody can open. Read-Host keeps
        the typed characters off the screen and out of the console history, and neither entry ever
        becomes ordinary text.
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
        Built as characters and encoded by hand rather than assembled into a string, because a
        managed string cannot be overwritten once it exists and would sit in memory until the
        collector happened to reclaim it. Everything this touches is cleared on the way out.
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
        passwords on a command line, so that is how the password reaches it: never as an argument
        another process could list, and never written to a file.

        The owner password is a fresh random value that is discarded. Microsoft's format allows an
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
        $stream = $process.StandardInput.BaseStream

        $preamble = [System.Text.Encoding]::UTF8.GetBytes("--encrypt`n")
        $stream.Write($preamble, 0, $preamble.Length)
        Write-PurviewSecretArgument -Stream $stream -Prefix '--user-password=' -Secret $Password
        $tail = [System.Text.Encoding]::UTF8.GetBytes(('--owner-password={0}{1}--bits=256{1}--{1}' -f [Convert]::ToBase64String($owner), "`n"))
        $stream.Write($tail, 0, $tail.Length)
        [Array]::Clear($tail, 0, $tail.Length)
        $stream.Flush()
        $process.StandardInput.Close()

        $problem = $process.StandardError.ReadToEnd()
        $null = $process.StandardOutput.ReadToEnd()
        # Bounded so a wedged qpdf cannot hold the run: the encrypted file is written to a temporary
        # path and only moved over the report once the exit code says it is whole.
        if (-not $process.WaitForExit(120000)) {
            try { $process.Kill() } catch { Write-Verbose 'qpdf had already exited.' }
            Write-Warning 'qpdf did not finish within two minutes, so the PDF was left unencrypted.'
            return $false
        }

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

    if (-not $IsWindows) {
        Write-Warning 'Word export needs Word on Windows, so no .docx was produced.'
        return ''
    }

    $word = $null
    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $document = $word.Documents.Open((Resolve-Path -LiteralPath $HtmlPath).Path, $false, $true)
        # 16 is wdFormatDocumentDefault, the .docx format.
        $document.SaveAs2($WordPath, 16)
        $document.Close($false)
        return $WordPath
    }
    catch {
        Write-Warning "Word export was unavailable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return ''
    }
    finally {
        if ($null -ne $word) {
            $word.Quit()
            $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)
        }
    }
}

function Test-PurviewEvidence {
    <#
    .SYNOPSIS
        Checks that every cited source still resolves, and whether it has changed since it was read.

    .DESCRIPTION
        Rules are authored against documentation as it read on a date, so the risk is not only that
        a link rots but that the page behind it now says something else. Where an entry records the
        fingerprint of the text it was written against, the page is fetched and compared, and a
        difference is reported so a human can re-read it. Entries without a fingerprint are reported
        as such rather than assumed current.
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
        Rules are data, never code: conditions are declarative and the engine only ever compares
        values, so a rule file cannot introduce a code path. It is still validated on the way in,
        because a malformed or over-reaching rule can mislead a reader even when it cannot execute.
        Rules sharing an id with a built-in replace it, so a single check can be corrected without
        restating the rest.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Rule file not found: $Path" }

    $document = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20

    $knownAssertions = @('countEquals', 'countGreaterThan', 'countLessThan', 'isEmpty', 'isNotEmpty', 'noDuplicatesOf', 'allHave', 'anyHave', 'noneHave')
    $knownOperators = @('eq', 'ne', 'gt', 'lt', 'ge', 'le', 'contains', 'notContains', 'startsWith', 'exists', 'isNullOrEmpty', 'isNotNullOrEmpty')

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
        if ([string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $condition -Name 'collector'))) {
            throw "Rule '$id' does not say which collector it reads."
        }

        $analysis = [string](Get-PurviewProperty -InputObject $condition -Name 'analysis')
        if ($analysis) {
            if ($analysis -notin 'PolicyRuleCoverage', 'DisabledRulesInEnforcingPolicies') {
                throw "Rule '$id' uses an unknown analysis '$analysis'."
            }
            if ([string](Get-PurviewProperty -InputObject $condition -Name 'collector') -ne 'DlpRule') {
                throw "Rule '$id' can use analysis '$analysis' only with the DlpRule collector."
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

function Get-PurviewContentFingerprint {
    <#
    .SYNOPSIS
        Fingerprints documentation text so a later fetch can be compared with it.

    .DESCRIPTION
        Markup, scripts and whitespace change constantly without the guidance changing, so they are
        stripped before hashing. This detects wording changes, not cosmetic ones.
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
        Write-Line -Style Dim -Message '    Every cited source resolves and reads as it did when the rule was written.'
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
    $null = $builder.AppendLine("<title>$(Enc $Title)</title>")
    # One stylesheet, two palettes: the rules below read from custom properties so a dark run
    # cannot drift from a light one.
    $palette = if ($DarkMode) {
        ':root{--bg:#1b1b1b;--fg:#e8e8e8;--line:#3f3f3f;--head:#262626;--rule:#333;--fail:#ff7b72;--warn:#e3b341;--pass:#7ee787;--dim:#9aa0a6;--info:#79c0ff;--link:#79c0ff;--code:#262626;}'
    }
    else {
        ':root{--bg:#fff;--fg:#1b1b1b;--line:#ccc;--head:#f3f3f3;--rule:#eee;--fail:#a80000;--warn:#8a6100;--pass:#0b6a0b;--dim:#666;--info:#0b4a8a;--link:#0645ad;--code:#f5f5f5;}'
    }

    $null = $builder.AppendLine("<style>$palette" + 'body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;max-width:70rem;background:var(--bg);color:var(--fg);}a{color:var(--link);}code{background:var(--code);padding:.1rem .2rem;}table{border-collapse:collapse;width:100%;margin-bottom:1.5rem;}th,td{border:1px solid var(--line);padding:.4rem;text-align:left;vertical-align:top;font-size:.9rem;}th{background:var(--head);}h2{border-bottom:2px solid var(--rule);padding-bottom:.3rem;margin-top:2rem;}.fail{color:var(--fail);font-weight:600;}.warn{color:var(--warn);}.pass{color:var(--pass);}.dim{color:var(--dim);}.info{color:var(--info);font-weight:600;}.mark{white-space:nowrap;width:2.5rem;text-align:center;}.tight{white-space:nowrap;width:6rem;}.wide{width:32%;}</style>')
    $null = $builder.AppendLine('</head><body>')
    $null = $builder.AppendLine("<h1>$(Enc $Title)</h1>")
    $null = $builder.AppendLine("<p class=""dim"">Generated $(Enc $generated) by version $(Enc $script:ToolVersion).</p>")

    # A narrowed run must never read as a full one: an unassessed solution is not a passing solution.
    if ((Test-Path variable:script:ActiveSolution) -and @($script:ActiveSolution).Count -gt 0) {
        $null = $builder.AppendLine("<p class=""info"">Scope: $(Enc ($script:ActiveSolution -join ', ')) only. Every other Purview solution was neither collected nor scored, and its absence from this report says nothing about it.</p>")
    }

    # Everything was still assessed, so say what was left out rather than let the reader assume this
    # is all there was to find.
    if ($Brief) {
        $null = $builder.AppendLine('<p class="dim">Condensed report. The full assessment ran; the prerequisites, Copilot and AI controls, taxonomy comparison, remediation checklist, coverage matrix, blueprint coverage and per-finding detail are omitted here. Run without -Brief for those.</p>')
    }

    $counts = @{}
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotCollected', 'Unsupported') {
        $counts[$status] = @($Finding | Where-Object { $_.status -eq $status }).Count
    }

    $null = $builder.AppendLine('<h2>Tenant at a Glance</h2>')
    $null = $builder.AppendLine('<p class="dim">Configuration and available usage information observed in this run. Where a row reads not checked, a reliable value was unavailable and the detail explains why.</p>')
    $null = $builder.AppendLine('<table><thead><tr><th>Area</th><th>Measure</th><th>Amount</th><th>Detail</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewInventory -Snapshot $Snapshot)) {
        Add-Row @((Enc $row.Area), (Enc $row.Metric), (Enc $row.Value), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Executive Summary</h2>')
    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add("<span class=""pass"">$($counts.Pass) passed</span>")
    if ($counts.Fail -gt 0) { $summary.Add("<span class=""fail"">$($counts.Fail) areas for improvement</span>") }
    if ($counts.Warning -gt 0) { $summary.Add("$($counts.Warning) warnings") }
    if ($counts.NeedsReview -gt 0) { $summary.Add("$($counts.NeedsReview) to review") }
    $unread = $counts.NotCollected + $counts.Unsupported
    if ($unread -gt 0) { $summary.Add("$unread not checked") }
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
            if ($movement.CouldNotAssess -gt 0) {
                $null = $builder.AppendLine("<p class=""dim"">$($movement.CouldNotAssess) could not be assessed this run. Kept out of movement because missing evidence says nothing changed in the tenant.</p>")
            }
            if ($movement.NewlyAssessed -gt 0) {
                $null = $builder.AppendLine("<p class=""dim"">$($movement.NewlyAssessed) newly assessed. New evidence is not movement.</p>")
            }

            $moved = @($movement.Changes | Where-Object { $_.Change -in 'Improved', 'Regressed', 'CouldNotAssess' })
            if ($moved.Count -eq 0) {
                $null = $builder.AppendLine('<p class="dim">No assessed outcome moved.</p>')
                continue
            }

            $sides = if ($cross) { '<th>There</th><th>Here</th>' } else { '<th>Was</th><th>Now</th>' }
            $null = $builder.AppendLine("<table><thead><tr><th>Item</th>$sides<th>Change</th><th>Note</th></tr></thead><tbody>")
            foreach ($row in ($moved | Sort-Object Change, RuleId, Name)) {
                $class = switch ($row.Change) { 'Improved' { 'pass' } 'Regressed' { 'fail' } 'CouldNotAssess' { 'warn' } default { 'dim' } }
                $was = if ($row.From) { Enc $row.From } else { '<span class="dim">&mdash;</span>' }
                $now = if ($row.To) { Enc $row.To } else { '<span class="dim">&mdash;</span>' }
                $what = if ($group.IsRule) { '{0} &mdash; {1}' -f (Enc $row.RuleId), (Enc $row.Title) } else { Enc $row.Name }
                $kind = Format-PurviewChangeKind -Change $row.Change -CrossTenant:$cross
                $null = $builder.AppendLine("<tr><td>$what</td><td>$was</td><td>$now</td><td class=""$class"">$(Enc $kind)</td><td>$(Enc $row.Detail)</td></tr>")
            }
            $null = $builder.AppendLine('</tbody></table>')
        }
    }

    # The condensed report carries the conversation; the seven detail sections below are for the
    # follow-up, and run to the matching end-of-detail brace above Quick Wins.
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
    # One predicate for both the buttons and the tick boxes. Holding it twice is how a row came to
    # offer a script the reader could never select: a change carrying a Script rather than a single
    # Command counted as remediable but rendered no box.
    $canRemediate = {
        param($row)
        ($row.State -eq 'Needs attention' -and ($row.Command -or $null -ne $row.Script)) -or @($row.Candidates).Count -gt 0
    }
    $remediable = @($prereq | Where-Object { & $canRemediate $_ })

    $attention = @($prereq | Where-Object { $_.State -eq 'Needs attention' }).Count
    $good = @($prereq | Where-Object { $_.State -eq 'As recommended' }).Count
    $inUse = @($prereq | Where-Object { $_.State -eq 'In use' }).Count
    $seenRecently = @($prereq | Where-Object { $_.State -eq 'Seen recently' }).Count
    $evidenceFound = @($prereq | Where-Object { $_.State -eq 'Evidence found' }).Count
    $granted = @($prereq | Where-Object { $_.State -eq 'Granted' }).Count
    $portal = @($prereq | Where-Object { $_.State -eq 'Confirm in portal' }).Count
    # Counted by state, not as a residual: evidence states must never be tallied as not read.
    $unread = @($prereq | Where-Object { $_.State -eq 'Not read' }).Count

    $summary = "<span class=""fail""><strong>$attention need attention</strong></span> &middot; <span class=""pass"">$good as recommended</span>"
    if ($inUse -gt 0) { $summary += " &middot; <span class=""pass"">$inUse in use</span>" }
    if ($granted -gt 0) { $summary += " &middot; <span class=""pass"">$granted granted</span>" }
    if ($seenRecently -gt 0) { $summary += " &middot; $seenRecently seen recently" }
    if ($evidenceFound -gt 0) { $summary += " &middot; $evidenceFound evidence found" }
    $summary += " &middot; $portal to confirm in the portal"
    if ($unread -gt 0) { $summary += " &middot; $unread not read this run" }
    $null = $builder.AppendLine("<p>$summary</p>")
    $null = $builder.AppendLine('<p class="dim">These are the tenant-wide switches Purview leaves in your hands, so each capability arrives when the organisation is ready for it rather than landing on users unannounced. Turning one on is what brings the labels and policies built on it into effect. Microsoft''s secure by default guidance works through them in step one, so the foundation is set before labels reach users.</p>')

    if ($remediable.Count -gt 0) {
        $null = $builder.AppendLine('<p><button type="button" id="rem-all">Select all</button> <button type="button" id="rem-none">Clear</button> <button type="button" id="rem-get">Download script for selected</button> <span class="dim" id="rem-count"></span></p>')
        $null = $builder.AppendLine('<p class="dim">Tick the changes you want. The script explains each one as it reaches it and applies it only if you answer yes, so nothing changes while you read.</p>')
        # Windows marks anything a browser downloads and the page cannot undo that, so the reader
        # needs the one command that clears it.
        $null = $builder.AppendLine('<p class="dim">Windows blocks scripts downloaded through a browser. Run <code>Unblock-File</code> on it before you run it.</p>')
    }

    $null = $builder.AppendLine('<table><thead><tr><th>Take</th><th>Status</th><th>Opt-in</th><th>Why it matters</th><th>Recommended state</th></tr></thead><tbody>')
    foreach ($row in $prereq) {
        $class = switch ($row.State) { 'As recommended' { 'pass' } 'Granted' { 'pass' } 'Needs attention' { 'fail' } 'In use' { 'pass' } default { 'dim' } }
        $name = if ($row.Url) { "<a href=""$(Enc $row.Url)"">$(Enc $row.Name)</a>" } else { Enc $row.Name }
        if ($row.Optional) { $name += ' <span class="dim">(optional)</span>' }
        $action = Enc $row.Action
        if ($row.Action -match '^(Set|Leave)') { $action = "<code>$action</code>" }

        $pick = if (& $canRemediate $row) {
            "<input type=""checkbox"" class=""rem-pick"" data-name=""$(Enc $row.Name)"">"
        }
        else { '' }

        $null = $builder.AppendLine("<tr><td>$pick</td><td class=""$class""><strong>$(Enc $row.State)</strong></td><td>$name<br><span class=""dim"">$(Enc $row.Detail)</span></td><td>$(Enc $row.Why)</td><td>$action</td></tr>")
    }
    $null = $builder.AppendLine('</tbody></table>')

    # The parts are embedded rather than linked so selection still works when this report is emailed
    # on its own. Base64 keeps PowerShell syntax away from the HTML parser.
    if ($remediable.Count -gt 0) {
        $tenantName = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'tenant') -Name 'displayName')
        # The same URL the run worked out, so a script downloaded from here does not ask again for
        # something the copy written beside the report already knows.
        $adminUrl = if (Test-Path variable:script:SharePointAdminUrl) { [string]$script:SharePointAdminUrl } else { '' }
        $parts = Get-PurviewRemediationPart -Prerequisite $prereq -TenantName $tenantName -GeneratedAt $generated -AdminUrl $adminUrl
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($parts | ConvertTo-Json -Depth 10 -Compress)))
        $null = $builder.AppendLine("<script>(function(){var P=JSON.parse(decodeURIComponent(escape(atob('$encoded'))));var picks=function(){return Array.prototype.slice.call(document.querySelectorAll('.rem-pick'));};var count=function(){var n=picks().filter(function(c){return c.checked;}).length;document.getElementById('rem-count').textContent=n+' selected';};picks().forEach(function(c){c.addEventListener('change',count);});document.getElementById('rem-all').addEventListener('click',function(){picks().forEach(function(c){c.checked=true;});count();});document.getElementById('rem-none').addEventListener('click',function(){picks().forEach(function(c){c.checked=false;});count();});document.getElementById('rem-get').addEventListener('click',function(){var names=picks().filter(function(c){return c.checked;}).map(function(c){return c.getAttribute('data-name');});var chosen=P.items.filter(function(i){return names.indexOf(i.name)>=0;});var t=P.header.replace('{COUNT}',chosen.length);if(chosen.length===0){t+='\r\nWrite-Host \'Nothing selected to remediate.\'\r\n';}else{Object.keys(P.connect).forEach(function(s){if(chosen.some(function(i){return i.session.indexOf(s)>=0;})){t+='\r\n'+P.connect[s];}});chosen.forEach(function(i){t+='\r\n'+i.block;});}t+='\r\n'+P.footer;var u=URL.createObjectURL(new Blob([t],{type:'text/plain'}));var l=document.createElement('a');l.href=u;l.download=(chosen.length===1&&chosen[0].file)?chosen[0].file:'Set-PurviewTenantOptIns.ps1';l.click();URL.revokeObjectURL(u);});count();})();</script>")
    }

    $null = $builder.AppendLine('<h2>Copilot and AI Controls</h2>')
    $copilot = @(Get-PurviewCopilotControl -Snapshot $Snapshot -Finding $Finding)

    $intro = 'Microsoft 365 Copilot can only surface content the person asking already has access to, so what protects it is the Purview configuration already in your tenant. This section shows which controls limit what Copilot can reach, and whether its activity is being recorded.'
    # Only promise the second group when there is one, or the sentence points at nothing.
    if (@($copilot | Where-Object { $_.Band -ne 'Copilot' }).Count -gt 0) {
        $intro += ' Rows are grouped by what they cover: the controls specific to Microsoft 365 Copilot first, then the ones that span every AI app in use, Copilot and third-party sites and agents alike.'
    }
    $null = $builder.AppendLine("<p class=""dim"">$intro</p>")

    # The table states each control, but a reader scanning the section should not have to assemble
    # the conclusion from it.
    $copilotGaps = @($copilot | Where-Object { $_.State -eq 'Needs attention' })
    if ($copilotGaps.Count -gt 0) {
        $names = ($copilotGaps | ForEach-Object { Enc $_.Control }) -join ', '
        $null = $builder.AppendLine("<p class=""fail""><strong>Not in place: $names.</strong></p>")
    }

    $null = $builder.AppendLine('<table><thead><tr><th>State</th><th>Control</th><th>Why it matters</th></tr></thead><tbody>')
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
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Label Taxonomy Comparison</h2>')
    $null = $builder.AppendLine('<table><thead><tr><th>Tier</th><th>In this tenant</th><th>Note</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewTaxonomyComparison -Snapshot $Snapshot)) {
        Add-Row @((Enc $row.Tier), (Enc $row.Match), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table>')
    $null = $builder.AppendLine('<p class="dim">The documented default taxonomy, compared by name against the labels defined in this tenant. Organisations classify to their own risk model, so a tier with no counterpart is a design decision to confirm rather than a gap to close. A tier serving the same purpose under a different name is reported as organisation-specific.</p>')

    $checklist = @(Get-PurviewChecklist -Finding $Finding)
    $progress = Get-PurviewChecklistProgress -Checklist $checklist

    $null = $builder.AppendLine('<h2>Remediation Checklist</h2>')
    if ($null -ne $progress.Percent) {
        $null = $builder.AppendLine("<p><strong>$($progress.Done) of $($progress.Judged) done</strong> ($($progress.Percent)%). $($progress.ToDo) to do, $($progress.ToCheck) to check by hand.</p>")
    }

    foreach ($group in 'To do', 'To check by hand', 'Done', 'Not checked') {
        $rows = @($checklist | Where-Object { $_.Group -eq $group })
        if ($rows.Count -eq 0) { continue }

        $null = $builder.AppendLine("<h3>$(Enc $group) ($($rows.Count))</h3>")
        $null = $builder.AppendLine('<table><thead><tr><th class="mark"></th><th class="wide">Check</th><th class="tight">Licence</th><th class="tight">Purview solution</th><th class="tight">Severity</th><th>What it takes</th></tr></thead><tbody>')
        foreach ($row in $rows) {
            $action = Enc $row.Action
            if ($row.Command) { $action += "<br><code>$(Enc $row.Command)</code>" }
            $null = $builder.AppendLine("<tr><td class=""mark"">[$(Enc $row.Marker)]</td><td>$(& $link $row.RuleId) $(Enc $row.Title)</td><td>$(Enc $row.Tier)</td><td>$(Enc $row.Solution)</td><td>$(Enc $row.Severity)</td><td>$action</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table>')
    }
    $null = $builder.AppendLine('<p class="dim">Ordered for working top down: highest severity first, and within that the licence tier the organisation is most likely to already hold. Progress counts only checks that returned a verdict, so items that could not be checked do not inflate it.</p>')

    $null = $builder.AppendLine('<h2>Purview Solution Coverage Matrix</h2>')
    $null = $builder.AppendLine('<p class="dim">Every area this run read, and what became of it: judged by a check, reported in one of the tables above, or collected only as context. Use it to trace any verdict in this report back to the data behind it, and to see which areas were read but not judged.</p>')
    $null = $builder.AppendLine('<table><thead><tr><th>Collector</th><th>Solution area</th><th>Data read</th><th>Rules</th><th>Assessment</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewCoverageMatrix -Snapshot $Snapshot -Finding $Finding)) {
        Add-Row @((Enc $row.Collector), (Enc $row.SolutionArea), (Enc $row.Collection), $row.Rules, (Enc $row.Assessment))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Blueprint Coverage</h2>')
    $null = $builder.AppendLine('<p class="dim">This tenant measured against Microsoft''s published Purview deployment blueprints, each heading linking to the guide it scores against. Only steps with a corresponding check are listed. This reports current configuration, not progress through a deployment programme.</p>')
    foreach ($model in (Get-PurviewDeploymentMaturity -Finding $Finding)) {
        $steps = @($model.Steps | Where-Object { $_.State -ne 'NoChecks' })
        if ($steps.Count -eq 0) { continue }

        # The heading names a published Microsoft guide, so it links to it rather than leaving the
        # reader to search for a title they can see but not follow.
        $heading = if ($model.Url) { "<a href=""$(Enc $model.Url)"">$(Enc $model.Name)</a>" } else { Enc $model.Name }
        $null = $builder.AppendLine("<h3>$heading</h3>")
        $null = $builder.AppendLine('<table><thead><tr><th>Step</th><th>What it covers</th><th>State</th></tr></thead><tbody>')
        foreach ($step in $steps) {
            $class = switch ($step.State) { 'ChecksPass' { 'pass' } 'ChecksFail' { 'fail' } 'Partial' { 'warn' } 'ChecksWarn' { 'warn' } default { 'dim' } }
            $title = if ($step.Title) { $step.Title } else { 'Not covered by this assessment' }
            $covers = Enc $title
            $ids = @(@($step.RuleIds) | ForEach-Object { & $link $_ }) -join ', '
            if ($ids) { $covers += "<br><span class=""dim"">Scored from $ids</span>" }
            $null = $builder.AppendLine("<tr><td>$($step.Step)</td><td>$covers</td><td class=""$class"">$(Enc $step.Verdict)</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table>')
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

    $healthy = @($Finding | Where-Object { $_.status -in 'Pass', 'NotCollected' })
    if ($healthy.Count -gt 0) {
        $null = $builder.AppendLine('<h3>Everything else</h3>')
        $null = $builder.AppendLine('<table><thead><tr><th>Rule</th><th>Title</th><th>Status</th><th>What we found</th></tr></thead><tbody>')
        foreach ($item in ($healthy | Sort-Object status, ruleId)) {
            $class = if ($item.status -eq 'Pass') { 'pass' } else { 'dim' }
            $null = $builder.AppendLine("<tr><td id=""$(Enc $item.ruleId)"">$(Enc $item.ruleId)</td><td>$(Enc $item.title)</td><td class=""$class"">$(Enc (Get-PurviewStatusLabel -Status $item.status))</td><td>$(Enc $item.reason)</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table>')
    }

    } # end of detail sections

    $null = $builder.AppendLine('<h2>Quick Wins</h2>')
    $quick = @($Finding | Where-Object { $_.status -in 'Fail', 'Warning' -and $_.PSObject.Properties['remediationCommand'] })
    if ($quick.Count -eq 0) {
        $null = $builder.AppendLine('<p class="dim">No single-command fixes were identified.</p>')
    }
    else {
        $null = $builder.AppendLine('<table><thead><tr><th>Rule</th><th>Title</th><th>Command to review and run yourself</th></tr></thead><tbody>')
        foreach ($item in $quick) { Add-Row @((Enc $item.ruleId), (Enc $item.title), "<code>$(Enc $item.remediationCommand)</code>") }
        $null = $builder.AppendLine('</tbody></table>')
    }

    $null = $builder.AppendLine('<h2>Strategic Improvements</h2>')
    $null = $builder.AppendLine('<p class="dim">Findings with no single-command fix, grouped by severity.</p>')
    $planned = @($Finding | Where-Object { $_.status -in 'Fail', 'Warning' -and -not $_.PSObject.Properties['remediationCommand'] })
    $higher = @($planned | Where-Object { $_.severity -in 'Critical', 'High' })
    $lower = @($planned | Where-Object { $_.severity -in 'Medium', 'Low' })
    $null = $builder.AppendLine('<h3>Critical and high severity</h3><ul>')
    if ($higher.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">Nothing outstanding.</li>') }
    foreach ($item in $higher) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
    $null = $builder.AppendLine('</ul><h3>Medium and low severity</h3><ul>')
    if ($lower.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">Nothing outstanding.</li>') }
    foreach ($item in $lower) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
    $null = $builder.AppendLine('</ul>')

    $toVerify = @($Finding | Where-Object { $_.status -eq 'NeedsReview' })
    if ($toVerify.Count -gt 0) {
        $null = $builder.AppendLine('<h2>Checks to Verify</h2>')
        $null = $builder.AppendLine('<p class="dim">These results need evidence or human confirmation. They are not configuration changes to make.</p><ul>')
        foreach ($item in $toVerify) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
        $null = $builder.AppendLine('</ul>')
    }

    $null = $builder.AppendLine('<h2>Licensing and SKU Analysis</h2>')
    $null = $builder.AppendLine('<table><thead><tr><th>SKU or add-on</th><th>Seats</th><th>Detail</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewLicensingAnalysis -Snapshot $Snapshot -Finding $Finding)) {
        Add-Row @((Enc $row.Sku), (Enc $row.State), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Limitations of This Assessment</h2>')
    $null = $builder.AppendLine('<p class="dim">What this run could not establish, and the qualifiers required to interpret the findings above. These describe the assessment, not the tenant.</p><ul>')
    foreach ($risk in (Get-PurviewOpenRisk -Finding $Finding -Snapshot $Snapshot)) { $null = $builder.AppendLine("<li>$(Enc $risk)</li>") }
    $null = $builder.AppendLine('</ul>')

    $null = $builder.AppendLine('<p class="dim">The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official Microsoft guidance, and every finding here links the page it came from. This script is not a Microsoft product: it reads what is configured in this tenant and reports it against those recommendations. It describes configuration observed at a point in time and is not a compliance certification.</p>')
    $null = $builder.AppendLine('</body></html>')

    return $builder.ToString()
}

#endregion

#region Sample data
# Not reachable from any switch: this is the fixture the verification suite runs against, so the
# read-only guarantee and the report can be proven without pointing the script at a real tenant.

function Get-PurviewDemoSnapshot {
    <# .SYNOPSIS Fabricated snapshot for trying the script without a tenant. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $demoNow = Get-PurviewTimestamp
    $stamp = Format-PurviewTimestamp -Timestamp $demoNow
    $activityEnd = $demoNow.AddMinutes(-1)
    $activityStart = $demoNow.AddDays(-30).AddMinutes(1)
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
                        [pscustomobject]@{ Guid = 'g1'; Name = 'Public'; UniqueName = 'sample-public'; ParentId = $null; Priority = 0; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g2'; Name = 'General'; UniqueName = 'sample-general'; ParentId = $null; Priority = 1; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g3'; Name = 'Confidential'; UniqueName = 'sample-confidential'; ParentId = $null; Priority = 2; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        # Encryption on a label that has sublabels is what a label group cannot hold,
                        # so this one stands for a taxonomy still on the older scheme.
                        [pscustomobject]@{ Guid = 'g4'; Name = 'Highly Confidential'; UniqueName = 'sample-highly-confidential'; ParentId = $null; Priority = 2; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EDIT' }
                        [pscustomobject]@{ Guid = 'g5'; Name = 'Board Material (fabricated)'; UniqueName = 'sample-board-material'; ParentId = $null; Priority = 3; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g6'; Name = 'Confidential \ All Employees'; UniqueName = 'sample-confidential-all-employees'; ParentId = 'g3'; Priority = 4; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EXTRACT, EDIT, PRINT' }
                        [pscustomobject]@{ Guid = 'g7'; Name = 'Highly Confidential \ Specific People'; UniqueName = 'sample-highly-confidential-specific-people'; ParentId = 'g4'; Priority = 5; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EDIT' }
                        [pscustomobject]@{ Guid = 'g8'; Name = 'General \ Anyone (unrestricted)'; UniqueName = 'sample-general-anyone'; ParentId = 'g2'; Priority = 6; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false }
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
                        [pscustomobject]@{ Guid = 'p1'; Name = 'All staff'; Enabled = $true; Labels = @('Public', 'General', 'Confidential'); UserScope = @('All'); GroupScope = @('All') }
                        [pscustomobject]@{ Guid = 'p2'; Name = 'Legal and finance'; Enabled = $true; Labels = @('Confidential'); UserScope = @('legal@contoso.example', 'finance@contoso.example'); GroupScope = @() }
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
                        [pscustomobject]@{ Guid = 'a1'; Name = 'Financial records (fabricated)'; Mode = 'Enable'; Enabled = $true }
                        [pscustomobject]@{ Guid = 'a2'; Name = 'Customer records (fabricated)'; Mode = 'TestWithoutNotifications'; Enabled = $true }
                        [pscustomobject]@{ Guid = 'a3'; Name = 'Legacy records (fabricated)'; Mode = 'Disable'; Enabled = $false }
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
                            Guid = 'ar1'; Name = 'Financial records rule (fabricated)'
                            PolicyName = ''; Policy = 'Financial records (fabricated)'; Disabled = $false
                            DirectSensitiveTypes = $null; AdvancedRule = $activeAutoLabelAdvanced
                            DirectSensitiveTypesReturned = $true; AdvancedRuleReturned = $true
                            ConditionKinds = @()
                        }
                        # Conditions on simulation and disabled policies are retained in the
                        # snapshot but excluded from the active-policy total.
                        [pscustomobject]@{
                            Guid = 'ar2'; Name = 'Customer records rule (fabricated)'
                            PolicyName = 'Customer records (fabricated)'; Policy = ''; Disabled = $false
                            DirectSensitiveTypes = @([pscustomobject]@{ name = 'U.S. Social Security Number (SSN)'; mincount = 1 })
                            AdvancedRule = $null
                            DirectSensitiveTypesReturned = $true; AdvancedRuleReturned = $true
                            ConditionKinds = @()
                        }
                        [pscustomobject]@{
                            Guid = 'ar3'; Name = 'Legacy records rule (fabricated)'
                            PolicyName = 'Legacy records (fabricated)'; Policy = ''; Disabled = $false
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
                        [pscustomobject]@{ Name = 'ExtendTeamsDlpPoliciesToSharePointOneDrive'; Value = 'False' }
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
                        [pscustomobject]@{ Guid = 'd1'; Name = 'Financial data'; Mode = 'Enable'; Workload = 'Exchange, SharePoint, OneDriveForBusiness'; ExchangeLocation = @('All'); SharePointLocation = @('All') }
                        [pscustomobject]@{ Guid = 'd2'; Name = 'Pilot'; Mode = 'TestWithoutNotifications'; Workload = 'EndpointDevices'; EndpointDlpLocation = @('All') }
                        # Named the way DLP analytics names what it creates, which is what proves it ran.
                        [pscustomobject]@{ Guid = 'd3'; Name = 'RiskSpotlighting-2026-08-01'; Mode = 'TestWithoutNotifications'; Workload = 'Exchange'; ExchangeLocation = @('All') }
                        # The documented name of the Copilot policy posture management creates in one click.
                        [pscustomobject]@{ Guid = 'd4'; Name = 'DSPM for AI - Protect sensitive data from Copilot processing'; Mode = 'Enable'; Workload = 'M365Copilot' }
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
                        [pscustomobject]@{ Guid = 'ap1'; Name = 'Copilot interactions'; Enabled = $true; Applications = 'User:M365Copilot,CopilotForSecurity,CopilotinFabricPowerBI,CopilotStudio,CopilotinBusinessApplicationplatformsSales,SQLCopilot' }
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
                        [pscustomobject]@{ Guid = 'apr1'; Name = 'Copilot interactions rule'; Policy = 'Copilot interactions' }
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
                collector = 'ProtectedFilesConsent'; solutionArea = 'PostureValidation'; status = 'Success'
                source = [pscustomobject]@{ interface = 'GET /servicePrincipals'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{ Grants = @([pscustomobject]@{ Count = 1 }) }
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
                collector = 'DlpRule'; solutionArea = 'DataLossPrevention'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-DlpComplianceRule'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Rules = @(
                        [pscustomobject]@{ Guid = 'r1'; Name = 'Credit card numbers (fabricated)'; Policy = 'Financial data'; Disabled = $false; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = 'r2'; Name = 'Bank account numbers (fabricated)'; Policy = 'Financial data'; Disabled = $false; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = 'r3'; Name = 'Passport numbers (fabricated)'; Policy = 'Pilot'; Disabled = $true; MentionsCopilot = $false }
                        [pscustomobject]@{ Guid = 'r4'; Name = 'Copilot processing (fabricated)'; Policy = 'DSPM for AI - Protect sensitive data from Copilot processing'; Disabled = $false; MentionsCopilot = $true }
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
                        [pscustomobject]@{ Guid = 'rp1'; Name = 'Mailbox retention (fabricated)'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; RuleTypes = 'Default'; HasRules = $true }
                        [pscustomobject]@{ Guid = 'rp2'; Name = 'Teams chat retention (fabricated)'; Enabled = $false; Mode = 'Enforce'; Workload = 'MicrosoftTeams'; RuleTypes = 'Default'; HasRules = $true }
                        [pscustomobject]@{ Guid = 'rp3'; Name = 'Auto-apply contracts label (fabricated)'; Enabled = $true; Mode = 'Enforce'; Workload = 'SharePoint'; RuleTypes = 'Apply'; HasRules = $true }
                        [pscustomobject]@{ Guid = 'rp4'; Name = 'Auto-apply invoices label (fabricated)'; Enabled = $true; Mode = 'TestWithoutNotifications'; Workload = 'SharePoint'; RuleTypes = 'Apply'; HasRules = $true }
                        [pscustomobject]@{ Guid = 'rp5'; Name = 'Publish records labels (fabricated)'; Enabled = $true; Mode = 'Enforce'; Workload = 'SharePoint'; RuleTypes = 'Publish'; HasRules = $true }
                        # Adaptive Protection writes this one itself, and the portal keeps it apart.
                        [pscustomobject]@{ Guid = 'rp6'; Name = 'Proactive data retention for risky users'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; RuleTypes = 'Apply, ProactiveDataRetention'; HasRules = $true }
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
                        [pscustomobject]@{ Guid = 't1'; Name = 'Keep 7 years (fabricated)'; IsRecordLabel = $true; RetentionAction = 'Keep'; RetentionDuration = 2555 }
                        [pscustomobject]@{ Guid = 't2'; Name = 'Delete after 1 year (fabricated)'; IsRecordLabel = $false; RetentionAction = 'Delete'; RetentionDuration = 365 }
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
                        [pscustomobject]@{ Name = 'Legal hold policy (fabricated)'; TagCount = 3 }
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
                source = [pscustomobject]@{ interface = 'Get-AdminAuditLogConfig'; kind = 'SecurityAndCompliancePowerShell' }
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
                        [pscustomobject]@{ Name = 'Keep Exchange admin activity for ten years (fabricated)'; Enabled = $true; RetentionDuration = 'TenYears'; RecordTypes = 'ExchangeAdmin'; Priority = 100 }
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
                        [pscustomobject]@{ Tag = 'Contoso Employee Identifier (fabricated)'; TagType = 'SensitiveInformationType'; TotalCount = 17 }
                        [pscustomobject]@{ Tag = 'Contoso Customer Number (fabricated)'; TagType = 'SensitiveInformationType'; TotalCount = 9 }
                    )
                    Requests = @(
                        [pscustomobject]@{ Tag = 'Contoso Employee Identifier (fabricated)'; TagType = 'SensitiveInformationType'; Status = 'Success'; TotalCount = 17 }
                        [pscustomobject]@{ Tag = 'Contoso Customer Number (fabricated)'; TagType = 'SensitiveInformationType'; Status = 'Success'; TotalCount = 9 }
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
                        [pscustomobject]@{ Guid = 's1'; Name = 'Credit Card Number'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
                        [pscustomobject]@{ Guid = 's2'; Name = 'U.S. Social Security Number (SSN)'; Publisher = 'Microsoft Corporation'; Type = 'Default' }
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
    Write-Line -Style Dim -Message '  you are not already connected to. Sign-in happens in your browser: no password,'
    Write-Line -Style Dim -Message '  secret or token is ever handled by this script.'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  -ReportFolder     write the report somewhere other than the current directory'
    Write-Line -Style Dim -Message '  -Demo             render a report from fabricated data, with no tenant or sign-in'
    Write-Line -Style Dim -Message '  -PdfReport        also render the report to PDF'
    Write-Line -Style Dim -Message '  -ProtectPdf       encrypt that PDF with a password you are asked for. Needs qpdf'
    Write-Line -Style Dim -Message '  -SkipInsights     configuration only; skip activity, indexed-content and oversharing reads'
    Write-Line -Style Dim -Message '  -SkipConnect      use only sessions you established yourself'
    Write-Line -Style Dim -Message '  -KeepSignedIn     leave the sessions open instead of signing out at the end'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  Get-Help .\Invoke-PurviewAdvisor.ps1 -Full for everything else.'
}

function Show-ModuleStatus {
    <# .SYNOPSIS Reports what happened to each prerequisite module. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Module)

    Write-Line -Style Head -Message '  Modules'
    $usable = 0

    foreach ($item in $Module) {
        switch ($item.State) {
            'Loaded' { $usable++; Write-Line -Style Good -Message ('    ready        {0}' -f $item.Service) }
            'InstalledAndLoaded' { $usable++; Write-Line -Style Good -Message ('    installed    {0}' -f $item.Service) }
            'UpdatedAndLoaded' { $usable++; Write-Line -Style Good -Message ('    updated      {0}' -f $item.Service) }
            # Usable, but the version is behind what the settings it reads are documented to need.
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

    # A role list nobody could read is not an empty role list, and the two must not print alike.
    $entra = if ([bool](Get-PurviewProperty -InputObject $Context -Name 'EntraRoleUnnamed')) {
        'held, but this sign-in cannot read their names. That needs a directory read permission'
    }
    elseif (-not $Context.EntraRoleRead) { 'not read; the run is not connected to Microsoft Graph' }
    elseif (@($Context.EntraRole).Count -eq 0) { 'none held directly' }
    else { @($Context.EntraRole) -join ', ' }
    & $line 'Entra' $entra 'Dim'

    $purview = if (-not $Context.PurviewRoleGroupRead) { 'not read; that needs the Role management role' }
    elseif (@($Context.PurviewRoleGroup).Count -eq 0) { 'none held directly' }
    else { @($Context.PurviewRoleGroup) -join ', ' }
    & $line 'Purview' $purview 'Dim'
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
        [ValidateSet('Commercial', 'GCC', 'GCCHigh', 'DoD', 'China')][string]$Environment = 'Commercial'
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
    $good = @($rows | Where-Object { $_.State -eq 'As recommended' })
    $inUse = @($rows | Where-Object { $_.State -eq 'In use' })
    $seenRecently = @($rows | Where-Object { $_.State -eq 'Seen recently' })
    $evidenceFound = @($rows | Where-Object { $_.State -eq 'Evidence found' })
    $granted = @($rows | Where-Object { $_.State -eq 'Granted' })
    $portal = @($rows | Where-Object { $_.State -eq 'Confirm in portal' })
    # Counted by state, not as a residual: evidence states must never be tallied as not read.
    $unread = @($rows | Where-Object { $_.State -eq 'Not read' }).Count

    $summary = '    {0} need attention, {1} as recommended' -f $attention.Count, $good.Count
    if ($inUse.Count -gt 0) { $summary += ", $($inUse.Count) in use" }
    if ($granted.Count -gt 0) { $summary += ", $($granted.Count) granted" }
    if ($seenRecently.Count -gt 0) { $summary += ", $($seenRecently.Count) seen recently" }
    if ($evidenceFound.Count -gt 0) { $summary += ", $($evidenceFound.Count) evidence found" }
    $summary += ", $($portal.Count) to confirm in the portal"
    if ($unread -gt 0) { $summary += ", $unread not read this run" }
    Write-Line -Style Dim -Message $summary

    foreach ($row in $rows) {
        $style = switch ($row.State) { 'As recommended' { 'Good' } 'Granted' { 'Good' } 'In use' { 'Good' } 'Needs attention' { 'Bad' } default { 'Dim' } }
        $marker = switch ($row.State) { 'As recommended' { 'ok    ' } 'Granted' { 'grant ' } 'Seen recently' { 'recent' } 'Evidence found' { 'found ' } 'In use' { 'in use' } 'Needs attention' { 'FIX   ' } 'Confirm in portal' { 'portal' } default { '?     ' } }
        $label = if ($row.Optional) { '{0} (optional)' -f $row.Name } else { [string]$row.Name }
        Write-Line -Style $style -Message ('    {0} {1}' -f $marker, $label)
        if ($row.State -ne 'As recommended' -and $row.Action) {
            Write-Line -Style Dim -Message ('             {0}' -f $row.Action)
        }
    }

    Write-Line -Style Dim -Message '    These ship switched off so that adopting Purview does not change behaviour'
    Write-Line -Style Dim -Message '    overnight. Microsoft exposes no way to read the ones marked portal.'
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
        Write-Line -Style $style -Message ('    {0,-22} {1}' -f $row.Tier, $row.Match)
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

    foreach ($group in 'To do', 'To check by hand', 'Done', 'Not checked') {
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
        NotCollected = 'Dim'; Unsupported = 'Dim'
    }

    $notAssessed = 0
    foreach ($status in 'Fail', 'Warning', 'NeedsReview', 'Pass', 'NotCollected', 'Unsupported') {
        $count = @($Finding | Where-Object { $_.status -eq $status }).Count
        if ($status -in 'NotCollected', 'Unsupported') { $notAssessed += $count }
        if ($count -eq 0) { continue }
        Write-Line -Style $styles[$status] -Message ('    {0,-22} {1}' -f (Get-PurviewStatusLabel -Status $status), $count)
    }

    if ($notAssessed -gt 0) {
        Write-Line -Message ''
        Write-Line -Style Dim -Message "    $notAssessed rule(s) had no data to work from. Connect to the services"
        Write-Line -Style Dim -Message '    listed above to bring them into the next run.'
    }
}

function Get-PurviewStatusLabel {
    <#
    .SYNOPSIS
        The wording a reader sees for a status.

    .DESCRIPTION
        Only the label changes. The stored value stays 'Fail', because posture records compare
        outcomes across runs and renaming the value would orphan every baseline already written.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Status)

    switch ($Status) {
        'Fail' { return 'Area for improvement' }
        'NotCollected' { return 'Not collected' }
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
        Write-Line -Style Good -Message '  Nothing actionable was found.'
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

#region Main

# Dot-sourcing this script exposes its functions without running an assessment, which is how the
# tests exercise it.
if ($MyInvocation.InvocationName -eq '.') { return }

try {

Write-Line -Message ''
Write-Line -Style Head -Message ('  Microsoft Purview advisor {0}' -f $script:ToolVersion)
Write-Line -Style Dim -Message '  Evidence-based assessment. Read-only: it changes nothing in your tenant.'
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

# The report is the deliverable, so a run always produces one somewhere findable. One folder,
# refreshed each time: run history lives in the posture records, not in a pile of stale reports.
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
    $modules = @(Install-PurviewPrerequisite -SkipInstall:$SkipModuleInstall -AllowPrompt:([Environment]::UserInteractive))
    $usable = Show-ModuleStatus -Module $modules
    Write-Line -Message ''

    if ($usable -eq 0) {
        Write-Line -Style Bad -Message '  No collection module is available, so there is nothing to collect.'
        Write-Line -Style Dim -Message '  Install them yourself, or run again without -SkipModuleInstall.'
        Write-Line -Message ''
        return
    }

    if (-not $SkipConnect) {
        Write-Line -Style Head -Message '  Signing in'
        $null = Connect-PurviewSession -TenantAdminUrl $TenantAdminUrl -Environment $Environment -AllowPrompt:([Environment]::UserInteractive)
        Write-Line -Message ''

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
        Write-Line -Style Dim -Message '  Rule outcomes only, so the next run can show what moved. -NoRecord skips it.'
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
    -GeneratedAt ([string](Get-PurviewProperty -InputObject $snapshot -Name 'capturedAt')) `
    -AdminUrl $(if (Test-Path variable:script:SharePointAdminUrl) { $script:SharePointAdminUrl } else { '' })
ConvertTo-PurviewRemediationScript -Part $remediationParts | Set-Content -LiteralPath $remediationPath -Encoding utf8

Write-Line -Message ''
Write-Line -Style Head -Message '  Report'
Write-Line -Style Good -Message ('    {0}' -f $htmlPath)
Write-Line -Style Dim -Message ('    {0}' -f $remediationPath)
Write-Line -Style Dim -Message '    The remediation script explains each change and applies it only if you answer yes.'

if ($PdfReport -or $ProtectPdf) {
    $pdfTarget = Join-Path $ReportFolder 'report.pdf'
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
                Write-Line -Style Dim -Message '    The PDF will be encrypted. Without this password it cannot be opened, and'
                Write-Line -Style Dim -Message '    nothing keeps a copy of it, so a lost password means a lost file.'
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
                # An unprotected copy of this data is not what was asked for, so it does not survive.
                Remove-Item -LiteralPath $pdf -Force -ErrorAction SilentlyContinue
                Write-Line -Style Bad -Message '    The PDF was deleted rather than left unprotected.'
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
Write-Line -Style Dim -Message '    This folder is refreshed each run. Use -ReportFolder to keep a copy elsewhere.'
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
Write-Line -Style Dim -Message '  Nothing was changed in your tenant. Any command shown above is for you to review and run yourself.'
Write-Line -Message ''

if ($PassThru) { $findings }

}
finally {
    # Runs on a normal exit, an error and Ctrl+C alike, so nothing is left behind either way.
    $signedIn = @($script:OwnedSession).Count -gt 0
    Clear-PurviewRunState -SignOut:(-not $KeepSignedIn)
    if (-not $KeepSignedIn -and $signedIn) {
        Write-Line -Style Dim -Message '  Signed out of the sessions this run opened.'
        Write-Line -Message ''
    }
}

#endregion
