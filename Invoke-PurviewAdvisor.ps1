<#
.SYNOPSIS
    Assesses Microsoft Purview configuration against evidence-based rules and reports the result.
    Read-only: it never creates, changes, publishes or deletes anything in a tenant.

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

.PARAMETER Demo
    Render the report from built-in sample data, to see the shape of the deliverable before running
    against a tenant. No tenant, no credentials, no modules. The findings are fabricated and
    describe no real organisation, so nothing in the output is a conclusion about anything.

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

.PARAMETER SignOut
    Sign out at the end. Off by default, because the cached token is what lets the next run start
    without asking you to sign in again.

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
    Skip the activity, classification and oversharing reads. They are what answer whether labels are
    actually applied, so a run without them is configuration only.

.PARAMETER InsightDays
    Days of activity to summarise, defaulting to the full 30 that activity explorer retains. A
    shorter window runs faster but misses labelling and DLP activity that did happen, which reads
    as a taxonomy nobody uses.

.PARAMETER InsightTag
    Extra sensitive information types or labels to count. Published sensitivity labels are counted
    sensitivity labels are counted anyway.

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
    Connect-SPOService -Url https://contoso-admin.sharepoint.com
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
    [switch]$SignOut,
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
    [switch]$WordReport,
    [switch]$CheckEvidence,
    [string]$RuleFile = '',
    [string]$ExportRules = '',
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
$script:ToolVersion = '1.1.0'

# Anything the run creates and must undo before it exits.
$script:OwnedSession = @()
$script:TempArtifact = @()

# User.Read is included because Microsoft documents it as sufficient to read an organisation's
# verifiedDomains, which is how the SharePoint admin URL is worked out without prompting.
$script:GraphScope = @('LicenseAssignment.Read.All', 'GroupSettings.Read.All', 'User.Read', 'ThreatHunting.Read.All')

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
        Url = 'https://learn.microsoft.com/graph/api/subscribedsku-list?view=graph-rest-1.0'
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
        Url = 'https://learn.microsoft.com/purview/audit-log-enable-disable'
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
    'EV-FASTTRACK-001' = @{
        Title = 'Microsoft Purview - FastTrack'
        Url = 'https://learn.microsoft.com/microsoft-365/fasttrack/microsoft-purview'
        RetrievedAt = '2026-08-21'
        ContentHash = 'FBCB9FCC55F2982635619E967A5F8F31'
        Status = 'GA'
        Note = 'Defines which Purview workloads FastTrack gives remote guidance for. Information barriers are listed out of scope under both Insider Risk Management and Communication Compliance, as are privileged access management, data connectors beyond HR, and SharePoint data governance and administration. That page still labels the DSPM entry with the older classic wording; the product is Data Security Posture Management.'
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
        Url = 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically'
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
    'EV-ACTIVITY-EXPLORER-001' = @{
        Title = 'Export-ActivityExplorerData'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/export-activityexplorerdata'
        RetrievedAt = '2026-08-21'
        ContentHash = '2B025353E7CF5E2805713C122D66215B'
        Status = 'GA'
        Note = 'Reads up to 30 days of activity explorer data. Despite the Export verb it returns data and changes nothing. Mandatory parameters are StartTime, EndTime and OutputFormat.'
    }
    'EV-CONTENT-EXPLORER-001' = @{
        Title = 'Export-ContentExplorerData'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/export-contentexplorerdata'
        RetrievedAt = '2026-08-21'
        ContentHash = '2C5B70C6885B2EE026F5A52EEF5C1D7D'
        Status = 'GA'
        Note = 'TagName and TagType are mandatory. The first object returned carries TotalCount, so an item count is available without reading any record. The Aggregate switch is private preview and is not used.'
    }
    'EV-CONTENT-EXPLORER-ROLES-001' = @{
        Title = 'Get started with content explorer'
        Url = 'https://learn.microsoft.com/purview/data-classification-content-explorer'
        RetrievedAt = '2026-08-21'
        ContentHash = '35083BDC6F914403DC969B7837087EC3'
        Status = 'GA'
        Note = 'Content Explorer List Viewer shows items and locations. Content Explorer Content Viewer additionally exposes item contents and names, and is not needed to read counts.'
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
        Note = 'Assigning at least one Microsoft Copilot license grants the Copilot-supporting capabilities. Others need the SharePoint Advanced Management Plan 1 add-on. An E5 base subscription alone does not unlock it.'
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

# Which FastTrack workload each solution area belongs to, per the FastTrack Purview page cited as
# EV-FASTTRACK-001. Anything mapping to an empty string is outside what FastTrack covers and carries
# no rule. Kept as data so a change in FastTrack scope is a table edit, not a code change, and
# -CheckEvidence flags the page itself if it is rewritten.
$script:FastTrackWorkload = [ordered]@{
    'SensitivityLabels' = 'Information Protection'
    'LabelPolicies' = 'Information Protection'
    'Classification' = 'Information Protection'
    'DataLossPrevention' = 'Information Protection'
    'AutoLabeling' = 'Information Protection (E5 Premium)'
    'EndpointDlp' = 'Information Protection (E5 Premium)'
    'ContentExplorer' = 'Information Protection (E5 Premium)'
    'ActivityExplorer' = 'Information Protection (E5 Premium)'
    'DataLifecycleManagement' = 'Data Lifecycle Management'
    'RecordsManagement' = 'Records Management'
    'CommunicationCompliance' = 'Communication Compliance'
    'Audit' = 'Audit (Premium)'
    'PostureValidation' = 'Data Security Posture Management'
    # Out of FastTrack scope: information barriers, privileged access management, and SharePoint
    # data governance and administration are each listed as out of scope on that page.
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
        rationale = 'A label is presented to users by its display name. Two labels competing in the same picker under the same name are indistinguishable at the point of choosing one, and in any report of what was applied afterwards. Sublabels are compared only against their siblings, because the documented default taxonomy repeats a name under more than one parent and Confidential\All Employees is distinct from Highly Confidential\All Employees.'
        recommendation = 'Rename all but one within each parent so that label pickers and reports stay unambiguous.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
            where = @{ field = 'Disabled'; operator = 'eq'; value = $false }
            assert = @{ type = 'noDuplicatesOf'; field = 'Name'; within = 'ParentId'; withinLabel = 'parent label' }
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
        rationale = 'Until this tenant opt-in is enabled, SharePoint and OneDrive cannot process labels applied to Office files. Labelled documents are still stored, but co-authoring, eDiscovery and search behave as though the label were absent, so protection assumed elsewhere is not in force.'
        recommendation = 'Review the impact on co-authoring and existing files, then turn on EnableAIPIntegration for the tenant.'
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
        rationale = 'Several Purview capabilities are deliberately off until a tenant turns them on, so that adopting Purview does not change behaviour for users overnight. The consequence is that a tenant can look configured while labels are never processed for PDFs, no owner is told when a document is more sensitive than the site holding it, and new uploads are treated as safe before they have been scanned. Two of these switches are worded as a block or a disable, so the recommended value for them is False rather than True, and setting them the wrong way round produces the opposite of what was intended.'
        recommendation = 'Work through the Prerequisites and Tenant Opt-ins section of this report, which lists each switch with its current value, the value Microsoft recommends and what it costs to leave it alone.'
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
        version = '1.0.0'
        title = 'Endpoint DLP coverage'
        solutionArea = 'EndpointDlp'
        severity = 'Medium'
        rationale = 'Endpoint DLP is what covers copying to a USB device or network share, printing, pasting into a browser, uploading to an unapproved cloud service, and access by restricted apps. A policy scoped to Exchange, SharePoint and Teams reaches none of those, because those locations govern content held in the service rather than what someone does with it on a device.'
        recommendation = 'Onboard devices and extend at least one DLP policy to the Devices location.'
        condition = @{
            collector = 'EndpointDlpSettings'
            select = 'Settings'
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{
            capability = 'Endpoint DLP'
            includedIn = @('SPE_E5')
            addOns = @('INFORMATION_PROTECTION_AND_GOVERNANCE', 'MICROSOFT_PURVIEW_SUITE')
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
            addOns = @('MICROSOFT_PURVIEW_SUITE')
        }
        evidence = @('EV-CMDLET-VERIFY-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'dspm step 1'
    }
    @{
        id = 'PA-IP-0005'
        version = '1.0.0'
        title = 'Sensitivity labels defined'
        solutionArea = 'SensitivityLabels'
        severity = 'Critical'
        rationale = 'Sensitivity labels are what auto-labeling policies apply, what a DLP policy can use as a condition, and what a container label attaches to a site, Team or group. With none defined, none of those can reference a classification.'
        recommendation = 'Create a label taxonomy, starting with the default set, before configuring policies that depend on labels.'
        condition = @{
            collector = 'SensitivityLabel'
            select = 'Labels'
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
        rationale = 'Labelling that depends entirely on users is applied inconsistently and never reaches content already at rest. Auto-labeling policies classify existing and incoming content on the service side, which is what makes coverage predictable rather than best-effort.'
        recommendation = 'Create auto-labeling policies for the sensitive information types that matter most, starting in simulation to assess the impact.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{
            capability = 'Auto-labeling'
            includedIn = @('SPE_E5')
            addOns = @('INFORMATION_PROTECTION_AND_GOVERNANCE', 'MICROSOFT_PURVIEW_SUITE')
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
        rationale = 'Simulation is a required stage rather than a fault, but a tenant where every policy is still simulating labels nothing at all. The policy list reads the same either way, so a rollout that stalled after the pilot looks finished until the mode is checked.'
        recommendation = 'Review the simulation results and turn on the policies that are labelling what you expected.'
        condition = @{
            collector = 'AutoLabeling'
            select = 'Policies'
            assert = @{ type = 'anyHave'; where = @{ field = 'Mode'; operator = 'eq'; value = 'Enable' } }
        }
        licensing = @{
            capability = 'Auto-labeling'
            includedIn = @('SPE_E5')
            addOns = @('INFORMATION_PROTECTION_AND_GOVERNANCE', 'MICROSOFT_PURVIEW_SUITE')
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
        version = '1.0.0'
        title = 'Retention policy coverage'
        solutionArea = 'DataLifecycleManagement'
        severity = 'High'
        rationale = 'A retention policy applies retention or deletion across an entire location, such as all Exchange mailboxes or all SharePoint sites. Retention policies are also the only mechanism covering Teams, Viva Engage, Skype and public folders. Without one, what is kept and what is deleted is left to each user.'
        recommendation = 'Define retention policies covering Exchange, SharePoint, OneDrive and Teams according to your retention schedule.'
        condition = @{
            collector = 'RetentionPolicy'
            select = 'Policies'
            where = @{ field = 'Enabled'; operator = 'eq'; value = $true }
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{ capability = 'Retention policies'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001')
        confidence = 'High'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
        deploymentModel = 'dspm step 1'
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
        deploymentModel = 'dspm step 1'
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
            addOns = @('MICROSOFT_PURVIEW_SUITE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-RETENTION-001')
        confidence = 'Low'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        deploymentModel = 'dspm step 1'
    }
    @{
        id = 'PA-CC-0001'
        version = '1.0.0'
        title = 'Communication compliance policies'
        solutionArea = 'CommunicationCompliance'
        severity = 'Low'
        rationale = 'Communication compliance helps detect messages that breach policy, covering regulatory obligations such as FINRA Rule 3110 along with harassment, threats, profanity and sensitive information shared in messages. It covers Teams, Exchange Online, Viva Engage and third-party sources, and generative AI interactions including Microsoft 365 Copilot. None of it is examined without a policy.'
        recommendation = 'If you are subject to supervision obligations or want conduct detection, configure at least one communication compliance policy. Otherwise dismiss this finding.'
        condition = @{
            collector = 'CommunicationCompliance'
            select = 'Policies'
            assert = @{ type = 'isNotEmpty' }
        }
        licensing = @{
            capability = 'Communication Compliance'
            includedIn = @('SPE_E5')
            addOns = @('MICROSOFT_PURVIEW_SUITE')
        }
        evidence = @('EV-CMDLET-VERIFY-001', 'EV-COMMCOMP-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Protect Critical Data Assets'
        deploymentModel = 'dspm step 3'
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
        id = 'PA-VAL-0001'
        version = '1.0.0'
        title = 'Sensitivity label usage'
        solutionArea = 'PostureValidation'
        severity = 'Medium'
        rationale = 'Activity explorer records when labels were applied, changed or removed, drawn from the unified audit log, covering the last 30 days. Microsoft publishes no adoption metric, so this compares the labels that are published against whether any labelling activity was observed at all.'
        recommendation = 'If labels are published but unused, check that a label publishing policy targets real users, then consider default labelling or auto-labelling so protection does not depend on people remembering.'
        condition = @{
            collector = 'PostureValidation'
            assert = @{ type = 'allHave'; where = @{ field = 'LabelsPublishedButUnused'; operator = 'eq'; value = $false } }
        }
        licensing = @{ capability = 'Sensitivity labels'; includedIn = @('SPE_E3', 'SPE_E5'); addOns = @() }
        evidence = @('EV-ACTIVITY-EXPLORER-001', 'EV-AUTOLABEL-001')
        confidence = 'Medium'
        guidanceStatus = 'GA'
        zeroTrust = 'Data / Know and Protect Your Data'
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
        version = '1.0.0'
        title = 'DLP rule coverage'
        solutionArea = 'DataLossPrevention'
        severity = 'High'
        rationale = 'A DLP policy holds no conditions or actions of its own; its rules do. A policy with no rules appears in the Purview portal as though it were protecting content while matching nothing at all.'
        recommendation = 'Open each DLP policy and confirm it has at least one enabled rule with conditions and actions.'
        condition = @{
            collector = 'DlpRule'
            select = 'Rules'
            assert = @{ type = 'isNotEmpty' }
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
        version = '1.0.0'
        title = 'Disabled DLP rules'
        solutionArea = 'DataLossPrevention'
        severity = 'Medium'
        rationale = 'A disabled rule inside an enforcing policy is the quietest kind of gap: the policy reports as on, and the specific condition that rule covered is simply not evaluated.'
        recommendation = 'Enable the rule, or delete it if it is no longer wanted, so the policy and its behaviour agree.'
        condition = @{
            collector = 'DlpRule'
            select = 'Rules'
            assert = @{ type = 'noneHave'; where = @{ field = 'Disabled'; operator = 'eq'; value = $true } }
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
        Portal = 'Purview portal > Settings > Device onboarding > Devices, then select "Turn on device onboarding"'
        Why = 'Endpoint data loss prevention and Insider Risk Management both require a device to be onboarded before they receive any monitoring data from it. Once onboarded, the device reports activities including copying to removable media or a network share, printing, pasting into a browser, and uploading to restricted cloud domains. Device onboarding is shared with Microsoft Defender for Endpoint, so devices already onboarded there appear automatically and require no further action.'
        Url = 'https://learn.microsoft.com/purview/device-onboarding-overview'
    }
    @{
        Name = 'Labels processed for Office files in SharePoint and OneDrive'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableAIPIntegration'
        Recommended = 'Set-SPOTenant -EnableAIPIntegration $true'
        Command = 'Set-SPOTenant -EnableAIPIntegration $true'; Session = 'SharePoint'
        Why = 'This parameter enables SharePoint to process the content of files stored in SharePoint and OneDrive that carry sensitivity labels including encryption. Until it is enabled, those files are stored but not processed, so search, eDiscovery, data loss prevention and co-authoring cannot operate on their contents. The label itself continues to apply in Outlook and the desktop applications.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    }
    @{
        Name = 'Labels on PDF files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforPDF'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforPDF $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it adds PDF support for applying a label in Office for the web, extracting and displaying the label on an uploaded file, search, eDiscovery and data loss prevention, and auto-labeling policies and default document library labels. Without it, none of those apply to a PDF.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    }
    @{
        Name = 'Labels on OneNote sections'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelforOneNote'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelforOneNote $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it allows a sensitivity label to be applied manually to a OneNote section across endpoints. Without it, OneNote content cannot carry a sensitivity label.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    }
    @{
        Name = 'Labels on MP4 video files'
        Collector = 'SharePointLabelingReadiness'; Setting = 'EnableSensitivityLabelForVideoFiles'
        Recommended = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'
        Command = 'Set-SPOTenant -EnableSensitivityLabelForVideoFiles $true'; Session = 'SharePoint'
        Why = 'Disabled by default. Enabling it allows a sensitivity label to be applied to video files in SharePoint, and the label on an uploaded file to be extracted and displayed. Meeting recordings are stored as ordinary files and cannot carry a label without it.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    }
    @{
        Name = 'Owner is emailed when a file is more sensitive than its site'
        Collector = 'SharePointLabelingReadiness'; Setting = 'BlockSendLabelMismatchEmail'
        Recommended = 'Leave off: Set-SPOTenant -BlockSendLabelMismatchEmail $false'
        Command = 'Set-SPOTenant -BlockSendLabelMismatchEmail $false'; Session = 'SharePoint'
        Why = 'Where a document carries a higher-priority label than the site holding it, SharePoint records a Detected document sensitivity mismatch audit event. Unless this setting blocks it, SharePoint also sends an Incompatible sensitivity label detected notification to the person who uploaded the file and to the site owners. The parameter is worded as a block and the notification is on by default, so a value of True means it has been turned off.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites'
    }
    @{
        Name = 'Default labels apply to document libraries'
        Collector = 'SharePointLabelingReadiness'; Setting = 'DisableDocumentLibraryDefaultLabeling'
        Recommended = 'Leave off: Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'
        Command = 'Set-SPOTenant -DisableDocumentLibraryDefaultLabeling $false'; Session = 'SharePoint'
        Why = 'This parameter disables the ability to configure a default sensitivity label on a document library, and its default value is False. Left at False, a document library can apply a default label to files added to it. Set to True, that option is removed from the library settings.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-default-label'
    }
    @{
        Name = 'New files are treated as sensitive until scanned'
        Collector = 'SharePointLabelingReadiness'; Setting = 'MarkNewFilesSensitiveByDefault'
        Recommended = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'
        Command = 'Set-SPOTenant -MarkNewFilesSensitiveByDefault BlockExternalSharing'; Session = 'SharePoint'
        Why = 'Where external sharing is on, sensitive content can be shared and accessed by guests before the Office DLP rule finishes processing the file. BlockExternalSharing prevents guests from accessing a newly added file until at least one Office DLP policy has scanned its content. AllowExternalSharing disables that protection.'
        Url = 'https://learn.microsoft.com/sharepoint/sensitive-by-default'
    }
    @{
        Name = 'Co-authoring for files encrypted with sensitivity labels'
        Collector = 'EndpointDlpSettings'; Setting = 'EnableLabelCoauth'; ExpectedValue = 'True'
        Recommended = 'Purview portal > Settings > Information Protection > Co-authoring for files with sensitivity labels, then select "Turn on co-authoring for files with sensitivity labels"'
        Command = 'Set-PolicyConfig -EnableLabelCoauth $true'; Session = 'SecurityAndCompliance'
        Caution = 'One way in the portal: once on, it can only be turned off with Set-PolicyConfig -EnableLabelCoauth:$false, and Microsoft documents that doing so loses the newer labelling metadata for unencrypted Word, Excel and PowerPoint files. Turning it on also enables sensitivity labels for Office files in SharePoint and OneDrive if that is not already on.'
        Why = 'Co-authoring allows multiple users to edit a file encrypted by a sensitivity label simultaneously, in the desktop, web and mobile applications, with AutoSave available. Without it, such files can be edited by one user at a time and AutoSave does not function.'
        Url = 'https://learn.microsoft.com/purview/sensitivity-labels-coauthoring'
    }
    @{
        Name = 'Container labels for groups, Teams and sites'
        Collector = 'ContainerLabel'; Setting = 'EnableMIPLabels'
        Recommended = 'Set EnableMIPLabels to True on the Group.Unified directory setting in Microsoft Entra, then run Execute-AzureAdLabelSync in Security & Compliance PowerShell'
        Why = 'Container labels apply privacy, external user access, external sharing, unmanaged device access and Conditional Access settings to a Team, Microsoft 365 group, SharePoint site, Viva Engage community or Loop workspace. Items inside the container do not inherit the label, so this governs access to the container rather than protection of its contents. Until the EnableMIPLabels directory setting is on in Microsoft Entra, the group and site settings on a label cannot be configured and container-scoped labels never appear. Configuring it needs an active Microsoft Entra ID P1 licence, which Microsoft 365 E3 includes and E5 covers through P2, so it is rarely the obstacle. The label scope must include groups and sites, and after synchronising a label can take up to 24 hours to become available in Microsoft Entra.'
        Url = 'https://learn.microsoft.com/entra/identity/users/groups-assign-sensitivity-labels'
    }
    @{
        Name = 'Unified audit logging'
        RuleId = 'PA-AUD-0002'
        Recommended = 'Purview portal > Audit, then select "Start recording user and admin activity"'
        Why = 'Auditing is on by default for enterprise tenants, though not for Small and Medium Business licences or unmanaged trial tenants. Where it is off, audit log search returns no results and the Management Activity API returns no data, and activity from that period is never recorded and cannot be recovered afterwards. Audit (Standard) retains records for 180 days; Audit (Premium) retains for one year and can be extended to 10 years with an add-on.'
        Url = 'https://learn.microsoft.com/purview/audit-log-enable-disable'
    }
    @{
        Name = 'Teams DLP policies extended to SharePoint and OneDrive'
        Collector = 'EndpointDlpSettings'; Setting = 'ExtendTeamsDlpPoliciesToSharePointOneDrive'; ExpectedValue = 'True'
        Recommended = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'
        Command = 'Set-PolicyConfig -ExtendTeamsDlpPoliciesToSharePointOneDrive $true'; Session = 'SecurityAndCompliance'
        Why = 'A file shared in a Teams chat is stored in the sender''s OneDrive account and linked from the message. A DLP policy scoped only to Teams therefore evaluates the message but not the stored copy. Extending Teams policies to SharePoint and OneDrive brings that copy within the same policy scope.'
        Url = 'https://learn.microsoft.com/powershell/module/exchangepowershell/set-policyconfig'
    }
    @{
        Name = 'DLP analytics'
        Evidence = @{
            Collector = 'DataLossPrevention'; Select = 'Policies'; Field = 'Name'; Match = '^RiskSpotlighting-'
            Found = 'DLP analytics has produced at least one policy recommendation in this tenant.'
            NotFound = 'No analytics recommendation was found. That does not mean analytics is off, since recommendations take seven days and need not be accepted. Confirm in the portal.'
        }
        Portal = 'Purview portal > Settings > Data Loss Prevention > Analytics, then turn on "Activate analytics"'
        Why = 'DLP analytics reports the top oversharing risks, blind spots and policy improvement opportunities from the last 30 days of activity, and can create a new DLP policy or refine an existing one from what it finds. It is off by default and has to be opted into. Scans run hourly against audit log and policy data, recommendations take seven days to appear after it is turned on, and they refresh weekly.'
        Url = 'https://learn.microsoft.com/purview/dlp-analytics-get-started'
    }
    @{
        Name = 'Insider risk analytics'
        Portal = 'Purview portal > Settings > Insider Risk Management > Analytics, then turn on "Show insights at tenant level"'
        Why = 'Analytics evaluates potential insider risks without any insider risk policy being configured, and the results indicate which policy types to configure and how broadly to scope them. Results are returned aggregated and anonymised, so reviewers cannot identify individual users. It scans Microsoft 365 audit logs, Exchange Online and Microsoft Entra ID, plus the HR data connector where one is configured, and scores against up to 10 days of activity. The first insights take up to 48 hours.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-analytics'
    }
    @{
        Name = 'Insider risk data shared with other security solutions'
        Evidence = @{
            Collector = 'InsiderRiskSharing'; Select = 'Behaviors'
            Found = 'Insider risk detail is reaching the Defender alert queues.'
            NotFound = 'No insider risk detail has reached Defender. That does not mean sharing is off, since a tenant with nothing to report looks the same. Confirm in the portal.'
        }
        Optional = $true
        Portal = 'Purview portal > Settings > Insider Risk Management > Data sharing, then turn on "Share user risk details with other security solutions"'
        Why = 'Enabling this makes the insider risk severity already calculated for a user available in the alert queues of Microsoft Defender XDR, Communication Compliance and data loss prevention, so an analyst investigating an alert can see that user''s recent exfiltration activity alongside it. Where it is disabled, those queues report that the user''s data is unavailable. It applies no enforcement and blocks nothing.'
        Url = 'https://learn.microsoft.com/purview/insider-risk-management-settings-share-data'
    }
    @{
        Name = 'Auto-labelling is turned on rather than left in simulation'
        RuleId = 'PA-IP-0008'
        Choose = @{
            Collector = 'AutoLabeling'; Select = 'Policies'; Field = 'Name'; Unless = 'Mode'; Is = 'Enable'
            Prompt = 'Auto-labeling policies not yet turned on'
            Apply = 'Set-AutoSensitivityLabelPolicy -Identity $name -Mode Enable'
            Session = 'SecurityAndCompliance'
        }
        Recommended = 'Purview portal > Solutions > Information Protection > Policies > Auto-labeling policies, then select "Turn on policy" for those whose simulation results look right'
        Why = 'Simulation is a required stage of the documented workflow: a policy cannot apply labels until it has completed at least one simulation. A policy left in simulation applies nothing. Enabling a policy also does not act on existing content, since files are labelled as they are created or modified from that point; content already at rest requires on-demand classification to be evaluated.'
        Url = 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically'
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
        }
        [pscustomobject]@{
            Name = 'Microsoft.Online.SharePoint.PowerShell'
            Service = 'SharePoint Online'
            Connect = 'Connect-SPOService -Url https://<tenant>-admin.sharepoint.com'
            WindowsOnly = $true
            # Microsoft documents that this module must be imported with -UseWindowsPowerShell on 7.
            NeedsWindowsPowerShell = $true
        }
        [pscustomobject]@{
            Name = 'Microsoft.Graph.Authentication'
            Service = 'Microsoft Graph'
            Connect = 'Connect-MgGraph -Scopes LicenseAssignment.Read.All, GroupSettings.Read.All'
            WindowsOnly = $false
            NeedsWindowsPowerShell = $false
        }
    )
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
        [switch]$SkipInstall
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($module in Get-PurviewRequiredModule) {
        $outcome = [ordered]@{ Name = $module.Name; Service = $module.Service; Connect = $module.Connect; State = 'Unknown'; Detail = '' }

        if ($module.WindowsOnly -and -not $IsWindows) {
            $outcome.State = 'Unavailable'
            $outcome.Detail = 'Windows only, so this service cannot be collected on this platform.'
            $results.Add([pscustomobject]$outcome)
            continue
        }

        if (@(Get-Module -ListAvailable -Name $module.Name).Count -eq 0) {
            if ($SkipInstall) {
                $outcome.State = 'Missing'
                $outcome.Detail = "Install-Module $($module.Name) -Scope CurrentUser"
                $results.Add([pscustomobject]$outcome)
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($module.Name, 'Install from PSGallery for the current user')) {
                $outcome.State = 'Missing'
                $outcome.Detail = 'Installation was declined.'
                $results.Add([pscustomobject]$outcome)
                continue
            }

            try {
                Install-Module -Name $module.Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
                $outcome.State = 'Installed'
            }
            catch {
                $outcome.State = 'Failed'
                $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
                $results.Add([pscustomobject]$outcome)
                continue
            }
        }
        else {
            $outcome.State = 'Present'
        }

        try {
            if ($module.NeedsWindowsPowerShell) {
                Import-Module -Name $module.Name -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            }
            else {
                Import-Module -Name $module.Name -ErrorAction Stop
            }
            $outcome.State = if ($outcome.State -eq 'Installed') { 'InstalledAndLoaded' } else { 'Loaded' }
        }
        catch {
            $outcome.State = 'Failed'
            $outcome.Detail = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
        }

        $results.Add([pscustomobject]$outcome)
    }

    return $results.ToArray()
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
                $null = Get-SPOTenant -ErrorAction Stop
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

    # A bare tenant name, which is what most people offer.
    if ($text -notmatch '[./]') { return ('https://{0}-admin.sharepoint.com' -f ($text -replace '-(admin|my)$', '')) }

    if ($text -notmatch '^https?://') { $text = "https://$text" }

    # -my and the plain hostname both point at the same tenant; the admin host is what is needed.
    if ($text -match '^https?://([^./]+?)(-admin|-my)?\.sharepoint\.com') {
        return "https://$($Matches[1])-admin.sharepoint.com"
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

    $build = { param($domain) 'https://{0}-admin.sharepoint.com' -f ([string]$domain).Split('.')[0] }

    if (Test-PurviewCommand -Name 'Invoke-MgGraphRequest') {
        try {
            foreach ($org in @(Invoke-PurviewGraphGet -Uri 'https://graph.microsoft.com/v1.0/organization')) {
                $domains = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $org -Name 'verifiedDomains')) |
                    Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'name') -match '\.onmicrosoft\.com$' }

                $initial = @($domains | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'isInitial') })
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
        # The module prints its own token errors; they only matter if the retry fails as well.
        $failure = ''
        try { Connect-IPPSSession @hint @sccArgs -ErrorAction Stop -WarningAction SilentlyContinue *> $null }
        catch { $failure = [string]$_.Exception.Message }

        if (Test-PurviewBrokerRetry -Command 'Connect-IPPSSession' -Message $failure) {
            $failure = ''
            try { Connect-IPPSSession @hint @sccArgs -DisableWAM -ErrorAction Stop -WarningAction SilentlyContinue *> $null }
            catch { $failure = 'Sign-in could not acquire a token, with and without the broker. ' + $_.Exception.Message }
        }

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
        $failure = ''
        try { Connect-ExchangeOnline @hint @exoArgs -ShowBanner:$false -ErrorAction Stop -WarningAction SilentlyContinue *> $null }
        catch { $failure = [string]$_.Exception.Message }

        if (Test-PurviewBrokerRetry -Command 'Connect-ExchangeOnline' -Message $failure) {
            $failure = ''
            try { Connect-ExchangeOnline @hint @exoArgs -DisableWAM -ShowBanner:$false -ErrorAction Stop -WarningAction SilentlyContinue *> $null }
            catch { $failure = 'Sign-in could not acquire a token, with and without the broker. ' + $_.Exception.Message }
        }

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
            Connect-MgGraph -Scopes $script:GraphScope @graphArgs -NoWelcome -ErrorAction Stop
            & $record 'Microsoft Graph' 'Connected' '' 'Graph'
        }
        catch {
            & $record 'Microsoft Graph' 'Failed' (Get-PurviewSafeErrorMessage -Message $_.Exception.Message) $null
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

    if (-not (Test-PurviewCommand -Name 'Connect-SPOService')) {
        & $record 'SharePoint Online' 'Unavailable' 'The SharePoint Online module is not loaded. It is Windows only.' $null
        return $results.ToArray()
    }

    $url = Format-PurviewAdminUrl -Value $TenantAdminUrl
    $derived = $false
    if ([string]::IsNullOrWhiteSpace($url)) {
        $url = Resolve-PurviewTenantAdminUrl
        $derived = -not [string]::IsNullOrWhiteSpace($url)
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

    # A derived URL is a good guess, not a certainty, so a wrong one is corrected rather than fatal.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            # The system browser is what makes passkeys and other platform authenticators available;
            # the module's own dialog falls back to a password.
            $spoArgs = @{}
            if ($cloud.SpoRegion) { $spoArgs['Region'] = $cloud.SpoRegion }
            Connect-SPOService -Url $url @spoArgs -UseSystemBrowser $true -ErrorAction Stop
            # Kept so the remediation script can carry the URL rather than ask for it again.
            $script:SharePointAdminUrl = $url
            & $record 'SharePoint Online' 'Connected' $(if ($derived) { "Worked out as $url" } else { '' }) 'SharePoint'
            return $results.ToArray()
        }
        catch {
            $message = Get-PurviewSafeErrorMessage -Message $_.Exception.Message
            Write-PurviewStepResult -Status 'Failed'
            Write-Line -Style Bad -Message ('    Could not sign in to {0}' -f $url)
            Write-Line -Style Dim -Message ('    {0}' -f $message)

            if ($derived) {
                Write-Line -Style Warn -Message '    That URL was worked out from your tenant domain, which does not always match'
                Write-Line -Style Warn -Message '    the SharePoint hostname. Yours may simply be named differently.'
            }

            if (-not $AllowPrompt -or $attempt -eq 3) {
                & $record 'SharePoint Online' 'Failed' "$message Tried $url. Pass -TenantAdminUrl to set it directly." $null
                return $results.ToArray()
            }

            Write-Line -Style Dim -Message '    Enter the correct admin URL, or press Enter to carry on without SharePoint.'
            $corrected = Format-PurviewAdminUrl -Value (Read-Host '    SharePoint admin URL')

            if ([string]::IsNullOrWhiteSpace($corrected)) {
                & $record 'SharePoint Online' 'Skipped' 'Carried on without SharePoint, so those checks were not assessed.' $null
                return $results.ToArray()
            }

            $url = $corrected
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
        Not done by default. Each module caches its token, and keeping that cache is what lets a
        later run start without asking you to sign in again.
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

    $script:OwnedSession = @()
}

function Clear-PurviewRunState {
    <# .SYNOPSIS Leaves the console and the machine as the run found them. #>
    [CmdletBinding()]
    param([switch]$SignOut)

    Write-Progress -Activity 'Collecting Microsoft Purview configuration' -Completed

    foreach ($path in @($script:TempArtifact | Select-Object -Unique)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    $script:TempArtifact = @()

    if ($SignOut) { Disconnect-PurviewSession }
    else { $script:OwnedSession = @() }
}

#endregion

#region Collection plumbing

function Test-PurviewCommand {
    <# .SYNOPSIS Reports whether a cmdlet is available, so a missing session is skipped not fatal. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)

    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
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
        Only fields a rule could depend on count. Enrichment fields that are legitimately absent,
        such as the parent of a top-level label, are passed as -Optional so their absence does not
        degrade the whole collection.
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
        if (-not (Test-PurviewProperty -InputObject $Record[0] -Name $key)) { $missing.Add($key) }
    }

    return $missing.ToArray()
}

function Test-PurviewAbsenceError {
    <# .SYNOPSIS Tells an unconfigured feature apart from a read that failed. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)

    # Deliberately narrow. A read that genuinely failed must keep saying so, so only phrasings that
    # can mean nothing else are treated as the feature never having been set up.
    return $Message -match "(?i)(couldn't find|could not find|cannot be found|couldn't be found|can't be found|does not exist|doesn't exist|ObjectNotFound)"
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
        [Parameter(Mandatory)][ValidateSet('SecurityAndCompliancePowerShell', 'SharePointOnlinePowerShell', 'MicrosoftGraph')][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequiredCommand,
        [Parameter(Mandatory)][scriptblock]$Collect,
        [object]$Context = $null,
        [string]$DocumentationUrl = '',
        [string]$ConnectWith = ''
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
            $result.status = 'NotConnected'
            $result.errors = @([pscustomobject]@{ message = "$($missing -join ', ') is not available to this sign-in, although the Security & Compliance session is live. The cmdlet appears once the role that grants it is assigned."; category = 'NotPermitted'; interface = $Interface })
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
            $message = Get-PurviewSafeErrorMessage -Message $_.Exception.Message

            if ($attempt -lt 3 -and (Test-PurviewTransientError -Message $message)) {
                Write-Verbose "$Collector failed transiently on attempt $attempt : $message"
                Start-Sleep -Seconds ($attempt * 3)
                continue
            }

            $retried = if ($attempt -gt 1) { " Tried $attempt times." } else { '' }

            # Never configured is not the same as could not be read, and reporting the first as a
            # failure invites someone to go looking for a fault that was never there.
            if (Test-PurviewAbsenceError -Message $message) {
                $result.status = 'Success'
                $result.data = [pscustomobject]@{}
                $result.limitations = @("$SolutionArea has not been configured in this tenant, so there was nothing to read.")
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
$script:SpoDocRoot = 'https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell'

# Which solution area belongs to which Purview solution, so a run can be narrowed to the ones a
# customer actually uses. Classification sits under both: sensitive information types feed
# auto-labelling and DLP alike, and dropping them would gut whichever half was chosen.
$script:SolutionMap = [ordered]@{
    'InformationProtection' = @('SensitivityLabels', 'LabelPolicies', 'AutoLabeling', 'Classification', 'ContentExplorer', 'ActivityExplorer')
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
            Map = [ordered]@{
                Guid = @('Guid', 'ImmutableId', 'Identity'); Name = @('DisplayName', 'Name')
                Priority = @('Priority'); Disabled = @('Disabled')
                ContentType = @('ContentType'); ParentId = @('ParentId')
                EncryptionEnabled = @('EncryptionEnabled')
                EncryptionRights = @('EncryptionRightsDefinitions')
            }
            Optional = @('ParentId', 'ContentType', 'EncryptionEnabled', 'EncryptionRights')
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
                Policy = @('ParentPolicyName', 'Policy'); Disabled = @('Disabled')
                SensitiveTypes = @('ContentContainsSensitiveInformation')
            }
            Optional = @('Policy', 'Disabled', 'SensitiveTypes')
        }
        @{
            Collector = 'DataLossPrevention'; Area = 'DataLossPrevention'; Cmdlet = 'Get-DlpCompliancePolicy'; Key = 'Policies'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Mode = @('Mode'); Enabled = @('Enabled'); Workload = @('Workload')
                # Microsoft documents the location as "Microsoft 365 Copilot and Copilot Chat" but
                # not the property behind it, so the candidates are tried and absence is declared.
                CopilotLocation = @('CopilotLocation', 'MicrosoftCopilotLocation', 'M365CopilotLocation')
            }
            Optional = @('Enabled', 'Workload', 'CopilotLocation')
        }
        @{
            Collector = 'RetentionPolicy'; Area = 'DataLifecycleManagement'; Cmdlet = 'Get-RetentionCompliancePolicy'; Key = 'Policies'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Enabled = @('Enabled'); Mode = @('Mode'); Workload = @('Workload')
            }
            Optional = @('Mode', 'Workload')
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
            Map = [ordered]@{ Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName'); Enabled = @('Enabled') }
            Optional = @('Enabled')
        }
        @{
            Collector = 'DlpRule'; Area = 'DataLossPrevention'; Cmdlet = 'Get-DlpComplianceRule'; Key = 'Rules'
            Map = [ordered]@{
                Guid = @('Guid', 'Identity'); Name = @('Name', 'DisplayName')
                Disabled = @('Disabled'); Policy = @('ParentPolicyName', 'Policy'); Mode = @('Mode')
            }
            Optional = @('Policy', 'Mode', 'Disabled')
        }
        @{
            # Get-DataClassification is on-premises Exchange only; Security & Compliance PowerShell
            # exposes the tenant's sensitive information types under this name instead.
            Collector = 'Classification'; Area = 'Classification'; Cmdlet = 'Get-DlpSensitiveInformationType'; Key = 'SensitiveInformationTypes'
            Map = [ordered]@{
                Guid = @('Id', 'Identity', 'Guid'); Name = @('Name', 'DisplayName')
                Publisher = @('Publisher'); Type = @('Type')
            }
            Optional = @('Publisher', 'Type')
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
        $records = @(& $ctx.Cmdlet -ErrorAction Stop | ForEach-Object { ConvertTo-PurviewRecord -InputObject $_ -Map $ctx.Map })
        $data = [ordered]@{}
        $data[$ctx.Key] = $records
        $data['PropertiesNotReturned'] = Get-PurviewUnmappedProperty -Record $records -Map $ctx.Map -Optional $ctx.Optional
        [pscustomobject]$data
    }
}

function Get-PurviewEndpointDlpData {
    <# .SYNOPSIS Collects endpoint DLP settings. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'EndpointDlpSettings' -SolutionArea 'EndpointDlp' `
        -Interface 'Get-PolicyConfig' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/get-policyconfig" `
        -RequiredCommand @('Get-PolicyConfig') -ConnectWith 'Connect-IPPSSession' -Collect {
        # Get-PolicyConfig returns a single configuration object rather than a collection, and a
        # tenant that has never configured endpoint DLP has nothing behind it to return.
        $config = Get-PolicyConfig -ErrorAction Stop
        if ($null -eq $config) {
            return [pscustomobject]@{ Settings = @(); Limitation = 'Endpoint DLP has not been configured in this tenant, so there are no settings to read.' }
        }

        $settings = @($config.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^(PS|RunspaceId)' } |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })

        [pscustomobject]@{ Settings = $settings }
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
        -Interface 'Get-AdminAuditLogConfig' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/get-adminauditlogconfig" `
        -RequiredCommand @('Get-AdminAuditLogConfig', 'Get-ConnectionInformation') -ConnectWith 'Connect-ExchangeOnline' -Collect {

        # The compliance session reports False regardless, so without Exchange Online this is unknown.
        $exchange = @(Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -like 'ExchangeOnline*' -and
                [string](Get-PurviewProperty -InputObject $_ -Name 'Name') -notlike 'ExchangeOnlineProtection*' })

        if ($exchange.Count -eq 0) {
            return [pscustomobject]@{ Settings = @(); PropertiesNotReturned = @('Enabled') }
        }

        $config = Get-AdminAuditLogConfig -ErrorAction Stop
        [pscustomobject]@{
            Settings = @([pscustomobject]@{
                    Name = 'UnifiedAuditLogIngestionEnabled'
                    Enabled = [bool](Get-PurviewProperty -InputObject $config -Name 'UnifiedAuditLogIngestionEnabled')
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

        # The service rejects a window that reaches the future or touches 30 days exactly. A UTC
        # value is re-read as local and converted forward, which lands in the future west of
        # Greenwich, so local time is sent and the window stops just inside both boundaries.
        $now = (Get-PurviewTimestamp).LocalDateTime
        $end = $now.AddMinutes(-1)
        $start = $now.AddDays(-[Math]::Min($ctx.Days, 29))
        $byActivity = @{}
        $byWorkload = @{}
        $total = 0
        $pages = 0
        $cookie = ''
        $truncated = $false
        $sawActivity = $false
        $sawWorkload = $false

        while ($pages -lt $ctx.PageLimit) {
            $arguments = @{
                StartTime = $start; EndTime = $end
                OutputFormat = 'Json'; PageSize = 5000; ErrorAction = 'Stop'
            }
            if ($cookie) { $arguments['PageCookie'] = $cookie }

            $page = Export-ActivityExplorerData @arguments
            $pages++

            $payload = Get-PurviewProperty -InputObject $page -Name 'ResultData'
            $rows = if ($payload -is [string] -and -not [string]::IsNullOrWhiteSpace($payload)) {
                @($payload | ConvertFrom-Json -Depth 20)
            }
            else { ConvertTo-PurviewArray -InputObject $payload }

            foreach ($row in $rows) {
                $total++
                $activity = [string](Get-PurviewProperty -InputObject $row -Name 'Activity', 'activity', 'Operation')
                $workload = [string](Get-PurviewProperty -InputObject $row -Name 'Workload', 'workload')
                if ($activity) { $sawActivity = $true; $byActivity[$activity] = 1 + $(if ($byActivity.ContainsKey($activity)) { $byActivity[$activity] } else { 0 }) }
                if ($workload) { $sawWorkload = $true; $byWorkload[$workload] = 1 + $(if ($byWorkload.ContainsKey($workload)) { $byWorkload[$workload] } else { 0 }) }
            }

            $last = Get-PurviewProperty -InputObject $page -Name 'LastPage'
            $cookie = [string](Get-PurviewProperty -InputObject $page -Name 'Watermark')
            if ($rows.Count -eq 0 -or $null -eq $last -or [bool]$last -or -not $cookie) { break }
            if ($pages -ge $ctx.PageLimit) { $truncated = $true }
        }

        $notReturned = [System.Collections.Generic.List[string]]::new()
        if ($total -gt 0 -and -not $sawActivity) { $notReturned.Add('Activity') }
        if ($total -gt 0 -and -not $sawWorkload) { $notReturned.Add('Workload') }

        $count = { param($table, $names)
            $sum = 0
            foreach ($name in $names) { if ($table.ContainsKey($name)) { $sum += $table[$name] } }
            $sum
        }

        [pscustomobject]@{
            WindowDays = $ctx.Days
            TotalEvents = $total
            Truncated = $truncated
            # Activity names are the documented Export-ActivityExplorerData filter values.
            LabelApplyEvents = (& $count $byActivity @('LabelApplied', 'SensitivityLabelApplied'))
            LabelChangeEvents = (& $count $byActivity @('LabelChanged', 'SensitivityLabelUpdated'))
            LabelRemoveEvents = (& $count $byActivity @('LabelRemoved', 'SensitivityLabelRemoved'))
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
        Counts items carrying each requested label or sensitive information type.

    .DESCRIPTION
        Reads only the aggregate TotalCount the cmdlet returns first. Records name files and
        mailboxes, so PageSize is held at one and no record is kept.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()][object[]]$Tag = @(),
        [int]$TagLimit = 25
    )

    return Invoke-PurviewCollector -Collector 'ClassificationCoverage' -SolutionArea 'ContentExplorer' `
        -Interface 'Export-ContentExplorerData' -Kind 'SecurityAndCompliancePowerShell' `
        -DocumentationUrl "$script:SccDocRoot/export-contentexplorerdata" `
        -RequiredCommand @('Export-ContentExplorerData') -ConnectWith 'Connect-IPPSSession' `
        -Context ([pscustomobject]@{ Tag = @($Tag); TagLimit = $TagLimit }) -Collect {
        param($ctx)

        $counts = [System.Collections.Generic.List[object]]::new()
        $failed = [System.Collections.Generic.List[string]]::new()

        foreach ($entry in @($ctx.Tag | Select-Object -First $ctx.TagLimit)) {
            $name = [string](Get-PurviewProperty -InputObject $entry -Name 'Name')
            $type = [string](Get-PurviewProperty -InputObject $entry -Name 'Type')
            if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($type)) { continue }

            try {
                $response = @(Export-ContentExplorerData -TagType $type -TagName $name -PageSize 1 -ErrorAction Stop)
                $summary = if ($response.Count -gt 0) { $response[0] } else { $null }
                $counts.Add([pscustomobject]@{
                        Tag = $name
                        TagType = $type
                        TotalCount = [int](Get-PurviewProperty -InputObject $summary -Name 'TotalCount')
                    })
            }
            catch {
                # One unreadable tag must not discard the tags that did resolve.
                $failed.Add($name)
            }
        }

        $labelledTotal = 0
        foreach ($entry in $counts) {
            if ([string](Get-PurviewProperty -InputObject $entry -Name 'TagType') -eq 'Sensitivity') {
                $labelledTotal += [int](Get-PurviewProperty -InputObject $entry -Name 'TotalCount')
            }
        }

        [pscustomobject]@{
            Tags = $counts.ToArray()
            TagsRequested = @($ctx.Tag).Count
            TagsUnreadable = $failed.ToArray()
            LabelledItemTotal = $labelledTotal
        }
    }
}

function Get-PurviewSharePointReadinessData {
    <# .SYNOPSIS Collects the tenant opt-ins that SharePoint and OneDrive labeling depends on. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Expected is not always $true: the mismatch email is kept by leaving its Block switch off,
    # default library labeling by leaving its Disable switch off, and one gate is not a switch at all.
    $gates = @(
        @{ Name = 'EnableAIPIntegration'; Expected = $true; Capability = 'Sensitivity labels for Office files in SharePoint and OneDrive' }
        @{ Name = 'EnableSensitivityLabelforPDF'; Expected = $true; Capability = 'Labels on PDF files' }
        @{ Name = 'EnableSensitivityLabelforOneNote'; Expected = $true; Capability = 'Labels on OneNote sections' }
        @{ Name = 'EnableSensitivityLabelForVideoFiles'; Expected = $true; Capability = 'Labels on MP4 video files' }
        @{ Name = 'BlockSendLabelMismatchEmail'; Expected = $false; Capability = 'Owner is emailed when a file is more sensitive than its site' }
        @{ Name = 'DisableDocumentLibraryDefaultLabeling'; Expected = $false; Capability = 'Default labels apply to document libraries' }
        @{ Name = 'MarkNewFilesSensitiveByDefault'; Expected = 'BlockExternalSharing'; Capability = 'New files are treated as sensitive until DLP has scanned them' }
    )

    return Invoke-PurviewCollector -Collector 'SharePointLabelingReadiness' -SolutionArea 'SensitivityLabels' `
        -Interface 'Get-SPOTenant' -Kind 'SharePointOnlinePowerShell' `
        -DocumentationUrl "$script:SpoDocRoot/get-spotenant" `
        -RequiredCommand @('Get-SPOTenant') -ConnectWith 'Connect-SPOService' -Context $gates -Collect {
        param($ctx)
        $tenant = Get-SPOTenant -ErrorAction Stop

        $settings = [System.Collections.Generic.List[object]]::new()
        $missing = [System.Collections.Generic.List[string]]::new()

        foreach ($gate in $ctx) {
            if (-not (Test-PurviewProperty -InputObject $tenant -Name $gate.Name)) {
                $missing.Add($gate.Name)
                continue
            }
            $raw = Get-PurviewProperty -InputObject $tenant -Name $gate.Name
            $isSwitch = $gate.Expected -is [bool]
            $asRecommended = if ($isSwitch) { [bool]$raw -eq [bool]$gate.Expected } else { [string]$raw -eq [string]$gate.Expected }

            $settings.Add([pscustomobject]@{
                    Name = $gate.Name
                    Enabled = if ($isSwitch) { [bool]$raw } else { $asRecommended }
                    Value = [string]$raw
                    Expected = [string]$gate.Expected
                    AsRecommended = $asRecommended
                    Capability = $gate.Capability
                })
        }

        [pscustomobject]@{ Settings = $settings.ToArray(); PropertiesNotReturned = $missing.ToArray() }
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

        foreach ($group in @(Invoke-PurviewGraphGet -Uri '/v1.0/groupSettings')) {
            if ([string](Get-PurviewProperty -InputObject $group -Name 'displayName') -ne 'Group.Unified') { continue }

            foreach ($value in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $group -Name 'values'))) {
                if ([string](Get-PurviewProperty -InputObject $value -Name 'name') -ne 'EnableMIPLabels') { continue }

                # The directory stores this as the string "true", not a boolean.
                $raw = [string](Get-PurviewProperty -InputObject $value -Name 'value')
                $settings.Add([pscustomobject]@{
                        Name = 'EnableMIPLabels'
                        Enabled = ($raw -eq 'true')
                        Expected = $true
                        AsRecommended = ($raw -eq 'true')
                        Capability = 'Sensitivity labels on Microsoft 365 groups, Teams and SharePoint sites'
                    })
            }
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
        $sites = @(Get-SPOSite -Limit $ctx.Limit -ErrorAction Stop |
            ForEach-Object { ConvertTo-PurviewRecord -InputObject $_ -Map $ctx.Map })

        [pscustomobject]@{
            Sites = $sites
            SiteLimit = $ctx.Limit
            PropertiesNotReturned = Get-PurviewUnmappedProperty -Record $sites -Map $ctx.Map -Optional $ctx.Optional
        }
    }
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
| where isnotempty(DlpInfo)
| summarize arg_max(Timestamp, *) by DeviceId
| extend d = parse_json(DlpInfo)
| summarize Devices = count(),
            DlpEnabled = countif(tobool(d.IsDlpEnabled) == true),
            ConfigurationValid = countif(tobool(d.IsDlpConfigurationValid) == true),
            RealTimeProtectionOff = countif(tobool(d.IsDefenderRealTimeProtectionEnabled) == false),
            BehaviorMonitoringOff = countif(tobool(d.IsDefenderBehaviorMonitoringEnabled) == false),
            BandwidthExceeded = countif(tobool(d.HasDlpACBandwidthExceeded) == true),
            InvalidUser = countif(tobool(d.HasDlpValidUpn) == false)
'@

        $response = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/security/runHuntingQuery' `
            -Body (@{ Query = $kql } | ConvertTo-Json -Depth 5) -ContentType 'application/json' `
            -OutputType PSObject -ErrorAction Stop

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))

        # Defender for Endpoint populates this table. Without it the query is valid and empty, which
        # means nothing is known about devices rather than that none are onboarded.
        if ($rows.Count -eq 0) {
            return [pscustomobject]@{ Devices = @(); PropertiesNotReturned = @('DeviceHealth') }
        }

        $read = { param($name) [int](Get-PurviewProperty -InputObject $rows[0] -Name $name) }
        [pscustomobject]@{
            Devices = @([pscustomobject]@{
                    Onboarded = (& $read 'Devices')
                    DlpEnabled = (& $read 'DlpEnabled')
                    ConfigurationValid = (& $read 'ConfigurationValid')
                    RealTimeProtectionOff = (& $read 'RealTimeProtectionOff')
                    BehaviorMonitoringOff = (& $read 'BehaviorMonitoringOff')
                    BandwidthExceeded = (& $read 'BandwidthExceeded')
                    InvalidUser = (& $read 'InvalidUser')
                })
        }
    }
}

function Get-PurviewInsiderRiskSharingData {
    <#
    .SYNOPSIS
        Looks for evidence that insider risk detail is being shared with Defender.

    .DESCRIPTION
        Microsoft documents that this table returns nothing unless the organisation has opted in to
        share insider risk alerts with Defender. Rows are therefore proof the opt-in is on; none is
        not proof it is off, because a tenant that opted in may simply have no behaviours.

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
        -ConnectWith 'Connect-MgGraph -Scopes ThreatHunting.Read.All' -Collect {

        $kql = 'DataSecurityBehaviors | summarize Behaviors = count()'

        $response = Invoke-MgGraphRequest -Method POST -Uri '/v1.0/security/runHuntingQuery' `
            -Body (@{ Query = $kql } | ConvertTo-Json -Depth 5) -ContentType 'application/json' `
            -OutputType PSObject -ErrorAction Stop

        $rows = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $response -Name 'results'))
        $count = if ($rows.Count -gt 0) { [int](Get-PurviewProperty -InputObject $rows[0] -Name 'Behaviors') } else { 0 }

        # An empty result is the same shape as never having opted in, so it carries no entry at all
        # rather than an entry saying zero.
        [pscustomobject]@{ Behaviors = @(if ($count -gt 0) { [pscustomobject]@{ Count = $count } }) }
    }
}

function Get-PurviewLicensingData {
    <# .SYNOPSIS Collects subscribed SKUs. Least-privilege permission: LicenseAssignment.Read.All. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return Invoke-PurviewCollector -Collector 'Licensing' -SolutionArea 'Licensing' `
        -Interface 'GET /subscribedSkus' -Kind 'MicrosoftGraph' `
        -DocumentationUrl 'https://learn.microsoft.com/graph/api/subscribedsku-list?view=graph-rest-1.0' `
        -RequiredCommand @('Invoke-MgGraphRequest') `
        -ConnectWith 'Connect-MgGraph -Scopes LicenseAssignment.Read.All' -Collect {
        $skus = @(Invoke-PurviewGraphGet -Uri '/v1.0/subscribedSkus' | ForEach-Object {
                $plans = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'servicePlans') |
                    ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'servicePlanName') })
                $units = Get-PurviewProperty -InputObject $_ -Name 'prepaidUnits'

                [pscustomobject]@{
                    skuPartNumber = [string](Get-PurviewProperty -InputObject $_ -Name 'skuPartNumber')
                    skuId = [string](Get-PurviewProperty -InputObject $_ -Name 'skuId')
                    servicePlans = $plans
                    prepaidUnitsEnabled = [int](Get-PurviewProperty -InputObject $units -Name 'enabled')
                    consumedUnits = [int](Get-PurviewProperty -InputObject $_ -Name 'consumedUnits')
                }
            })

        [pscustomobject]@{ SubscribedSkus = $skus }
    }
}

function Get-PurviewInsightTag {
    <#
    .SYNOPSIS
        Builds the tag list for content explorer from labels already collected.

    .DESCRIPTION
        Deriving names from the tenant's own labels avoids guessing at label names that vary by
        organisation. Sensitive information types have no such source, so they are named by hand.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CollectorResult,
        [AllowEmptyCollection()][string[]]$ExtraTag = @()
    )

    $tags = [System.Collections.Generic.List[object]]::new()
    $labels = @($CollectorResult | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq 'SensitivityLabel' })

    if ($labels.Count -gt 0 -and [string](Get-PurviewProperty -InputObject $labels[0] -Name 'status') -in 'Success', 'PartialSuccess') {
        $records = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $labels[0] -Name 'data') -Name 'Labels')
        foreach ($label in @($records | Where-Object { -not [bool](Get-PurviewProperty -InputObject $_ -Name 'Disabled') })) {
            $name = [string](Get-PurviewProperty -InputObject $label -Name 'Name')
            if ($name) { $tags.Add([pscustomobject]@{ Name = $name; Type = 'Sensitivity' }) }
        }
    }

    foreach ($extra in @($ExtraTag | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $tags.Add([pscustomobject]@{ Name = $extra; Type = 'SensitiveInformationType' })
    }

    return $tags.ToArray()
}

function Get-PurviewTenantIdentity {
    <# .SYNOPSIS Reads the connected tenant identity for the snapshot header. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (-not (Test-PurviewCommand -Name 'Get-MgContext')) {
        return [pscustomobject]@{ displayName = 'Unknown'; tenantId = ''; redacted = $false }
    }

    try {
        $context = Get-MgContext -ErrorAction Stop
        return [pscustomobject]@{
            displayName = [string](Get-PurviewProperty -InputObject $context -Name 'Account')
            tenantId = [string](Get-PurviewProperty -InputObject $context -Name 'TenantId')
            redacted = $false
        }
    }
    catch {
        Write-Verbose "Tenant identity unavailable: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return [pscustomobject]@{ displayName = 'Unknown'; tenantId = ''; redacted = $false }
    }
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
        @{ Name = 'EndpointDlpSettings'; Area = 'EndpointDlp'; Call = { Get-PurviewEndpointDlpData } }
        @{ Name = 'AuditIngestion'; Area = 'Audit'; Call = { Get-PurviewAuditIngestionData } }
        @{ Name = 'SharePointLabelingReadiness'; Area = 'SensitivityLabels'; Call = { Get-PurviewSharePointReadinessData } }
        @{ Name = 'ContainerLabel'; Area = 'SensitivityLabels'; Call = { Get-PurviewContainerLabelData } }
        @{ Name = 'EndpointDeviceHealth'; Area = 'EndpointDlp'; Call = { Get-PurviewEndpointDeviceHealthData } }
        @{ Name = 'InsiderRiskSharing'; Area = 'InsiderRisk'; Call = { Get-PurviewInsiderRiskSharingData } }
        @{ Name = 'Licensing'; Area = 'Licensing'; Call = { Get-PurviewLicensingData } }
    ) | Where-Object { & $inScope $_.Area }
    $extras = @($extras)

    $wantActivity = $IncludeInsights -and (& $inScope 'ActivityExplorer')
    $wantCoverage = $IncludeInsights -and (& $inScope 'ContentExplorer')
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
        $tags = @(Get-PurviewInsightTag -CollectorResult $results.ToArray() -ExtraTag $InsightTag)
        $results.Add((& $run 'ClassificationCoverage' { param($t) Get-PurviewClassificationCoverageData -Tag $t } $tags))
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

    $licensing = @($CollectorResult | Where-Object { $_.collector -eq 'Licensing' })

    # Unknown licensing keeps rules out of Fail rather than guessing an entitlement.
    if ($licensing.Count -eq 0 -or $licensing[0].status -notin 'Success', 'PartialSuccess') {
        return [pscustomobject]@{ collected = $false; subscribedSkus = @() }
    }

    return [pscustomobject]@{
        collected = $true
        subscribedSkus = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $licensing[0].data -Name 'SubscribedSkus'))
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

    $field = Get-PurviewProperty -InputObject $Predicate -Name 'field'
    $operator = Get-PurviewProperty -InputObject $Predicate -Name 'operator'
    $expected = Get-PurviewProperty -InputObject $Predicate -Name 'value'

    $present = Test-PurviewProperty -InputObject $InputObject -Name $field
    $actual = Get-PurviewProperty -InputObject $InputObject -Name $field

    switch ($operator) {
        'exists' { return $present }
        'isNullOrEmpty' { return (-not $present) -or $null -eq $actual -or ('' -eq [string]$actual) }
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
        'startsWith' { return ([string]$actual).StartsWith([string]$expected, [StringComparison]::OrdinalIgnoreCase) }
        default { throw "Unsupported predicate operator '$operator'." }
    }
}

function Format-PurviewPredicate {
    <# .SYNOPSIS Describes a predicate in words, so a finding can be checked against the facts. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][object]$Predicate)

    if ($null -eq $Predicate) { return 'the condition' }

    $field = [string](Get-PurviewProperty -InputObject $Predicate -Name 'field')
    $operator = [string](Get-PurviewProperty -InputObject $Predicate -Name 'operator')
    $value = Get-PurviewProperty -InputObject $Predicate -Name 'value'

    $words = @{
        eq = 'is'; ne = 'is not'; gt = 'is greater than'; lt = 'is less than'
        ge = 'is at least'; le = 'is at most'; contains = 'contains'; startsWith = 'starts with'
        exists = 'is present'; isNullOrEmpty = 'is empty'
    }
    $phrase = if ($words.ContainsKey($operator)) { $words[$operator] } else { $operator }

    if ($operator -in 'exists', 'isNullOrEmpty') { return "$field $phrase" }
    return "$field $phrase $value"
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

    foreach ($source in @($where, $assert, (Get-PurviewProperty -InputObject $assert -Name 'where'))) {
        $field = [string](Get-PurviewProperty -InputObject $source -Name 'field')
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
        [Parameter(Mandatory)][int]$Count,
        [Parameter(Mandatory)][string]$Singular,
        [string]$Plural = ''
    )

    if ($Count -eq 1) { return "$Count $Singular" }
    if ($Plural) { return "$Count $Plural" }
    return "$Count ${Singular}s"
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
            # Uniqueness can be scoped to a parent: the documented default taxonomy repeats a
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
        Works out which suite tiers a tenant holds, from SKU names that vary widely.

    .DESCRIPTION
        skuPartNumber is not a stable identifier for a tier. The same E5 entitlement appears as
        SPE_E5, ENTERPRISEPREMIUM, Microsoft_365_E5_(no_Teams) and others depending on how it was
        bought, so an exact match reports a fully licensed tenant as unlicensed. Service plan names
        are checked too, because a suite that does not name its tier still carries the plans.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Sku)

    $tiers = [System.Collections.Generic.List[string]]::new()

    foreach ($item in $Sku) {
        $name = ([string](Get-PurviewProperty -InputObject $item -Name 'skuPartNumber')).ToUpperInvariant()
        # The collector flattens service plans to names, but a snapshot from Graph keeps objects.
        $plans = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $item -Name 'servicePlans') |
            ForEach-Object {
                $plan = if ($_ -is [string]) { $_ } else { Get-PurviewProperty -InputObject $_ -Name 'servicePlanName' }
                ([string]$plan).ToUpperInvariant()
            })
        $text = (@($name) + $plans) -join ' '

        if ($name -match '(^|[^A-Z])E5([^A-Z]|$)' -or $name -match 'ENTERPRISEPREMIUM' -or $name -match 'SPE_E5' -or
            $name -match 'INFORMATION_PROTECTION_COMPLIANCE' -or $text -match 'MIP_S_CLP2|RMS_S_PREMIUM2|PREMIUM_ENCRYPTION') {
            $tiers.Add('SPE_E5')
        }
        if ($name -match '(^|[^A-Z])E3([^A-Z]|$)' -or $name -match 'ENTERPRISEPACK' -or $name -match 'SPE_E3' -or
            $text -match 'MIP_S_CLP1|RMS_S_ENTERPRISE|RMS_S_PREMIUM') {
            $tiers.Add('SPE_E3')
        }
        if ($name -match 'PURVIEW') { $tiers.Add('MICROSOFT_PURVIEW_SUITE') }
        if ($name -match 'COPILOT') { $tiers.Add('Microsoft_365_Copilot') }

        # The exact name is always accepted, so a rule can still name a specific SKU.
        $tiers.Add($name)
    }

    # E5 carries everything E3 does, so a rule asking for E3 is satisfied by E5.
    if ($tiers -contains 'SPE_E5') { $tiers.Add('SPE_E3') }

    return @($tiers | Select-Object -Unique)
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
    $collected = Get-PurviewProperty -InputObject $block -Name 'collected'
    # Re-wrap at the call site: a single-element array unrolls to a scalar, which would turn the
    # concatenation below into string concatenation and silently misreport the licence as absent.
    $includedIn = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'includedIn'))
    $addOns = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Licensing -Name 'addOns'))
    $accepted = @($includedIn) + @($addOns)

    if ($null -eq $block -or -not $collected -or $accepted.Count -eq 0) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
    }

    $skus = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $block -Name 'subscribedSkus'))
    if ($skus.Count -eq 0) {
        return [pscustomobject]@{ State = 'Unknown'; Capability = $capability; UnlockedBy = $accepted }
    }

    $held = @(Get-PurviewLicenceTier -Sku $skus)

    foreach ($sku in $accepted) {
        if ($held -contains ([string]$sku).ToUpperInvariant() -or $held -contains [string]$sku) {
            return [pscustomobject]@{ State = 'Licensed'; Capability = $capability; UnlockedBy = @() }
        }
    }

    return [pscustomobject]@{ State = 'NotLicensed'; Capability = $capability; UnlockedBy = $accepted }
}

function Get-PurviewFastTrackWorkload {
    <# .SYNOPSIS Names the FastTrack workload a solution area belongs to, or empty if outside it. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SolutionArea)

    if ($script:FastTrackWorkload.Contains($SolutionArea)) { return [string]$script:FastTrackWorkload[$SolutionArea] }
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
        fastTrack = Get-PurviewFastTrackWorkload -SolutionArea ([string](Get-PurviewProperty -InputObject $Rule -Name 'solutionArea'))
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
    if ($licensing.State -ne 'Unknown') {
        $finding.licensing = [ordered]@{ capability = $licensing.Capability; state = $licensing.State; unlockedBy = @($licensing.UnlockedBy) }
    }

    # An unlicensed capability is not a misconfiguration, so it must never reach Fail.
    if ($licensing.State -eq 'NotLicensed') {
        $finding.status = 'NotApplicable'
        $unlock = @($licensing.UnlockedBy) -join ', '
        $finding.reason = "$($licensing.Capability) is not licensed for this tenant." + $(if ($unlock) { " It would be unlocked by: $unlock." } else { '' })
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
        $finding.reason = "$collectorName could not be read, so this is unknown rather than absent: nothing here says whether it is configured. The service replied: $why"
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
            $finding.reason = "The service did not return $($blocked -join ', '), so this rule could not be evaluated. Check it manually."
            return [pscustomobject]$finding
        }
    }

    $where = Get-PurviewProperty -InputObject $condition -Name 'where'
    if ($null -ne $where) {
        $items = @($items | Where-Object { Test-PurviewPredicate -InputObject $_ -Predicate $where })
    }

    $outcome = Test-PurviewAssertion -Items @($items) -Assertion (Get-PurviewProperty -InputObject $condition -Name 'assert')

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

    # Corroboration is derived from the snapshot, so it belongs to analysis rather than collection.
    $results = @($results) + @(Get-PurviewCorroboration -Snapshot $Snapshot)

    # Sorting by id keeps output order independent of rule declaration order.
    foreach ($definition in @($Rule | Sort-Object -Property { [string](Get-PurviewProperty -InputObject $_ -Name 'id') })) {
        $findings.Add((ConvertTo-PurviewFinding -Rule $definition -Snapshot $Snapshot -CollectorResults $results -Stamp $stamp))
    }

    return $findings.ToArray()
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
        return [pscustomobject]@{ Collected = $false; Enabled = @(); TopLevel = @(); SubLabels = @(); HierarchyKnown = $false }
    }

    $labels = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $matched[0] -Name 'data') -Name 'Labels')
    $enabled = @($labels | Where-Object { -not [bool](Get-PurviewProperty -InputObject $_ -Name 'Disabled') })

    # ParentId is enrichment and may be absent, in which case hierarchy is unknown rather than flat.
    $hierarchyKnown = @($enabled | Where-Object { Test-PurviewProperty -InputObject $_ -Name 'ParentId' }).Count -gt 0
    $sub = @($enabled | Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')) })
    $top = if ($hierarchyKnown) {
        @($enabled | Where-Object { [string]::IsNullOrWhiteSpace([string](Get-PurviewProperty -InputObject $_ -Name 'ParentId')) })
    }
    else { $enabled }

    return [pscustomobject]@{
        Collected = $true
        Enabled = @($enabled | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        TopLevel = @($top | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') })
        SubLabels = @($sub | ForEach-Object {
                [pscustomobject]@{
                    Name = [string](Get-PurviewProperty -InputObject $_ -Name 'Name')
                    # Absent is not the same as off: Get-Label does not always return the property.
                    Encrypted = if (Test-PurviewProperty -InputObject $_ -Name 'EncryptionEnabled') { [bool](Get-PurviewProperty -InputObject $_ -Name 'EncryptionEnabled') } else { $null }
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
    foreach ($sub in @($taxonomy.SubLabels | Sort-Object -Property Name)) {
        $detail = if ($null -eq $sub.Encrypted) { 'Encryption state was not returned for this label.' }
        elseif ($sub.Encrypted) { 'Applies encryption, so the protection stays with the file wherever it is copied or sent.' }
        else { 'Applies markings only. Content keeps the label but is not encrypted.' }
        $output.Add([pscustomobject]@{ Tier = $sub.Name; Match = 'Sublabel'; Detail = $detail })
    }

    return $output.ToArray()
}

function Get-PurviewCorroboration {
    <#
    .SYNOPSIS
        Cross-checks configuration against observed activity, as a virtual collector result.

    .DESCRIPTION
        Configuration says what should happen and activity says what did. Comparing them catches
        the policy that exists but never fires. Reports NotCollected unless activity was collected,
        so an absent comparison never reads as a passing one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowNull()][object]$Snapshot)

    $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')

    $find = {
        param($name)
        $hit = @($results | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'collector') -eq $name })
        if ($hit.Count -gt 0 -and [string](Get-PurviewProperty -InputObject $hit[0] -Name 'status') -in 'Success', 'PartialSuccess') { $hit[0] } else { $null }
    }

    $result = [ordered]@{
        collector = 'PostureValidation'
        solutionArea = 'PostureValidation'
        status = 'NotCollected'
        source = [pscustomobject]@{ interface = 'Derived from the snapshot'; kind = 'SecurityAndCompliancePowerShell' }
        collectedAt = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)
        data = [pscustomobject]@{}
        errors = @()
        limitations = @('Activity was not collected, so configuration could not be corroborated.')
    }

    $activity = & $find 'ProtectionActivity'
    if ($null -eq $activity) { return [pscustomobject]$result }

    $activityData = Get-PurviewProperty -InputObject $activity -Name 'data'
    $window = [int](Get-PurviewProperty -InputObject $activityData -Name 'WindowDays')
    $labelApplies = [int](Get-PurviewProperty -InputObject $activityData -Name 'LabelApplyEvents')

    $taxonomy = Get-PurviewLabelTaxonomy -Snapshot $Snapshot
    $labelsPublished = @($taxonomy.Enabled).Count

    $result.status = 'Success'
    $result.limitations = @()
    $result.data = [pscustomobject]@{
        WindowDays = $window
        LabelsPublished = $labelsPublished
        LabelApplyEvents = $labelApplies
        LabelsPublishedButUnused = ($labelsPublished -gt 0 -and $labelApplies -eq 0)
        CopilotEvents = [int](Get-PurviewProperty -InputObject $activityData -Name 'CopilotEvents')
        DlpRuleMatchEvents = [int](Get-PurviewProperty -InputObject $activityData -Name 'DlpRuleMatchEvents')
    }

    return [pscustomobject]$result
}

#endregion

#region Posture history
# A posture record is rule outcomes, not tenant content: no policy names, no reasons, no counts of
# anything a customer owns. That makes it far less sensitive than a snapshot and safe to retain for
# as long as the trend is useful.

$script:PostureRank = @{ Fail = 0; Warning = 1; Pass = 2 }
$script:PostureUndetermined = @('NeedsReview', 'NotCollected', 'Unsupported')

function ConvertTo-PurviewPostureRecord {
    <# .SYNOPSIS Reduces a run to the outcomes needed to compare it with another run. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Snapshot,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding
    )

    $zone = Get-PurviewTimeZoneContext
    $summary = [ordered]@{}
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotApplicable', 'NotCollected', 'Unsupported') {
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

    $mode = [string](Get-PurviewProperty -InputObject $Current -Name 'mode')
    $tenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Current -Name 'tenant') -Name 'tenantId')

    for ($index = $History.Count - 1; $index -ge 0; $index--) {
        $candidate = $History[$index]
        if ([string](Get-PurviewProperty -InputObject $candidate -Name 'mode') -ne $mode) { continue }

        $candidateTenant = [string](Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $candidate -Name 'tenant') -Name 'tenantId')
        if ($tenant -and $candidateTenant -and $tenant -ne $candidateTenant) { continue }

        return $candidate
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

        if ($baseMode -ne $thisMode) {
            $comparable = $false
            $blocker = "The baseline was captured in $baseMode mode and this run is $thisMode, so the two describe different things."
        }
        elseif ($differentTenant -and -not $AcrossTenants) {
            $comparable = $false
            $blocker = 'The baseline belongs to a different tenant, so comparing them would be meaningless.'
        }
        elseif ($differentTenant) {
            $crossTenant = $true
        }
    }

    $changes = [System.Collections.Generic.List[object]]::new()

    if ($comparable) {
        $before = @{}
        foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Baseline -Name 'findings'))) {
            $before[[string](Get-PurviewProperty -InputObject $item -Name 'ruleId')] = $item
        }

        foreach ($item in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Current -Name 'findings'))) {
            $id = [string](Get-PurviewProperty -InputObject $item -Name 'ruleId')
            $now = [string](Get-PurviewProperty -InputObject $item -Name 'status')
            $title = [string](Get-PurviewProperty -InputObject $item -Name 'title')

            if (-not $before.ContainsKey($id)) {
                $changes.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = ''; To = $now; Change = 'New'; Detail = 'This rule did not exist when the baseline was taken.' })
                continue
            }

            $previous = $before[$id]
            $was = [string](Get-PurviewProperty -InputObject $previous -Name 'status')
            $before.Remove($id)

            $wasVersion = [string](Get-PurviewProperty -InputObject $previous -Name 'ruleVersion')
            $nowVersion = [string](Get-PurviewProperty -InputObject $item -Name 'ruleVersion')
            if ($wasVersion -ne $nowVersion) {
                $changes.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = $was; To = $now; Change = 'RuleChanged'; Detail = "The rule moved from version $wasVersion to $nowVersion, so a difference in outcome may be the rule rather than the tenant." })
                continue
            }

            $change = 'Unchanged'
            $detail = ''

            if ($was -eq $now) { $detail = '' }
            elseif ($was -in $script:PostureUndetermined -and $now -in $script:PostureUndetermined) {
                $detail = 'Still undetermined.'
            }
            elseif ($now -in $script:PostureUndetermined) {
                $change = 'VisibilityLost'
                $detail = 'This was assessed before and is not now, which is a loss of visibility rather than a change in the tenant.'
            }
            elseif ($was -in $script:PostureUndetermined) {
                $change = 'VisibilityGained'
                $detail = 'This could not be assessed before, so the outcome is new information rather than movement.'
            }
            elseif ($was -eq 'NotApplicable' -or $now -eq 'NotApplicable') {
                $change = 'ScopeChanged'
                $detail = 'Applicability changed, usually because licensing did. That is not progress on the control itself.'
            }
            elseif ($script:PostureRank[$now] -gt $script:PostureRank[$was]) {
                $change = 'Improved'
            }
            else {
                $change = 'Regressed'
            }

            $changes.Add([pscustomobject]@{ RuleId = $id; Title = $title; From = $was; To = $now; Change = $change; Detail = $detail })
        }

        foreach ($id in @($before.Keys | Sort-Object)) {
            $previous = $before[$id]
            $changes.Add([pscustomobject]@{
                    RuleId = $id
                    Title = [string](Get-PurviewProperty -InputObject $previous -Name 'title')
                    From = [string](Get-PurviewProperty -InputObject $previous -Name 'status')
                    To = ''
                    Change = 'Removed'
                    Detail = 'This rule is no longer evaluated by the script.'
                })
        }
    }

    $count = { param($name) @($changes | Where-Object { $_.Change -eq $name }).Count }

    return [pscustomobject]@{
        Comparable = $comparable
        Blocker = $blocker
        CrossTenant = $crossTenant
        BaselineRecordedAt = if ($null -eq $Baseline) { '' } else { [string](Get-PurviewProperty -InputObject $Baseline -Name 'recordedAt') }
        CurrentRecordedAt = [string](Get-PurviewProperty -InputObject $Current -Name 'recordedAt')
        Improved = (& $count 'Improved')
        Regressed = (& $count 'Regressed')
        Unchanged = (& $count 'Unchanged')
        VisibilityLost = (& $count 'VisibilityLost')
        VisibilityGained = (& $count 'VisibilityGained')
        ScopeChanged = (& $count 'ScopeChanged')
        RuleChanged = (& $count 'RuleChanged')
        New = (& $count 'New')
        Removed = (& $count 'Removed')
        Changes = $changes.ToArray()
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

        $now = Get-PurviewProperty -InputObject $item -Name 'passingSteps'
        $was = Get-PurviewProperty -InputObject $before[$model] -Name 'passingSteps'
        $nowChecked = [int](Get-PurviewProperty -InputObject $item -Name 'checkedSteps')
        $wasChecked = [int](Get-PurviewProperty -InputObject $before[$model] -Name 'checkedSteps')

        # Steps passing means nothing across a different number of checked steps.
        $detail = if ($null -eq $now -or $null -eq $was) { 'Not measured in both runs.' }
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
    # no rule maps to yet carry counts only, so a rule tagged against them still finds a home.
    $models = [ordered]@{
        'secure-by-default' = @{
            Name = 'Secure by default with Microsoft Purview'; Steps = 4
            Titles = @(
                'Start with default labeling'
                'Address files with the highest sensitivity'
                'Expand protection to your entire Microsoft 365 data estate'
                'Operate, expand, and retroactive actions'
            )
        }
        'shadow-ai' = @{ Name = 'Prevent data leak to shadow AI'; Steps = 4; Titles = @() }
        'copilot-agents' = @{ Name = 'Secure and govern Microsoft 365 Copilot agents'; Steps = 4; Titles = @() }
        'dspm' = @{
            Name = 'Deploy and use Data Security Posture Management'; Steps = 4
            Titles = @(
                'Establish foundational elements'
                'Configure access and analytics'
                'Understand data landscape and risks'
                'Take action and investigate with Security Copilot'
            )
        }
        'lightweight-dlp' = @{
            Name = 'Lightweight guide to mitigate data leakage'; Steps = 3
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
            $contributing = @($Finding | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'deploymentModel') -eq $tag })

            # NotApplicable means the capability is not licensed, which is not the step being done.
            $passed = @($contributing | Where-Object { $_.status -eq 'Pass' }).Count
            $assessed = @($contributing | Where-Object { $_.status -in 'Pass', 'Fail', 'Warning' }).Count

            $state = if ($contributing.Count -eq 0) { 'NoChecks' }
            elseif ($assessed -eq 0) { 'NotAssessed' }
            elseif ($passed -eq $assessed) { 'ChecksPass' }
            elseif ($passed -gt 0) { 'Partial' }
            else { 'ChecksFail' }

            $plural = if ($assessed -eq 1) { 'check' } else { 'checks' }
            $verdict = switch ($state) {
                'NoChecks' { 'No check covers this step' }
                'NotAssessed' { 'Not assessed, the data was not collected' }
                'ChecksPass' { "$assessed $plural passed" }
                'Partial' { "$passed of $assessed checks passed" }
                default { "$assessed $plural failed" }
            }

            if ($state -in 'ChecksPass', 'Partial', 'ChecksFail') {
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
        $hasCommand = [bool]$item.PSObject.Properties['remediationCommand']

        $group, $marker, $action = switch ($status) {
            'Pass' { 'Done', 'x', 'Nothing to do.'; break }
            'Fail' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'Warning' { 'To do', ' ', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'NeedsReview' { 'To check by hand', '?', [string](Get-PurviewProperty -InputObject $item -Name 'recommendation'); break }
            'NotApplicable' { 'Not applicable', '-', [string](Get-PurviewProperty -InputObject $item -Name 'reason'); break }
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
                FastTrack = [string](Get-PurviewProperty -InputObject $item -Name 'fastTrack')
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
        NotApplicable = @($Checklist | Where-Object { $_.Group -eq 'Not applicable' }).Count
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
            'ClassificationCoverage' { return 'Labelled-content counts were not read this run. Drop -SkipInsights to include them.' }
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

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $known) {
        $raw = Get-PurviewProperty -InputObject $item -Name 'Workload'
        # The service returns this as a comma-separated string in some shapes and a list in others.
        $names = if ($raw -is [string]) { $raw -split ',' } else { @(ConvertTo-PurviewArray -InputObject $raw) }
        foreach ($name in $names) {
            $trimmed = ([string]$name).Trim()
            if ($trimmed) { $null = $seen.Add($trimmed) }
        }
    }

    $covered = @($seen | Sort-Object)
    return [pscustomobject]@{
        Known = $true
        Covered = $covered
        Detail = if ($covered.Count -gt 0) { 'Covers ' + ($covered -join ', ') } else { 'No workload was named on any of them' }
    }
}

function Get-PurviewInventory {
    <#
    .SYNOPSIS
        Counts what the tenant actually has, with no judgement attached.

    .DESCRIPTION
        Findings say what is wrong; this says what is there, which is what a reader needs first.
        A collector that did not run reports as not checked rather than as zero, because those
        two mean opposite things: one is that we could not look, the other that there is nothing
        there.
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
                Value = if ($ran) { [string]$value } else { 'not checked' }
                Detail = if ($ran) { [string]$detail } else { Get-PurviewCollectorReason -Snapshot $Snapshot -Collector $collector }
            })
    }

    $labels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
    & $add 'Sensitivity labels' 'Labels defined' 'SensitivityLabel' $labels.Count 'Exist in the tenant, whether or not anyone can use them'

    $labelPolicies = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabelPolicy' -Select 'Policies')
    $publishedPolicies = @($labelPolicies | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'Enabled') })
    $policyDetail = if ($labelPolicies.Count -eq $publishedPolicies.Count) { 'All of them are enabled' }
    else { "$($labelPolicies.Count - $publishedPolicies.Count) more defined but not enabled" }
    & $add 'Sensitivity labels' 'Label publishing policies enabled' 'SensitivityLabelPolicy' $publishedPolicies.Count $policyDetail

    # A label reaches users only through a publishing policy that includes it, and the same label
    # often sits in several, so this is the distinct union rather than a sum across policies.
    $published = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $labelsKnown = $false

    foreach ($policy in $publishedPolicies) {
        if (-not (Test-PurviewProperty -InputObject $policy -Name 'Labels')) { continue }
        $labelsKnown = $true
        foreach ($name in @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $policy -Name 'Labels'))) {
            $null = $published.Add([string]$name)
        }
    }

    if ($labelsKnown) {
        $reach = @($labels | Where-Object {
                $published.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'Name')) -or
                $published.Contains([string](Get-PurviewProperty -InputObject $_ -Name 'Guid'))
            })
        $reachDetail = if ($reach.Count -lt $labels.Count) { "Of $($labels.Count) defined; $($labels.Count - $reach.Count) in no publishing policy, so nobody can apply them" }
        else { "All $($labels.Count) defined labels are published" }
        & $add 'Sensitivity labels' 'Labels published to users' 'SensitivityLabelPolicy' $reach.Count $reachDetail
    }

    # Reach is reported as the scope the policies declare. Turning that into a share of users would
    # mean expanding every group, which needs directory permissions this assessment does not take.
    $scoped = @($publishedPolicies | Where-Object { (Test-PurviewProperty -InputObject $_ -Name 'UserScope') -or (Test-PurviewProperty -InputObject $_ -Name 'GroupScope') })
    if ($publishedPolicies.Count -gt 0 -and $scoped.Count -gt 0) {
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

    $auto = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AutoLabeling' -Select 'Policies')
    $autoOn = @($auto | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -eq 'Enable' })
    $autoSimulating = @($auto | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -like 'Test*' })
    $otherAuto = $auto.Count - $autoOn.Count - $autoSimulating.Count
    $autoDetail = "Of $($auto.Count) defined: $($autoSimulating.Count) still simulating, which label nothing until they are turned on"
    if ($otherAuto -gt 0) { $autoDetail += ", $otherAuto in another mode" }
    & $add 'Auto-labeling' 'Auto-labeling policies turned on' 'AutoLabeling' $autoOn.Count $autoDetail

    # A count of policies says nothing about what they protect, which is the question asked of them.
    if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'AutoLabelingRule') {
        $autoRules = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AutoLabelingRule' -Select 'Rules')
        $types = [System.Collections.Generic.List[string]]::new()
        $silent = 0
        foreach ($rule in $autoRules) {
            $named = @(Get-PurviewSensitiveTypeName -Condition (Get-PurviewProperty -InputObject $rule -Name 'SensitiveTypes'))
            if ($named.Count -eq 0) { $silent++ }
            foreach ($n in $named) { if (-not $types.Contains($n)) { $types.Add($n) } }
        }

        $detail = if ($types.Count -gt 0) {
            $sorted = @($types | Sort-Object)
            $shown = if ($sorted.Count -le 10) { $sorted -join ', ' }
            else { (@($sorted | Select-Object -First 10) -join ', ') + ", and $($sorted.Count - 10) more" }
            $text = "Across $(Format-PurviewCount -Count $autoRules.Count -Singular 'rule'): $shown"
            if ($silent -gt 0) { $text += ". $silent returned no condition, so what they match on is unread" }
            $text
        }
        elseif ($autoRules.Count -gt 0) { "$(Format-PurviewCount -Count $autoRules.Count -Singular 'rule') returned no sensitive information type, so what they match on could not be read" }
        else { 'No auto-labeling rule is defined, so no policy matches on a sensitive information type' }

        & $add 'Auto-labeling' 'Sensitive information these policies look for' 'AutoLabelingRule' $types.Count $detail
    }
    else {
        & $add 'Auto-labeling' 'Sensitive information these policies look for' 'AutoLabelingRule' 'Not checked' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'AutoLabelingRule')
    }

    # Every mode has to be accounted for. Reporting only enforcing and test leaves the remainder to
    # be inferred, and a disabled policy then reads as missing from one section and absent from another.
    $dlp = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataLossPrevention' -Select 'Policies')
    $enforcing = @($dlp | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -eq 'Enable' })
    $testing = @($dlp | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -like 'Test*' })
    $disabledDlp = @($dlp | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Mode') -eq 'Disable' })
    $otherDlp = $dlp.Count - $enforcing.Count - $testing.Count - $disabledDlp.Count

    $dlpDetail = "Of $($dlp.Count) defined: $($testing.Count) in test mode, $($disabledDlp.Count) disabled"
    if ($otherDlp -gt 0) { $dlpDetail += ", $otherDlp in another mode" }
    & $add 'Data loss prevention' 'DLP policies enforcing' 'DataLossPrevention' $enforcing.Count $dlpDetail

    # Coverage is per workload, not per policy: ten policies over one workload leave the rest open.
    $dlpWorkloads = Get-PurviewWorkloadCoverage -Policy $enforcing
    if ($dlpWorkloads.Known) {
        & $add 'Data loss prevention' 'Workloads an enforcing policy covers' 'DataLossPrevention' $dlpWorkloads.Covered.Count ($dlpWorkloads.Detail)
    }

    $dlpRules = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DlpRule' -Select 'Rules')
    $liveRules = @($dlpRules | Where-Object { -not [bool](Get-PurviewProperty -InputObject $_ -Name 'Disabled') })
    & $add 'Data loss prevention' 'DLP rules active' 'DlpRule' $liveRules.Count "Of $($dlpRules.Count) defined; $($dlpRules.Count - $liveRules.Count) disabled. Rules carry the conditions, policies only group them"

    $retention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'RetentionPolicy' -Select 'Policies')
    $liveRetention = @($retention | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'Enabled') })
    & $add 'Data lifecycle' 'Retention policies enabled' 'RetentionPolicy' $liveRetention.Count "Of $($retention.Count) defined; $($retention.Count - $liveRetention.Count) not enabled"

    $retentionWorkloads = Get-PurviewWorkloadCoverage -Policy $liveRetention
    if ($retentionWorkloads.Known) {
        & $add 'Data lifecycle' 'Workloads an enabled policy covers' 'RetentionPolicy' $retentionWorkloads.Covered.Count ($retentionWorkloads.Detail)
    }

    $retentionLabels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'RetentionLabel' -Select 'Labels')
    $records = @($retentionLabels | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'IsRecordLabel') })
    & $add 'Records management' 'Retention labels' 'RetentionLabel' $retentionLabels.Count "$($records.Count) declare content as a record"

    $audit = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditIngestion' -Select 'Settings')
    $auditOn = @($audit | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'Enabled') }).Count -gt 0
    & $add 'Audit' 'Unified audit logging' 'AuditIngestion' $(if ($auditOn) { 'on' } else { 'off' }) 'The record every other solution reads from'

    $auditRetention = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'AuditConfiguration' -Select 'RetentionPolicies')
    & $add 'Audit' 'Custom audit log retention policies' 'AuditConfiguration' $auditRetention.Count 'Beyond the Audit (Premium) default of one year for Exchange, SharePoint, OneDrive and Entra, and 180 days for everything else'

    $comm = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'CommunicationCompliance' -Select 'Policies')
    & $add 'Communication compliance' 'Policies' 'CommunicationCompliance' $comm.Count 'Regulatory and conduct monitoring'

    $classifiers = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'Classification' -Select 'SensitiveInformationTypes')
    $custom = @($classifiers | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Publisher') -ne 'Microsoft Corporation' })
    & $add 'Classification' 'Custom sensitive information types' 'Classification' $custom.Count 'Built-in Microsoft types excluded'

    $tags = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'ClassificationCoverage' -Select 'Tags')
    # Measure-Object over an empty set yields nothing, and reading .Sum off that throws under StrictMode.
    $labelled = 0
    foreach ($tag in $tags) {
        if ([string](Get-PurviewProperty -InputObject $tag -Name 'TagType') -eq 'Sensitivity') {
            $labelled += [int](Get-PurviewProperty -InputObject $tag -Name 'TotalCount')
        }
    }

    # A count is only a total if every label was readable. Where some were not, saying so is the
    # difference between "nothing is labelled" and "we could not see most of it".
    $requested = [int](Get-PurviewCollectorValue -Snapshot $Snapshot -Collector 'ClassificationCoverage' -Select 'TagsRequested')
    $unreadable = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'ClassificationCoverage' -Select 'TagsUnreadable')

    $detail = if ($requested -gt 0 -and $tags.Count -lt $requested) {
        $named = if ($unreadable.Count -gt 0) { " ($(@($unreadable | Select-Object -First 3) -join ', '))" } else { '' }
        "Content explorer would not return counts for $($requested - $tags.Count) of the $requested labels$named, so content carrying those is missing here and the real figure is higher."
    }
    elseif ($requested -gt 0) { 'Across every label defined in the tenant' }
    else { 'Across the labels content explorer returned' }

    & $add 'Labelled content' 'Items carrying a sensitivity label' 'ClassificationCoverage' $labelled $detail

    $activity = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'ProtectionActivity' -Select 'ByActivity')
    $applies = 0
    $window = 0
    if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'ProtectionActivity') {
        $results = ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'collectorResults')
        $data = Get-PurviewProperty -InputObject @($results | Where-Object { $_.collector -eq 'ProtectionActivity' })[0] -Name 'data'
        $applies = [int](Get-PurviewProperty -InputObject $data -Name 'LabelApplyEvents')
        $window = [int](Get-PurviewProperty -InputObject $data -Name 'WindowDays')
    }
    & $add 'Labelling activity' 'Labels applied' 'ProtectionActivity' $applies "Observed over the last $(Format-PurviewCount -Count $window -Singular 'day')"
    $null = $activity

    $skus = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject (Get-PurviewProperty -InputObject $Snapshot -Name 'licensing') -Name 'subscribedSkus'))
    $suites = @($skus | Where-Object { Test-PurviewSuiteSku -Sku $_ })
    $suiteNames = @($suites | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'skuPartNumber') } | Select-Object -First 4) -join ', '
    & $add 'Licensing' 'Subscriptions that affect Purview' 'Licensing' $suites.Count $suiteNames

    return $output.ToArray()
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
                $asRecommended = [bool](Get-PurviewProperty -InputObject $match[0] -Name 'AsRecommended')
                $state = if ($asRecommended) { 'As recommended' } else { 'Needs attention' }
                $detail = '{0} is currently set to {1}. The expected value is {2}.' -f $item.Setting,
                    (Get-PurviewProperty -InputObject $match[0] -Name 'Value'),
                    (Get-PurviewProperty -InputObject $match[0] -Name 'Expected')
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
            # Reads the same figures as the device onboarding page. Where Defender for Endpoint is
            # not deployed the table is empty, which is unknown rather than no devices.
            $devices = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'EndpointDeviceHealth' -Select 'Devices')
            if ($devices.Count -gt 0) {
                $read = { param($name) [int](Get-PurviewProperty -InputObject $devices[0] -Name $name) }
                $onboarded = & $read 'Onboarded'
                $unfit = ($onboarded - (& $read 'ConfigurationValid')) + (& $read 'RealTimeProtectionOff')
                $state = if ($unfit -gt 0) { 'Needs attention' } else { 'As recommended' }
                $detail = '{0} onboarded, {1} with endpoint DLP enabled, {2} holding a valid configuration. {3} report Defender real-time protection off.' -f
                    $onboarded, (& $read 'DlpEnabled'), (& $read 'ConfigurationValid'), (& $read 'RealTimeProtectionOff')
            }
        }
        elseif ($item.ContainsKey('Evidence')) {
            # Positive only. Finding the artefact proves the setting is on; not finding it proves
            # nothing, so the state falls back to confirming in the portal rather than reporting off.
            $e = $item.Evidence
            if (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector $e.Collector) {
                $candidates = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector $e.Collector -Select $e.Select)
                $hits = @(if ($e.ContainsKey('Field')) {
                        @($candidates | Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name $e.Field) -match $e.Match })
                    }
                    else { $candidates })

                if ($hits.Count -gt 0) {
                    $state = 'In use'
                    $detail = $e.Found
                }
                else { $detail = $e.NotFound }
            }
        }
        elseif ($item.ContainsKey('RuleId')) {
            $rule = @($Finding | Where-Object { $_.ruleId -eq $item.RuleId })
            if ($rule.Count -eq 0) {
                $state = 'Not read'
                $detail = 'The check for this did not run.'
            }
            else {
                $state = switch ([string]$rule[0].status) {
                    'Pass' { 'As recommended' }
                    'Fail' { 'Needs attention' }
                    'Warning' { 'Needs attention' }
                    default { 'Not read' }
                }
                $detail = [string]$rule[0].reason
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
                Candidates = @(
                    if ($item.ContainsKey('Choose') -and (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector $item.Choose.Collector)) {
                        @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector $item.Choose.Collector -Select $item.Choose.Select |
                                Where-Object { [string](Get-PurviewProperty -InputObject $_ -Name $item.Choose.Unless) -ne $item.Choose.Is } |
                                ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name $item.Choose.Field) } |
                                Where-Object { $_ })
                    })
            })
    }

    # What needs doing comes first, then what a person has to confirm, then what is already right.
    $rank = @{ 'Needs attention' = 0; 'Confirm in portal' = 1; 'In use' = 2; 'As recommended' = 3 }
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

    foreach ($result in $results) {
        $name = [string](Get-PurviewProperty -InputObject $result -Name 'collector')
        $ruleIds = @($script:Rules | Where-Object { $_.condition.collector -eq $name } | ForEach-Object { $_.id })
        $related = @($Finding | Where-Object { $_.ruleId -in $ruleIds })

        # These carry no rule of their own; they are what the corroboration checks compare against.
        $feedsValidation = $name -in 'ProtectionActivity', 'ClassificationCoverage'

        # A verdict word cannot separate one failure from four, so the outcomes are counted out.
        # The total is not repeated here; the Rules column beside it already carries that.
        $tally = [System.Collections.Generic.List[string]]::new()
        foreach ($bucket in @(
                @{ Label = 'passed'; Match = { $_.status -eq 'Pass' } }
                @{ Label = 'need attention'; One = 'needs attention'; Match = { $_.status -eq 'Fail' } }
                @{ Label = 'to review'; Match = { $_.status -in 'Warning', 'NeedsReview' } }
                @{ Label = 'not licensed'; Match = { $_.status -eq 'NotApplicable' } }
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
                    'Unsupported' { 'No documented interface' }
                    default { 'Not read' }
                }
                Rules = $ruleIds.Count
                Assessment = if ($feedsValidation) { 'Compared against configuration by the corroboration checks' }
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

    $name = ([string](Get-PurviewProperty -InputObject $Sku -Name 'skuPartNumber')).ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }

    # Enterprise, frontline, academic and government tiers all carry a letter and a number, so the
    # shape is matched rather than a list of names that would go stale.
    if ($name -match '(^|[^A-Z])(SPE|SPB|ENTERPRISE|M365|MICROSOFT_365|OFFICE_365)') { return $true }
    if ($name -match '(^|[^A-Z])[EAFG]\d([^A-Z]|$)') { return $true }

    # Add-ons that unlock Purview capability on their own.
    return $name -match 'PURVIEW|COMPLIANCE|INFORMATION_PROTECTION|COPILOT|ADV_COMM|IDENTITY_THREAT'
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
    $collected = [bool](Get-PurviewProperty -InputObject $block -Name 'collected')
    $output = [System.Collections.Generic.List[object]]::new()

    if (-not $collected) {
        $output.Add([pscustomobject]@{
                Sku = 'Not collected'
                State = 'Unknown'
                Detail = 'Subscribed SKUs were not collected, so licensing could not be assessed. Connect Microsoft Graph with LicenseAssignment.Read.All.'
            })
        return $output.ToArray()
    }

    $skus = @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $block -Name 'subscribedSkus'))

    # Name the tier held, not the set a rule would accept. E5 satisfies anything asking for E3,
    # but printing both reads as two subscriptions the customer does not have.
    $held = @(Get-PurviewLicenceTier -Sku $skus)
    $tier = if ($held -contains 'SPE_E5') { 'Microsoft 365 E5' }
    elseif ($held -contains 'SPE_E3') { 'Microsoft 365 E3' }
    else { '' }

    $addOns = [System.Collections.Generic.List[string]]::new()
    if ($held -contains 'MICROSOFT_PURVIEW_SUITE') { $addOns.Add('the Microsoft Purview add-on') }
    if ($held -contains 'Microsoft_365_Copilot') { $addOns.Add('Microsoft 365 Copilot') }

    $detail = if ($tier) {
        $line = "Read as $tier from $(Format-PurviewCount -Count $skus.Count -Singular 'subscribed SKU')."
        if ($addOns.Count -gt 0) { $line += " Also holding $($addOns -join ' and ')." }
        if ($tier -eq 'Microsoft 365 E5') { $line += ' E5 covers everything a check asks of E3.' }
        $line
    }
    else { "No suite tier was recognised in $(Format-PurviewCount -Count $skus.Count -Singular 'subscribed SKU'), so checks were evaluated rather than skipped." }

    $output.Add([pscustomobject]@{
            Sku = 'Entitlement recognised'
            State = if ($tier) { 'Recognised' } else { 'Unknown' }
            Detail = $detail
        })

    $relevant = @($skus | Where-Object { Test-PurviewSuiteSku -Sku $_ })
    foreach ($sku in $relevant) {
        $enabled = [int](Get-PurviewProperty -InputObject $sku -Name 'prepaidUnitsEnabled')
        $consumed = [int](Get-PurviewProperty -InputObject $sku -Name 'consumedUnits')
        $spare = $enabled - $consumed

        $seatDetail = if ($enabled -le 0) { 'This subscription reported no seat count.' }
        elseif ($spare -gt 0) { "$(Format-PurviewCount -Count $spare -Singular 'seat') $(if ($spare -eq 1) { 'is' } else { 'are' }) paid for and assigned to nobody." }
        elseif ($spare -lt 0) { "$(Format-PurviewCount -Count ([math]::Abs($spare)) -Singular 'more seat') $(if ($spare -eq -1) { 'is' } else { 'are' }) assigned than the subscription lists as enabled." }
        else { 'Every seat is assigned.' }

        $output.Add([pscustomobject]@{
                Sku = [string](Get-PurviewProperty -InputObject $sku -Name 'skuPartNumber')
                State = if ($enabled -gt 0) { "$consumed of $enabled assigned" } else { 'Seats not reported' }
                Detail = $seatDetail
            })
    }

    if ($skus.Count -gt $relevant.Count) {
        $output.Add([pscustomobject]@{
                Sku = Format-PurviewCount -Count ($skus.Count - $relevant.Count) -Singular 'other subscription'
                State = 'Not relevant'
                Detail = 'Not listed: they carry no Purview capability, so they change nothing in this assessment.'
            })
    }

    foreach ($blocked in @($Finding | Where-Object { $_.PSObject.Properties['licensing'] -and $_.licensing.state -eq 'NotLicensed' })) {
        $capability = $blocked.licensing.capability
        $rule = $blocked.ruleId
        $output.Add([pscustomobject]@{
                Sku = @($blocked.licensing.unlockedBy) -join ' or '
                State = 'Absent'
                Detail = "$capability is blocked without this. Affects $rule."
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
    $header = @(
        '<#'
        '    Remediation for Microsoft Purview tenant opt-ins.'
        ''
        "    Tenant:     $TenantName"
        "    Assessed:   $GeneratedAt"
        "    Generator:  Purview advisor $script:ToolVersion"
        '    Changes:    {COUNT}'
        ''
        '    Every change here is tenant-wide. Read each one, confirm it suits this'
        '    organisation, and put it through change control before running with -Apply.'
        '    Without -Apply this script only reports what it would do.'
        '#>'
        ''
        '[CmdletBinding()]'
        ("param([switch]`$Apply, [string]`$AdminUrl = '{0}')" -f ($AdminUrl -replace "'", "''"))
        ''
        "`$ErrorActionPreference = 'Stop'"
        ''
    ) -join $nl

    $connect = [ordered]@{
        SharePoint = @(
            '# SharePoint Online, for the tenant-wide labelling switches.'
            'if (-not $AdminUrl) { throw "Pass -AdminUrl https://<tenant>-admin.sharepoint.com" }'
            'if (-not (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue)) { Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell }'
            'Connect-SPOService -Url $AdminUrl'
            ''
        ) -join $nl
        SecurityAndCompliance = @(
            '# Security & Compliance, for the policy configuration settings.'
            'Connect-IPPSSession'
            ''
        ) -join $nl
    }

    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($Prerequisite | Where-Object { $_.State -eq 'Needs attention' -and ($_.Command -or @($_.Candidates).Count -gt 0) })) {
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add(('# {0}' -f $item.Name))
        $lines.Add(('#   Now:         {0}' -f $item.Detail))
        $lines.Add(('#   Why:         {0}' -f $item.Why))
        if ($item.Caution) { $lines.Add(('#   CAUTION:     {0}' -f $item.Caution)) }
        $lines.Add(('#   Reference:   {0}' -f $item.Url))

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
            $lines.Add('    if ($Apply) {')
            $lines.Add(('        if ($PSCmdlet.ShouldContinue($name, ''Turn this policy on?'')) {{ {0} }}' -f $item.Choose.Apply))
            $lines.Add('    }')
            $lines.Add(('    else {{ Write-Host "Would run: {0}" }}' -f $item.Choose.Apply))
            $lines.Add('}')
            $lines.Add('')

            $items.Add([pscustomobject]@{
                    name = [string]$item.Name
                    session = [string]$item.Choose.Session
                    caution = [bool]$item.Caution
                    file = 'Enable-AutoLabelingPolicies.ps1'
                    block = ($lines -join $nl)
                })
            continue
        }

        # Single quotes in the generated file: a command containing $true must print literally
        # rather than interpolating when the operator runs the dry run.
        $lines.Add('if ($Apply) {')
        $lines.Add(("    if (`$PSCmdlet.ShouldContinue('{0}', 'Apply this change?')) {{ {1} }}" -f ($item.Name -replace "'", "''"), $item.Command))
        $lines.Add('}')
        $lines.Add(("else {{ Write-Host 'Would run: {0}' }}" -f ($item.Command -replace "'", "''")))
        $lines.Add('')

        # Named for the setting it changes, so a single download says what it does from the filename.
        # Matched after whitespace, or the hyphen in the cmdlet name wins and every file is alike.
        $switch = if ($item.Command -match '\s-(\w+)') { $Matches[1] } else { 'PurviewSetting' }

        $items.Add([pscustomobject]@{
                name = [string]$item.Name
                session = [string]$item.Session
                caution = [bool]$item.Caution
                file = "Set-$switch.ps1"
                block = ($lines -join $nl)
            })
    }

    return [pscustomobject]@{ header = $header; connect = $connect; items = $items.ToArray() }
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
    $chosen = if ($null -eq $Only) { @($Part.items) } else { @($Part.items | Where-Object { $_.name -in $Only }) }
    $text = $Part.header -replace '\{COUNT\}', $chosen.Count

    if ($chosen.Count -eq 0) {
        return $text + $nl + "Write-Host 'Nothing selected to remediate.' -ForegroundColor Green" + $nl
    }

    foreach ($session in @($Part.connect.Keys)) {
        if (@($chosen | Where-Object { $_.session -eq $session }).Count -gt 0) { $text += $nl + $Part.connect[$session] }
    }

    foreach ($item in $chosen) { $text += $nl + $item.block }
    return $text
}

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
        param($control, $state, $detail, $why, $url)
        $output.Add([pscustomobject]@{ Control = $control; State = $state; Detail = $detail; Why = $why; Url = $url })
    }

    # Setup before recommendations: labels reach Copilot content only once SharePoint and OneDrive
    # process them, so the rest of this section is theoretical until this one is on.
    $prereq = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding |
        Where-Object { $_.Name -eq 'Labels processed for Office files in SharePoint and OneDrive' })
    if ($prereq.Count -gt 0) {
        & $add 'Labels processed in SharePoint and OneDrive' $prereq[0].State $prereq[0].Detail 'Until this is on, the encrypted files Copilot can reach are limited to what is open in an Office app on Windows. Everything at rest is outside the protection the labels imply.' 'https://learn.microsoft.com/purview/sensitivity-labels-sharepoint-onedrive-files'
    }

    # Withholding EXTRACT or VIEW is the documented lever for keeping encrypted content out of
    # Copilot, so this reports which way round it is rather than treating either state as a fault.
    $labels = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'SensitivityLabel' -Select 'Labels')
    $encrypting = @($labels | Where-Object { [bool](Get-PurviewProperty -InputObject $_ -Name 'EncryptionEnabled') })
    $rightsControl = 'Label rights that exclude content from Copilot'
    $rightsUrl = 'https://learn.microsoft.com/purview/ai-m365-copilot'
    $rightsWhy = 'Copilot returns encrypted content only where the label grants the person asking both VIEW and EXTRACT. Withholding either is therefore the way to keep a class of content out of Copilot entirely, and the effect is silence rather than an error: the content never appears in an answer and nobody is told why. The same configuration reads as deliberate protection or as an accidental blind spot depending on what was intended, which is the only thing worth establishing here.'

    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'SensitivityLabel')) {
        & $add $rightsControl 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'SensitivityLabel') $rightsWhy $rightsUrl
    }
    elseif ($encrypting.Count -eq 0) {
        & $add $rightsControl 'Not configured' 'No label applies encryption, so no label withholds anything from Copilot.' $rightsWhy $rightsUrl
    }
    else {
        $known = @($encrypting | Where-Object { Test-PurviewProperty -InputObject $_ -Name 'EncryptionRights' })
        if ($known.Count -eq 0) {
            $applying = if ($encrypting.Count -eq 1) { 'applies' } else { 'apply' }
            & $add $rightsControl 'Not configured' "$(Format-PurviewCount -Count $encrypting.Count -Singular 'label') $applying encryption, but none returned any usage rights, so this could not be established either way." $rightsWhy $rightsUrl
        }
        else {
            # OWNER is full control, so it carries VIEW and EXTRACT without naming them.
            $without = @($known | Where-Object {
                    $rights = [string](Get-PurviewProperty -InputObject $_ -Name 'EncryptionRights')
                    -not ($rights -match '(?i)OWNER' -or ($rights -match '(?i)EXTRACT' -and $rights -match '(?i)VIEW'))
                })
            $names = @($without | ForEach-Object { [string](Get-PurviewProperty -InputObject $_ -Name 'Name') } | Select-Object -First 4) -join ', '
            $scope = Format-PurviewCount -Count $known.Count -Singular 'label that controls access' -Plural 'labels that control access'
            $state = if ($without.Count -gt 0) { 'In use' } else { 'Not in use' }
            $detail = if ($without.Count -gt 0) {
                $verb = if ($without.Count -eq 1) { 'withholds' } else { 'withhold' }
                $owns = if ($without.Count -eq 1) { 'it protects' } else { 'they protect' }
                "$($without.Count) of $scope $verb VIEW or EXTRACT, so Copilot returns nothing from the content ${owns}: $names. Confirm that is deliberate."
            }
            else { "$scope grant VIEW and EXTRACT, so Copilot can reach everything they protect. Withholding EXTRACT is the lever if a class of content should be excluded." }
            & $add $rightsControl $state $detail $rightsWhy $rightsUrl
        }
    }

    # The Copilot DLP location is only offered in the Custom template and disables every other
    # location, so a policy carrying it is identifiable by that alone.
    $dlp = @(Get-PurviewCollectorItem -Snapshot $Snapshot -Collector 'DataLossPrevention' -Select 'Policies')
    if (-not (Test-PurviewCollectorRan -Snapshot $Snapshot -Collector 'DataLossPrevention')) {
        & $add 'DLP policy scoped to Copilot' 'Not read' (Get-PurviewCollectorReason -Snapshot $Snapshot -Collector 'DataLossPrevention') 'The Copilot location is what lets DLP keep sensitive prompts out of web search, stop labelled files being summarised, and exclude untrusted external mail from grounding.' 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about'
    }
    else {
        $readable = @($dlp | Where-Object { Test-PurviewProperty -InputObject $_ -Name 'CopilotLocation' })
        if ($readable.Count -eq 0) {
            & $add 'DLP policy scoped to Copilot' 'Needs review' 'The service did not return a Copilot location on any DLP policy, so this could not be judged from PowerShell. Check the policy list in the portal.' 'The Copilot location is what lets DLP keep sensitive prompts out of web search, stop labelled files being summarised, and exclude untrusted external mail from grounding.' 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about'
        }
        else {
            $scoped = @($readable | Where-Object { @(ConvertTo-PurviewArray -InputObject (Get-PurviewProperty -InputObject $_ -Name 'CopilotLocation')).Count -gt 0 })
            $state = if ($scoped.Count -gt 0) { 'As recommended' } else { 'Needs attention' }
            $detail = if ($scoped.Count -gt 0) { "$(Format-PurviewCount -Count $scoped.Count -Singular 'DLP policy' -Plural 'DLP policies') target the Microsoft 365 Copilot and Copilot Chat location." }
            else { 'No DLP policy targets the Microsoft 365 Copilot and Copilot Chat location.' }
            & $add 'DLP policy scoped to Copilot' $state $detail 'The Copilot location is what lets DLP keep sensitive prompts out of web search, stop labelled files being summarised, and exclude untrusted external mail from grounding.' 'https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about'
        }
    }

    # Same order as the prerequisites: what needs doing, what needs a decision, what could not be
    # established, then what is simply worth knowing. Setup keeps its place at the top of its band.
    $rank = @{ 'Needs attention' = 0; 'Needs review' = 1; 'Not read' = 2; 'Not configured' = 3; 'In use' = 4; 'Not in use' = 5; 'As recommended' = 6 }
    return @($output | Sort-Object @{ Expression = { if ($rank.ContainsKey([string]$_.State)) { $rank[[string]$_.State] } else { 7 } } })
}

function Get-PurviewSensitiveTypeName {
    <# .SYNOPSIS Pulls the sensitive information type names out of a rule condition. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowNull()][object]$Condition)

    $found = [System.Collections.Generic.List[string]]::new()

    # The condition nests differently depending on how the rule was built, so this walks whatever
    # shape came back rather than assuming one. Anything unrecognised is skipped, not guessed at.
    $walk = {
        param($node, $depth)
        if ($null -eq $node -or $depth -gt 6) { return }
        if ($node -is [string]) { return }

        if ($node -is [System.Collections.IEnumerable]) {
            foreach ($item in $node) { & $walk $item ($depth + 1) }
            return
        }

        $name = [string](Get-PurviewProperty -InputObject $node -Name 'name')
        if ($name -and -not $found.Contains($name)) { $found.Add($name) }

        foreach ($branch in 'sensitivetypes', 'groups', 'Groups', 'SensitiveTypes') {
            if (Test-PurviewProperty -InputObject $node -Name $branch) {
                & $walk (Get-PurviewProperty -InputObject $node -Name $branch) ($depth + 1)
            }
        }
    }

    & $walk $Condition 0
    return $found.ToArray()
}

function Get-PurviewOpenRisk {
    <# .SYNOPSIS States the qualifiers a reader needs to interpret these findings correctly. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding)

    $risks = [System.Collections.Generic.List[string]]::new()

    foreach ($item in @($Finding | Where-Object { $_.status -in 'NotCollected', 'NeedsReview' })) {
        # The inner parentheses matter: inside a method call, a bare comma binds to the argument
        # list rather than to -f, leaving the format string one value short.
        $risks.Add(('{0} could not be established. {1}' -f $item.ruleId, $item.reason))
    }

    $risks.Add('Activity findings describe the collection window only, and activity explorer holds at most 30 days.')
    $risks.Add('The label taxonomy is compared to the documented default by name. A tier named differently but serving the same purpose reads as organisation-specific.')
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

    $arguments = @(
        '--headless'
        '--disable-gpu'
        '--no-pdf-header-footer'
        "--print-to-pdf=$PdfPath"
        ([Uri]::new((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri
    )

    try {
        # Chromium writes diagnostics to stderr even on success, so keep it out of the console.
        $noise = New-TemporaryFile
        $script:TempArtifact += $noise.FullName
        $process = Start-Process -FilePath $browser -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden `
            -RedirectStandardError $noise.FullName
        Remove-Item -LiteralPath $noise.FullName -Force -ErrorAction SilentlyContinue

        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $PdfPath)) {
            Write-Warning "The browser did not produce a PDF (exit code $($process.ExitCode)). The HTML report is still available."
            return ''
        }
        return $PdfPath
    }
    catch {
        Write-Warning "PDF rendering failed: $(Get-PurviewSafeErrorMessage -Message $_.Exception.Message)"
        return ''
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
    $knownOperators = @('eq', 'ne', 'gt', 'lt', 'ge', 'le', 'contains', 'startsWith', 'exists', 'isNullOrEmpty')

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

        $assert = Get-PurviewProperty -InputObject $condition -Name 'assert'
        $type = [string](Get-PurviewProperty -InputObject $assert -Name 'type')
        if ($type -notin $knownAssertions) { throw "Rule '$id' uses an unknown assertion '$type'." }

        foreach ($predicate in @((Get-PurviewProperty -InputObject $condition -Name 'where'), (Get-PurviewProperty -InputObject $assert -Name 'where'))) {
            if ($null -eq $predicate) { continue }
            $operator = [string](Get-PurviewProperty -InputObject $predicate -Name 'operator')
            if ($operator -notin $knownOperators) { throw "Rule '$id' uses an unknown operator '$operator'." }
        }

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
        $null = $builder.AppendLine('<p class="dim">Condensed report. The full assessment ran; the prerequisites, Copilot controls, taxonomy comparison, remediation checklist, coverage matrix, blueprint coverage and per-finding detail are omitted here. Run without -Brief for those.</p>')
    }

    $counts = @{}
    foreach ($status in 'Pass', 'Fail', 'Warning', 'NeedsReview', 'NotApplicable', 'NotCollected', 'Unsupported') {
        $counts[$status] = @($Finding | Where-Object { $_.status -eq $status }).Count
    }

    $null = $builder.AppendLine('<h2>Tenant at a Glance</h2>')
    $null = $builder.AppendLine('<p class="dim">An inventory of what is configured in this tenant, reported without assessment. A row reading not checked means the data could not be read, and states the reason. A count of zero means the area was read and nothing is configured.</p>')
    $null = $builder.AppendLine('<table><thead><tr><th>Area</th><th>Inventory item</th><th>Amount</th><th>Detail</th></tr></thead><tbody>')
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
    if ($counts.NotApplicable -gt 0) { $summary.Add("$($counts.NotApplicable) not licensed") }
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
            $null = $builder.AppendLine("<p>Compared against a record from a different tenant, taken $(Enc $Delta.BaselineRecordedAt). <span class=""pass"">$($Delta.Improved) stronger here</span>, <span class=""fail"">$($Delta.Regressed) weaker here</span>, $($Delta.Unchanged) the same.</p>")
            $null = $builder.AppendLine("<p class=""dim"">Kept out of that count: $($Delta.VisibilityLost) readable there but not here, $($Delta.VisibilityGained) readable here but not there, $($Delta.ScopeChanged) differing in applicability, usually licensing, $($Delta.RuleChanged) evaluated by a changed rule, $($Delta.New) absent from the other record, $($Delta.Removed) absent from this one. None of these is a difference in configuration.</p>")
            $null = $builder.AppendLine('<p class="dim">The two tenants may be licensed or scoped differently, so a difference is a question to ask rather than a fault to fix.</p>')
        }
        else {
            $null = $builder.AppendLine('<h2>Progress Since Last Assessment</h2>')
            $null = $builder.AppendLine("<p>Compared against the run of $(Enc $Delta.BaselineRecordedAt). <span class=""pass"">$($Delta.Improved) improved</span>, <span class=""fail"">$($Delta.Regressed) regressed</span>, $($Delta.Unchanged) unchanged.</p>")
            $null = $builder.AppendLine("<p class=""dim"">Kept out of that count: $($Delta.VisibilityLost) lost visibility, $($Delta.VisibilityGained) newly visible, $($Delta.ScopeChanged) changed applicability, $($Delta.RuleChanged) evaluated by a changed rule, $($Delta.New) new, $($Delta.Removed) removed. None of these is progress in the tenant.</p>")
        }

        $moved = @($Delta.Changes | Where-Object { $_.Change -ne 'Unchanged' })
        if ($moved.Count -eq 0) {
            $null = $builder.AppendLine('<p class="dim">Nothing moved.</p>')
        }
        else {
            $header = if ($cross) { '<table><thead><tr><th>Rule</th><th>Title</th><th>There</th><th>Here</th><th>Change</th><th>Note</th></tr></thead><tbody>' }
            else { '<table><thead><tr><th>Rule</th><th>Title</th><th>Was</th><th>Now</th><th>Change</th><th>Note</th></tr></thead><tbody>' }
            $null = $builder.AppendLine($header)
            foreach ($row in ($moved | Sort-Object Change, RuleId)) {
                $class = switch ($row.Change) { 'Improved' { 'pass' } 'Regressed' { 'fail' } 'VisibilityLost' { 'warn' } default { 'dim' } }
                # A rule that was added or removed has no counterpart on one side, and an empty cell
                # reads as a rendering fault rather than an absence.
                $was = if ($row.From) { Enc $row.From } else { '<span class="dim">&mdash;</span>' }
                $now = if ($row.To) { Enc $row.To } else { '<span class="dim">&mdash;</span>' }
                $null = $builder.AppendLine("<tr><td>$(Enc $row.RuleId)</td><td>$(Enc $row.Title)</td><td>$was</td><td>$now</td><td class=""$class"">$(Enc $row.Change)</td><td>$(Enc $row.Detail)</td></tr>")
            }
            $null = $builder.AppendLine('</tbody></table>')
        }

        $maturityMoves = @($Delta.Maturity | Where-Object { $null -ne $_.Delta -and $_.Delta -ne 0 })
        if ($maturityMoves.Count -gt 0) {
            $null = $builder.AppendLine('<table><thead><tr><th>Deployment model</th><th>Was</th><th>Now</th><th>Change</th></tr></thead><tbody>')
            foreach ($row in $maturityMoves) {
                Add-Row @((Enc $row.Model), "$($row.From)%", "$($row.To)%", ('{0:+#;-#;0}' -f $row.Delta))
            }
            $null = $builder.AppendLine('</tbody></table>')
        }
    }

    # The condensed report carries the conversation; the seven detail sections below are for the
    # follow-up, and run to the matching end-of-detail brace above Quick Wins.
    if (-not $Brief) {

    $null = $builder.AppendLine('<h2>Prerequisites and Tenant Opt-ins</h2>')
    $prereq = @(Get-PurviewPrerequisiteState -Snapshot $Snapshot -Finding $Finding)
    $remediable = @($prereq | Where-Object { $_.State -eq 'Needs attention' -and $_.Command })

    $attention = @($prereq | Where-Object { $_.State -eq 'Needs attention' }).Count
    $good = @($prereq | Where-Object { $_.State -eq 'As recommended' }).Count
    $portal = @($prereq | Where-Object { $_.State -eq 'Confirm in portal' }).Count
    $unread = $prereq.Count - $attention - $good - $portal

    $summary = "<span class=""fail""><strong>$attention need attention</strong></span> &middot; <span class=""pass"">$good as recommended</span> &middot; $portal to confirm in the portal"
    if ($unread -gt 0) { $summary += " &middot; $unread not read this run" }
    $null = $builder.AppendLine("<p>$summary</p>")
    $null = $builder.AppendLine('<p class="dim">Tenant-wide settings that determine whether the rest of Purview takes effect. Most remain off until an administrator enables them. Two are worded as a block, so the recommended value for those is False.</p>')

    if ($remediable.Count -gt 0) {
        $null = $builder.AppendLine('<p><button type="button" id="rem-all">Select all</button> <button type="button" id="rem-none">Clear</button> <button type="button" id="rem-get">Download script for selected</button> <span class="dim" id="rem-count"></span></p>')
        $null = $builder.AppendLine('<p class="dim">Tick the changes you want. The script reports what it would do and needs <code>-Apply</code> to change anything, confirming each change one at a time.</p>')
        # Windows marks anything a browser downloads and the page cannot undo that, so the reader
        # needs the one command that clears it.
        $null = $builder.AppendLine('<p class="dim">Windows blocks scripts downloaded through a browser. Run <code>Unblock-File</code> on it before you run it.</p>')
    }

    $null = $builder.AppendLine('<table><thead><tr><th>Take</th><th>Status</th><th>Opt-in</th><th>Why it matters</th><th>Recommended state</th></tr></thead><tbody>')
    foreach ($row in $prereq) {
        $class = switch ($row.State) { 'As recommended' { 'pass' } 'Needs attention' { 'fail' } 'In use' { 'info' } default { 'dim' } }
        $name = if ($row.Url) { "<a href=""$(Enc $row.Url)"">$(Enc $row.Name)</a>" } else { Enc $row.Name }
        if ($row.Optional) { $name += ' <span class="dim">(optional)</span>' }
        $action = Enc $row.Action
        if ($row.Action -match '^(Set|Leave)') { $action = "<code>$action</code>" }

        $pick = if ($row.State -eq 'Needs attention' -and $row.Command) {
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
        $parts = Get-PurviewRemediationPart -Prerequisite $prereq -TenantName $tenantName -GeneratedAt $generated
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($parts | ConvertTo-Json -Depth 10 -Compress)))
        $null = $builder.AppendLine("<script>(function(){var P=JSON.parse(decodeURIComponent(escape(atob('$encoded'))));var picks=function(){return Array.prototype.slice.call(document.querySelectorAll('.rem-pick'));};var count=function(){var n=picks().filter(function(c){return c.checked;}).length;document.getElementById('rem-count').textContent=n+' selected';};picks().forEach(function(c){c.addEventListener('change',count);});document.getElementById('rem-all').addEventListener('click',function(){picks().forEach(function(c){c.checked=true;});count();});document.getElementById('rem-none').addEventListener('click',function(){picks().forEach(function(c){c.checked=false;});count();});document.getElementById('rem-get').addEventListener('click',function(){var names=picks().filter(function(c){return c.checked;}).map(function(c){return c.getAttribute('data-name');});var chosen=P.items.filter(function(i){return names.indexOf(i.name)>=0;});var t=P.header.replace('{COUNT}',chosen.length);if(chosen.length===0){t+='\r\nWrite-Host \'Nothing selected to remediate.\'\r\n';}else{Object.keys(P.connect).forEach(function(s){if(chosen.some(function(i){return i.session===s;})){t+='\r\n'+P.connect[s];}});chosen.forEach(function(i){t+='\r\n'+i.block;});}var u=URL.createObjectURL(new Blob([t],{type:'text/plain'}));var l=document.createElement('a');l.href=u;l.download=(chosen.length===1&&chosen[0].file)?chosen[0].file:'Set-PurviewTenantOptIns.ps1';l.click();URL.revokeObjectURL(u);});count();})();</script>")
    }

    $null = $builder.AppendLine('<h2>Microsoft 365 Copilot Controls</h2>')
    $null = $builder.AppendLine('<p class="dim">Microsoft 365 Copilot answers in the security context of the person asking, so it is governed by the Purview configuration already present in the tenant. These are the controls that determine what it can reach and what is recorded about it. Setup first, then the controls that build on it.</p>')
    $copilot = @(Get-PurviewCopilotControl -Snapshot $Snapshot -Finding $Finding)

    # The table states each control, but a reader scanning the section should not have to assemble
    # the conclusion from it.
    $copilotGaps = @($copilot | Where-Object { $_.State -eq 'Needs attention' })
    if ($copilotGaps.Count -gt 0) {
        $names = ($copilotGaps | ForEach-Object { Enc $_.Control }) -join ', '
        $null = $builder.AppendLine("<p class=""fail""><strong>Not in place: $names.</strong></p>")
    }

    $null = $builder.AppendLine('<table><thead><tr><th>State</th><th>Control</th><th>Why it matters</th></tr></thead><tbody>')
    foreach ($row in $copilot) {
        $class = switch ($row.State) { 'As recommended' { 'pass' } 'Needs attention' { 'fail' } 'Needs review' { 'warn' } 'In use' { 'info' } default { 'dim' } }
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

    foreach ($group in 'To do', 'To check by hand', 'Done', 'Not checked', 'Not applicable') {
        $rows = @($checklist | Where-Object { $_.Group -eq $group })
        if ($rows.Count -eq 0) { continue }

        $null = $builder.AppendLine("<h3>$(Enc $group) ($($rows.Count))</h3>")
        $null = $builder.AppendLine('<table><thead><tr><th class="mark"></th><th class="wide">Check</th><th class="tight">Licence</th><th class="tight">FastTrack workload</th><th class="tight">Severity</th><th>What it takes</th></tr></thead><tbody>')
        foreach ($row in $rows) {
            $action = Enc $row.Action
            if ($row.Command) { $action += "<br><code>$(Enc $row.Command)</code>" }
            $null = $builder.AppendLine("<tr><td class=""mark"">[$(Enc $row.Marker)]</td><td>$(Enc $row.RuleId) $(Enc $row.Title)</td><td>$(Enc $row.Tier)</td><td>$(Enc $row.FastTrack)</td><td>$(Enc $row.Severity)</td><td>$action</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table>')
    }
    $null = $builder.AppendLine('<p class="dim">Ordered for working top down: highest severity first, and within that the licence tier the organisation is most likely to already hold. Every check maps to a workload FastTrack provides remote guidance for. Progress counts only checks that returned a verdict, so items that could not be checked do not inflate it.</p>')

    $null = $builder.AppendLine('<h2>Purview Solution Coverage Matrix</h2>')
    $null = $builder.AppendLine('<table><thead><tr><th>Collector</th><th>Solution area</th><th>Data read</th><th>Rules</th><th>Assessment</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewCoverageMatrix -Snapshot $Snapshot -Finding $Finding)) {
        Add-Row @((Enc $row.Collector), (Enc $row.SolutionArea), (Enc $row.Collection), $row.Rules, (Enc $row.Assessment))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Blueprint Coverage</h2>')
    $null = $builder.AppendLine('<p class="dim">This tenant measured against the Secure by Default and Data Security Posture Management blueprints. Only steps with a corresponding check are listed. This reports current configuration, not progress through a deployment programme.</p>')
    foreach ($model in (Get-PurviewDeploymentMaturity -Finding $Finding)) {
        $steps = @($model.Steps | Where-Object { $_.State -ne 'NoChecks' })
        if ($steps.Count -eq 0) { continue }

        $null = $builder.AppendLine("<h3>$(Enc $model.Name)</h3>")
        $null = $builder.AppendLine('<table><thead><tr><th>Step</th><th>What it covers</th><th>State</th></tr></thead><tbody>')
        foreach ($step in $steps) {
            $class = switch ($step.State) { 'ChecksPass' { 'pass' } 'ChecksFail' { 'fail' } 'Partial' { 'warn' } default { 'dim' } }
            $title = if ($step.Title) { $step.Title } else { 'Not covered by this assessment' }
            $covers = Enc $title
            $ids = @($step.RuleIds) -join ', '
            if ($ids) { $covers += "<br><span class=""dim"">Scored from $(Enc $ids)</span>" }
            $null = $builder.AppendLine("<tr><td>$($step.Step)</td><td>$covers</td><td class=""$class"">$(Enc $step.Verdict)</td></tr>")
        }
        $null = $builder.AppendLine('</tbody></table>')
    }

    $null = $builder.AppendLine('<h2>Findings by Severity</h2>')
    foreach ($item in ($Finding | Where-Object { $_.status -in 'Fail', 'Warning', 'NeedsReview' } |
            Sort-Object @{ Expression = { Get-PurviewSeverityOrder -Severity ([string](Get-PurviewProperty -InputObject $_ -Name 'severity')) } }, ruleId)) {
        $class = switch ($item.status) { 'Fail' { 'fail' } 'Pass' { 'pass' } default { 'warn' } }
        $null = $builder.AppendLine("<h3><span class=""$class"">$(Enc (Get-PurviewStatusLabel -Status $item.status))</span> $(Enc $item.ruleId) &mdash; $(Enc $item.title)</h3>")
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

    $healthy = @($Finding | Where-Object { $_.status -in 'Pass', 'NotApplicable', 'NotCollected' })
    if ($healthy.Count -gt 0) {
        $null = $builder.AppendLine('<h3>Everything else</h3>')
        $null = $builder.AppendLine('<table><thead><tr><th>Rule</th><th>Title</th><th>Status</th><th>What we found</th></tr></thead><tbody>')
        foreach ($item in ($healthy | Sort-Object status, ruleId)) {
            $class = if ($item.status -eq 'Pass') { 'pass' } else { 'dim' }
            $null = $builder.AppendLine("<tr><td>$(Enc $item.ruleId)</td><td>$(Enc $item.title)</td><td class=""$class"">$(Enc (Get-PurviewStatusLabel -Status $item.status))</td><td>$(Enc $item.reason)</td></tr>")
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
    $planned = @($Finding | Where-Object { $_.status -in 'Fail', 'Warning', 'NeedsReview' -and -not $_.PSObject.Properties['remediationCommand'] })
    $higher = @($planned | Where-Object { $_.severity -in 'Critical', 'High' })
    $lower = @($planned | Where-Object { $_.severity -in 'Medium', 'Low' })
    $null = $builder.AppendLine('<h3>Critical and high severity</h3><ul>')
    if ($higher.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">Nothing outstanding.</li>') }
    foreach ($item in $higher) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
    $null = $builder.AppendLine('</ul><h3>Medium and low severity</h3><ul>')
    if ($lower.Count -eq 0) { $null = $builder.AppendLine('<li class="dim">Nothing outstanding.</li>') }
    foreach ($item in $lower) { $null = $builder.AppendLine("<li>$(Enc $item.title) - $(Enc $item.recommendation)</li>") }
    $null = $builder.AppendLine('</ul>')

    $null = $builder.AppendLine('<h2>Licensing and SKU Analysis</h2>')
    $null = $builder.AppendLine('<table><thead><tr><th>SKU or add-on</th><th>Seats</th><th>Detail</th></tr></thead><tbody>')
    foreach ($row in (Get-PurviewLicensingAnalysis -Snapshot $Snapshot -Finding $Finding)) {
        Add-Row @((Enc $row.Sku), (Enc $row.State), (Enc $row.Detail))
    }
    $null = $builder.AppendLine('</tbody></table>')

    $null = $builder.AppendLine('<h2>Limitations of This Assessment</h2>')
    $null = $builder.AppendLine('<p class="dim">What this run could not establish, and the qualifiers required to interpret the findings above. These describe the assessment, not the tenant.</p><ul>')
    foreach ($risk in (Get-PurviewOpenRisk -Finding $Finding)) { $null = $builder.AppendLine("<li>$(Enc $risk)</li>") }
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

    $stamp = Format-PurviewTimestamp -Timestamp (Get-PurviewTimestamp)

    return [pscustomobject]@{
        snapshotVersion = '1.0'
        toolVersion = $script:ToolVersion
        capturedAt = $stamp
        mode = 'SyntheticSample'
        tenant = [pscustomobject]@{ displayName = 'Contoso Sample (fabricated)'; tenantId = ''; redacted = $true }
        licensing = [pscustomobject]@{
            collected = $true
            subscribedSkus = @([pscustomobject]@{ skuPartNumber = 'SPE_E5'; skuId = 'sample'; servicePlans = @(); prepaidUnitsEnabled = 120; consumedUnits = 112 })
        }
        collectorResults = @(
            [pscustomobject]@{
                collector = 'SensitivityLabel'; solutionArea = 'SensitivityLabels'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-Label'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Labels = @(
                        [pscustomobject]@{ Guid = 'g1'; Name = 'Public'; Priority = 0; Disabled = $false; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g2'; Name = 'General'; Priority = 1; Disabled = $false; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g3'; Name = 'Confidential'; Priority = 2; Disabled = $false; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g4'; Name = 'Highly Confidential'; Priority = 2; Disabled = $false; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g5'; Name = 'Board Material (fabricated)'; Priority = 3; Disabled = $false; EncryptionEnabled = $false }
                        [pscustomobject]@{ Guid = 'g6'; Name = 'Confidential \ All Employees'; ParentId = 'g3'; Priority = 4; Disabled = $false; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EXTRACT, EDIT, PRINT' }
                        [pscustomobject]@{ Guid = 'g7'; Name = 'Highly Confidential \ Specific People'; ParentId = 'g4'; Priority = 5; Disabled = $false; EncryptionEnabled = $true; EncryptionRights = 'VIEW, EDIT' }
                        [pscustomobject]@{ Guid = 'g8'; Name = 'General \ Anyone (unrestricted)'; ParentId = 'g2'; Priority = 6; Disabled = $false; EncryptionEnabled = $false }
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
                        [pscustomobject]@{ Guid = 'a1'; Name = 'Financial records (fabricated)'; Mode = 'TestWithoutNotifications'; Enabled = $true }
                        [pscustomobject]@{ Guid = 'a2'; Name = 'Customer records (fabricated)'; Mode = 'TestWithNotifications'; Enabled = $true }
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
                        # Flat and grouped conditions both occur, so the fixture carries one of each.
                        [pscustomobject]@{
                            Guid = 'ar1'; Name = 'Financial records rule (fabricated)'; Policy = 'Financial records (fabricated)'; Disabled = $false
                            SensitiveTypes = @(
                                [pscustomobject]@{ name = 'Credit Card Number'; mincount = 1 }
                                [pscustomobject]@{ name = 'ABA Routing Number'; mincount = 1 }
                            )
                        }
                        [pscustomobject]@{
                            Guid = 'ar2'; Name = 'Customer records rule (fabricated)'; Policy = 'Customer records (fabricated)'; Disabled = $false
                            SensitiveTypes = [pscustomobject]@{
                                operator = 'And'
                                groups = @([pscustomobject]@{ sensitivetypes = @([pscustomobject]@{ name = 'U.S. Social Security Number (SSN)'; mincount = 1 }) })
                            }
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
                        [pscustomobject]@{ Name = 'EnableAIPIntegration'; Enabled = $false; Value = 'False'; Expected = 'True'; AsRecommended = $false; Capability = 'Sensitivity labels for Office files' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelforPDF'; Enabled = $true; Value = 'True'; Expected = 'True'; AsRecommended = $true; Capability = 'Labels on PDF files' }
                        [pscustomobject]@{ Name = 'BlockSendLabelMismatchEmail'; Enabled = $true; Value = 'True'; Expected = 'False'; AsRecommended = $false; Capability = 'Owner is emailed when a file is more sensitive than its site' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelforOneNote'; Enabled = $true; Value = 'True'; Expected = 'True'; AsRecommended = $true; Capability = 'Labels on OneNote sections' }
                        [pscustomobject]@{ Name = 'EnableSensitivityLabelForVideoFiles'; Enabled = $false; Value = 'False'; Expected = 'True'; AsRecommended = $false; Capability = 'Labels on MP4 video files' }
                        [pscustomobject]@{ Name = 'DisableDocumentLibraryDefaultLabeling'; Enabled = $false; Value = 'False'; Expected = 'False'; AsRecommended = $true; Capability = 'Default labels apply to document libraries' }
                        [pscustomobject]@{ Name = 'MarkNewFilesSensitiveByDefault'; Enabled = $false; Value = 'AllowExternalSharing'; Expected = 'BlockExternalSharing'; AsRecommended = $false; Capability = 'New files are treated as sensitive until DLP has scanned them' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'EndpointDlpSettings'; solutionArea = 'EndpointDlp'; status = 'Success'
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
                        [pscustomobject]@{ Guid = 'd1'; Name = 'Financial data'; Mode = 'Enable'; Workload = 'Exchange, SharePoint, OneDriveForBusiness' }
                        [pscustomobject]@{ Guid = 'd2'; Name = 'Pilot'; Mode = 'TestWithoutNotifications'; Workload = 'Endpoint' }
                        # Named the way DLP analytics names what it creates, which is what proves it ran.
                        [pscustomobject]@{ Guid = 'd3'; Name = 'RiskSpotlighting-2026-08-01'; Mode = 'TestWithoutNotifications'; Workload = 'Exchange' }
                    )
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'EndpointDeviceHealth'; solutionArea = 'EndpointDlp'; status = 'Success'
                source = [pscustomobject]@{ interface = 'POST /security/runHuntingQuery'; kind = 'MicrosoftGraph' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Devices = @([pscustomobject]@{
                            Onboarded = 13; DlpEnabled = 13; ConfigurationValid = 9
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
                collector = 'DlpRule'; solutionArea = 'DataLossPrevention'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Get-DlpComplianceRule'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    Rules = @(
                        [pscustomobject]@{ Guid = 'r1'; Name = 'Credit card numbers (fabricated)'; Policy = 'Financial data'; Disabled = $false; Mode = 'Enable' }
                        [pscustomobject]@{ Guid = 'r2'; Name = 'Bank account numbers (fabricated)'; Policy = 'Financial data'; Disabled = $false; Mode = 'Enable' }
                        [pscustomobject]@{ Guid = 'r3'; Name = 'Passport numbers (fabricated)'; Policy = 'Pilot'; Disabled = $true; Mode = 'TestWithoutNotifications' }
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
                        [pscustomobject]@{ Guid = 'rp1'; Name = 'Mailbox retention (fabricated)'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange' }
                        [pscustomobject]@{ Guid = 'rp2'; Name = 'Teams chat retention (fabricated)'; Enabled = $false; Mode = 'Enforce'; Workload = 'MicrosoftTeams' }
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
                    SubscribedSkus = @([pscustomobject]@{ skuPartNumber = 'SPE_E5'; skuId = 'sample'; servicePlans = @(); prepaidUnitsEnabled = 120; consumedUnits = 112 })
                }
                errors = @(); limitations = @()
            }
            [pscustomobject]@{
                collector = 'AuditConfiguration'; solutionArea = 'Audit'; status = 'NotConnected'
                source = [pscustomobject]@{ interface = 'Get-UnifiedAuditLogRetentionPolicy'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{}
                errors = @([pscustomobject]@{ message = 'No Security & Compliance session was available.'; category = 'NotConnected' })
                limitations = @('Audit configuration was not assessed in this run.')
            }
            [pscustomobject]@{
                collector = 'ProtectionActivity'; solutionArea = 'ActivityExplorer'; status = 'Success'
                source = [pscustomobject]@{ interface = 'Export-ActivityExplorerData'; kind = 'SecurityAndCompliancePowerShell' }
                collectedAt = $stamp
                data = [pscustomobject]@{
                    WindowDays = 30; TotalEvents = 1840; Truncated = $false
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
                    Tags = @(
                        [pscustomobject]@{ Tag = 'Confidential'; TagType = 'Sensitivity'; TotalCount = 0 }
                        [pscustomobject]@{ Tag = 'General'; TagType = 'Sensitivity'; TotalCount = 0 }
                    )
                    TagsRequested = 4; TagsUnreadable = @('Highly Confidential', 'Personal'); LabelledItemTotal = 0
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
    Write-Line -Style Dim -Message '  -PdfReport        also render the report to PDF'
    Write-Line -Style Dim -Message '  -SkipInsights     configuration only, skipping the activity and content reads'
    Write-Line -Style Dim -Message '  -SkipConnect      use only sessions you established yourself'
    Write-Line -Style Dim -Message '  -SignOut          sign out at the end instead of keeping the session'
    Write-Line -Message ''
    Write-Line -Style Dim -Message '  Get-Help .\Invoke-PurviewAdvisor.ps1 -Full for everything else.'
}

function Show-Connection {
    <# .SYNOPSIS Reports what each service sign-in did. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Connection)

    Write-Line -Style Head -Message '  Sessions'

    foreach ($item in $Connection) {
        switch ($item.State) {
            'AlreadyConnected' { Write-Line -Style Good -Message ('    connected    {0}' -f $item.Service) }
            'Connected' { Write-Line -Style Good -Message ('    signed in    {0}' -f $item.Service) }
            'Skipped' { Write-Line -Style Dim -Message ('    skipped      {0}' -f $item.Service) }
            default {
                Write-Line -Style Warn -Message ('    unavailable  {0}' -f $item.Service)
                if ($item.Detail) { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
            }
        }
    }
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
            default {
                Write-Line -Style Warn -Message ('    unavailable  {0}' -f $item.Service)
                if ($item.Detail) { Write-Line -Style Dim -Message ('                 {0}' -f $item.Detail) }
            }
        }
    }

    return $usable
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
    $portal = @($rows | Where-Object { $_.State -eq 'Confirm in portal' })
    $unread = $rows.Count - $attention.Count - $good.Count - $portal.Count

    $summary = '    {0} need attention, {1} as recommended, {2} to confirm in the portal' -f $attention.Count, $good.Count, $portal.Count
    if ($unread -gt 0) { $summary += ", $unread not read this run" }
    Write-Line -Style Dim -Message $summary

    foreach ($row in $rows) {
        $style = switch ($row.State) { 'As recommended' { 'Good' } 'Needs attention' { 'Bad' } default { 'Dim' } }
        $marker = switch ($row.State) { 'As recommended' { 'ok    ' } 'Needs attention' { 'FIX   ' } 'Confirm in portal' { 'portal' } default { '?     ' } }
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
    Write-Line -Style Head -Message '  Microsoft 365 Copilot controls'

    foreach ($row in $rows) {
        $style = switch ($row.State) { 'As recommended' { 'Good' } 'Needs attention' { 'Bad' } 'Needs review' { 'Warn' } 'In use' { 'Warn' } default { 'Dim' } }
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
            $stepStyle = switch ($step.State) { 'ChecksPass' { 'Good' } 'ChecksFail' { 'Bad' } 'Partial' { 'Warn' } default { 'Dim' } }
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
    if ($Delta.Improved -gt 0) { Write-Line -Style Good -Message ('    {0} {1}' -f $(if ($cross) { 'stronger here ' } else { 'improved      ' }), $Delta.Improved) }
    if ($Delta.Regressed -gt 0) { Write-Line -Style Bad -Message ('    {0} {1}' -f $(if ($cross) { 'weaker here   ' } else { 'regressed     ' }), $Delta.Regressed) }
    Write-Line -Style Dim -Message ('    {0} {1}' -f $(if ($cross) { 'the same      ' } else { 'unchanged     ' }), $Delta.Unchanged)

    foreach ($row in @($Delta.Changes | Where-Object { $_.Change -in 'Improved', 'Regressed' } | Sort-Object Change, RuleId)) {
        $style = if ($row.Change -eq 'Improved') { 'Good' } else { 'Bad' }
        Write-Line -Style $style -Message ('      {0} {1} -> {2}  {3}' -f $row.RuleId, $row.From, $row.To, $row.Title)
    }

    $excluded = $Delta.VisibilityLost + $Delta.VisibilityGained + $Delta.ScopeChanged + $Delta.RuleChanged + $Delta.New + $Delta.Removed
    if ($excluded -gt 0) {
        Write-Line -Message ''
        $noun = Format-PurviewCount -Count $excluded -Singular 'change'
        $lead = if ($cross) { 'Not a difference in configuration' } else { 'Not counted as progress' }
        Write-Line -Style Dim -Message ('    {0} ({1}):' -f $lead, $noun)
        foreach ($row in @($Delta.Changes | Where-Object { $_.Change -in 'VisibilityLost', 'VisibilityGained', 'ScopeChanged', 'RuleChanged', 'New', 'Removed' } | Sort-Object Change, RuleId)) {
            $style = if ($row.Change -eq 'VisibilityLost') { 'Warn' } else { 'Dim' }
            Write-Line -Style $style -Message ('      {0,-16} {1} {2}' -f $row.Change, $row.RuleId, $row.Title)
        }
    }

    foreach ($row in @($Delta.Maturity | Where-Object { $null -ne $_.Delta -and $_.Delta -ne 0 })) {
        Write-Line -Style Dim -Message ('    {0,-22} {1}% -> {2}%' -f $row.Model, $row.From, $row.To)
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

    $skipped = @($checklist | Where-Object { $_.Group -eq 'Not applicable' }).Count
    if ($skipped -gt 0) {
        Write-Line -Message ''
        Write-Line -Style Dim -Message ('    {0} check(s) do not apply to this tenant, usually because the capability is not licensed.' -f $skipped)
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
        NotApplicable = 'Dim'; NotCollected = 'Dim'; Unsupported = 'Dim'
    }

    $notAssessed = 0
    foreach ($status in 'Fail', 'Warning', 'NeedsReview', 'Pass', 'NotApplicable', 'NotCollected', 'Unsupported') {
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
        'NotApplicable' { return 'Not applicable' }
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
if (@($Solution).Count -gt 0) {
    Write-Line -Style Warn -Message ('  Scope      {0} only. Everything else is neither collected nor scored.' -f ($Solution -join ', '))
    Write-Line -Message ''
}

# Collecting is the default, so the script does something useful with no arguments at all.
$bare = -not $Collect -and [string]::IsNullOrWhiteSpace($SnapshotPath)
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

if ($Collect -or $bare) {
    $modules = @(Install-PurviewPrerequisite -SkipInstall:$SkipModuleInstall)
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
    }

    Write-Line -Style Head -Message '  Collecting'
    Write-Line -Style Dim -Message '    A large tenant can take a few minutes.'
    if (-not $SkipInsights) {
        Write-Line -Style Dim -Message ('    Reading {0} days of activity and labelled-content counts. Only totals are kept.' -f $InsightDays)
    }
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
    $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100
    Write-Line -Style Dim -Message ('  Snapshot   {0}' -f $SnapshotPath)
}

$findings = @(Invoke-PurviewRuleEngine -Snapshot $snapshot -Rule $script:ActiveRule)

Write-Line -Message ''
Write-Line -Style Dim -Message ('  Mode       {0}' -f $snapshot.mode)
Write-Line -Style Dim -Message ('  Rules      {0}' -f $script:ActiveRule.Count)
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
    $baseline = Get-PurviewComparableBaseline -History @(Get-PurviewPostureHistory -Folder $recordFolder) -Current $record
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
Write-Line -Style Dim -Message '    The remediation script reports what it would do; it needs -Apply to change anything.'

if ($PdfReport) {
    $pdf = Export-PurviewPdfReport -HtmlPath $htmlPath -PdfPath (Join-Path $ReportFolder 'report.pdf')
    if ($pdf) { Write-Line -Style Good -Message ('    {0}' -f $pdf) }
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
Write-Line -Style Dim -Message '    These describe real configuration. Treat them as customer data.'

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
    Clear-PurviewRunState -SignOut:$SignOut
    if ($SignOut -and $signedIn) {
        Write-Line -Style Dim -Message '  Signed out of the sessions this run opened.'
        Write-Line -Message ''
    }
}

#endregion
