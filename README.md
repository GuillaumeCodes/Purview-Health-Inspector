# Purview Health Inspector

A single PowerShell script that assesses Microsoft Purview configuration and privacy-safe aggregate
observations against evidence-based rules. Evaluation of a collected snapshot is deterministic; the
report keeps current configuration, recent telemetry and delayed content inventory distinct. It
checks licensing eligibility and produces a report you can hand to a customer. Every recommendation
carries the Microsoft source it came from, the date that source was retrieved, and a confidence level.

**What it is not.** The assessment itself never changes anything in a tenant — every call it makes
is a read. It does, though, *write* remediation: where a fix exists it prints the command, and the
report can generate a PowerShell script for the changes you tick. Those scripts are yours to review
before you run them. Each one explains every change as it reaches it and applies it only if you
answer yes, but read the file first and put it through change control — the changes are tenant-wide.
It is not a Microsoft product — it reads what is configured and reports it against the Purview
Deployment Blueprints and Secure by Default guidance, which are Microsoft's own.

Everything is in [Invoke-PurviewAdvisor.ps1](Invoke-PurviewAdvisor.ps1). Copy that one file
anywhere and run it.

## Read-only guarantee

**It never creates, modifies, publishes or deletes anything in a connected tenant.**

Only reads are used. Every cmdlet is a `Get-*`, apart from two `Export-*` cmdlets —
`Export-ActivityExplorerData` and `Export-ContentExplorerData` — which despite the verb return data
to the pipeline and change nothing, and four advanced hunting queries that run read-only KQL and
return counts.

Don't take that on trust. It is one file, so check it yourself in a few seconds:

```powershell
# Every tenant interface the script declares. All reads.
Select-String .\Invoke-PurviewAdvisor.ps1 -Pattern "Cmdlet = '([^']+)'|-Interface '([^']+)'" -AllMatches |
    ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value } | Sort-Object -Unique

# Every permission named anywhere in the file. All are .Read.All.
Select-String .\Invoke-PurviewAdvisor.ps1 -Pattern '\w+\.\w+\.All' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

The last one lists `Organization.Read.All` and `Directory.Read.All` as well. Those appear only in a
note explaining that Microsoft marks them higher-privileged and that this script therefore does not
request them.

Sign-in is interactive and runs in your browser. No password, secret or token is accepted as a
parameter, held in a variable, or written anywhere.

Installing a PowerShell module changes your machine, not the tenant. The guarantee is about tenant
configuration and is unaffected.

## Quick start

Downloaded it from GitHub? Windows marks anything that arrives from the internet and PowerShell
refuses to run it, so clear the mark once:

```powershell
Unblock-File -Path .\Invoke-PurviewAdvisor.ps1
```

Then run it:

```powershell
.\Invoke-PurviewAdvisor.ps1
```

That is the whole thing. It installs what it needs, signs you in to anything you are not already
connected to, collects, assesses, and writes an HTML report into a `PurviewReport` folder in the
current directory — then opens it. That folder is refreshed on each run rather than piling up:
run history lives in the posture records. `-ReportFolder` writes somewhere else, `-NoOpen` leaves it
closed.

Alongside the report you get `findings.json` (the same findings as data), `snapshot.json` (what was
collected, so a run can be re-assessed later without going back to the tenant) and
`Set-PurviewTenantOptIns.ps1` (the fixes this run identified, as a script to review).

The remediation script explains each change as it reaches it — what is set now, why it matters, and
the exact command — then applies it only if you answer yes, so reading it through changes nothing.
These are tenant-wide settings, so it is written to go through change control rather than to be run
on sight. The report carries a download button for the same script, which works even when the HTML
is emailed on its own.

Most of those changes connect to SharePoint Online or Security & Compliance. Turning on container
labels is the exception, because it writes a Microsoft Entra directory setting: that one asks for
`Directory.ReadWrite.All` and for the two Graph modules Microsoft documents for it, prompting before
it installs either. It then synchronises the labels to Entra, which Microsoft documents as taking up
to 24 hours before a label can be assigned to a group.

A script downloaded through the browser is marked by Windows as coming from another machine, and
PowerShell refuses to run it. Read it, then clear the mark:

```powershell
Unblock-File -Path .\Set-PurviewTenantOptIns.ps1
```

The copy written next to the report needs none of this, because it never left the machine.

Double-clicked it, or launched it from Windows PowerShell 5.1? It restarts itself in PowerShell 7
and carries your arguments across. If PowerShell 7 is not installed it tells you the one command
that installs it.

If you would rather manage your own sessions, connect first and pass `-SkipConnect`. You do not need
all three connections — anything you skip is reported as `NotCollected` rather than guessed at.

| Switch | Effect |
| --- | --- |
| *(none)* | Collect from your tenant and assess |
| `-Collect` | Collect and assess, stated explicitly; the same as passing nothing |
| `-SnapshotPath` | Assess a snapshot already on disk |
| `-SnapshotOutputPath` | Where the snapshot is written, instead of a timestamped file here |
| `-TenantAdminUrl` | Your SharePoint admin URL, if it cannot be worked out for you |
| `-Environment` | The cloud the tenant is in: Commercial, GCC, GCCHigh, DoD or China |
| `-Solution` | Assess only the named Purview solutions instead of all of them |
| `-Brief` | Write the condensed report instead of the full one |
| `-AcrossTenants` | Compare against a `-BaselinePath` record from a different tenant |
| `-SkipConnect` | Sign in to nothing; use only sessions you established |
| `-KeepSignedIn` | Leave the sessions this run opened signed in, instead of signing out at the end |
| `-ReportFolder` | Write the report somewhere other than the current directory |
| `-Demo` | Render a full report from fabricated data, with no tenant, sign-in or licence |
| `-NoOpen` | Do not open the report when it is finished |
| `-DarkMode` | Render the report on a dark background |
| `-PdfReport` | Also render a PDF (needs Edge, Chrome or Chromium) |
| `-WordReport` | Also write a `.docx` (needs Word on Windows) |
| `-CheckEvidence` | Verify every cited Microsoft source still resolves and reads as it did |
| `-ExportRules` | Write the rules and citations to a JSON file you can edit |
| `-RuleFile` | Assess using rules from that file |
| `-SkipInsights` | Configuration only, skipping the activity, indexed-content and oversharing reads |
| `-InsightDays` | Rolling Activity Explorer operation window in days. Defaults to 30; it does not limit Content Explorer counts requested with `-InsightTag` |
| `-InsightTag` | Sensitive information type names to ask Content Explorer for. Nothing is requested automatically; every delayed count is shown separately and never summed |
| `-BaselineFolder` | Where to keep posture records, if not the default per-user folder |
| `-BaselinePath` | Compare against one specific posture record |
| `-NoRecord` | Do not record this run |
| `-RedactTenant` | Blank tenant name and id before sharing |
| `-IncludeSites` | Enumerate SharePoint sites (slow on a large tenant) |
| `-SiteLimit` | How many sites `-IncludeSites` will enumerate before it stops |
| `-SkipModuleInstall` | Use only modules already installed |
| `-PassThru` | Return findings as objects to filter or pipe |

## Prerequisites

PowerShell 7, on Windows, macOS or Linux. Windows PowerShell 5.1 is handled for you: the script
restarts itself rather than failing.

For live collection the script installs any missing module to **CurrentUser** scope, so no elevation
is needed. Pass `-SkipModuleInstall` to opt out.

| Module | Service | Notes |
| --- | --- | --- |
| `ExchangeOnlineManagement` | Security & Compliance | Runs natively on PowerShell 7 |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online | Windows only; its required commands run in a fresh local Windows PowerShell session created with `-UseWindowsPowerShell`, as Microsoft documents for PowerShell 7 |
| `Microsoft.Graph.Authentication` | Microsoft Graph | Runs natively on PowerShell 7 |

Permissions, all read-only:

| Permission | Why |
| --- | --- |
| `LicenseAssignment.Read.All` | Subscribed SKUs for licensing analysis. Microsoft marks this least privileged for `GET /subscribedSkus` |
| `GroupSettings.Read.All` | Whether container labelling is switched on in the directory. Least privileged for `GET /groupSettings`; `Directory.Read.All` also works and is deliberately not requested |
| `User.Read` | The tenant's initial domain, which gives the SharePoint admin URL, and the signed-in account's own Entra roles. Microsoft documents this as enough to read `verifiedDomains`, and as the least privileged permission for `GET /me/memberOf` |
| `ThreatHunting.Read.All` | Endpoint DLP device health through the `DlpInfo` column of `DeviceInfo`, plus 30-day historical signals from `CloudAppEvents`, `DataSecurityBehaviors` and `DataSecurityEvents`. Every query aggregates in the service and returns counts only |
| `Application.Read.All` | Whether Defender for Cloud Apps holds the documented Azure Rights Management `Content.SuperUser` role for protected-file inspection. The client app id is checked against Microsoft's cloud-specific ids; an unrelated assignment or same-name app earns no credit. Microsoft marks this least privileged for `GET /servicePrincipals/{id}/appRoleAssignments` |
| **Global Reader** in Microsoft Purview | Read-only counterpart of Global Administrator |
| **Content Explorer List Viewer** | Needed only when `-InsightTag` requests sensitive-information-type counts. It has to be granted explicitly because it is a Purview role group, so no Entra role carries it and Global Administrator does not include it. *Content Viewer* additionally exposes item contents and names, and is deliberately not requested |

`Organization.Read.All` and `Directory.Read.All` also work for subscribed SKUs, but Microsoft lists
them as *higher privileged*, so they are deliberately not requested.

SharePoint collection runs on Windows, because its module does. The oversharing reports need
SharePoint Advanced Management, which a Microsoft Copilot license or the Plan 1 add-on unlocks.
`-PdfReport` uses Edge, Chrome or Chromium and `-WordReport` uses Word on Windows; where
neither is present the HTML and JSON reports are still written. PDF rendering uses a temporary
blank browser profile instead of your normal browser session, waits for the complete file, and
removes the temporary profile afterward.

### Password-protecting the PDF

`-ProtectPdf` asks for a password and encrypts the PDF with it, using 256-bit AES. You are asked
twice, because a password mistyped once produces a file nobody can open, and nothing anywhere keeps
a copy of it.

A browser can print a PDF but cannot encrypt one, so this needs [qpdf](https://qpdf.sourceforge.io).
If it is missing the script installs it through the package manager the machine already trusts —
winget on Windows, Homebrew on macOS — so the download is the one that manager has pinned rather
than something this script fetched. `-SkipModuleInstall` declines that as it does for the modules.
On Linux the command is printed for you to run, because installing there needs `sudo`.

The password never becomes ordinary text. It is read as a `SecureString`, compared through
unmanaged memory, and written to qpdf's standard input as bytes, which qpdf documents as the way to
avoid passwords appearing on a command line. It is never an argument, never written to a file, and
never logged. The owner password — the one that would lift the restrictions — is random and
discarded, since an empty one or one matching the user password is documented as insecure.

If the PDF cannot be encrypted for any reason, it is deleted rather than left sitting unprotected.

## How to read the output

### Finding statuses

| Status | Meaning |
| --- | --- |
| `Pass` | Checked and correct |
| `Area for improvement` | Checked and incorrect |
| `Warning` | Works today, but ambiguous or fragile |
| `NotCollected` | Applies, but the data was not read — the service was not connected, or the sign-in did not hold the role that exposes it |
| `NeedsReview` | The data was ambiguous, or a property the rule needs was not returned |

In `findings.json` and in posture records the status is stored as `Fail`, so anything reading those
files or comparing against an earlier baseline sees a stable value.

The unresolved statuses matter as much as the verdicts. `NotCollected` tells you what a further
connection would add and is never reported as a failure. `NeedsReview` carries no remediation command
and recommends verifying the current state before acting, because missing evidence does not establish
that a setting should change. A check that does not apply is withheld from customer output entirely;
internal applicability bookkeeping is not a tenant observation.

Licensing is deliberately conservative. Microsoft's [product identifier reference](https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference)
defines the string ID as Graph `skuPartNumber` and the GUID as `skuId`, so this version recognizes a
product only when both values form one verified pair. Friendly names, substrings, service-plan names
and service-plan states never establish marketed-product identity.

| Product shown in the report | Exact `skuPartNumber` | Exact `skuId` | What the pair can establish |
| --- | --- | --- | --- |
| Microsoft 365 E3 | `SPE_E3` | `05e9a617-0261-4cee-bb44-138d3ef5d965` | E3 capability |
| Microsoft 365 E5 | `SPE_E5` | `06ebc4ee-1bb5-47dd-8120-11324bc54e06` | E5 and E3 capability |
| Microsoft 365 E7 | `MICROSOFT_365_E7` | `9a18296a-025f-4e37-9ffa-30bf8d1ce775` | Displayed as E7; satisfies E7, E5 and E3 requirements |
| Microsoft 365 E5 Compliance | `INFORMATION_PROTECTION_COMPLIANCE` | `184efa21-98c3-4e5d-95ab-d07053a96e67` | Purview E5 Compliance add-on capability; never a suite tier |
| Microsoft 365 Copilot | `Microsoft_365_Copilot` | `639dec6b-bb19-468b-871c-c5c441c4b0cb` | Microsoft 365 Copilot add-on capability |
| Microsoft Purview Audit 10-year retention add-on | `10_ALR_ADDON` | `c2e41e49-e2a2-4c55-832a-cf13ffba1d6a` | Ten-year audit retention add-on capability |

For a recognized pair, only the exact case-sensitive Graph `capabilityStatus` value `Enabled`
establishes current entitlement. A positive match can stand even when unrelated records are
incomplete. A recognized product in `Warning`, `Suspended`, `Deleted` or `LockedOut`, a missing or
unrecognized status, a mismatched pair, or conflicting duplicate evidence grants and denies nothing.
The [Graph resource contract](https://learn.microsoft.com/graph/api/resources/subscribedsku) defines
the status and seat fields; the [Purview service description](https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description)
remains the feature-by-feature source for which users require which rights.

Absence is a stronger claim. A capability is `NotLicensed` only when
[`GET /subscribedSkus`](https://learn.microsoft.com/graph/api/subscribedsku-list) returned a readable,
complete and internally consistent list, every product record and status was classifiable, and no
recognized product could provide that capability. Any incomplete, malformed, unclassified or
conflicting evidence leaves licensing `Unknown`; the rule is still evaluated because suppressing it
would look like nothing is wrong. Customer-facing inventory and licensing tables name only exact
verified products that affect Purview. Unrelated, malformed, unclassified and conflicting SKU
records remain in the snapshot and still block unsafe proof of absence, but they do not become
customer-facing subscription rows.

Enabled and assigned seat counts are displayed only when both are usable non-negative integers.
They are diagnostics only: zero, exhausted, over-assigned or unreadable seats never create, remove
or rename an entitlement.

### Sources

Every finding carries the Microsoft page its recommendation came from, shown with the finding rather
than collected into a bibliography. Confidence is `High` when behaviour was confirmed on a reference
page, `Medium` when confirmed in guidance with some detail inferred, `Low` when the guidance is
preview or the interface appears only in a code sample.

Timestamps are stored with an explicit UTC offset and displayed in the time zone of whoever runs the
script, resolved at runtime.

## How it decides things

A cmdlet or API counts as a documented interface only if **its own reference page** resolves and its
heading matches the name. Appearing in a code sample is not enough, because a cmdlet without a
reference page may be undocumented, in preview, or renamed. The deliberate exception is
`Get-OcrConfiguration`: Microsoft publishes no reference page for it, but the Purview portal reads
the same OCR configuration and Microsoft documents the feature itself. The collector therefore
links the [OCR feature documentation](https://learn.microsoft.com/purview/ocr-learn-about) and
treats every returned state defensively rather than claiming that the cmdlet is documented.

### What the checks are grounded in, and what that does not mean

Each rule was written against a specific Microsoft page, cites it, and records the date it was read.
Be clear about what that is and is not: the rules are **authored judgement informed by those pages**,
not something derived from them mechanically. No tool can honestly read "labels need distinct
priorities" out of prose, so nothing here pretends to.

Two things follow from that, and both are handled rather than assumed away.

**Guidance changes.** `-CheckEvidence` fetches every cited page, strips markup and whitespace, and
compares a fingerprint of the wording against the one recorded when the rule was written. A page
that has been rewritten reports `Changed` so you know to re-read it, rather than a link check
quietly passing because the URL still works. A page with no fingerprint recorded says so instead of
being assumed current.

**Your standards are not these standards.** Nothing about the rules is fixed in the script:

```powershell
.\Invoke-PurviewAdvisor.ps1 -ExportRules .\rules.json    # edit it
.\Invoke-PurviewAdvisor.ps1 -RuleFile .\rules.json       # assess with it
```

A rule sharing an id with a built-in replaces it, so one check can be corrected or retuned without
restating the other twenty. Rules are data throughout — conditions are declarative and the engine
only ever compares values — so a rule file cannot introduce a code path. It is still validated on
the way in: unknown assertions or operators, rules that do not say which collector they read, and
citations that resolve to nothing are all rejected, and any source cited must be `https`.

Collection and analysis are separate. A run writes a snapshot; analysis reads only that
snapshot. A run is reproducible, reviewable long afterwards, and re-assessable without going back to
the tenant. Snapshot replay preserves case-distinct JSON keys instead of merging or rejecting them,
because service-returned policy values can legally contain both forms.

## What it checks today

21 rules, across the Purview solutions a deployment is normally judged on: Information
Protection (sensitivity labels, label publishing policies, classification, DLP policies and rules),
the Microsoft 365 E5 additions (auto-labeling, endpoint DLP, content and activity explorer),
Data Lifecycle Management, Records Management, Communication Compliance, Audit (Premium) and Data
Security Posture Management.

That includes the tenant opt-ins that ship switched off: label processing for Office files, PDFs,
OneNote and video in SharePoint and OneDrive, the label mismatch email to document and site owners,
default labelling on document libraries, treating new files as sensitive until scanned, container
labelling for groups and Teams, co-authoring on encrypted files, and extending Teams DLP to
SharePoint and OneDrive. Each carries its documented expected value rather than an assumption that
on is always right — the mismatch email is kept by leaving `BlockSendLabelMismatchEmail` set to
`False`, so that one is checked for false.

Scope is held as a table keyed by solution area, so adding or removing an area is a single edit
rather than a rewrite. Where an area carries no rule the report says so rather than staying silent,
which is what keeps a populated snapshot from implying an assessment nothing performed.

Insider Risk Management and information barriers carry no check for the same reason: neither exposes
a documented read-only interface, so there is nothing to read without changing the tenant.

Licensing and SharePoint sites are collected as context. The coverage matrix in
the report shows which areas carry rules and which are there for background, so a populated snapshot
never implies an assessment that no rule performed.

Two checks read through Exchange Online rather than the compliance session.
`UnifiedAuditLogIngestionEnabled` is documented as **always `False` in Security & Compliance
PowerShell even when auditing is on**, so reading it there would report every tenant as unaudited.
Exchange messaging records management policies are only exposed there at all. That is why the run
signs in to Exchange Online as well.

Signing in to both, though, is what makes routing matter: the two connections load separate modules
that export around eighty of the same cmdlet names, and the one imported last wins an unqualified
call. Left alone, a compliance read reaches Exchange instead — the tenant policy configuration fails
outright, and role group membership comes back describing Exchange rather than Purview. Every
compliance read is therefore resolved through the module its own connection loaded.

### Configuration against activity

An ordinary run reads Activity Explorer through `Export-ActivityExplorerData`. Content Explorer is
read through `Export-ContentExplorerData` only when at least one sensitive information type is named
with `-InsightTag`. The oversharing inventory reads existing SharePoint data access governance report
metadata. All three are read-only, and `-SkipInsights` omits them for a faster, configuration-only
run.

Configured sensitivity labels are deliberately not turned into Content Explorer requests. The
cmdlet documents a `TagName` parameter but does not establish which sensitivity-label identity that
name represents, so a sensitivity-label item total would rest on an unverified join. The report
withholds it rather than guessing.

Every non-empty `-InsightTag` value is treated as an explicit sensitive information type name.
Repeated names are collapsed case-insensitively, then each type is queried and rendered on its own.
One item can match several sensitive information types, so their counts are never added together.
If one request fails or returns an invalid `TotalCount`, that type says **Not checked** while readable
types retain their own exact counts.

Each count spans supported Exchange, SharePoint, OneDrive and Teams locations. It is delayed current
inventory rather than a rolling 30-day amount: counts can take seven days to update, SharePoint files
can take 14 days, and SharePoint or OneDrive files encrypted by sensitivity labels are not included.
It covers only data visible to the signed-in account, which administrative-unit role assignments can
narrow.

The separate row **Sensitivity labels applied in the last 30 days** reports recent application
operations. One item can produce several applications, so this is never turned into a distinct-item
count and drives no finding. A zero means no matching application was recorded in that finite window;
it does not mean no content is currently labelled. Core Microsoft 365 activity usually takes 60 to 90
minutes to appear, other workloads can take longer, and sensitivity-label activity from Power BI and
Defender for Cloud Apps is not included.

Activity Explorer uses `LabelApplied`, `LabelChanged` and `LabelRemoved` for both sensitivity and
retention labels. A generic event is counted only when its returned label fields establish that it
describes a sensitivity label. Filter parameters use compact names such as `LabelApplied`, while
returned rows can use friendly names such as `Label applied`; both are matched only after controlled
case and separator normalization. Every page must also complete, and every filtered row must carry
a recognized activity. If the service truncates the query, omits that detail, returns an unknown
activity name, or leaves the label kind ambiguous, the report says **Not checked** rather than
manufacturing a number. A complete broad activity scan is the only fallback if the filtered label
query cannot supply one.

The auto-labeling rows correlate rules only to policies whose returned mode is `Enable`. Rules on
policies in simulation or switched off are excluded, as are rules explicitly disabled. Direct
`ContentContainsSensitiveInformation` conditions and the documented `AdvancedRule` JSON shape are
read separately; only `sensitivetypes` below an explicit
`ContentContainsSensitiveInformation` condition are counted, so label, group and metadata names
cannot be mistaken for sensitive information types. Missing policy mode or linkage, missing rule
state, an active policy with no returned rule, or any malformed, unsupported or partially decoded
condition makes the amount **Not checked**. A complete active rule that uses only a classifier,
metadata, sharing or another non-SIT condition can truthfully report zero.

DLP earns enforcement credit only when a rule correlates to exactly one policy, that policy returns
exact `Mode = Enable`, and the rule returns an authoritative Boolean `Disabled = false`. Simulation,
disabled policies, disabled rules, zero or multiple parent matches, partial reads and missing state
fields cannot support an enforcement verdict. Classic retention similarly requires a Boolean enabled
state, exact `Mode = Enforce`, at least one linked rule and a classic retention rule type rather than
publishing, auto-apply or adaptive-retention configuration.

Application retention is a separate model. `Get-AppRetentionCompliancePolicy` supplies policy scope
and enabled state; `Get-AppRetentionComplianceRule` supplies the separately linked rule. Application
scope can arrive as separate values or as one comma-delimited value. It is split, trimmed and
deduplicated case-insensitively before exact known values are matched; neither a substring nor the
policy name supplies scope. A Copilot, Teams or Viva Engage policy is called active only when its
scope is complete, `Enabled` is the Boolean `True`, and a rule joins to it unambiguously. No policy
`Mode` is assumed. Communication compliance policy objects, by contrast, establish only that
definitions are configured; current inspection, health and last scan remain portal checks.

Only counts survive. Activity rows name users, files, devices and IP addresses, so they are
aggregated and discarded; each explicitly requested Content Explorer type is queried with a page
size of one, only its summary `TotalCount` is accessed, and the returned record is discarded. Only
the List Viewer role is used; Content Viewer is never requested. No user, file name, location or
content reaches the snapshot.

The advanced-hunting rows are also aggregate-only and deliberately positive-only. Policy matches,
insider-risk sharing, Copilot activity and Microsoft 365 app-connector events prove only that an
event was recorded during the stated 30-day window. They do not establish current policy state,
recording health, connector status or connector health. A zero proves none of those features is off.
Derived counts must be non-negative and internally possible; for example, blocked DLP events cannot
exceed DLP matches.

### Label taxonomy

The report compares your label tiers against the documented default taxonomy — Personal, Public,
General, Confidential, Highly Confidential — and names where they coincide.

That comparison is a reference, not a score. Organisations classify to their own risk model, so a
tier you do not have is a design choice to confirm rather than a gap to close, and no rule fails for
it. Matching is by name only, because a synonym table would be invention: a tier called *Restricted*
serving the same purpose as *Highly Confidential* reads as organisation-specific. What the rules do
check is structural and name-independent — whether there is more than one tier at all, and whether
precedence between them is deterministic.

Hierarchy is evaluated only when every enabled label returns its `ParentId` property. A present null
value is valid evidence of a top-level root; a missing property means the hierarchy was not fully
read. A duplicate-name warning and rename recommendation require two proven siblings, including two
roots with explicit null parents. The same leaf name under different parents is not treated as a
duplicate, and incomplete hierarchy evidence never recommends renaming anything.

### Progress over time

Every run is recorded, so the next one shows what moved. Records go to a per-user folder by default,
which means a comparison works wherever you run the script from. `-BaselineFolder` puts them
somewhere else and `-NoRecord` skips it.

Rule outcomes and tenant opt-ins are separate movement populations; their totals are never combined.
Only a change between two assessed outcomes counts as progress or regression. If this run lacks the
evidence needed for a verdict, the row says **Could not assess this run** and stays out of movement;
that includes `Pass` to `NeedsReview`. Evidence unavailable in both runs is classified separately as
unavailable. A check first assessed in this run is newly assessed, not improved. New or removed rules,
rule-version changes and applicability-only transitions are also kept outside tenant movement.
Maturity percentages are compared only when measured over the same number of assessed steps.

Positive historical signals such as **Seen recently** are not scored as progress. Saved maturity
counts must be valid, non-negative and internally possible; malformed values remain non-comparable
instead of being cast to zero.

Tenant opt-ins still have their own comparison because no finding covers most of them. A baseline
recorded before opt-ins were tracked holds none, so that population is left out until two runs carry
comparable opt-in state.

Comparison is refused outright across tenants unless `-AcrossTenants` names the record explicitly.

A posture record holds rule outcomes and opt-in states only — no policy names, no label names, no
reasons, and no current values. It is a far less sensitive artifact than a snapshot.

### Leaving no trace

Sign-in is reused wherever possible. A service that already has a live session is left alone, and
Microsoft Graph is only re-authorised when a scope it needs is actually missing rather than to
refresh what is already there. At the end the run signs out of the sessions it opened, so a
read-only assessment does not leave a signed-in session behind it; sessions you opened yourself are
never touched. `-KeepSignedIn` preserves the token cache each module keeps instead, which lets a
second run start without any prompt at all.

The Exchange endpoints sign in first, and the account the first of them used is handed to the
second, so the address is typed once rather than at every prompt. That order is deliberate:
`Microsoft.Graph.Authentication` and `ExchangeOnlineManagement` each ship their own copy of MSAL and
.NET keeps only the first one loaded, so connecting Graph first leaves the Exchange modules binding
their newer broker extension against Graph's older MSAL, which throws before any sign-in prompt
appears. Graph therefore goes last, and takes no account hint because it accepts none — by that
point the browser usually has a session to reuse. Nothing but the user principal name is carried
across; no password, token or cookie is read or passed by the script.

If the MSAL broker fails anyway, the sign-in is retried once with Microsoft's documented
`-DisableWAM` switch rather than reported, since nothing had been asked of you yet. Windows on Arm
starts with that path because the broker can stop before opening its browser prompt. The non-WAM
sign-in keeps its browser instructions visible; the module's first token error matters only if the
retry also fails.

SharePoint sign-in uses the system browser, which is what makes passkeys and other platform
authenticators available. The module's own dialog falls back to a password.

The SharePoint module has its own local Windows PowerShell session instead of sharing PowerShell's
process-wide compatibility session. This keeps a SharePoint Client assembly loaded by another
module from breaking SharePoint import. The run removes only the command proxy and session it
created; an existing session is reused and left alone. If the module still cannot load on Windows,
the console shows its sanitized import error rather than incorrectly reporting Windows as the
unsupported platform. `-KeepSignedIn` keeps the proxy and its session together so the connection
remains usable.

Your SharePoint admin URL is worked out from the tenant's initial domain rather than asked for.
That reads `verifiedDomains`, which Microsoft documents as available with only `User.Read`, so it
costs no extra consent. It is a good guess rather than a certainty — a tenant whose SharePoint
hostname differs from its initial domain will not match. If the sign-in fails, the URL it tried is
shown and you are asked for the right one rather than the run failing; a tenant name on its own is
enough, and pressing Enter carries on without SharePoint. `-TenantAdminUrl` skips the question.

Temporary files are removed on the way out. Cleanup runs on a normal exit, an error and Ctrl+C
alike.

### Watching it work

Every check is named before it runs and closed with its result and elapsed time when it returns, so
a slow tenant call shows what it is waiting on rather than looking hung.

If the label list omits expanded protection settings, the assessment reads the affected labels
again by exact identifier. That sequence shows `Label x of y` progress without displaying a label
name or identifier, so a slow service response is visible rather than looking like a stopped run.

### Who you signed in as

Before anything is collected, the run prints the account it is about to read the tenant with, the
services it reached, and the roles that account holds. Entra roles come from the account's own
memberships, which Microsoft documents as needing only `User.Read`, so nothing beyond the
permissions listed above is requested. Purview role groups are readable only by a *Role management*
holder; where they cannot be read the run says so rather than printing an empty list, because
holding no roles and not being allowed to look are different answers.

When at least one in-scope `-InsightTag` was supplied, this is also where the run offers the
**Content Explorer List Viewer** role group if the account lacks it. No tag means no Content Explorer
read and no role prompt. A role granted at this point still counts for the run in progress, so the
offer comes before collection rather than as a note at the end. You can wait while it is added, skip
the requested counts for this run, or carry on and let each report as not permitted. A role granted
part way through only reaches a new session, so accepting the offer signs in again rather than
retrying on the session that was already open. Unattended runs are told rather than asked, and carry
on.

## The report

A run writes `report.html`, `findings.json` and `snapshot.json` into a `PurviewReport` folder,
replacing whatever was there before. The HTML has a fixed section order:

1. Tenant at a Glance
2. Executive Summary
3. Progress Since Last Assessment
4. Prerequisites and Tenant Opt-ins
5. Copilot and AI Controls
6. Label Taxonomy Comparison
7. Remediation Checklist
8. Purview Solution Coverage Matrix
9. Blueprint Coverage
10. Findings by Severity
11. Quick Wins
12. Strategic Improvements (by severity)
13. Licensing and SKU Analysis
14. Limitations of This Assessment

Section 3 appears only when a baseline from an earlier run is available and comparable, so a first
assessment does not carry an empty progress heading.

### Copilot and AI controls

Copilot answers in the security context of the person asking, so what governs it is the Purview
configuration already in the tenant rather than a separate product. This section gathers the
controls that decide what it can reach and what is recorded about it, which otherwise sit across
labels, DLP, SharePoint, retention, communication compliance and activity explorer.

It is split into two bands. The first covers Microsoft 365 Copilot itself. The second covers AI
beyond Copilot, because Data Security Posture Management reaches third-party sites, agents and
enterprise AI apps, and a policy covering ChatGPT is not a policy covering Copilot — reporting them
together would say the tenant governs Copilot when what it governs is people pasting into a browser.

Sensitivity-label encryption is an access-control layer, not a blanket Copilot exclusion. Copilot
uses the requesting person's Microsoft 365 authorization and effective encryption rights. Someone
the encryption policy does not authorize cannot decrypt the content. For someone who is authorized,
Copilot needs both **VIEW** and **EXTRACT** to summarize it; VIEW without EXTRACT permits a link to
the item but not a summary. A label-wide rights definition still cannot prove every item's outcome,
because permissions can be assigned by the user or changed independently on the item.

Cloud labels are read through Security & Compliance PowerShell with
`Get-Label -IncludeDetailedLabelActions`. If the bulk response omits an encryption action, only the
affected label is read again, by its exact non-empty GUID; exactly one response carrying that same
GUID is accepted. On that accepted detailed response, an explicitly null expanded action proves the
label does not encrypt. A missing property, failed read, mismatched identity, duplicate response or
contradiction remains unresolved. A label name is never used as its identity.

The **Sensitivity label encryption** control is **In use** as soon as one label is proven to apply
encryption. Unresolved companion labels make that count a lower bound; they do not erase positive
security evidence. If none is proven and any state remains unresolved, the control is **Not read**.
Only a complete set of explicit non-encrypting states produces **Not configured**. A missing static
rights definition does not negate a proven encryption action and is never used to claim that content
is universally available to, or excluded from, Copilot.

No property names the Copilot DLP location, so the section settles it two other ways. Microsoft
documents selecting that location as disabling every other location on the policy, which makes a
policy holding any other location provably not a Copilot one; and it documents by name the Copilot
policy Data Security Posture Management creates in one click. Those signals identify intended scope;
they do not prove enforcement. The control is **As recommended** only when the policy is in exact
`Enable` mode and has an enabled linked rule. A policy naming no readable location and carrying no
documented name leaves scope open, and that case defers to the portal.

Retention for Copilot is read separately from everything else, because Microsoft moved prompts and
responses to their own location served by different cmdlets. The current application scope is
normalized first, then matched only to the exact documented `User:M365Copilot` value. If no current
match exists, a narrow classic read asks only for the older Teams policy family. An empty classic
result, or records carrying only the exact `User:TeamsChatUserInteractions` migration scope, proves
that family does not cover Copilot. Missing or partial classic evidence reads **Not read**; any
other classic scope reads **Needs review**. **Not configured** appears only when both policy models
prove absence. A policy name and the classic `Workload` property are never treated as scope.

### Prerequisites and tenant opt-ins

Several Purview capabilities ship switched off, so that adopting Purview does not change behaviour
for users overnight. A tenant can therefore look configured while labels are never processed for
PDFs, container labels never appear, or nobody is told when a document is more sensitive than the
site holding it. This section lists current state where a supported interface exposes it, otherwise
the strongest recent evidence or a portal confirmation, plus why the setting matters and its
recommended state — which for two of them is off rather than on.

It leads with a count of what needs attention, so the section can be read at a glance before anyone
reads a word of it.

What can be read is read: the SharePoint tenant switches through `Get-SPOTenant`, co-authoring and
the Teams DLP extension through `Get-PolicyConfig`, container labelling through `GET /groupSettings`,
and unified audit logging through its own check. Two are inverted — `BlockSendLabelMismatchEmail`
and `DisableDocumentLibraryDefaultLabeling` are both kept at `False` — and the current value is
shown against the expected one so nobody has to remember which way round each switch runs.

Insider risk analytics remains portal-only. DLP analytics and sharing insider-risk detail have
positive indicators: a generated analytics recommendation is **Evidence found**, and behavior
recorded in Defender during the last 30 days is **Seen recently**. Neither proves the switch is on
now, and an empty result never proves it is off, so current state still requires the portal. That is kept
distinct from *not read this run*, which means a service the tool can read was not connected and a
further sign-in would settle it.

Device onboarding uses privacy-safe endpoint totals. A device reporting endpoint DLP enabled proves
monitoring is operating for at least that device. Defender onboarding or status reporting without
endpoint DLP does not reveal the Windows or macOS monitoring switch, so the row names what was seen
and asks for portal confirmation rather than reporting the switch off. Missing or malformed totals
make the row **Not read**.

Four Defender for Cloud Apps settings appear here too, because Purview labelling and DLP reach SaaS
files through them. Microsoft 365 app-connector events are isolated by documented `AuditSource` and
application values; their presence is **Seen recently**, not a current Connected or healthy verdict.
The inspect-protected-files consent is **Granted** only when a documented Microsoft Cloud App Security
app id holds the exact Azure Rights Management `Content.SuperUser` role. The other two — file
monitoring and sensitivity-label scan settings — expose no documented read, so they are marked
*confirm in the portal*. Each is enabled only in the portal; the assessment reads, never writes.

### Tenant at a glance

What the assessment observed, summarised rather than judged, and the section to open a conversation
with: labels defined, how many a publishing policy reaches users with, DLP policies and rules proven
to be enforcing versus in test mode, classic retention policies proven enabled and linked to rules,
application-retention policies assessed with their separate rules, retention labels declaring
records, configured Exchange policies that carry at least one retention tag, configured communication
compliance definitions, OCR state, unified audit logging, organisation-specific sensitive information
types, independent delayed counts for explicitly requested sensitive information types, and separate
recent activity counts.

The OCR row uses only the OCR configuration that backs the portal. Direct records, nested
`ResultData` wrappers and JSON text are unwrapped recursively; malformed or unrecognized payloads
make the read partial rather than proving OCR is off. It reports *on* only when `Enabled`, `Mode`,
`IsValid` and `IsOcrUsageBlocked` agree that OCR is enabled, valid and unblocked, and at least one
recognized workload scope was returned. The portal projects `OcrMode` as `Active`, while the direct
cmdlet can project the same enabled record as `None`; that exact `None` value is neutral and never
establishes *on* or *off* by itself. A successfully returned empty configuration or a coherent
disabled record reports *off*. A partial result, missing or unrecognised state, contradiction,
invalid record, usage block, or enabled record without a proven Exchange, SharePoint, OneDrive,
Teams or Devices scope reports *not checked*. The legacy `TextExtractionConfig` value from
`Get-PolicyConfig` is not used as an OCR switch because it can disagree with the current portal
state. Only aggregate workload names are retained; configuration names and scoped location values
are discarded.

One cmdlet returns retention policies, auto-apply label policies and label publishing policies
together, which no portal page shows as a single number, so they are counted separately. Policies
Adaptive Protection wrote for itself are separated again: the portal does not list them beside the
ones an admin made, and including them makes the total disagree with the Label policies page.

Exchange messaging records management is reported independently of those modern Purview policies.
Its value counts configured Exchange policy definitions with at least one retention tag, including
`Default MRM Policy`; a definition with no tags contributes no retention action and is not counted.
If tag attachment is unreadable for any returned policy, the value is **Not checked** rather than a
partial total. The collector does not read mailbox policy assignments, so the row never claims that
a configured policy currently governs a mailbox.

A label is not something that gets switched on or off: it either exists or it does not, and what
decides whether anyone can use it is a label publishing policy that includes it. So the count that
matters is not how many labels were created but how many reach a user, and a label defined but left
out of every publishing policy is reported as exactly that.

Where several publishing policies exist, the headline figure is the distinct set of labels reaching
at least one user, with a count per policy beneath it. Summing the policies would double-count every
label that appears in more than one, and a single number on its own cannot be read either way.

Built-in sensitive information types are deliberately left out of the count. Every tenant has the
same ones, so they say nothing about this customer; only types the organisation published itself
are reported.

A row reading *not checked* means a trustworthy total could not be established, and says why beside
it — a missing connection or role, incomplete pagination, ambiguous event type, unreadable tag,
invalid total, or collection limit. That is deliberately never shown as `0`, because incomplete or
ambiguous data is not evidence of absence.

### The checklist

The headline section, and the one to hand someone: what is done, what is left, and in what order to
work it.

- **To do** — worst severity first, and where a single command would fix it that command is shown
- **To check by hand** — the tool could not settle it, so a person must
- **Done** — checks that passed
- **Not checked** — no data, with the connection that would supply it

Progress counts only the checks that returned a verdict. Items that could not be checked are
excluded rather than counted either way, so the number never flatters itself by ignoring the things
it could not see.

### What a finding tells you

Each one that needs action answers four questions: **what we found**, listing the specific labels,
policies or settings involved; **why it matters**; **what to do**; and where to read more, linking
the Microsoft page the recommendation came from.

The guidance is attached to the finding rather than gathered into a reference table at the end,
because a list of every source the tool knows about is not much help when you are trying to fix one
thing.

### Blueprint coverage

Where the tenant stands against the Secure by Default and Data Security Posture Management
blueprints. The blueprints are the reference the checks were written against; the section reports
current state rather than progress through a programme.

Only steps this tool can actually check are listed. A step with no check behind it would say nothing
about the tenant, only about the tool, so it is left out rather than shown as an empty row. There is
no percentage, deliberately: most steps carry one check or none, so a percentage would announce that
a model is complete on the strength of a single passing rule. An unlicensed capability does not
count as done either — not owning something is not the same as having implemented it.

## Where this sits against Microsoft's own assessment

Microsoft publishes a [Zero Trust Assessment](https://learn.microsoft.com/security/zero-trust/assessment/get-started)
that scores a tenant across identity, devices, network and data. Every rule here falls in the data
pillar, so the two are complements rather than alternatives: run theirs for breadth across the four
pillars, this for depth on Purview.

They differ in what they cost to run. The Zero Trust Assessment needs Global Administrator for the
first consent, around twenty Graph permissions, an Azure sign-in, and Microsoft warns it can take
over a day on a large tenant. It also does not support Windows on Arm. This script asks for a
handful of read-only Graph scopes, finishes in minutes, and runs anywhere PowerShell 7 does.

Their report and this one both name real policies and settings. Treat either as sensitive and share
it only with people entitled to see the tenant's configuration.

## Reading the results accurately

A few qualifiers change how a finding should be read:

- **Items matching *sensitive information type*** appears only for a type explicitly named with
  `-InsightTag`. Each delayed current count stands alone: an item can match several types, so adding
  the rows would double-count. A failed or malformed request makes only that type `Not checked`.
  Sensitivity-label item totals are withheld because the cmdlet does not document which label
  identity its `TagName` parameter accepts.
- **Sensitivity labels applied in the last 30 days** counts recent application operations, not
  distinct items. One item can be counted more than once. Core Microsoft 365 activity usually appears
  after 60 to 90 minutes; other workloads can take longer, and sensitivity-label activity from Power
  BI and Defender for Cloud Apps is not included. A zero means only that no matching application was
  recorded during that period; it does not establish how many items currently carry labels.
- Activity Explorer shares generic applied, changed and removed event names between sensitivity and
  retention labels. A row that does not establish which kind it describes, or a query whose last page
  was not confirmed, makes the value `Not checked` rather than zero.
- Active auto-labeling SITs are counted only from enabled rules linked to policies returned in
  `Enable` mode. Simulation and disabled policies do not contribute. Incomplete linkage, state or
  condition data makes the value `Not checked`; a decoded subtotal is never presented as the total.
- Explicit Content Explorer counts can take seven days to update, SharePoint files can take 14 days,
  and SharePoint or OneDrive files encrypted by sensitivity labels are not included.
  Administrative-unit role scope can narrow the view. Only summary counts are retained, never an
  item record, name, location or content.
- Cmdlet *output* property names are not documented on Learn the way parameters are. Collectors
  normalise against candidate names and declare anything absent; where a property a rule needs is
  missing, the finding is `NeedsReview` rather than a guess.
- Evidence is a static table inside the script, captured on the dates each entry records.
  `-CheckEvidence` compares each page against the wording it was written against, so a rewrite is
  detected — but a page that changed meaning without changing wording, or changed somewhere the
  fingerprint does not cover, would still pass.
- A full live collection, assessment, HTML report and PDF render have been exercised against a
  Microsoft 365 tenant. Fabricated suites cover failure and ambiguity boundaries that a healthy live
  run does not produce.

## License and disclaimer

Licensed under the [MIT License](LICENSE).

The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official
Microsoft guidance, and every check links the page it came from. This script is not a Microsoft
product: it reads what is configured in a tenant and reports it against those recommendations. It
describes configuration observed at a point in time and is not a compliance certification.
