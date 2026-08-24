# Purview Health Inspector

A single PowerShell script that assesses Microsoft Purview configuration and aggregate
observations against evidence-based rules. Evaluation of a collected snapshot is deterministic; the
report keeps current configuration, recent telemetry and delayed content inventory distinct. It
adds advisory subscription context and produces a customer-facing report. Findings carry source
references, recorded retrieval dates and confidence levels; the rules remain the tool's interpretation
of that guidance, not Microsoft certification.

**Supported scope:** Microsoft 365 commercial cloud, including education tenants in that cloud.
GCC, GCC High, DoD and China are not supported or validated by this release. Education is not a
separate environment option or a new licensing requirement; inclusion does not imply feature parity.

**What it is not.** The assessment does not change tenant configuration. It does, though, *write*
remediation: where a fix exists it prints the command, and the report can generate a PowerShell
script for the changes you tick. Those scripts are yours to review
before you run them. Each one explains every change as it reaches it and applies it only if you
answer yes, but read the file first and put it through change control — the changes are tenant-wide.
It is not a Microsoft product — it reads what is configured and reports it against the Purview
Deployment Blueprints and Secure by Default guidance, which are Microsoft's own.

Everything is in [Invoke-PurviewAdvisor.ps1](Invoke-PurviewAdvisor.ps1). Copy that one file
anywhere and run it.

## Read-only assessment scope

**Collection does not create, modify, publish or delete tenant configuration.** It reads settings
and existing evidence through service cmdlets, including `Export-ActivityExplorerData` and
`Export-ContentExplorerData`. Advanced hunting uses read-only aggregate KQL through Graph's
[`POST /security/runHuntingQuery`](https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0);
an HTTP POST is not necessarily a configuration write. The assessment does not generate new
SharePoint data access governance reports or execute the remediation it writes.

This is not a no-side-effects guarantee. The script connects and disconnects services, can install
or update local dependencies, writes reports and temporary files, and normally saves posture history.
Sign-in and consent can create service logs and authentication state. Review requested permissions
before consenting; generated remediation is a separate, potentially tenant-wide write operation.

Tenant sign-in is delegated to Microsoft modules. The script has no tenant password or token
parameter, but those modules handle tokens and may cache them. In particular,
[Microsoft Graph defaults to a persistent CurrentUser context](https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands).
PDF protection separately prompts for a password. Neither feature promises that secrets never
exist in process memory or that all authentication state is removed afterward.

## Quick start

Downloaded it from GitHub? Windows may mark the script as internet-originated. After reviewing the
file and its source, clear that mark if your execution policy requires it:

```powershell
Unblock-File -Path .\Invoke-PurviewAdvisor.ps1
```

Then run it:

```powershell
.\Invoke-PurviewAdvisor.ps1
```

That is the whole thing. It installs what it needs, signs you in to anything you are not already
connected to, collects, assesses, and writes an HTML report into a `PurviewReport` folder in the
current directory — then opens it. Individual output files are overwritten; the folder is not
emptied. Use a fresh `-ReportFolder` to keep runs separate, or `-NoOpen` to leave the report closed.

Alongside the report you get `findings.json` (the findings as data), a live-run `snapshot.json` (what
was collected, so it can be re-assessed later without going back to the tenant) and
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

A remediation script downloaded through the browser may have the same internet-origin mark.
Review it before unblocking:

```powershell
Unblock-File -Path .\Set-PurviewTenantOptIns.ps1
```

The locally generated copy normally has no download mark, but still obeys your execution policy.
[Execution policy](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies)
can require signed scripts, and Group Policy takes precedence. Unblocking does not override those
requirements; do not weaken an organization-managed policy to run this assessment.

Launched it from Windows PowerShell 5.1? Once the script is allowed to execute, it attempts to
restart in PowerShell 7 and carries your arguments across. If PowerShell 7 is not found, it prints
installation guidance and exits.

If you would rather manage your own sessions, connect first and pass `-SkipConnect`. You do not need
every service connection — unavailable collector data is reported rather than guessed at. Security
& Compliance and Exchange Online are separate connections, alongside Graph and SharePoint Online.
You must ensure existing sessions belong to the intended tenant in the supported commercial cloud.
Neither `-SkipConnect` nor normal session reuse independently verifies their cloud. Generated
remediation has the same commercial-only scope and does not independently verify existing sessions'
cloud either; its header records that boundary.

| Switch | Effect |
| --- | --- |
| *(none)* | Collect from your tenant and assess |
| `-SnapshotPath` | Assess a snapshot already on disk |
| `-SnapshotOutputPath` | Live snapshot destination instead of `ReportFolder\snapshot.json` |
| `-TenantAdminUrl` | Your SharePoint admin URL, if it cannot be worked out for you |
| `-Environment` | `Commercial` is the default and only accepted value, including education tenants in that cloud |
| `-Solution` | Assess only the named Purview solutions instead of all of them |
| `-Brief` | Write the condensed report instead of the full one |
| `-AcrossTenants` | Compare against a `-BaselinePath` record from a different tenant |
| `-SkipConnect` | Sign in to nothing; use only sessions you established |
| `-KeepSignedIn` | Skip the run's sign-out attempt and preserve its connected SharePoint proxy/session |
| `-ReportFolder` | Output directory; defaults to `PurviewReport` under the current directory |
| `-Demo` | Render a full report from fabricated data, with no tenant, sign-in or licence |
| `-NoOpen` | Do not open the report when it is finished |
| `-DarkMode` | Render the report on a dark background |
| `-PdfReport` | Also render a PDF (needs Edge, Chrome or Chromium) |
| `-ProtectPdf` | Render and password-encrypt a PDF with qpdf; other outputs remain unencrypted |
| `-WordReport` | Also write a `.docx` (needs Word on Windows) |
| `-CheckEvidence` | Fetch evidence-table URLs and compare available content fingerprints; not a semantic validation |
| `-ExportRules` | Write the rules and citations to a JSON file you can edit |
| `-RuleFile` | Assess using rules from that file |
| `-SkipInsights` | Skip Activity Explorer, requested Content Explorer counts and SharePoint DAG metadata; advanced hunting still runs when in scope |
| `-InsightDays` | Rolling Activity Explorer operation window in days. Defaults to 30; it does not limit Content Explorer counts requested with `-InsightTag` |
| `-InsightTag` | Sensitive information type names to ask Content Explorer for. Nothing is requested automatically; every delayed count is shown separately and never summed |
| `-BaselineFolder` | Where to keep posture records, if not the default per-user folder |
| `-BaselinePath` | Compare against one specific posture record |
| `-NoRecord` | Do not save posture history or discover an automatic baseline; explicit `-BaselinePath` still works |
| `-RedactTenant` | Blank top-level tenant name and id, not identities or names elsewhere in the artifacts |
| `-IncludeSites` | Enumerate SharePoint sites (slow on a large tenant) |
| `-SiteLimit` | How many sites `-IncludeSites` will enumerate before it stops |
| `-SkipModuleInstall` | Use only modules already installed |
| `-PassThru` | Return findings as objects to filter or pipe |

## Prerequisites

PowerShell 7 is required. Available collection and export features depend on the operating system,
installed modules, cloud and service permissions; PowerShell support alone does not establish full
feature parity. The bootstrap can relaunch from Windows PowerShell 5.1 as described above.

For live collection the script installs any missing module to **CurrentUser** scope, so no elevation
is needed. Pass `-SkipModuleInstall` to opt out.

| Module | Service | Notes |
| --- | --- | --- |
| `ExchangeOnlineManagement` | Security & Compliance and Exchange Online | Separate service connections in PowerShell 7 |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online | Windows only; its required commands run in a fresh local Windows PowerShell session created with `-UseWindowsPowerShell`, as Microsoft documents for PowerShell 7 |
| `Microsoft.Graph.Authentication` | Microsoft Graph | Runs natively on PowerShell 7 |

### Permissions and access

The assessment brings together configuration from Purview, Exchange Online and SharePoint with
subscription information, supporting directory settings and historical security signals from
Microsoft Graph. This helps distinguish what is configured, where activity has been observed and
what still needs checking. Historical activity is not proof that a control is effective today.

These five read-only delegated Graph permissions support that picture. They do not replace the
service-specific roles listed below.

| Graph permission | Purpose in the assessment |
| --- | --- |
| `LicenseAssignment.Read.All` | Show tenant subscriptions as licensing context, without treating them as proof of each user's entitlement. |
| `GroupSettings.Read.All` | Check the directory setting that enables sensitivity labels for groups and Teams. |
| `User.Read` | Identify the signed-in account's direct Entra role memberships and help locate the tenant's SharePoint admin endpoint. |
| `ThreatHunting.Read.All` | Add historical signals about endpoint DLP, data-security activity, Copilot use and cloud-app connections. The script's queries return aggregate counts only. |
| `Application.Read.All` | Look for existing consent that allows Defender for Cloud Apps to inspect protected files; this evidence still needs confirmation in the product. |

`Organization.Read.All` and `Directory.Read.All` also work for subscribed SKUs, but Microsoft lists
them as *higher privileged*, so they are deliberately not requested.

Use service-specific roles with the least access that permits the selected reads:

| Service or feature | Authorization to arrange |
| --- | --- |
| Security & Compliance | Appropriate [Purview roles and role groups](https://learn.microsoft.com/purview/purview-permissions) for the selected cmdlets. Global Reader is not a blanket prerequisite or proof of access to all collectors |
| Exchange Online | Exchange RBAC exposing the organization and retention-policy reads; Purview permissions alone do not establish it |
| SharePoint Online | [`Get-SPOTenant`](https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell/get-spotenant) requires SharePoint administrator access. This role can write settings even though the assessment only reads them |
| Advanced hunting | `ThreatHunting.Read.All` plus access to the underlying Defender data; a scope grant alone does not ensure each queried table is available |
| Content Explorer | Only needed for requested `-InsightTag` counts: the data classification list viewer role, typically through **Content Explorer List Viewer**. It permits item/location listing, not a counts-only privilege. **Content Explorer Content Viewer** separately permits contents and item names and is not requested. See [Content Explorer permissions](https://learn.microsoft.com/purview/data-classification-content-explorer) |

Do not assign Global Administrator merely to make all reads succeed. Consent, service RBAC and
licensing are separate requirements; leave unavailable areas uncollected if broader access is not
appropriate.

SharePoint collection runs on Windows, because its module does. Oversharing metadata depends on
[SharePoint Advanced Management prerequisites](https://learn.microsoft.com/sharepoint/sharepoint-advanced-management-prerequisites)
and an existing report. A qualifying base subscription and assigned Copilot license can unlock
Copilot-related capabilities; the Plan 1 add-on is another route, and some features require it.
`-PdfReport` uses Edge, Chrome or Chromium and `-WordReport` uses Word on Windows; where
neither is present the HTML and JSON reports are still written. PDF rendering uses a temporary
blank browser profile instead of your normal browser session, waits for the complete file, and
attempts to remove that profile afterward. Treat non-Windows PDF export as unverified rather than
assuming browser availability establishes support.

### Password-protecting the PDF

`-ProtectPdf` implies PDF export and asks twice for an opening password, then uses qpdf's 256-bit
AES encryption. Keep the password securely: the assessment provides no password recovery.

A browser can print a PDF but cannot encrypt one, so this needs
[qpdf 11.7.0 or later](https://qpdf.readthedocs.io/en/stable/cli.html), which supports the flag-form
encryption arguments used here. An existing executable is not version-checked by the script.
If it is missing, the script attempts installation through winget on Windows or Homebrew on macOS.
`-SkipModuleInstall` declines that as it does for the modules. Linux installation instructions are
printed instead. Package-manager availability and local installation permissions still apply.

The password is collected as a `SecureString`, but conversion for qpdf temporarily creates plaintext
memory buffers. The script attempts to clear those buffers afterward. qpdf receives its encryption
arguments through `@-` (one argument per standard-input line), rather than placing passwords on the
process command line. A separate random owner password is generated; printing and copying
restrictions are not configured.

Rendering creates a plaintext PDF before encryption. On failure the script attempts deletion, but
cleanup is best effort, not secure erasure. HTML, JSON, snapshots, posture records and Word exports
are not encrypted by `-ProtectPdf`. Use an access-controlled output folder and verify the resulting
files before sharing them; skipped exports can leave an older PDF in that folder.

## How to read the output

### Finding statuses

| Status | Meaning |
| --- | --- |
| `Pass` | Available evidence satisfied this rule's assertion; not proof of effective deployment or compliance |
| `Area for improvement` (`Fail`) | Evidence did not satisfy an assertion reported as a failure |
| `Warning` | An assessed condition warrants attention; generic Medium/Low-severity assertion failures use this status, while named analyses can assign it directly |
| `NotCollected` | Required collector data was unavailable, failed or absent; causes include connection, permission and service limitations |
| `NeedsReview` | The data was ambiguous, or a property the rule needs was not returned |
| `Unsupported` | The tool does not support collecting this check; not a claim that the product has no API |
| `NotLicensed` | Historical licensing-exclusion status retained for older findings and posture records; current assessment no longer generates it |

Only the display phrase **Area for improvement** maps to stored `Fail` in `findings.json` and
posture records. Other statuses retain their own values. Generic Critical/High-severity assertion
failures use `Fail`; preview guidance can yield `NeedsReview` instead. Partial reads can still
support a limited verdict when required operands are present, with reduced confidence.

The unresolved statuses matter as much as the verdicts. `NotCollected` identifies missing evidence,
not a configuration failure; a further connection does not necessarily resolve it. `NeedsReview` carries no remediation command
and recommends verifying the current state before acting, because missing evidence does not establish
that a setting should change. A check that does not apply is withheld from customer output entirely;
internal applicability bookkeeping is not a tenant observation.

### Licensing

Licensing is advisory, not a gate on configuration checks. **Licensing and SKU Analysis** summarizes
recognized Purview-related products, excluding deleted records. The embedded registry contains
**13 verified friendly-name and positive-advisory entries**; it selects the customer summary, not
an exhaustive Microsoft catalog. A friendly name requires a coherent `skuPartNumber`/`skuId` pair
from that registry. Other products and deleted records remain in **Technical details**, using the
returned part number, SKU ID, or **Unnamed subscription record** when no friendly name is known.
An empty summary does not establish that Purview licensing is absent.
Microsoft's [product identifier reference](https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference)
defines those identifiers; names, substrings and service plans are not used to infer a marketed
product. No new runtime catalog download or network dependency is introduced: inventory comes from
the existing [`GET /subscribedSkus`](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
read, and snapshot replay uses the retained data.

The main table shows **Subscription**, **Status**, **Enabled seats** and **Assigned seats**.
All returned records, their statuses, SKU identifiers and service-plan references are collapsed under
**Technical details** for troubleshooting; they are omitted from print. Incomplete reads and a notice
of identity or duplicate-record warnings on other non-deleted products remain visible beside the
summary. Status is Graph `capabilityStatus`, not an inferred entitlement
or seat-availability verdict. Graph documents `Enabled`, `Warning`, `Suspended`, `Deleted` and
`LockedOut`; recognized products retain warning, suspended, locked-out and unfamiliar statuses
without interpretation rather than hiding a possible licensing problem. Missing status reads
**Not reported**. Enabled seats (`prepaidUnits.enabled`, retained as `prepaidUnitsEnabled`) and
assigned seats (`consumedUnits`) are shown independently when each is a usable non-negative integer.
An invalid or missing seat count reads **Unknown**, without hiding its usable companion.
Duplicate rows keep their own observations; their seats are not added together.

The [subscribedSku contract](https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0)
defines `consumedUnits` as assigned licenses and `Enabled` as having at least one enabled prepaid
unit, not certification that every user has every feature right. Snapshots retain service-plan
names, `servicePlanId` GUIDs and `provisioningStatus` values where returned under
`licensing.subscribedSkus[].servicePlans`. A [service plan's](https://learn.microsoft.com/en-us/graph/api/resources/serviceplaninfo?view=graph-rest-1.0)
`Success` status means fully provisioned; it is not proof of user entitlement.

Finding metadata carries `licensing.mode = Advisory`. Its historical `Licensed` value means only a
recognized positive advisory match: a coherent registered pair with exact case-sensitive
`capabilityStatus = Enabled` and no conflict affecting that match. An unrelated incomplete record
does not erase a positive match. Without one, the state is `Unknown`, even for a complete empty
subscription list. Neither state suppresses configuration checks, and current collection and
evaluation generate no new `NotLicensed` exclusions; readers retain compatibility with historical
ones. Seat counts do not determine advisory matches. Findings may therefore need an applicability
and user-rights review before remediation; consult the feature-specific
[Purview service description](https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description)
rather than treating subscription presence as permission to deploy a feature for everyone.

**Tenant subscriptions** in Tenant at a Glance counts distinct valid, non-empty SKU GUIDs across
all statuses, independently of registry recognition — not billing agreements or Graph
`subscriptionIds`. A complete, coherent read gives an exact count, including **0** for an empty
list. An incomplete read, identity gap or conflicting record metadata gives **At least N** when
valid IDs confirm a positive lower bound, otherwise **Not checked**. An unconfirmed or unreadable
collection, or conflicting duplicate collector results, is **Not checked** with no inferred total;
returned records remain available in Technical details with the relevant qualification. This inventory
count is unchanged by the customer-summary filter.

### Sources

Findings show their source references. These include Microsoft guidance and cmdlet reference pages;
the evidence table also contains supplementary non-Microsoft material. A reference page can establish
an interface without supporting every recommendation inferred from it. Confidence reflects the
rule's evidence classification and collection quality, not a live verification of Microsoft's
guidance or the tenant's effective protection.

Timestamps are stored with an explicit UTC offset and displayed in the time zone of whoever runs the
script, resolved at runtime.

## How it decides things

Collectors use an embedded interface and evidence registry, not runtime discovery of every
supported product API. Some rely on candidate output properties or feature guidance rather than a
complete output contract. For example, the `Get-OcrConfiguration` collector links the
[OCR feature documentation](https://learn.microsoft.com/purview/ocr-learn-about) and treats returned
states defensively; that link is not a cmdlet reference. Neither collection nor the evidence checker
verifies reference-page headings or proves that an interface is supported in every cloud.

### Rule provenance and customization

Each rule cites the evidence entries it was written against and their recorded retrieval dates.
They are the tool's interpretation of that guidance, not automatically extracted Microsoft checks.

**Guidance changes.** `-CheckEvidence` fetches every URL in the evidence table, including entries
not used by an active rule. It removes scripts, styles and tags, normalizes whitespace and case,
and compares a text fingerprint where a baseline exists. Results are `Unreachable`, `NoBaseline`,
`Unchanged` or `Changed`. A change is a cue to review the page; an unchanged fingerprint does not
validate its meaning, headings or support for a recommendation.

**Rules are customizable.** Export and override their declarative definitions:

```powershell
.\Invoke-PurviewAdvisor.ps1 -ExportRules .\rules.json    # edit it
.\Invoke-PurviewAdvisor.ps1 -RuleFile .\rules.json       # assess with it
```

A rule sharing an id with a built-in replaces it, so one check can be corrected or retuned without
restating the other twenty. Conditions are declarative and the engine only ever compares values, so
a rule file cannot introduce a code path. It is still validated on the way in: unknown assertions or
operators, missing collector references and unknown citation IDs are rejected, and cited URLs must
start with `https`. Import does not fetch those URLs or validate their substantive support. Custom
rules use the existing collectors; a rule file cannot add arbitrary collection code.

Collection and analysis are separate. Live collection writes a snapshot; analysis reads that saved
evidence. Given the same rules and evaluator, it is re-assessable without going back to
the tenant. Snapshot replay preserves case-distinct JSON keys instead of merging or rejecting them,
because service-returned policy values can legally contain both forms.

## What it checks today

21 rules, across the Purview solutions a deployment is normally judged on: Information
Protection (sensitivity labels, label publishing policies, classification, DLP policies and rules),
the Microsoft 365 E5 additions (auto-labeling, endpoint DLP, content and activity explorer),
Data Lifecycle Management, Records Management, Communication Compliance, Audit (Premium) and Data
Security Posture Management.

That includes supporting tenant settings: label processing for Office files, PDFs,
OneNote and video in SharePoint and OneDrive, the label mismatch email to document and site owners,
default labelling on document libraries, treating new files as sensitive until scanned, container
labelling for groups and Teams, co-authoring on encrypted files, and extending Teams DLP to
SharePoint and OneDrive. Defaults and applicability differ by feature; each returned value is
compared with the report's reference value, not an assumption that on is always right. For example,
the mismatch email is kept by leaving `BlockSendLabelMismatchEmail` set to `False`.

Insider Risk Management and information barriers have no configuration rule in this tool.
That is a coverage limit, not an absence-of-API claim: Microsoft documents
[`Get-InformationBarrierPolicy`](https://learn.microsoft.com/powershell/module/exchangepowershell/get-informationbarrierpolicy).
Collection-policy configuration is likewise not collected here; verify it through the appropriate
product interface.

Licensing and SharePoint sites are collected as context. The coverage matrix in
the report shows which areas carry rules and which are there for background, so a populated snapshot
never implies an assessment that no rule performed.

Two checks read through Exchange Online rather than the compliance session.
`UnifiedAuditLogIngestionEnabled` is documented as **always `False` in Security & Compliance
PowerShell even when auditing is on**, so reading it there would report every tenant as unaudited.
Exchange messaging records management policies are only exposed there at all. That is why the run
signs in to Exchange Online as well.

These connections can export overlapping command names. The script attempts to select commands
from the intended service module, but this is not a guarantee of connection isolation. Prefer a
dedicated assessment session rather than mixing it with other administrative work.

### Configuration against activity

An ordinary run reads Activity Explorer through `Export-ActivityExplorerData`. Content Explorer is
read through `Export-ContentExplorerData` only when at least one sensitive information type is named
with `-InsightTag`. The oversharing inventory reads existing SharePoint data access governance report
metadata. All three are read-only, and `-SkipInsights` omits them. It does not omit the separate
advanced-hunting collectors, so it is not a configuration-only or no-telemetry switch.

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

DLP rule checks count enabled-rule configuration only when a rule correlates to exactly one policy,
that policy returns exact `Mode = Enable`, and the rule returns a usable Boolean `Disabled = false`. Simulation,
disabled policies, disabled rules, zero or multiple parent matches, partial reads and missing state
fields cannot support that verdict. This does not test effective enforcement. Classic retention
similarly checks an enabled state, `Mode = Enforce`, reported `HasRules = true` and classic retention
rule-type metadata rather than publishing, auto-apply or adaptive-retention configuration. It does
not read those rules' actions or durations or validate content coverage.

Endpoint DLP policy coverage (`PA-DLP-0002`) checks configuration separately: a populated
`EndpointDlpLocation` or an exact `EndpointDevices` workload token establishes Devices scope,
and `Mode = Enable` establishes that the policy is on. **DLP policies covering Devices** includes
simulation and disabled policies, with their modes counted separately. Missing or unreadable
scope remains unknown. This is not proof of effective protection on every device: applicable
rules, user and device scope, onboarding and device health still need verification.

**Retention label definitions** (`PA-DLM-0002`) assesses definition existence only. Microsoft supports
[retention policies, labels or both](https://learn.microsoft.com/purview/retention), including labels
that classify without retention actions. One complete, readable list of uniquely named definitions
earns `Pass`, even without publishing policies; this does not validate the retention schedule or prove
publication or content application. A complete empty list is optional (`NotApplicable` internally):
zero stays visible in inventory, but contributes no finding, checklist item or score. It does not
establish that retention needs are satisfied. Missing or null lists and unavailable reads are
`NotCollected`; partial, duplicate or malformed evidence is `NeedsReview`, never an exact total or
proof of absence. Missing optional action, duration or record-designation fields alone do not negate
definition existence or establish a classification-only label.

`PA-DLM-0001` assesses classic retention policies independently, and **Records declaration**
(`PA-RM-0001`) remains a separate check. Compare label definitions with the portal's **Retention
labels** page, not **Retention policies**.
After a tenant change, collect a fresh report: `-SnapshotPath` only reassesses the saved capture,
and `-Demo` uses fabricated data.

The [application-retention model](https://learn.microsoft.com/powershell/module/exchangepowershell/new-appretentioncompliancepolicy)
covers supported Microsoft 365 workloads, including Teams, and AI applications, not AI alone.
`Get-AppRetentionCompliancePolicy` supplies policy scope and enabled state;
`Get-AppRetentionComplianceRule` supplies the separately linked rule. Application
scope can arrive as separate values or as one comma-delimited value. It is split, trimmed and
deduplicated case-insensitively before exact known values are matched; neither a substring nor the
policy name supplies scope. A Copilot, Teams or Viva Engage policy is called active only when its
scope is complete, `Enabled` is the Boolean `True`, and a rule joins to it unambiguously. No policy
`Mode` is assumed. This proves configured scope, enabled state and rule linkage, not the rule's
retention schedule, distribution or effective content coverage. Communication compliance policy
objects, by contrast, establish only that definitions are configured; current inspection, health and
last scan remain portal checks.

Only aggregate observations from these activity/content reads are retained. Activity rows can name
users, files, devices and IP addresses, so they are aggregated and discarded; each explicitly
requested Content Explorer type is queried with a page
size of one, only its summary `TotalCount` is accessed, and the returned record is discarded. Only
the List Viewer role is requested; Content Viewer is not requested. This limit applies to these
collectors, not the whole snapshot: configuration can retain policy and label names, user/group
scopes, tenant settings and optional site URLs/titles. Review all artifacts as sensitive data.

The advanced-hunting rows are also aggregate-only and deliberately positive-only. Policy matches,
insider-risk sharing, Copilot activity and Microsoft 365 app-connector events prove only that an
event was recorded during the stated 30-day window. They do not establish current policy state,
recording health, connector status or connector health. A zero proves none of those features is off.
The tool validates non-negative counts and rejects a blocking count greater than the DLP-match
count. That comparison is only a validation rule: the two aggregates are independent, so even equal
counts do not establish that the matching events were blocked.

### Label taxonomy

The report compares your label tiers against the documented default taxonomy — Personal, Public,
General, Confidential, Highly Confidential — and names where they coincide.

That comparison is a reference, not a score. Organisations classify to their own risk model, so a
tier you do not have is a design choice to confirm rather than a gap to close, and no rule fails for
that comparison. Matching is by name only, because a synonym table would be invention: a tier called
*Restricted* serving the same purpose as *Highly Confidential* reads as organisation-specific. What the rules do
check is structural and name-independent: whether more than one enabled label is defined and whether
priority values are duplicated. Those heuristics do not validate the full precedence model or
same-parent sublabel exceptions.

The built-in sensitivity-label existence, publishing-policy and multiple-label checks are deployment
heuristics, not requirements for every organization. Microsoft recommends
[keeping label counts small and categories aligned to business needs](https://learn.microsoft.com/purview/sensitivity-labels).
Absence of sensitivity labels needs an applicability review before remediation.
[Custom SITs](https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about) are for
needs not met by preconfigured types: the non-Microsoft-publisher check does not establish that built-in SITs are insufficient,
or inventory every EDM/trainable-classifier alternative. Retention labels are optional as described
above, and record declaration is relevant only where records obligations call for it. Classic
retention-policy checks do not assess all alternative ways of satisfying a retention requirement.

Hierarchy is evaluated only when every enabled label returns its `ParentId` property. A present null
value is valid evidence of a top-level root; a missing property means the hierarchy was not fully
read. A duplicate-name warning and rename recommendation require two proven siblings, including two
roots with explicit null parents. The same leaf name under different parents is not treated as a
duplicate, and incomplete hierarchy evidence never recommends renaming anything.

### Progress over time

By default a run saves a posture record so a later run can show what moved. Records go to a per-user
folder, which means a comparison works wherever you run the script from. `-BaselineFolder` puts them
somewhere else. `-NoRecord` disables saving and automatic baseline discovery; an explicit
`-BaselinePath` remains usable.

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

Cross-tenant comparison requires `-AcrossTenants` together with an explicit `-BaselinePath`.

A posture record holds tenant identity, timestamps, tool/rule versions, summary and maturity counts,
finding titles/statuses and opt-in names/states. It omits detailed finding reasons and policy/label
inventories, but is still sensitive. Top-level identity can include the signed-in account.
`-RedactTenant` blanks only the top-level name and ID; it does not anonymize embedded configuration,
named scopes or other artifact contents. Review before sharing and set an appropriate retention
period for both reports and posture history.

### Sessions and cleanup

The script attempts to reuse existing connections and to disconnect run-created connections at the
end. Service-level session tracking does not guarantee exact preservation of pre-existing sessions
or complete sign-out. `-KeepSignedIn` skips the disconnect attempt; it is not the only way module
token caches can persist and does not guarantee prompt-free authentication. Use a dedicated session
and verify service sign-out afterward when required. Closing PowerShell alone does not clear every
module or browser cache.

The Exchange endpoints sign in first, and the account the first of them used is handed to the
second, so the address is typed once rather than at every prompt. That order is deliberate:
`Microsoft.Graph.Authentication` and `ExchangeOnlineManagement` each ship their own copy of MSAL and
.NET assembly-version conflicts can cause authentication failures. Graph therefore goes last and
takes no account hint. This ordering and the child-process fallback reduce known conflicts, but
do not guarantee successful authentication for every installed module version or cloud.

If the MSAL broker fails anyway, the sign-in is retried once with Microsoft's documented
`-DisableWAM` switch rather than reported, since nothing had been asked of you yet. Windows on Arm
starts with that path because the broker can stop before opening its browser prompt. The non-WAM
sign-in keeps its browser instructions visible; the module's first token error matters only if the
retry also fails.

SharePoint sign-in requests the system-browser path. Available authentication methods depend on the
module, platform and tenant authentication policies.

The SharePoint module has its own local Windows PowerShell session instead of sharing PowerShell's
process-wide compatibility session. This keeps a SharePoint Client assembly loaded by another
module from breaking SharePoint import. The run removes only the command proxy and session it
created where cleanup succeeds. If the module still cannot load on Windows,
the console shows its sanitized import error rather than incorrectly reporting Windows as the
unsupported platform. `-KeepSignedIn` keeps the proxy and its session together so the connection
remains usable.

Your SharePoint admin URL is worked out from the tenant's initial domain rather than asked for.
That reads `verifiedDomains`, which Microsoft documents as available with only `User.Read`, so it
costs no extra consent. It is a good guess rather than a certainty — a tenant whose SharePoint
hostname differs from its initial domain will not match. If the sign-in fails, the URL it tried is
shown and you are asked for the right one rather than the run failing; a tenant name on its own is
enough, and pressing Enter carries on without SharePoint. `-TenantAdminUrl` skips the question.

Cleanup is attempted on normal and handled exits. Failed deletion, an abrupt process termination or
module behavior can leave temporary files or authentication state behind; this is not a no-trace
execution mode.

### Watching it work

Every check is named before it runs and closed with its result and elapsed time when it returns, so
a slow tenant call shows what it is waiting on rather than looking hung.

If the label list omits expanded protection settings, the assessment reads the affected labels
again by exact identifier. That sequence shows `Label x of y` progress without displaying a label
name or identifier, so a slow service response is visible rather than looking like a stopped run.

### Who you signed in as

Before collection, the run prints the reported account, connected services and observed **direct
memberships**. Entra roles come from the signed-in account's
[`/me/memberOf`](https://learn.microsoft.com/graph/api/user-list-memberof?view=graph-rest-1.0)
response using the existing `User.Read` permission. Readable names remain visible when other roles
arrive without names; an incomplete or failed read never becomes an empty role list.

Purview role groups are matched by directory object ID only after the compliance command, account
and tenant are verified against the Graph identity. Different accounts or tenants, ambiguous
sessions, unavailable commands and unreadable membership data are reported rather than attributed
automatically to a missing role. When Graph runs separately and its tenant is unavailable in the
parent session, the existing permission also allows reading the
[organization ID](https://learn.microsoft.com/graph/api/organization-list?view=graph-rest-1.0).
No additional permission is requested.

This summary is not an effective-permissions or PIM eligibility audit: it does not expand nested
groups or certify every access path. Assessment collectors still attempt their reads independently
of the displayed role list.

When at least one in-scope `-InsightTag` was supplied, this is also where the run offers the
**Content Explorer List Viewer** role group if the account lacks it. No tag means no Content Explorer
read and no role prompt. A role granted at this point still counts for the run in progress, so the
offer comes before collection rather than as a note at the end. You can wait while it is added, skip
the requested counts for this run, or carry on and let each report as not permitted. A role granted
part way through only reaches a new session, so accepting the offer signs in again rather than
retrying on the session that was already open. Unattended runs are told rather than asked, and carry
on.

## The report

A report run writes `report.html`, `findings.json` and `Set-PurviewTenantOptIns.ps1` to the output
folder. Live collection also writes `snapshot.json` there unless `-SnapshotOutputPath` overrides it.
Demo and snapshot replay do not refresh that live snapshot. The directory is not emptied, and an
optional export that is skipped can leave an older file. Check timestamps or use a fresh folder.
The HTML has a fixed section order:

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
13. Checks to Verify
14. Licensing and SKU Analysis
15. Limitations of This Assessment

Section 3 appears only when a baseline from an earlier run is available and comparable, so a first
assessment does not carry an empty progress heading. Section 13 appears only when findings need
review; it separates evidence to verify from configuration changes to make.

### Copilot and AI controls

Copilot answers in the security context of the person asking, so what governs it is the Purview
configuration and supported Copilot-specific controls. This section gathers configuration evidence
about what it can reach and what is recorded about it, which otherwise sits across
labels, DLP, SharePoint, retention, communication compliance and activity explorer.

It is split into two bands. The first covers Microsoft 365 Copilot itself. The second covers AI
beyond Copilot, because Data Security Posture Management reaches third-party sites, agents and
enterprise AI apps, and a policy covering ChatGPT is not a policy covering Copilot — reporting them
together would say the tenant governs Copilot when what it governs is people pasting into a browser.

Sensitivity-label encryption is an access-control layer, not a blanket Copilot exclusion. Copilot
uses the requesting person's Microsoft 365 authorization and effective encryption rights. Someone
the encryption policy does not authorize cannot decrypt the content. For someone who is authorized,
Microsoft documents **VIEW** and **EXTRACT** requirements for summarization in supported scenarios;
VIEW without EXTRACT can permit a link but not a summary. A label-wide rights definition still cannot
prove every item's outcome, because permissions can be assigned by the user or changed independently
on the item. Consult the [Copilot considerations](https://learn.microsoft.com/purview/ai-m365-copilot-considerations)
for application-specific behavior and exceptions; container labels do not label every file within them.

Cloud labels are read through Security & Compliance PowerShell with
`Get-Label -IncludeDetailedLabelActions`. If the bulk response omits an encryption action, only the
affected label is read again, by its exact non-empty GUID; exactly one response carrying that same
GUID is accepted. On that accepted detailed response, an explicitly null expanded action proves the
label does not encrypt. A missing property, failed read, mismatched identity, duplicate response or
contradiction remains unresolved. A label name is never used as its identity.

The **Sensitivity label encryption** control currently displays **In use** when at least one label
definition is configured to encrypt. It does not observe label application to content or test
effective item rights. Unresolved companion labels make that count a lower bound. If none is proven
and any state remains unresolved, the control is **Not read**.
Only a complete set of explicit non-encrypting states produces **Not configured**. A missing static
rights definition does not negate a proven encryption action and is never used to claim that content
is universally available to, or excluded from, Copilot.

Copilot DLP scope uses candidate location properties, recognized policy names and Copilot text in
linked rules. These are configuration signals, not complete semantic validation of a rule. The
control can show **As recommended** when a candidate policy is in exact `Enable` mode and has an
enabled linked rule; that does not prove the intended Copilot condition/action or effective
protection. Known other locations support negative scope inference where the evidence is complete;
ambiguous scope requires portal verification. Check the current
[Copilot DLP conditions, actions and coverage limits](https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about)
before relying on the result.

Retention for Copilot is read separately from everything else, because Microsoft moved prompts and
responses to their own location served by different cmdlets. The current application scope is
normalized first, then matched only to the exact documented `User:M365Copilot` value. If no current
match exists, a narrow classic read asks only for the older Teams policy family. An empty classic
result, or records carrying only the exact `User:TeamsChatUserInteractions` migration scope, proves
that family does not cover Copilot. Missing or partial classic evidence reads **Not read**; any
other classic scope reads **Needs review**. **Not configured** appears only when both policy models
prove absence. A policy name and the classic `Workload` property are never treated as scope.

Audit and retention answer different questions. Audit records interaction activity metadata, not
the actual prompts and responses. Content retention and eDiscovery for Copilot interactions are
separate capabilities. Recent audit activity is not proof of a content-retention policy or of
complete audit coverage.

### Prerequisites and tenant opt-ins

Configured labels and policies do not establish that supporting settings are ready. This section
lists returned configuration, qualified signals or a portal confirmation, plus why each setting
matters and its reference value. Defaults and applicability vary; two Boolean reference values are
`False` rather than `True`.

It leads with a count of what needs attention, so the section can be read at a glance before anyone
reads a word of it.

What can be read is read: the SharePoint tenant switches through `Get-SPOTenant`, co-authoring and
the Teams DLP extension through `Get-PolicyConfig`, container labelling through `GET /groupSettings`,
and unified audit logging through its own check. Two are inverted — `BlockSendLabelMismatchEmail`
and `DisableDocumentLibraryDefaultLabeling` are both kept at `False` — and the current value is
shown against the expected one so nobody has to remember which way round each switch runs.

Insider risk analytics is a portal confirmation in this tool. DLP analytics and sharing insider-risk
detail have limited positive indicators. A policy name beginning with `RiskSpotlighting-` produces
**Evidence found**; the tool does not read recommendation objects or verify their origin or freshness.
Behavior recorded in Defender during the last 30 days is **Seen recently**. Neither indicator proves
the switch is on now; an absent indicator does not prove it is off. Current state still requires portal
confirmation. A connection may help an unavailable read, but permissions, service availability or
unreadable evidence can still prevent assessment.

Device onboarding uses aggregate counts from each device's latest available `DeviceInfo` row in the
hunting window (`arg_max(Timestamp, *)`). A DLP-enabled count can produce **As recommended**, but it
is a historical signal, not proof of current monitoring, health or effective enforcement. Defender
onboarding or status reporting alone also does not reveal the Windows or macOS monitoring switch.
Without a positive DLP-enabled signal, confirm in the portal rather than interpreting the result as
off. Unreadable required counts in a returned aggregate make the row **Not read**; no aggregate
leaves portal confirmation required. Device-health counts are independent, so their differences do
not establish how many DLP-enabled devices are unhealthy.

Four Defender for Cloud Apps settings appear here too, because Purview labelling and DLP reach SaaS
files through them. Microsoft 365 app-connector events are isolated by documented `AuditSource` and
application values; their presence is **Seen recently**, not a current Connected or healthy verdict.
The inspect-protected-files consent row uses an application-name lookup and a `Content.SuperUser`
assignment; **Granted** is not independent verification of the Microsoft client/resource app
identities. Confirm that consent in the product before relying on it. The other two — file
monitoring and sensitivity-label scan settings — are not collected and are marked *confirm in the
portal*. The assessment does not change any of these settings.

### Tenant at a glance

This section summarizes returned configuration and observations: label definitions and enabled
publishing-policy membership; DLP policy modes and linked-rule states; classic retention policy state
and linked-rule metadata; application-retention policies and their separate rules; retention label
definitions and reported record designations; Exchange policies with retention tags; communication
compliance definitions; OCR and audit settings; and non-Microsoft sensitive information types.
Requested delayed content counts and recent activity counts remain separate.

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
together, so exact normalized `RuleTypes` separate `Default`, `Apply`, `Publish` and
`Apply` + `ProactiveDataRetention` (system-managed). Unknown kinds never become classic retention.
Exact aggregates require one successful, complete, readable list and usable state evidence for the
enforcing count. Older, untyped or incomplete captures retain the combined metric as **Not checked**,
with up to six returned named records for context. Configured policy kinds and states do not prove
distribution or content application, and this read establishes no per-label policy association.

**Retention labels** counts definitions, not use. Its detail shows reported record designations and
up to six named definitions, with an omitted-record count. Microsoft documents
[`RetentionDuration`](https://learn.microsoft.com/powershell/module/exchangepowershell/new-compliancetag)
as days or `unlimited`, with `Keep`, `Delete` and `KeepAndDelete` actions. Missing or unreadable
values stay unknown; neither a duration nor a label name establishes the retention start date,
publication or actual use. Publishing and auto-apply policy configuration is separate: labels have
multiple application methods, and previously applied labels
can remain on content after a policy is removed. No publishing policy does not mean labels are unused.

Exchange messaging records management is reported independently of those modern Purview policies.
Its value counts configured Exchange policy definitions with at least one retention tag, including
`Default MRM Policy`; a definition with no tags contributes no retention action and is not counted.
If tag attachment is unreadable for any returned policy, the value is **Not checked** rather than a
partial total. The collector does not read mailbox policy assignments, so the row never claims that
a configured policy currently governs a mailbox.

The publishing inventory distinguishes definitions from labels included in enabled sensitivity-label
publishing policies, with a distinct count and per-policy counts. Summing those policy counts would
double-count labels included more than once. Rows currently phrased as labels published to users
or who labels reach describe policy membership and declared scope, not effective reach: the tool
does not expand group membership or verify exclusions, propagation and each user's picker.

Microsoft-published sensitive information types are deliberately left out of this count so it
focuses on non-Microsoft definitions. A zero is not a classification gap: built-in types can meet
the organization's needs, and this inventory is not a test of detection quality or policy use.

A row reading *not checked* explains the evidence gap for that measure. Numeric values describe
returned observations, not necessarily complete tenant totals: an auto-labeling `PartialSuccess`
result with an empty policy list can still report `0`, with qualifications in its detail and the
assessment limitations. Check read completeness before inferring absence from any zero.

### The checklist

The headline section, and the one to hand someone: what is done, what is left, and in what order to
work it.

- **To do** — worst severity first, and where a single command would fix it that command is shown
- **To check by hand** — the tool could not settle it, so a person must
- **Done** — checks that passed
- **Not checked** — unavailable or unsupported evidence, with the reported reason

The checklist percentage is **Done / (Done + To do + To check by hand)**, so `NeedsReview` remains
in its denominator. **Not checked** and historical licensing exclusions are excluded. This measures
checklist completion, not deployment effectiveness or assessment coverage.

### What a finding tells you

Each one that needs action answers four questions: **what we found**, listing the specific labels,
policies or settings involved; **why it matters**; **what to do**; and where to read more, linking
the source references used for the check. A reference is not certification of the recommendation.

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
a model is complete on the strength of a single passing rule. Advisory licensing metadata does not
earn implementation credit; historical `NotLicensed` outcomes do not count as done either.

## Where this sits against Microsoft's own assessment

Microsoft publishes a [Zero Trust Assessment](https://learn.microsoft.com/security/zero-trust/assessment/get-started)
that scores a tenant across identity, devices, network and data. Every rule here falls in the data
pillar, so the two are complements rather than alternatives: run theirs for breadth across the four
pillars, this for depth on Purview.

They differ in scope and prerequisites. Microsoft's current guide calls for Global Administrator
for initial consent and documents subsequent-run roles separately. Its Azure connection supports
Azure-dependent checks, including log export; that part can be skipped when Azure is unavailable.
Microsoft warns that large tenants can take more than 24 hours and that Windows on ARM64 is not
supported. This script requests five read-only Graph scopes plus service-specific access; runtime
depends on tenant size, selected collectors and service response times. SharePoint collection and
Word export require Windows, and other optional features have their own platform dependencies.

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
- Cmdlet output contracts can be incomplete. Collectors normalize candidate properties; missing
  collector data can be `NotCollected`, while missing required operands can be `NeedsReview`.
  Optional fields need not prevent a limited verdict, as with retention-label definition existence.
- Evidence is an embedded table with recorded retrieval dates. The fingerprint check described
  above is a maintenance aid, not verification that all guidance remains applicable.
- Demo and snapshot replay do not exercise live authentication, service permissions, session routing
  or cleanup. A successful offline report does not establish that those paths work in your environment.

## License and disclaimer

Licensed under the [MIT License](LICENSE).

The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official
Microsoft guidance used as references for selected checks. This script is not a Microsoft
product: it reads what is configured in a tenant and reports it against those recommendations. It
describes configuration observed at a point in time and is not a compliance certification.
