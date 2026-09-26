# Purview Health Inspector

A single PowerShell script that checks Microsoft Purview configuration and produces a report of
findings, supporting evidence and recommended actions. The report separates current configuration,
recent activity and delayed content counts, with subscriptions shown as advisory context.
Findings include source references, retrieval dates and confidence levels.

**Supported scope:** Microsoft 365 commercial cloud, including education tenants in that cloud.
GCC, GCC High, DoD and China are not supported. Feature availability depends on your subscription.

**Assessment is read-only; remediation is separate.** The assessment does not change tenant
configuration. The report shows available fix commands and can generate a script for selected
changes, which require your review and confirmation. Checks use Microsoft's Purview Deployment
Blueprints and Secure by Default guidance as references.

Everything is in [Invoke-PurviewAdvisor.ps1](Invoke-PurviewAdvisor.ps1). Copy that one file
anywhere and run it.

## Read-only assessment scope

The assessment reviews your Purview settings and available activity to identify gaps and recommend
actions. It does not change tenant settings or apply fixes.

The assessment covers Purview configuration and evidence across the areas described below. It also
includes one check for Microsoft 365 Purview audit and compliance data reaching Microsoft Sentinel.

A run can install or update local dependencies, sign in to services, write reports and save posture
history. Microsoft modules handle authentication; review the requested permissions before consenting.
Sign-in logs and cached authentication state may remain after cleanup.

## Quick start

Windows may block scripts downloaded through a browser, including remediation downloads.
After reviewing the file and its source, clear the download mark if your organisation permits it:

```powershell
Unblock-File -Path .\Invoke-PurviewAdvisor.ps1
```

Use the actual downloaded filename. Unblocking does not override signature requirements or
Group Policy; follow your organisation's
[execution policy](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies).

Then run it:

```powershell
.\Invoke-PurviewAdvisor.ps1
```

The script installs missing dependencies, connects to services, collects evidence, and opens an
HTML report in the `PurviewReport` folder under the current directory.
Use a fresh `-ReportFolder` to keep runs separate, or `-NoOpen` to leave the report closed.

To try the report without connecting to a tenant:

```powershell
.\Invoke-PurviewAdvisor.ps1 -Demo -NoRecord -ReportFolder .\PurviewDemo
```

Alongside `report.html`, the output folder contains:

- `findings.json` — findings as structured data.
- `snapshot.json` — evidence from a live run, for reassessment without reconnecting.
- `Set-PurviewTenantOptIns.ps1` — proposed fixes, as a script to review.

### Running fixes

The remediation script shows the current setting, reason and exact command before asking you to
confirm each change. Review tenant-wide impact through change control before running it. The file
beside the report includes all available fixes from that run; the HTML download includes your selection.

Most fixes use SharePoint Online or Security & Compliance. Enabling container labels also writes
a Microsoft Entra directory setting and requests `Directory.ReadWrite.All`. Remediation checks the
assessed tenant ID when retained and reconnects SharePoint to the reviewed admin URL.

- Required module installs and available updates ask for approval and use **CurrentUser** scope
  from the official PowerShell Gallery. Declining a required dependency stops the script; declining
  an optional update keeps the installed version. If an updated module was already loaded, the
  assessment automatically continues in a fresh PowerShell session.
- After updating the inspector, generate a new report to get the current fixes. Saved reports and
  previously downloaded scripts do not update automatically.

#### Unified audit logging

When a complete audit read reports ingestion disabled, **Unified audit logging** offers
`Set-UnifiedAuditLogIngestionEnabled.ps1` in the report and is included in the combined remediation.
It uses Exchange Online, verifies the connection and tenant, rechecks the setting, and asks before
enabling it. An already-enabled setting is left unchanged; missing or ambiguous evidence does not
produce an audit action. Only ingestion is changed, not audit retention or mailbox auditing.

The [Audit Logs role in Exchange Online](https://learn.microsoft.com/purview/audit-log-enable-disable)
is required. Enablement can take up to 60 minutes, and events can take several hours to become
searchable. Missed activity is not backfilled.

If enablement fails, the script rechecks the setting and shows the original error. It never retries
the change automatically.

- Use the printed read-only check in a fresh PowerShell 7 window connected to **Exchange Online**
  for the same tenant, not Security & Compliance. If it returns `True`, do not rerun enablement.
- For an unconfirmed change, follow the printed recheck guidance before another attempt.
  Investigate sign-in and permission errors immediately; use Microsoft support for persistent failures.

### Common options

No options are needed for a normal run. Use these when you want to change the scope or output:

| Option | Use it to |
| --- | --- |
| `-TenantAdminUrl` | Supply your SharePoint admin URL if automatic detection is incorrect |
| `-Solution` | Check selected Purview solutions instead of all of them |
| `-ReportFolder` | Choose where to save the reports |
| `-Brief` | Produce a shorter report |
| `-PdfReport` | Also save a PDF; requires Edge, Chrome or Chromium |
| `-ProtectPdf` | Save a password-protected PDF; prompts for a password and requires qpdf |
| `-Help` | Show all options without signing in or running an assessment |

For the full list:

```powershell
.\Invoke-PurviewAdvisor.ps1 -Help
```

## Prerequisites

PowerShell 7 is required. The assessment can relaunch from Windows PowerShell 5.1.
SharePoint collection and Word export require Windows; other features depend on the modules and
service access available on your machine.

For live collection the script installs any missing module to **CurrentUser** scope, so no elevation
is needed for module installation. It verifies the official HTTPS PowerShell Gallery source first.
Pass `-SkipModuleInstall` to use only installed modules.

| Module | Service | Notes |
| --- | --- | --- |
| `Az.Accounts`, `Az.Resources` | Azure / Microsoft Sentinel | Required for Azure sign-in, role information and read-only Sentinel checks |
| `ExchangeOnlineManagement` | Security & Compliance and Exchange Online | Separate service connections in PowerShell 7 |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online | Windows only; its required commands run in a fresh local Windows PowerShell session created with `-UseWindowsPowerShell`, as Microsoft documents for PowerShell 7 |
| `Microsoft.Graph.Authentication` | Microsoft Graph | Runs natively on PowerShell 7 |

### Permissions and access

The assessment needs service-specific roles plus these five read-only delegated Graph permissions.
Graph consent does not replace Azure, Purview, Exchange Online or SharePoint access.

| Graph permission | Purpose in the assessment |
| --- | --- |
| `LicenseAssignment.Read.All` | Show tenant subscriptions as licensing context, without treating them as proof of each user's entitlement. |
| `GroupSettings.Read.All` | Check the directory setting that enables sensitivity labels for groups and Teams. |
| `User.Read` | Identify the signed-in account's current direct Entra role memberships and help locate the tenant's SharePoint admin endpoint. |
| `ThreatHunting.Read.All` | Add historical signals about endpoint DLP, data-security activity, Copilot use and cloud-app connections. The script's queries return aggregate counts only. |
| `Application.Read.All` | Look for existing consent that allows Defender for Cloud Apps to inspect protected files; this evidence still needs confirmation in the product. |

Use service-specific roles with the least access that permits the selected reads:

| Service or feature | Authorization to arrange |
| --- | --- |
| Azure / Microsoft Sentinel | Read access to subscriptions, Sentinel workspaces and data connectors, plus Log Analytics query access to the relevant Microsoft 365 tables. Reader and Log Analytics Reader are common starting points; resource and table restrictions can still prevent individual reads |
| Security & Compliance | Appropriate [Purview roles and role groups](https://learn.microsoft.com/purview/purview-permissions) for the selected cmdlets. Global Reader is not a blanket prerequisite or proof of access to all collectors |
| Exchange Online | Exchange RBAC exposing the organization and retention-policy reads; Purview permissions alone do not establish it |
| SharePoint Online | [`Get-SPOTenant`](https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell/get-spotenant) requires SharePoint administrator access. This role can write settings even though the assessment only reads them |
| Advanced hunting | `ThreatHunting.Read.All` plus access to the underlying Defender data; a scope grant alone does not ensure each queried table is available |
| Content Explorer | Only needed for requested `-InsightTag` counts: the data classification list viewer role, typically through **Content Explorer List Viewer**. It permits item/location listing, not a counts-only privilege. **Content Explorer Content Viewer** separately permits contents and item names and is not requested. See [Content Explorer permissions](https://learn.microsoft.com/purview/data-classification-content-explorer) |

Do not assign Global Administrator merely to make all reads succeed. Consent, service RBAC and
licensing are separate requirements; leave unavailable areas uncollected if broader access is not
appropriate.

Hunting reads also depend on [Defender XDR onboarding](https://learn.microsoft.com/defender-xdr/m365d-enable).
Insider-risk tables have additional [role and data-sharing prerequisites](https://learn.microsoft.com/defender-xdr/irm-investigate-alerts-defender).
If a read is denied, check the reported cause before adding permissions. The inspector does not
provision services or grant roles to make a read succeed.

Oversharing metadata needs an existing report and the relevant
[SharePoint Advanced Management access](https://learn.microsoft.com/sharepoint/sharepoint-advanced-management-prerequisites).
PDF export needs Edge, Chrome or Chromium; Word export needs Word on Windows. HTML and JSON output
remain available without either. Non-Windows PDF export has not been validated.

### Microsoft Sentinel integration

One check looks for Microsoft 365 audit and Purview compliance telemetry in accessible Sentinel
workspaces. It considers the [Microsoft 365, Information Protection and Insider Risk connectors](https://learn.microsoft.com/azure/sentinel/connect-services-api-based)
and checks recent events during `-LookbackDays` (30 days by default).

The result distinguishes **events observed**, **configured but ingestion not confirmed**, and
**not checked**. An installed solution alone is not proof of data flow, and no recent events do not
prove a broken connection. Observing one source does not establish coverage of every Purview workload.
Counts come from `OfficeActivity`, `MicrosoftPurviewInformationProtection`, and IRM-specific
`SecurityAlert` records; IRM alerts are qualified when their source tenant cannot be verified.
The check is read-only and does not use Azure Purview Data Map or scanning evidence.

### Password-protecting the PDF

`-ProtectPdf` implies PDF export and asks twice for an opening password, then uses qpdf's 256-bit
AES encryption. Keep the password securely: the assessment provides no password recovery.

This requires [qpdf 11.7.0 or later](https://qpdf.readthedocs.io/en/stable/cli.html).
If missing, the script attempts installation through winget on Windows or Homebrew on macOS;
Linux installation instructions are printed instead. `-SkipModuleInstall` prevents this installation.
An existing qpdf executable is not version-checked.

Only the PDF is encrypted. Rendering creates a plaintext copy first; failed exports are deleted where
possible, not securely erased. Use an access-controlled output folder and verify files before sharing.

## How to read the output

### Accessibility

Statuses are written out, not conveyed by color alone. The HTML supports browser zoom, keyboard
navigation and system high-contrast colors. Wide tables scroll independently of the page.

Console summaries can use your terminal's default color: set `$env:NO_COLOR = '1'` before running.
They also honor `$PSStyle.OutputRendering = 'PlainText'` where that preference is available.

### Finding statuses

| Status | Meaning |
| --- | --- |
| `Pass` | Available evidence satisfied this rule's assertion; not proof of effective deployment or compliance |
| `Area for improvement` (`Fail`) | Evidence did not satisfy an assertion reported as a failure |
| `Warning` | An assessed condition warrants attention |
| `NotCollected` | Required collector data was unavailable, failed or absent; causes include connection, permission and service limitations |
| `NeedsReview` | The data was ambiguous, or a property the rule needs was not returned |
| `Unsupported` | The inspector does not support collecting this check |
| `NotLicensed` | Historical licensing-exclusion status retained for older findings and posture records; current assessment no longer generates it |

**Area for improvement** is stored as `Fail` in JSON and posture records. Partial reads can support
a limited verdict when the required evidence is present, with reduced confidence.

`NotCollected` means missing evidence, not a configuration failure; reconnecting may not resolve it.
`NeedsReview` requires verification before action and carries no remediation command. Missing
evidence does not justify changing a setting. Checks that do not apply are omitted from customer
output.

### Licensing

Licensing is advisory, not a gate on configuration checks. **Licensing and SKU Analysis** summarizes
recognized Purview-related products, excluding deleted records. It shows subscription status,
enabled seats and assigned seats from Graph's
[`subscribedSkus`](https://learn.microsoft.com/graph/api/subscribedsku-list?view=graph-rest-1.0) response.
Missing values remain **Unknown** or **Not reported**; duplicate records are not added together.

Other products, deleted records and service-plan details remain under **Technical details** for
troubleshooting, but are omitted from print. Product names come from an embedded list matched to
Microsoft's [product identifiers](https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference),
not a complete catalog. An empty summary does not mean Purview licensing is absent.

A subscription does not establish each user's entitlement. Check the feature-specific
[Purview service description](https://learn.microsoft.com/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-purview-service-description)
before deploying a feature.

**Tenant subscriptions** in Tenant at a Glance counts distinct valid, non-empty SKU GUIDs across
all statuses, not billing agreements. Incomplete data gives **At least N** or **Not checked**, with
the reason shown beside the count.

### Sources

Findings show their source references. These include Microsoft guidance and cmdlet reference pages;
the evidence table also contains supplementary non-Microsoft material. Confidence reflects the
quality of the rule's sources and collected evidence, not a test of effective protection.

Report timestamps use the time zone of the computer running the assessment.

### Customizing checks (optional)

Use `-CheckEvidence` to check the cited links and flag possible guidance changes for review.
The checks interpret the cited guidance; they are not Microsoft certification tests.

To customize a check, export the rules, edit the relevant definition, and run with the edited file:

```powershell
.\Invoke-PurviewAdvisor.ps1 -ExportRules .\rules.json    # edit it
.\Invoke-PurviewAdvisor.ps1 -RuleFile .\rules.json       # assess with it
```

A custom rule replaces the built-in rule with the same ID; other checks are unchanged.
Review your changes against the supporting guidance before using a customized assessment.

## What it checks today

Checks cover the Purview solutions a deployment is normally judged on: Information
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

Licensing and SharePoint sites provide context. The report's coverage matrix distinguishes assessed
areas from background data; collecting data does not mean a rule evaluated it.

Two checks read through Exchange Online rather than the compliance session.
`UnifiedAuditLogIngestionEnabled` is documented as **always `False` in Security & Compliance
PowerShell even when auditing is on**, so reading it there would report every tenant as unaudited.
Exchange messaging records management policies also require Exchange Online.

The script routes overlapping commands to the intended service and stops if the connection is
ambiguous. Use a dedicated assessment session rather than mixing it with other administrative work.

### Configuration and activity

An ordinary run reads Activity Explorer through `Export-ActivityExplorerData` and existing SharePoint
data access governance report metadata. Content Explorer uses `Export-ContentExplorerData` only for
sensitive information types named with `-InsightTag`. `-SkipInsights` omits these reads, but not the
separate advanced-hunting collectors.

The report does not request Content Explorer counts for sensitivity labels: the cmdlet's `TagName`
documentation does not establish which sensitivity-label identity it accepts.

Each requested sensitive information type gets its own count. An item can match several types, so
counts are never added together. They cover supported Exchange, SharePoint, OneDrive and Teams
locations visible to your account, including any administrative-unit restrictions. Counts can take
seven days to update, or 14 days for SharePoint files. SharePoint and OneDrive files encrypted by
sensitivity labels are excluded. Failed or incomplete requests read **Not checked**, not zero.

The separate row **Sensitivity labels applied in the last 30 days** reports recent application
operations, not distinct files. Zero recent operations does not mean no content is labelled. Core
Microsoft 365 activity usually takes 60 to 90 minutes to appear; other workloads can take longer.
Power BI and Defender for Cloud Apps label activity is excluded. Incomplete queries or events that
cannot be distinguished from retention-label activity read **Not checked**.

Auto-labeling and DLP rule checks link enabled rules to enabled policies; simulation and disabled
rules do not earn an enforcing verdict. Auto-labeling SIT counts come from rule conditions, not
policy names. A rule using only classifiers or other non-SIT conditions can legitimately report zero.
Missing policy links, unreadable states or incomplete conditions remain **Not checked**.

Endpoint DLP policy coverage (`PA-DLP-0002`) checks configuration separately: a populated
`EndpointDlpLocation` or an exact `EndpointDevices` workload token establishes Devices scope,
and `Mode = Enable` establishes that the policy is on. **DLP policies covering Devices** includes
simulation and disabled policies, with their modes counted separately. Missing or unreadable
scope remains unknown. This is not proof of effective protection on every device: applicable
rules, user and device scope, onboarding and device health still need verification.

**Retention label definitions** (`PA-DLM-0002`) assesses definition existence only. Microsoft supports
[retention policies, labels or both](https://learn.microsoft.com/purview/retention), including labels
that classify without retention actions. A complete list of uniquely named definitions can earn
`Pass` without publishing policies. A complete empty list stays visible as zero but contributes no
finding or score. Neither result validates the retention schedule, publication or content application.

`PA-DLM-0001` assesses classic retention policies independently, and **Records declaration**
(`PA-RM-0001`) remains a separate check. Compare label definitions with the portal's **Retention
labels** page, not **Retention policies**.
After a tenant change, collect a fresh report: `-SnapshotPath` only reassesses the saved capture,
and `-Demo` uses fabricated data.

The [application-retention model](https://learn.microsoft.com/powershell/module/exchangepowershell/new-appretentioncompliancepolicy)
covers supported Microsoft 365 workloads, including Teams, and AI applications, not AI alone.
`Get-AppRetentionCompliancePolicy` supplies policy scope and enabled state;
`Get-AppRetentionComplianceRule` supplies its rules. Active counts require an enabled policy with
known scope and an unambiguous rule link. Communication compliance inventory counts definitions;
current inspection and service health remain portal checks.

Advanced hunting adds aggregate observations such as policy matches, insider-risk sharing and
app-connector activity. These show what was recorded in the stated window, not whether a feature is
currently on or healthy. No matching activity is not proof that a feature is off.

### Label taxonomy

The report compares your top-level labels and label groups against the documented default taxonomy —
Personal, Public, General, Confidential, Highly Confidential — and shows matching names. A separate
**Type** column distinguishes sensitivity labels from label groups. Missing type information reads
**Not recorded**; the report does not guess from the name.

Children appear immediately beneath their uniquely identified group or parent. For example,
**Confidential** is the group and **Confidential \ All Employees** is a label in that group.
A child also named Confidential appears as **Confidential \ Confidential**, not as a second
top-level label. **Same name** means a match to the reference tier, not a duplicate-label warning.

[Label groups](https://learn.microsoft.com/purview/sensitivity-labels#sublabels-that-use-parent-labels-or-label-groups)
organize labels and cannot themselves be published or applied to content.

This is a reference, not a score: different tiers are a design choice, not a failed check. Matching
uses names only, so *Restricted* is shown as organisation-specific even if it serves the same purpose
as *Highly Confidential*. A separate rule checks whether multiple enabled labels exist. Label order
still matters, but this tool does not validate precedence or score priority/name uniqueness.
Microsoft distinguishes [unique internal names from display names](https://learn.microsoft.com/purview/create-sensitivity-labels#powershell-tips-for-specifying-the-advanced-settings);
display names can repeat across different groups.

Apply these checks to your organisation's needs. Microsoft recommends
[small label sets aligned to business needs](https://learn.microsoft.com/purview/sensitivity-labels);
[custom SITs](https://learn.microsoft.com/purview/sit-sensitive-information-type-learn-about) are useful
when built-in types are insufficient. Not every tenant needs custom types or retention labels.

**Modern label scheme** reports Modern or Legacy from the scheme setting or, when that is absent,
a complete label list with explicit group markers and parent identifiers. Missing or conflicting evidence remains
unconfirmed, rather than an instruction to rename labels or migrate.

[Migration is irreversible](https://learn.microsoft.com/purview/migrate-sensitivity-label-scheme).
In the portal, use **Get started > Review new scheme** when the migration banner is present, and
review naming conflicts, newly selectable sublabels and publishing impact before approval. Microsoft
recommends testing in a tenant with the same label configuration first. Migration and post-migration
unpublishing are excluded from generated fixes, including **Select all**.

### Progress over time

By default, each run saves a posture record in a per-user folder for later comparison, independent of the
working directory. Use `-BaselineFolder` to change that location. `-NoRecord` disables saving and
automatic baseline discovery; an explicit `-BaselinePath` still works.

Rule outcomes and tenant opt-ins are compared separately; their totals are never combined.
Only a change between two assessed outcomes counts as progress or regression. If this run lacks the
evidence needed for a verdict, the row says **Could not assess this run** and stays out of movement;
that includes `Pass` to `NeedsReview`. New or retired checks, changed rules, portal-only confirmations
and historical signals such as **Seen recently** are not counted as tenant improvements.

Cross-tenant comparison requires `-AcrossTenants` together with an explicit `-BaselinePath`.

Posture records retain tenant identity, timestamps, finding summaries and opt-in states, not the full
snapshot. Treat them as sensitive alongside the reports.

### Sessions and cleanup

The script attempts to reuse existing connections and disconnects all supported service sessions at
the end of every run. Use `-SkipConnect` to manage sign-in yourself; those sessions are also
disconnected during cleanup.
Missing services are reported as unavailable rather than silently treated as empty.

Security & Compliance and Exchange Online are separate connections. Their tenant IDs must agree with
Graph and Azure. Multiple connections to the same service stop collection; start a fresh PowerShell
window if this happens. Verify SharePoint's tenant and supported cloud yourself.

Complete each Microsoft sign-in dialog and wait for **Connected** beside the service name.
A valid existing session may be reused without another prompt. A role-information read failure is
reported separately and does not by itself mean that sign-in failed.

With `-SkipConnect`, establish your service sessions first, including a normal persisted
`Connect-AzAccount` session for Azure. Use the same tenant for all services. The script will not
prompt for missing connections in this mode.

The SharePoint admin URL is detected from the tenant domain. If it is wrong, supply
`-TenantAdminUrl` or correct it when prompted. Press Enter to continue without SharePoint.

Cleanup is best effort. Temporary files and authentication caches can remain after errors or an
interrupted run. Treat any remaining temporary authentication files as sensitive and follow cleanup
warnings. The assessment does not permanently change your Azure sign-in preferences.

### Watching it work

Each check shows its name before it runs, then its result and elapsed time when it finishes.

If the label list omits expanded protection settings, the assessment reads the affected labels
again by exact identifier. `Label x of y` shows progress without exposing label names or identifiers.

### Who you signed in as

Before collection, the run prints the reported account, connected services and observed **current
memberships**. Entra roles come from the signed-in account's
[`/me/memberOf`](https://learn.microsoft.com/graph/api/user-list-memberof?view=graph-rest-1.0)
response using `User.Read`. An incomplete or failed read is identified as such, not shown as an empty list.

Microsoft Entra PIM [temporarily creates an active assignment](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-activate-role),
so an activated role can appear while it is active. Eligible-but-inactive assignments are not listed.

Purview role groups are matched by directory object ID after verifying the account and tenant.
Unreadable membership data is not automatically attributed to a missing role.

Azure shows role assignments reported for the active subscription, not effective access to every
subscription queried. If Azure uses a different account in the same tenant, that identity is shown
separately. A role lookup failure does not by itself mean Azure authentication failed, and does not
prevent independent Sentinel reads.

This is not an effective-permissions or PIM eligibility audit and does not expand nested groups.
Collectors attempt their reads independently of the displayed roles.

When at least one in-scope `-InsightTag` was supplied, this is also where the run offers the
**Content Explorer List Viewer** guidance if the read is unavailable. No tag means no Content Explorer
read and no role prompt. Before collection, you can wait for the role to be added, skip the requested
counts, or continue and receive any permission errors in the report. Waiting for a role change triggers
a fresh sign-in when you continue. Unattended runs show a notice and continue.

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
11. Recommended next actions
12. Strategic Improvements (by severity)
13. Checks to Verify
14. Licensing and SKU Analysis
15. Limitations of This Assessment

Section 3 appears only when a baseline from an earlier run is available and comparable, so a first
assessment does not carry an empty progress heading. Section 13 appears only when findings need
review; it separates evidence to verify from configuration changes to make.

### Copilot and AI controls

Copilot uses the requesting person's security context. This section brings together relevant
configuration and activity evidence from labels, DLP, SharePoint, retention, communication compliance
and Activity Explorer.

Microsoft 365 Copilot controls are shown separately from controls for third-party AI sites, agents
and enterprise AI apps. A policy covering ChatGPT, for example, does not establish Copilot coverage.

Sensitivity-label encryption is an access-control layer, not a blanket Copilot exclusion. Copilot
respects the user's access and encryption rights; supported summarization scenarios generally require
**VIEW** and **EXTRACT**. Consult the [Copilot considerations](https://learn.microsoft.com/purview/ai-m365-copilot-considerations)
for application-specific exceptions. A label definition alone cannot establish every file's access.

Cloud labels are read through Security & Compliance PowerShell with
`Get-Label -IncludeDetailedLabelActions`, with per-label follow-up reads where details are missing.
**Sensitivity label encryption — In use** means at least one label is configured to encrypt content, not that
files were observed using it. Unresolved labels keep the count qualified.

Copilot DLP checks use policy locations, names and linked-rule text to identify candidate policies.
**As recommended** requires an enabled policy and enabled linked rule, but their conditions and actions
still need review against the current
[Copilot DLP conditions, actions and coverage limits](https://learn.microsoft.com/purview/dlp-microsoft365-copilot-location-learn-about)
before relying on protection.

Copilot retention uses the application-retention cmdlets and an explicit Copilot scope. A separate
read checks the older Teams policy family when needed. Unavailable or ambiguous scope remains
**Not read** or **Needs review**, rather than **Not configured**.

Audit and retention answer different questions. Audit records interaction activity metadata, not
the actual prompts and responses. Their retention and eDiscovery are separate capabilities.

### Prerequisites and tenant opt-ins

This section checks the settings that support labels and policies, starting with a count of those
needing attention. Each entry shows the available evidence or required portal check, why the setting
matters and its reference value. Defaults and applicability vary.

The script reads SharePoint tenant switches through `Get-SPOTenant`, co-authoring and
the Teams DLP extension through `Get-PolicyConfig`, container labelling through `GET /groupSettings`,
and unified audit logging through its own check. Two are inverted — `BlockSendLabelMismatchEmail`
and `DisableDocumentLibraryDefaultLabeling` are both kept at `False` — and the current value is
shown alongside the reference value.

Insider risk analytics is a portal confirmation in this tool. DLP analytics and sharing insider-risk
detail have limited indicators: matching policy names show **Evidence found**, and recorded Defender
activity shows **Seen recently**. Neither confirms the current switch state.

Device onboarding uses the latest reported device states within the hunting window. These can show
reported DLP status, but cannot establish the Windows or macOS monitoring switch; confirm that in the portal.

Defender for Cloud Apps rows cover Microsoft 365 connector activity, consent to inspect protected
files, file monitoring and sensitivity-label scan settings. The first two use observed activity or
consent records; file monitoring and scan settings require portal confirmation.

### Tenant at a glance

This section summarizes returned configuration and observations: label definitions and enabled
publishing-policy membership; DLP policy modes and linked-rule states; classic retention policy state
and linked-rule metadata; application-retention policies and their separate rules; retention label
definitions and reported record designations; Exchange policies with retention tags; communication
compliance definitions; OCR and audit settings; and non-Microsoft sensitive information types.
Requested delayed content counts and recent activity counts remain separate.

The OCR row reads `Get-OcrConfiguration`, reporting whether OCR is enabled, valid and unblocked for
known workloads. Missing or contradictory settings read *not checked*. Review
[OCR requirements](https://learn.microsoft.com/purview/ocr-learn-about) before enabling it.

[`Get-RetentionCompliancePolicy`](https://learn.microsoft.com/powershell/module/exchangepowershell/get-retentioncompliancepolicy)
returns classic retention, auto-apply, publishing and system-managed policies together. The report
separates those kinds using `RetentionRuleTypes` and counts enforcing policies only with the required
type and state evidence. When policy types are unknown, a complete named list can still supply a
**Retention and retention label policy definitions** count, not an enforcing total.

`RuleTypes` is the snapshot name for `RetentionRuleTypes`, not a retention period. Missing values mean
incomplete policy details, not proof that settings are absent. Enabled status alone cannot confirm a
retention action or period. Review the policy and rules in Purview, including any **Settings not found**
message; the inspector does not verify policy distribution or effective content retention.

**Retention labels** counts definitions, not use. Its detail shows reported record designations and
up to six named definitions with their available actions and durations. Publishing and auto-apply
policies are separate; labels can reach content in other ways and remain after a policy is removed.

Exchange messaging records management is reported independently of those modern Purview policies.
Its value counts configured Exchange policy definitions with at least one retention tag, including
`Default MRM Policy`. It does not read mailbox assignments, so the count does not establish how many
mailboxes use those policies.

The publishing inventory distinguishes definitions from labels included in enabled sensitivity-label
publishing policies, with a distinct count and per-policy counts. Summing those policy counts would
double-count labels included more than once. These rows describe declared policy scope, not delivery
to every user's label picker.

Microsoft-published sensitive information types are deliberately left out of this count so it
focuses on non-Microsoft definitions. A zero is not a classification gap: built-in types can meet
the organization's needs, and this inventory is not a test of detection quality or policy use.

A row reading *not checked* explains the evidence gap. Counts from partial reads carry qualifications;
read those before treating a number, including zero, as a tenant-wide total.

### The checklist

Start here to see what is done, what needs action and what to verify next.

- **To do** — highest severity first, with a fix command where available
- **To check by hand** — evidence needs manual verification
- **Done** — checks that passed
- **Not checked** — unavailable or unsupported evidence, with the reported reason

The checklist percentage is **Done / (Done + To do + To check by hand)**, so `NeedsReview` remains
in its denominator. **Not checked** and historical licensing exclusions are excluded. This measures
checklist completion, not deployment effectiveness or assessment coverage.

### What a finding tells you

Each actionable finding includes:

- **What we found** — the labels, policies or settings involved.
- **Why it matters** — the reason for the recommendation.
- **What to do** — the recommended action.
- **References** — links to the guidance used for that check, not certification of the recommendation.

### Recommended next actions

A shortlist of up to five planning actions, showing **why now / benefit**, **expected user impact**
and **preparation**. The suggested order is audit visibility, label foundations, then policy rollout;
it is not a risk or effort score or an instruction to enable every setting.

Only selected built-in findings with complete evidence qualify. Related DLP or auto-labeling findings
share one slot; other findings remain under Strategic Improvements or Checks to Verify.

Review licensing, scope and pilot results before approving a change. Full reports link actions to
their findings; condensed reports keep the rule ID and guidance link.

### Blueprint coverage

This section maps current results to the Secure by Default and Data Security Posture Management
blueprints. It lists only steps the tool can check, not progress through a deployment programme.

No completion percentage is shown: most steps have one check or none, which is insufficient to
measure blueprint completion. Advisory licensing matches and historical `NotLicensed` outcomes do
not count as completed steps.

## Comparison with Microsoft's Zero Trust Assessment

Microsoft publishes a [Zero Trust Assessment](https://learn.microsoft.com/security/zero-trust/assessment/get-started)
that scores a tenant across identity, devices, network and data. Every rule here falls in the data
pillar, so the two are complements rather than alternatives: run theirs for breadth across the four
pillars, this for depth on Purview.

The tools have different access and platform requirements. Follow each one's prerequisites;
Health Inspector uses the five Graph permissions and service roles listed above.

## Handling report data

Reports, snapshots and posture history contain tenant information. Store them in an access-controlled
location, set a retention period and review them before sharing.

- Activity, hunting and Content Explorer reads retain aggregate counts, not individual activity records.
  Configuration can still include policy and label names, user/group scopes and site URLs.
- `-RedactTenant` removes only the top-level tenant name and ID; it does not anonymize the snapshot.
- `-NoRecord` prevents automatic posture-history saving and discovery. Explicit `-BaselinePath` still works.
- `-ProtectPdf` protects only the PDF, not HTML, JSON, Word or history files.

This is a configuration assessment, not a live enforcement test or a complete security audit.
Demo and snapshot replay do not validate live sign-in or service access.

## License and disclaimer

Licensed under the [MIT License](LICENSE).

The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official
Microsoft guidance used as references for selected checks. This script is not a Microsoft
product: it reads what is configured in a tenant and reports it against those recommendations. It
describes configuration observed at a point in time and is not a compliance certification.
