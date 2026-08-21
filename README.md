# Purview Health Inspector

A single PowerShell script that assesses Microsoft Purview configuration against evidence-based
rules and reports what it finds. It collects tenant configuration, evaluates it deterministically,
checks licensing eligibility, and prints a report you can hand to a customer. Every recommendation
carries the Microsoft source it came from, the date that source was retrieved, and a confidence
level.

**What it is not.** Not a remediation tool: the assessment never changes anything in a tenant, and
where a fix exists it prints the command for you to review and run yourself. It is not a Microsoft
product — it reads what is configured and reports it against the Purview Deployment Blueprints and
Secure by Default guidance, which are Microsoft's own.

Everything is in [Invoke-PurviewAdvisor.ps1](Invoke-PurviewAdvisor.ps1). Copy that one file
anywhere and run it.

## Read-only guarantee

**It never creates, modifies, publishes or deletes anything in a connected tenant.**

Only reads are used. Every cmdlet is a `Get-*`, apart from two `Export-*` cmdlets —
`Export-ActivityExplorerData` and `Export-ContentExplorerData` — which despite the verb return data
to the pipeline and change nothing, and one advanced hunting query that runs read-only KQL and
returns counts.

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

The remediation script reports what it would do and changes nothing unless you pass `-Apply`, and
even then it confirms each change one at a time. These are tenant-wide settings, so it is written to
go through change control rather than to be run on sight. The report carries a download button for
the same script, which works even when the HTML is emailed on its own.

Double-clicked it, or launched it from Windows PowerShell 5.1? It restarts itself in PowerShell 7
and carries your arguments across. If PowerShell 7 is not installed it tells you the one command
that installs it.

If you would rather manage your own sessions, connect first and pass `-SkipConnect`. You do not need
all three connections — anything you skip is reported as `NotCollected` rather than guessed at.

| Switch | Effect |
| --- | --- |
| *(none)* | Collect from your tenant and assess |
| `-SnapshotPath` | Assess a snapshot already on disk |
| `-TenantAdminUrl` | Your SharePoint admin URL, if it cannot be worked out for you |
| `-Environment` | The cloud the tenant is in: Commercial, GCC, GCCHigh, DoD or China |
| `-Solution` | Assess only the named Purview solutions instead of all of them |
| `-Brief` | Write the condensed report instead of the full one |
| `-AcrossTenants` | Compare against a `-BaselinePath` record from a different tenant |
| `-SkipConnect` | Sign in to nothing; use only sessions you established |
| `-SignOut` | Sign out at the end instead of keeping the session |
| `-ReportFolder` | Write the report somewhere other than the current directory |
| `-NoOpen` | Do not open the report when it is finished |
| `-DarkMode` | Render the report on a dark background |
| `-PdfReport` | Also render a PDF (needs Edge, Chrome or Chromium) |
| `-WordReport` | Also write a `.docx` (needs Word on Windows) |
| `-CheckEvidence` | Verify every cited Microsoft source still resolves and reads as it did |
| `-ExportRules` | Write the rules and citations to a JSON file you can edit |
| `-RuleFile` | Assess using rules from that file |
| `-SkipInsights` | Configuration only, skipping the activity and labelled-content reads |
| `-InsightDays` | Days of activity to summarise. Defaults to 30, the most the service keeps |
| `-InsightTag` | Extra sensitive information types to count |
| `-BaselineFolder` | Where to keep posture records, if not the default per-user folder |
| `-BaselinePath` | Compare against one specific posture record |
| `-NoRecord` | Do not record this run |
| `-RedactTenant` | Blank tenant name and id before sharing |
| `-IncludeSites` | Enumerate SharePoint sites (slow on a large tenant) |
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
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online | Windows only; imported with `-UseWindowsPowerShell`, which Microsoft documents as required on PowerShell 7 |
| `Microsoft.Graph.Authentication` | Microsoft Graph | Runs natively on PowerShell 7 |

Permissions, all read-only:

| Permission | Why |
| --- | --- |
| `LicenseAssignment.Read.All` | Subscribed SKUs for licensing analysis. Microsoft marks this least privileged for `GET /subscribedSkus` |
| `GroupSettings.Read.All` | Whether container labelling is switched on in the directory. Least privileged for `GET /groupSettings`; `Directory.Read.All` also works and is deliberately not requested |
| `User.Read` | The tenant's initial domain, which gives the SharePoint admin URL. Microsoft documents this as enough to read `verifiedDomains` |
| `ThreatHunting.Read.All` | Endpoint DLP device health, through the `DlpInfo` column of the advanced hunting `DeviceInfo` table. The query aggregates in the service and returns counts only |
| **Global Reader** in Microsoft Purview | Read-only counterpart of Global Administrator |
| **Content Explorer List Viewer** | For the labelled-content counts. Shows items and locations. *Content Viewer* additionally exposes item contents and names and is deliberately not needed, because only counts are read |

`Organization.Read.All` and `Directory.Read.All` also work for subscribed SKUs, but Microsoft lists
them as *higher privileged*, so they are deliberately not requested.

SharePoint collection runs on Windows, because its module does. The oversharing reports need
SharePoint Advanced Management, which a Microsoft Copilot license or the Plan 1 add-on unlocks.
`-PdfReport` uses Edge, Chrome or Chromium and `-WordReport` uses Word on Windows; where
neither is present the HTML and JSON reports are still written.

## How to read the output

### Finding statuses

| Status | Meaning |
| --- | --- |
| `Pass` | Checked and correct |
| `Area for improvement` | Checked and incorrect |
| `Warning` | Works today, but ambiguous or fragile |
| `NotApplicable` | Does not apply — including when the capability is not licensed |
| `NotCollected` | Applies, but you were not connected to the service that holds the data |
| `NeedsReview` | The data was ambiguous, or a property the rule needs was not returned |

In `findings.json` and in posture records the status is stored as `Fail`, so anything reading those
files or comparing against an earlier baseline sees a stable value.

The last three matter as much as the first three. `NotCollected` tells you what a further connection
would add, and is never reported as a failure. An unlicensed capability is `NotApplicable` with an
upgrade note — you are not marked down for something you have not bought.

Licence detection matches suite tiers rather than exact SKU names, because the same entitlement is
sold under several: an E5 tenant may show `SPE_E5`, `ENTERPRISEPREMIUM` or
`Microsoft_365_E5_(no_Teams)`, and service plan names are read too for suites that do not name their
tier. E5 satisfies anything asking for E3. Where the tier cannot be established the rule is
evaluated anyway, because suppressing a check reads as nothing being wrong.

The licensing section lists only the subscriptions that bear on Purview — the enterprise, frontline,
academic and government suites, and add-ons such as Purview or Copilot that unlock capability on
their own. Everything else a tenant buys is counted but not named, because a page of Visio and Power
BI lines buries the two or three that decide what is available.

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
reference page may be undocumented, in preview, or renamed. Every interface the script uses cleared
that bar.

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
restating the other twenty-one. Rules are data throughout — conditions are declarative and the engine
only ever compares values — so a rule file cannot introduce a code path. It is still validated on
the way in: unknown assertions or operators, rules that do not say which collector they read, and
citations that resolve to nothing are all rejected, and any source cited must be `https`.

Collection and analysis are separate. A run writes a snapshot; analysis reads only that
snapshot. A run is reproducible, reviewable long afterwards, and re-assessable without going back to
the tenant.

## What it checks today

22 rules, scoped to the Purview workloads **FastTrack gives remote guidance for**: Information
Protection (sensitivity labels, label publishing policies, classification, DLP policies and rules),
the E5 Premium additions (auto-labeling, endpoint DLP, content and activity explorer),
Data Lifecycle Management, Records Management, Communication Compliance, Audit (Premium) and Data
Security Posture Management.

That includes the tenant opt-ins that ship switched off: label processing for Office files, PDFs,
OneNote and video in SharePoint and OneDrive, the label mismatch email to document and site owners,
default labelling on document libraries, treating new files as sensitive until scanned, container
labelling for groups and Teams, co-authoring on encrypted files, and extending Teams DLP to
SharePoint and OneDrive. Each carries its documented expected value rather than an assumption that
on is always right — the mismatch email is kept by leaving `BlockSendLabelMismatchEmail` set to
`False`, so that one is checked for false.

What FastTrack lists as out of scope carries no check, so the report never grades a customer on
something nobody is engaged to help them deploy. Information barriers are the clearest example — out
of scope under both Insider Risk Management and Communication Compliance — along with privileged
access management and SharePoint data governance and administration.

Scope is held as a table keyed by solution area, so a change in FastTrack scope is a single edit
rather than a rewrite. The FastTrack page itself is a cited source with a content fingerprint, so
`-CheckEvidence` reports when it is rewritten.

Insider Risk Management *is* FastTrack-supported, but has no documented read-only interface, so it
carries no check for that separate reason.

Licensing and SharePoint sites are collected as context. The coverage matrix in
the report shows which areas carry rules and which are there for background, so a populated snapshot
never implies an assessment that no rule performed.

One check reads through Exchange Online rather than the compliance session:
`UnifiedAuditLogIngestionEnabled` is documented as **always `False` in Security & Compliance
PowerShell even when auditing is on**, so reading it there would report every tenant as unaudited.
That is why the run signs in to Exchange Online as well.

### Configuration against activity

Every run reads two further sources beyond configuration: activity explorer through
`Export-ActivityExplorerData` and content explorer through `Export-ContentExplorerData`. Both are
reads. `-SkipInsights` turns them off for a faster, configuration-only run.

This is what turns configuration into assessment. A published label proves nothing on its own — the
question is whether anyone applies it. Comparing the two catches the taxonomy that exists only in
the admin portal, which no configuration check alone can see.

Only counts survive. Activity rows name users, files, devices and IP addresses, so they are
aggregated and discarded; content explorer is asked for a single record so its per-item detail is
never read. No user or file name reaches the snapshot.

Data Security Posture Management's own data risk assessments and the Purview posture reports are
portal-only, with no documented cmdlet or endpoint. These are the sources they draw on, read
directly — not those reports.

### Label taxonomy

The report compares your label tiers against the documented default taxonomy — Personal, Public,
General, Confidential, Highly Confidential — and names where they coincide.

That comparison is a reference, not a score. Organisations classify to their own risk model, so a
tier you do not have is a design choice to confirm rather than a gap to close, and no rule fails for
it. Matching is by name only, because a synonym table would be invention: a tier called *Restricted*
serving the same purpose as *Highly Confidential* reads as organisation-specific. What the rules do
check is structural and name-independent — whether there is more than one tier at all, and whether
precedence between them is deterministic.

### Progress over time

Every run is recorded, so the next one shows what moved. Records go to a per-user folder by default,
which means a comparison works wherever you run the script from. `-BaselineFolder` puts them
somewhere else and `-NoRecord` skips it.

Only a change between two assessed outcomes counts as progress. Four things that look like movement
in a naive diff are classified separately and kept out of the count: losing visibility of a rule,
gaining a rule the baseline never had, a rule changing version between runs, and a capability
becoming inapplicable because licensing changed. A tenant that dropped a licence would otherwise
read as having improved. Maturity percentages are compared only when measured over the same number
of assessed steps.

Comparison is refused outright across tenants unless `-AcrossTenants` names the record explicitly.

A posture record holds rule outcomes only — no policy names, no label names, no reasons. It is a far
less sensitive artifact than a snapshot.

### Leaving no trace

Sign-in is reused wherever possible. A service that already has a live session is left alone, and
Microsoft Graph is only re-authorised when a scope it needs is actually missing rather than to
refresh what is already there. The token cache each module keeps is deliberately preserved, so a
second run usually starts without any prompt at all. `-SignOut` closes the sessions this run opened
if you would rather not leave them live; sessions you opened yourself are never touched.

The Exchange endpoints sign in first, and the account the first of them used is handed to the
second, so the address is typed once rather than at every prompt. That order is deliberate:
`Microsoft.Graph.Authentication` and `ExchangeOnlineManagement` each ship their own copy of MSAL and
.NET keeps only the first one loaded, so connecting Graph first leaves the Exchange modules binding
their newer broker extension against Graph's older MSAL, which throws before any sign-in prompt
appears. Graph therefore goes last, and takes no account hint because it accepts none — by that
point the browser usually has a session to reuse. Nothing but the user principal name is carried
across; no password, token or cookie is read or passed by the script.

If the MSAL broker fails anyway, the sign-in is retried once with `-DisableWAM` rather than
reported, since nothing had been asked of you yet. The module's own token error is shown only if
that retry fails as well.

SharePoint sign-in uses the system browser, which is what makes passkeys and other platform
authenticators available. The module's own dialog falls back to a password.

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

## The report

A run writes `report.html`, `findings.json` and `snapshot.json` into a `PurviewReport` folder,
replacing whatever was there before. The HTML has a fixed section order:

1. Tenant at a Glance
2. Executive Summary
3. Progress Since Last Assessment
4. Prerequisites and Tenant Opt-ins
5. Microsoft 365 Copilot Controls
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

### Microsoft 365 Copilot controls

Copilot answers in the security context of the person asking, so what governs it is the Purview
configuration already in the tenant rather than a separate product. This section gathers the
controls that decide what it can reach, which otherwise sit across labels, DLP and SharePoint.

The one worth knowing about: where a sensitivity label applies encryption, Microsoft documents that
Copilot needs the **EXTRACT** usage right alongside VIEW before it will return that content. A label
that withholds either does not block Copilot so much as make the content invisible to it, and the
symptom is Copilot appearing to have nothing to say rather than an error anyone can trace. Where no
label encrypts, or none returns any usage rights, the control reads as not configured rather than
as a pass, because nothing has been established either way.

The DLP location for Copilot is read where the service returns it. Microsoft documents the location
itself but not the property behind it, so where nothing comes back the section says the check could
not be made from PowerShell rather than reporting no policy.

### Prerequisites and tenant opt-ins

Several Purview capabilities ship switched off, so that adopting Purview does not change behaviour
for users overnight. A tenant can therefore look configured while labels are never processed for
PDFs, container labels never appear, or nobody is told when a document is more sensitive than the
site holding it. This section lists each opt-in with its current state, a paragraph on what it
costs to leave alone, and the recommended state — which for two of them is off rather than on.

It leads with a count of what needs attention, so the section can be read at a glance before anyone
reads a word of it.

What can be read is read: the SharePoint tenant switches through `Get-SPOTenant`, co-authoring and
the Teams DLP extension through `Get-PolicyConfig`, container labelling through `GET /groupSettings`,
and unified audit logging through its own check. Two are inverted — `BlockSendLabelMismatchEmail`
and `DisableDocumentLibraryDefaultLabeling` are both kept at `False` — and the current value is
shown against the expected one so nobody has to remember which way round each switch runs.

Three are marked *confirm in the portal*: DLP analytics, insider risk analytics, and sharing insider
risk detail with other security solutions. Microsoft documents no cmdlet or Graph endpoint that
reads any of them, so this is a gap in what the product exposes rather than one in the tool, and
connecting to more services will not close it. They are never reported as switched off, because
nobody looked. That is kept distinct from *not read this run*, which means a service the tool can
read was not connected and a further sign-in would settle it.

### Tenant at a glance

What the customer actually has, counted rather than judged, and the section to open a conversation
with: labels defined, how many of them a publishing policy actually reaches users with, label
publishing policies enabled, DLP policies enforcing versus in test mode, DLP rules active, retention
policies enabled, retention labels declaring records, whether unified audit logging is on, sensitive
information types specific to this organisation, items carrying a sensitivity label, and how many
labels were applied in the collection window.

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

A row reading *not checked* means the service could not be read, and says why beside it — which
module was missing, or which sign-in did not happen. That is deliberately never shown as `0`,
because the two mean opposite things: one is that we could not look, the other that there is
genuinely nothing there.

### The checklist

The headline section, and the one to hand someone: what is done, what is left, and in what order to
work it.

- **To do** — worst severity first, and where a single command would fix it that command is shown
- **To check by hand** — the tool could not settle it, so a person must
- **Done** — checks that passed
- **Not checked** — no data, with the connection that would supply it
- **Not applicable** — usually an unlicensed capability

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
over a day on a large tenant. It also does not support Windows on Arm. This script asks for three
Graph scopes, finishes in minutes, and runs anywhere PowerShell 7 does.

Their report and this one both name real policies and settings. Treat either as sensitive and share
it only with people entitled to see the tenant's configuration.

## Reading the results accurately

A few qualifiers change how a finding should be read:

- Activity findings describe the collection window, and activity explorer holds at most 30 days. An
  event absent from that window is not proof it never happened.
- Cmdlet *output* property names are not documented on Learn the way parameters are. Collectors
  normalise against candidate names and declare anything absent; where a property a rule needs is
  missing, the finding is `NeedsReview` rather than a guess.
- Evidence is a static table inside the script, captured on the dates each entry records.
  `-CheckEvidence` compares each page against the wording it was written against, so a rewrite is
  detected — but a page that changed meaning without changing wording, or changed somewhere the
  fingerprint does not cover, would still pass.
- Live collection has been exercised against stubbed cmdlets rather than a production tenant.

## Extending it

Rules live in the `$script:Rules` table, after the `$script:Evidence` citations they draw on. Copy an
existing entry rather than starting from scratch: fourteen fields are mandatory, and the checks
reject a rule missing any of them — among them the FastTrack workload, the deployment model step and
the licensing SKU the rule maps to, none of which are obvious from the outside. Every id in
`evidence` must exist as a key in `$script:Evidence`, and `-CheckEvidence` tells you whether the
source you cited still resolves.

## License and disclaimer

Licensed under the [MIT License](LICENSE).

The Microsoft Purview Deployment Blueprints and the Secure by Default guidance are official
Microsoft guidance, and every check links the page it came from. This script is not a Microsoft
product: it reads what is configured in a tenant and reports it against those recommendations. It
describes configuration observed at a point in time and is not a compliance certification.
