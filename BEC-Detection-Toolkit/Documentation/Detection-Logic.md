# Detection Logic

**Project:** BEC Detection Toolkit
**Scope:** Microsoft 365 (Exchange Online, Entra ID/Azure AD, Microsoft Graph, Unified/Audit Logs)
**Owner:** Don Cook

---

## Purpose

This document describes *how* each detector in the BEC Detection Toolkit works: data sources, signals, rules/heuristics, tunable thresholds, severity scoring, output schema, and known false-positive patterns. Use this as the reference when extending detections or reviewing results.

---

## Architecture Overview

### Data Sources

* **Exchange Online (EXO) PowerShell**

  * `Get-InboxRule`, `Get-EXOMailbox`, `Search-UnifiedAuditLog`, `Get-EXOMailboxPermission`, `Get-MailboxPermission`, `Get-RecipientPermission`, `Get-MailboxFolderStatistics`
* **Microsoft Graph**

  * Identity/Sign-in logs: `/auditLogs/signIns` (risk events, locations, client app)
  * Risk APIs: `/identityProtection/riskyUsers`, `/identityProtection/riskyUserHistoryItems`, `/identityProtection/riskyServicePrincipals`
  * OAuth apps: `/servicePrincipals`, `/oauth2PermissionGrants`, `/applications`
  * Users & Directory: `/users`, `/directory/auditLogs`
* **Unified Audit Log (UAL)**

  * Rule creation/modification, mailbox access (delegate/admin), transport rule changes, MFA events

### Processing Flow

1. **Collect**: Pull scoped data (tenant-wide or per-user) in parallel batches.
2. **Normalize**: Map raw events to a canonical schema (User, Time, Entity, Action, Indicators, Source).
3. **Evaluate**: Apply detection rules and thresholds; flag hits with severity.
4. **Correlate**: Merge hits into a timeline per user to reduce noise and show kill-chain context.
5. **Report**: Emit to CSV (per-detector and global), and print interactive prompts for high-risk actions.

### Severity Scoring (0–100)

* Base score per detector + indicator multipliers + recency boost.
* **Critical (80–100)**, **High (60–79)**, **Medium (40–59)**, **Low (20–39)**.
* Correlation bonus: multiple detectors within short windows raise severity.

---

## Detectors

### 1) Malicious Inbox Rules

**Goal:** Find rules that hide/divert finance or internal emails to mask fraud.

**Primary Signals**

* Actions: `DeleteMessage`, `MarkAsRead`, `MoveToFolder` (RSS/Archive/Junk/Custom), `ForwardTo` external domains.
* Conditions: `FromContains` internal domain (e.g., `@yourdomain.com`), `SubjectContains` "invoice", "payment", "wire", or finance keywords.
* Hidden targets: moves to low-visibility folders (`RSS Subscriptions`, `Conversation History`).

**Heuristics / Thresholds**

* **Critical** if:

  * External forward OR internal-only suppression (`@yourdomain.com`) AND actions include hide/delete/mark-as-read.
  * Rule created within last *7 days* **and** user has recent risky sign-ins.
* **High** if:

  * Internal-only suppression *or* suspicious keywords + hide actions.
* **Medium** if:

  * Any forward to consumer domains (`gmail.com`, `outlook.com`, `yahoo.com`) without explicit business allowlist.

**EXO Pseudocode**

```powershell
Get-EXOMailbox -ResultSize Unlimited | ForEach-Object {
  $rules = Get-InboxRule -Mailbox $_.PrimarySmtpAddress
  foreach ($r in $rules) {
    $score = 0
    if ($r.ForwardTo | Where-Object {$_.SmtpAddress -notlike "*@yourdomain.com"}) { $score += 60 }
    if ($r.DeleteMessage -or $r.MarkAsRead) { $score += 20 }
    if ($r.MoveToFolder -match 'RSS|Archive|Junk|Conversation History') { $score += 20 }
    if ($r.Conditions.FromAddressContains -match 'yourdomain.com') { $score += 20 }
    if ($score -ge 60) { Emit-Detection 'InboxRule' $user $r $score }
  }
}
```

**False Positives**

* Legit shared-mailbox workflows (accounting tools) that forward to allowlisted vendors.
* User-created newsletter filters to RSS/Archive (allowlist known senders).

**Response**

* Offer `Disable-InboxRule` prompt and export the rule details to CSV.

---

### 2) Impossible Travel (Geo Anomalies)

**Goal:** Detect sign-in pairs from distant geolocations within impossible timeframes.

**Signals**

* Distances between last-known successful sign-ins.
* Time deltas between events vs. min realistic travel time.
* ClientAppType (legacy auth), RiskLevel, IP Reputation.

**Heuristics**

* Compute Haversine distance and required speed. Flag if *average speed > 900 km/h* (commercial jet threshold) or *country changes within < 1 hour*.
* Increase severity if device/platform also changes and MFA not present.

**Graph Pseudocode**

```powershell
$signins = Get-GraphSignIns -User $upn -LastDays 7 | Sort-Object createdDateTime
foreach (pair in AdjacentPairs($signins)) {
  $d = GeoDistance($pair.A.IP, $pair.B.IP)
  $dt = ($pair.B.Time - $pair.A.Time).TotalHours
  if ($dt -le 1 -and $pair.A.Country -ne $pair.B.Country) { Score 70 }
  if ($d/$dt -ge 900) { Score 80 }
}
```

**False Positives**

* VPN egress changes, mobile data to Wi-Fi jumps, M365 geo misclassification.

**Response**

* Prompt password reset + sign-out everywhere + re-register MFA. Add conditional access review.

---

### 3) Risky Users (Identity Protection)

**Goal:** Surface users flagged by Entra ID risk signals.

**Signals**

* `riskLevel` (High/Medium/Low), `riskState`, `riskDetail` (leaked credentials, unfamiliar sign-in properties, anonymous IP, malware-linked IP).

**Heuristics**

* Any **High** or **Medium** risk within the past *72 hours* escalates severity of other hits for that user by +10 to +20.
* Auto-annotate detections with `riskDetail` codes.

**Response**

* Recommend risk remediation policies, force password change, and investigate correlated inbox rules/OAuth grants.

---

### 4) Failed Auth Patterns (Spray/Brute)

**Goal:** Identify password spray or brute-force attempts.

**Signals**

* Burst of failed `UserAuthenticationMethod` events from few IPs targeting many users.
* Same IP failing across multiple usernames within *10–30 minutes*.

**Heuristics**

* **Spray:** ≥10 users with ≥3 failures each from a single IP in ≤30 minutes.
* **Brute (single user):** ≥20 failures from ≤3 IPs in ≤15 minutes.
* Boost score if legacy auth or no MFA challenge observed.

**Response**

* Recommend IP blocking/Conditional Access, notify SOC, and audit for successful follow-on sign-ins.

---

### 5) MFA Fatigue (Push Bombing)

**Goal:** Detect repeated MFA prompts designed to coerce approval.

**Signals**

* Multiple MFA challenges without successful password change or device registration.
* Short intervals between prompts (e.g., <60 sec), especially off-hours.

**Heuristics**

* Threshold: ≥5 prompts in ≤10 minutes or ≥10 prompts in ≤30 minutes.
* Severity up if prompts occur between 22:00–05:00 user local time.

**Response**

* Advise number matching, geofencing, and temporary sign-in risk policy tightening.

---

### 6) Suspicious OAuth Applications

**Goal:** Identify malicious or over‑privileged app grants.

**Signals**

* New `oauth2PermissionGrants` to multi-tenant apps requesting `Mail.ReadWrite`, `offline_access`, `Files.ReadWrite.All`, `Mail.Send`.
* App consent by non-admins; consent outside business hours; unknown publisher.

**Heuristics**

* **Critical:** `Mail.ReadWrite` + `offline_access` + multi-tenant + unknown publisher within last 24h.
* **High:** Any `Mail.Send`/`Files.ReadWrite.All` without prior allowlist entry.

**Response**

* Offer revocation steps: remove grant, disable service principal, and investigate mailbox activity.

---

### 7) Mailbox Delegation Abuse

**Goal:** Detect unauthorized delegate access.

**Signals**

* New `FullAccess`/`SendAs`/`SendOnBehalf` permissions; Admin or peer accounts added as delegates.
* Unified Audit events: `MailboxLogin` with `ClientInfoString` indicating delegate access.

**Heuristics**

* **High** if new delegate added within *7 days* + finance/exec mailbox + non‑helpdesk actor.
* **Critical** if delegate activity + inbox rules suppression present.

**Response**

* Suggest immediate permission removal and reset of sharing/delegation.

---

### 8) Mailbox Audit "Covering Tracks"

**Goal:** Detect actions that hide evidence.

**Signals**

* `Set-Mailbox` audit settings changed to disable auditing or reduce retention.
* Audit log search anomalies: gaps around incident window.

**Heuristics**

* Any audit disablement within *72 hours* of suspicious activity → **Critical**.

**Response**

* Re-enable auditing, export available audit data, and preserve via eDiscovery hold if needed.

---

### 9) Attack Timeline Reconstruction

**Goal:** Combine events to show the BEC kill chain.

**Method**

* Merge detections per user keyed by UPN and 30–120 minute windows.
* Order by timestamp; annotate with risk data, IP, geo, client app.

**Output Example**

```
2025-10-20 09:15  Sign-in from RU (Risk: High)
2025-10-20 09:20  Inbox rule created: hide @company.com -> RSS
2025-10-20 09:25  50 emails moved to RSS (auto)
2025-10-20 09:30  Password changed (no MFA)
```

---

## Configuration & Tuning

### Global Parameters

* **TimeWindowDays** (default: 7–14)
* **InternalDomains**: `@yourdomain.com`, subsidiary domains
* **FinanceKeywords**: `invoice`, `payment`, `wire`, `ACH`, `remittance`
* **ConsumerDomains**: `gmail.com`, `outlook.com`, `yahoo.com`, etc.
* **FolderRiskList**: `RSS Subscriptions`, `Junk E-mail`, `Archive`, `Conversation History`

### Performance

* Batch mailbox queries (200–500 mailboxes per run) using parallel jobs.
* Cache sign-in locations per IP to reduce reverse-geo lookups.

### Output Schema (CSV)

Columns:

```
Timestamp, UserPrincipalName, Detector, Severity, IndicatorSummary, Entity, Action, Source, CorrelationId, MetadataJson
```

---

## Operational Guidance

### Remediation Prompts (One‑Click)

* `Disable-InboxRule` (by Identity)
* `Revoke-OAuthGrant` (by GrantId / ServicePrincipalId)
* `Remove-MailboxPermission` (delegate abuse)

### Playbooks

* **BEC Suspected:** Reset password, revoke refresh tokens, disable inbox rules, review forwarding, block risky IPs, enforce MFA number matching, confirm bank account change with finance *via out-of-band*.

---

## Limitations & False Positives

* VPN and mobile IP churn may trigger geo anomalies.
* Legit automation rules (newsletters, apps) can resemble hide rules; maintain allowlists.
* Identity Protection risk signals may lag several minutes.

---

## Extensibility

* Add detectors via a new rule file and register in the pipeline.
* Contribute KQL queries to `KQL-Queries/` mirroring the detectors.
* Optional: Emit SARIF for GitHub code scanning dashboards.

---

## Appendices

### A) Example KQL Snippets (for M365 Unified Audit)

```kusto
AuditLogs
| where Operation in ("New-InboxRule","Set-InboxRule")
| project TimeGenerated, UserId, Operation, Parameters
```

```kusto
SigninLogs
| order by TimeGenerated asc
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ClientAppUsed
```

### B) Example Allowlist Structure

```json
{
  "AllowlistedForwardDomains": ["contoso.com", "vendor-payments.com"],
  "AllowlistedApps": ["Power Automate", "SharePoint"],
  "AllowlistedFolders": ["Archive"]
}
```

### C) Example Severity Policy (YAML)

```yaml
inboxRule:
  base: 50
  externalForward: +30
  hideInternal: +20
  riskyUser: +10
impossibleTravel:
  base: 40
  crossCountryUnder1h: +40
  speedOver900kph: +40
```
