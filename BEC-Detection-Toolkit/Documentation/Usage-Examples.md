# Usage Examples

**Project:** BEC Detection Toolkit
**Author:** Don Cook
**Purpose:** Demonstrate common and advanced use cases for running the toolkit in Microsoft 365 environments.

---

## 🚀 Basic Setup

Ensure prerequisites are installed and you have the required permissions before running any scripts.

```powershell
# Install required modules
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
Install-Module -Name Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft 365 services
Connect-ExchangeOnline -UserPrincipalName admin@domain.com
Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All','User.Read.All','Mail.Read'
```

---

## 🧩 Example 1 — Detect Malicious Inbox Rules

Scan all mailboxes for hidden or forwarding inbox rules.

```powershell
# Run the malicious rule check
.\Scripts\Check-MaliciousMailRules.ps1
```

**Output Example:**

```
[!] HIGH RISK RULE DETECTED!
User: user@domain.com
Rule: Hide Internal
Actions: Move to RSS Subscriptions, MarkAsRead
Targets Internal: Yes
```

**Next Steps:**

* Disable rule if confirmed malicious.
* Reset user credentials.
* Re-enable auditing if disabled.

---

## 🧠 Example 2 — Comprehensive BEC Sweep

Run the master detection script to evaluate all indicators across the tenant.

```powershell
# Comprehensive tenant-wide detection
.\Scripts\Invoke-BECDetection.ps1
```

This performs checks for:

* Inbox rule manipulation
* Impossible travel patterns
* Risky users
* OAuth grants
* MFA fatigue
* Delegation and mailbox access abuse

**Optional Parameters:**

```powershell
-UserPrincipalName user@domain.com   # Scan specific account only
-ExportCSV ./Reports/DetectionResults.csv  # Save results to file
-SkipAuditChecks  # Speed up run for quick triage
```

---

## 🌍 Example 3 — Geo Anomaly Review

Detect sign-ins from geographically distant regions within short timeframes.

```powershell
# Run impossible travel analysis
.\Scripts\Check-ImpossibleTravel.ps1
```

**Output Example:**

```
User: exec@company.com
Route: United States -> Nigeria (45 min)
Device: Unknown Browser
MFA: Not Challenged
Severity: HIGH
```

**Response Steps:**

* Reset password.
* Revoke sessions.
* Enforce Conditional Access location restrictions.

---

## ⚙️ Example 4 — Investigate a Single User

Perform targeted investigation when a specific account is suspected.

```powershell
.\Scripts\Invoke-BECDetection.ps1 -UserPrincipalName finance@domain.com
```

**What This Checks:**

* Malicious inbox rules
* Risky sign-ins
* Suspicious OAuth grants
* Delegate permissions

**Outputs:**

* Console display with color-coded severity
* CSV file for audit trail

---

## 🔐 Example 5 — OAuth Application Review

Find and disable suspicious app consents with over-privileged access.

```powershell
.\Scripts\Check-OAuthApps.ps1
```

**Output Example:**

```
[!] CRITICAL APP DETECTED!
App: MailSync Service
Scopes: Mail.ReadWrite, offline_access
Publisher: Unknown
Tenant: Multi-tenant
Consent Given By: user@domain.com
```

**Response:**

* Disable or delete the app in Azure AD.
* Remove permission grants using Graph API.

---

## 🧑‍💻 Example 6 — Automated Report Generation

Export all findings to a CSV report for review or ticketing systems.

```powershell
Invoke-BECDetection.ps1 -ExportCSV ./Reports/BEC_Detection_Report.csv
```

**Example Output Columns:**

```
Timestamp,UserPrincipalName,Detector,Severity,IndicatorSummary,Entity,Action,Source
```

You can import these into Excel, Power BI, or SIEM dashboards for visualization.

---

## 🧾 Example 7 — Scheduling Daily Scans

Use Windows Task Scheduler to automate daily detections.

**Example Task Action:**

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\BEC-Detection-Toolkit\Scripts\Invoke-BECDetection.ps1" -ExportCSV "C:\Reports\Daily_BEC_Report.csv"
```

**Recommended Frequency:** Once daily during off-hours (e.g., 1 AM).

---

## 🪪 Example 8 — Permission Audit

Check for unauthorized mailbox delegation.

```powershell
.\Scripts\Check-MailboxDelegation.ps1
```

**Output Example:**

```
[!] HIGH RISK: Unauthorized Delegate Found
User: exec@domain.com
Delegate: intern@domain.com (FullAccess)
Action Recommended: Remove-MailboxPermission
```

**Follow-up:**

```powershell
Remove-MailboxPermission -Identity exec@domain.com -User intern@domain.com -AccessRights FullAccess
```

---

## 💡 Pro Tips

* Always run the toolkit as a Global Reader, Security Reader, or higher.
* Use the `-Verbose` flag to display extended logs.
* Combine with Power Automate to send email alerts for high-severity results.
* Store exports centrally for auditing and long-term baselining.

---

## 🧠 Example Automation Flow

**Goal:** Auto-remediate malicious rules detected by `Check-MaliciousMailRules.ps1`.

```powershell
$results = .\Scripts\Check-MaliciousMailRules.ps1 -Silent
foreach ($r in $results) {
  if ($r.Severity -eq 'High' -or $r.Severity -eq 'Critical') {
    Disable-InboxRule -Identity $r.RuleName -Mailbox $r.User
    Write-Host "Disabled rule $($r.RuleName) for $($r.User)" -ForegroundColor Yellow
  }
}
```

---

## 🧩 Example 9 — Correlated Timeline View

Generate a chronological incident timeline combining detections across detectors.

```powershell
.\Scripts\Build-AttackTimeline.ps1 -UserPrincipalName user@domain.com
```

**Output Example:**

```
2025-10-20 09:15 - Sign-in from Russia (High Risk)
2025-10-20 09:20 - Inbox Rule Created: Hide @domain.com
2025-10-20 09:25 - 50 Emails Moved to RSS Folder
2025-10-20 09:30 - Password Changed (No MFA)
```

---

## 🧰 Example 10 — Integration with Other Tools

Combine the toolkit with SIEM or SOAR pipelines.

**Example: Sentinel Ingestion via API**

```powershell
Invoke-RestMethod -Method POST -Uri $SentinelIngestEndpoint -Body (Get-Content ./Reports/BEC_Detection_Report.csv)
```

**Example: Slack Alert (via webhook)**

```powershell
$payload = @{ text = "High Risk BEC detected for $($user)" } | ConvertTo-Json
Invoke-RestMethod -Uri $SlackWebhookURL -Method Post -Body $payload -ContentType 'application/json'
```

---

## 🧾 Summary

These examples cover typical and advanced use cases of the BEC Detection Toolkit. Adapt scripts as needed for your organization’s security posture.

* Use the master detection script for wide sweeps.
* Run individual detectors for focused investigations.
* Export and correlate results for full incident timelines.

**Built for defenders who need enterprise detection — without enterprise
