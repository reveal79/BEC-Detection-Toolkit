# Usage Guide

Complete guide for using the BEC Detection Toolkit PowerShell scripts and KQL queries.

---

## PowerShell Scripts

### 1. Check-MaliciousMailRules.ps1

**Purpose:** Detects inbox rules that may indicate account compromise.

#### Basic Usage

```powershell
# Interactive mode - will prompt for options
.\Scripts\Check-MaliciousMailRules.ps1

# Check specific user
.\Scripts\Check-MaliciousMailRules.ps1 -UserPrincipalName "user@domain.com"

# Check all mailboxes
.\Scripts\Check-MaliciousMailRules.ps1

# Specify custom export path
.\Scripts\Check-MaliciousMailRules.ps1 -ExportPath "C:\Reports\MailRules.csv"
```

#### What It Detects

- ✅ Rules that delete messages
- ✅ Rules that move to Deleted Items/Junk/RSS
- ✅ Rules that mark messages as read (hiding new emails)
- ✅ Rules that forward to external addresses
- ✅ Rules that redirect emails
- ✅ **CRITICAL:** Rules targeting internal domain emails

#### Example Output

```
========================================
  Mailbox Compromise Detection Script
========================================

Check [S]pecific user or [A]ll mailboxes? (S/A): A
Results will be exported to: .\SuspiciousMailRules_20251024_143052.csv

Analyzing 150 mailbox(es) for suspicious rules...

[!] HIGH RISK RULE DETECTED!
    User: john.doe@domain.com
    Rule: Hide IT Emails
    Actions: Moves to RSS Subscriptions, Marks as read
    Targets Internal: Yes
    Rule Enabled: True

    Do you want to DISABLE this rule now? (Y/N): Y
    [✓] Rule disabled successfully!

=========== SCAN SUMMARY ===========
Total mailboxes scanned: 150
Suspicious rules found: 3
High-risk rules: 1
Medium-risk rules: 2
====================================

✓ Results exported to: .\SuspiciousMailRules_20251024_143052.csv
```

---

### 2. Check-BECIndicators.ps1

**Purpose:** Checks for various BEC compromise indicators beyond just mail rules.

#### Basic Usage

```powershell
# Interactive mode
.\Scripts\Check-BECIndicators.ps1

# Check specific user
.\Scripts\Check-BECIndicators.ps1 -UserPrincipalName "user@domain.com"

# Custom time window (days back)
.\Scripts\Check-BECIndicators.ps1 -DaysBack 60

# Specify export path
.\Scripts\Check-BECIndicators.ps1 -ExportPath "C:\SecurityReports"
```

#### What It Detects

1. **Mailbox Delegates** - Unauthorized full access permissions
2. **Inbox Permissions** - Unusual folder access grants
3. **SendAs Permissions** - Ability to send as another user
4. **SendOnBehalf** - Ability to send on behalf of another user
5. **Suspicious Auto-Reply** - Phishing patterns in out-of-office messages
6. **Malicious Mail Rules** - Rules hiding internal emails
7. **External Forwarding** - Emails forwarded to external addresses
8. **High Send Volume** - Potential spam/phishing from compromised account

#### Example Output

```
========================================
  BEC Indicator Detection Script
========================================

Check [S]pecific user or [A]ll mailboxes? (S/A): S
Enter user email address: jane.smith@domain.com

Analyzing 1 mailbox(es) for BEC indicators...

[!] Issues found for: jane.smith@domain.com
    • [HIGH] Mailbox delegate: external-contractor@vendor.com
    • [HIGH] SendAs permission: admin-account@domain.com
    • [CRITICAL] Rule hiding @domain.com emails: 'Important Filter'

=========== SCAN SUMMARY ===========
Total mailboxes scanned: 1
Total findings: 3
Critical findings: 1
High-risk findings: 2
Medium-risk findings: 0
====================================
```

---

### 3. Invoke-BECDetection.ps1

**Purpose:** Comprehensive BEC detection across multiple vectors.

#### Basic Usage

```powershell
# Interactive mode - full detection
.\Scripts\Invoke-BECDetection.ps1

# Check specific user
.\Scripts\Invoke-BECDetection.ps1 -UserPrincipalName "user@domain.com"

# Specify time window and export path
.\Scripts\Invoke-BECDetection.ps1 -DaysBack 30 -ExportPath "C:\Reports"

# Skip certain checks for faster execution
.\Scripts\Invoke-BECDetection.ps1 -SkipRiskyUserCheck
.\Scripts\Invoke-BECDetection.ps1 -SkipSignInAnalysis
```

#### What It Detects

**All features from Check-BECIndicators.ps1 PLUS:**
- ✅ Azure AD Identity Protection risky users
- ✅ Impossible travel patterns (geographic anomalies)
- ✅ Suspicious sign-in patterns
- ✅ OAuth application abuse
- ✅ Mailbox audit log forensics
- ✅ Attack timeline reconstruction

#### Example Output

```
################################################################################
#                                                                              #
#              Business Email Compromise (BEC) Detection Tool                  #
#                                                                              #
################################################################################

  Version: 1.0
  Author: Don Cook - IT Operations
  Date: October 24, 2025

========================================
         CONFIGURATION
========================================

Check [S]pecific user or [A]ll mailboxes? (S/A): A
Days back to analyze sign-in logs? (Default: 30): 30

[✓] Reports will be saved to:
    • .\BEC_Detection_Report_20251024_143052.csv
    • .\BEC_Detection_Summary_20251024_143052.txt

========================================
    CONNECTING TO MICROSOFT 365
========================================

[✓] Already connected to Exchange Online
[✓] Already connected to Microsoft Graph

========================================
         COLLECTING DATA
========================================

--- Azure AD Identity Protection - Risky Users ---
[!!] Risky user detected: john.doe@domain.com - Risk: high - State: atRisk
[✓] Found 1 risky user(s)

--- Sign-In Analysis - Impossible Travel Detection ---
[!!] Impossible travel: jane.smith@domain.com - Sign-in from United States (Chicago) 
     to China (Beijing) in 0.75 hours
[✓] Found 1 user(s) with suspicious sign-in patterns

========================================
  ANALYZING MAILBOXES FOR BEC INDICATORS
========================================

Processing: john.doe@domain.com (1 of 150)

[!] Issues found for: john.doe@domain.com
    [CRITICAL] Azure AD flagged as risky user
    [CRITICAL] Rule hiding internal emails: 'Hide Alerts'
    [HIGH] Mailbox delegate: suspicious-user@external.com

  ╔══════════════════════════════════════════════════════════════╗
  ║                      DETECTION SUMMARY                       ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Total Mailboxes Scanned:                            150 ║
  ║  Analysis Period:                          Last 30 days ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Total Findings:                                      25 ║
  ║  CRITICAL:                                             3 ║
  ║  HIGH:                                                12 ║
  ║  MEDIUM:                                              10 ║
  ║  LOW:                                                  0 ║
  ╚══════════════════════════════════════════════════════════════╝

[✓] Detailed findings exported to: .\BEC_Detection_Report_20251024_143052.csv
[✓] Summary report exported to: .\BEC_Detection_Summary_20251024_143052.txt

========================================
   CRITICAL FINDINGS - IMMEDIATE ACTION REQUIRED
========================================

User                       FindingType                Details
----                       -----------                -------
john.doe@domain.com       Azure AD Risky User         Risk Level: high | State: atRisk
john.doe@domain.com       Malicious Mail Rule         Rule 'Hide Alerts' hides @domain.com emails
jane.smith@domain.com     External Forwarding         Forwarding to external@malicious.com
```

---

## KQL Queries Usage

### Where to Run KQL Queries

#### Option 1: Azure AD / Entra - Log Analytics
**Portal:** `portal.azure.com` → Azure Active Directory → Monitoring & Health → Log Analytics

**Best For:** Sign-in analysis, Azure AD audit events

#### Option 2: Microsoft 365 Defender - Advanced Hunting
**Portal:** `security.microsoft.com` → Hunting → Advanced hunting

**Best For:** Email-specific hunting

#### Option 3: Microsoft Sentinel
**Portal:** `portal.azure.com` → Microsoft Sentinel → Logs

**Best For:** Comprehensive SIEM analysis

### Running Queries

1. **Copy query** from `KQL-Queries/` folder
2. **Paste into query window** in your chosen portal
3. **Adjust time range** if needed:
   ```kql
   | where TimeGenerated > ago(7d)  // Change to 1h, 24h, 30d, etc.
   ```
4. **Click "Run"**
5. **Review results** in the output pane

### Creating Alerts from Queries

**In Azure Sentinel:**
1. Run your query
2. Click **New alert rule** button
3. Set alert name and description
4. Configure query scheduling (frequency)
5. Set alert threshold (e.g., `count() > 0`)
6. Configure actions (email, Teams, webhook)
7. Save alert rule

**Example Alert Configuration:**
```
Alert Name: BEC - Malicious Mail Rule Detected
Frequency: Every 5 minutes
Query: [Paste from detect-mail-rule-creation.kql]
Threshold: Results count > 0
Severity: High
Actions: Email to SOC team
```

---

## Common Workflows

### Workflow 1: Weekly Security Scan

```powershell
# Monday morning routine
cd "C:\Path\To\BEC-Detection-Toolkit"

# 1. Full organizational scan
.\Scripts\Invoke-BECDetection.ps1 -DaysBack 7 -ExportPath "\\SecureShare\Reports"

# 2. Review the summary report
notepad "\\SecureShare\Reports\BEC_Detection_Summary_*.txt"

# 3. Investigate critical findings
Import-Csv "\\SecureShare\Reports\BEC_Detection_Report_*.csv" | 
    Where-Object Severity -eq "CRITICAL" | Format-Table
```

### Workflow 2: Incident Response - Suspected Compromise

```powershell
# User reports suspicious activity
$suspectedUser = "compromised.user@domain.com"

# 1. Quick mailbox rule check
.\Scripts\Check-MaliciousMailRules.ps1 -UserPrincipalName $suspectedUser

# 2. Full BEC indicator scan
.\Scripts\Invoke-BECDetection.ps1 -UserPrincipalName $suspectedUser -DaysBack 30

# 3. Review sign-in history (KQL)
# Run detect-impossible-travel.kql filtered by user
# Run detect-failed-signin-patterns.kql filtered by user

# 4. Check OAuth apps (KQL)
# Run detect-oauth-abuse.kql to see recent approvals

# 5. If compromised, remediate:
# - Reset password
# - Revoke sessions
# - Disable malicious rules
# - Remove delegates
# - Revoke OAuth permissions
```

### Workflow 3: Proactive Threat Hunting

```powershell
# Daily hunting routine using KQL queries

# 1. Check for risky users
# Run KQL-Queries/detect-risky-users.kql

# 2. Look for credential attacks
# Run KQL-Queries/detect-failed-signin-patterns.kql

# 3. Monitor OAuth activity
# Run KQL-Queries/detect-oauth-abuse.kql

# 4. Check for impossible travel
# Run KQL-Queries/detect-impossible-travel.kql

# 5. Review any new mail rules
# Run KQL-Queries/detect-mail-rule-creation.kql
```

---

## Advanced Usage

### Filtering Specific Users

```powershell
# Check only VIP users
$vipUsers = @("ceo@domain.com", "cfo@domain.com", "admin@domain.com")

foreach ($user in $vipUsers) {
    .\Scripts\Invoke-BECDetection.ps1 -UserPrincipalName $user `
        -ExportPath "C:\Reports\VIP" -DaysBack 90
}
```

### Automated Scheduling

```powershell
# Create scheduled task for daily 8 AM scan
$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-File C:\BEC-Detection-Toolkit\Scripts\Invoke-BECDetection.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At 8am

Register-ScheduledTask `
    -TaskName "Daily BEC Scan" `
    -Action $action `
    -Trigger $trigger `
    -Description "Automated BEC detection scan"
```

### Email Notifications

```powershell
# Add to your script to send email alerts
$findings = Import-Csv ".\BEC_Detection_Report_*.csv"
$critical = $findings | Where-Object Severity -eq "CRITICAL"

if ($critical) {
    Send-MailMessage `
        -From "security-alerts@domain.com" `
        -To "soc@domain.com" `
        -Subject "⚠️ CRITICAL BEC Findings Detected" `
        -Body "Found $($critical.Count) critical findings. See attached." `
        -Attachments ".\BEC_Detection_Report_*.csv" `
        -SmtpServer "smtp.office365.com" `
        -UseSSL
}
```

---

## Output Files Explained

### CSV Report Format

| Column | Description |
|--------|-------------|
| User | UserPrincipalName of affected user |
| FindingType | Type of indicator (e.g., "Malicious Mail Rule") |
| Severity | CRITICAL, HIGH, MEDIUM, or LOW |
| Details | Description of the finding |
| Value | Specific values (rule name, IP, etc.) |
| Category | Grouping (Mail Rules, Permissions, etc.) |
| DateDetected | When the scan was run |

### Summary Report Contents

1. **Header** - Report metadata
2. **Findings Summary** - Count by severity
3. **Critical Findings** - Detailed list requiring immediate action
4. **High Risk Findings** - Summary of high-priority items
5. **Top Affected Users** - Users with most findings
6. **Recommended Actions** - Step-by-step remediation guide

---

## Tips & Best Practices

### Performance Optimization

```powershell
# For large organizations (1000+ mailboxes), scan in batches
$mailboxes = Get-Mailbox -ResultSize Unlimited
$batches = 0..9

foreach ($batch in $batches) {
    $batchMailboxes = $mailboxes | Where-Object {
        $_.UserPrincipalName -like "$batch*"
    }
    
    # Process this batch
    .\Scripts\Invoke-BECDetection.ps1 # adjust for batch
}
```

### False Positive Reduction

1. **Whitelist legitimate mail rules:**
   - Vacation responders
   - Newsletter filters
   - Team distribution rules

2. **Exclude service accounts:**
   - Automated systems
   - Monitoring accounts
   - Shared mailboxes

3. **Adjust thresholds** based on your environment

---

## Next Steps

1. ✅ Set up scheduled scans
2. ✅ Create alerts for critical findings
3. ✅ Train team on interpreting results
4. ✅ Document remediation procedures
5. ✅ Review [BEST-PRACTICES.md](BEST-PRACTICES.md)

---

**Need help?** Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or [open an issue](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/issues).
