# Troubleshooting Guide

Common issues and solutions when using the BEC Detection Toolkit.

---

## PowerShell Script Issues

### Issue: "Module Not Found" Error

**Error Message:**
```
The term 'Connect-ExchangeOnline' is not recognized as the name of a cmdlet
```

**Cause:** Exchange Online Management module not installed

**Solution:**
```powershell
# Install the module
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# Verify installation
Get-Module -ListAvailable -Name ExchangeOnlineManagement

# Import manually if needed
Import-Module ExchangeOnlineManagement
```

---

### Issue: "Access Denied" or "Insufficient Permissions"

**Error Message:**
```
Access Denied. You do not have permission to view this information
```

**Cause:** Missing required admin roles

**Solution:**

1. **Verify your roles:**
```powershell
# Check your roles
Get-MgUser -UserId "your.email@domain.com" -Property MemberOf | 
    Select-Object -ExpandProperty MemberOf
```

2. **Required roles:**
   - Exchange Administrator OR View-Only Organization Management
   - Security Reader (for Identity Protection)
   - Global Reader (alternative)

3. **Request role assignment from Global Admin:**
   ```powershell
   # Have Global Admin run:
   Add-RoleGroupMember -Identity "View-Only Organization Management" `
       -Member "your.email@domain.com"
   ```

---

### Issue: Connection Timeout or Authentication Failure

**Error Message:**
```
Connect-ExchangeOnline : Unable to connect. Verify your credentials
```

**Solutions:**

**Solution 1: MFA Issues**
```powershell
# Use interactive login with MFA
Connect-ExchangeOnline -UserPrincipalName "your.email@domain.com" -ShowBanner:$false

# Browser will open for MFA authentication
```

**Solution 2: Conditional Access Blocking**
- Check if Conditional Access policies are blocking PowerShell
- Add exception for PowerShell/Graph API
- Use compliant device or trusted location

**Solution 3: Certificate-based Authentication (For Automation)**
```powershell
Connect-ExchangeOnline `
    -CertificateThumbprint "THUMBPRINT" `
    -AppId "APP_ID" `
    -Organization "yourdomain.onmicrosoft.com"
```

---

### Issue: Script Runs But Returns No Results

**Symptoms:** Script completes but CSV is empty or shows "No findings"

**Possible Causes & Solutions:**

**Cause 1: No Audit Data Available**
```powershell
# Check if audit logging is enabled
Get-AdminAuditLogConfig | Select-Object AdminAuditLogEnabled

# Enable if disabled (requires admin)
Set-AdminAuditLogConfig -AdminAuditLogEnabled $true

# Enable mailbox auditing
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
```

**Cause 2: Data Retention Period**
```powershell
# Check audit log age limit
Get-AdminAuditLogConfig | Select-Object AdminAuditLogAgeLimit

# Data may have expired (default 90 days for E3, 1 year for E5)
```

**Cause 3: No Risky Users (Good News!)**
- If `detect-risky-users.kql` returns nothing, that's actually good
- Means no current Identity Protection alerts

**Cause 4: Time Range Too Narrow**
```powershell
# Try longer time window
.\Scripts\Invoke-BECDetection.ps1 -DaysBack 90
```

---

### Issue: Script Extremely Slow (Large Organization)

**Symptoms:** Script takes hours to complete for 1000+ mailboxes

**Solutions:**

**Solution 1: Process in Batches**
```powershell
# Get all mailboxes
$allMailboxes = Get-Mailbox -ResultSize Unlimited

# Process first 100
$batch1 = $allMailboxes | Select-Object -First 100

foreach ($mailbox in $batch1) {
    # Run your scan
    .\Scripts\Check-MaliciousMailRules.ps1 `
        -UserPrincipalName $mailbox.UserPrincipalName
}
```

**Solution 2: Skip Time-Consuming Checks**
```powershell
# Skip sign-in analysis for faster execution
.\Scripts\Invoke-BECDetection.ps1 -SkipSignInAnalysis -SkipRiskyUserCheck
```

**Solution 3: Use Parallel Processing (PowerShell 7+)**
```powershell
$mailboxes = Get-Mailbox -ResultSize Unlimited

$mailboxes | ForEach-Object -Parallel {
    & ".\Scripts\Check-MaliciousMailRules.ps1" `
        -UserPrincipalName $_.UserPrincipalName
} -ThrottleLimit 10
```

---

### Issue: "Execution Policy" Error (Windows)

**Error Message:**
```
File cannot be loaded because running scripts is disabled on this system
```

**Solution:**
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single session
PowerShell.exe -ExecutionPolicy Bypass -File .\Scripts\Invoke-BECDetection.ps1
```

---

## KQL Query Issues

### Issue: "Table Not Found" Error

**Error Message:**
```
'OfficeActivity' operator: Failed to resolve table or column
```

**Cause:** Office 365 logs not configured in your Log Analytics workspace

**Solutions:**

**For OfficeActivity table:**
1. Go to Azure Sentinel → Data connectors
2. Find "Office 365" connector
3. Click "Open connector page"
4. Click "Install" and select Exchange, SharePoint, Teams
5. Wait 24-48 hours for data ingestion

**Alternative - Use PowerShell Export:**
```powershell
# Export to custom table instead
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -Operations "New-InboxRule","Set-InboxRule" -ResultSize 5000 |
    Export-Csv -Path "MailRules.csv"
```

---

### Issue: "Failed to Resolve Column" Error

**Error Message:**
```
'LocationDetails' - Failed to resolve column expression
```

**Cause:** Column name changed or doesn't exist in your schema

**Solution:**
```kql
// Check what columns are available
SigninLogs
| getschema

// Adjust query to use correct column names
// Old: LocationDetails.countryOrRegion
// New: Location.countryOrRegion (varies by table version)
```

---

### Issue: Query Times Out or Too Slow

**Symptoms:** Query runs for minutes and then times out

**Solutions:**

**Solution 1: Add Time Filter Early**
```kql
// BAD - filters late
SigninLogs
| project UserPrincipalName, TimeGenerated
| where TimeGenerated > ago(7d)

// GOOD - filters first
SigninLogs
| where TimeGenerated > ago(7d)
| project UserPrincipalName, TimeGenerated
```

**Solution 2: Reduce Time Range**
```kql
// Instead of 30 days
| where TimeGenerated > ago(30d)

// Try 7 days first
| where TimeGenerated > ago(7d)
```

**Solution 3: Use Summarize with Time Bins**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, 1h), UserPrincipalName
```

**Solution 4: Limit Results for Testing**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| take 1000  // Test with smaller dataset first
```

---

### Issue: Query Returns No Results

**Possible Causes:**

**Cause 1: Data Not Yet Ingested**
- Azure AD logs: 15 minute delay
- Office 365 logs: Up to 24 hours delay
- Solution: Wait and try again

**Cause 2: Data Retention Expired**
```kql
// Check your oldest data
SigninLogs
| summarize min(TimeGenerated)

// If older than 30 days, you may need Log Analytics
```

**Cause 3: Filters Too Restrictive**
```kql
// Remove filters temporarily to test
SigninLogs
| where TimeGenerated > ago(1h)
// | where RiskLevel == "high"  // Comment this out
| take 10
```

---

### Issue: Can't Create Alerts from Query

**Problem:** "New alert rule" button grayed out

**Solutions:**

**Solution 1: Permissions**
- Need "Microsoft Sentinel Contributor" role
- Or "Log Analytics Contributor" role

**Solution 2: Workspace Limitations**
- Free tier has alert limitations
- Upgrade to Pay-as-you-go

**Solution 3: Query Compatibility**
```kql
// Alerts require aggregation
// BAD for alerts:
SigninLogs | where RiskLevel == "high"

// GOOD for alerts:
SigninLogs 
| where RiskLevel == "high"
| summarize count()
```

---

## Microsoft Graph / Azure AD Issues

### Issue: "Insufficient Privileges" for Graph API

**Error Message:**
```
Insufficient privileges to complete the operation
```

**Solution:**
```powershell
# Disconnect and reconnect with correct scopes
Disconnect-MgGraph

Connect-MgGraph -Scopes @(
    "User.Read.All",
    "AuditLog.Read.All",
    "IdentityRiskyUser.Read.All",
    "Directory.Read.All"
)

# Verify you're connected
Get-MgContext
```

---

### Issue: Azure AD Premium Features Not Available

**Error Message:**
```
This feature requires Azure AD Premium P2
```

**Features Requiring P2:**
- Identity Protection (Risky Users)
- Conditional Access advanced features
- Privileged Identity Management

**Solutions:**
- Purchase Azure AD Premium P2 licenses
- Or skip those checks: `.\Scripts\Invoke-BECDetection.ps1 -SkipRiskyUserCheck`

---

## General Performance Issues

### Issue: High Memory Usage

**Symptoms:** PowerShell consumes >4GB RAM

**Solution:**
```powershell
# Process in smaller batches
$mailboxes = Get-Mailbox -ResultSize Unlimited
$batchSize = 100

for ($i = 0; $i -lt $mailboxes.Count; $i += $batchSize) {
    $batch = $mailboxes[$i..($i + $batchSize - 1)]
    
    foreach ($mailbox in $batch) {
        # Process mailbox
    }
    
    # Force garbage collection between batches
    [System.GC]::Collect()
}
```

---

### Issue: Rate Limiting / Throttling

**Error Message:**
```
The request was throttled. Please try again
```

**Solution:**
```powershell
# Add delays between operations
foreach ($mailbox in $mailboxes) {
    try {
        Get-InboxRule -Mailbox $mailbox.UserPrincipalName
        Start-Sleep -Milliseconds 500  # 500ms delay
    } catch {
        if ($_.Exception.Message -like "*throttled*") {
            Start-Sleep -Seconds 60  # Wait 1 minute
            # Retry
        }
    }
}
```

---

## Common False Positives

### Mail Rules

**False Positive:** Legitimate user-created cleanup rules

**Solution:**
```powershell
# Whitelist known good rules
$legitRules = @("Newsletter Cleanup", "Old Items Archive")

# Filter out in your results
$findings | Where-Object { $_.RuleName -notin $legitRules }
```

---

### Impossible Travel

**False Positive:** VPN usage showing rapid location changes

**Solution:**
- Document known VPN IP ranges
- Correlate with corporate VPN logs
- Adjust time threshold (2 hours → 4 hours)

```kql
// Exclude known VPN IPs
let vpnIPs = dynamic(["203.0.113.1", "203.0.113.2"]);
SigninLogs
| where IPAddress !in (vpnIPs)
| where TimeGenerated > ago(7d)
// ... rest of impossible travel query
```

---

### OAuth Apps

**False Positive:** Legitimate business applications

**Solution:**
```kql
// Whitelist approved apps
let approvedApps = dynamic(["Microsoft Teams", "Power BI", "Zoom"]);
AuditLogs
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| where AppName !in (approvedApps)
```

---

## Data Collection Issues

### Issue: Mailbox Audit Logs Empty

**Solution:**
```powershell
# Enable mailbox auditing (requires admin)
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true

# Check specific mailbox
Get-Mailbox -Identity "user@domain.com" | Format-List AuditEnabled

# Verify audit actions are logged
Get-Mailbox -Identity "user@domain.com" | 
    Select-Object AuditAdmin, AuditDelegate, AuditOwner
```

---

### Issue: Sign-In Logs Show Limited History

**Problem:** Only see 7 days of sign-in data

**Cause:** Azure AD Free tier limitation

**Solutions:**
1. Upgrade to Azure AD Premium (30-90 days retention)
2. Configure diagnostic settings to export to Log Analytics (unlimited with paid workspace)

```powershell
# Check current retention
# Go to: portal.azure.com → Azure AD → Diagnostic settings
# Send sign-in logs to Log Analytics workspace
```

---

## Getting Help

### Before Opening an Issue

1. ✅ Check this troubleshooting guide
2. ✅ Review [INSTALLATION.md](INSTALLATION.md) and [USAGE.md](USAGE.md)
3. ✅ Search [existing issues](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/issues)
4. ✅ Test with `-Verbose` flag for detailed output

### When Opening an Issue

Include:
- **Error message** (full text)
- **PowerShell version**: `$PSVersionTable`
- **Module versions**: `Get-Module -ListAvailable`
- **Environment**: (E3/E5, Azure AD Premium, etc.)
- **Steps to reproduce**
- **Expected vs actual behavior**

### Community Support

- 💬 [GitHub Discussions](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/discussions)
- 📧 Security questions: security@yourdomain.com
- 🐛 Bug reports: [GitHub Issues](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/issues)

---

## Additional Resources

- [Microsoft Graph API Permissions](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Exchange Online PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/exchange/)
- [KQL Quick Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Azure AD Audit Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)

---

**Still having issues?** [Open an issue](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/issues/new) with details.
