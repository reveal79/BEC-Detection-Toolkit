# Installation Guide

## Prerequisites

Before using the BEC Detection Toolkit, ensure you have the following:

### Software Requirements

#### PowerShell Scripts:
- **PowerShell 5.1** or higher (Windows PowerShell)
- **PowerShell 7.x** (PowerShell Core) - Recommended for cross-platform use

#### Required PowerShell Modules:
```powershell
# Exchange Online Management
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser

# Microsoft Graph (for risky user detection)
Install-Module -Name Microsoft.Graph -Scope CurrentUser
```

### License Requirements

| Feature | License Required |
|---------|-----------------|
| Basic mail rule detection | Microsoft 365 E3/E5 or Exchange Online Plan 1/2 |
| Sign-in log analysis | Azure AD Free (30 days) or Premium (90+ days) |
| Risky user detection | Azure AD Premium P2 |
| Advanced threat protection | Microsoft Defender for Office 365 Plan 2 |
| KQL queries | Log Analytics workspace (optional) |

### Permissions Required

#### For PowerShell Scripts:
- **Exchange Admin** role OR **View-Only Organization Management**
- **Security Reader** role (for Azure AD Identity Protection)
- **Global Reader** (alternative to individual roles)

#### For KQL Queries:
- **Log Analytics Reader** (for Azure Monitor)
- **Security Reader** (for Azure AD logs)
- **Microsoft Sentinel Reader** (if using Sentinel)

---

## Installation Steps

### Step 1: Download the Toolkit

#### Option A: Git Clone (Recommended)
```bash
git clone https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit.git
cd BEC-Detection-Toolkit
```

#### Option B: Download ZIP
1. Go to the [GitHub repository](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit)
2. Click **Code** → **Download ZIP**
3. Extract to your desired location

### Step 2: Install PowerShell Modules

```powershell
# Run as Administrator (Windows) or with sudo (Linux/Mac)

# Install Exchange Online Management
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force

# Install Microsoft Graph
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# Verify installation
Get-Module -ListAvailable -Name ExchangeOnlineManagement
Get-Module -ListAvailable -Name Microsoft.Graph
```

### Step 3: Set Execution Policy (Windows Only)

```powershell
# Check current policy
Get-ExecutionPolicy

# If it's Restricted, change it:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 4: Connect to Microsoft 365

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -ShowBanner:$false

# Connect to Microsoft Graph (for risky users)
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","IdentityRiskyUser.Read.All"

# Verify connections
Get-OrganizationConfig  # Should return your org details
Get-MgContext           # Should show connected account
```

### Step 5: Test the Toolkit

```powershell
# Navigate to the toolkit directory
cd "C:\Path\To\BEC-Detection-Toolkit"

# Test with a single user
.\Scripts\Check-MaliciousMailRules.ps1 -UserPrincipalName "testuser@yourdomain.com"

# If successful, you'll see scan results
```

---

## Configuration

### Environment Variables (Optional)

Create a configuration file for your environment:

```powershell
# Create config.ps1 in the root directory
@{
    # Your organization domain
    Domain = "yourdomain.com"
    
    # Export path for reports
    ExportPath = "C:\SecurityReports"
    
    # Email notification settings (optional)
    EmailAlerts = @{
        Enabled = $false
        SMTPServer = "smtp.office365.com"
        From = "security-alerts@yourdomain.com"
        To = "soc@yourdomain.com"
    }
    
    # VIP users to monitor
    VIPUsers = @(
        "ceo@yourdomain.com",
        "cfo@yourdomain.com",
        "admin@yourdomain.com"
    )
} | Export-Clixml -Path ".\config.xml"
```

### Log Analytics Workspace Setup (For KQL Queries)

If you don't have Log Analytics configured:

1. **Enable Azure AD Diagnostic Settings:**
   - Portal: `portal.azure.com` → Azure Active Directory → Diagnostic settings
   - Click **Add diagnostic setting**
   - Select: SignInLogs, AuditLogs, NonInteractiveUserSignInLogs
   - Destination: **Send to Log Analytics workspace**
   - Save

2. **Configure Office 365 Connector (Optional - for OfficeActivity):**
   - Portal: `portal.azure.com` → Microsoft Sentinel → Data connectors
   - Find **Office 365**
   - Click **Open connector page** → **Install**
   - Select: Exchange, SharePoint, Teams

3. **Verify Data Ingestion:**
   ```kql
   SigninLogs
   | where TimeGenerated > ago(1h)
   | take 10
   ```

---

## Unattended/Scheduled Execution

### Option 1: Windows Task Scheduler

```powershell
# Create scheduled task for daily scan
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Path\To\BEC-Detection-Toolkit\Scripts\Invoke-BECDetection.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At 8am

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -TaskName "BEC Detection Scan" `
    -Action $action -Trigger $trigger -Settings $settings `
    -Description "Daily BEC indicator scan"
```

### Option 2: Azure Automation Account

1. Create Automation Account in Azure Portal
2. Import modules: ExchangeOnlineManagement, Microsoft.Graph
3. Create Runbook with your script
4. Schedule execution
5. Configure managed identity for authentication

---

## Troubleshooting

### Issue: "Module Not Found"
**Solution:**
```powershell
# Update PowerShellGet first
Install-Module -Name PowerShellGet -Force -AllowClobber

# Then reinstall required modules
Install-Module -Name ExchangeOnlineManagement -Force
```

### Issue: "Access Denied"
**Solution:**
- Verify you have required admin roles
- Check if MFA is enabled (you may need app password)
- Ensure conditional access policies allow access

### Issue: "Connection Timeout"
**Solution:**
```powershell
# Use certificate-based authentication for automation
Connect-ExchangeOnline -CertificateThumbprint "THUMBPRINT" `
    -AppId "APP_ID" -Organization "yourdomain.onmicrosoft.com"
```

### Issue: "No Data Returned"
**Solution:**
- Check audit logging is enabled: `Get-AdminAuditLogConfig`
- Verify mailbox audit is enabled: `Get-Mailbox | Set-Mailbox -AuditEnabled $true`
- Allow 24-48 hours for initial data collection

---

## Updating the Toolkit

```bash
# If installed via Git
cd BEC-Detection-Toolkit
git pull origin main

# If downloaded as ZIP
# Download latest release and replace files
```

---

## Next Steps

1. ✅ Review [USAGE.md](USAGE.md) for detailed command examples
2. ✅ Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
3. ✅ Read [BEST-PRACTICES.md](BEST-PRACTICES.md) for security recommendations
4. ✅ Join our [Discussions](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/discussions) for community support

---

## Security Considerations

### Storing Credentials Securely

**DO NOT** store credentials in plain text. Use:

```powershell
# Option 1: Credential Manager (Windows)
$cred = Get-Credential
$cred | Export-Clixml -Path "$env:USERPROFILE\secure-cred.xml"

# Later, import:
$cred = Import-Clixml -Path "$env:USERPROFILE\secure-cred.xml"
Connect-ExchangeOnline -Credential $cred
```

```powershell
# Option 2: Certificate-based authentication (Recommended for automation)
# See: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2
```

### Audit Logging

The toolkit generates logs. Store them securely:
```powershell
# Export to secure location
$ExportPath = "\\secure-share\SecurityReports"
```

---

## Support

- 📖 [Documentation](../README.md)
- 💬 [Discussions](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/discussions)
- 🐛 [Report Issues](https://github.com/YOUR-USERNAME/BEC-Detection-Toolkit/issues)
- 📧 Contact: security@yourdomain.com

---

**Installation complete!** Proceed to [USAGE.md](USAGE.md) to start detecting threats.
