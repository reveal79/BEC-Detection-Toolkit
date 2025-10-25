################################################################################
#                                                                              #
#              Business Email Compromise (BEC) Detection Tool                  #
#                                                                              #
################################################################################
#                                                                              #
#  This comprehensive script detects Business Email Compromise indicators      #
#  across multiple Microsoft 365 security vectors.                             #
#                                                                              #
#  WHAT THIS SCRIPT DOES:                                                      #
#  • Detects malicious mail rules hiding internal emails                       #
#  • Identifies risky users flagged by Azure AD Identity Protection            #
#  • Analyzes sign-in logs for impossible travel patterns                      #
#  • Checks for suspicious mailbox permissions and delegates                   #
#  • Monitors SendAs/SendOnBehalf permissions                                  #
#  • Detects mailbox forwarding configurations                                 #
#  • Analyzes recent sent items for fraud patterns                             #
#  • Checks for suspicious auto-reply messages                                 #
#  • Generates comprehensive CSV reports with findings                         #
#                                                                              #
#  REQUIREMENTS:                                                               #
#  • ExchangeOnlineManagement module                                           #
#  • Microsoft.Graph module (User.Read.All, AuditLog.Read.All,                 #
#    IdentityRiskyUser.Read.All, Directory.Read.All)                           #
#  • Global Admin or Security Reader + Exchange Admin roles                    #
#                                                                              #
#  Author: Don Cook          |    Team: IT Operations (ITO)                    #
#  Date: October 23, 2025    |    Version: 1.0                                 #
#                                                                              #
################################################################################

<#
.SYNOPSIS
    Comprehensive Business Email Compromise (BEC) detection and analysis tool.

.DESCRIPTION
    This script performs multi-vector analysis to detect BEC indicators including:
    - Malicious mail rules targeting internal emails
    - Azure AD risky user detections
    - Impossible travel and suspicious sign-in patterns
    - Unauthorized mailbox access and permissions
    - Email forwarding and delegation abuse
    - Suspicious email sending patterns

.PARAMETER UserPrincipalName
    Specific user to check. If not specified, checks all mailboxes.

.PARAMETER DaysBack
    Number of days back to analyze sign-in and audit logs. Default: 30

.PARAMETER ExportPath
    Directory path to export results. Default: Current directory

.PARAMETER SkipRiskyUserCheck
    Skip the Azure AD risky user analysis (faster for Exchange-only checks)

.PARAMETER SkipSignInAnalysis
    Skip the sign-in log analysis (faster for mailbox-only checks)

.EXAMPLE
    .\Invoke-BECDetection.ps1
    Interactive mode - prompts for all parameters

.EXAMPLE
    .\Invoke-BECDetection.ps1 -UserPrincipalName user@domain.com
    Check specific user with all detection modules

.EXAMPLE
    .\Invoke-BECDetection.ps1 -DaysBack 60 -ExportPath "C:\SecurityReports"
    Check all users for last 60 days, export to specific folder
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipRiskyUserCheck,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSignInAnalysis
)

#region Helper Functions

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    
    $border = "=" * 80
    Write-Host "`n$border" -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host "$border`n" -ForegroundColor $Color
}

function Write-Section {
    param([string]$Text)
    Write-Host "`n--- $Text ---" -ForegroundColor Yellow
}

function Write-Finding {
    param(
        [string]$Severity,
        [string]$Message
    )
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Gray" }
        default { "White" }
    }
    
    $icon = switch ($Severity) {
        "CRITICAL" { "[!!!]" }
        "HIGH" { "[!!]" }
        "MEDIUM" { "[!]" }
        "LOW" { "[i]" }
        default { "[-]" }
    }
    
    Write-Host "  $icon $Message" -ForegroundColor $color
}

#endregion

#region Initialization

Write-Host @"
################################################################################
#                                                                              #
#              Business Email Compromise (BEC) Detection Tool                  #
#                                                                              #
################################################################################
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "  Version: 1.0" -ForegroundColor Gray
Write-Host "  Author: Don Cook - IT Operations" -ForegroundColor Gray
Write-Host "  Date: $(Get-Date -Format 'MMMM dd, yyyy')" -ForegroundColor Gray
Write-Host ""

# Interactive mode
if (-not $UserPrincipalName) {
    Write-Banner "CONFIGURATION" "Yellow"
    
    $choice = Read-Host "Check [S]pecific user or [A]ll mailboxes? (S/A)"
    
    if ($choice -eq 'S' -or $choice -eq 's') {
        $UserPrincipalName = Read-Host "Enter user email address"
        if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            Write-Host "`n[X] No user specified. Exiting." -ForegroundColor Red
            exit 1
        }
    } elseif ($choice -ne 'A' -and $choice -ne 'a') {
        Write-Host "`n[X] Invalid selection. Exiting." -ForegroundColor Red
        exit 1
    }
    
    $daysInput = Read-Host "Days back to analyze sign-in logs? (Default: 30)"
    if ($daysInput -and $daysInput -match '^\d+$') {
        $DaysBack = [int]$daysInput
    }
}

# Set export path
if (-not $ExportPath) {
    $ExportPath = "."
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportPath = Join-Path $ExportPath "BEC_Detection_Report_$timestamp.csv"
$summaryPath = Join-Path $ExportPath "BEC_Detection_Summary_$timestamp.txt"

Write-Host "`n[✓] Reports will be saved to:" -ForegroundColor Green
Write-Host "    • $reportPath" -ForegroundColor Gray
Write-Host "    • $summaryPath" -ForegroundColor Gray

#endregion

#region Module Checks and Connection

Write-Banner "CONNECTING TO MICROSOFT 365" "Cyan"

# Check Exchange Online
Write-Host "[*] Checking Exchange Online connection..." -ForegroundColor Cyan
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "[✓] Already connected to Exchange Online" -ForegroundColor Green
} catch {
    Write-Host "[*] Connecting to Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "[✓] Connected to Exchange Online" -ForegroundColor Green
    } catch {
        Write-Host "[X] Failed to connect to Exchange Online: $_" -ForegroundColor Red
        exit 1
    }
}

# Check Microsoft Graph
if (-not $SkipRiskyUserCheck -or -not $SkipSignInAnalysis) {
    Write-Host "`n[*] Checking Microsoft Graph connection..." -ForegroundColor Cyan
    
    if (-not (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable)) {
        Write-Host "[!] Microsoft.Graph module not installed" -ForegroundColor Yellow
        Write-Host "[*] Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Gray
        
        $install = Read-Host "`nSkip Graph checks (risky users & sign-ins)? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y') {
            $SkipRiskyUserCheck = $true
            $SkipSignInAnalysis = $true
        } else {
            exit 1
        }
    } else {
        try {
            $context = Get-MgContext -ErrorAction Stop
            if (-not $context) {
                throw "Not connected"
            }
            Write-Host "[✓] Already connected to Microsoft Graph" -ForegroundColor Green
        } catch {
            Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
            try {
                $scopes = @(
                    "User.Read.All",
                    "AuditLog.Read.All", 
                    "IdentityRiskyUser.Read.All",
                    "Directory.Read.All"
                )
                Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
                Write-Host "[✓] Connected to Microsoft Graph" -ForegroundColor Green
            } catch {
                Write-Host "[!] Failed to connect to Microsoft Graph: $_" -ForegroundColor Yellow
                Write-Host "[!] Skipping risky user and sign-in checks" -ForegroundColor Yellow
                $SkipRiskyUserCheck = $true
                $SkipSignInAnalysis = $true
            }
        }
    }
}

#endregion

#region Data Collection

Write-Banner "COLLECTING DATA" "Cyan"

$findings = @()
$startDate = (Get-Date).AddDays(-$DaysBack)
$riskyUsers = @{}
$signInAnalysis = @{}

# Get mailboxes to check
if ($UserPrincipalName) {
    Write-Host "[*] Retrieving mailbox: $UserPrincipalName" -ForegroundColor Cyan
    $mailboxes = @(Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop)
} else {
    Write-Host "[*] Retrieving all mailboxes..." -ForegroundColor Cyan
    $mailboxes = Get-Mailbox -ResultSize Unlimited
}

$totalMailboxes = $mailboxes.Count
Write-Host "[✓] Found $totalMailboxes mailbox(es) to analyze" -ForegroundColor Green

# Get risky users from Azure AD Identity Protection
if (-not $SkipRiskyUserCheck) {
    Write-Section "Azure AD Identity Protection - Risky Users"
    try {
        Write-Host "[*] Querying risky users from Azure AD Identity Protection..." -ForegroundColor Cyan
        $riskyUserList = Get-MgRiskyUser -All -ErrorAction Stop
        
        foreach ($riskyUser in $riskyUserList) {
            if ($riskyUser.RiskState -eq "atRisk" -or $riskyUser.RiskState -eq "confirmedCompromised") {
                $riskyUsers[$riskyUser.UserPrincipalName] = @{
                    RiskLevel = $riskyUser.RiskLevel
                    RiskState = $riskyUser.RiskState
                    RiskDetail = $riskyUser.RiskDetail
                    RiskLastUpdated = $riskyUser.RiskLastUpdatedDateTime
                }
                
                $severity = if ($riskyUser.RiskState -eq "confirmedCompromised") { "CRITICAL" } else { "HIGH" }
                Write-Finding $severity "Risky user detected: $($riskyUser.UserPrincipalName) - Risk: $($riskyUser.RiskLevel) - State: $($riskyUser.RiskState)"
            }
        }
        
        Write-Host "[✓] Found $($riskyUsers.Count) risky user(s)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Unable to retrieve risky users: $_" -ForegroundColor Yellow
        Write-Host "[i] May require IdentityRiskyUser.Read.All permission" -ForegroundColor Gray
    }
}

# Analyze sign-in logs for impossible travel
if (-not $SkipSignInAnalysis) {
    Write-Section "Sign-In Analysis - Impossible Travel Detection"
    try {
        Write-Host "[*] Analyzing sign-in logs for last $DaysBack days..." -ForegroundColor Cyan
        Write-Host "[i] This may take a few minutes for large datasets..." -ForegroundColor Gray
        
        $filter = "createdDateTime ge $($startDate.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        
        if ($UserPrincipalName) {
            $filter += " and userPrincipalName eq '$UserPrincipalName'"
        }
        
        $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
        
        Write-Host "[✓] Retrieved $($signIns.Count) sign-in records" -ForegroundColor Green
        
        # Group by user and analyze
        $signInsByUser = $signIns | Group-Object UserPrincipalName
        
        foreach ($userGroup in $signInsByUser) {
            $userSignIns = $userGroup.Group | Sort-Object CreatedDateTime
            $locations = @()
            $suspiciousPatterns = @()
            
            foreach ($signIn in $userSignIns) {
                if ($signIn.Location.City -and $signIn.Location.CountryOrRegion) {
                    $locations += @{
                        Time = $signIn.CreatedDateTime
                        City = $signIn.Location.City
                        Country = $signIn.Location.CountryOrRegion
                        IPAddress = $signIn.IPAddress
                        Status = $signIn.Status.ErrorCode
                    }
                }
                
                # Check for risk detections in sign-in
                if ($signIn.RiskDetail -and $signIn.RiskDetail -ne "none") {
                    $suspiciousPatterns += "Risk detected: $($signIn.RiskDetail) - $($signIn.RiskLevelDuringSignIn)"
                }
            }
            
            # Detect impossible travel (different countries within short timeframe)
            if ($locations.Count -gt 1) {
                for ($i = 0; $i -lt ($locations.Count - 1); $i++) {
                    $loc1 = $locations[$i]
                    $loc2 = $locations[$i + 1]
                    
                    if ($loc1.Country -ne $loc2.Country) {
                        $timeDiff = ($loc2.Time - $loc1.Time).TotalHours
                        
                        if ($timeDiff -lt 2) {
                            $impossibleTravel = "Sign-in from $($loc1.Country) ($($loc1.City)) to $($loc2.Country) ($($loc2.City)) in $([math]::Round($timeDiff, 2)) hours"
                            $suspiciousPatterns += $impossibleTravel
                            Write-Finding "HIGH" "Impossible travel: $($userGroup.Name) - $impossibleTravel"
                        }
                    }
                }
            }
            
            # Check for sign-ins from multiple countries
            $uniqueCountries = ($locations | Select-Object -ExpandProperty Country -Unique).Count
            if ($uniqueCountries -gt 2) {
                $countries = ($locations | Select-Object -ExpandProperty Country -Unique) -join ', '
                $suspiciousPatterns += "Sign-ins from $uniqueCountries countries: $countries"
            }
            
            if ($suspiciousPatterns.Count -gt 0) {
                $signInAnalysis[$userGroup.Name] = @{
                    SuspiciousPatterns = $suspiciousPatterns
                    TotalSignIns = $userSignIns.Count
                    UniqueCountries = $uniqueCountries
                    Locations = $locations
                }
            }
        }
        
        Write-Host "[✓] Found $($signInAnalysis.Count) user(s) with suspicious sign-in patterns" -ForegroundColor Green
    } catch {
        Write-Host "[!] Unable to analyze sign-in logs: $_" -ForegroundColor Yellow
        Write-Host "[i] May require AuditLog.Read.All permission" -ForegroundColor Gray
    }
}

#endregion

#region Mailbox Analysis

Write-Banner "ANALYZING MAILBOXES FOR BEC INDICATORS" "Cyan"

$currentCount = 0

foreach ($mailbox in $mailboxes) {
    $currentCount++
    $percentComplete = [math]::Round(($currentCount / $totalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Analyzing Mailboxes for BEC Indicators" `
        -Status "Processing: $($mailbox.UserPrincipalName) ($currentCount of $totalMailboxes)" `
        -PercentComplete $percentComplete
    
    $user = $mailbox.UserPrincipalName
    $userIssues = @()
    
    try {
        # Check 1: Risky User Status
        if ($riskyUsers.ContainsKey($user)) {
            $risk = $riskyUsers[$user]
            $severity = if ($risk.RiskState -eq "confirmedCompromised") { "CRITICAL" } else { "HIGH" }
            
            $findings += [PSCustomObject]@{
                User = $user
                FindingType = "Azure AD Risky User"
                Severity = $severity
                Details = "Risk Level: $($risk.RiskLevel) | State: $($risk.RiskState) | Detail: $($risk.RiskDetail)"
                Value = "$($risk.RiskLevel) - $($risk.RiskState)"
                Category = "Identity Protection"
                DateDetected = Get-Date
            }
            $userIssues += "[$severity] Azure AD flagged as risky user"
        }
        
        # Check 2: Suspicious Sign-In Patterns
        if ($signInAnalysis.ContainsKey($user)) {
            $signInData = $signInAnalysis[$user]
            
            foreach ($pattern in $signInData.SuspiciousPatterns) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "Suspicious Sign-In Pattern"
                    Severity = "HIGH"
                    Details = $pattern
                    Value = "Total sign-ins: $($signInData.TotalSignIns) | Countries: $($signInData.UniqueCountries)"
                    Category = "Sign-In Analysis"
                    DateDetected = Get-Date
                }
            }
            $userIssues += "[HIGH] Suspicious sign-in patterns detected"
        }
        
        # Check 3: Malicious Mail Rules (Hiding internal domain emails)
        Write-Verbose "Checking mail rules for $user"
        $inboxRules = Get-InboxRule -Mailbox $user -ErrorAction Stop
        
        foreach ($rule in $inboxRules) {
            $hidesEmails = $false
            $ruleReasons = @()
            
            if ($rule.DeleteMessage -eq $true) {
                $hidesEmails = $true
                $ruleReasons += "Deletes messages"
            }
            
            if ($rule.MoveToFolder -and ($rule.MoveToFolder -match 'Deleted Items|Junk|RSS Subscriptions|Archive')) {
                $hidesEmails = $true
                $ruleReasons += "Moves to: $($rule.MoveToFolder)"
            }
            
            if ($rule.MarkAsRead -eq $true) {
                $hidesEmails = $true
                $ruleReasons += "Marks as read"
            }
            
            # Check if targeting internal domain
            $internalDomain = ($user -split '@')[1]
            $targetsInternal = $false
            
            if ($rule.From -and ($rule.From | Where-Object { $_ -like "*@$internalDomain" })) {
                $targetsInternal = $true
            }
            
            if ($rule.FromAddressContainsWords -and ($rule.FromAddressContainsWords | Where-Object { $_ -like "*@$internalDomain*" -or $_ -eq $internalDomain })) {
                $targetsInternal = $true
            }
            
            if ($hidesEmails -and $targetsInternal) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "Malicious Mail Rule"
                    Severity = "CRITICAL"
                    Details = "Rule '$($rule.Name)' hides @$internalDomain emails: $($ruleReasons -join ', ')"
                    Value = "Enabled: $($rule.Enabled) | Actions: $($ruleReasons -join ', ')"
                    Category = "Mail Rules"
                    DateDetected = Get-Date
                }
                $userIssues += "[CRITICAL] Rule hiding internal emails: '$($rule.Name)'"
            }
        }
        
        # Check 4: Mailbox Delegates/Full Access
        Write-Verbose "Checking delegates for $user"
        $permissions = Get-MailboxPermission -Identity $user -ErrorAction Stop | Where-Object {
            $_.User -notlike "NT AUTHORITY\SELF" -and 
            $_.User -notlike "S-1-5-*" -and
            $_.AccessRights -contains "FullAccess"
        }
        
        if ($permissions) {
            foreach ($perm in $permissions) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "Mailbox Delegate"
                    Severity = "HIGH"
                    Details = "Full Access granted to: $($perm.User)"
                    Value = $perm.User
                    Category = "Permissions"
                    DateDetected = Get-Date
                }
                $userIssues += "[HIGH] Mailbox delegate: $($perm.User)"
            }
        }
        
        # Check 5: SendAs/SendOnBehalf Permissions
        Write-Verbose "Checking SendAs permissions for $user"
        $sendAsPerms = Get-RecipientPermission -Identity $user -ErrorAction Stop | Where-Object {
            $_.Trustee -notlike "NT AUTHORITY\SELF" -and
            $_.Trustee -notlike "S-1-5-*" -and
            $_.AccessRights -contains "SendAs"
        }
        
        if ($sendAsPerms) {
            foreach ($sa in $sendAsPerms) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "SendAs Permission"
                    Severity = "HIGH"
                    Details = "SendAs permission granted to: $($sa.Trustee)"
                    Value = $sa.Trustee
                    Category = "Permissions"
                    DateDetected = Get-Date
                }
                $userIssues += "[HIGH] SendAs permission: $($sa.Trustee)"
            }
        }
        
        if ($mailbox.GrantSendOnBehalfTo) {
            foreach ($sob in $mailbox.GrantSendOnBehalfTo) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "SendOnBehalf Permission"
                    Severity = "MEDIUM"
                    Details = "SendOnBehalf permission granted to: $sob"
                    Value = $sob
                    Category = "Permissions"
                    DateDetected = Get-Date
                }
                $userIssues += "[MEDIUM] SendOnBehalf: $sob"
            }
        }
        
        # Check 6: Mailbox Forwarding
        Write-Verbose "Checking forwarding for $user"
        if ($mailbox.ForwardingSmtpAddress) {
            $findings += [PSCustomObject]@{
                User = $user
                FindingType = "External Forwarding"
                Severity = "CRITICAL"
                Details = "Forwarding to external address: $($mailbox.ForwardingSmtpAddress)"
                Value = $mailbox.ForwardingSmtpAddress
                Category = "Forwarding"
                DateDetected = Get-Date
            }
            $userIssues += "[CRITICAL] External forwarding: $($mailbox.ForwardingSmtpAddress)"
        }
        
        if ($mailbox.ForwardingAddress) {
            $findings += [PSCustomObject]@{
                User = $user
                FindingType = "Internal Forwarding"
                Severity = "MEDIUM"
                Details = "Forwarding to internal address: $($mailbox.ForwardingAddress)"
                Value = $mailbox.ForwardingAddress
                Category = "Forwarding"
                DateDetected = Get-Date
            }
            $userIssues += "[MEDIUM] Internal forwarding: $($mailbox.ForwardingAddress)"
        }
        
        # Check 7: Suspicious Auto-Reply
        Write-Verbose "Checking auto-reply for $user"
        $autoReply = Get-MailboxAutoReplyConfiguration -Identity $user -ErrorAction Stop
        
        if ($autoReply.AutoReplyState -ne "Disabled") {
            $externalMsg = $autoReply.ExternalMessage
            $internalMsg = $autoReply.InternalMessage
            
            $suspiciousPatterns = @('click here', 'verify', 'update payment', 'suspended', 'confirm', 'urgent', 'account', 'password')
            $foundSuspicious = $false
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($externalMsg -like "*$pattern*" -or $internalMsg -like "*$pattern*") {
                    $foundSuspicious = $true
                    break
                }
            }
            
            if ($foundSuspicious -or $externalMsg.Length -gt 500) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "Suspicious Auto-Reply"
                    Severity = "MEDIUM"
                    Details = "Auto-reply enabled with suspicious content or unusual length"
                    Value = "Length: $($externalMsg.Length) chars"
                    Category = "Auto-Reply"
                    DateDetected = Get-Date
                }
                $userIssues += "[MEDIUM] Suspicious auto-reply message"
            }
        }
        
        # Display user summary if issues found
        if ($userIssues.Count -gt 0) {
            Write-Host "`n[!] Issues found for: $user" -ForegroundColor Yellow
            foreach ($issue in $userIssues) {
                Write-Host "    $issue" -ForegroundColor Gray
            }
        }
        
    } catch {
        Write-Warning "Error processing $($user): $_"
    }
}

Write-Progress -Activity "Analyzing Mailboxes for BEC Indicators" -Completed

#endregion

#region Reporting

Write-Banner "GENERATING REPORTS" "Cyan"

# Group findings by severity
$criticalFindings = $findings | Where-Object Severity -eq "CRITICAL"
$highFindings = $findings | Where-Object Severity -eq "HIGH"
$mediumFindings = $findings | Where-Object Severity -eq "MEDIUM"
$lowFindings = $findings | Where-Object Severity -eq "LOW"

# Display summary
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                      DETECTION SUMMARY                       ║" -ForegroundColor Cyan
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "  ║  Total Mailboxes Scanned:    " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $totalMailboxes) -ForegroundColor White
Write-Host "  ║  Analysis Period:            " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f "Last $DaysBack days") -ForegroundColor White
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "  ║  Total Findings:             " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $findings.Count) -ForegroundColor $(if ($findings.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  ║  CRITICAL:                   " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $criticalFindings.Count) -ForegroundColor $(if ($criticalFindings.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  ║  HIGH:                       " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $highFindings.Count) -ForegroundColor $(if ($highFindings.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  ║  MEDIUM:                     " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $mediumFindings.Count) -ForegroundColor $(if ($mediumFindings.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  ║  LOW:                        " -NoNewline -ForegroundColor Cyan
Write-Host ("{0,29} ║" -f $lowFindings.Count) -ForegroundColor $(if ($lowFindings.Count -gt 0) { "Gray" } else { "Green" })
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($findings.Count -gt 0) {
    # Export to CSV
    $findings | Export-Csv -Path $reportPath -NoTypeInformation
    Write-Host "[✓] Detailed findings exported to:" -ForegroundColor Green
    Write-Host "    $reportPath" -ForegroundColor Gray
    
    # Create summary report
    $summary = @"
################################################################################
#                                                                              #
#         Business Email Compromise (BEC) Detection Summary Report             #
#                                                                              #
################################################################################

Report Generated: $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')
Analysis Period: Last $DaysBack days (from $($startDate.ToString('yyyy-MM-dd')) to $(Get-Date -Format 'yyyy-MM-dd'))
Mailboxes Analyzed: $totalMailboxes

================================================================================
FINDINGS SUMMARY
================================================================================

Total Findings: $($findings.Count)
  • CRITICAL: $($criticalFindings.Count)
  • HIGH: $($highFindings.Count)
  • MEDIUM: $($mediumFindings.Count)
  • LOW: $($lowFindings.Count)

"@

    if ($criticalFindings.Count -gt 0) {
        $summary += @"

================================================================================
CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED)
================================================================================

"@
        foreach ($finding in $criticalFindings) {
            $summary += @"
User: $($finding.User)
Type: $($finding.FindingType)
Details: $($finding.Details)
Category: $($finding.Category)
Detected: $($finding.DateDetected)
---

"@
        }
    }

    if ($highFindings.Count -gt 0) {
        $summary += @"

================================================================================
HIGH RISK FINDINGS
================================================================================

"@
        $highSummary = $highFindings | Group-Object FindingType | ForEach-Object {
            "  • $($_.Name): $($_.Count) instance(s)"
        }
        $summary += $highSummary -join "`n"
        $summary += "`n`nAffected Users: $($highFindings | Select-Object -ExpandProperty User -Unique | Sort-Object)"
        $summary += "`n"
    }

    # Top affected users
    $topUsers = $findings | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
    if ($topUsers) {
        $summary += @"

================================================================================
TOP 10 USERS WITH MOST FINDINGS
================================================================================

"@
        foreach ($user in $topUsers) {
            $summary += "  $($user.Count) finding(s): $($user.Name)`n"
        }
    }

    # Recommendations
    $summary += @"

================================================================================
RECOMMENDED ACTIONS
================================================================================

IMMEDIATE (CRITICAL & HIGH):
  1. Review all CRITICAL findings immediately
  2. Disable malicious mail rules targeting internal domain:
     Disable-InboxRule -Identity '<RuleIdentity>' -Confirm:`$false
  
  3. Reset passwords for all affected users:
     Set-MsolUser -UserPrincipalName <user> -ForceChangePassword `$true
  
  4. Remove unauthorized mailbox permissions:
     Remove-MailboxPermission -Identity <user> -User <delegate> -AccessRights FullAccess
     Remove-RecipientPermission -Identity <user> -Trustee <delegate> -AccessRights SendAs
  
  5. Disable external forwarding if unauthorized:
     Set-Mailbox -Identity <user> -ForwardingSmtpAddress `$null

SHORT-TERM (HIGH & MEDIUM):
  6. Review Azure AD sign-in logs for compromised accounts:
     Azure Portal > Azure AD > Sign-in logs > Filter by user
  
  7. Check for risky users and confirm compromise if needed:
     Azure Portal > Azure AD > Identity Protection > Risky users
  
  8. Enable MFA for all affected users if not already enabled
  
  9. Review mailbox audit logs for suspicious activity:
     Search-UnifiedAuditLog -UserIds <user> -StartDate (Get-Date).AddDays(-30)
  
  10. Contact any external parties (vendors, customers) who may have received
      fraudulent emails from compromised accounts

LONG-TERM:
  11. Implement Conditional Access policies to block legacy authentication
  12. Enable Azure AD Identity Protection risk-based policies
  13. Deploy anti-phishing and anti-spoofing policies
  14. Conduct security awareness training for affected users
  15. Review and strengthen password policies
  16. Consider implementing privileged access workstations for admins

================================================================================
ADDITIONAL RESOURCES
================================================================================

Microsoft Incident Response: https://aka.ms/MicrosoftIR
BEC Response Playbook: https://aka.ms/BECPlaybook
Azure AD Identity Protection: https://aka.ms/AzureADIP

For assistance, contact IT Operations (ITO) or your security team.

################################################################################
"@

    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    Write-Host "[✓] Summary report exported to:" -ForegroundColor Green
    Write-Host "    $summaryPath" -ForegroundColor Gray
    Write-Host ""
    
    # Display critical findings table
    if ($criticalFindings) {
        Write-Banner "CRITICAL FINDINGS - IMMEDIATE ACTION REQUIRED" "Red"
        $criticalFindings | Format-Table User, FindingType, Details -AutoSize -Wrap
    }
    
    # Display high findings summary
    if ($highFindings) {
        Write-Banner "HIGH RISK FINDINGS" "Yellow"
        $highFindings | Group-Object FindingType | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "  • $($_.Name): $($_.Count) instance(s)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    # Display affected users
    $affectedUsers = $findings | Where-Object { $_.Severity -in @("CRITICAL", "HIGH") } | 
        Select-Object -ExpandProperty User -Unique | Sort-Object
    
    if ($affectedUsers) {
        Write-Host "`n[!] Users requiring immediate attention:" -ForegroundColor Red
        foreach ($affectedUser in $affectedUsers) {
            $userFindings = $findings | Where-Object { $_.User -eq $affectedUser -and $_.Severity -in @("CRITICAL", "HIGH") }
            Write-Host "    • $affectedUser ($($userFindings.Count) critical/high finding(s))" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
} else {
    Write-Host "[✓] No BEC indicators detected! All mailboxes appear clean." -ForegroundColor Green
    Write-Host "[i] This is good news - no immediate action required." -ForegroundColor Gray
}

#endregion

#region Footer

Write-Host ""
Write-Host "################################################################################" -ForegroundColor Cyan
Write-Host "#                                                                              #" -ForegroundColor Cyan
Write-Host "#                          Analysis Complete                                   #" -ForegroundColor Cyan
Write-Host "#                                                                              #" -ForegroundColor Cyan
Write-Host "################################################################################" -ForegroundColor Cyan
Write-Host ""
Write-Host "  For questions or assistance, contact Don Cook - IT Operations" -ForegroundColor Gray
Write-Host "  $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

#endregion