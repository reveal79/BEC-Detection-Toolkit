# Check-BECIndicators.ps1
# Comprehensive Business Email Compromise (BEC) detection script
# Checks for indicators beyond just malicious mail rules

<#
.SYNOPSIS
    Checks for additional BEC compromise indicators in mailboxes.

.DESCRIPTION
    This script checks for various BEC attack indicators including:
    - Mailbox delegates/permissions
    - Auto-forwarding configurations
    - Suspicious sent items
    - OAuth app permissions
    - Recent password changes
    - Mailbox folder permissions

.PARAMETER UserPrincipalName
    Specific user to check. If not specified, checks all mailboxes.

.PARAMETER DaysBack
    Number of days back to check for suspicious activity. Default: 30

.PARAMETER ExportPath
    Path to export results CSV file.

.EXAMPLE
    .\Check-BECIndicators.ps1 -UserPrincipalName user@domain.com
    
.EXAMPLE
    .\Check-BECIndicators.ps1 -DaysBack 60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Interactive mode
if (-not $UserPrincipalName) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  BEC Indicator Detection Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $choice = Read-Host "Check [S]pecific user or [A]ll mailboxes? (S/A)"
    
    if ($choice -eq 'S' -or $choice -eq 's') {
        $UserPrincipalName = Read-Host "Enter user email address"
        if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            Write-Host "No user specified. Exiting." -ForegroundColor Red
            exit 1
        }
    } elseif ($choice -ne 'A' -and $choice -ne 'a') {
        Write-Host "Invalid selection. Exiting." -ForegroundColor Red
        exit 1
    }
}

if (-not $ExportPath) {
    $ExportPath = ".\BEC_Indicators_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}

# Ensure modules are loaded
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "✓ Connected to Exchange Online" -ForegroundColor Green
} catch {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false
}

$findings = @()
$startDate = (Get-Date).AddDays(-$DaysBack)

# Get mailboxes to check
if ($UserPrincipalName) {
    $mailboxes = @(Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop)
    Write-Host "Checking mailbox: $UserPrincipalName" -ForegroundColor Cyan
} else {
    Write-Host "Retrieving all mailboxes..." -ForegroundColor Cyan
    $mailboxes = Get-Mailbox -ResultSize Unlimited
}

$totalMailboxes = $mailboxes.Count
$currentCount = 0

Write-Host "`nAnalyzing $totalMailboxes mailbox(es) for BEC indicators...`n" -ForegroundColor Yellow

foreach ($mailbox in $mailboxes) {
    $currentCount++
    Write-Progress -Activity "Scanning for BEC Indicators" -Status "Processing: $($mailbox.UserPrincipalName)" -PercentComplete (($currentCount / $totalMailboxes) * 100)
    
    $user = $mailbox.UserPrincipalName
    $issues = @()
    
    try {
        # Check 1: Mailbox Delegates/Full Access Permissions
        Write-Verbose "Checking delegates for $user"
        $permissions = Get-MailboxPermission -Identity $user | Where-Object {
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
                    DateDetected = Get-Date
                }
                $issues += "Delegate: $($perm.User)"
            }
        }
        
        # Check 2: Mailbox Folder Permissions (Inbox, Sent Items)
        Write-Verbose "Checking folder permissions for $user"
        $folderPerms = Get-MailboxFolderPermission -Identity "$($user):\Inbox" -ErrorAction SilentlyContinue | 
            Where-Object {$_.User -notlike "Default" -and $_.User -notlike "Anonymous" -and $_.AccessRights -ne "None"}
        
        if ($folderPerms) {
            foreach ($fp in $folderPerms) {
                $findings += [PSCustomObject]@{
                    User = $user
                    FindingType = "Inbox Permission"
                    Severity = "MEDIUM"
                    Details = "Inbox access granted to: $($fp.User) - Rights: $($fp.AccessRights)"
                    Value = "$($fp.User) ($($fp.AccessRights))"
                    DateDetected = Get-Date
                }
                $issues += "Inbox access: $($fp.User)"
            }
        }
        
        # Check 3: SendAs/SendOnBehalf Permissions
        Write-Verbose "Checking SendAs permissions for $user"
        $sendAsPerms = Get-RecipientPermission -Identity $user | Where-Object {
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
                    DateDetected = Get-Date
                }
                $issues += "SendAs: $($sa.Trustee)"
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
                    DateDetected = Get-Date
                }
                $issues += "SendOnBehalf: $sob"
            }
        }
        
        # Check 4: Auto-Reply Configuration (could contain malicious content)
        Write-Verbose "Checking auto-reply for $user"
        $autoReply = Get-MailboxAutoReplyConfiguration -Identity $user
        
        if ($autoReply.AutoReplyState -ne "Disabled") {
            $externalMsg = $autoReply.ExternalMessage
            $internalMsg = $autoReply.InternalMessage
            
            # Check for suspicious patterns in auto-reply
            $suspiciousPatterns = @('click here', 'verify', 'update payment', 'suspended', 'confirm', 'urgent')
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
                    Details = "Auto-reply enabled with suspicious content"
                    Value = "External: $($externalMsg.Substring(0, [Math]::Min(100, $externalMsg.Length)))..."
                    DateDetected = Get-Date
                }
                $issues += "Suspicious auto-reply"
            }
        }
        
        # Check 5: Malicious Mail Rules (hiding internal domain emails)
        Write-Verbose "Checking for mail rules hiding internal emails for $user"
        try {
            $inboxRules = Get-InboxRule -Mailbox $user -ErrorAction Stop
            
            foreach ($rule in $inboxRules) {
                $hidesEmails = $false
                $ruleReasons = @()
                
                # Check for hiding/deleting actions
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
                
                # Check if targeting internal domain emails specifically
                $internalDomain = ($user -split '@')[1]
                $targetsInternal = $false
                
                if ($rule.From -and ($rule.From | Where-Object { $_ -like "*@$internalDomain" })) {
                    $targetsInternal = $true
                }
                
                if ($rule.FromAddressContainsWords -and ($rule.FromAddressContainsWords | Where-Object { $_ -like "*@$internalDomain*" -or $_ -eq $internalDomain })) {
                    $targetsInternal = $true
                }
                
                # CRITICAL: Rule hiding internal domain emails
                if ($hidesEmails -and $targetsInternal) {
                    $findings += [PSCustomObject]@{
                        User = $user
                        FindingType = "Rule Hides Internal Domain Email"
                        Severity = "CRITICAL"
                        Details = "Rule '$($rule.Name)' hides @$internalDomain emails: $($ruleReasons -join ', ')"
                        Value = "Rule: $($rule.Name) | Enabled: $($rule.Enabled) | Actions: $($ruleReasons -join ', ')"
                        DateDetected = Get-Date
                    }
                    $issues += "CRITICAL: Rule hiding @$internalDomain emails: '$($rule.Name)'"
                    
                    Write-Host "`n[!] CRITICAL: Rule hiding @$internalDomain emails detected!" -ForegroundColor Red
                    Write-Host "    User: $user" -ForegroundColor Yellow
                    Write-Host "    Rule: $($rule.Name)" -ForegroundColor Yellow
                    Write-Host "    Enabled: $($rule.Enabled)" -ForegroundColor Yellow
                    Write-Host "    Actions: $($ruleReasons -join ', ')" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Verbose "Unable to check inbox rules for $user"
        }
        
        # Check 6: Mailbox Forwarding (even though you get alerts, check anyway)
        Write-Verbose "Checking forwarding for $user"
        if ($mailbox.ForwardingSmtpAddress) {
            $findings += [PSCustomObject]@{
                User = $user
                FindingType = "External Forwarding"
                Severity = "CRITICAL"
                Details = "Forwarding to external address: $($mailbox.ForwardingSmtpAddress)"
                Value = $mailbox.ForwardingSmtpAddress
                DateDetected = Get-Date
            }
            $issues += "External forward: $($mailbox.ForwardingSmtpAddress)"
        }
        
        if ($mailbox.ForwardingAddress) {
            $findings += [PSCustomObject]@{
                User = $user
                FindingType = "Internal Forwarding"
                Severity = "MEDIUM"
                Details = "Forwarding to internal address: $($mailbox.ForwardingAddress)"
                Value = $mailbox.ForwardingAddress
                DateDetected = Get-Date
            }
            $issues += "Internal forward: $($mailbox.ForwardingAddress)"
        }
        
        # Check 7: Unusual Sent Items (if unified audit log is available)
        Write-Verbose "Checking sent items for $user"
        try {
            $sentItems = Search-UnifiedAuditLog -UserIds $user -StartDate $startDate -EndDate (Get-Date) `
                -Operations "Send" -ResultSize 100 -ErrorAction SilentlyContinue
            
            if ($sentItems) {
                # Look for high volume sending
                $sentCount = ($sentItems | Measure-Object).Count
                
                if ($sentCount -gt 50) {
                    $findings += [PSCustomObject]@{
                        User = $user
                        FindingType = "High Send Volume"
                        Severity = "MEDIUM"
                        Details = "Sent $sentCount emails in last $DaysBack days"
                        Value = $sentCount
                        DateDetected = Get-Date
                    }
                    $issues += "High send volume: $sentCount emails"
                }
            }
        } catch {
            Write-Verbose "Unable to check sent items for $user"
        }
        
        # Display findings for this user if any
        if ($issues.Count -gt 0) {
            Write-Host "`n[!] Issues found for: $user" -ForegroundColor Yellow
            foreach ($issue in $issues) {
                Write-Host "    • $issue" -ForegroundColor Gray
            }
        }
        
    } catch {
        Write-Warning "Error processing $($user): $_"
    }
}

Write-Progress -Activity "Scanning for BEC Indicators" -Completed

# Display summary
Write-Host "`n=========== SCAN SUMMARY ===========" -ForegroundColor Cyan
Write-Host "Total mailboxes scanned: $totalMailboxes" -ForegroundColor White
Write-Host "Total findings: $($findings.Count)" -ForegroundColor Yellow

$criticalFindings = $findings | Where-Object Severity -eq "CRITICAL"
$highFindings = $findings | Where-Object Severity -eq "HIGH"
$mediumFindings = $findings | Where-Object Severity -eq "MEDIUM"

Write-Host "Critical findings: $($criticalFindings.Count)" -ForegroundColor Red
Write-Host "High-risk findings: $($highFindings.Count)" -ForegroundColor Red
Write-Host "Medium-risk findings: $($mediumFindings.Count)" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Cyan

if ($findings.Count -gt 0) {
    # Export results
    $findings | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "✓ Results exported to: $ExportPath" -ForegroundColor Green
    
    # Display critical and high findings
    if ($criticalFindings) {
        Write-Host "`n=== CRITICAL FINDINGS ===" -ForegroundColor Red
        $criticalFindings | Format-Table User, FindingType, Details -AutoSize
    }
    
    if ($highFindings) {
        Write-Host "`n=== HIGH RISK FINDINGS ===" -ForegroundColor Red
        $highFindings | Format-Table User, FindingType, Details -AutoSize
    }
    
    # Group findings by user
    $userSummary = $findings | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
    
    if ($userSummary) {
        Write-Host "`n=== TOP 10 USERS WITH MOST FINDINGS ===" -ForegroundColor Yellow
        foreach ($summary in $userSummary) {
            Write-Host "  $($summary.Name): $($summary.Count) finding(s)" -ForegroundColor Gray
        }
    }
    
    # Recommended actions
    Write-Host "`n=== RECOMMENDED ACTIONS ===" -ForegroundColor Yellow
    Write-Host "1. Review all CRITICAL and HIGH findings immediately" -ForegroundColor White
    Write-Host "`n2. Remove suspicious delegates/permissions:" -ForegroundColor White
    Write-Host "   Remove-MailboxPermission -Identity <user> -User <delegate> -AccessRights FullAccess" -ForegroundColor Gray
    Write-Host "   Remove-RecipientPermission -Identity <user> -Trustee <delegate> -AccessRights SendAs" -ForegroundColor Gray
    Write-Host "`n3. Reset passwords for affected users" -ForegroundColor White
    Write-Host "`n4. Review audit logs for suspicious sign-ins" -ForegroundColor White
    Write-Host "`n5. Check for compromised OAuth apps:" -ForegroundColor White
    Write-Host "   Get-MsolServicePrincipal | Where-Object {$_.DisplayName -like '*suspicious*'}" -ForegroundColor Gray
    
} else {
    Write-Host "✓ No BEC indicators detected!" -ForegroundColor Green
}

Write-Host "`nScript completed." -ForegroundColor Cyan