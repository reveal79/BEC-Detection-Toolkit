# Check-MaliciousMailRules.ps1
# Script to detect mailbox rules that may indicate compromise
# Specifically looking for rules that delete/reject internal emails

<#
.SYNOPSIS
    Checks for suspicious mailbox rules that could indicate a compromised account.

.DESCRIPTION
    This script examines Inbox rules for specified users or all users to detect
    rules that delete, move, or reject internal emails - a common attacker tactic
    to hide their activities from being discovered by coworkers.

.PARAMETER UserPrincipalName
    Specific user to check. If not specified, checks all mailboxes.

.PARAMETER ExportPath
    Path to export results CSV file. Default: Current directory

.EXAMPLE
    .\Check-MaliciousMailRules.ps1 -UserPrincipalName user@domain.com
    
.EXAMPLE
    .\Check-MaliciousMailRules.ps1 -ExportPath "C:\Reports\MailRules.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Interactive mode - ask for parameters if not provided
if (-not $UserPrincipalName) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Mailbox Compromise Detection Script" -ForegroundColor Cyan
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

# Set default export path if not provided
if (-not $ExportPath) {
    $defaultPath = ".\SuspiciousMailRules_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $ExportPath = $defaultPath
    Write-Host "Results will be exported to: $ExportPath" -ForegroundColor Gray
}

# Ensure Exchange Online module is loaded
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Error "Exchange Online Management module not found. Install with: Install-Module -Name ExchangeOnlineManagement"
    exit 1
}

# Connect to Exchange Online if not already connected
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Already connected to Exchange Online" -ForegroundColor Green
} catch {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false
}

# Suspicious patterns to look for
$suspiciousPatterns = @{
    'DeleteMessage' = 'Rule deletes messages'
    'MoveToFolder' = 'Rule moves messages to folder'
    'MarkAsRead' = 'Rule marks messages as read'
    'ForwardTo' = 'Rule forwards to external address'
    'RedirectTo' = 'Rule redirects to external address'
    'Junk' = 'Rule moves to Junk/Deleted Items'
    'RSS' = 'Rule moves to RSS folder'
}

$results = @()

# Get mailboxes to check
if ($UserPrincipalName) {
    Write-Host "Checking mailbox: $UserPrincipalName" -ForegroundColor Cyan
    $mailboxes = @(Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop)
} else {
    Write-Host "Retrieving all mailboxes..." -ForegroundColor Cyan
    $mailboxes = Get-Mailbox -ResultSize Unlimited
}

$totalMailboxes = $mailboxes.Count
$currentCount = 0

Write-Host "`nAnalyzing $totalMailboxes mailbox(es) for suspicious rules...`n" -ForegroundColor Yellow

foreach ($mailbox in $mailboxes) {
    $currentCount++
    Write-Progress -Activity "Scanning Mailboxes" -Status "Processing: $($mailbox.UserPrincipalName)" -PercentComplete (($currentCount / $totalMailboxes) * 100)
    
    try {
        # Get inbox rules for the mailbox
        $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop
        
        foreach ($rule in $rules) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            # Check for deletion actions
            if ($rule.DeleteMessage -eq $true) {
                $isSuspicious = $true
                $suspiciousReasons += "Deletes messages"
            }
            
            # Check for moves to deleted items or junk
            if ($rule.MoveToFolder -and ($rule.MoveToFolder -match 'Deleted Items|Junk|RSS Subscriptions|Archive')) {
                $isSuspicious = $true
                $suspiciousReasons += "Moves to: $($rule.MoveToFolder)"
            }
            
            # Check for mark as read (hiding new messages)
            if ($rule.MarkAsRead -eq $true) {
                $isSuspicious = $true
                $suspiciousReasons += "Marks messages as read"
            }
            
            # Check for forwarding to external addresses
            if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo) {
                $isSuspicious = $true
                $suspiciousReasons += "Forwards to: $($rule.ForwardTo -join ', ')$($rule.ForwardAsAttachmentTo -join ', ')"
            }
            
            # Check for redirection
            if ($rule.RedirectTo) {
                $isSuspicious = $true
                $suspiciousReasons += "Redirects to: $($rule.RedirectTo -join ', ')"
            }
            
            # Check if rule targets internal senders (from domain)
            $targetsInternal = $false
            $internalDomain = ($mailbox.UserPrincipalName -split '@')[1]
            
            if ($rule.From -and ($rule.From | Where-Object { $_ -like "*@$internalDomain" })) {
                $targetsInternal = $true
            }
            
            if ($rule.FromAddressContainsWords -and ($rule.FromAddressContainsWords | Where-Object { $_ -like "*@$internalDomain*" -or $_ -eq $internalDomain })) {
                $targetsInternal = $true
            }
            
            # HIGH RISK: Rule that affects internal emails AND performs suspicious actions
            if ($isSuspicious -and $targetsInternal) {
                $severity = "HIGH RISK"
            } elseif ($isSuspicious) {
                $severity = "MEDIUM RISK"
            } else {
                continue  # Skip non-suspicious rules
            }
            
            # Create result object
            $result = [PSCustomObject]@{
                Severity = $severity
                UserPrincipalName = $mailbox.UserPrincipalName
                RuleName = $rule.Name
                RuleEnabled = $rule.Enabled
                RuleDescription = $rule.Description
                TargetsInternal = $targetsInternal
                SuspiciousActions = ($suspiciousReasons -join '; ')
                From = ($rule.From -join ', ')
                FromContains = ($rule.FromAddressContainsWords -join ', ')
                SubjectContains = ($rule.SubjectContainsWords -join ', ')
                DeleteMessage = $rule.DeleteMessage
                MoveToFolder = $rule.MoveToFolder
                MarkAsRead = $rule.MarkAsRead
                ForwardTo = ($rule.ForwardTo -join ', ')
                RedirectTo = ($rule.RedirectTo -join ', ')
                RuleIdentity = $rule.Identity
            }
            
            $results += $result
            
            # Display high-risk findings immediately
            if ($severity -eq "HIGH RISK") {
                Write-Host "`n[!] HIGH RISK RULE DETECTED!" -ForegroundColor Red
                Write-Host "    User: $($mailbox.UserPrincipalName)" -ForegroundColor Yellow
                Write-Host "    Rule: $($rule.Name)" -ForegroundColor Yellow
                Write-Host "    Actions: $($suspiciousReasons -join ', ')" -ForegroundColor Yellow
                Write-Host "    Targets Internal: Yes" -ForegroundColor Red
                Write-Host "    Rule Enabled: $($rule.Enabled)" -ForegroundColor Yellow
                
                # Ask if user wants to disable this rule
                if ($rule.Enabled) {
                    $response = Read-Host "`n    Do you want to DISABLE this rule now? (Y/N)"
                    if ($response -eq 'Y' -or $response -eq 'y') {
                        try {
                            Disable-InboxRule -Identity $rule.Identity -Confirm:$false
                            Write-Host "    [✓] Rule disabled successfully!" -ForegroundColor Green
                            $result.RuleEnabled = $false
                            $result | Add-Member -MemberType NoteProperty -Name "ActionTaken" -Value "Disabled by script"
                        } catch {
                            Write-Host "    [X] Failed to disable rule: $_" -ForegroundColor Red
                            $result | Add-Member -MemberType NoteProperty -Name "ActionTaken" -Value "Failed to disable"
                        }
                    } else {
                        Write-Host "    Rule left enabled - manual action required" -ForegroundColor Yellow
                        $result | Add-Member -MemberType NoteProperty -Name "ActionTaken" -Value "No action taken"
                    }
                } else {
                    Write-Host "    Rule is already disabled" -ForegroundColor Gray
                    $result | Add-Member -MemberType NoteProperty -Name "ActionTaken" -Value "Already disabled"
                }
                Write-Host ""
            }
        }
    } catch {
        Write-Warning "Failed to retrieve rules for $($mailbox.UserPrincipalName): $_"
    }
}

Write-Progress -Activity "Scanning Mailboxes" -Completed

# Analyze for attack patterns (same rule name hitting multiple users)
$rulePatterns = $results | Where-Object Severity -eq "HIGH RISK" | Group-Object RuleName | Where-Object Count -gt 1 | Sort-Object Count -Descending

# Display summary
Write-Host "`n=========== SCAN SUMMARY ===========" -ForegroundColor Cyan
Write-Host "Total mailboxes scanned: $totalMailboxes" -ForegroundColor White
Write-Host "Suspicious rules found: $($results.Count)" -ForegroundColor Yellow
Write-Host "High-risk rules: $(($results | Where-Object Severity -eq 'HIGH RISK').Count)" -ForegroundColor Red
Write-Host "Medium-risk rules: $(($results | Where-Object Severity -eq 'MEDIUM RISK').Count)" -ForegroundColor Yellow

# Alert on attack patterns
if ($rulePatterns) {
    Write-Host "`n⚠️  ATTACK PATTERN DETECTED!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "The following rule(s) affected MULTIPLE users:" -ForegroundColor Red
    foreach ($pattern in $rulePatterns) {
        Write-Host "  • '$($pattern.Name)' - Found on $($pattern.Count) mailboxes" -ForegroundColor Yellow
        $affectedUsers = ($pattern.Group | Select-Object -ExpandProperty UserPrincipalName) -join ', '
        Write-Host "    Affected: $affectedUsers" -ForegroundColor Gray
    }
    Write-Host "`nThis indicates a coordinated attack or malware campaign!" -ForegroundColor Red
}

Write-Host "====================================`n" -ForegroundColor Cyan

if ($results.Count -gt 0) {
    # Always export to CSV
    $results | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "✓ Results exported to: $ExportPath" -ForegroundColor Green
    Write-Host "  Total suspicious rules logged: $($results.Count)" -ForegroundColor Gray
    
    # Display high-risk results in console
    $highRisk = $results | Where-Object Severity -eq "HIGH RISK"
    if ($highRisk) {
        Write-Host "`n=== HIGH RISK RULES (Internal Email Targeting) ===" -ForegroundColor Red
        $highRisk | Format-Table UserPrincipalName, RuleName, SuspiciousActions, RuleEnabled, ActionTaken -AutoSize
    }
    
    # Display medium-risk summary
    $mediumRisk = $results | Where-Object Severity -eq "MEDIUM RISK"
    if ($mediumRisk) {
        Write-Host "`n=== MEDIUM RISK RULES ===" -ForegroundColor Yellow
        Write-Host "Found $($mediumRisk.Count) medium-risk rule(s). See CSV for details." -ForegroundColor Gray
    }
    
    # Remediation suggestions
    Write-Host "`n=== RECOMMENDED ACTIONS ===" -ForegroundColor Yellow
    Write-Host "1. Review the exported CSV file for all findings" -ForegroundColor White
    Write-Host "`n2. For any remaining enabled rules, disable them using:" -ForegroundColor White
    Write-Host "   Disable-InboxRule -Identity '<RuleIdentity>'" -ForegroundColor Gray
    Write-Host "`n3. Reset passwords for affected users" -ForegroundColor White
    Write-Host "`n4. Review sign-in logs for suspicious activity:" -ForegroundColor White
    Write-Host "   Azure AD > Sign-in logs > Filter by user" -ForegroundColor Gray
    Write-Host "`n5. Check for mailbox delegates/forwarding:" -ForegroundColor White
    Write-Host "   Get-MailboxPermission -Identity <user>" -ForegroundColor Gray
    Write-Host "   Get-Mailbox -Identity <user> | Select ForwardingSmtpAddress" -ForegroundColor Gray
    Write-Host "`n6. Enable MFA if not already enabled" -ForegroundColor White
    Write-Host "`n7. Consider running a full mailbox audit:" -ForegroundColor White
    Write-Host "   Search-UnifiedAuditLog -UserIds <user> -StartDate (Get-Date).AddDays(-30)" -ForegroundColor Gray
    
} else {
    Write-Host "✓ No suspicious rules detected. All mailboxes appear clean." -ForegroundColor Green
    Write-Host "`nNote: Clean results were not exported to CSV." -ForegroundColor Gray
}

Write-Host "`nScript completed." -ForegroundColor Cyan