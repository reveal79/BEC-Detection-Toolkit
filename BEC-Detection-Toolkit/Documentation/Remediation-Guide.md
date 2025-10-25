# Remediation Guide

**Project:** BEC Detection Toolkit
**Author:** Don Cook
**Purpose:** This document provides structured response procedures for findings detected by the BEC Detection Toolkit in Microsoft 365 environments.

---

## 🧭 Overview

Each detector in the toolkit can trigger alerts at varying severity levels. This guide outlines immediate containment, short-term remediation, and long-term prevention steps for each finding type.

Use this document during incident response or as a training reference for IT/SOC teams.

---

## 🛑 High-Level Response Framework

| Phase            | Objective                     | Example Actions                                                     |
| ---------------- | ----------------------------- | ------------------------------------------------------------------- |
| **1. Contain**   | Stop attacker access          | Reset passwords, revoke sessions, disable malicious rules           |
| **2. Eradicate** | Remove persistence mechanisms | Revoke OAuth apps, delete mail rules, remove delegates              |
| **3. Recover**   | Restore business operations   | Restore inbox visibility, re-enable auditing, confirm MFA integrity |
| **4. Prevent**   | Implement security controls   | Conditional Access, number matching MFA, user education             |

---

## 📨 Inbox Rule Abuse

**Symptoms:**

* Inbox rules deleting, hiding, or forwarding internal emails.
* Finance or executive accounts missing key messages.

**Containment:**

* Run `Check-MaliciousMailRules.ps1` or `Invoke-BECDetection.ps1`.
* Confirm malicious rules and disable with `Disable-InboxRule`.
* Export rule details for recordkeeping.

**Eradication:**

* Reset password and revoke refresh tokens.
* Review delegated access using `Get-MailboxPermission` and `Remove-MailboxPermission` as needed.
* Check for similar rules across other mailboxes.

**Recovery:**

* Re-enable auditing if disabled.
* Notify affected departments of restored email visibility.

**Prevention:**

* Enforce MFA with number matching.
* Block automatic forwarding to external domains.
* Create a baseline of legitimate rules for comparison.

---

## 🌍 Impossible Travel / Geo Anomalies

**Symptoms:**

* Sign-ins from distant countries in short timeframes.
* Unfamiliar devices or client apps in logs.

**Containment:**

* Force sign-out of all sessions: `Revoke-AzureADUserAllRefreshToken`.
* Reset password immediately.

**Eradication:**

* Verify account recovery details not changed.
* Re-register MFA devices.
* Investigate related risky events (`Get-RiskyUser` or Graph API).

**Recovery:**

* Monitor subsequent sign-ins for 48–72 hours.

**Prevention:**

* Enforce location-based Conditional Access.
* Require compliant devices for sign-in.

---

## 👤 Risky Users (Identity Protection)

**Symptoms:**

* User flagged as high-risk by Microsoft Entra ID (Azure AD).
* Suspicious sign-ins or leaked credentials detected.

**Containment:**

* Require password reset and force MFA re-registration.
* Disable sign-ins temporarily for critical roles.

**Eradication:**

* Review risky service principals and OAuth grants.
* Remove any unused or suspicious tokens.

**Recovery:**

* Clear user’s risk state via Identity Protection once remediated.

**Prevention:**

* Enable real-time risk remediation policies.
* Block legacy authentication.

---

## 🔐 Failed Authentication (Brute Force / Spray)

**Symptoms:**

* Multiple failed logins across many users.
* Login attempts from shared IP addresses.

**Containment:**

* Block offending IPs in Conditional Access or firewall.
* Notify users of suspicious activity.

**Eradication:**

* Enforce MFA for all accounts.
* Reset affected user passwords.

**Recovery:**

* Review Azure AD sign-in logs for continued attempts.

**Prevention:**

* Limit legacy protocols (POP/IMAP).
* Implement smart lockout policies.

---

## 📱 MFA Fatigue Attacks

**Symptoms:**

* Multiple MFA prompts sent within minutes.
* User reports repeated requests outside normal hours.

**Containment:**

* Disable user sign-in temporarily.
* Reset password and re-enroll MFA.

**Eradication:**

* Confirm user did not approve a fraudulent prompt.
* Review for associated OAuth grants or mail rules.

**Recovery:**

* Reinstate access after verifying identity.

**Prevention:**

* Enable number matching or phishing-resistant MFA.
* Educate users on MFA prompt hygiene.

---

## ⚙️ Suspicious OAuth Applications

**Symptoms:**

* Unexpected third-party app consent requests.
* Apps with `Mail.ReadWrite`, `Files.ReadWrite.All`, or `offline_access` scopes.

**Containment:**

* Run Graph query for recent consents:

  ```powershell
  Get-MgOauth2PermissionGrant | Where-Object {$_.Scope -match 'Mail.ReadWrite|Files.ReadWrite.All'}
  ```
* Disable affected service principal or app ID.

**Eradication:**

* Revoke OAuth consent via Graph:

  ```powershell
  Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <ID>
  ```
* Delete unused app registrations.

**Recovery:**

* Notify users and reset affected tokens.

**Prevention:**

* Restrict app consent to admins only.
* Maintain allowlist of trusted publishers.

---

## 👥 Mailbox Delegation Abuse

**Symptoms:**

* Unexpected delegate access or SendAs permissions.
* Emails sent from unauthorized accounts.

**Containment:**

* Enumerate permissions:

  ```powershell
  Get-MailboxPermission -Identity user@domain.com
  ```
* Remove suspicious delegates immediately.

**Eradication:**

* Review Unified Audit Logs for historical access.
* Reset credentials of both delegator and delegate.

**Recovery:**

* Restore legitimate delegation where needed.

**Prevention:**

* Limit FullAccess to approved support staff only.
* Regularly audit mailbox permissions.

---

## 🧹 Mailbox Audit Manipulation

**Symptoms:**

* Audit logging disabled or reduced retention observed.
* Missing entries in audit log searches.

**Containment:**

* Re-enable auditing immediately:

  ```powershell
  Set-Mailbox -Identity user@domain.com -AuditEnabled $true
  ```

**Eradication:**

* Export available logs to CSV for preservation.

**Recovery:**

* Store logs in secure repository or eDiscovery case.

**Prevention:**

* Periodically validate auditing policies.
* Enable unified audit retention for 1+ year.

---

## 📊 Post-Incident Reporting

After remediation, generate reports using built-in toolkit exports:

```powershell
Invoke-BECDetection.ps1 -ExportCSV -Path ./Reports/BEC_Incident_<date>.csv
```

Include:

* Detected indicators
* Timeline of compromise
* Actions taken
* Accounts remediated
* Preventive controls implemented

---

## 🧩 Lessons Learned Checklist

* [ ] Was the root cause identified?
* [ ] Were affected users notified?
* [ ] Was data exfiltration ruled out?
* [ ] Were IAM/MFA controls improved?
* [ ] Was user awareness training updated?
* [ ] Was logging validated for completeness?

---

## 🧠 Reference

* Microsoft 365 Unified Audit Logs
* Exchange Online Management Module
* Microsoft Graph API (Identity Protection, Risky Users, OAuth Grants)
* NIST SP 800-61r2 Incident Handling Guide

---

**End of Document**
