// ============================================================================
// KQL Queries - README and Usage Guide
// ============================================================================
// BEC Detection Toolkit - KQL Query Collection
// Author: Don Cook
// Version: 1.0
// Last Updated: October 24, 2025
// ============================================================================

# KQL Queries for BEC Detection

This directory contains Kusto Query Language (KQL) queries for detecting Business Email Compromise indicators in Microsoft 365 environments.

## 📁 Query Files

| File | Description | Data Source | Severity |
|------|-------------|-------------|----------|
| `detect-mail-rule-creation.kql` | Detects suspicious inbox rule creation/modification | OfficeActivity / AuditLogs | HIGH |
| `detect-impossible-travel.kql` | Identifies impossible travel patterns | SigninLogs | HIGH |
| `detect-failed-signin-patterns.kql` | Brute force, password spray detection | SigninLogs | CRITICAL |
| `detect-oauth-abuse.kql` | Suspicious OAuth app permissions | AuditLogs | HIGH |
| `detect-risky-users.kql` | Azure AD Identity Protection integration | SigninLogs, AADRiskyUsers | CRITICAL |

---

## 🎯 Where to Run These Queries

### **Option 1: Azure AD / Entra - Log Analytics**
**Portal:** `portal.azure.com` → Azure Active Directory → Monitoring & Health → Log Analytics

**Tables Available:**
- `SigninLogs` - Interactive user sign-ins
- `AADNonInteractiveUserSignInLogs` - Service principals
- `AuditLogs` - Azure AD audit events
- `AADRiskyUsers` - Identity Protection data

**Best For:** Sign-in analysis, risky user detection, Azure AD changes

---

### **Option 2: Microsoft 365 Defender - Advanced Hunting**
**Portal:** `security.microsoft.com` → Hunting → Advanced hunting

**Tables Available:**
- `EmailEvents` - Email metadata
- `EmailUrlInfo` - URLs in emails
- `CloudAppEvents` - Microsoft 365 app events
- `IdentityLogonEvents` - Identity events

**Best For:** Email-specific hunting, cross-workload correlation

---

### **Option 3: Azure Sentinel (If Configured)**
**Portal:** `portal.azure.com` → Microsoft Sentinel → Logs

**Tables Available:** All tables from Option 1 + Option 2 (if configured)
- `OfficeActivity` - Exchange, SharePoint, Teams activity
- `SecurityAlert` - Alerts from various sources
- Custom tables from data connectors

**Best For:** Comprehensive hunting across all data sources, SIEM analytics

---

## ⚙️ Prerequisites

### **Required Permissions:**
- **Azure AD:** Security Reader or Global Reader
- **Microsoft 365:** Security Reader
- **Log Analytics:** Log Analytics Reader

### **Required Licenses:**
- **Azure AD Premium P2** - For Identity Protection data (AADRiskyUsers)
- **Microsoft Defender for Office 365 Plan 2** - For EmailEvents tables
- **Azure Sentinel** - Optional, for OfficeActivity table

### **Data Retention:**
- Sign-in logs: 30 days (free), 90+ days (Log Analytics)
- Audit logs: 90 days (E3), 1 year (E5)
- Email events: 30 days

---

## 🚀 Quick Start

### **Step 1: Verify Your Environment**
Run this query to see what tables you have:

```kql
search *
| where TimeGenerated > ago(1h)
| distinct $table
| sort by $table asc
```

### **Step 2: Test with Sample Query**
Try this basic query to confirm data is flowing:

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| summarize SignIns = count() by UserPrincipalName
| top 10 by SignIns
```

### **Step 3: Choose Your Queries**
Based on your threat model, select queries from the collection.

---

## 📊 Query Customization

### **Time Range:**
All queries use `ago()` function. Adjust as needed:
```kql
| where TimeGenerated > ago(7d)   // Last 7 days
| where TimeGenerated > ago(24h)  // Last 24 hours
| where TimeGenerated > ago(30d)  // Last 30 days
```

### **Filtering Specific Users:**
```kql
| where UserPrincipalName == "user@domain.com"
| where UserPrincipalName contains "admin"
| where UserPrincipalName in ("user1@domain.com", "user2@domain.com")
```

### **Performance Optimization:**
For large datasets, add these optimizations:
```kql
| where TimeGenerated > ago(7d)  // Filter time FIRST
| summarize ... by bin(TimeGenerated, 1h)  // Aggregate by time bins
| take 1000  // Limit results for testing
```

---

## 🔔 Creating Alerts from Queries

### **In Azure Sentinel:**
1. Go to Analytics → Create → Scheduled query rule
2. Paste KQL query
3. Set threshold (e.g., `count() > 0`)
4. Configure schedule (e.g., every 5 minutes)
5. Set severity (Info/Low/Medium/High/Critical)
6. Add alert grouping and suppression

### **In Log Analytics:**
1. Run your query
2. Click "New alert rule"
3. Configure condition
4. Add action groups for notifications
5. Set alert details

### **Recommended Alert Settings:**

| Query Type | Frequency | Threshold | Severity |
|------------|-----------|-----------|----------|
| Mail Rule Creation | 5 min | count() > 0 | High |
| Impossible Travel | 15 min | count() > 0 | High |
| Failed Sign-Ins | 5 min | FailedAttempts >= 10 | High |
| OAuth Abuse | 15 min | count() > 0 | High |
| Risky Users | Real-time | RiskLevel == "high" | Critical |

---

## 🎓 Learning Resources

### **KQL Documentation:**
- [KQL Quick Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Azure Monitor KQL](https://docs.microsoft.com/en-us/azure/azure-monitor/logs/log-query-overview)

### **Video Tutorials:**
- [Must Learn KQL (YouTube)](https://www.youtube.com/playlist?list=PLmAptfqzxVEVQ3zl5yf5H4TqgaT8oekFa)
- [KQL for Threat Hunting](https://www.youtube.com/watch?v=UHvwc6VsHfo)

### **Practice Environment:**
- [Azure Data Explorer Demo](https://dataexplorer.azure.com/clusters/help/databases/Samples)
- Test queries against sample data

---

## 🛠️ Troubleshooting

### **Error: "Table not found"**
**Problem:** OfficeActivity table doesn't exist  
**Solution:** Configure Office 365 connector in Azure Sentinel, or use PowerShell export

### **Error: "Failed to resolve column"**
**Problem:** Column name is wrong or doesn't exist in your data  
**Solution:** Run `TableName | getschema` to see available columns

### **Query returns no results:**
**Problem:** No data in specified timeframe, or filters too restrictive  
**Solution:** 
1. Check data retention period
2. Expand time range: `ago(30d)` instead of `ago(1d)`
3. Remove filters temporarily to test

### **Query times out:**
**Problem:** Dataset too large or query inefficient  
**Solution:**
1. Add time filter at beginning: `| where TimeGenerated > ago(7d)`
2. Reduce time range
3. Add `| take 1000` for testing
4. Use summarize with time bins

---

## 📈 Query Performance Tips

### **DO:**
- ✅ Filter on TimeGenerated first
- ✅ Use `summarize` instead of multiple `where` clauses
- ✅ Use `project` to limit columns early
- ✅ Use `has` instead of `contains` when possible

### **DON'T:**
- ❌ Search across all tables: `search *`
- ❌ Use complex regex unnecessarily
- ❌ Join very large tables without time filters
- ❌ Use `distinct` on large datasets

---

## 🤝 Contributing

Have improvements or new queries? Follow these guidelines:

1. **Query Header:** Include description, data source, author
2. **Comments:** Explain complex logic
3. **Variables:** Use `let` statements for thresholds
4. **Testing:** Test against production data
5. **Documentation:** Update this README

---

## 📞 Support

**Issues or questions?** 
- Check the main README.md in the root directory
- Review Microsoft's KQL documentation
- Open an issue on GitHub (when published)

---

## 📝 Version History

**v1.0 (October 2025):**
- Initial release
- 5 core detection queries
- Tested in production environment
- Used to detect real BEC incident

---

**Last Updated:** October 24, 2025  
**Maintained by:** Don Cook - IT Operations
