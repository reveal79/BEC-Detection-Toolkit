\# BEC Detection Toolkit



\[!\[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

\[!\[PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

\[!\[Platform](https://img.shields.io/badge/Platform-Microsoft%20365-orange.svg)](https://www.microsoft.com/en-us/microsoft-365)



Enterprise-grade Business Email Compromise (BEC) detection and response  toolkit for Microsoft 365 environments. Built for organizations that can't  afford expensive SIEM/SOAR solutions like Darktrace, Splunk, or CrowdStrike.



\*\*Author:\*\* Don Cook | \*\*TryHackMe:\*\* Top 1% (scrizo) | \*\*Role:\*\* Security Engineer



---



\## 🎯 Why This Toolkit?



Enterprise security tools cost $100K-500K+ annually. This toolkit provides 

comparable BEC detection capabilities \*\*for free\*\* using native Microsoft 

tools and PowerShell automation.



\*\*Real-world impact:\*\* Used to detect and contain a BEC incident in < 18 hours, 

preventing $500K+ in wire fraud.



---



\## ✨ Features



\### \*\*Automated Detection:\*\*

\- ✅ Malicious mail rules (hiding internal emails, forwarding, deletion)

\- ✅ Impossible travel patterns (geographic anomalies)

\- ✅ Risky user detection (Azure AD Identity Protection integration)

\- ✅ Failed authentication patterns (brute force, password spray)

\- ✅ MFA fatigue attacks (repeated MFA prompts)

\- ✅ Suspicious OAuth applications (dangerous permissions)

\- ✅ Mailbox delegation abuse (unauthorized access)

\- ✅ Mailbox audit log forensics (covering tracks detection)



\### \*\*Response Automation:\*\*

\- ✅ One-click remediation for common threats

\- ✅ Automatic CSV reporting with findings

\- ✅ Attack timeline reconstruction

\- ✅ Email notifications for critical findings

\- ✅ Interactive prompts for high-risk actions



\### \*\*Enterprise Features (Free):\*\*

\- ✅ Scan 600+ mailboxes in minutes

\- ✅ Pattern detection across organization

\- ✅ Detailed audit trails

\- ✅ Customizable alert thresholds

\- ✅ No additional licensing required



---



\## 🚀 Quick Start



\### \*\*Prerequisites:\*\*

```powershell

\# Install required modules

Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser

Install-Module -Name Microsoft.Graph -Scope CurrentUser

```



\### \*\*Basic Usage:\*\*

```powershell

\# Detect malicious mail rules

.\\Scripts\\Check-MaliciousMailRules.ps1



\# Comprehensive BEC detection (all indicators)

.\\Scripts\\Invoke-BECDetection.ps1



\# Specific user investigation

.\\Scripts\\Invoke-BECDetection.ps1 -UserPrincipalName user@domain.com

```



---



\## 📊 Detection Capabilities



\### \*\*1. Malicious Mail Rules\*\*

Detects rules that:

\- Hide internal emails (@yourdomain.com)

\- Delete messages automatically

\- Forward to external addresses

\- Move to hidden folders (RSS, Archive)

\- Mark as read (hiding new messages)



\*\*Example output:\*\*

```

\[!] HIGH RISK RULE DETECTED!

&nbsp;   User: user@domain.com

&nbsp;   Rule: ...

&nbsp;   Actions: Moves to RSS Subscriptions, Marks as read

&nbsp;   Targets Internal: Yes

```



\### \*\*2. Impossible Travel\*\*

Flags sign-ins from different countries within hours:

```

Route: United States → Russia (45 minutes)

User: executive@domain.com

First IP: 203.0.113.50 | Second IP: 198.51.100.20

```



\### \*\*3. Risky Users (Azure AD Identity Protection)\*\*

Integrates with Microsoft's threat intelligence:

\- Leaked credentials

\- Malicious IP addresses

\- Unfamiliar sign-in properties

\- Anonymous IPs (Tor, VPN)



\### \*\*4. Attack Timeline Reconstruction\*\*

Builds chronological view of compromise:

```

2025-10-20 09:15 - Sign-in from Russia (Risk: High)

2025-10-20 09:20 - Inbox rule created: "..."

2025-10-20 09:25 - 50 emails moved to RSS folder

2025-10-20 09:30 - Password changed

```



---



\## 📖 Documentation



\- \[Installation Guide](Documentation/Installation.md)

\- \[Usage Examples](Documentation/Usage-Examples.md)

\- \[Detection Logic](Documentation/Detection-Logic.md)

\- \[Remediation Guide](Documentation/Remediation-Guide.md)

\- \[KQL Query Reference](KQL-Queries/)



---



\## 🎯 Use Cases



\### \*\*Small/Medium Businesses\*\*

Can't afford enterprise SIEM? Use this toolkit for automated BEC detection 

with zero licensing costs.



\### \*\*Nonprofits/Education\*\*

Limited security budget? Get enterprise-grade detection using native M365 tools.



\### \*\*MSPs/MSSPs\*\*

Protect multiple clients without per-tenant licensing fees.



\### \*\*Security Teams\*\*

Supplement existing tools with PowerShell automation and custom detections.



---



\## 🔍 Example: Real Incident Response



\*\*Scenario:\*\* User clicks phishing link, credentials stolen, attacker creates 

malicious mail rules.



\*\*Detection (18 minutes):\*\*

```powershell

PS> .\\Scripts\\Check-MaliciousMailRules.ps1



\[!] HIGH RISK RULE DETECTED!

&nbsp;   User: finance@company.com

&nbsp;   Rule: "..."

&nbsp;   Actions: Hides @company.com emails in RSS folder

&nbsp;   

Do you want to DISABLE this rule now? (Y/N): Y

\[✓] Rule disabled successfully!

```



\*\*Result:\*\* BEC contained in < 18 hours, $500K+ fraud prevented.



---



\## 🛡️ What This Replaces



| Enterprise Tool | Annual Cost | This Toolkit |

|----------------|-------------|--------------|

| Darktrace | $100K-300K | \*\*FREE\*\* |

| Splunk Security | $150K-500K | \*\*FREE\*\* |

| CrowdStrike Falcon | $50K-150K | \*\*FREE\*\* |

| Proofpoint TAP | $30K-100K | \*\*FREE\*\* |



\*\*Total potential savings:\*\* $330K-1M+ annually



---



\## 🤝 Contributing



Contributions welcome! Please read \[CONTRIBUTING.md](Contributing.md) for:

\- Bug reports

\- Feature requests

\- Pull request guidelines

\- Code of conduct



---



\## 📜 License



MIT License - Free for personal and commercial use.



See \[LICENSE](LICENSE) for details.



---



\## ⚠️ Disclaimer



This toolkit is provided "as-is" for educational and defensive security 

purposes. Always test in non-production environments first. The author is 

not responsible for misuse or damage caused by these tools.



---



\## 🙏 Acknowledgments



\- Built from real-world incident response experience

\- Inspired by the need for accessible enterprise security

\- Community feedback and contributions welcome



---



\## 📧 Contact



\*\*Author:\*\* Don Cook  

\*\*TryHackMe:\*\* \[Top 1% - scrizo](https://tryhackme.com/p/scrizo)  

\*\*LinkedIn:\*\* \[Your Profile]  

\*\*Issues:\*\* \[GitHub Issues](https://github.com/\[you]/BEC-Detection-Toolkit/issues)



---



\## ⭐ Star this repo if it helped you!



If this toolkit prevented a breach at your organization, consider:

\- ⭐ Starring the repository

\- 🐛 Reporting bugs or suggesting features

\- 💬 Sharing with other security professionals

\- ☕ \[Buying me a coffee](https://buymeacoffee.com/\[you]) (optional)



---



\*\*Built by security professionals, for security professionals.\*\*

```



---



\## 📄 \*\*Additional Files You Need:\*\*



\### \*\*LICENSE (MIT - Recommended):\*\*

```

MIT License



Copyright (c) 2025 Don Cook



Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:



The above copyright notice and this permission notice shall be included in all

copies or substantial portions of the Software.



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE

AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.

