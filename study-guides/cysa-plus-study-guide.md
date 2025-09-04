# CompTIA CySA+ (CS0-003) Comprehensive Study Guide

This guide is designed to ensure you’re ready for CySA+ with both exam-focused knowledge and practical, hands-on skills for real-world security analyst roles.

Note: This guide aligns with the current CySA+ (CS0-003) exam domains and objectives. CySA+ emphasizes applied analysis, incident response, detection engineering, vulnerability management, and communication/reporting.

-------------------------------------------------------------------------------

## Exam Overview

- Target audience: Security analysts, SOC analysts, threat hunters, incident responders, vulnerability analysts.
- Prerequisites: Recommended Security+ or equivalent knowledge, 3–4 years in security or IT ops (not required but helpful).
- Format: Multiple-choice and performance-based questions (PBQs).
- Time and questions: Up to ~85 questions in ~165 minutes.
- Scoring: Scaled score with a typical passing benchmark of 750 (on a 100–900 scale).
- Core focus:
  - Security operations and monitoring
  - Vulnerability management and remediation
  - Incident response management
  - Reporting and communication with stakeholders

How to use this guide:
- Start with the domain summaries and objectives.
- Practice with labs throughout.
- Use the weekly study plan to pace yourself.
- Drill with the cheat sheets and sample questions near the end.
- Build repeatable notes and playbooks you can use at work.

-------------------------------------------------------------------------------

## Domain 1: Security Operations

You must gather, normalize, analyze, and act on telemetry across endpoints, networks, applications, identity, and cloud. Expect PBQs that involve reading logs, pivoting, and choosing the best next action.

### 1.1 Telemetry and Logging Fundamentals
- Time sync: NTP everywhere (SIEM, servers, endpoints, network gear); avoid time skew.
- Log sources:
  - Windows: Security, System, Application, PowerShell Operational, Sysmon, Application-specific.
  - Linux: /var/log/auth.log, secure, messages, syslog, auditd logs, application logs, systemd-journald.
  - Network: Firewall, NGFW, IDS/IPS (Snort/Suricata), web proxy, load balancer, WAF, VPN, NetFlow/sFlow/IPFIX.
  - Identity: AD Domain Controller logs, Azure AD sign-in logs, SSO/IdP (Okta, Ping).
  - Cloud: 
    - AWS: CloudTrail, GuardDuty, VPC Flow Logs, CloudWatch, Config, S3 access logs.
    - Azure: Activity Logs, Azure AD sign-in/audit, Microsoft Defender for Cloud, Microsoft Sentinel.
    - GCP: Cloud Audit Logs, VPC Flow Logs, Security Command Center.
- Data normalization and parsing: ECS, CIM; field names consistency; timestamps, timezones.
- Baselining: “Normal” behavior for host, user, service, network. Supports anomaly detection.

### 1.2 SIEM and Detection Engineering
- SIEM concepts: data ingestion, parsing, normalization, correlation rules, saved searches, dashboards, lookup tables, enrichment (GeoIP, threat intel, asset/identity context).
- Tuning: Reduce false positives; implement suppression, allowlists, thresholding, exclusions; triage and feedback loops.
- Use-cases: 
  - Credential misuse
  - Lateral movement
  - Data exfiltration
  - Persistence mechanisms
  - C2 and beaconing
  - Suspicious process tree or parent-child relationships
- Threat hunting: Hypothesis-driven, iterative, map to MITRE ATT&CK; create detections from hunts.

### 1.3 Network Analysis
- PCAP basics: TCP 3-way handshake, retransmissions, HTTP/S, DNS, SMTP, SMB.
- Flow data (NetFlow/sFlow/IPFIX): Source/destination/bytes/packets; detect beaconing, exfiltration, scanning.
- TLS fingerprinting: JA3/JA3S; SNI; certificate details; unusual ciphers.
- DNS telemetry: NXDOMAIN, DNS tunneling patterns, unusual subdomain lengths/entropy, DGA.

### 1.4 Endpoint Telemetry
- Windows:
  - Key Event IDs:
    - 4624 (logon), 4625 (failed logon), 4672 (admin logon), 4688 (process creation), 4698 (scheduled task created), 4720 (user created), 4732 (user added to local group), 7045 (service installed).
  - Sysmon (recommended):
    - Event ID 1 (Process Create), 3 (Network), 7 (Image Load), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (File Create), 13 (Registry), 22 (DNS), 23/24/25 (File Delete).
  - PowerShell logging: Module, ScriptBlock, Transcription; detect Base64 encoded commands and AMSI bypass attempts.
- Linux:
  - auth.log, secure, messages; last, lastlog, wtmp; sudo logs; auditd for system calls (execve, chmod); watch for abnormal parent processes and cron modifications.
- EDR/XDR:
  - Process lineage, command-line args, parent/child, DLL loads, memory protections, MITRE mappings.

### 1.5 Data Loss, Email, and Web Security
- DLP policies and alerts; context-aware detections; sensitive data classifications.
- Email security: SPF, DKIM, DMARC; phishing indicators; URL rewriting; attachment sandboxing.
- Web proxy/WAF: Category blocks, TLS inspection, client reputation, OWASP rules.

### 1.6 Common Tools and Commands

Windows:
```
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /c:10
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | ? {$_.Message -match "Base64"}
Get-Process | Sort-Object CPU -Descending | Select -First 10
netstat -ano | findstr :443
schtasks /query /fo LIST /v
wmic process get ProcessId,ParentProcessId,ExecutablePath,CommandLine
```

Linux:
```
sudo journalctl -u ssh --since "1 hour ago"
sudo ausearch -x bash | aureport -x --summary
sudo netstat -plant | grep ESTABLISHED
grep -E "sudo|authentication failure" /var/log/auth.log
sudo find / -xdev -type f -mtime -1 2>/dev/null | head
```

Network:
```
tshark -r capture.pcap -Y "dns && dns.flags.response==0"
zeek -Cr capture.pcap
nmap -sS -sV -O -Pn 192.168.1.0/24
```

### 1.7 SIEM Query Examples

Splunk SPL:
```
index=win* EventCode=4688
| stats count by ParentProcessName, NewProcessName, CommandLine
| where like(CommandLine,"% -enc %") OR like(CommandLine,"%Base64%")
```

```
index=network sourcetype=pan:traffic action=allow
| bin _time span=5m
| stats count by src_ip, dest_ip, dest_port, _time
| streamstats window=12 count as windowCount by src_ip,dest_ip,dest_port
| where windowCount>10
```

Microsoft Sentinel (KQL):
```
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("-enc", "FromBase64String")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```

```
DeviceNetworkEvents
| where RemotePort in (4444, 3389)
| summarize count() by DeviceName, RemoteIP, RemotePort, bin(Timestamp, 5m)
```

### 1.8 Hands-on Labs
- Build a home SIEM: Wazuh or Elastic Stack; forward Windows (with Sysmon) and Linux logs.
- Analyze a PCAP from malware-traffic-analysis.net with Wireshark/Zeek; identify beaconing and exfiltration.
- Create two Splunk/Sentinel detections and tune them using synthetic data (Atomic Red Team).
- Enable PowerShell logging and Sysmon (SwiftOnSecurity config); generate benign “suspicious” events and tune.

-------------------------------------------------------------------------------

## Domain 2: Vulnerability Management

You’ll prioritize, validate, and drive remediation with business context.

### 2.1 Program and Process
- Lifecycle:
  1) Discover assets and exposures
  2) Scan and assess (authenticated/unauthenticated, agent vs network)
  3) Validate and analyze (false positives, exploitability, exposure)
  4) Prioritize (CVSS + asset criticality + exploit intel + compensating controls)
  5) Remediate or mitigate (patch/config change/disable/compensate)
  6) Verify closure and report (trending, SLA performance)
- Governance:
  - Asset inventory, CMDB accuracy, tagging strategy (env, owner, criticality).
  - SLAs by severity and asset class.
  - Change management integration and maintenance windows.

### 2.2 Scanning Types and Considerations
- Network scanning: discovery, port/service fingerprinting, credentialed checks.
- Application scanning: SAST/DAST, API scanning, auth/roles, rate limiting, CSRF tokens.
- Container/image scanning: packages, OS base, third-party libs, SBOM (SPDX/CycloneDX).
- Cloud posture (CSPM): misconfigurations, over-privileged roles, public buckets, key rotation.
- Authenticated scanning benefits: fewer false positives, config/compliance checks, patch level.
- Safe checks: avoid disruptive tests in prod; exclude fragile systems.

### 2.3 Interpreting Results
- CVE and CVSS v3.1:
  - Base metrics: AV, AC, PR, UI, S, C/I/A.
  - Temporal: Exploit Code Maturity, Remediation Level, Report Confidence.
  - Environmental: Modified base by your environment (CR, IR, AR, MPR, etc.).
- Prioritization inputs:
  - Known exploited vulnerabilities (KEV)
  - Exploit availability (Metasploit/Pocs)
  - Exposure: internet-facing, reachable from threat actors
  - Business criticality and data sensitivity
  - Compensating controls (WAF, IPS, EDR)
- False positive handling: verify with version checks, banner accuracy, local package managers, file hashes.

### 2.4 Remediation and Exceptions
- Remediation types: patch, config change, upgrade, disable, virtual patching (WAF/IPS rules).
- Exceptions/risk acceptance: time-bound, documented, with compensating controls.
- Validation: rescan, endpoint telemetry, config audits (CIS Benchmarks), change tickets closure.

### 2.5 Compliance and Configuration
- Benchmarks and standards: CIS Benchmarks, DISA STIGs, NIST 800-53, SOC2, ISO 27001, PCI DSS.
- SCAP content, OVAL checks; automated compliance scans.
- Secure baselines and drift detection.

### 2.6 Hands-on Labs
- Run OpenVAS/Nessus Essentials on a test network; compare authenticated vs unauthenticated results.
- Scan a container image (Trivy/Grype); generate SBOM and interpret critical findings.
- Harden a Linux host using a CIS benchmark profile (Ansible or manual) and verify improvement.
- Prioritize a mock vulnerability list using CVSS + KEV + asset criticality; document decisions.

-------------------------------------------------------------------------------

## Domain 3: Incident Response Management

Expect scenarios that test triage, containment, evidence handling, and communication.

### 3.1 Frameworks and Roles
- NIST SP 800-61 phases:
  1) Preparation
  2) Detection and Analysis
  3) Containment, Eradication, and Recovery
  4) Post-Incident Activity (Lessons Learned)
- RACI and playbooks; tiered analyst responsibilities; legal and HR involvement when needed.

### 3.2 Triage and Analysis
- Indicators of Compromise (IoCs): hashes, domains/URLs, IPs, file paths, registry keys, mutexes, JA3.
- Indicator of Attack (IoA): behaviors, techniques, anomalies mapped to MITRE ATT&CK.
- Enrichment: passive DNS, WHOIS, VirusTotal, sandbox reports, internal asset/identity context.
- Confidence scoring; severity and priority assignment.

### 3.3 Containment and Eradication
- Containment strategies: host isolation (EDR), block at firewall/proxy, disable accounts, rotate credentials/tokens, kill C2 domains (sinkhole).
- Eradication: remove persistence, reimage, patch, reset keys/secrets, password resets.
- Recovery: staged reintroduction, increased monitoring, validation tests.

### 3.4 Forensics Basics
- Order of volatility; memory before disk; network before logs in some cases.
- Chain of custody; evidence integrity (hashes), write blockers for disk imaging.
- Memory analysis: Volatility/Detect-It-Easy; look for injected code, malicious threads, network connections.
- Timeline analysis: mactime/log2timeline; correlate with SIEM.
- Legal/regulatory: breach notification laws, PII/PHI/PCI; data retention policies.

### 3.5 Common Playbooks
- Ransomware: isolate, identify family, check dead man switch, backups integrity, avoid detonation while collecting evidence, engage legal/execs, consider law enforcement; restore securely.
- BEC (Business Email Compromise): mailbox rules/forwarding, OAuth grants, MFA fatigue attacks, vendor fraud; communicate with finance and impacted parties; rotate tokens and reset creds.
- Phishing: user report triage, detonate in sandbox, indicators extraction, retrohunt across mailboxes, purge, awareness feedback.
- Web shell on server: isolate, snapshot, collect logs, integrity check, close access vector, patch, rotate secrets, verify no lateral movement.
- Insider data exfil: DLP alerts, VPN/file access logs, SIEM correlation; HR/legal involved; disable access, preserve evidence.

### 3.6 Metrics and Post-Incident
- KPIs: MTTD/MTTR, containment time, eradication time, % incidents by vector, false-positive rate, detection coverage against ATT&CK techniques.
- Lessons learned: root cause, control gaps, update playbooks/detections, training needs, executive readout.

### 3.7 Hands-on Labs
- Memory capture in a VM (e.g., using DumpIt) and basic Volatility analysis.
- Build and test an IR playbook template for ransomware; run a tabletop.
- Create a detonation pipeline for suspicious emails and automatically generate IoCs and SIEM queries.

-------------------------------------------------------------------------------

## Domain 4: Reporting and Communication

Turning findings into action with the right audience, format, and timing.

### 4.1 Reporting Structure
- Executive summary: clear business impact, risk level, recommended actions in plain language.
- Technical details: evidence, timeline, IoCs, analysis steps, affected assets, logs, screenshots.
- Remediation plan: prioritized steps, owners, timelines, risk of delay.
- Compliance mapping: show how findings align to controls (NIST/ISO/CIS/PCI).

### 4.2 Stakeholder Communication
- Audiences: Execs, IT Ops, DevOps, Legal, HR, Compliance, PR, Third parties.
- Channels: Secure ticketing, IR bridge, status updates, post-mortems.
- Severity model and SLAs; when to escalate (e.g., widespread exfiltration, KEV exploitation).

### 4.3 Visualization and Dashboards
- Trends: incidents by type, vulnerabilities by severity and asset class, patch SLA performance.
- Coverage: ATT&CK heatmaps; detective and preventive control coverage.
- ROI/context: incidents avoided, time saved with automation, risk reduction narratives.

### 4.4 Hands-on Labs
- Write two report versions (exec vs technical) for the same incident dataset.
- Build a dashboard showing detection-to-containment timeline trends.

-------------------------------------------------------------------------------

## Cloud, Identity, and DevSecOps Essentials

- Cloud IAM anomalies:
  - AWS: unusual AssumeRole, AccessKey creation, password policy changes, S3 public ACLs.
  - Azure: OAuth app consent grants, risky sign-ins, privileged role assignments.
  - GCP: Service account key creation, overly broad IAM bindings, public buckets.
- Sample KQL (Sentinel) for risky sign-ins:
```
SigninLogs
| where RiskState != "none" or RiskDetail !in ("none","hidden")
| summarize count() by UserPrincipalName, AppDisplayName, RiskLevelAggregated
```
- Containers/Kubernetes:
  - Image scanning (Trivy), runtime detections (Falco), namespace RBAC, network policies, secrets management.
  - Common risks: privileged pods, hostPath mounts, insecure admission controllers, exposed dashboards.
- CI/CD Security:
  - Protect secrets, signed artifacts (Sigstore), least-privileged runners, dependency scanning (SCA).

-------------------------------------------------------------------------------

## Scripting, Automation, and Querying

### 6.1 Python Log Parsing
```
import json, re
suspicious = re.compile(r'(frombase64string|-enc|mimikatz|powershell.exe)', re.I)
with open('win_events.jsonl') as f:
    for line in f:
        evt = json.loads(line)
        cmd = evt.get('CommandLine','')
        if suspicious.search(cmd):
            print(evt['TimeCreated'], evt.get('Computer',''), cmd)
```

### 6.2 PowerShell IR Snippets
```
Get-EventLog -LogName Security -Newest 1000 | Where {$_.EventID -in 4624,4625} | Group-Object ReplacementStrings[5] | Sort Count -Desc | Select -First 10
Get-ScheduledTask | Where {$_.TaskPath -notlike '\\Microsoft\\*'} | Format-Table TaskName,TaskPath,State
Get-LocalUser | Where {$_.Enabled -eq $true} | Format-Table Name,LastLogon
```

### 6.3 Bash + jq
```
grep -i "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head
journalctl -o json | jq 'select(.MESSAGE|test("sudo|authentication")) | {t:.__REALTIME_TIMESTAMP,msg:.MESSAGE}'
```

### 6.4 Regex Quick Patterns
```
Base64: (?i)(frombase64string|-enc\s+[A-Za-z0-9+/=]{8,})
IPv4: \b(?:\d{1,3}\.){3}\d{1,3}\b
Email: [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
URL: https?://[^\s"]+
```

### 6.5 SQL/SPL/KQL Thoughts
- Joins for asset/identity enrichment
- Time-bucket aggregation
- Stats, percentiles, moving averages
- Anomaly: z-score, baselines by Entity (User, Host)

-------------------------------------------------------------------------------

## Cheat Sheets

### Common Ports
- 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 445 SMB, 3389 RDP, 389/636 LDAP/LDAPS, 1433 MS SQL, 1521 Oracle, 3306 MySQL, 5432 Postgres, 5601 Kibana, 6379 Redis, 8080 HTTP-alt, 9000 SonarQube.

### Windows Event IDs
- Auth: 4624/4625, Admin: 4672, User: 4720/4726, Group changes: 4732/4733, Process: 4688, Service install: 7045, Scheduled task: 4698, GPO change: 4739, DC sync attempts: 4662 on directory objects.

### Linux Logs
- /var/log/auth.log or secure: SSH, sudo
- auditd: syscall auditing (execve, chmod, chown)
- last/lastlog: login history
- .bash_history (careful: can be tampered)

### HTTP Status Families
- 2xx success, 3xx redirects, 4xx client errors, 5xx server errors.
- Red flags: many 401/403 then 200; bursts of 500s; unusual 3xx chains.

### KPIs
- MTTD, MTTR, containment time, TP/FP rates, patch SLA compliance, coverage against ATT&CK.

-------------------------------------------------------------------------------

## Sample PBQ-Style Scenarios and Questions

1) You see repeated 4625 followed by a 4624 with LogonType=10 from the same external IP to a jump server. What’s the best next step?
- A. Block the IP at the firewall and notify IR lead
- B. Force password resets for all domain users
- C. Disable the jump server host immediately
- D. Run a full vulnerability scan on the subnet
Answer: A. Rationale: Likely brute-force leading to success (type 10 = RemoteInteractive/RDP). Quick containment is to block source and escalate. Then proceed with host triage.

2) CVSS base score is 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) but the asset is internal, non-critical, behind strong EDR. Which prioritization is best?
- A. Treat as critical due to CVSS alone
- B. Defer until next quarter
- C. Prioritize high but consider exposure and controls; remediate within SLA
- D. Accept the risk permanently
Answer: C. Rationale: Consider CVSS plus environmental factors and controls.

3) Your SIEM shows encoded PowerShell commands launching from winword.exe after a phishing email. What is the most probable technique?
- A. Credential stuffing
- B. Living-off-the-land via Office macro leading to PowerShell
- C. Misconfigured firewall rule
- D. DNS tunneling
Answer: B.

4) A web server shows spikes in POST requests with high-entropy parameters and odd User-Agents. Which action first?
- A. Shut down the server
- B. Capture PCAP and enable WAF rules to block suspected patterns while investigating
- C. Reimage immediately
- D. Rotate all TLS certificates
Answer: B.

5) During IR, which comes first?
- A. Public disclosure
- B. Containment
- C. Lessons learned
- D. Recovery
Answer: B. (After detection/analysis, containment precedes eradication and recovery.)

6) Which Windows event best detects new local admin user creation?
- A. 4688
- B. 4732
- C. 4720 with group membership change to Administrators
- D. 4624
Answer: C. (Account creation 4720 plus check added to Administrators group.)

7) Best evidence integrity practice when imaging a disk:
- A. Zip the image for faster sharing
- B. Calculate and record cryptographic hash (e.g., SHA-256) before and after
- C. Store on a shared network drive
- D. Encrypt with a weak passphrase
Answer: B.

8) Flow logs show 443 outbound at exact 60s intervals, small byte counts, long-lived. What is this likely?
- A. Backup jobs
- B. TLS heartbeat
- C. Beaconing C2
- D. Normal browsing
Answer: C.

9) Which logging helps detect DNS exfiltration?
- A. Only HTTP logs
- B. DNS query logs with query length and response codes
- C. DHCP assignments
- D. NTP server logs
Answer: B.

10) Your scanner flags SMB signing disabled on Domain Controllers. Priority?
- A. Low, DCs are internal
- B. High, enables relay attacks and should be remediated quickly
- C. Medium, accept risk
- D. None, not relevant
Answer: B.

-------------------------------------------------------------------------------

## 8-Week Study Plan

Week 1: Foundations
- Review exam objectives and this guide.
- Set up lab: 1 Windows VM (with Sysmon), 1 Linux VM, SIEM stack (Wazuh/Elastic or Splunk Free).
- Read: Logging fundamentals, Windows Event IDs, Sysmon config.

Week 2: SIEM Basics + Network
- Ingest Windows/Linux logs; create basic dashboards.
- PCAP and flow analysis labs; detect simple scans and beaconing.
- Write two detections in SIEM; tune out false positives.

Week 3: Endpoint and EDR
- PowerShell logging; Sysmon deep dive; Linux auditd basics.
- Build detections for suspicious PS, scheduled tasks, and new services.
- Atomic Red Team tests; validate detections.

Week 4: Vulnerability Management
- Run network and authenticated scans; interpret CVSS and prioritize.
- Container image scanning and SBOM basics.
- Draft remediation plan with SLAs and risk exceptions.

Week 5: Incident Response
- NIST 800-61; playbooks; evidence handling.
- Memory capture and Volatility intro.
- Tabletop: phishing to malware execution; reporting paths.

Week 6: Cloud and Identity
- Enable cloud logs (simulated or free tiers).
- KQL basics in Sentinel or equivalent; detect risky sign-ins and role changes.
- IAM hardening and key rotation practices.

Week 7: Reporting and Communication
- Write an executive summary + technical report from lab incidents.
- Build KPIs dashboards (MTTD/MTTR, detection coverage).
- Practice PBQs-style drills.

Week 8: Review and Mock Exam
- Full-length practice exam; review misses.
- Revisit weak domains; retune detections.
- Flash through cheat sheets and glossary.

Daily habit: 60–90 minutes weekdays; 2–4 hours weekend labs.

-------------------------------------------------------------------------------

## Templates and Playbooks

IR Playbook (generic):
```
Title: [Incident Type]
Scope: Systems/Accounts/Regions
Severity: [Low/Med/High/Critical]
Trigger: [Alert name, detection logic, thresholds]
Actions:
  - Triage: [Analyst steps, logs to pull, queries]
  - Containment: [Host isolation, blocks, account disable]
  - Eradication: [Remove persistence, patches, reset secrets]
  - Recovery: [Validation tests, staged reintroduction]
Communications:
  - Stakeholders, frequency, channels
Evidence Handling:
  - Collection steps, hashing, storage location
Metrics:
  - Start/contain/eradicate/recover timestamps
Lessons Learned:
  - Root cause, gaps, improvements
```

Vuln Report:
```
Title: [Vuln Name, CVE]
Assets: [Hostnames/IPs/Apps]
Severity/Priority: [CVSS base/env, KEV, exposure, business criticality]
Details: [Version, plugin output, proof]
Risk: [Impact + Likelihood]
Remediation: [Steps, owners, due date]
Exceptions: [If any, controls, expiry]
Validation: [Rescan date, evidence]
```

-------------------------------------------------------------------------------

## Recommended Study Resources

- CompTIA CySA+ official exam objectives and practice questions
- MITRE ATT&CK knowledge base
- CIS Benchmarks
- NIST SP 800-61 (Computer Security Incident Handling Guide)
- Vendor docs and free labs for:
  - Elastic/ELK, Wazuh, Splunk (SPL)
  - Microsoft Sentinel (KQL)
  - Zeek/Wireshark
  - Trivy/Grype (container scanning)
- Malware-Traffic-Analysis.net (PCAPs)
- Atomic Red Team (ATT&CK-aligned tests)
- DFIR blogs and cheat sheets (memory analysis, Windows logging)

-------------------------------------------------------------------------------

## Glossary (selected)

- ATT&CK: Adversary Tactics, Techniques, and Common Knowledge matrix.
- Baselining: Establishing normal behavior thresholds.
- Beaconing: Periodic outbound callbacks to C2.
- CIS Benchmark: Security configuration best practices for systems/software.
- CVE/CVSS: Public vulnerability IDs and scoring system.
- DLP: Data loss prevention.
- EDR/XDR: Endpoint/Extended Detection and Response tools.
- IOC/IOA: Indicators of Compromise/Attack.
- JA3/JA3S: TLS client/server fingerprinting.
- KEV: Known Exploited Vulnerabilities (CISA catalog).
- KQL/SPL: Query languages for Sentinel/Splunk.
- MTTD/MTTR: Mean Time to Detect/Respond.
- NTP: Network Time Protocol.
- PCAP: Packet capture file.
- SCAP/OVAL: Security automation and vulnerability assessment languages.
- SIEM: Security Information and Event Management.
- Sysmon: Windows system monitor for enhanced telemetry.
- Virtual patching: Mitigation via compensating controls (e.g., WAF) when patching is delayed.

-------------------------------------------------------------------------------

You’ve got this. If you want, I can convert this guide into a printable PDF, break it into weekly checklists, or turn the labs into a GitHub repo with sample data and queries.
