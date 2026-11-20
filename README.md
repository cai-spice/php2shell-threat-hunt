<div align="center">

<img src="project-card-health-check.svg" alt="The Health Check That Wasn't: a web shell threat hunt using Microsoft Sentinel and KQL. 14 hunt steps, 13 ATT&CK techniques, 9 kill chain phases. Hypothesis confirmed." width="100%">

</div>

<img src="divider.svg" alt="" width="100%">

## 📜 Quest Summary

> **A public WordPress server was compromised through PHP's `session.upload_progress` handling. A web shell named `health-check.php` gave the attacker control as `www-data`, and they stole the database credentials and the WordPress user table. They never rose above that low-privilege account, their attempts to switch off monitoring failed, and nothing points to lateral movement.**

| | |
|---|---|
| **Type** | Hypothesis-driven threat hunt |
| **Environment** | Practice lab (simulated organization) |
| **Hunt window** | 23 October 2026, 04:00 to 16:00 UTC |
| **Report date** | 20 November 2026 |
| **Platform** | Microsoft Sentinel (Log Analytics) and KQL. Host telemetry from Sysmon for Linux and auditd |
| **Target** | One web server: WordPress 7.1.3, Apache 2.4.69, PHP 8.4.4, Debian 13, MySQL on localhost |
| **Result** | Hypothesis confirmed |
| **Scale** | 14 hunt steps · 13 ATT&CK techniques · 9 phases · 8 queries documented |

**In short:** It started with one auditd alert, the Apache service account writing a file into the webroot, which it should never do. Working outward from that alert through web, endpoint and system logs, the hunt reconstructed the whole intrusion: scanning, exploitation, a disguised web shell, discovery, credential theft, a failed attempt to blind monitoring, cron persistence, and exfiltration through the shell's own HTTP responses. It also set the limits of the damage, which gives a response team a clear list of what to remove, reset and block.

<img src="divider.svg" alt="" width="100%">

## 🧭 Scope and Rules

- **In scope:** One host, the web server, and the seven log tables listed below.
- **Out of scope:** Any other system on the network. The hunt looked for signs of movement to other hosts but did not hunt on them.
- **Environment note:** This is a practice scenario run in a learning workspace, not a live production environment.
- **Time handling:** Every time filter uses the `OriginalTime` column, which holds the true event time, and all times are UTC.

<img src="divider.svg" alt="" width="100%">

## 🔮 Hypothesis

> An attacker exploited the public WordPress site, gained the ability to run code as `www-data`, and used that access to install a web shell and operate on the server.

**Trigger:** An auditd alert that `www-data` wrote files to the Apache webroot. This account runs the Apache worker processes and should never write outside the WordPress upload directory.

**Baseline used:** The system administrator and a service account connect over SSH from two known hosts during business hours (08:00 to 18:00, weekdays). `www-data` should never spawn interactive shells, run discovery commands, or write files outside the upload directory.

### Why this was the detection point

| Candidate | Strengths | Chosen? |
|---|---|---|
| `www-data` writing to the webroot | Breaks a hard baseline rule and marks the moment of foothold | **Chosen.** High confidence, and it sits between the entry and everything that followed |
| Scanning from the outlier IP | Earliest sign of the attacker | Not chosen. Scanning alone does not prove a compromise |
| Attempts to stop monitoring | Clear sign of hostile intent | Not chosen. It happened after credentials were already taken |

<img src="divider.svg" alt="" width="100%">

## 🗂️ Data Sources

| Table | What it records | Used for |
|---|---|---|
| `HartwellApache_CL` | Apache access log | Spotting the outlier IP and its scanning |
| `HartwellApacheError_CL` | Apache error log | PHP warnings that revealed the exploited feature |
| `HartwellHTTPEnriched_CL` | HTTP requests rebuilt from packet capture | Exploit requests and the encoded web shell commands |
| `HartwellSysmon_CL` | Sysmon for Linux process and file events | Commands run as `www-data`, and security tool discovery |
| `HartwellAudit_CL` | auditd system call records | The original webroot write alerts |
| `HartwellSyslog_CL` | System log | Checking whether the monitoring services were stopped |
| `HartwellAuth_CL` | Authentication events | Checking logins against the staff baseline |

<img src="divider.svg" alt="" width="100%">

## 🪜 Hunt Steps

| # | Question asked | Source (query) | Result |
|---|---|---|---|
| 1 | Who generated unusual traffic? | Apache access ([Q01](queries/Q01-traffic-by-source-ip.kql)) | `192.168.1.100`, once the server's own address and staff hosts were set aside |
| 2 | What tool did the scanning? | HTTP enriched ([Q03](queries/Q03-methods-and-content-types.kql)) | Nmap Scripting Engine (NSE) |
| 3 | What PHP feature did the exploit hit? | Apache error ([Q02](queries/Q02-php-warnings-from-attacker.kql)) | `session.upload_progress` |
| 4 | What made the exploit traffic stand out? | HTTP enriched ([Q03](queries/Q03-methods-and-content-types.kql), [Q04](queries/Q04-attacker-post-requests.kql)) | `POST` with `multipart/form-data` |
| 5 | What new file appeared in the webroot? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | `health-check.php` |
| 6 | Which account ran the commands? | Sysmon ([Q06](queries/Q06-which-account-ran-commands.kql)) | `www-data` |
| 7 | How were the commands disguised? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | ROT13, then Base64 |
| 8 | How did the attacker map the network? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | `ip addr`, `ip neigh`, `ss -tlnp` |
| 9 | Which security tools did they find? | Sysmon ([Q07](queries/Q07-security-tool-discovery.kql)) | Sysmon, auditd, Splunk Universal Forwarder |
| 10 | Where did the credentials come from? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | `wp-config.php`, then the `wp_users` table |
| 11 | Did they disable monitoring? | Sysmon ([Q08](queries/Q08-did-monitoring-stop.kql)) | No. The stop attempts failed |
| 12 | How did they stay in? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | Cron job running `/dev/shm/.cache-helper` |
| 13 | How did the data leave? | HTTP enriched ([Q05](queries/Q05-web-shell-commands.kql)) | Base64 in the web shell's HTTP responses |
| 14 | Did they move to other systems? | All tables | No evidence of lateral movement |

<img src="divider.svg" alt="" width="100%">

## ⏳ Timeline

Reconstructed from the logs, in order. The only timestamp I saved was the last exploit request (09:57 UTC); the rest sat in query results I did not keep (see the limits at the end of Lessons Learned).

| # | Phase | What happened | ATT&CK | Evidence |
|---|---|---|---|---|
| 1 | Reconnaissance | The outlier IP floods the site with traffic and scans it with Nmap NSE | T1595, T1595.002 | [Q01](queries/Q01-traffic-by-source-ip.kql), [Q03](queries/Q03-methods-and-content-types.kql) |
| 2 | Initial access | Crafted multipart uploads hit `session.upload_progress`; last `POST` at 09:57 UTC | T1190 | [Q02](queries/Q02-php-warnings-from-attacker.kql), [Q04](queries/Q04-attacker-post-requests.kql) |
| 3 | Execution | Web shell `health-check.php` lands in the webroot | T1505.003 | [Q05](queries/Q05-web-shell-commands.kql) |
| 4 | Execution | Commands arrive in a custom header, encoded with ROT13 then Base64, and run as `www-data` | T1059.004, T1027 | [Q05](queries/Q05-web-shell-commands.kql), [Q06](queries/Q06-which-account-ran-commands.kql) |
| 5 | Discovery | Network commands, then discovery of Sysmon, auditd and Splunk | T1016, T1518.001 | [Q05](queries/Q05-web-shell-commands.kql), [Q07](queries/Q07-security-tool-discovery.kql) |
| 6 | Credential access | `wp-config.php` read; `wp_users` queried and dumped | T1552.001 | [Q05](queries/Q05-web-shell-commands.kql) |
| 7 | Defense evasion | Attempts to stop the monitoring services fail | T1562.001 | [Q07](queries/Q07-security-tool-discovery.kql), [Q08](queries/Q08-did-monitoring-stop.kql) |
| 8 | Persistence | Implant staged in `/dev/shm`; cron job set to run it every 5 minutes | T1053.003, T1036.005 | [Q05](queries/Q05-web-shell-commands.kql) |
| 9 | Damage | Stolen data Base64-encoded and returned in HTTP responses | T1041 | [Q05](queries/Q05-web-shell-commands.kql) |

<img src="divider.svg" alt="" width="100%">

## 🛡️ MITRE ATT&CK Mapping

Status key: **Observed** (seen in logs) · **Attempted** (tried, did not succeed) · **Not observed** (hunted for, nothing found)

| Tactic | ID | Technique | Status | Evidence | Query |
|---|---|---|---|---|---|
| Reconnaissance | [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | Observed | Heavy traffic from the outlier IP | [Q01](queries/Q01-traffic-by-source-ip.kql) |
| Reconnaissance | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | Observed | Nmap Scripting Engine scanning ports, versions and vulnerabilities | [Q03](queries/Q03-methods-and-content-types.kql) |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Observed | Crafted `POST` multipart/form-data uploads against `session.upload_progress` | [Q02](queries/Q02-php-warnings-from-attacker.kql), [Q04](queries/Q04-attacker-post-requests.kql) |
| Persistence | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component: Web Shell | Observed | `health-check.php` in the webroot | [Q05](queries/Q05-web-shell-commands.kql) |
| Execution | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | Observed | Commands run through the web shell as `www-data` | [Q06](queries/Q06-which-account-ran-commands.kql) |
| Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Observed | Commands encoded with ROT13, then Base64 | [Q05](queries/Q05-web-shell-commands.kql) |
| Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Observed | `ip addr`, `ip neigh`, `ss -tlnp` | [Q05](queries/Q05-web-shell-commands.kql) |
| Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Software Discovery: Security Software Discovery | Observed | Found Sysmon, auditd and the Splunk Universal Forwarder | [Q07](queries/Q07-security-tool-discovery.kql) |
| Credential Access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Observed | `wp-config.php` read in plaintext; `wp_users` queried for `user_pass` | [Q05](queries/Q05-web-shell-commands.kql) |
| Defense Evasion | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | Attempted | `systemctl` attempts to stop Sysmon, auditd and the Splunk Forwarder all failed | [Q07](queries/Q07-security-tool-discovery.kql), [Q08](queries/Q08-did-monitoring-stop.kql) |
| Persistence | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job: Cron | Observed | Cron job running the implant every 5 minutes | [Q05](queries/Q05-web-shell-commands.kql) |
| Defense Evasion | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | Observed | Implant named `.cache-helper`, hidden in `/dev/shm` | [Q05](queries/Q05-web-shell-commands.kql) |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Observed | Base64 data returned in the web shell's HTTP responses | [Q05](queries/Q05-web-shell-commands.kql) |
| Lateral Movement | [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Not observed | No SSH, SCP, rsync or remote access commands | Checked across all tables |

**Coverage:** 13 techniques observed or attempted across 8 tactics, plus 1 hunted for and not found.

<!-- Note on T1552.001: the original report mapped the wp-config.php credential read to T1555
     (Credentials from Password Stores). T1552.001 fits better because the password sits in a plain
     config file. Change it back here if you prefer to keep the report's mapping. -->

<img src="divider.svg" alt="" width="100%">

## 🔍 KQL Queries

Each query is in [`queries/`](queries/) with a header giving its purpose, tables, ATT&CK mapping, and tuning notes. All time windows are 23 October 2026 UTC. Table names come from the practice workspace; change them for your own.

| ID | Name | Finds | Report ref |
|---|---|---|---|
| [Q01](queries/Q01-traffic-by-source-ip.kql) | Traffic volume by source IP | The outlier address | A1 |
| [Q02](queries/Q02-php-warnings-from-attacker.kql) | PHP warnings from the attacker | The exploited PHP feature | A2 |
| [Q03](queries/Q03-methods-and-content-types.kql) | Methods and content types | Nmap probes and the multipart exploit | A3 |
| [Q04](queries/Q04-attacker-post-requests.kql) | Attacker POST requests | The last exploit request | A3 |
| [Q05](queries/Q05-web-shell-commands.kql) | Web shell commands | Every encoded command sent to the shell | A4 |
| [Q06](queries/Q06-which-account-ran-commands.kql) | Which account ran the commands | `www-data` | (second A4) |
| [Q07](queries/Q07-security-tool-discovery.kql) | Security tool discovery | Checks on, and attempts to stop, monitoring | A5 |
| [Q08](queries/Q08-did-monitoring-stop.kql) | Did monitoring stop | The failed stop attempts | A6 |

<details>
<summary><b>Q01 · Traffic volume by source IP</b>: find the outlier address</summary>

**Hunt step:** 1 · **ATT&CK:** T1595 · **Table:** `HartwellApache_CL`

```kql
HartwellApache_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| summarize count() by SourceIP
```

**Result:** `192.168.1.100` stood out once the server's own address and the staff hosts were set aside.

</details>

<details>
<summary><b>Q02 · PHP warnings from the attacker</b>: reveal the exploited feature</summary>

**Hunt step:** 3 · **ATT&CK:** T1190 · **Table:** `HartwellApacheError_CL`

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where ClientIP == "192.168.1.100"
| where Message contains "session"
| project OriginalTime, Level, Message
```

**Result:** A string of PHP warnings from the `session.upload_progress` handler. These are internal state messages the handler emits before the memory corruption succeeds.

</details>

<details>
<summary><b>Q03 · Methods and content types</b>: profile what the attacker sent</summary>

**Hunt step:** 2 and 4 · **ATT&CK:** T1595.002, T1190 · **Table:** `HartwellHTTPEnriched_CL`

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where id_orig_h == "192.168.1.100"
| summarize count() by method, content_type
```

**Result:** Nmap Scripting Engine probes, plus `POST` requests with `multipart/form-data`, which normal web browsing does not produce.

</details>

<details>
<summary><b>Q04 · Attacker POST requests</b>: find the last exploit request</summary>

**Hunt step:** 4 · **ATT&CK:** T1190 · **Table:** `HartwellHTTPEnriched_CL`

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where id_orig_h == "192.168.1.100"
| where method == "POST"
| project method, content_type, OriginalTime
| order by OriginalTime desc
```

**Result:** The last crafted upload arrived at 09:57 UTC. Soon after, `health-check.php` appeared in the webroot.

</details>

<details>
<summary><b>Q05 · Web shell commands</b>: every request to the shell</summary>

**Hunt step:** 5, 7, 8, 10, 12, 13 · **ATT&CK:** T1505.003, T1059.004, T1027, T1016, T1552.001, T1053.003, T1041 · **Table:** `HartwellHTTPEnriched_CL`

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where uri == "/health-check.php"
| project OriginalTime, id_orig_h, request_headers
| order by OriginalTime asc
```

**Decoding:** Commands arrive in a custom header wrapped in two layers of encoding. Decode each value with Base64 first, then ROT13. Neither is encryption. Both have single built-in PHP functions, so the shell stays small and the goal is evasion, not secrecy.

**Result:** Decoded, the commands show network mapping, a read of `wp-config.php`, two `wp_users` queries (one for `user_login` and `user_email`, one for `user_login` and `user_pass`), a `SELECT * FROM wp_users` piped through Base64, cron persistence, and exfiltration in the response bodies.

</details>

<details>
<summary><b>Q06 · Which account ran the commands</b>: identify the account behind the activity</summary>

**Hunt step:** 6 · **ATT&CK:** T1059.004 · **Table:** `HartwellSysmon_CL`

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T09:57:00Z) .. datetime(2026-10-23T16:00:00Z))
| distinct User
```

**Result:** `www-data`. The window starts at the last exploit request from Q04.

</details>

<details>
<summary><b>Q07 · Security tool discovery</b>: find the attacker looking at, and stopping, monitoring</summary>

**Hunt step:** 9 · **ATT&CK:** T1518.001, T1562.001 · **Table:** `HartwellSysmon_CL`

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where CommandLine contains "systemctl"
| project OriginalTime, User, ParentImage, Image, CommandLine
| order by OriginalTime asc
```

**Result:** The attacker found three security tools: Sysmon (process, file and network events), auditd (system calls) and the Splunk Universal Forwarder (shipping logs to a central SIEM).

</details>

<details>
<summary><b>Q08 · Did monitoring stop</b>: check whether the stop attempts worked</summary>

**Hunt step:** 11 · **ATT&CK:** T1562.001 (attempted) · **Table:** `HartwellSysmon_CL`

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime(2026-10-23T04:00:00Z) .. datetime(2026-10-23T16:00:00Z))
| where User == "www-data"
| where CommandLine contains "systemctl stop"
| project OriginalTime, CommandLine, Image
```

**Result:** The stop attempts failed. `www-data` cannot stop services without root privileges. The attacker's own `systemctl is-active sysmon auditd SplunkForwarder` check confirmed all three kept running. That also shows the attacker never escalated beyond `www-data`, and that the monitoring data can be trusted from that point on.

</details>

<img src="divider.svg" alt="" width="100%">

## 🔎 Findings

| Item | Finding |
|---|---|
| Classification | Confirmed compromise: web shell, credential theft, data exfiltration, persistence |
| Attacker source | `192.168.1.100`, the one outlier address that was neither the server nor a staff host |
| Entry point | Crafted `POST` `multipart/form-data` uploads abusing PHP's `session.upload_progress` handler |
| Foothold | Web shell `/var/www/html/health-check.php`, running commands as `www-data` |
| Data taken | Contents of `wp-config.php` (database credentials) and the full `wp_users` table |
| Persistence | Cron job running `/dev/shm/.cache-helper` every 5 minutes |
| Monitoring | Attempts to stop Sysmon, auditd and the Splunk Forwarder all failed |
| Lateral movement | None found |

### Impact

| Area | Impact | Severity |
|---|---|---|
| Confidentiality | Database credentials and the full `wp_users` table, including password hashes, were exfiltrated | High |
| Integrity | Web shell, implant and cron job added to the server | High |

### Did the attacker move to other systems?

The evidence says no. The attacker stayed on the web server for the whole intrusion.

- The decoded command log contains no SSH, SCP, rsync or remote access commands.
- Sysmon process events from `www-data` show only local commands and loopback MySQL connections.
- An attempt to read `/etc/shadow` failed with permission denied, so no system password hashes were obtained.
- The MySQL credentials (`wpuser`) are database-local and cannot be used to log in to other hosts.

<img src="divider.svg" alt="" width="100%">

## 🧾 Indicators of Compromise

Values from a practice scenario.

| Type | Indicator | Action |
|---|---|---|
| IP address | `192.168.1.100` | Block and alert |
| Web shell | `/var/www/html/health-check.php` | Remove; alert on any request to it |
| File | `/dev/shm/.cache-helper` | Remove; hunt for it on other hosts |
| Scheduled task | `www-data` cron job running `/dev/shm/.cache-helper` every 5 minutes | Remove |
| Request pattern | `POST` with `multipart/form-data` used to exploit `session.upload_progress` | Alert |

<img src="divider.svg" alt="" width="100%">

## ⚔️ Response and Detection Recommendations

**Contain now**
1. Block the attacker's address, `192.168.1.100`.
2. Cut off access to `/var/www/html/health-check.php`, the attacker's only channel into the server.
3. Copy `/dev/shm/.cache-helper` **before** the server is rebooted. It lives in RAM, so a reboot destroys it and leaves no disk evidence.

**Accounts and credentials**

| Account or secret | Why it is affected | Action |
|---|---|---|
| WordPress database credentials (`wp-config.php`) | Read in plaintext by the attacker | Change the database password and update `wp-config.php` |
| WordPress user accounts | The `wp_users` table, including `user_pass` hashes, was exfiltrated | Reset every WordPress user's password |
| `www-data` | Ran every attacker command and owns the cron job | Remove its malicious cron entry |

**Remove persistence**
- [ ] Delete the web shell `/var/www/html/health-check.php`
- [ ] Remove the cron job from the `www-data` crontab
- [ ] Delete `/dev/shm/.cache-helper`, after preserving a copy for forensics

**Harden and detect**

| Recommendation | Finding it addresses | Priority |
|---|---|---|
| Fix or disable PHP's `session.upload_progress` handling | The exploit that gave the attacker code execution | High |
| Alert whenever `www-data` writes outside the upload directory | The web shell drop (the original detection point) | High |
| Alert on any attempt to stop Sysmon, auditd or the Splunk Forwarder | The attempt to blind monitoring ([Q07](queries/Q07-security-tool-discovery.kql), [Q08](queries/Q08-did-monitoring-stop.kql)) | Medium |

<img src="divider.svg" alt="" width="100%">

## 🕯️ Lessons Learned

- **What worked:** Starting from one precise detection point and following the trail in order: access log, error log, HTTP data, then endpoint telemetry. Mapping each finding to ATT&CK as I went kept the hunt organized.
- **Precision matters as much as resourcefulness.** Something as simple as the wrong time window can hide the evidence you are looking for.
- **Blind spots show up in real time.** Finding them and working through them was the most valuable part of the hunt.
- **What I'd do differently:** Save every query and take screenshots as I go. I did not, and a good amount of the work is not documented.

**Limits of this write-up**
- The eight queries above are the ones I saved. Others were run during the hunt but not kept, including the decoding step for Q05 and the checks that other tables showed no lateral movement.
- Most timestamps from the hunt were not saved. Only the last exploit request (09:57 UTC) is recorded.
- One host, one practice scenario. The queries have not been tested at production scale.
- The queries were corrected for syntax before publishing (see the headers of Q05, Q07 and Q08), and I have not been able to re-run them against the original workspace.

<img src="divider.svg" alt="" width="100%">

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Kusto Query Language reference](https://learn.microsoft.com/en-us/kusto/query/)
- [PHP session upload progress](https://www.php.net/manual/en/session.upload-progress.php)

### Glossary

| Term | Meaning |
|---|---|
| Web shell | A script planted on a web server that lets an attacker run commands through ordinary web requests |
| `www-data` | The low-privilege Debian account that runs Apache |
| `session.upload_progress` | A PHP feature that tracks the progress of file uploads, and the target of the exploit |
| ROT13 / Base64 | Simple, reversible encodings used to disguise the web shell's commands |
| tmpfs (`/dev/shm`) | A filesystem held entirely in RAM, wiped on reboot |
| Cron | The Linux scheduler for running jobs on a timetable |

<div align="center">

*Written by [Cai Spice](https://github.com/cai-spice) · [Back to profile](https://github.com/cai-spice)*

</div>
