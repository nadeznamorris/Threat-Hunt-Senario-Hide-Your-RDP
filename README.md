# Threat-Hunting-Scenario-Hide-Your-RDP

## RDP Compromise Incident

**Report ID:** INC-2025-1409

**Analyst:** Nadezna Morris

**Date:** 21-September-2025

**Incident Date:** 14-September-2025

---

## **1. Findings**

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** `159.26.106.84`
- **Compromised Account:** `slflare`
- **Malicious File:** `msupdate.exe`
- **Persistence Mechanism:** `Scheduled Task`
- **C2 Server:** `185.92.220.87`
- **Exfiltration Destination:** `185.92.220.87`

### **KQL Queries Used:**

**Query 1 - Initial Access Detection:**

```
DeviceLogonEvents
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-18 00:00:00))
| where DeviceName contains "flare"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, AccountName, RemoteIP
| order by Timestamp asc
```
**Results:** `159.26.106.84` and `slflare`

<img width="900" height="172" alt="Flag 1-2" src="https://github.com/user-attachments/assets/8243f8e8-aa21-4b61-9c14-cc98a2043d7b" />

---

**Query 2 - Compromised Account:**

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-18 00:00:00))
| where DeviceName == "slflarewinsysmo"
| where AccountName == "slflare"
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Users\\Public\\", "\\Temp\\", "\\Downloads\\", "\\Desktop\\")
| project Timestamp, AccountName, FileName, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:** `msupdate.exe` and `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`

<img width="1000" height="372" alt="Flag 3-4" src="https://github.com/user-attachments/assets/95a6f218-e93e-4c7f-811e-deab5777a2c9" />

---

**Query 3 - Persistence Detection:**

```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-18 00:00:00))
| where DeviceName == "slflarewinsysmo"
| where RegistryKey has @"\Schedule\TaskCache\Tree\"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc
```

**Results:** `MicrosoftUpdateSync`

<img width="900" height="210" alt="Flag 5" src="https://github.com/user-attachments/assets/d816ed6f-ce9f-4ffb-bd80-57ae5b3bffcf" />

---

**Query 4 - Defense Evasion:**

```
DeviceRegistryEvents
| where DeviceName contains "flare"
| where RegistryKey has @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" 
      or RegistryKey has @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData, ReportId
| sort by Timestamp desc
```

**Results:** `C:\Windows\Temp`

<img width="700" height="358" alt="Flag 6" src="https://github.com/user-attachments/assets/b05cb3ec-915e-4587-84e2-fd6ea62aa1c7" />

---

**Query 5 - Discovery:**

```
DeviceProcessEvents
| where DeviceName == "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-13 00:00:00) .. datetime(2025-09-18 00:00:00))
| where ProcessCommandLine has_any ("systeminfo", "ipconfig", "whoami", "net user", "netstat", "wmic", "query", "Get-Process", "Get-Service")
      or FileName in ("systeminfo.exe","ipconfig.exe","whoami.exe","net.exe","netstat.exe","wmic.exe","powershell.exe","cmd.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
| sort by Timestamp asc
```

**Results:** `"cmd.exe" /c systeminfo`

<img width="1200" height="332" alt="image" src="https://github.com/user-attachments/assets/2fe97e4f-f42a-4360-aee0-10f333e50f36" />

**Additional Evidence:**  
After impairing defenses, the attacker conducted host reconnaissance using built-in Windows commands, consistent with MITRE Technique **T1082 – System Information Discovery**. The earliest command observed was `"cmd.exe" /c systeminfo`, followed by a sequence of enumeration commands including `"whoami /all"`, `"net user"`, `"net localgroup administrators"`, and `"ipconfig /all"`. These commands provided the adversary with detailed information about the system configuration, user accounts, administrative group memberships, and network settings, supporting their situational awareness and potential privilege escalation planning.

---

**Query 6 - Discovery:**

```
DeviceFileEvents
| where Timestamp between (datetime(2025-09-14 00:00:00) .. datetime(2025-09-18 00:00:00))
| where DeviceName == "slflarewinsysmo"
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, ReportId
| sort by Timestamp asc
```

**Results:** `backup_sync.zip`

<img width="900" height="330" alt="Flag 8" src="https://github.com/user-attachments/assets/9d61b676-70b0-4267-a9af-889e04766f0e" />

---

**Query 7 - Command and Control (C2):**

```
let suspiciousProcesses = dynamic(["powershell.exe","cmd.exe","wscript.exe","mshta.exe","python.exe","cscript.exe"]);
DeviceNetworkEvents
| where Timestamp between (datetime(2025-09-14 00:00:00) .. datetime(2025-09-18 00:00:00))
| where DeviceName == "slflarewinsysmo"
| where InitiatingProcessFileName in (suspiciousProcesses)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, Protocol
| sort by Timestamp asc
```

**Results:** `185.92.220.87`

<img width="1000" height="142" alt="Flag 9" src="https://github.com/user-attachments/assets/4ff26790-1ba5-460f-807e-4f1566ff63e4" />

---

**Query 8 - Exfiltration:**

```
DeviceNetworkEvents
| where RemoteIP == "185.92.220.87"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol, ReportId
| sort by Timestamp asc
```

**Results:** `185.92.220.87:8081`

<img width="1100" height="208" alt="Flag 10" src="https://github.com/user-attachments/assets/f340c11c-77ba-452f-94c7-834872821539" />

---

## **2. Investigation Summary**

**What Happened:**  
An external actor from `159.26.106.84` performed a brute-force RDP attack, with 10 failed attempts followed by 5 successful logins, including a **RemoteInteractive** session on **2025-09-16T18:43:46.8644523Z**. The attacker used the compromised account `slflare` to execute a suspicious binary `msupdate.exe` via PowerShell with execution-policy bypass, from the **Public** folder. Persistence was established through a scheduled task named `MicrosoftUpdateSync`, and Microsoft Defender was modified to exclude `C:\Windows\Temp`, allowing the attacker to evade detection. Host reconnaissance was conducted using commands like `systeminfo`, `whoami /all`, `net user`, `net localgroup administrators`, and `ipconfig /all`. Collected data was archived into `backup_sync.zip` for exfiltration. Finally, the attacker’s system connected to `185.92.220.87` and attempted to exfiltrate the archive over port **8081** using **powershell.exe** and **curl.exe**, likely to bypass standard monitoring and firewall restrictions.

---

**Attack Timeline:**

- **Started:** 2025-09-16T18:43:46.8644523Z
- **Ended:** 2025-09-16T19:43:42.3902425Z
- **Duration:** 60 mins 05 sec

**Impact Level:** High

---

## **3. Who, What, When, Where, Why, How**

### **Who:**

- **Attacker:** 159.26.106.84
- **Victim Account:** slflare
- **Affected System:** slflarewinsysmo
- **Impact on Users:** account compromise, data exposure risk, service disruption and privacy and security risk

### **What:**

- **Attack Type:** RDP Brute Force with Post-Compromise Execution and Data Exfiltration Attempt
- **Malicious Activities:**
    - **Brute‑force RDP attempts and successful login** — 10 failed RDP attempts followed by 5 successful logins, culminating in a RemoteInteractive session (first success observed at 2025-09-16T18:43:46.8644523Z).
    - **Account compromise / valid-credentials use** — Attacker authenticated using the legitimate account slflare.
    - **Suspicious binary execution** — Execution of msupdate.exe on the host.
    - **PowerShell-based execution with bypass** — msupdate.exe invoked PowerShell: "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1.
    - **Persistence via scheduled task** — Creation of scheduled task MicrosoftUpdateSync to maintain access.
    - **Tampering Defender exclusions** — Added C:\Windows\Temp to Microsoft Defender’s exclusion list to avoid detection.
    - **Host discovery / reconnaissance** — Commands executed to enumerate the system and accounts: systeminfo, whoami /all, net user, net localgroup administrators, ipconfig /all.
    - **Local data staging / archiving** — Creation of archive backup_sync.zip to prepare data for exfiltration.
    - **Command-and-control communication** — Beaconing / outbound connection to external host 185.92.220.87.
    - **Exfiltration attempt over non‑standard port** — Attempt to send staged data to 185.92.220.87:8081 using powershell.exe and curl.exe (last observed activity: curl.exe at 2025-09-16T19:43:42.3902425Z).

### **When:**

- **First Malicious Activity:** 2025-09-16T18:43:46.8644523Z
- **Last Observed Activity:** 2025-09-16T19:43:42.3902425Z
- **Detection Time:** 2025-09-16T18:36:55.2404102Z
- **Total Attack Duration:** 60min 05 sec (363056 seconds)
- - **Is it still active?** No

### **Where:**

- **Target System:** slflarewinsysmo
- **Attack Origin:** ________________ *(geographic location if known)*
- **Network Segment:** 159.26.106.0/24
- **Affected Directories/Files:** `C:\Users\Public\update_check.ps1` (executed), `msupdate.exe` (executed), `backup_sync.zip` (staged for exfiltration), scheduled task `C:\Windows\System32\Tasks\MicrosoftUpdateSync` (persistence), and `C:\Windows\Temp` (added to Defender exclusions). Additional likely locations to check: `C:\Users\Public`, `C:\Windows\Temp`, `%APPDATA%`, and the user Downloads folder.

### **Why:** 

- **Likely Motive:** financially or operationally motivated data theft
- **Target Value:** The account `slflare` may have had administrative or elevated permissions on the host, accessible remotely via RDP and likely to host or access sensitive data

### **How:**

- **Initial Access Method:** Brute‑force RDP (password guessing) leading to valid‑credential logon.
- **Tools/Techniques Used:** msupdate.exe, powershell.exe (used with -ExecutionPolicy Bypass), curl.exe, Built‑in Windows CLI utilities used for discovery: systeminfo, whoami, net (net user / net localgroup), ipconfig, archiver/zip utility (used to create backup_sync.zip)
- **Persistence Method:** Scheduled task (MicrosoftUpdateSync)
- **Data Collection Method:** Local host‑based collection (archiving)
- **Communication Method:** HTTP-style application‑layer communication over TCP (185.92.220.87:8081)

---

## **4. Recommendations** 

### **Immediate Actions Needed:**

1. **Isolate the host slflarewinsysmo from the network** — prevent further lateral movement/C2/exfil (pull network cable or block on switch/firewall).
2. **Contain & remove active persistence** — disable/delete the scheduled task MicrosoftUpdateSync and remove Defender exclusion. (Example commands: schtasks /Delete /TN "MicrosoftUpdateSync" /F and Remove-MpPreference -ExclusionPath "C:\Windows\Temp" — run from an admin/IR machine.)
3. **Rotate credentials & revoke sessions for slflare** — reset the slflare password, force logoff/terminate sessions, and revoke any long‑lived tokens or sessions; enable temporary lockout for that account.

### **Short-term Improvements (1-30 days):**

1. **Hunt & remediate artifacts on the host** — collect and preserve update_check.ps1, msupdate.exe, backup_sync.zip, Task XML and relevant registry keys; run full AV/EDR scan and manually remove malicious files.
2. **Network blocking & logging** — block the attacker IPs/subnets (159.26.106.84, 159.26.106.0/24, 185.92.220.87, 185.92.220.0/24) at perimeter and proxy; capture PCAPs/session logs for the exfil attempts and retain for IR.
3. **Strengthen access controls for RDP accounts** — disable direct internet RDP, require VPN/bastion, enable MFA for remote access, and apply stricter account lockout policies (low threshold for failed RDP logons)

### **Long-term Security Enhancements:**

1. **Harden remote access & least privilege** — remove unnecessary RDP exposure, implement jump/bastion hosts, enforce least privilege on user accounts, and remove local admin rights where possible.
2. **Improve detection & telemetry** — deploy/enable logging for process command lines, scheduled task creation, Defender exclusion changes, and network connection metadata; tune alerts for rapid detection of these TTPs.
3. **Security lifecycle controls** — enforce strong password policies + MFA, regular credential rotation, endpoint configuration baselines (application allowlisting), regular threat‑intel‑driven blocklist updates, and a tested incident response runbook.


### **Detection Improvements:**
- **Monitoring Gaps Identified:**
   1. RDP brute-force attempts not fully monitored — repeated failed logins followed by a success weren’t automatically alerted.
   2. File/script execution in public/temp folders — creation/execution of malicious binaries or scripts wasn’t generating high-priority alerts.
   3. Defender exclusions changes — modification of exclusion paths (e.g., C:\Windows\Temp) went unnoticed.
   4. Suspicious archive creation & staging — creation of backup_sync.zip or similar files for exfiltration lacked detection.
   5. Outbound C2 / exfil attempts — non-standard ports (8081) and use of powershell.exe or curl.exe weren’t flagged promptly.
- **Recommended Alerts:**
   1. Failed RDP logon spikes — alert when multiple failed logins are followed by a successful login for the same account/IP.
   2. Execution from public/temp directories — alert on binaries (*.exe) or scripts executed from C:\Users\Public, C:\Windows\Temp, or user Downloads folder.
   3. Registry changes to Defender exclusions — alert on modifications to keys under HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions.
   4. Suspicious archiving / data staging — alert when a large .zip or similar archive is created by non-standard processes.
   5. Unusual outbound connections — alert on connections to uncommon external IPs or high-risk subnets on non-standard ports (especially via powershell.exe or curl.exe).
- **Query Improvements:**
   1. Combine process, file, and network telemetry — write unified KQL to correlate:
      - Process execution in Public/Temp
      - Creation of .zip archives
      - Outbound connections by same process/account
   2. Include account, host, and command-line filters — detect both suspicious process and its parameters (-ExecutionPolicy Bypass, update_check.ps1).
   3. Enhance RDP monitoring — track failed login counts per IP per account, plus alert on success after multiple failures.
   4. Add time-based windows — e.g., alert if multiple events happen within 10–15 minutes, indicating rapid attacker activity.
   5. Normalize JSON / nested fields — ensure DeviceDetail, RegistryValueData, and CommandLine are searchable consistently to reduce false negatives.

---

**Report Status:** Complete

**Next Review:** 4th October 2025

**Distribution:** Cyber Range




