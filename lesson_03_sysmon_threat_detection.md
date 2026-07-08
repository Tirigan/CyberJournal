# Sysmon: Supercharging Windows Logging for Threat Detection

## What is it?
The Windows Security event log is useful, but it has significant gaps — it won't tell you what command-line arguments a process ran, what files it created, or what network connections it made. **Sysmon (System Monitor)** is a free Microsoft Sysinternals tool that fills those gaps by injecting a kernel-level driver that monitors and logs deep system activity.

Once installed, Sysmon generates its own event log under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`. It runs silently as a Windows service and survives reboots.

Key Sysmon Event IDs:
| Event ID | What it Logs |
|---|---|
| **1** | Process creation (includes full command line + parent process) |
| **3** | Network connection (process, source/dest IP, port) |
| **7** | Image loaded (DLL loads — detect DLL hijacking) |
| **8** | CreateRemoteThread (process injection detection) |
| **10** | Process access (credential dumping via LSASS) |
| **11** | File creation |
| **22** | DNS query (process → domain lookups) |

## Why does it matter in cybersecurity?
Without Sysmon, a SOC analyst reviewing Windows logs sees that `powershell.exe` ran — nothing else. With Sysmon Event ID 1, they see the **full command line**, the **parent process** that launched it, the **user**, and a **hash of the binary**. That difference is the line between a missed alert and a caught intrusion.

Sysmon is a cornerstone of detection engineering. It feeds SIEMs like Splunk and Microsoft Sentinel with the telemetry needed to write meaningful detection rules.

## How attackers use it
Attackers cannot directly abuse Sysmon — but they actively try to **evade or disable it**:
1. **Sysmon Tampering**: Attackers with admin privileges may attempt to stop the Sysmon service (`sc stop sysmon`) or uninstall it (`sysmon -u`) to blind defenders before lateral movement.
2. **Living off the Land (LOLBins)**: Attackers use built-in Windows tools like `certutil.exe`, `mshta.exe`, or `wscript.exe` to execute malicious payloads because they appear legitimate. Sysmon Event ID 1 catches these because it logs the command-line arguments.
3. **LSASS Dumping**: Tools like Mimikatz access `lsass.exe` to dump credentials. Sysmon Event ID 10 (ProcessAccess targeting `lsass.exe`) is one of the most reliable detections for this.

## How defenders detect it
Sysmon enables detections that are impossible with native Windows logging alone:

**Detecting PowerShell Encoded Commands (Event ID 1)**:
Attackers frequently base64-encode PowerShell payloads to evade string-based detection.
Look for processes where `CommandLine` contains `-enc` or `-EncodedCommand`:
```
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -enc JABjAGwAaQBlAG4AdA...
```

**Detecting LSASS Access (Event ID 10)**:
```
EventID: 10
TargetImage: C:\Windows\System32\lsass.exe
SourceImage: C:\Users\attacker\mimikatz.exe
GrantedAccess: 0x1010
```

**Detecting Suspicious DNS Queries (Event ID 22)**:
Malware beaconing to C2 infrastructure shows as repeated DNS queries to unknown domains from processes like `cmd.exe` or `powershell.exe`.

## How to mitigate it
Sysmon is a detection tool, not a prevention tool. Pair it with:
1. **A solid Sysmon config**: The default Sysmon config is noisy and logs everything. Use the community-maintained **SwiftOnSecurity Sysmon config** or **Olaf Hartong's modular config** to filter out noise and focus on high-value events.
2. **SIEM ingestion**: Forward Sysmon logs to Splunk, Microsoft Sentinel, or an ELK stack for correlation and alerting.
3. **Protect Sysmon itself**: Use Windows SACL auditing to alert if the Sysmon service is stopped or its configuration is modified.

## Tools to learn
- **Sysmon**: [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — download and install free from Microsoft.
- **SwiftOnSecurity Sysmon Config**: Community Sysmon config used by many real SOC environments.
- **Sysmon View**: A GUI tool for visualizing Sysmon logs locally.
- **PowerShell (`Get-WinEvent`)**: Query Sysmon logs from the command line.
- **Splunk / Microsoft Sentinel**: Where Sysmon logs go in enterprise environments.

## Hands-on Practice
### Install Sysmon on your Windows PC

1. **Download Sysmon**: 
   ```powershell
   # Download from Microsoft Sysinternals
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
   ```

2. **Download the SwiftOnSecurity config**:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
   ```

3. **Install Sysmon with the config (run as Administrator)**:
   ```powershell
   & "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
   ```

4. **Query Sysmon for process creation events**:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 10 |
   ForEach-Object {
       [xml]$xml = $_.ToXml()
       [PSCustomObject]@{
           Time        = $_.TimeCreated
           Process     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"}).'#text'
           CommandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
           ParentImage = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ParentImage"}).'#text'
       }
   }
   ```

5. Open another PowerShell window and run something interesting (e.g., `ping google.com`, `whoami /all`), then re-run the query above and observe your own activity being logged.

## Interview Questions
1. *What are the limitations of native Windows Security event logging that Sysmon addresses?*
2. *A SOC alert fires on Sysmon Event ID 10 targeting `lsass.exe`. What attack technique should you suspect and what is your next step?*
3. *Why is filtering Sysmon with a configuration file important in a production environment?*
4. *How would you use Sysmon Event ID 3 to detect a reverse shell connecting to a C2 server?*
5. *An attacker runs `sc stop sysmon` on a compromised host. What monitoring would you put in place to detect this action?*

## Next Topics
- **MITRE ATT&CK Framework**: Mapping real attack techniques to detections — how SOC teams use it to categorize threats and build detection coverage.
- **Windows Lateral Movement Detection**: Pass-the-Hash, Pass-the-Ticket, and PsExec — what they look like in logs and how to catch them.
