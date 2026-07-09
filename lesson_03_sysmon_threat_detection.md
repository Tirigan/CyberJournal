# Sysmon: Extending Windows Logging for Threat Detection

## Overview
Native Windows Security logging has real gaps — it won't show command-line arguments, file creation, or network connections tied to a process. **Sysmon** (System Monitor), a free Microsoft Sysinternals tool, closes those gaps with a kernel-level driver that logs deep system activity.

Sysmon writes to its own log path (`Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`) and runs as a Windows service that survives reboots.

**Key Sysmon Event IDs:**

| Event ID | Logs |
|---|---|
| 1 | Process creation (full command line + parent process) |
| 3 | Network connection (process, source/dest IP, port) |
| 7 | Image loaded (DLL loads — useful for DLL hijacking) |
| 8 | CreateRemoteThread (process injection) |
| 10 | Process access (credential dumping via LSASS) |
| 11 | File creation |
| 22 | DNS query (process → domain lookups) |

## Why It Matters
Without Sysmon, native logging shows only that `powershell.exe` ran. With Sysmon Event ID 1, an analyst gets the full command line, parent process, user, and a hash of the binary — often the difference between catching an intrusion and scrolling past it.

Sysmon is foundational to detection engineering: it's the raw telemetry feeding SIEMs like Splunk and Sentinel for detections that mean something, instead of alerting on noise.

## Attacker Perspective
Attackers can't abuse Sysmon directly, but they work to evade or kill it:

1. **Tampering** — with admin rights, stop the service (`sc stop sysmon`) or uninstall it (`sysmon -u`) before noisy activity like lateral movement.
2. **Living off the land** — using built-in tools (`certutil.exe`, `mshta.exe`, `wscript.exe`) to look legitimate. Sysmon Event ID 1 still catches this because it logs the full command line, not just the process name.
3. **LSASS dumping** — tools like Mimikatz reach into `lsass.exe` for credentials. Sysmon Event ID 10 (process access targeting `lsass.exe`) is one of the more reliable ways to catch this.

## Detection
**Encoded PowerShell (Event ID 1)** — watch `CommandLine` for `-enc` / `-EncodedCommand`:
```
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -enc JABjAGwAaQBlAG4AdA...
```

**LSASS access (Event ID 10):**
```
EventID: 10
TargetImage: C:\Windows\System32\lsass.exe
SourceImage: C:\Users\attacker\mimikatz.exe
GrantedAccess: 0x1010
```

**Suspicious DNS (Event ID 22)**: repeated lookups to unfamiliar domains, especially from `cmd.exe` or `powershell.exe` rather than a browser — a common C2 beaconing pattern.

## Mitigation
Sysmon detects — it doesn't prevent. Pair it with:

1. **A real config.** The default config is noisy. Use a community baseline (SwiftOnSecurity, Olaf Hartong's modular config) to filter for what matters.
2. **Log forwarding.** Ship Sysmon output to Splunk, Sentinel, or ELK so it's correlated and alerted on, not sitting locally.
3. **Protect Sysmon itself.** SACL auditing to alert if the service is stopped or its config is touched — otherwise an attacker just turns off visibility silently.

## Tools
- **Sysmon** — [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **SwiftOnSecurity Sysmon config** — widely-used community baseline
- **Sysmon View** — GUI for browsing logs locally
- **PowerShell** (`Get-WinEvent`) — querying Sysmon logs from the command line
- **Splunk / Sentinel** — where these logs typically land in production

## Hands-On Lab

**1. Download Sysmon:**
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
```

**2. Get the SwiftOnSecurity config:**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
```

**3. Install with that config (run as Administrator):**
```powershell
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

**4. Query process creation events:**
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

**5.** Open a second PowerShell window, run something ordinary (`ping google.com`, `whoami /all`), then re-run the query above. Watching your own activity land in the log is the same visibility a SOC analyst works from during a real investigation.

## Interview Prep
1. What limitations of native Windows Security logging does Sysmon fix?
2. A Sysmon Event ID 10 alert fires targeting `lsass.exe`. What technique should you suspect, and what's your next step?
3. Why does a proper filtering config matter in production?
4. How would Sysmon Event ID 3 catch a reverse shell phoning home to C2?
5. An attacker runs `sc stop sysmon` on a compromised host. What monitoring catches that?

## Next
- MITRE ATT&CK: mapping real techniques to detections and organizing coverage
- Windows lateral movement detection — Pass-the-Hash, Pass-the-Ticket, PsExec
