# Sysmon: Supercharging Windows Logging for Threat Detection

## What is it?
The Windows Security log is useful, but it has real gaps — it won't tell you what command-line arguments a process ran, what files it created, or what it connected to over the network. Sysmon (System Monitor) is a free Microsoft Sysinternals tool that fills those gaps by installing a kernel-level driver that watches and logs deep system activity.

Once it's running, Sysmon writes to its own log under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`. It sits quietly as a Windows service and survives reboots without you having to think about it.

**Key Sysmon Event IDs:**

| Event ID | What it Logs |
|---|---|
| **1** | Process creation (full command line + parent process) |
| **3** | Network connection (process, source/dest IP, port) |
| **7** | Image loaded (DLL loads — useful for catching DLL hijacking) |
| **8** | CreateRemoteThread (process injection) |
| **10** | Process access (credential dumping via LSASS) |
| **11** | File creation |
| **22** | DNS query (process → domain lookups) |

## Why does it matter in cybersecurity?
Without Sysmon, a SOC analyst looking at Windows logs just sees that `powershell.exe` ran — that's it. With Sysmon Event ID 1, they get the full command line, the parent process that spawned it, the user running it, and a hash of the binary. That extra context is often the difference between catching an intrusion and scrolling right past it.

Sysmon is genuinely foundational to detection engineering. It's what feeds SIEMs like Splunk and Microsoft Sentinel the raw telemetry needed to write detections that actually mean something, instead of just alerting on noise.

## How attackers use it
Attackers can't really "abuse" Sysmon directly — but they absolutely try to evade or kill it:

1. **Tampering with Sysmon itself** — with admin rights, an attacker might stop the service (`sc stop sysmon`) or uninstall it entirely (`sysmon -u`) to blind defenders before doing anything noisy like lateral movement.
2. **Living off the land** — using built-in Windows tools like `certutil.exe`, `mshta.exe`, or `wscript.exe` to run malicious payloads, since these binaries look "legitimate" on the surface. Sysmon Event ID 1 still catches this because it logs the full command line, not just the process name.
3. **LSASS dumping** — tools like Mimikatz reach into `lsass.exe` to pull credentials out of memory. Sysmon Event ID 10 (process access targeting `lsass.exe`) is one of the more reliable ways to catch this in the act.

## How defenders detect it
This is where Sysmon earns its keep — these detections just aren't possible with native Windows logging alone.

**Catching encoded PowerShell (Event ID 1):**
Attackers love base64-encoding their PowerShell payloads to dodge simple string matching. Watch for `CommandLine` containing `-enc` or `-EncodedCommand`:
```
EventID: 1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -enc JABjAGwAaQBlAG4AdA...
```

**Catching LSASS access (Event ID 10):**
```
EventID: 10
TargetImage: C:\Windows\System32\lsass.exe
SourceImage: C:\Users\attacker\mimikatz.exe
GrantedAccess: 0x1010
```

**Catching suspicious DNS activity (Event ID 22):**
Malware beaconing back to a C2 server tends to show up as repeated DNS lookups to unfamiliar domains, often coming from `cmd.exe` or `powershell.exe` rather than a browser.

## How to mitigate it
Sysmon detects — it doesn't prevent. Pair it with:

1. **A real config, not the default one.** Sysmon out of the box logs everything and drowns you in noise. Use a community config like SwiftOnSecurity's or Olaf Hartong's modular one to actually filter for what matters.
2. **Ship the logs somewhere.** Forward Sysmon output to Splunk, Sentinel, or an ELK stack so it can actually be correlated and alerted on, not just sitting locally.
3. **Protect Sysmon itself.** Use SACL auditing so you get alerted if someone stops the service or messes with its config — otherwise an attacker just turns off your visibility and you'd never know.

## Tools worth knowing
- **Sysmon** — free from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **SwiftOnSecurity Sysmon config** — the community config a lot of real SOCs actually run.
- **Sysmon View** — a GUI for browsing Sysmon logs locally.
- **PowerShell (`Get-WinEvent`)** — for querying Sysmon logs from the command line.
- **Splunk / Microsoft Sentinel** — where these logs typically end up in an enterprise setup.

## Hands-on Practice
### Install Sysmon on your own PC

**1. Download Sysmon:**
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
```

**2. Grab the SwiftOnSecurity config:**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
```

**3. Install Sysmon with that config (run as Administrator):**
```powershell
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

**4. Query for process creation events:**
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

**5.** Open a second PowerShell window and run something ordinary — `ping google.com`, `whoami /all` — then re-run the query above and watch your own activity show up in the log. It's a small moment, but it's a good one: this is the same visibility a SOC analyst would be staring at during a real investigation.

## Interview Questions
1. What are the limitations of native Windows Security logging that Sysmon fixes?
2. A SOC alert fires on Sysmon Event ID 10 targeting `lsass.exe`. What technique should you suspect, and what's your next step?
3. Why does filtering Sysmon with a proper config matter in production?
4. How would you use Sysmon Event ID 3 to catch a reverse shell phoning home to a C2 server?
5. An attacker runs `sc stop sysmon` on a compromised host. What monitoring would catch that?

## Next Topics
- **MITRE ATT&CK Framework** — mapping real attack techniques to detections, and how SOC teams use it to organize their detection coverage.
- **Windows Lateral Movement Detection** — Pass-the-Hash, Pass-the-Ticket, and PsExec: what they actually look like in the logs and how to catch them.
