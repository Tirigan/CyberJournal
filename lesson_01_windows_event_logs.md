# Windows Event Logs: Authentication Failures & Successes (Event IDs 4624 & 4625)

## Overview
The Windows Security log is the primary source of truth for authentication activity. Every logon attempt — successful or failed — generates an audit event from the Local Security Authority (LSA).

- **4624**: Successful logon
- **4625**: Failed logon

Each event also records a **Logon Type**, which describes *how* the logon happened: interactive at the keyboard (Type 2), over a network share (Type 3), or Remote Desktop (Type 10). That distinction is often the difference between "normal admin activity" and "someone is inside the network."

## Why It Matters
Attackers rarely need a zero-day. Stolen credentials — from phishing, memory dumping, or brute force — are enough to move laterally across a network. 4624/4625 are the first place that abuse surfaces, which makes them a baseline detection source for any SOC.

## Attacker Perspective
- **Brute force / credential stuffing**: a wall of 4625 failures in a short window — a script hammering RDP or WinRM with password guesses.
- **Lateral movement**: an attacker who already owns one machine uses stolen admin credentials to reach a domain controller, typically via PowerShell Remoting (Type 3) or RDP (Type 10). This shows up as a *successful* 4624 — from a source that has no business logging in there.

## Detection
Key fields on both event types:

| Field | What it tells you |
|---|---|
| `TargetUserName` | Account being authenticated |
| `IpAddress` | Source of the connection |
| `LogonProcessName` | Should typically be `NtLmSsp` or `Kerberos` |
| `WorkstationName` | Hostname of the source system |

Patterns worth alerting on:
- High volume of 4625 against a single account in a short window (brute force), or one password tried across many accounts (spraying)
- A standard user account logging in via RDP or network logon to a server it has no business touching

## Mitigation
1. **Account lockout policy** — lock accounts after a defined number of failed attempts (e.g. 5–10 within 15 minutes).
2. **Disable unused remote protocols** — turn off RDP/WinRM on workstations that don't need them.
3. **MFA** — enforce it on all remote and administrative logons.
4. **LAPS** — unique, randomized local admin passwords per machine, so one compromised credential can't be reused for lateral movement.

## Tools
- **Event Viewer** (`eventvwr.msc`) — default GUI
- **PowerShell** (`Get-WinEvent`) — for querying at scale
- **Log Parser Studio** — SQL-style queries against raw log files
- **SIEMs** (Splunk, Sentinel, ELK) — aggregation and correlation at scale

## Hands-On Lab
Pull the 10 most recent failed logon attempts:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 10 | Format-Table TimeCreated, Message -Wrap
```

Extract specific fields — target user, source IP, sub-status — from the event XML:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 5 | ForEach-Object {
    [xml]$xml = $_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        TargetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
        IpAddress  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"}).'#text'
        SubStatus  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubStatus"}).'#text'
    }
}
```

## Interview Prep
1. Difference between 4624 and 4625?
2. What does a 4624 with Logon Type 10 tell you?
3. Which field on a 4625 points to the attack's source?
4. How does password spraying differ from brute force in the logs, and how do detection thresholds change?
5. Why does lateral movement so often show up as Logon Type 3, and what services trigger it?

## Next
- Kerberos authentication flow and how Kerberoasting abuses it
- Active Directory architecture: OUs, GPOs, Domain Controllers
- Sysmon: extending native Windows logging to process creation and network connections
