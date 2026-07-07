# Windows Event Logs: Analyzing Authentication Failures & Successes (Event IDs 4624 & 4625)

## What is it?
In Windows environments, the Security log is the primary source of truth for auditing access control and authentication. Whenever a user attempts to log in (whether successfully or unsuccessfully), the Local Security Authority (LSA) generates an audit event. 
- **Event ID 4624**: Successful Account Logon
- **Event ID 4625**: Failed Account Logon

Importantly, Windows distinguishes *how* the login occurred using **Logon Types**. For example, a local interactive login (sitting at the keyboard) is Logon Type 2, whereas a network connection (like mapping a network drive or accessing a shared folder) is Logon Type 3, and Remote Desktop (RDP) is Logon Type 10.

## Why does it matter in cybersecurity?
As a defender, authentication logs are the first line of detection for credential abuse. Attackers rarely exploit zero-days; instead, they use stolen credentials (obtained via phishing, dumping memory, or brute force) to move laterally across a network. Monitoring 4624 and 4625 events allows security analysts to pinpoint credential stuffing, brute-force attacks, and lateral movement.

## How attackers use it
1. **Brute-Force & Credential Stuffing**: An attacker runs a tool like Hydra or a PowerShell script against an exposed service (like RDP or WinRM), attempting thousands of passwords. This generates hundreds of Event ID 4625 (failed logon) alerts in a short time.
2. **Lateral Movement**: After compromising a workstation, an attacker uses stolen domain admin credentials to access a domain controller via PowerShell Remoting (Logon Type 3 or 9) or RDP (Logon Type 10). This creates a successful Event ID 4624 from an anomalous source IP.

## How defenders detect it
Defenders look for patterns in the Security log:
- **Brute Force**: High volume of Event ID 4625 within a short time frame (e.g., 50 failed logons in 1 minute) targeting a single account, or one password tried against multiple accounts (password spraying).
- **Anomalous Logon Types**: A standard user account suddenly logging in via RDP (Logon Type 10) or network logon (Logon Type 3) to a critical server they have no business accessing.
- **Key Fields to Inspect**:
  - `TargetUserName`: The account targeted.
  - `IpAddress` (under network information): The source IP of the connection.
  - `LogonProcessName`: Should typically be `NtLmSsp` or `Kerberos`.
  - `WorkstationName`: The host name of the source system.

## How to mitigate it
1. **Account Lockout Policies**: Configure Active Directory Group Policies (GPOs) to temporarily lock accounts after a specific number of failed attempts (e.g., 5-10 attempts within 15 minutes).
2. **Disable Remote Protocols**: Disable RDP and WinRM on workstations where they are not required.
3. **Multi-Factor Authentication (MFA)**: Enforce MFA for all remote and administrative logons to neutralize password-only compromises.
4. **LAPS (Local Administrator Password Solution)**: Ensure local administrator accounts have unique, randomized passwords across all systems to stop lateral movement.

## Tools to learn
- **Event Viewer (`eventvwr.msc`)**: The default GUI tool on Windows.
- **PowerShell (`Get-WinEvent`)**: Crucial for querying logs at scale.
- **Log Parser Studio**: A Microsoft tool to run SQL-like queries against raw log files.
- **SIEMs (Splunk, Sentinel, ELK)**: Enterprise platforms where event logs are aggregated and correlated.

## Hands-on Practice
Let's run a query on your local Windows machine to find all failed logon attempts. 
1. Open PowerShell as an **Administrator**.
2. Run the following command to retrieve the 10 most recent failed logon attempts (Event ID 4625):
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 10 | Format-Table TimeCreated, Message -Wrap
   ```
3. To extract specific fields like the target user and source IP, parse the XML structure of the log:
   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 5 | ForEach-Object {
       [xml]$xml = $_.ToXml()
       [PSCustomObject]@{
           Time           = $_.TimeCreated
           TargetUser     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
           IpAddress      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"}).'#text'
           SubStatus      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubStatus"}).'#text'
       }
   }
   ```

## Interview Questions
1. *What is the difference between Windows Event ID 4624 and Event ID 4625?*
2. *If you see an Event ID 4624 with Logon Type 10, what does that indicate?*
3. *What field in a 4625 event would you inspect to find the physical source of a brute-force attack?*
4. *How does password spraying differ from a standard brute-force attack in Event Logs, and how would you adjust your detection thresholds?*
5. *Why is Logon Type 3 common in lateral movement, and what services generate it?*

## Next Topics
- **Kerberos Authentication Flow (AS-REQ, TGS, TGT)** and how attacks like Kerberoasting work.
- **Active Directory Architecture**: OUs, Group Policies, and Domain Controllers.
- **Sysmon**: Extending standard Windows logging to track process creation (Event ID 1) and network connections (Event ID 3).
