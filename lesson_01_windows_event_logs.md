# Windows Event Logs: Analyzing Authentication Failures & Successes (Event IDs 4624 & 4625)

## What is it?
In Windows environments, the Security log is the primary source of truth for auditing access control and authentication. Whenever a user attempts to log in (whether successfully or unsuccessfully), the Local Security Authority (LSA) generates an audit event. 
- **Event ID 4624**: Successful Account Logon
- **Event ID 4625**: Failed Account Logon

Windows also tracks how someone logged in, called the Logon Type. Sitting down at the actual keyboard is Type 2. Connecting to a shared drive over the network is Type 3. Remote Desktop is Type 10. That distinction turns out to matter a lot for spotting attacks..

## Why does it matter in cybersecurity?
As a defender, authentication logs are the first line of detection for credential abuse. Attackers rarely exploit zero-days; instead, they use stolen credentials (obtained via phishing, dumping memory, or brute force) to move laterally across a network. Monitoring 4624 and 4625 events allows security analysts to pinpoint credential stuffing, brute-force attacks, and lateral movement.

## How attackers use it
A brute-force or credential-stuffing attempt shows up as a wall of 4625 failures in a short window — think a script hammering RDP or WinRM with thousands of password guesses. Lateral movement looks different: an attacker who's already compromised one machine uses stolen admin creds to hop onto a domain controller, usually via PowerShell Remoting (Type 3) or RDP (Type 10). That shows up as a successful 4624 — but from a source that has no business logging in there.

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
1. *Difference between 4624 and 4625?*
2. *What does a 4624 with Logon Type 10 tell you?*
3. *Which field on a 4625 points you to the attack's source?*
4. *How is password spraying different from brute force in the logs, and how do your detection thresholds change?*
5. *Why does lateral movement so often show up as Logon Type 3, and what services trigger it?*

## Next Topics
- **Kerberos Authentication Flow (AS-REQ, TGS, TGT)** and how attacks like Kerberoasting work.
- **Active Directory Architecture**: OUs, Group Policies, and Domain Controllers.
- **Sysmon**: Extending standard Windows logging to track process creation (Event ID 1) and network connections (Event ID 3).
