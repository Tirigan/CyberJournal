# Active Directory Enumeration & Kerberoasting (Targeting Service Accounts)

## What is it?
In an enterprise Active Directory (AD) environment, users and services authenticate using the **Kerberos protocol**. 
When a user wants to access a service (like a SQL database or a web server running under a specific service account), they ask the Domain Controller (specifically the Key Distribution Center, or KDC) for a **Ticket Granting Service (TGS)** ticket.
A **Service Principal Name (SPN)** is a unique identifier that associates a service instance with a specific Active Directory login account.
**Kerberoasting** is an offline password-cracking technique where any authenticated domain user requests a TGS ticket for a service account associated with an SPN. Because the ticket is encrypted using the service account's password hash, the attacker can extract the ticket from memory, take it offline, and attempt to brute-force the password.

## Why does it matter in cybersecurity?
Kerberoasting is one of the most common and effective techniques for privilege escalation and lateral movement. 
1. **No Admin Privileges Needed**: Any domain user (even a low-privileged temp worker or a compromised endpoint) can query the domain controller and request TGS tickets for all SPNs.
2. **Stealthy**: Querying SPNs and requesting TGS tickets is a normal part of how Kerberos functions. To a basic monitoring system, it looks like standard user behavior.
3. **High Reward**: Service accounts are frequently configured with domain administrator privileges or access to highly sensitive database servers.

## How attackers use it
1. **SPN Scanning (Enumeration)**: The attacker queries Active Directory using LDAP to list all registered SPNs. This tells them which user accounts are running services.
2. **Ticket Request**: The attacker requests a TGS ticket for target SPNs. The domain controller complies and sends the ticket.
3. **Extraction**: Using tools like Mimikatz or Rubeus, the attacker dumps the TGS tickets from their system's memory.
4. **Offline Cracking**: The attacker copies the tickets to their attack machine and uses `hashcat` or `John the Ripper` to brute-force the plaintext password using a wordlist (like RockYou). If the service account has a weak password, it will be cracked in minutes.

## How defenders detect it
While Kerberos ticket requests are normal, Kerberoasting generates anomalous patterns:
1. **Event ID 4769 (A Kerberos service ticket was requested)**:
   - **Encryption Type**: Watch for requests using weaker encryption algorithms like **RC4 (0x17)**. Modern Windows environments should use **AES (0x12 / 0x18)**. Attackers often request RC4 because it is much faster to crack offline.
   - **Frequency / Volume**: A single user requesting tickets for dozens of service accounts in a matter of seconds is highly anomalous.
2. **Honeytokens**: Create a dummy service account (e.g., `sql-service-backup`) with a high-privilege SPN but no actual access. Configure an alert for any TGS request (Event ID 4769) targeting this dummy account. Since it has no legitimate use, any request to it is a confirmed indicator of compromise (IoC).

## How to mitigate it
1. **Strong Passwords for Service Accounts**: Ensure all service account passwords are at least 25+ characters, or migrate them to **Group Managed Service Accounts (gMSAs)**, which automatically rotate 120-character passwords.
2. **Enforce AES Encryption**: Disable RC4 encryption for Kerberos in Group Policy, forcing the use of AES-128 and AES-256.
3. **Least Privilege**: Ensure service accounts only have the exact permissions they need to run their services, rather than default Domain Admin rights.

## Tools to learn
- **Rubeus**: A C# toolset for raw Kerberos interaction and abuses (used by red teams).
- **Impacket (`GetUserSPNs.py`)**: A Python collection of network protocols, widely used to perform Kerberoasting from non-Windows systems.
- **PowerView**: A PowerShell script for AD enumeration.
- **Hashcat**: A GPU-based password recovery tool used to crack the dumped tickets offline.

## Hands-on Practice: Viewing & Enumerating SPNs
Even without an Active Directory lab, you can inspect your local computer's Kerberos tickets and query SPNs using built-in Windows tools.

### Part 1: Inspecting Your Active Kerberos Tickets
1. Open Command Prompt or PowerShell.
2. Run `klist` to view your current cached Kerberos tickets.
   ```cmd
   klist
   ```
   *Note: If you are on a home computer not joined to a domain, this list may be empty or show local credentials.*

### Part 2: Querying SPNs (Active Directory Commands)
If you were on an enterprise domain-joined machine, you could run the following built-in command to search for SPNs without triggering antivirus alerts:
- **Built-in tool**:
  ```cmd
  setspn -T targetdomain -Q */*
  ```
- **PowerShell (Active Directory Module)**:
  ```powershell
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName
  ```

## Interview Questions
1. *What is an SPN (Service Principal Name) in Active Directory, and how does Kerberoasting abuse it?*
2. *Why is Kerberoasting considered a highly stealthy attack, and what makes it difficult to detect?*
3. *If you are reviewing Event ID 4769 logs in your SIEM, what specific fields would you look at to detect potential Kerberoasting?*
4. *How does the encryption type requested in a TGS ticket affect an attacker's ability to crack it?*
5. *What are Group Managed Service Accounts (gMSAs), and how do they mitigate the risk of Kerberoasting?*

## Next Topics
- **Active Directory Delegation**: Unconstrained, Constrained, and Resource-Based Constrained Delegation security risks.
- **Sysmon Logging for Execution**: Setting up Sysmon to monitor command-line arguments and detect offensive tools like Rubeus.
