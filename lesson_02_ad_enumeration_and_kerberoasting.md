# Active Directory Enumeration & Kerberoasting

## Overview
In Active Directory, users and services authenticate via Kerberos. When a user needs to access a service — a SQL database, an internal web app — they request a Ticket Granting Service (TGS) ticket from the Domain Controller (specifically the KDC).

Every service that supports this has a Service Principal Name (SPN), a tag linking the service to a specific AD account.

**Kerberoasting** abuses normal Kerberos behavior: any authenticated domain user can request a TGS ticket for any SPN. That part is by design. The problem is that the ticket is encrypted with the *service account's password hash* — so an attacker can grab it, take it offline, and crack it at leisure with zero risk of triggering an account lockout.

## Why It Matters
- **No admin rights required.** Any domain user — including a freshly compromised low-privilege account — can enumerate SPNs and request tickets.
- **It blends in.** Requesting a service ticket is routine Kerberos traffic. Basic monitoring won't flag it.
- **High payoff.** Service accounts are frequently over-privileged (sometimes sitting at Domain Admin), because nobody wanted to scope permissions properly at setup.

## Attacker Perspective
1. **Enumerate** — query AD via LDAP for registered SPNs to identify service accounts.
2. **Request** — ask the DC for a TGS ticket tied to a target SPN. Standard Kerberos behavior; the DC complies.
3. **Extract** — pull the ticket from memory (Mimikatz, Rubeus).
4. **Crack offline** — run hashcat or John the Ripper against the ticket with a wordlist. A weak service account password can fall in minutes.

## Detection
**Event ID 4769** ("A Kerberos service ticket was requested") is the primary signal:

- **Encryption type**: RC4 (`0x17`) is the flag to watch for — it's far faster to crack than AES, and attackers request it deliberately even when AES is available. A healthy environment runs mostly AES128 (`0x11`) / AES256 (`0x12`).
- **Volume**: one account requesting tickets for dozens of SPNs in seconds is a scan, not a user doing their job.

**Honeytokens**: create a decoy service account (e.g. `sql-service-backup`) with a convincing SPN and no real access behind it. Since no legitimate process would ever request a ticket for it, any 4769 against that account is close to a confirmed indicator.

## Mitigation
- **Strong service account passwords** — 25+ characters, or move to Group Managed Service Accounts (gMSAs), which auto-rotate a 120-character password.
- **Disable RC4** via Group Policy, forcing Kerberos onto AES-128/256.
- **Least privilege** — service accounts should have only what the service needs, not Domain Admin because it was easier at setup time.

## Tools
- **Rubeus** — Kerberos abuse toolkit (C#)
- **Impacket's `GetUserSPNs.py`** — Kerberoasting from non-Windows hosts
- **PowerView** — general-purpose AD enumeration
- **Hashcat** — GPU-accelerated offline cracking

## Hands-On Lab

**Check current Kerberos tickets:**
```cmd
klist
```
On a non-domain-joined machine, this may come back empty or show only local tickets.

**Query SPNs on a domain-joined machine:**
```cmd
setspn -T targetdomain -Q */*
```
or via the AD PowerShell module:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName
```

## Interview Prep
1. What is an SPN, and how does Kerberoasting take advantage of it?
2. Why is Kerberoasting considered hard to detect?
3. Looking at a batch of Event ID 4769 logs — which fields actually matter?
4. Why does the encryption type on a TGS ticket affect how easily it's cracked?
5. What are gMSAs, and how do they reduce Kerberoasting risk?

## Next
- AD delegation (unconstrained, constrained, resource-based constrained) and the risk profile of each
- Sysmon for execution logging — catching command-line arguments from tools like Rubeus in action
