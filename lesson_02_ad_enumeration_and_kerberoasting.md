# Active Directory Enumeration & Kerberoasting (Targeting Service Accounts)

## What is it?
In an enterprise Active Directory (AD) environment, users and services authenticate using the Kerberos protocol. When a user wants to access a service — say, a SQL database or a web app running under a specific service account — they ask the Domain Controller (specifically the Key Distribution Center, or KDC) for a Ticket Granting Service (TGS) ticket.

Every service that needs this kind of authentication has a Service Principal Name (SPN), which is basically a unique tag linking that service to a specific AD account.

Kerberoasting takes advantage of this. Any authenticated domain user can request a TGS ticket for a service account tied to an SPN — that part is completely normal Kerberos behavior. The catch is that the ticket gets encrypted using the service account's password hash. An attacker grabs that ticket, takes it offline, and tries to crack the password at their leisure with no risk of triggering a lockout.

## Why does it matter in cybersecurity?
This is one of the most common paths to privilege escalation and lateral movement in AD environments, for a few reasons:

1. **You don't need admin rights to try it.** Any domain user — even a low-privileged temp account or a freshly compromised workstation — can query the domain controller and request TGS tickets for every SPN it can see.
2. **It blends in.** Requesting a service ticket is just... what Kerberos does all day. To a basic monitoring setup, this looks like normal traffic.
3. **The payoff can be huge.** Service accounts are notorious for being overprivileged — sometimes even sitting at Domain Admin — because nobody wanted to deal with permissions properly when the service was set up.

## How attackers use it
1. **Enumeration** — query AD via LDAP to pull a list of all registered SPNs, which tells the attacker exactly which accounts are running services.
2. **Request the ticket** — ask the DC for a TGS ticket tied to a target SPN. The DC hands it over, because that's just how Kerberos works.
3. **Extract it** — pull the ticket out of memory using something like Mimikatz or Rubeus.
4. **Crack it offline** — move the ticket to an attack machine and throw hashcat or John the Ripper at it with a wordlist (RockYou is the classic). If the service account's password is weak, it can fall in minutes.

## How defenders detect it
Ticket requests happen constantly in a healthy AD environment, so the trick is spotting what's *abnormal* about them:

**Event ID 4769** ("A Kerberos service ticket was requested") is where you'll live for this.
- Check the encryption type. RC4 (0x17) is the one to watch for — it's much faster to crack, so attackers request it deliberately even when AES is available. A healthy environment should mostly be using AES128 (0x11) or AES256 (0x12).
- Watch the volume. One user requesting tickets for dozens of service accounts within a few seconds isn't normal behavior — that's a scan, not a person doing their job.

Honeytokens are also worth setting up: create a fake service account (something like `sql-service-backup`) with a juicy-looking SPN but no real access behind it. Since nobody has a legitimate reason to ever request a ticket for it, any 4769 hitting that account is basically a confirmed red flag.

## How to mitigate it
- **Make service account passwords actually strong** — 25+ characters, or better, move to Group Managed Service Accounts (gMSAs), which auto-rotate a 120-character password so nobody has to remember or manage it.
- **Kill RC4** — disable it via Group Policy so Kerberos is forced onto AES-128/256. This alone removes a big chunk of Kerberoasting's appeal.
- **Actually apply least privilege** — service accounts should only have what they need to run the service, not Domain Admin because it was easier at setup time.

## Tools worth knowing
- **Rubeus** — C# toolset for raw Kerberos abuse, common on red teams.
- **Impacket's `GetUserSPNs.py`** — the go-to for running Kerberoasting from a non-Windows box.
- **PowerView** — PowerShell script for AD enumeration generally.
- **Hashcat** — GPU-accelerated cracking, used once the tickets are offline.

## Hands-on Practice: Viewing & Enumerating SPNs
You don't need a full AD lab to poke at this — a couple of built-in Windows tools will get you started.

**Part 1: Check your current Kerberos tickets**

Open Command Prompt or PowerShell and run:
```cmd
klist
```
If you're on a home machine that isn't domain-joined, don't be surprised if this comes back empty or just shows local stuff.

**Part 2: Querying SPNs**

On an actual domain-joined machine, these would let you search for SPNs without tripping AV:
```cmd
setspn -T targetdomain -Q */*
```
Or via the AD PowerShell module:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName
```

## Interview Questions
1. What is an SPN, and how does Kerberoasting take advantage of it?
2. Why is Kerberoasting considered so hard to detect?
3. If you're staring at a pile of Event ID 4769 logs in your SIEM, what fields actually tell you something useful?
4. Why does the encryption type on a TGS ticket matter for how easily it can be cracked?
5. What are gMSAs, and how do they cut down Kerberoasting risk?

## Next Topics
- **AD Delegation** — unconstrained, constrained, and resource-based constrained delegation, and why each carries its own risks.
- **Sysmon for execution logging** — setting it up to catch command-line arguments from tools like Rubeus in action.
