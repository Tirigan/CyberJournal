# ⚡ CyberJournal

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██╗ ██████╗ ██╗   ██╗██████╗ ███╗   ██╗ █████╗ ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ██║██╔═══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗██║
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     ██║██║   ██║██║   ██║██████╔╝██╔██╗ ██║███████║██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██   ██║██║   ██║██║   ██║██╔══██╗██║╚██╗██║██╔══██║██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚█████╔╝╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████╗
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
```

> *"The quieter you become, the more you are able to hear."* — Kali Linux motto

---

## 🔍 What is This?

A cybersecurity learning journal, written while transitioning from IT support into a security operations role.

Each entry works through one topic end-to-end — what it is, how attackers use it, how defenders catch it — with logs, commands, and detection logic included rather than just theory.

---

## 🎯 Target Roles

```
SOC Analyst
Security Operations Specialist
Cybersecurity Analyst
Vulnerability Management Analyst
Junior Security Engineer
```

---

## 📁 Repository Structure

```
CyberJournal/
├── lesson_01_windows_event_logs.md                # Auth events, 4624/4625, logon types
├── lesson_02_ad_enumeration_and_kerberoasting.md   # Kerberos, SPNs, TGS ticket attacks
├── lesson_03_sysmon_threat_detection.md            # Sysmon process, network & DLL loading
├── lesson_04_mitre_attack.md                       # MITRE ATT&CK mapping & coverage heatmap
└── README.md                                       # You are here
```

---

## 🧠 Learning Path

```
[MSP / IT Helpdesk]
        │
        ▼
[Windows & Active Directory Security]
        │
        ▼
[Blue Team Fundamentals / SOC Skills]
        │
        ▼
[SIEM · Detection Engineering · MITRE ATT&CK]
        │
        ▼
[Incident Response & Threat Hunting]
        │
        ▼
[Security Operations Role]
```

---

## 📚 Lesson Index

| # | Topic | Focus Area |
|---|-------|------------|
| 01 | [Windows Event Logs: 4624 & 4625](./lesson_01_windows_event_logs.md) | Authentication · Brute Force Detection |
| 02 | [AD Enumeration & Kerberoasting](./lesson_02_ad_enumeration_and_kerberoasting.md) | Active Directory · Privilege Escalation |
| 03 | [Sysmon: Extending Windows Logging](./lesson_03_sysmon_threat_detection.md) | Detection Engineering · Threat Hunting |
| 04 | [MITRE ATT&CK: Detection Mapping](./lesson_04_mitre_attack.md) | Threat Intelligence · Coverage Mapping |
| 05+ | In progress | Lateral movement, SIEM fundamentals, security automation |

---

## 🛠️ Tools Covered

`Event Viewer` · `PowerShell` · `Get-WinEvent` · `Sysmon` · `Splunk` · `Wireshark` · `Hashcat` · `Impacket` · `BloodHound` · `MITRE ATT&CK Navigator` · `Rubeus`

---

## 🧰 Related Projects

Two small tools, built from scratch while working through offensive/defensive fundamentals:

- **[Recon-Assistant](https://github.com/Tirigan/Recon-Assistant)** — multi-threaded Python recon toolkit (port scanning, subdomain brute-forcing, HTTP header grabbing, directory brute-forcing), with a shared rate limiter and JSON/text reporting.
- **[HashAdder](https://github.com/Tirigan/HashAdder)** — command-line file-hashing utility (MD5/SHA-1/SHA-256/SHA-512) with a comparison mode for verifying downloads or checking known hashes.

---

## 📅 Pace

This journal is self-paced rather than scheduled — entries get added as topics are worked through and labbed out, not on a fixed weekly drop.

---

## ⚠️ Disclaimer

> This journal is for **defensive security education** only.
> All techniques documented here are studied from a **Blue Team / Defender perspective**.
> Nothing in this repository should be used for unauthorized access to systems.

---

*Built with curiosity. Committed with purpose.*
