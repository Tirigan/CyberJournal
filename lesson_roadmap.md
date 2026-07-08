# CyberJournal Lesson Roadmap

This document serves as the guide and model context for upcoming lessons. Every lesson must follow the established structure: What it is, Why it matters, How attackers use it, How defenders detect/mitigate it, Tools to learn, Hands-on practice, and Interview questions.

---

## 📅 Lesson 05: Windows Lateral Movement Detection
**Scheduled Release**: Wednesday, July 15, 2026

### Focus
Detecting how adversaries move from one compromised workstation to other systems (servers or workstations) within the Active Directory domain.

### Concepts to Cover
*   **Pass-the-Hash (PtH)**: Executing commands as a domain user using their NTLM hash without knowing the plaintext password.
*   **Pass-the-Ticket (PtT)**: Stealing Kerberos Ticket Granting Tickets (TGTs) from LSASS memory to authenticate to other domain resources.
*   **PsExec / SMB Execution**: How tools like PsExec or Impacket's `psexec.py` run commands remotely by creating services on the destination system.

### Defender Telemetry & Detections
*   **Event ID 4624 (Logon Type 3)** using NTLM (especially checking for Key Length = 0 or specific NTLM authentication parameters which can point to Pass-the-Hash).
*   **Sysmon Event ID 1 & 3** for remote execution tools (e.g., `psexec.exe` spawning cmd.exe, network connections over port 445).
*   **Event ID 7045 (New Service Created)**: Extremely reliable detection for PsExec lateral movement, where a random/suspicious service is registered.

### Hands-on Practice
Query local Sysmon operational logs or security logs to identify a simulated PsExec service installation or a logon type 3 event using PowerShell.

---

## 📅 Lesson 06: Python for Security Analysts (Automated Log Parsing)
**Scheduled Release**: Wednesday, July 22, 2026

### Focus
Using Python scripting to automate defensive operations, parsing XML/JSON log files, and tagging detected malicious events with MITRE ATT&CK IDs.

### Concepts to Cover
*   Handling Evtx/XML formats using Python.
*   Automated string parsing and pattern matching for IoCs.
*   Outputting structured alerts (JSON or CSV).

### Hands-on Practice
Write a Python script that reads a simulated Sysmon/Windows security log file (JSON or XML format), identifies suspicious activities (e.g., LSASS access, encoded PowerShell, brute-force logs), maps them to MITRE ATT&CK IDs (from Lesson 04), and alerts the user.

---

## 📅 Lesson 07: SIEM Fundamentals & Log Ingestion
**Scheduled Release**: Wednesday, July 29, 2026

### Focus
Understanding log ingestion pipelines, building basic correlation searches, and utilizing a SIEM (e.g., Splunk or ELK) in a SOC environment.

### Concepts to Cover
*   Log forwarding (Universal Forwarders, Winlogbeat).
*   Parsing/Index configurations.
*   Writing correlation searches to link Event ID 4625 (Failed Logon) to Event ID 4624 (Successful Logon) from the same IP.
