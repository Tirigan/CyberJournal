# MITRE ATT&CK Framework: Mapping Threat Intelligence to Practical Detections

## What is it?
In cybersecurity operations, we need a common language to describe how adversaries behave. The **MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge)** framework is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. 

Rather than focusing on indicators of compromise (IOCs) like file hashes or IP addresses (which change constantly), MITRE ATT&CK focuses on **TTPs (Tactics, Techniques, and Procedures)**—the behaviors and methods attackers use.

To understand the framework, it is helpful to break down its hierarchy:
*   **Tactics (The "Why")**: The adversary's immediate goal. (e.g., *Credential Access*—trying to steal usernames and passwords).
*   **Techniques (The "How")**: The method used to achieve a tactic. (e.g., *OS Credential Dumping*).
*   **Sub-techniques (The "Specific How")**: A more granular description of the technique. (e.g., *LSASS Memory* dumping).
*   **Procedures (The "Action")**: The specific implementation of the technique by an actor or software. (e.g., *Mimikatz extracting credentials from LSASS memory using specific API calls*).

---

## Why does it matter in cybersecurity?
For a SOC Analyst or Detection Engineer, MITRE ATT&CK is the ultimate blueprint for defensive posture. 
*   **Structured Alerting**: Triaging alerts in a SIEM is much easier when they are tagged with a MITRE ID (e.g., `T1003`). It tells you exactly what phase of the intrusion you are looking at.
*   **Gap Analysis**: By mapping your organization’s log sources and security tools to the framework, you can visualize what attack techniques you can detect (coverage) and where you are completely blind.
*   **Threat Intel Integration**: When a threat intelligence report describes a new threat group targeting your industry, they will document the group's TTPs using MITRE IDs. You can immediately cross-reference this with your existing detections to see if you are protected.

---

## How attackers use it
Adversaries don't just ignore the framework—they study it:
1.  **Finding Defensive Blind Spots**: Attackers look at standard enterprise detection baselines. If they know most SOCs have low visibility into *Resource Development* or specific *Defense Evasion* techniques, they will build their campaigns around those gaps.
2.  **Impairing Defenses (T1562)**: When an attacker gains administrative privileges on a workstation, their first move is often to target the security tools themselves—such as attempts to disable Sysmon (`sc stop sysmon`) or modify AV exclusions to blind the defenders.

---

## Mapping Our CyberJournal Detections
To see how threat modeling works, let's map the defensive telemetry and concepts we studied in **Lessons 1, 2, and 3** to their official MITRE ATT&CK Tactics and Techniques:

| Lesson | Threat / Activity | MITRE Tactic | MITRE Technique | MITRE ID |
|---|---|---|---|---|
| **Lesson 01** | Failed RDP/WinRM Logons | **Credential Access** | Brute Force | `T1110` |
| **Lesson 01** | Remote Desktop Connection | **Lateral Movement** | Remote Services: Remote Desktop Protocol | `T1021.001` |
| **Lesson 02** | Active Directory SPN Query | **Discovery** | Account Discovery: Domain Account | `T1087.002` |
| **Lesson 02** | Requesting Kerberos TGS Tickets | **Credential Access** | Steal or Forge Kerberos Tickets: Kerberoasting | `T1558.003` |
| **Lesson 03** | Command-Line Execution | **Execution** | Command and Scripting Interpreter: PowerShell | `T1059.001` |
| **Lesson 03** | Dumping LSASS memory | **Credential Access** | OS Credential Dumping: LSASS Memory | `T1003.001` |
| **Lesson 03** | Stopping the Sysmon Service | **Defense Evasion** | Impair Defenses: Disable or Modify Tools | `T1562.001` |

---

## Tools to learn
*   **MITRE ATT&CK Navigator**: A web-based tool to visualize, customize, and color-code the ATT&CK matrix. SOC teams use it to create heatmaps representing their detection coverage.
*   **Atomic Red Team (by Red Canary)**: A library of simple, open-source tests mapped to the MITRE ATT&CK framework. Defenders run these "atomic" tests to verify if their SIEM alerts actually fire.
*   **MITRE CAR (Cyber Analytics Repository)**: A knowledge base of analytics and pseudocode detection rules maintained by MITRE to detect specific techniques.

---

## Hands-on Practice: Building Your Coverage Heatmap
In this lab, you will create a custom **MITRE ATT&CK Navigator Layer** using JSON to visualize the detection coverage you have documented in your `CyberJournal` so far.

### Step 1: Create your Navigator Layer JSON
1. Create a file named `cyberjournal_coverage.json` in your local environment.
2. Paste the following JSON configuration into the file. This file configures the Navigator to highlight the specific techniques you've studied in Lessons 1 to 3:

```json
{
    "name": "CyberJournal Detection Coverage",
    "versions": {
        "attack": "14",
        "navigator": "5.0",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Visualizing detection coverage built throughout the CyberJournal portfolio.",
    "filters": {
        "platforms": ["windows", "linux", "iaas"]
    },
    "layout": {
        "layout": "side",
        "aggregateFunction": "max",
        "showID": true,
        "showName": true
    },
    "techniques": [
        {
            "techniqueID": "T1110",
            "color": "#00ff41",
            "comment": "Covered in Lesson 01: Audit Event ID 4625 for remote authentication brute force.",
            "enabled": true
        },
        {
            "techniqueID": "T1021.001",
            "color": "#00ff41",
            "comment": "Covered in Lesson 01: RDP Logon Type 10 detection using Event ID 4624.",
            "enabled": true
        },
        {
            "techniqueID": "T1087.002",
            "color": "#00ff41",
            "comment": "Covered in Lesson 02: AD SPN querying and domain user enumeration.",
            "enabled": true
        },
        {
            "techniqueID": "T1558.003",
            "color": "#00ff41",
            "comment": "Covered in Lesson 02: TGS ticket requests (Event ID 4769) with weak RC4 encryption.",
            "enabled": true
        },
        {
            "techniqueID": "T1059.001",
            "color": "#00ff41",
            "comment": "Covered in Lesson 03: Sysmon Event ID 1 process creation tracking for PowerShell arguments.",
            "enabled": true
        },
        {
            "techniqueID": "T1003.001",
            "color": "#00ff41",
            "comment": "Covered in Lesson 03: Sysmon Event ID 10 tracking ProcessAccess targeting lsass.exe.",
            "enabled": true
        },
        {
            "techniqueID": "T1562.001",
            "color": "#00ff41",
            "comment": "Covered in Lesson 03: Monitoring Sysmon service tampering and stop commands.",
            "enabled": true
        }
    ],
    "gradient": {
        "colors": ["#ff6666", "#ffe266", "#8ec89a"],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {
            "label": "Techniques Covered in CyberJournal",
            "color": "#00ff41"
        }
    ]
}
```

### Step 2: Upload to MITRE ATT&CK Navigator
1. Open your browser and navigate to the official [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Click **Open Existing Layer** -> **Upload from local**.
3. Choose the `cyberjournal_coverage.json` file you created.
4. You will see a fully interactive matrix of the Enterprise ATT&CK framework, with the 7 techniques you've analyzed highlighted in **green** with your custom notes visible when hovering over them.

*As you continue adding lessons to this journal, you can update this JSON file to build a visual indicator of your technical detection skills—a highly impressive asset to show recruiters.*

---

## Interview Questions
1.  *What is the difference between a Tactic and a Technique in the MITRE ATT&CK framework?*
2.  *If an organization claims they have "100% MITRE ATT&CK coverage", why is this statement misleading or practically impossible?*
3.  *How can a SOC use MITRE ATT&CK to prioritize security engineering and logging budgets?*
4.  *Under which Tactic would you classify an attacker running commands to discover domain controllers, and what is a specific technique ID associated with it?*
5.  *How does the Atomic Red Team framework integrate with the MITRE ATT&CK matrix to validate detection rules?*

---

## Next Topics
*   **Windows Lateral Movement Detection**: Pass-the-Hash, Pass-the-Ticket, and PsExec—what lateral movement looks like in logs and how to write alerts.
*   **Python for Security Analysts**: Writing a script to automate the parsing of Windows XML logs and tagging found events with their respective MITRE ATT&CK IDs.
