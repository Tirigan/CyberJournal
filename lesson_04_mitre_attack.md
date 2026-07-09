# MITRE ATT&CK: Mapping Threat Intelligence to Detections

## Overview
**MITRE ATT&CK®** (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary behavior, built from real-world observations. Instead of tracking indicators of compromise (file hashes, IPs — things that change constantly), it focuses on **TTPs**: the behaviors and methods attackers actually use.

The hierarchy:
- **Tactic** (the *why*) — e.g. *Credential Access*
- **Technique** (the *how*) — e.g. *OS Credential Dumping*
- **Sub-technique** (the specific *how*) — e.g. *LSASS Memory*
- **Procedure** (the *action*) — e.g. Mimikatz extracting credentials from LSASS via specific API calls

## Why It Matters
- **Structured alerting** — a SIEM alert tagged with a MITRE ID (`T1003`) tells you exactly what phase of an intrusion you're looking at.
- **Gap analysis** — mapping log sources and tooling against the framework shows what's covered and where visibility is blind.
- **Threat intel integration** — intel reports document threat-group TTPs by MITRE ID, so they can be cross-referenced against existing detections immediately.

## Attacker Perspective
Adversaries study the framework too:
1. **Finding blind spots** — if most SOCs have weak visibility into specific *Defense Evasion* or *Resource Development* techniques, campaigns get built around those gaps.
2. **Impairing defenses (T1562)** — with admin access, an early move is often targeting the security tooling itself: disabling Sysmon, modifying AV exclusions, blinding the defenders before the noisy part starts.

## Detection Mapping: Lessons 01–03
Telemetry and concepts from the earlier lessons in this project, mapped to their MITRE Tactic/Technique:

| Lesson | Activity | Tactic | Technique | ID |
|---|---|---|---|---|
| 01 | Failed RDP/WinRM logons | Credential Access | Brute Force | `T1110` |
| 01 | Remote Desktop connection | Lateral Movement | Remote Services: RDP | `T1021.001` |
| 02 | AD SPN query | Discovery | Account Discovery: Domain Account | `T1087.002` |
| 02 | Requesting Kerberos TGS tickets | Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | `T1558.003` |
| 03 | Command-line execution | Execution | Command and Scripting Interpreter: PowerShell | `T1059.001` |
| 03 | Dumping LSASS memory | Credential Access | OS Credential Dumping: LSASS Memory | `T1003.001` |
| 03 | Stopping the Sysmon service | Defense Evasion | Impair Defenses: Disable or Modify Tools | `T1562.001` |

## Tools
- **MITRE ATT&CK Navigator** — web-based matrix visualizer; SOC teams use it to build coverage heatmaps.
- **Atomic Red Team** (Red Canary) — open-source tests mapped to ATT&CK, used to verify detections actually fire.
- **MITRE CAR** — analytics and pseudocode detection rules maintained by MITRE.

## Hands-On Lab: Building a Coverage Heatmap

**1.** Create `cyberjournal_coverage.json`:

```json
{
    "name": "CyberJournal Detection Coverage",
    "versions": { "attack": "14", "navigator": "5.0", "layer": "4.5" },
    "domain": "enterprise-attack",
    "description": "Detection coverage tracked across this project.",
    "filters": { "platforms": ["windows", "linux", "iaas"] },
    "layout": { "layout": "side", "aggregateFunction": "max", "showID": true, "showName": true },
    "techniques": [
        { "techniqueID": "T1110", "color": "#00ff41", "comment": "Lesson 01: Event ID 4625 brute-force detection.", "enabled": true },
        { "techniqueID": "T1021.001", "color": "#00ff41", "comment": "Lesson 01: RDP Logon Type 10 via Event ID 4624.", "enabled": true },
        { "techniqueID": "T1087.002", "color": "#00ff41", "comment": "Lesson 02: AD SPN querying and domain enumeration.", "enabled": true },
        { "techniqueID": "T1558.003", "color": "#00ff41", "comment": "Lesson 02: TGS requests (Event ID 4769), weak RC4 encryption.", "enabled": true },
        { "techniqueID": "T1059.001", "color": "#00ff41", "comment": "Lesson 03: Sysmon Event ID 1 PowerShell argument tracking.", "enabled": true },
        { "techniqueID": "T1003.001", "color": "#00ff41", "comment": "Lesson 03: Sysmon Event ID 10, ProcessAccess targeting lsass.exe.", "enabled": true },
        { "techniqueID": "T1562.001", "color": "#00ff41", "comment": "Lesson 03: Sysmon service tampering / stop commands.", "enabled": true }
    ],
    "gradient": { "colors": ["#ff6666", "#ffe266", "#8ec89a"], "minValue": 0, "maxValue": 100 },
    "legendItems": [ { "label": "Covered in this project", "color": "#00ff41" } ]
}
```

**2.** Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → **Open Existing Layer** → **Upload from local** → select the file.

The Enterprise matrix renders with the seven techniques above highlighted, notes visible on hover. Update the file as new lessons are added to keep the coverage map current.

## Interview Prep
1. Difference between a Tactic and a Technique?
2. Why is "100% MITRE ATT&CK coverage" a misleading claim?
3. How does a SOC use MITRE ATT&CK to prioritize logging and engineering budget?
4. Under which Tactic would an attacker enumerating domain controllers fall, and what's a technique ID for it?
5. How does Atomic Red Team integrate with ATT&CK to validate detections?

## Next
- Windows lateral movement detection — Pass-the-Hash, Pass-the-Ticket, PsExec, and what they look like in the logs
- Python for security analysts — automating log parsing and MITRE ID tagging
