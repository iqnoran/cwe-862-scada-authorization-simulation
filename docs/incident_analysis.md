# Incident Analysis: 2021 Oldsmar Water Treatment Facility Cyber Incident

## 1. Executive Summary

On February 5, 2021, an unauthorized setpoint modification occurred at the municipal water treatment facility in Oldsmar, Florida. According to the joint cybersecurity advisory issued by CISA, the FBI, the EPA, and the MS-ISAC (Alert AA21-042A, 2021), an operator observed an unauthorized party remotely accessing the plant's Human-Machine Interface (HMI) via remote desktop software (TeamViewer) and increasing the chemical dosing setpoint for Sodium Hydroxide ($\text{NaOH}$, commonly referred to as lye) from approximately **100 parts per million (ppm)** to **11,100 ppm**. The plant operator observed the mouse cursor moving on screen in real time and immediately restored the setpoint to 100 ppm once the unauthorized actor exited the interface.

This incident did not result in contaminated water reaching consumers. The primary reason adverse physical consequences were averted was the immediate human-in-the-loop intervention by the alert operator. Furthermore, as noted in CISA Alert AA21-042A, municipal water treatment systems have significant chemical mixing and retention latency (24 to 36 hours), providing a temporal buffer during which routine water quality sampling and downstream pH monitoring would have indicated an abnormality before treated water entered the public distribution network. However, public advisories and academic analyses (Cervini et al., 2022) emphasize that the facility's SCADA system itself failed to generate an automated alarm upon the setpoint modification. The event exposed critical vulnerabilities in water and wastewater systems (WWS), including insecure remote access, shared passwords without multi-factor authentication, unsupported operating systems, and an absence of independent cyber-physical safety interlocks.

This document provides a research-grounded analysis of the incident based on primary government advisories, academic literature, and investigative records, establishing the theoretical and empirical rationale for the educational simulation implemented in this laboratory project.

---

## 2. Chronology and Sequence of Events

Based on CISA Alert AA21-042A (2021) and investigative summaries released by the FBI, the confirmed high-level sequence of events on February 5, 2021, transpired as follows:

| Approximate Time (EST) | Event Description | Source & Evidentiary Status |
| :--- | :--- | :--- |
| **~08:00** | A plant operator observed a remote mouse cursor moving across an HMI screen. The operator did not find this alarming at the time because supervisory staff periodically accessed the workstation remotely via TeamViewer. | Confirmed Fact (CISA AA21-042A; FBI Final Records) |
| **~13:30** | An operator observed the mouse cursor again taking control of the HMI workstation. The cursor operated for approximately 3 to 5 minutes, navigated the interface, accessed SCADA controls, and manipulated chemical dosing functions. | Confirmed Fact (CISA AA21-042A; FBI Final Records) |
| **~13:35** | The remote actor increased the chemical dosing setpoint for Sodium Hydroxide ($\text{NaOH}$) from approximately 100 ppm to 11,100 ppm. The actor then exited the software and disconnected. | Confirmed Fact (CISA AA21-042A; FBI Final Records) |
| **Immediately after** | The operator observed the elevated setpoint on screen and immediately reverted the setting back to 100 ppm. | Confirmed Fact (CISA AA21-042A; FBI Final Records) |
| **Post-incident** | Plant personnel notified municipal management, disabled TeamViewer remote access capabilities on the workstation, and engaged local law enforcement, the Pinellas County Sheriff's Office, the FBI, and CISA. | Confirmed Fact (CISA AA21-042A; FBI Final Records) |

---

## 3. Reported Setpoint Change vs. Finished Drinking-Water Quality

A critical distinction in cyber-physical systems security is the separation between an **operator-interface setpoint**, the **operator's corrective intervention**, and the **actual physical water-treatment outcome**:

1. **Requested Setpoint Modification**: The 11,100 ppm value was an operational target entered into the SCADA software interface controlling the Sodium Hydroxide ($\text{NaOH}$) dosing process, increased upward from the baseline of approximately 100 ppm. It represented a requested control parameter within the supervisory software rather than a physical chemical concentration measured in the water.
2. **Operator Reversal**: The plant operator visually observed the mouse cursor actively manipulating the software interface in real time and immediately reduced the setpoint back to 100 ppm as soon as the unauthorized actor exited the system (CISA Alert AA21-042A).
3. **Actual Water-Treatment Outcome**: Finished drinking-water quality was unaffected. CISA Alert AA21-042A explicitly affirms: *"At no time did the water treatment facility significantly increase the amount of [$\text{NaOH}$] in the water treated."* Furthermore, municipal mixing and storage residence times would have required **24 to 36 hours** for water treated under an altered setpoint to reach consumers, during which routine water testing and downstream pH monitoring would have indicated an abnormality before water entered distribution.
4. **Secondary Downstream Controls vs. Immediate SCADA Alerting**: While plant staff reported redundant fail-safes and manual sampling checks, primary sources do not establish that automated shutoff valves were configured to autonomously halt operations without human intervention. Crucially, as highlighted by Cervini et al. (2022), the SCADA software itself did not generate an automated alarm upon the setpoint modification, leaving detection entirely dependent on the operator's visual presence at the console.

---

## 4. Cybersecurity Weaknesses and Vulnerabilities

### Confirmed Weaknesses
Primary government advisories (CISA Alert AA21-042A) and FBI investigative records documented several compounding cybersecurity deficiencies:

* **Insecure Remote Access Architecture**: TeamViewer desktop sharing software was installed directly on computers connected to the SCADA system to facilitate remote access for staff and contractors.
* **Shared Authentication Credentials**: All computers used by plant personnel were connected to the SCADA system and shared the same password for remote access (CISA AA21-042A).
* **Absence of Multi-Factor Authentication (MFA)**: Remote access sessions were secured solely by static passwords without secondary authentication factors or token verification.
* **Unsupported Operating Systems**: Workstations interfaced with the SCADA system were running 32-bit versions of Microsoft Windows 7. Microsoft support for Windows 7 ended on January 14, 2020, leaving the operating system without ongoing security patches (CISA AA21-042A).
* **Absence of Software Bounds Checking**: The SCADA/HMI software permitted a user to enter an extreme setpoint (>100 times baseline) without requiring dual-operator authorization, administrative override, or automated parameter validation.

### Preliminary Advisory Statements vs. Final Investigative Findings
It is essential to distinguish initial advisory statements from subsequent forensic findings:

* **Direct Internet Exposure**: CISA Alert AA21-042A noted that computers connected to the SCADA system *"appeared to be connected directly to the Internet without any type of firewall control in place."* While this reflected CISA's initial assessment of poor network boundary defense, subsequent reviews highlighted that the overall municipal environment involved interconnected city networks, making perimeter defense and internal segmentation ambiguous rather than an intentional lack of all routing infrastructure.
* **Attribution and Attack Origin**: Initial public announcements framed the event as an intrusion by an external malicious hacker. However, the FBI's final investigative summary noted that digital forensic examination of the workstation and network logs revealed **no malware installed**, no persistent backdoor artifacts, and **inconclusive evidence to definitively attribute the intrusion to an external advanced persistent threat (APT) or foreign state-sponsored entity**. Due to the pervasive use of shared TeamViewer credentials, lack of detailed connection logging, and employee remote usage, investigators could not rule out external credential stuffing, an authorized user logging in remotely without authorization, or other unauthenticated internal/contractor connections.

---

## 5. Technical Recommendations from Primary Sources

Advisory AA21-042A and related federal guidance issued by CISA, the FBI, the EPA, and the MS-ISAC outline core defense-in-depth measures for Industrial Control Systems (ICS):

1. **Remote Access Hardening**:
   - Enforce Multi-Factor Authentication (MFA) on all remote connections to operational networks.
   - Prohibit direct remote desktop applications (such as unmanaged TeamViewer) on HMI consoles; require dedicated, encrypted Virtual Private Network (VPN) tunnels terminating in a secure Demilitarized Zone (DMZ).
   - Route remote sessions through bastion hosts/jump servers with centralized logging and session recording.
2. **Network Architecture & Segmentation**:
   - Implement the Purdue Enterprise Reference Architecture (PERA), isolating Level 1 (control/actuation) and Level 2 (supervisory HMI) networks from enterprise business networks (Level 4/5) and the public Internet.
3. **Patch and Lifecycle Management**:
   - Decommission or isolate unsupported legacy operating systems (e.g., Windows 7) and maintain regular security patch cycles for control system workstations.
4. **Audit Logging and Anomaly Detection**:
   - Forward SCADA transaction records and operating system security logs to an out-of-band Security Information and Event Management (SIEM) repository.
   - Implement automated alerts for unusual setpoint changes, rapid consecutive parameter modifications, and anomalous session origins.
5. **Independent Cyber-Physical Safety Interlocks (SIS)**:
   - Implement physical, PLC-level, or independent Safety Instrumented System (SIS) logic that validates setpoints against physical plant operating limits before signals are dispatched to chemical dosing pumps.

---

## 6. Findings from Academic Literature: Cervini, Rubin, and Watkins (2022)

In their peer-reviewed study, *Don’t Drink the Cyber: Extrapolating the Possibilities of Oldsmar’s Water Treatment Cyberattack* (Proceedings of the 17th International Conference on Cyber Warfare and Security, ICCWS 2022, Vol. 17, No. 1, pp. 19–25), Cervini, Rubin, and Watkins analyze the systemic vulnerabilities of municipal water treatment facilities.

### Historical Incident vs. Systemic Vulnerability
The authors emphasize that the 2021 Oldsmar incident was thwarted due to fortuitous human observation (an operator actively seated in front of the console watching the cursor move) and physical process residence latency, rather than proactive technical security controls. Crucially, the authors note that the plant's SCADA system generated **no automated alarm** when the sodium hydroxide dosing setpoint was elevated to 11,100 ppm.

### Cervini et al.'s Threat Models (Table 2: Comparison of Attacker Model Characteristics)
Rather than defining a generic multi-tiered hierarchy, Cervini et al. explicitly compare the **real-world Oldsmar attacker** against two distinct **theoretical attacker profiles** in the paper's comparative framework (*Table 2: A comparison of attacker model characteristics*, p. 21):

1. **Real-World Oldsmar Attacker**:
   - *Access Vector*: Remote desktop connection (TeamViewer) on a workstation with shared credentials.
   - *Attack Timing*: Executed during regular daytime operating hours (~13:30 EST) while the workstation was staffed.
   - *Attack Method*: Directly and overtly manipulated the SCADA software controls to increase the sodium hydroxide setpoint from 100 ppm to 11,100 ppm.
   - *Telemetry & Persistence*: Did not deploy malware, modify PLC logic, or manipulate sensor feedback, resulting in immediate visual discovery and reversal by the operator.
2. **Theoretical Attacker A (Off-Hours Setpoint Manipulation with Ransomware)**:
   - *Attack Timing*: Shifted to off-peak hours (01:00 AM) to exploit unstaffed workstations and avoid real-time human visual observation.
   - *Attack Method*: Commands a dangerous chemical setpoint increase while simultaneously launching a **ransomware attack** across operator workstations and connected networks.
   - *Strategic Objective*: Disables operator consoles, hinders operational oversight, prevents timely setpoint reversal, and impedes incident remediation.
3. **Theoretical Attacker B (Off-Hours Ladder-Logic Tampering with Telemetry Falsification)**:
   - *Attack Timing*: Shifted to off-peak hours (01:00 AM).
   - *Attack Method*: Focuses on deep persistence and stealth by modifying the **Programmable Logic Controller (PLC) internal ladder logic** and conducting a **Man-in-the-Middle (MITM)** manipulation.
   - *Strategic Objective*: Alters the chemical addition process at the controller level while falsifying the pH reporting telemetry sent to operator dashboards. By presenting deceptive normal readings, this model blinds operators and evades visual or manual inspection until caustic water enters distribution.

### Authors' Proposed Mitigations vs. Our Laboratory Implementation
* **Cervini et al.'s Proposed Technologies**: The authors evaluate low-cost cyber-physical security measures, including cyber-physical anomaly detection (evaluating physical invariant relationships such as flow rates and tank capacities), network security monitoring (e.g., Security Onion), and controller-level logic verification.
* **Laboratory Distinction**: Our educational laboratory does not attempt to reproduce the ransomware payloads of Theoretical Attacker A or the low-level PLC ladder-logic tampering of Theoretical Attacker B. Instead, our simulation addresses the core research question raised by the historical incident: evaluating whether an independent, decoupled safety interlock (implementing illustrative bounds of 80–120 ppm normal range, a 150 ppm hard cutoff, and a 10 ppm single-step delta limit) and an automated anomaly detector can reliably intercept and reject an unauthorized 11,100 ppm setpoint command even when the supervisory SCADA software generates no native alarm.

---

## 7. Source-Evidence Mapping

The following table provides traceability from primary sources to our educational laboratory simulation:

| Claim / Topic | Primary Source | Evidence Type | Relevance to Our Laboratory Implementation |
| :--- | :--- | :--- | :--- |
| **Initial Reference Setpoint (100 ppm)** | CISA AA21-042A (2021); Cervini et al. (2022) | Joint Cybersecurity Advisory; Peer-Reviewed Academic Paper | Baseline setpoint initialized in `src/config.py` (`HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM = 100.0`). |
| **Unauthorized Target Setpoint (11,100 ppm)** | CISA AA21-042A (2021); FBI Final Records; Cervini et al. (2022) | Joint Advisory; Investigative Summary; Academic Case Study | Historical target setpoint evaluated in `src/config.py` and tested in `tests/test_safety_interlocks.py`. |
| **Insecure Remote Access Vector** | CISA AA21-042A (2021); FBI Final Records | Official Incident Advisory & Investigative Findings | Modeled as `SessionType.UNAUTHORIZED_REMOTE` in `src/safety.py`, requiring session verification. |
| **Need for Independent Safety Limits** | Cervini et al. (2022); CISA AA21-042A (2021) | Academic Threat Modeling; Federal Guidance | Implemented as decoupled `SafetyInterlock` in `src/safety.py`, independent of user privileges. |
| **Process Lag / State Preservation** | CISA AA21-042A (2021) | Water Process Engineering Facts | Implemented in `src/process.py`, ensuring rejected commands cause zero modification to physical state. |
| **Audit Logging & Alerting Deficiencies** | CISA AA21-042A (2021); FBI Final Records | Investigative Findings & Recommendations | Implemented in `src/audit.py` with structured ISO-8601 UTC schema, anomaly detection, and query filters. |
| **Native SCADA Alarm Untimeliness** | Cervini et al. (2022); Incident Reporting | Academic Case Study & Historical Fact | Implemented in `src/scada_alarm.py` as independent `NativeScadaAlarmSubsystem` (PV delay and unconfigured SP modes); tested in `tests/test_scada_alarm.py`. |
| **Illustrative Laboratory Bounds** | Laboratory Assumption (Our Design) | Educational Simulation Model | Bounds (80–120 ppm normal, 150 ppm cutoff, 10 ppm delta) are illustrative assumptions, not plant specifications. |

---

## 8. Research Question and Objectives

### Research Question
> **"Can an additional defensive layer detect and prevent unauthorized process-setpoint changes even when the original SCADA system does not generate a timely alarm?"**

### Research Objectives
1. **Simulate Normal Authorized Setpoint Changes**: Validate that routine, authorized operator adjustments within illustrative operational tolerances are committed cleanly without generating false alarms.
2. **Simulate the Historical Reported Incident**: Model the attempted setpoint change from 100.0 ppm to 11,100.0 ppm in an isolated, local-only Python simulation.
3. **Evaluate Layered Defense Mechanisms**: Test independent authorization policies, automated anomaly detection, hard physical safety interlocks, and structured audit logging.
4. **Verify Process-State Preservation**: Assert that unauthorized or out-of-bounds requests are rejected and preserve the active setpoint and physical tank dynamics intact.
5. **Maintain Empirical Integrity**: Document test outcomes accurately without claiming the simulation reproduces proprietary plant hardware or validates real-world chemical engineering parameters.

---

## 9. References

1. **Cybersecurity and Infrastructure Security Agency (CISA), Federal Bureau of Investigation (FBI), Environmental Protection Agency (EPA), and Multi-State Information Sharing and Analysis Center (MS-ISAC)**. (2021, February 11). *Alert (AA21-042A): Compromise of U.S. Water Treatment Facility*. Cybersecurity and Infrastructure Security Agency.  
   Official URL: [https://us-cert.cisa.gov/ncas/alerts/aa21-042a](https://us-cert.cisa.gov/ncas/alerts/aa21-042a)  
   Archival PDF: [https://us-cert.cisa.gov/sites/default/files/publications/AA21-042A_Joint%20Cybersecurity%20Advisory_Compromise%20of%20U.S.%20Water%20Treatment%20Facility.pdf](https://us-cert.cisa.gov/sites/default/files/publications/AA21-042A_Joint%20Cybersecurity%20Advisory_Compromise%20of%20U.S.%20Water%20Treatment%20Facility.pdf)

2. **Cervini, J., Rubin, A., & Watkins, L.** (2022). *Don’t Drink the Cyber: Extrapolating the Possibilities of Oldsmar’s Water Treatment Cyberattack*. In *Proceedings of the 17th International Conference on Cyber Warfare and Security (ICCWS 2022)* (Vol. 17, No. 1, pp. 19–25). Academic Conferences International.  
   DOI: [https://doi.org/10.34190/iccws.17.1.29](https://doi.org/10.34190/iccws.17.1.29)

3. **Federal Bureau of Investigation (FBI)**. (2021). *Attempted Hacking of Oldsmar Water Treatment Plant on February 5, 2021 — Final Investigative Summary*. U.S. Department of Justice (FOIA / Investigative Records).

---

## Research Question for Discussion

**"Can an additional defensive layer detect and prevent unauthorized process-setpoint changes even when the original SCADA system does not generate a timely alarm?"**
