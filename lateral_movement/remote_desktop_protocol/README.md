## Technique: RDP Lateral Movement Lifecycle

### Brief Description
This detection strategy focuses on the end-to-end lifecycle of lateral movement via Remote Desktop Protocol (RDP). It tracks an attacker from the initial **Credential Acquisition** phase (dumping LSASS memory) through the **Lateral Movement** hop (via standard or Restricted Admin RDP) to the final **Privilege Escalation** (UAC Bypass) on the target host. By correlating these three distinct stages, we reduce false positives and identify high-confidence malicious activity.

---

### Attack Flow
The sequence of events follows a logical progression commonly seen in advanced persistent threats (APT) and ransomware deployments:

1.  **Credential Acquisition (Machine A):**
    * **Action:** Attacker gains local access and attempts to dump the memory of the `lsass.exe` process.
    * **Result:** Extraction of NTLM hashes or plaintext passwords (if WDigest is enabled) of users with remote access rights.

2.  **Lateral Movement (Machine B):**
    * **Action:** Attacker uses stolen credentials to initiate a connection to a remote target.
    * **Method:** Standard Interactive RDP or **Restricted Admin Mode** (Pass-the-Hash for RDP).
    * **Logon Type:** Windows Event ID 4624, Logon Type 10.

3.  **Privilege Escalation (Machine B):**
    * **Action:** Upon landing, the attacker is limited by User Account Control (UAC). They execute an auto-elevating binary (e.g., `fodhelper.exe`).
    * **Goal:** Achieve "High Integrity" or `SYSTEM` context to gain full control of the target machine.

---

### Atomic Rules Used

| Phase | Detection Target | Event ID / Provider | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **Credential Access** | LSASS Memory Access | **Sysmon 10** (Process Access) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Lateral Movement** | RDP Success | **Security 4624** (Logon Type 10) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| **Privilege Escalation**| UAC Bypass Execution | **Sysmon 1 / Security 4688** | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) |

#### 1. LSASS Access (Atomic)
Detects specific access masks (`0x1fffff`, `0x1410`) against the LSASS process, indicating a memory dump attempt for credential harvesting.

#### 2. RDP Connection (Atomic)
Monitors for successful Remote Interactive logons. This rule is enhanced to monitor for the `/RestrictedAdmin` flag in process command lines for Pass-the-Hash scenarios.

#### 3. UAC Bypass (Atomic)
Monitors for the execution of Windows binary primitives (e.g., `fodhelper.exe`, `computerdefaults.exe`) that are frequently abused to bypass UAC prompts and gain administrative privileges.
