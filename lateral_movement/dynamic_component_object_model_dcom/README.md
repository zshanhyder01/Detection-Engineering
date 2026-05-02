# Lateral Movement via DCOM: Analysis and Detection

This repository contains a comprehensive breakdown, attack flow, and detection logic for **Lateral Movement via Distributed Component Object Model (DCOM)**. It is designed for SOC Analysts and Detection Engineers to understand and defend against this common "Living off the Land" technique.

---

## 1. Introduction

### What is COM?
The **Component Object Model (COM)** is a binary-interface standard for inter-process communication (IPC). It allows software components to talk to each other regardless of programming language. Locally, COM enables applications like Word or Excel to share functionality.

### What is DCOM?
**Distributed COM (DCOM)** extends this across a network using **RPC (Remote Procedure Call)**. It allows a client on Machine A to request the activation of a COM object on Machine B. While designed for remote administration, it is a primary vector for lateral movement.

---

## 2. How Lateral Movement Occurs
Lateral movement via DCOM occurs when an attacker, possessing valid administrative credentials (stolen via LSASS dumping, Kerberoasting, etc.), remotely instantiates a COM object on a target machine to execute arbitrary code.

**Why attackers use DCOM:**
*   **Living off the Land:** Uses legitimate processes (`mmc.exe`, `excel.exe`), bypassing many signature-based detections.
*   **Fileless Nature:** Commands are executed through object methods, often leaving no malicious files on disk.
*   **Trust:** Execution occurs under the context of the administrative user provided during the RPC handshake.

---

## 3. Attack Flow
A typical DCOM lateral movement attack follows this sequence:

1.  **Credential Acquisition:** Attacker harvests Admin NTLM hashes or Kerberos tickets.
2.  **Remote Handshake:** Attacker connects to the target's **RPC Endpoint Mapper (Port 135)**.
3.  **Authentication:** Target’s Service Control Manager (SCM) validates the admin credentials.
4.  **Host Activation:** SCM starts the host process (e.g., `mmc.exe`) with the `-Embedding` flag.
5.  **Method Invocation:** Attacker calls a method (e.g., `ExecuteShellCommand`) within the object.
6.  **Payload Execution:** The host process spawns a child shell (`cmd.exe` or `powershell.exe`).

---

## 4. Detection Strategy
Detection relies on correlating three distinct atomic events within a short timeframe (usually <60s).

### Atomic Rules
| ID | Rule Name | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- |
| **[AR-01](#ar-01-remote-network-logon)** | **Remote Network Logon** | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Detects the initial Type 3 logon. |
| **[AR-02](#ar-02-dcom-service-activation)** | **DCOM Service Activation** | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Detects the spawning of the COM server. |
| **[AR-03](#ar-03-com-object-shell-execution)** | **COM Shell Execution** | [T1059](https://attack.mitre.org/techniques/T1059/) | Detects the final payload execution. |

---

### <a name="ar-01"></a>AR-01: Remote Network Logon
*   **Logic:** Event ID **4624** + **Logon Type 3**.
*   **Purpose:** Confirms a remote connection was established before the process activity started.

### <a name="ar-02"></a>AR-02: DCOM Service Activation
*   **Logic:** `ParentImage == svchost.exe` spawning `Image == mmc.exe` (or `excel.exe`).
*   **Key Indicator:** Command line must contain `-Embedding` and Parent Command Line contains `DcomLaunch`.

### <a name="ar-03"></a>AR-03: COM Object Shell Execution
*   **Logic:** `ParentImage == mmc.exe` spawning `Image == cmd.exe` or `powershell.exe`.
*   **Purpose:** This is the high-fidelity alert. Legitimate DCOM host apps rarely spawn shells.

---

## 5. Mitigation & Prevention
*   **Network Segmentation:** Block inbound TCP Port 135 from workstation-to-workstation traffic.
*   **Restrict DCOM Permissions:** Use `dcomcnfg.exe` to remove "Remote Activation" rights for non-admin groups.
*   **Credential Hardening:** Deploy **LAPS** to prevent the use of the same local admin credentials across multiple machines.
