# Lateral Movement via DCOM: Analysis and Detection

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
### <a name="remote-network-logon"></a>[Remote Network Logon](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_remote_logon_t1021.003)
*   **Event ID:** 4624
*   **Logon Type:** 3 (Network)
*   **Purpose:** Establishes that the activity originated from a remote network source.
*   **Context:** This represents the initial authentication required to interact with DCOM objects remotely.

### <a name="dcom-service-activation"></a>[DCOM Service Activation](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/dcom_activation_svchost_t1021.003)
*   **Logic:** `ParentImage` is `svchost.exe` (DcomLaunch) and `Image` is a known DCOM host (`mmc.exe`, `excel.exe`, etc.).
*   **Indicator:** The command line contains the `-Embedding` flag, signifying it was started as a COM server.
*   **Context:** This confirms the system service is handing off execution to the requested application.

### <a name="com-shell-execution"></a>[COM Shell Execution](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_com_shell_payload_t1059)
*   **Logic:** `ParentImage` is a DCOM host and `Image` is a shell (`cmd.exe`, `powershell.exe`).
*   **Significance:** High-fidelity alert. Under normal conditions, MMC or Excel should not spawn command-line interpreters.
*   **Context:** This is the execution phase where the attacker gains a remote shell.
---

## 5. Mitigation & Prevention
*   **Network Segmentation:** Block inbound TCP Port 135 from workstation-to-workstation traffic.
*   **Restrict DCOM Permissions:** Use `dcomcnfg.exe` to remove "Remote Activation" rights for non-admin groups.
*   **Credential Hardening:** Deploy **LAPS** to prevent the use of the same local admin credentials across multiple machines.
