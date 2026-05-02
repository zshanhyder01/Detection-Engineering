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

### <a name="remote-network-logon"></a>Remote Network Logon
*   **Event ID:** 4624
*   **Logon Type:** 3 (Network)
*   **Purpose:** Establishes that the activity originated from a remote network source.

### <a name="dcom-service-activation"></a>DCOM Service Activation
*   **Logic:** `ParentImage` is `svchost.exe` (DcomLaunch) and `Image` is a known DCOM host (`mmc.exe`, `excel.exe`, etc.).
*   **Indicator:** The command line contains the `-Embedding` flag, signifying it was started as a COM server.

### <a name="com-shell-execution"></a>COM Shell Execution
*   **Logic:** `ParentImage` is a DCOM host and `Image` is a shell (`cmd.exe`, `powershell.exe`).
*   **Significance:** High-fidelity alert. Under normal conditions, MMC or Excel should not spawn command-line interpreters.

---

### <a name="ar-01"></a>Remote Network Logon
*   **Logic:** Event ID **4624** + **Logon Type 3**.
*   **Purpose:** Confirms a remote connection was established before the process activity started.

### <a name="ar-02"></a>DCOM Service Activation
*   **Logic:** `ParentImage == svchost.exe` spawning `Image == mmc.exe` (or `excel.exe`).
*   **Key Indicator:** Command line must contain `-Embedding` and Parent Command Line contains `DcomLaunch`.

### <a name="ar-03"></a>COM Object Shell Execution
*   **Logic:** `ParentImage == mmc.exe` spawning `Image == cmd.exe` or `powershell.exe`.
*   **Purpose:** This is the high-fidelity alert. Legitimate DCOM host apps rarely spawn shells.

---

## 5. Mitigation & Prevention
*   **Network Segmentation:** Block inbound TCP Port 135 from workstation-to-workstation traffic.
*   **Restrict DCOM Permissions:** Use `dcomcnfg.exe` to remove "Remote Activation" rights for non-admin groups.
*   **Credential Hardening:** Deploy **LAPS** to prevent the use of the same local admin credentials across multiple machines.
