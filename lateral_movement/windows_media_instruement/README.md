# Lateral Movement via WMI (Windows Management Instrumentation)

## Introduction
Windows Management Instrumentation (WMI) is a core Windows framework for managing data and operations. In the context of offensive security, WMI is a premier method for **Lateral Movement** because it is "fileless." 

Unlike the SCM (PsExec) method, it does not necessarily require dropping an `.exe` onto the target’s disk to start. It leverages the operating system's own management framework to execute commands, making it highly stealthy and difficult for traditional AV to detect.

---

## Attack Flow
The following steps outline the lifecycle of a WMI-based lateral movement attack.

### 1. The Pre-Requisite: Administrative Credentials
WMI remote access is restricted to the **Administrators** group.
* **Requirement**: The attacker must possess the password or NTLM hash of a Local Admin on the target.
* **Tools**: `wmic`, PowerShell `Invoke-WmiMethod`, or Impacket's `wmiexec.py`.

### 2. The Connection (RPC/DCOM)
The attacker initiates communication with the remote target.
* **Protocol**: WMI initially communicates over **TCP Port 135 (RPC)**.
* **Negotiation**: The RPC port mapper instructs the attacker's machine to switch to a random **high port** (between 49152 and 65535) for data transfer via DCOM.

### 3. The Instruction (Win32_Process)
The attacker calls the `Win32_Process` class to initiate the payload.
* **Method**: `Create`.
* **Payload**: Instead of a binary, they send a string (e.g., `powershell.exe -e <Base64_Payload>` or `cmd.exe /c ...`).

### 4. Execution & Privilege Escalation
This is the critical phase for detection and impact.
* **The Parent**: The process `WmiPrvSE.exe` (WMI Provider Host) receives the instruction.
* **The Child**: `WmiPrvSE.exe` spawns the attacker's command (e.g., `cmd.exe`).
* **Result**: Because the WMI service is a high-privilege component, the child process inherits **SYSTEM** or **High-Integrity** access immediately.

---

## Atomic Rules for Detection
To defend against WMI lateral movement, monitor for the following "Atomic" indicators:

### Rule 1: Suspicious Parent-Child Relationship
* **Logic**: Monitor for `WmiPrvSE.exe` spawning shells or scripting engines.
* **Condition**: `ParentImage == 'C:\Windows\System32\wbem\WmiPrvSE.exe'`
* **Target Children**: `cmd.exe`, `powershell.exe`, `scrcons.exe`, `pwsh.exe`.

### Rule 2: Remote WMI Network Activity
* **Logic**: Detect inbound RPC traffic (Port 135) followed by a high-port DCOM connection from a workstation (rather than a known management server).
* **Ports**: `TCP 135` and `TCP 49152-65535`.

### Rule 3: Win32_Process.Create Command Lines
* **Logic**: Inspect command-line logs for WMI-based process creation strings.
* **Keywords**: `wmic process call create`, `Invoke-WmiMethod -ClassName Win32_Process`.

### Rule 4: WMI Activity Event Logs
* **Logic**: Monitor the WMI-Activity operational log for remote execution events.
* **Event ID**: `Microsoft-Windows-WMI-Activity` **Event ID 5861** (indicates creation of a process via WMI).

