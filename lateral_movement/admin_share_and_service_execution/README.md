# Lateral Movement: SMB Admin Shares & Service Control Manager (SCM)

This repository provides an overview and detection strategy for lateral movement via SMB and the Service Control Manager. This technique is a staple of post-exploitation, allowing attackers to pivot through a network with high privileges.

---

## Lateral Movement via SMB / Admin Share and Service Control Manager 

This technique involves leveraging administrative credentials to interact with a remote host's file system and service architecture. It is the underlying mechanism for many popular movement tools because it utilizes built-in Windows functionality (SMB for file transfer and RPC for service management), making it difficult to block without impacting legitimate administration.

---

## Attack Flow 

This is the most common method (used by tools like **PsExec** or **Impacket’s psexec.py**).

1.  **The Drop:** The attacker copies `malicious.exe` to `\\Target-PC\ADMIN$\`.
2.  **The Instruction:** The attacker connects to the target's **Service Control Manager** (via RPC over port 445).
3.  **The Creation:** They create a new service (e.g., named "Updates") and set the "Binary Path" to point directly to the file they just dropped: `C:\Windows\malicious.exe`.
4.  **The Trigger:** They send a "Start" command to that service.
5.  **The Result:** The Windows OS itself executes the binary. Because services run as **NT AUTHORITY\SYSTEM** by default, the attacker has not only moved laterally but also achieved **instant Privilege Escalation** on the target.

---

## Atomic Rules Used

To detect this specific chain of events, monitor for the following telemetry:

* **Detect File Drop (T1021.002):** Monitor for new executable files (`.exe`, `.dll`) being written to administrative shares like `ADMIN$` or `C$`.
* **Detect Service Creation (T1543.003):** Log and alert on the creation of new Windows Services (Security Event ID 4697 or System Event ID 7045), especially those with suspicious binary paths.
* **Detect Process Spawn from Services.exe (T1569.002):** Identify non-standard processes where the parent process is `services.exe`.
* **Detect File Deletion (T1070.004):** Track the deletion of the original binary immediately following the service stop/completion, a common cleanup tactic.
