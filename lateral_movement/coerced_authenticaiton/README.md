# Coerced Authentication

## What is Coerced Authentication?

**Coerced Authentication** occurs when an attacker forces a high-privileged process (usually the **SYSTEM** account) on a remote server to authenticate to an attacker-controlled machine. 

Unlike traditional credential theft, the attacker doesn't "steal" a password. Instead, they "coerce" the server into showing its identity. This identity is typically the **Machine Account (Computer$)**, which holds significant privileges within an Active Directory domain.

---

## How Coerced Authentication Works in Lateral Movement

In modern Windows environments, **Local Account Token Filtering** often prevents local administrators from moving laterally over the network. However, **Domain Identities** (like Machine Accounts) are not subject to these same restrictions.

By coercing a server (like a Domain Controller or File Server) to authenticate, an attacker can:
1. **Bypass Token Filtering:** Use the server's own domain identity to gain access elsewhere.
2. **Relay the Authentication:** Catch the incoming authentication request and "relay" it to a secondary target (e.g., AD Certificate Services or another member server).
3. **Escalate Privileges:** Since the machine account is a trusted domain member, the attacker can perform administrative tasks on the target system as if they were the coerced server itself.

---

## Attack Flow

The process can be visualized as a sequence of "The Whistle," "The Reflex," and "The Pivot":

1.  **Initial Foothold:** The attacker gains a foothold on a workstation within the domain.
2.  **The Whistle (The Trigger):** The attacker uses a tool (e.g., *PetitPotam*, *SpoolSample*, or *ShadowCoerce*) to send a specific RPC or protocol request to a target server.
3.  **The Reflex (The Forced Walk):** The target server’s **SYSTEM** process reacts to the request by attempting to authenticate back to the attacker’s IP address to "verify" or "update" a service (like a printer or file share).
4.  **The Badge Presentation:** Because the server is communicating over the network, it automatically uses its **Machine Account Credentials (`ComputerName$`)**.
5.  **The Pivot (The Relay):** The attacker does not crack the credentials. Instead, they immediately forward (relay) that authentication request to a different target machine.
6.  **Access Granted:** The final target machine sees a valid authentication request from a trusted Domain Computer and grants administrative access.

---

## Detection Engineering Overview

To effectively catch this behavior, we utilize a tiered detection strategy:

*   **[Rule 1 (Atomic):](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_print_spooler_outbound_connection_t1210)** Detects the "Whistle" by monitoring for unusual outbound network connections from the Print Spooler (`spoolsv.exe`) or LSASS.
*   **[Rule 2 (Atomic):](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_Network_Logon_via_Machine_Account_t1078.002)** Detects the "Badge Presentation" by monitoring for successful `Logon Type 3` events using a Machine Account (`$`).
*   **[Rule 3 (Correlation):](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/coerced_authenticaiton)** Links Rule 1 and Rule 2 together using a stateful sequence to confirm the full attack flow with high confidence.
