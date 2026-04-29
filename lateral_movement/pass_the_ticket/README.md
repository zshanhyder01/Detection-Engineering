# Pass-the-Ticket Lateral Movement Chain

## What is lateral movement with pass the ticket technique?

**Pass-the-Ticket (PtT)** is a method of authenticating to a remote system using Kerberos tickets without needing the user's clear-text password or even their NTLM hash. It exploits the Kerberos authentication protocol:

1.  **Identity:** The attacker steals a Kerberos Ticket Granting Ticket (TGT) or Service Ticket from the memory of the `lsass.exe` process.
2.  **Authentication:** The attacker injects this stolen ticket into their own session.
3.  **Access:** Since the ticket is a valid cryptographic blob signed by the Key Distribution Center (KDC), the attacker can present it to other services in the domain to gain access, effectively impersonating the user.

## Attack Flow

The detection rule identifies a specific temporal sequence of events occurring on a single host:

1.  **The Harvest/Injection (Credential Activity):**
    * The attacker dumps LSASS memory to get tickets.
    * OR, the attacker uses a tool (like Rubeus) to inject a ticket via command line.
    * OR, a suspicious "NewCredentials" logon (Type 9) is created to facilitate the use of different credentials.
2.  **The Lateral Leap (Movement):**
    * Within **15 minutes** of the credential activity, the same source host initiates a connection to a remote **Administrative Share (C$, ADMIN$)**.

## Atomic Rules Used

The correlation rule relies on the following atomic detection rules to identify the components of the chain:

### Phase 1: Credential Activity
* [`detect_lsass_access_t1003.001`](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_lsass_access_t1003.001): Detects dumping of LSASS memory (Credential Dumping).
* [`detect_pass_the_ticket_command_line_t1550.003`](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_pass_the_ticket_command_line_t1550.003): Identifies command-line patterns for Rubeus, Mimikatz, and other PtT tools.
* [`detect_suspicious_NewCredentials_Logon_t1550.003`](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_suspicious_NewCredentials_Logon_t1550.003): Identifies Logon Type 9, often used by attackers to use injected tickets without affecting their current session.
* [`detect_sacrificial_process_ticket_injection_T1550.003`](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_sacrificial_process_ticket_injection_T1550.003): Detects the creation of processes used as containers for stolen tickets.

### Phase 2: Lateral Movement
* [`detect_admin_share_access_t1021.002`](https://github.com/zshanhyder01/Detection-Engineering/tree/main/atomic_rules/windows/detect_admin_share_access_t1021.002): Detects successful or attempted access to hidden network shares (Remote Services/SMB).
