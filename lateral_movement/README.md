
## Lateral Movement

### What is Lateral Movement?

Lateral movement refers to the techniques attackers use to move through a network after gaining initial access. Instead of staying on a single compromised host, the attacker attempts to access additional systems, escalate privileges, and expand control within the environment.

This phase is critical in an attack lifecycle because it allows adversaries to:

- Access sensitive systems and data  
- Establish persistence across multiple hosts  
- Reach high-value targets such as domain controllers or databases  

---

### Reference

For a detailed understanding of lateral movement techniques and adversary behavior, refer to the MITRE ATT&CK framework:

- MITRE ATT&CK – Lateral Movement: https://attack.mitre.org/tactics/TA0008/

---

### Techniques Covered in This Repository

The following lateral movement techniques are covered in this section:
1. [SMB Admin Shares & Service Control Manager (SCM)](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/admin_share_and_service_execution)
2. [Coerced Authentication & NTLM Relay Detection](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/coerced_authenticaiton)
3. [Lateral Movement via DCOM](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/dynamic_component_object_model_dcom)
4. [Pass-the-Ticket](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/pass_the_ticket)
5. [Remote Desktop Protocol](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/pass_the_ticket)
6. [Windows Management Instrumentation](https://github.com/zshanhyder01/Detection-Engineering/tree/main/lateral_movement/windows_media_instruement)

---

### Detection Approach

Each technique includes:

- **Correlation Rules**  
  Detection logic combining multiple events to identify attacker behavior  

- **Multiple Approaches**  
  Different detection strategies for the same technique to improve coverage and reduce false positives  

- **Implementation (EQL)**  
  Ready-to-use queries for deployment in SIEM platforms  

---

### Notes

- Lateral movement detection relies heavily on **event correlation**, not single-event alerts  
- Proper **log collection and normalization** (e.g., authentication logs, file share access, service creation events) is essential  
- False positives may occur due to legitimate administrative activity and should be tuned accordingly  
