# One Target, Two Flags — Detection & Response Pack

Community detection, threat-hunting, and incident-response content for the espionage activity
against Pakistani law enforcement (Balochistan Police and others) described by **SentinelLABS**.

**TLP:CLEAR** · Activity window: **February 2024 – April 2026**
Tooling observed: **PlugX · ShadowPad · Cobalt Strike · Remcos (TAG-179) · AsyncRAT**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Disclaimer](#2-disclaimer)
3. [Credit](#3-credit)
4. [License](#4-license)
5. [Indicators of Compromise (IOC)](#5-indicators-of-compromise-ioc)
   - [5.1 IP Addresses (C2)](#51-ip-addresses-c2)
   - [5.2 URL](#52-url)
   - [5.3 Hashes](#53-hashes)
   - [5.4 Host Artifacts](#54-host-artifacts)
6. [YARA Rule](#6-yara-rule)
7. [Sigma Rules](#7-sigma-rules)
8. [Threat-Hunting Queries](#8-threat-hunting-queries)
   - [8.1 Elastic (KQL / EQL / ES|QL)](#81-elastic-kql--eql--esql)
   - [8.2 IBM QRadar (AQL)](#82-ibm-qradar-aql)
9. [Mitigations](#9-mitigations)
10. [Incident-Response Playbook](#10-incident-response-playbook)

---

## 1. Introduction

In July 2026, SentinelLABS published research documenting sustained cyberespionage activity against
several Pakistani law enforcement organizations between February 2024 and April 2026. Balochistan
Police was the most heavily affected, with compromised assets including network appliances, a
Fortinet FortiMail gateway, and web servers hosting applications that manage criminal, biometric,
personnel, and citizen-complaint records.

The reporting describes **suspected China- and India-nexus** actors, grouped into four clusters by
tooling: **PlugX**, **ShadowPad**, and **Cobalt Strike** (suspected China-nexus), and **Remcos**
(India-nexus, tracked as **TAG-179 / Bitter**). A notable second stage was an **AsyncRAT** loader
(`cms_plugin.exe`) planted on the public Complaint Management System portal
(`cms.balochistanpolice.gov.pk`), turning a citizen-facing service into a malware-delivery mechanism.

This repository packages **detection rules, hunting queries, mitigations, and an IR playbook**
derived from that public reporting so defenders can operationalize it. Because the tooling is largely
shared or commodity, this content is useful well beyond this single campaign.

---

## 2. Disclaimer

- Provided **as-is, without warranty**. Validate every rule and query against your own telemetry
  before deploying to production — field names, schemas, and false-positive rates vary by environment.
- The IOCs below are **defanged** (`.` written as `[.]`). **Refang** before use, and add the C2 IPs
  to blocklists/lookups only — do **not** actively connect to them from analyst systems.
- **Attribution is an assessment, not a confirmed fact.** SentinelLABS clusters activity by *tooling*,
  not confirmed operators; each cluster may involve more than one actor. Nothing here should be read
  as a definitive claim of responsibility, or as confirmation from any affected organization.
- At the time of writing, **no affected organization has publicly confirmed** these findings. This
  content is shared for defensive preparedness.
- This repository is **not** original threat research. See [Credit](#3-credit).

---

## 3. Credit

All underlying research, indicators, victimology, and attribution belong to **SentinelLABS
(SentinelOne)**:

> **"One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforcement"**
> Aleksandar Milenkoski & Julian-Ferdinand Vögele — 9 July 2026
> https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/

Please read and cite the original report. The detection/hunting/IR content in this repo is a
community contribution built on top of that public reporting. TAG-179 is tracked by Recorded Future;
related activity is documented by Kaspersky (Mysterious Elephant) and Qihoo 360 (APT-C-08 / Bitter).

---

## 4. License

Detection content in this repository is released under the **MIT License** (see `LICENSE`).
SentinelLABS' report, imagery, and original research remain the property of SentinelOne and are
referenced here under fair use for defensive purposes. Third-party marks (Elastic, IBM QRadar,
Sysmon, etc.) belong to their respective owners.

---

## 5. Indicators of Compromise (IOC)

> Defanged. Refang (`[.]` → `.`) before loading into tooling.

### 5.1 IP Addresses (C2)

| IP Address | Cluster / Role |
|---|---|
| 172.111.233[.]36 | PlugX C2 |
| 172.111.233[.]96 | PlugX C2 |
| 172.111.233[.]12 | PlugX C2 |
| 172.111.233[.]105 | PlugX C2 |
| 172.111.233[.]26 | PlugX C2 |
| 172.94.9[.]49 | PlugX C2 |
| 172.94.9[.]43 | PlugX C2 |
| 172.94.9[.]19 | PlugX C2 |
| 45.74.6[.]17 | PlugX C2 |
| 45.125.32[.]218 | ShadowPad C2 |
| 142.171.183[.]8 | Cobalt Strike C2 |
| 193.42.25[.]65 | Cobalt Strike C2 / CMS implant next-stage |
| 89.31.121[.]220 | Remcos C2 (TAG-179) |
| 41.216.188[.]140 | AsyncRAT C2 |

### 5.2 URL

| URL | Note |
|---|---|
| hxxps://cms.balochistanpolice[.]gov[.]pk/client%20scripts/cms_plugin.exe | Implant hosted on the compromised CMS portal |

Associated compromised domain: **cms.balochistanpolice[.]gov[.]pk** (legitimate government site,
abused to host the implant).

### 5.3 Hashes

SHA-1:

| SHA-1 | Note |
|---|---|
| 23f6781919a50b118d8d4e6a7e9ae63b71ecc885 | cms_plugin.exe |
| 4039454c9189e64285e93fc075a30b93f814b5b5 | cms_plugin.exe |
| 58cb2d95063b9df807b7aa8dc106b74ce988a491 | cms_plugin.exe |
| 000fad96a85dd6933c22d3dbec9aed47b7f1f066 | Backdoor launcher (TAG-179) |
| 08570471f39bb6725f07b8cddbea99ed48c22686 | Backdoor launcher (TAG-179) |
| 23f4766c011d193f076dfc735dc460e2a41ead79 | Backdoor launcher (TAG-179) |
| 47f8cb0c2dcf62702f58cfc1603d6325755f6820 | Backdoor launcher (TAG-179) |
| 5d60ff36ff519c2e13e7f66cfa0bb46be79592a7 | Backdoor (TAG-179) |
| 63b88d00331de88af696dfb7a896935d830e485f | Backdoor (TAG-179) |
| 8c329db96e093fa25268e078405a33c518dbb5c9 | Backdoor (TAG-179) |
| d66ab0cd2e44dc8389c111b7ed34c7bcb0b35311 | Backdoor (TAG-179) |
| 2bab40c55637398f0497cff9c8cbea564d595c7f | Lure file (TAG-179) |
| 539bd79fbb684edea94eb37518134b97e94b9dd8 | Lure file (TAG-179) |
| 6fe2e74d009abbd56de01fd7404a1245e9b47c79 | Lure file (TAG-179) |
| 71757adba833b46f961e840d0f055bcce0b529c4 | Lure file (TAG-179) |
| c6c197e61079a0a33108c2c87b5e3c7056a138ec | Lure file (TAG-179) |

### 5.4 Host Artifacts

| Type | Value | Note |
|---|---|---|
| Filename | `cms_plugin.exe` | Implant / stager on CMS portal |
| Filename | `360Safe.exe` | Masquerade — legit Qihoo 360 binary name, wrong path |
| PDB path | `D:\codedome\case\six\Client\Client2\obj\Debug\Client2.pdb` | Developer artifact |
| PDB prefix | `D:\codedome` | Shared across related samples (pivot) |
| UI string | `Update Complete! Please refresh the page` | Fake update shown on execution |
| PDB pinyin | `xinshi` | Chinese-language dev indicator |
| Web path | `/client scripts/` | Attacker drop location on the CMS web server |

---

## 6. YARA Rule

```yara
import "hash"

rule APT_TwoFlags_CMS_Implant_AsyncRAT
{
    meta:
        description = "cms_plugin.exe / D:\\codedome AsyncRAT loader - One Target Two Flags (SentinelLABS 2026-07)"
        reference   = "https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/"
        author      = "community"
        date        = "2026-07-16"
        tlp         = "CLEAR"

    strings:
        $pdb_prefix = "D:\\codedome" ascii wide
        $pdb_full   = "Client2.pdb" ascii wide
        $fakeupdate = "Update Complete! Please refresh the page" ascii wide
        $masq       = "360Safe.exe" ascii wide
        $pinyin     = "xinshi" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $pdb_prefix or
            $fakeupdate or
            (2 of ($pdb_full, $masq, $pinyin))
        )
}

rule APT_TwoFlags_Known_Hashes
{
    meta:
        description = "Known SHA-1 IOCs - One Target Two Flags"
    condition:
        hash.sha1(0, filesize) in (
            "23f6781919a50b118d8d4e6a7e9ae63b71ecc885",
            "4039454c9189e64285e93fc075a30b93f814b5b5",
            "58cb2d95063b9df807b7aa8dc106b74ce988a491",
            "000fad96a85dd6933c22d3dbec9aed47b7f1f066",
            "08570471f39bb6725f07b8cddbea99ed48c22686",
            "23f4766c011d193f076dfc735dc460e2a41ead79",
            "47f8cb0c2dcf62702f58cfc1603d6325755f6820",
            "5d60ff36ff519c2e13e7f66cfa0bb46be79592a7",
            "63b88d00331de88af696dfb7a896935d830e485f",
            "8c329db96e093fa25268e078405a33c518dbb5c9",
            "d66ab0cd2e44dc8389c111b7ed34c7bcb0b35311",
            "2bab40c55637398f0497cff9c8cbea564d595c7f",
            "539bd79fbb684edea94eb37518134b97e94b9dd8",
            "6fe2e74d009abbd56de01fd7404a1245e9b47c79",
            "71757adba833b46f961e840d0f055bcce0b529c4",
            "c6c197e61079a0a33108c2c87b5e3c7056a138ec"
        )
}
```

---

## 7. Sigma Rules

The atomic Sigma rules live in the `sigma/` directory. Each maps to a specific behavior and set of
Event IDs. **Links below to be added.**

| # | Rule | Behavior | Event IDs | Link |
|---|---|---|---|---|
| 4.1 | C2 network connection to known IPs | Outbound C2 | Sysmon 3 / Security 5156 (+ DNS: Sysmon 22 / DNS-Client 3008) | [sigma.yml](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/One_Target_Two%20Flags_Against_Pakistan_Law_Enforcement/Detect_C2_network_connection_to_known_IPs/sigma.yml) |
| 4.2 | Masqueraded `360Safe.exe` from unexpected path | Masquerading (T1036.005) | Sysmon 1 / Security 4688 (+ Sysmon 7) | [sigma.yml](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/One_Target_Two%20Flags_Against_Pakistan_Law_Enforcement/Masqueraded_360Safe_exe_running_from_unexpected_path/sigma.yml) |
| 4.3 | Executable dropped in web `client scripts` dir | Web-hosted implant (T1505.003) | Sysmon 11 / Security 4663 | [sigma.yml](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/One_Target_Two%20Flags_Against_Pakistan_Law_Enforcement/Executable_dropped_into_web_server_client_scripts_directory/sigma.yml) |
| 4.4 | Implant host artifacts (`cms_plugin.exe`) | User Execution (T1204.002) | Sysmon 1 / Security 4688 (+ Sysmon 11) | [sigma.yml](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/One_Target_Two%20Flags_Against_Pakistan_Law_Enforcement/Fake_update_string_codedome_PDB_in_process_memory_or_%20file/sigma.yml) |

**Logging prerequisites:** deploy Sysmon with a curated config (EIDs 1, 3, 7, 8, 10, 11, 17, 18, 22
enabled); enable *Audit Process Creation* + command-line auditing for 4688; set an audit SACL on web
roots for 4663 (silent without it); prefer Sysmon 3 over 5156 for host network telemetry (volume).

---

## 8. Threat-Hunting Queries

> Field names assume **ECS** (Elastic) and typical **QRadar** custom properties. Adjust to your
> normalization. Refang IOCs first.

### 8.1 Elastic (KQL / EQL / ES|QL)

**C2 IP match — KQL (Discover / alert):**
```
destination.ip : ("172.111.233.36" or "172.111.233.96" or "172.111.233.12" or "172.111.233.105" or "172.111.233.26" or "172.94.9.49" or "172.94.9.43" or "172.94.9.19" or "45.74.6.17" or "45.125.32.218" or "142.171.183.8" or "193.42.25.65" or "89.31.121.220" or "41.216.188.140")
```

**C2 IP match — ES|QL (aggregated):**
```esql
FROM logs-*
| WHERE destination.ip IN ("172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17","45.125.32.218","142.171.183.8","193.42.25.65","89.31.121.220","41.216.188.140")
| STATS hits = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name, destination.ip
| SORT hits DESC
```

**CMS C2 domain resolution — KQL (Sysmon EID 22 / DNS-Client 3008):**
```
event.category : "dns" and dns.question.name : "cms.balochistanpolice.gov.pk"
```

**Masqueraded 360Safe.exe / cms_plugin.exe — EQL (Sysmon EID 1 / 4688):**
```eql
process where event.type == "start" and
  process.name in ("360Safe.exe", "cms_plugin.exe") and
  not process.executable : ("*\\360\\*", "*\\360safe\\*", "*\\360 Total Security\\*")
```

**Executable dropped in web dir — EQL (Sysmon EID 11 / 4663):**
```eql
file where event.type in ("creation", "change") and
  file.extension == "exe" and
  file.path : ("*\\client scripts\\*", "*\\client%20scripts\\*")
```

**Known-hash sweep — ES|QL (Sysmon Hashes on EID 1/11/7):**
```esql
FROM logs-*
| WHERE process.hash.sha1 IN ("23f6781919a50b118d8d4e6a7e9ae63b71ecc885","4039454c9189e64285e93fc075a30b93f814b5b5","58cb2d95063b9df807b7aa8dc106b74ce988a491","000fad96a85dd6933c22d3dbec9aed47b7f1f066","08570471f39bb6725f07b8cddbea99ed48c22686","23f4766c011d193f076dfc735dc460e2a41ead79","47f8cb0c2dcf62702f58cfc1603d6325755f6820","5d60ff36ff519c2e13e7f66cfa0bb46be79592a7","63b88d00331de88af696dfb7a896935d830e485f","8c329db96e093fa25268e078405a33c518dbb5c9","d66ab0cd2e44dc8389c111b7ed34c7bcb0b35311","2bab40c55637398f0497cff9c8cbea564d595c7f","539bd79fbb684edea94eb37518134b97e94b9dd8","6fe2e74d009abbd56de01fd7404a1245e9b47c79","71757adba833b46f961e840d0f055bcce0b529c4","c6c197e61079a0a33108c2c87b5e3c7056a138ec")
   OR file.hash.sha1 IN ("23f6781919a50b118d8d4e6a7e9ae63b71ecc885","4039454c9189e64285e93fc075a30b93f814b5b5","58cb2d95063b9df807b7aa8dc106b74ce988a491","000fad96a85dd6933c22d3dbec9aed47b7f1f066","08570471f39bb6725f07b8cddbea99ed48c22686","23f4766c011d193f076dfc735dc460e2a41ead79","47f8cb0c2dcf62702f58cfc1603d6325755f6820","5d60ff36ff519c2e13e7f66cfa0bb46be79592a7","63b88d00331de88af696dfb7a896935d830e485f","8c329db96e093fa25268e078405a33c518dbb5c9","d66ab0cd2e44dc8389c111b7ed34c7bcb0b35311","2bab40c55637398f0497cff9c8cbea564d595c7f","539bd79fbb684edea94eb37518134b97e94b9dd8","6fe2e74d009abbd56de01fd7404a1245e9b47c79","71757adba833b46f961e840d0f055bcce0b529c4","c6c197e61079a0a33108c2c87b5e3c7056a138ec")
| KEEP @timestamp, host.name, process.name, file.path, process.hash.sha1, file.hash.sha1
```

### 8.2 IBM QRadar (AQL)

> QRadar property names (e.g. `"Process Name"`, `"Filename"`, `"SHA1 Hash"`, `"DNS Query"`) depend on
> your DSMs and defined custom properties. Rename to match your deployment. Adjust the time window
> (`LAST N HOURS/DAYS`) as needed.

**C2 IP match:**
```sql
SELECT sourceip, destinationip, "Process Name", QIDNAME(qid) AS event, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE destinationip IN (
  '172.111.233.36','172.111.233.96','172.111.233.12','172.111.233.105','172.111.233.26',
  '172.94.9.49','172.94.9.43','172.94.9.19','45.74.6.17','45.125.32.218',
  '142.171.183.8','193.42.25.65','89.31.121.220','41.216.188.140'
)
LAST 7 DAYS
```

**CMS C2 domain resolution:**
```sql
SELECT sourceip, "DNS Query", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE "DNS Query" ILIKE '%cms.balochistanpolice.gov.pk%'
LAST 7 DAYS
```

**Masqueraded 360Safe.exe / cms_plugin.exe:**
```sql
SELECT sourceip, "Process Name", "Process Path", "Command Line", username, DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE ("Process Name" ILIKE '%cms_plugin.exe' OR "Process Name" ILIKE '%360Safe.exe')
  AND "Process Path" NOT ILIKE '%\360\%'
  AND "Process Path" NOT ILIKE '%\360safe\%'
  AND "Process Path" NOT ILIKE '%\360 Total Security\%'
LAST 30 DAYS
```

**Executable dropped in web dir:**
```sql
SELECT sourceip, "Filename", "Process Name", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE ("Filename" ILIKE '%\client scripts\%' OR "Filename" ILIKE '%\client%20scripts\%')
  AND "Filename" ILIKE '%.exe'
LAST 30 DAYS
```

**Known-hash sweep:**
```sql
SELECT sourceip, "Process Name", "Filename", "SHA1 Hash", DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS time
FROM events
WHERE "SHA1 Hash" IN (
  '23f6781919a50b118d8d4e6a7e9ae63b71ecc885','4039454c9189e64285e93fc075a30b93f814b5b5',
  '58cb2d95063b9df807b7aa8dc106b74ce988a491','000fad96a85dd6933c22d3dbec9aed47b7f1f066',
  '08570471f39bb6725f07b8cddbea99ed48c22686','23f4766c011d193f076dfc735dc460e2a41ead79',
  '47f8cb0c2dcf62702f58cfc1603d6325755f6820','5d60ff36ff519c2e13e7f66cfa0bb46be79592a7',
  '63b88d00331de88af696dfb7a896935d830e485f','8c329db96e093fa25268e078405a33c518dbb5c9',
  'd66ab0cd2e44dc8389c111b7ed34c7bcb0b35311','2bab40c55637398f0497cff9c8cbea564d595c7f',
  '539bd79fbb684edea94eb37518134b97e94b9dd8','6fe2e74d009abbd56de01fd7404a1245e9b47c79',
  '71757adba833b46f961e840d0f055bcce0b529c4','c6c197e61079a0a33108c2c87b5e3c7056a138ec'
)
LAST 30 DAYS
```

---

## 9. Mitigations

**Perimeter / appliances (highest priority — the entry point):**
- Patch all internet-facing Fortinet devices (FortiMail, FortiGate) to current firmware; review Fortinet PSIRT advisories.
- Fully decommission — not just "retire" — appliances no longer in primary use. The FortiMail box was compromised while still live but no longer the designated gateway.
- Restrict management interfaces to out-of-band / VPN; enforce MFA on all appliance admin accounts.

**Web applications (CMS / Smart Police Station stack):**
- Enforce hard separation between served content and any writable/upload path — a PE landing in `/client scripts/` should be structurally impossible.
- File-integrity monitoring on all web roots; alert on any new `.exe/.dll/.ps1` in served directories.
- WAF in front of public forms (e.g. `/Complaint/PublicSearch`); rate-limit and log.
- Content policy so uploaded files can never execute server-side.

**Endpoint:**
- Application allow-listing (WDAC / AppLocker) to block masqueraded `360Safe.exe` from non-standard paths and unsigned `cms_plugin.exe`.
- Alert on reflective .NET assembly loading via EDR.
- Deploy the YARA + Sigma content in this repo.

**Identity:**
- Force password reset for all CMS portal accounts (the `ps-<district>` credentials were harvested from infostealer logs) and enable MFA.
- Monitor infostealer-log / dark-web feeds for corporate credentials.

**Email / lures:**
- Block/quarantine the lure hashes; awareness on ACC-repatriation / "operational plan" decoy themes.

---

## 10. Incident-Response Playbook

**Phase 0 — Prep**
- Load IOCs (Section 5) into SIEM watchlists, EDR custom indicators, and firewall/proxy blocklists.
- Deploy the YARA + Sigma content.

**Phase 1 — Detect & Scope**
1. Run the hunting queries (Section 8) across your **full** retention window (activity dates to Feb 2024).
2. Any C2/hash/domain hit → mark the host suspected-compromised; snapshot volatile data before containment.
3. Pull threat-intel context (e.g. VirusTotal) on any matched hash before eradicating.

**Phase 2 — Contain**
4. Network-isolate confirmed hosts via EDR (don't power off — preserve memory).
5. Block C2 IPs egress-wide at the perimeter and at DNS.
6. Disable/rotate credentials seen on affected hosts; revoke sessions/tokens.
7. For appliances: pull from the mail/network path; preserve config + logs.

**Phase 3 — Investigate**
8. Capture memory + disk images, EDR process trees, PowerShell/Sysmon logs, and web-server access logs (grep for `cms_plugin.exe`, `client scripts`, `client%20scripts`).
9. Identify patient zero and the initial-access vector (appliance exploit vs. lure vs. portal drop).
10. Map lateral movement — especially reachability from web servers to the record data stores (FIR, CRMS, HRMIS, HotelEye, TRS) — and assess data exposure.
11. Timeline C2 activity per cluster; determine dwell time.

**Phase 4 — Eradicate**
12. Remove implants (`cms_plugin.exe`, masqueraded `360Safe.exe`, TAG-179 backdoors/launchers), plus any scheduled tasks, services, or web shells.
13. Rebuild — don't just clean — any host with confirmed backdoor persistence.
14. Patch the exploited entry point(s); replace/reflash compromised appliances.

**Phase 5 — Recover**
15. Restore from known-good backups predating first-seen (conservative baseline: PlugX first-seen 27 Feb 2024).
16. Staged reconnection under heightened monitoring; keep IOC alerts hot for 30–90 days.
17. Force org-wide credential reset for any system touched; re-enable MFA everywhere.

**Phase 6 — Post-incident**
18. Retain evidence; notify the relevant national CERT — **PKCERT (National CERT of Pakistan)**, https://pkcert.gov.pk/ — and affected data subjects per local law.
19. Lessons learned → close the structural gaps (appliance lifecycle, web-root write controls, portal auth).

---

*Underlying research © SentinelOne / SentinelLABS. This repository is an independent community contribution and is not affiliated with or endorsed by SentinelOne.*
