# Detection Engineering: Exfiltration to Cloud Storage (T1567.002)

---

## 1. Technique Title

**Exfiltration Over Web Service: Exfiltration to Cloud Storage**
**MITRE ATT&CK ID:** `T1567.002`
**Tactic:** Exfiltration (`TA0010`)
**Related techniques:** `T1560` (Archive Collected Data), `T1074` (Data Staged), `T1030` (Data Transfer Size Limits)

---

## 2. Introduction

Adversaries exfiltrate collected data to commercial cloud storage services instead of routing it back through their primary command-and-control (C2) channel. Services such as **MEGA, Dropbox, Google Drive, Microsoft OneDrive, Box, pCloud, WeTransfer, gofile.io**, and **AWS S3 / Azure Blob / GCS** are attractive because they are:

- **Trusted and rarely blocked** — most enterprises allow at least some cloud storage traffic for business use.
- **TLS-encrypted** — payload contents are opaque to inspection without SSL interception.
- **API- and client-driven** — uploads look like ordinary application traffic and blend into normal user behavior.
- **Reputationally clean** — the destination domains have high reputation, so they evade domain/URL blocklists.

In practice this technique is executed either with **purpose-built utilities** (most notably `rclone`, plus `MEGAcmd`, `megatools`, `aws s3 cp/sync`, `gsutil`, `az storage blob upload`), with **scripted uploads** (PowerShell `Invoke-WebRequest`/`Invoke-RestMethod`, `curl`, `System.Net.WebClient`), or **directly through a browser**. In cloud-native intrusions, the same objective is achieved by copying data into an attacker-controlled bucket or by making a victim bucket publicly accessible.

Because the destination is legitimate, detection engineering focuses less on the destination itself and more on **who is talking to it, with what tool, in what volume, and immediately after what activity** (e.g., archive staging).

---

## 3. Attack Flow

```
[1] Collection            Adversary gathers target files (documents, DBs, credentials)
        │                 from local disk, shares, or cloud drives.
        ▼
[2] Staging (T1074)       Data is consolidated into a working/staging directory.
        │
        ▼
[3] Archive (T1560)       Data is compressed and often password-protected
        │                 (7-Zip / WinRAR / zip) to shrink volume and hide content.
        ▼
[4] Tool / Channel Setup  Exfil tool is dropped or a native one is abused
        │                 (rclone config, MEGAcmd login, aws credentials, PS script).
        ▼
[5] Transfer (T1567.002)  Archive is uploaded to a cloud storage service over TLS,
        │                 frequently in parallel/multi-threaded chunks.
        ▼
[6] Cleanup               Staged archives and tool configs are deleted to remove traces.
```

Key observable moments for defenders: **archive creation (3)**, **exfil tool execution or scripted upload (4–5)**, **the outbound network/proxy transaction to the cloud storage host (5)**, and — in cloud environments — **the bucket write or exposure event (5)**.

---

## 4. Detection Strategy

The strategy layers **atomic rules** (each catches a single high-value artifact on one log source) with a small number of **correlation rules** (which link stages together to raise fidelity where a single event is too noisy on its own — cloud storage has heavy legitimate use).

**Prerequisite telemetry**

| Data source | Enables |
|---|---|
| Process creation (Sysmon EID 1 / EDR) | Rules 1, 2, 7 |
| PowerShell Script Block Logging (EID 4104) | Rule 3 |
| Network connection (Sysmon EID 3 / EDR) | Rule 4 |
| Web proxy / SWG logs (with bytes + host) | Rule 5, Correlation 2 |
| AWS CloudTrail | Rule 6 |

### List of Atomic Rules

| # | Rule name | Log source | What it detects |
|---|---|---|---|
| 1 | [`rclone_execution`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/windows/Detect_Rclone_Data_Exfiltration_Tool_Execution_t1567.002/sigma.yml) | process_creation | Execution of `rclone` (the most abused cloud-exfil tool), including renamed binaries via flag combinations. |
| 2 | [`cloud_cli_upload_tool`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/windows/detect_Cloud_Storage_CLI_Upload_Utility_Execution_t1567.002/sigma.yml) | process_creation | Execution of cloud storage CLIs (MEGAcmd/megatools, `aws s3`, `gsutil`, `az storage`) in an upload mode. |
| 3 | [`script_cloud_upload`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/windows/Detect_Scripted_Upload_to_Cloud_Storage_Endpoint_t1567.002/sigma.yml) | ps_script | Scripted/manual upload primitives (`Invoke-WebRequest`, `WebClient`, `curl`) targeting cloud storage API endpoints. |
| 4 | [`cloud_storage_network_connection`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/windows/Detect_Non_Browser_Network_Connection_to_Cloud_Storage_Service/sigma.yml) | network_connection | A **non-browser** process making a network connection to a known cloud storage service. |
| 5 | [`cloud_storage_large_upload`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/Proxy/Large_Outbound_Upload_to_Cloud_Storage_via_Web_Proxy/sigma.yml) | proxy | A single large (`≥10 MB`) `PUT`/`POST` upload to a cloud storage host. |
| 6 | [`data_staged_archive`](https://github.com/zshanhyder01/Detection-Engineering/blob/main/atomic_rules/windows/Detect_Data_Staged_via_Archive_Utility_t1560.001/sigma.yml) | process_creation | Data being compressed/password-protected into an archive — the staging precursor to exfiltration. |
### List of Correlation Rules

| # | Rule name | Type | Atomic rules used | Why it helps |
|---|---|---|---|---|
| C1 | `stage_then_cloud_exfil` | `temporal_ordered` | `data_staged_archive` → `cloud_storage_network_connection` | Confirms the **archive-then-upload** kill-chain sequence on one host in a short window, converting two medium-confidence signals into one high-confidence detection. |
| C2 | `bulk_cloud_upload_volume` | `event_count` | `cloud_storage_large_upload` | Catches **automated bulk exfiltration** — many large uploads from one source in a short window — even when each individual upload looks routine. |
