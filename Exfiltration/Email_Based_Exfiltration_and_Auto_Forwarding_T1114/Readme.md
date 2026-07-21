# Detection Engineering: Email-Based Exfiltration & Auto-Forwarding (T1114)

---

## 1. Technique Title

**Email Collection — Email Forwarding Rule (Auto-Forwarding)**
**Primary MITRE ATT&CK ID:** `T1114.003` (Email Forwarding Rule)
**Parent technique:** `T1114` (Email Collection)
**Tactic:** Collection (`TA0009`) — feeding Exfiltration (`TA0010`)
**Related techniques:** `T1114.001` (Local Email Collection), `T1114.002` (Remote Email Collection), `T1564.008` (Email Hiding Rules), `T1098.002` (Additional Email Delegate Permissions)

---

## 2. Introduction

Email-based exfiltration abuses the mail system itself as the covert channel to steal data. Instead of dropping a tool or opening a new network path, an adversary configures the victim's mailbox — or the whole tenant's mail flow — to silently copy or redirect messages to an address they control. Because the traffic is ordinary SMTP leaving through the organization's own mail infrastructure over trusted, encrypted channels, it blends into normal business email and frequently evades network-focused DLP.

The technique appears in several forms, most of which are set through a single administrative action:

- **Inbox (client) forwarding rules** — a user-level rule (`New-InboxRule`) that forwards, redirects, or forwards-as-attachment incoming mail to an external address. This is the classic Business Email Compromise (BEC) move after account takeover.
- **Mailbox-level forwarding** — `Set-Mailbox` with `ForwardingSmtpAddress` or `ForwardingAddress`, forwarding all of a user's mail server-side.
- **Organization-wide transport (mail-flow) rules** — `New-TransportRule` that blind-copies or redirects mail for many users at once.
- **Remote-domain auto-forward** — `Set-RemoteDomain -AutoForwardEnabled $true`, which re-enables the external auto-forwarding that Microsoft 365 blocks by default.
- **Stealth "hiding" rules** — forwarding combined with mark-as-read, move-to-obscure-folder, and delete, so the victim never notices the exfiltration (overlaps with `T1564.008`).

Because most of these are **discrete, high-signal audit events**, detection engineering leans heavily on **atomic rules** over the Microsoft 365 / Exchange audit log. Correlation is then layered on to (a) confirm a newly-created rule is *actively moving data* and (b) catch forwarding that was configured **before** logging was in place or through an unmonitored channel — a gap atomic creation-time rules cannot close.

---

## 3. Attack Flow

```
[1] Initial Access        Adversary obtains mailbox access — phished credentials,
        │                 token theft, or OAuth consent grant.
        ▼
[2] Recon                 Reviews mailbox for value (finance, HR, credentials,
        │                 supplier threads) and identifies keywords to target.
        ▼
[3] Persistence of Access Creates the exfil channel — ONE of:
        │                   • Inbox rule: ForwardTo / RedirectTo external
        │                   • Set-Mailbox ForwardingSmtpAddress
        │                   • New-TransportRule BlindCopyTo external
        │                   • Set-RemoteDomain -AutoForwardEnabled $true
        ▼
[4] Concealment (T1564.008) Rule also marks-as-read, moves to an obscure folder
        │                 (RSS Feeds / Archive), and/or deletes — hiding activity.
        ▼
[5] Exfiltration (ongoing) Every matching message is auto-copied out over SMTP
        │                 to the attacker mailbox — no further action needed.
        ▼
[6] Abuse                 Harvested threads fuel BEC/fraud, or bulk mailbox
                          content is siphoned continuously and silently.
```

The key observable moments are **the rule/forwarding configuration event (step 3–4)** in the audit log, and **the resulting outbound mail to the external address (step 5)** in message-trace / mail-gateway logs.

---

## 4. Detection Strategy

The backbone is a set of **atomic rules** on the Microsoft 365 / Exchange audit log — each fires on a single configuration event that establishes an email-exfiltration channel. These are high-signal because creating external forwarding is, by itself, the alertable action.

Two **correlation rules** are then required to close a real coverage gap: atomic rules only fire **at the moment a rule is created**. If a forwarding rule already existed before detection was deployed (or was set through a channel you don't audit), no atomic rule ever fires while data keeps leaving. The volume-based correlation catches that silent case, and the temporal correlation confirms a freshly-created rule is genuinely exfiltrating (cutting false positives from benign personal-account forwarding).

**Prerequisite telemetry**

| Data source | Enables |
|---|---|
| M365 Unified Audit Log / Exchange admin audit (`Operation`, `Parameters`, `RecordType`) | Rules 1–5 |
| Message trace / Defender for O365 `EmailEvents` / mail gateway (Proofpoint, Mimecast) | Rule 6, Correlations C1 & C2 |

**Audit Event ID reference (Microsoft 365 Unified Audit Log `RecordType`)**

Unlike Windows logs, the M365 audit log identifies each record by a numeric **`RecordType`** (the platform's equivalent of an Event ID) alongside the `Operation` name. The rules below combine both for precision:

| RecordType | Name | Operations covered here |
|---|---|---|
| `1` | ExchangeAdmin | `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `New-/Set-TransportRule`, `Set-/New-RemoteDomain` |
| `2` | ExchangeItem | `UpdateInboxRules` (mailbox-side rule change from the Outlook client) |
| `SEND` / `REDIRECT` | Message-tracking `EventId` | Outbound send / auto-forward redirect events (Rule 6) |

### List of Atomic Rules

| # | Rule name | Log source | Audit Event ID (RecordType) | What it detects |
|---|---|---|---|---|
| 1 | `inbox_rule_external_forward` | m365:exchange (audit) | `1` ExchangeAdmin, `2` ExchangeItem | A user inbox rule (`New-/Set-InboxRule`) that forwards, redirects, or forwards-as-attachment to an external recipient. |
| 2 | `mailbox_forwarding_enabled` | m365:exchange (audit) | `1` ExchangeAdmin | Mailbox-level server-side forwarding set via `Set-Mailbox` (`ForwardingSmtpAddress` / `ForwardingAddress`). |
| 3 | `transport_rule_external_redirect` | m365:exchange (audit) | `1` ExchangeAdmin | An org-wide transport/mail-flow rule that BCCs or redirects mail to an external address. |
| 4 | `remote_domain_autoforward_enabled` | m365:exchange (audit) | `1` ExchangeAdmin | Tenant external auto-forwarding re-enabled via `Set-RemoteDomain -AutoForwardEnabled`. |
| 5 | `email_hiding_rule` | m365:exchange (audit) | `1` ExchangeAdmin, `2` ExchangeItem | A stealth inbox rule that forwards/redirects **and** hides evidence (mark-as-read, move-to-folder, delete). |
| 6 | `external_mail_attachment` | message trace / gateway | `SEND` / `REDIRECT` (msg-tracking EventId) | Outbound mail carrying attachment(s) to a consumer / free-mail domain (the exfil transport itself). |

### List of Correlation Rules

| # | Rule name | Type | Atomic rules used | Why it helps |
|---|---|---|---|---|
| C1 | `forwarding_rule_then_external_mail` | `temporal_ordered` | `inbox_rule_external_forward` → `external_mail_attachment` | Confirms a newly-created forwarding rule is **actively exfiltrating** mail to the outside within a short window — separating live BEC channels from benign/dormant forwarding. |
| C2 | `bulk_external_forwarding_volume` | `event_count` | `external_mail_attachment` | Catches **pre-existing or silently-configured** forwarding by alerting on a spike of outbound mail to consumer domains from one sender — the case atomic creation-time rules miss. |
