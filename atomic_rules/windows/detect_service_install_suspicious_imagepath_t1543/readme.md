### Explanation

- **`logsource`** targets `service: system`, i.e. the **Windows System event log**, because service installs are recorded there as **event 7045** ("A service was installed in the system").
- **`selection`** anchors on `EventID: 7045` — every new-service installation.
- **`selection_susp_path`** matches when the service's `ImagePath` lives in a **user-writable directory**. Legitimate services almost always run from `\Windows\System32` or a signed vendor `Program Files` path; a service binary in `\Temp`, `\AppData`, `\ProgramData`, `\Public`, or `\PerfLogs` is highly anomalous.
- **`selection_lolbin`** matches when the `ImagePath` **directly invokes a script host or LOLBin** (`powershell`, `rundll32`, `regsvr32`, `mshta`, …) or contains encoded-payload markers (`-enc`, `FromBase64String`, `DownloadString`). A real service binary is an executable, not a command line running PowerShell.
- **`condition: selection and (selection_susp_path or selection_lolbin)`** — it must be a service install **and** *either* the location *or* the invoked binary is suspicious.
- **`level: high`** — specific enough to alert on directly. The listed false positive (some vendors install services from `ProgramData`) is why you should baseline and allowlist known-good service names before enabling.
