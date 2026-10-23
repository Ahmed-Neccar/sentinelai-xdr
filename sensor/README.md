# SentinelAI live host sensor (Windows)

The passive sensor captures real traffic visible to **one Windows computer**, forwards selected connection metadata to the local SentinelAI API, and applies the project's enabled detections. Passive capture does not generate traffic, inject packets, or record packet payloads. SentinelAI also provides a separate, manually started network discovery check described below.

## Authorized network discovery

The **Network discovery** page uses the Windows loopback controller to check a network from this computer. It requires an explicit authorization confirmation and accepts only private IPv4/IPv6 ranges containing at most 256 addresses. Public, loopback, link-local, and multicast targets are rejected. Users can select up to 12 ports from the built-in common-service list; arbitrary port ranges are not accepted. For directly connected IPv4 networks, the scanner also attempts ARP host discovery so a device can appear even when all selected TCP ports are filtered. Selected TCP connect checks run against every target address with bounded concurrency and short timeouts, and can be stopped from the page. Results include open, closed, and filtered states. SSH, HTTP(S), DNS over TCP, PostgreSQL, and RDP receive limited protocol probes; a service name is marked identified only when its response matches the expected protocol. Other reachable ports are shown as open with a port-based hint that is explicitly unverified. The UI reports checked-address and responding-device counts; filtered/no-response addresses are not proof that a device is offline.

This is a bounded Nmap-style summary, not a full Nmap replacement: IPv6 host discovery remains TCP-only; routed networks, hotspot client isolation, host firewalls, or unavailable Npcap can prevent ARP visibility; and it does not perform UDP scans, operating-system fingerprinting, version scripts, or vulnerability checks. The scanner does not authenticate to, exploit, change, or block devices. Start the local controller with `./start_sensor_controller.ps1`, rebuild the frontend, then use **Network discovery**. Scan start/finish metadata is appended to `sensor/runtime/network-discovery.jsonl` on the Windows host.

## What it records

- IPv4/IPv6 TCP connection attempts (initial SYN packets) and UDP packet headers
- Source/destination IP address, source/destination port, protocol, observation time, and local adapter/host labels
- Optional Windows Security events: successful logon (4624), failed logon (4625), and workstation unlock (4801), collected only after the sensor starts
- Optional Windows process creation events (4688), collected only when `--process-events` is enabled; includes executable, parent executable, and process IDs but no command line or account name
- Optional endpoint/security events (account changes such as 4720/4724/4726, group membership such as 4728/4732/4756, service/task changes such as 4697/4698/4699/4702, 4719 audit-policy change, and 1102 Security log cleared), collected only when `--endpoint-events` is enabled; includes allowlisted metadata and never scheduled-task XML or command content
- The API normalizes and stores these as `net.conn` events and runs enabled detection rules
- A Windows Security 4624 event with LogonType 10 creates a low-severity analyst review finding; Windows may omit the source IP, which limits attribution. Ordinary local sign-ins and workstation unlocks do not match this rule.

Windows logon events are opt-in because usernames and sign-in history are sensitive. Enable them with `--windows-events`; run the sensor elevated so Windows permits Security log access. The collector starts at the newest log record and does not backfill old sign-in history. Windows must also be configured to audit the relevant event categories. In elevated PowerShell, enable logon success/failure and workstation lock/unlock auditing with:

```powershell
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable
```

Process creation is a separate opt-in because it can produce medium-to-high event volume. In elevated PowerShell, enable the Windows **Audit Process Creation** success policy with:

```powershell
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
```

Then add `--process-events` when starting the sensor. The collector intentionally ignores the `CommandLine` field even if Windows has been configured to record it.

Account, security-group, service, scheduled-task, audit-policy, and Security-log-clear events are a separate opt-in in the Sensors UI or with `--endpoint-events`. Configure Windows Audit User Account Management and Audit Security Group Management success auditing as appropriate; Windows documents that these policies emit low-volume account-management and group membership events ([account management](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management), [group management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)). Policy can vary by host and domain; verify event IDs in Event Viewer before relying on coverage. The collector deliberately ignores scheduled-task XML (`TaskContent`) and arbitrary event fields. These events are investigation leads, not proof of persistence or compromise. Event 4688 contains process and parent names; Windows documents the process-creation event and its fields in [Event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688). Microsoft notes process auditing can generate medium-to-high volume in [Audit Process Creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-creation).

The collector forwards event ID, record ID, account name, logon type, workstation, failure reason, activity, and a valid source IP when present. It does not collect passwords or command lines. Windows can apply organization policy that overrides these local settings.

It does not inspect DNS names, URLs, credentials, packet contents, or application payloads. IP addresses and ports can still be sensitive telemetry; keep this lab local and use it only on devices/networks you are authorized to monitor.

## Coverage limits

The sensor sees traffic that Windows/Npcap exposes on the selected adapter. This normally means traffic to/from this PC, and it may omit traffic handled entirely by other devices. A Wi-Fi adapter in normal mode does **not** provide visibility into every other Wi-Fi client's unicast traffic. For whole-LAN visibility, run an authorized sensor at the router/gateway, on a network TAP, or on a switch/AP configured to mirror traffic. This project does not configure those devices.

## Install and run

1. Start the SentinelAI stack from the project folder and confirm the web app works at `http://127.0.0.1:8080` and the API at `http://127.0.0.1:8001`.
2. This project currently targets Python 3.12. Check that the Python launcher can find it:

   ```powershell
   py -3.12 --version
   ```

   If it is unavailable, install Python 3.12 x64 and reopen PowerShell.
3. Install Npcap from [npcap.com](https://npcap.com/#download). In the installer, leave **WinPcap API-compatible Mode** unchecked, as Scapy recommends. Restart PowerShell after installation.
4. Open **PowerShell as Administrator** in the project folder. Install the sensor's Python packages:

   ```powershell
   py -3.12 -m venv sensor\.venv
   .\sensor\.venv\Scripts\python.exe -m pip install -r sensor\requirements.txt
   ```

5. List adapters and choose the exact adapter name for the active Ethernet or Wi-Fi connection:

   ```powershell
   .\sensor\.venv\Scripts\python.exe sensor\live_sensor.py --list-interfaces
   ```

6. Create a dedicated account through the administrator-only `POST /api/v1/users` endpoint (open `http://127.0.0.1:8001/docs`, sign in/authorize with an administrator bearer token, then create a user with only the `ingestion_service` role). Use a distinct account for each sensor. Set that account email and a separate long password as `SENTINEL_SENSOR_EMAIL` and `SENTINEL_SENSOR_PASSWORD` in the ignored local `.env` file, then restart the controller if it is running. The first live session binds that account to its persisted sensor ID and data source; it cannot later be reused for another sensor ID. Rotate its password or deactivate the account through the administrator user API to revoke its credentials. The sensor must not use the bootstrap administrator credentials. For a **manual fallback**, select the adapter whose name and IP match the active **Wi-Fi** or **Ethernet** connection and start capture from elevated PowerShell:

   ```powershell
   .\sensor\.venv\Scripts\python.exe sensor\live_sensor.py --interface "<adapter name>" --duration-seconds 120 --use-project-env
   ```

   For continuous capture, use `--duration-seconds 0`; press `Ctrl+C` to stop. Add `--windows-events`, `--process-events`, or `--endpoint-events` only if you want those sources and have enabled their audit policies. If you prefer not to load credentials from `.env`, omit `--use-project-env` and enter them at the prompts. If the API is temporarily unavailable during capture, header-only batches are queued under `sensor\spool\` and retried while the sensor is running; remaining batches are replayed into the next capture session after the API returns. The queue is best-effort local storage, not a guaranteed durable buffer; keep the files if the sensor reports a replay error.

7. To control capture from the web app, first stop any manually started sensor session. Open an elevated PowerShell in the project folder and run `./start_sensor_controller.ps1`. Approve the Windows elevation prompt and leave the controller window open (minimize it if desired). Optional: run `./install_sensor_autostart.ps1` once as Administrator to start a hidden controller at sign-in. If a controller is already running, the scheduled task takes effect at your next sign-in. Remove it with `./remove_sensor_autostart.ps1`. In the app, open **Sensors**, choose the active Wi-Fi/Ethernet adapter, and press **Start sensor**. The app can optionally collect new Windows sign-ins or process starts. Press **Stop sensor** in the app to flush queued records and close the session gracefully. The controller is loopback-only and accepts control requests only from `http://127.0.0.1:8080`; do not change those defaults or expose its port. In the web app, **Events** shows records as they arrive and **Hosts** shows telemetry-reported host labels. A recent heartbeat proves the process checked in, not that the adapter sees every expected packet or the rest of the LAN. A process crash becomes **Signal delayed** after the 30-second heartbeat window. Network events are `net.conn`; Windows logons appear as `auth.success` or `auth.failure`, with workstation unlocks marked by activity `workstation_unlock`; process starts appear as `process.start`; selected service/task/audit events appear as `endpoint.*`. A detection appears only if an enabled rule matches observed records; ordinary connections and sign-ins are not automatically attacks.

The `--server` option can point to a different reachable SentinelAI API, for example `--server http://127.0.0.1:8001`. Do not expose the development API publicly.

## Troubleshooting

- **Npcap/driver error:** install or repair Npcap, reboot if its installer requests it, and reopen an elevated PowerShell window.
- **No traffic:** confirm the selected interface is up and carries the computer's traffic. Try Ethernet/Wi-Fi adapter names shown by `--list-interfaces`.
- **Login rejected:** check that the dedicated sensor account in `.env` is active and has only the `ingestion_service` role; restart the controller after changing `.env`.
- **Sensor credentials missing:** create the account with administrator-only `POST /api/v1/users` in the API docs, assign only `ingestion_service`, configure `SENTINEL_SENSOR_EMAIL` and `SENTINEL_SENSOR_PASSWORD` in `.env`, then restart the controller. Do not put administrator credentials in these settings.
- **API unreachable:** keep Docker Compose running and check `http://127.0.0.1:8001/api/v1/ready`.
- **Automatic controller startup:** run `./install_sensor_autostart.ps1` once as Administrator. To remove the scheduled task, run `./remove_sensor_autostart.ps1`. Controller diagnostics are written to `sensor/runtime/controller.log`.
- **Sensors page says controller unavailable:** run `./start_sensor_controller.ps1` in elevated PowerShell and keep its window open. Open the app at `http://127.0.0.1:8080` (not another hostname).

## Current implementation boundary

This is a real passive host sensor integrated with the existing event and rule pipeline. The Windows Security collector is an initial identity signal, not full endpoint detection: file telemetry, centralized agent enrollment and rotation, persistence coverage beyond selected Windows Security events, network-wide packet brokerage, sensor auto-update, multi-sensor health, and a guaranteed durable local queue are not implemented. Validate each source on the actual machine before presenting it as operational.
