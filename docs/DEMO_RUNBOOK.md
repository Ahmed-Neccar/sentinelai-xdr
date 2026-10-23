# SentinelAI XDR — Demo Runbook

This walkthrough demonstrates real, passive telemetry from the Windows computer running the sensor. It does not scan or attack the local network. Only capture devices and networks you are authorized to monitor.

## 1. Start the application

From PowerShell in the project folder:

```powershell
docker compose up --build -d
```

Open `http://127.0.0.1:8080` and sign in with the bootstrap email and password from `.env`. Keep Docker Desktop running. If startup fails, check `docker compose ps` and [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

## 2. Start real host telemetry from the app

Stop any previously started manual sensor session first. Open PowerShell in the project folder and run the controller launcher:

```powershell
.\start_sensor_controller.ps1
```

Approve the elevation prompt and keep the controller window open. In the app, open **Sensors**, select the active Wi-Fi/Ethernet adapter, and click **Start sensor**. Leave Windows sign-in and process collection off unless you specifically want those sources and have enabled their audit policies. The app's **Stop sensor** button flushes queued records and closes the session. A controller window is required because the web application runs inside Docker and cannot access the Windows network card directly.

Use the computer normally to generate traffic visible to its selected adapter. The sensor reads its login from the project `.env`; the password is not displayed in the browser. Optional process collection requires the Windows Audit Process Creation policy described in [`sensor/README.md`](../sensor/README.md).

## 3. Follow the activity in the app

1. Open **Events**. While the sensor is running, new `Network connection` records should appear as visible traffic arrives. Windows sign-ins appear only if Windows auditing is enabled and `--windows-events` is on.
2. Open **Hosts** and select the reported host. `Seen in last 2 min` means an event arrived recently; it is not a sensor heartbeat or proof the capture process is still alive.
3. Open **Sensors**. A recent heartbeat indicates the sensor process checked in. The row becomes **Online** after start and **Stopped** after using the app's stop button. A heartbeat does not prove the adapter is seeing all expected traffic.
4. Select an event to inspect its normalized details. Process records show the executable and parent when available.
5. Open **Detections**. A finding appears only when received events match an enabled rule. Ordinary traffic and sign-ins usually do not trigger a detection.
6. Open a finding to review why it matched and its supporting evidence. Findings are review signals, not confirmed attacks. If a case exists, open **Cases** to add an analyst note and record its status.

## 4. Optional repeatable sample

For a predictable UI walkthrough, go to **Ingestion** and upload `data/samples/auth_and_network_synthetic.json` using **Generic JSON**. Its records are labeled synthetic and use example addresses; they do not come from the network sensor. Its timestamps are fixed and may appear old in the Hosts view. It should demonstrate repeated-authentication and distinct-port rule matches. Do not describe this sample as real attack traffic, and do not mix it with a live-evidence claim.

## What to say

> “SentinelAI XDR is a local defensive monitoring prototype. A Windows sensor passively forwards connection headers and, when enabled, selected Windows Security events. The application normalizes those records, evaluates transparent lab rules, and lets an analyst review evidence and cases. It monitors only what the selected adapter and enabled Windows audit sources expose. A rule match is a lead for investigation, not proof of compromise.”

Automated isolation, blocking, full endpoint detection, whole-LAN visibility, and commercial production readiness are not implemented.
