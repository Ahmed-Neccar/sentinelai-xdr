"""Passive host-interface flow sensor. Captures headers only; never sends packets."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import platform
import queue
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, conf, get_if_list
except ImportError as exc:
    raise SystemExit("Scapy is missing. Install sensor/requirements.txt and Npcap; see sensor/README.md.") from exc

from windows_security import WindowsSecurityLog

SENSOR_VERSION = "0.4.0"
_COUNTER_LOCK = threading.Lock()


def get_or_create_sensor_id() -> str:
    """Keep a local, stable identifier for this sensor installation."""
    runtime_dir = Path(__file__).resolve().parent / "runtime"
    id_path = runtime_dir / "sensor-id"
    try:
        value = id_path.read_text(encoding="ascii").strip()
        return str(UUID(value))
    except (OSError, ValueError):
        runtime_dir.mkdir(parents=True, exist_ok=True)
        value = str(uuid4())
        id_path.write_text(value, encoding="ascii")
        return value


def get_or_create_sensor_key() -> tuple[Ed25519PrivateKey, str]:
    """Persist a per-installation Ed25519 key and return its base64 raw public key."""
    runtime_dir = Path(__file__).resolve().parent / "runtime"
    key_path = runtime_dir / "sensor-signing-key.pem"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise RuntimeError("Stored sensor signing key has an unsupported format.")
    except FileNotFoundError:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private_key, base64.b64encode(public_key).decode("ascii")


def next_sensor_request_counter() -> int:
    """Persist a strictly increasing request counter to prevent signed-request replay."""
    runtime_dir = Path(__file__).resolve().parent / "runtime"
    counter_path = runtime_dir / "sensor-request-counter"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    with _COUNTER_LOCK:
        try:
            previous = int(counter_path.read_text(encoding="ascii").strip())
        except FileNotFoundError:
            previous = 0
        except ValueError as exc:
            raise RuntimeError("Sensor request counter is damaged; rotate the sensor credential to re-enroll.") from exc
        current = previous + 1
        temporary = counter_path.with_suffix(".tmp")
        temporary.write_text(str(current), encoding="ascii")
        temporary.replace(counter_path)
        return current


class SensorAuthorizationError(RuntimeError):
    """The server rejected a sensor credential or live-session authorization."""


class ApiClient:
    def __init__(self, base_url: str, email: str, password: str, sensor_id: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.sensor_id = sensor_id
        self.private_key, self.public_key = get_or_create_sensor_key()
        self.session = httpx.Client(timeout=10.0, follow_redirects=False)
        response = self.session.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        if response.is_error:
            raise RuntimeError(f"API login failed ({response.status_code}): {safe_message(response)}")
        self.access_token = response.json()["access_token"]

    def post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        if path.startswith("/api/v1/ingest/live/"):
            headers.update(self._sensor_proof(path, body))
        response = self.session.post(
            f"{self.base_url}{path}",
            content=body,
            headers=headers,
        )
        if response.status_code == 401:
            refresh = self.session.post(f"{self.base_url}/api/v1/auth/refresh")
            if refresh.is_error:
                if refresh.status_code in (401, 403):
                    raise SensorAuthorizationError("Sensor credentials are no longer authorized.")
                raise RuntimeError(f"Session refresh failed ({refresh.status_code})")
            self.access_token = refresh.json()["access_token"]
            headers["Authorization"] = f"Bearer {self.access_token}"
            if path.startswith("/api/v1/ingest/live/"):
                headers.update(self._sensor_proof(path, body))
            response = self.session.post(
                f"{self.base_url}{path}",
                content=body,
                headers=headers,
            )
        if response.status_code in (401, 403, 409):
            raise SensorAuthorizationError(
                f"Sensor access is no longer authorized ({response.status_code}): {safe_message(response)}"
            )
        if response.is_error:
            raise RuntimeError(f"API request failed ({response.status_code}): {safe_message(response)}")
        return response.json()

    def _sensor_proof(self, path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        counter = str(next_sensor_request_counter())
        message = f"{self.sensor_id}\n{counter}\n{timestamp}\nPOST\n{path}\n".encode() + body
        signature = self.private_key.sign(message)
        return {
            "X-Sentinel-Sensor-ID": self.sensor_id,
            "X-Sentinel-Counter": counter,
            "X-Sentinel-Timestamp": timestamp,
            "X-Sentinel-Signature": base64.b64encode(signature).decode("ascii"),
        }

    def get(self, path: str) -> Any:
        response = self.session.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.access_token}"},
        )
        if response.status_code in (401, 403, 409):
            raise SensorAuthorizationError(
                f"Sensor access is no longer authorized ({response.status_code}): {safe_message(response)}"
            )
        if response.is_error:
            raise RuntimeError(f"API request failed ({response.status_code}): {safe_message(response)}")
        return response.json()


def safe_message(response: httpx.Response) -> str:
    try:
        body = response.json()
        return str(body.get("error", {}).get("message", "Request rejected"))[:300]
    except (ValueError, AttributeError):
        return "Request rejected"


def list_interfaces_data() -> list[dict]:
    items = []
    for name in get_if_list():
        iface = conf.ifaces.get(name)
        display_name = getattr(iface, "name", None) or "Unknown adapter"
        description = getattr(iface, "description", None) or ""
        try:
            addresses = sorted(
                {
                    address
                    for values in getattr(iface, "ips", {}).values()
                    for address in values
                    if address not in {"0.0.0.0", "::"}
                }
            )
        except (AttributeError, TypeError):  # Some Npcap pseudo-interfaces have no address map.
            addresses = []
        items.append(
            {
                "capture_interface": name,
                "display_name": display_name,
                "description": description,
                "addresses": addresses,
            }
        )
    return items


def list_interfaces() -> None:
    for item in list_interfaces_data():
        name = item["capture_interface"]
        display_name = item["display_name"]
        description = item["description"]
        addresses = item["addresses"]
        print(f"Adapter: {display_name}")
        if description and description != display_name:
            print(f"  Description: {description}")
        print(f"  IP address: {', '.join(addresses) if addresses else 'none assigned (inactive or virtual adapter)'}")
        print(f"  Capture interface: {name}")


def project_env_credentials() -> tuple[str, str]:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        raise RuntimeError(f"Project .env file not found: {env_path}")
    values: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key.strip()] = value
    email = values.get("SENTINEL_SENSOR_EMAIL", "").strip()
    password = values.get("SENTINEL_SENSOR_PASSWORD", "")
    if not email or not password:
        raise RuntimeError(
            ".env must contain SENTINEL_SENSOR_EMAIL and SENTINEL_SENSOR_PASSWORD for a dedicated "
            "ingestion_service account. Do not use the administrator account for a sensor."
        )
    return email, password


def spool_events(spool: Path, events: list[dict]) -> Path:
    spool.mkdir(parents=True, exist_ok=True)
    path = spool / f"unsent-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.json"
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return path


def replay_spool(api: ApiClient, job_id: str, spool: Path, batch_size: int) -> int:
    """Forward saved batches to the current live session; retain a file until all posts succeed."""
    recovered = 0
    for path in sorted(spool.glob("unsent-*.json")):
        try:
            events = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
                raise ValueError("spool file must contain a list of event objects")
            for start in range(0, len(events), batch_size):
                batch = events[start : start + batch_size]
                api.post(f"/api/v1/ingest/live/{job_id}/events", {"events": batch})
                recovered += len(batch)
            path.unlink()
        except (OSError, ValueError, httpx.HTTPError, RuntimeError) as exc:
            print(f"Could not replay queued batch {path.name}; it remains on disk: {exc}", file=sys.stderr)
            break
    if recovered:
        print(f"Replayed {recovered} queued events from an earlier API interruption.")
    return recovered


def parse_packet(packet, *, interface: str, host: str, seen: dict, output: queue.SimpleQueue) -> None:
    if IP in packet:
        layer = packet[IP]
    elif IPv6 in packet:
        layer = packet[IPv6]
    else:
        return

    if TCP in packet:
        tcp = packet[TCP]
        flags = int(tcp.flags)
        # Emit only the initial SYN to avoid logging every TCP packet.
        if not flags & 0x02 or flags & 0x10:
            return
        protocol, src_port, dst_port = "tcp", int(tcp.sport), int(tcp.dport)
    elif UDP in packet:
        udp = packet[UDP]
        protocol, src_port, dst_port = "udp", int(udp.sport), int(udp.dport)
    else:
        return

    now = time.monotonic()
    flow = (protocol, layer.src, layer.dst, src_port, dst_port)
    if now - seen.get(flow, 0) < 15:
        return
    seen[flow] = now
    if len(seen) > 20_000:
        for key, last_seen in list(seen.items()):
            if now - last_seen >= 15:
                seen.pop(key, None)

    timestamp = datetime.now(UTC).isoformat()
    bucket = int(now // 300)
    identity = f"{host}|{interface}|{bucket}|{flow}"
    dedup_key = hashlib.sha256(identity.encode()).hexdigest()
    output.put(
        {
            "event_time": timestamp,
            "event_type": "net.conn",
            "src_ip": layer.src,
            "dst_ip": layer.dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "host_id": host,
            "severity": "informational",
            "protocol": protocol,
            "message": "Observed initial TCP SYN" if protocol == "tcp" else "Observed UDP flow",
            "dedup_key": dedup_key,
            "capture_interface": interface,
            "capture_method": "passive_headers_only",
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Passively observe this Windows host's TCP/UDP flow headers.")
    parser.add_argument("--server", default="http://127.0.0.1:8001", help="SentinelAI API base URL")
    parser.add_argument("--interface", help="Npcap adapter name; use --list-interfaces first")
    parser.add_argument("--list-interfaces", action="store_true", help="List capture adapters and exit")
    parser.add_argument("--source-name", default=f"{platform.node()}-live-sensor", help="Name shown in SentinelAI")
    parser.add_argument("--sensor-id", default=None, help="Stable sensor installation ID; generated if omitted")
    parser.add_argument("--duration-seconds", type=int, default=120, help="Capture duration; 0 runs until Ctrl+C")
    parser.add_argument("--flush-seconds", type=float, default=5.0, help="Upload interval")
    parser.add_argument("--stop-file", help=argparse.SUPPRESS)
    parser.add_argument("--batch-size", type=int, default=25, help="Maximum events per upload batch")
    parser.add_argument(
        "--windows-events",
        action="store_true",
        help="Also collect new Windows Security logon/unlock events (4624/4625/4801)",
    )
    parser.add_argument(
        "--endpoint-events",
        action="store_true",
        help="Also collect selected Windows account/group/service/task/audit events (including 4720/4732/4697/4698/4719/1102)",
    )
    parser.add_argument(
        "--process-events",
        action="store_true",
        help="Also collect new Windows process-creation events (4688); requires Process Creation auditing",
    )
    parser.add_argument(
        "--use-project-env",
        action="store_true",
        help="Read the dedicated sensor login from local .env instead of prompting for a password",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return 0
    if not args.interface:
        parser.error("--interface is required; run --list-interfaces to select an adapter")
    if args.duration_seconds < 0 or args.flush_seconds <= 0 or not 1 <= args.batch_size <= 100:
        parser.error("duration must be >= 0, flush interval > 0, and batch size between 1 and 100")
    if conf.L2listen.__class__.__name__ == "_NotAvailableSocket":
        print(
            "Packet capture is unavailable: Scapy cannot find Npcap's wpcap.dll. "
            "Install Npcap, reopen PowerShell as Administrator, and run this sensor again.",
            file=sys.stderr,
        )
        return 4

    windows_log = None
    if args.windows_events or args.process_events or args.endpoint_events:
        try:
            windows_log = WindowsSecurityLog(
                collect_processes=args.process_events,
                collect_endpoint=args.endpoint_events,
            )
            if args.windows_events:
                print("Windows Security collection enabled for new logon/unlock events (4624/4625/4801).")
            if args.process_events:
                print("Windows process-creation collection enabled (4688); executable and parent names only.")
            if args.endpoint_events:
                print("Selected Windows account/group/service/task/security events enabled; allowlisted metadata only.")
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"Cannot enable Windows Security log collection: {exc}", file=sys.stderr)
            return 4

    if args.use_project_env:
        try:
            email, password = project_env_credentials()
            print(f"Using dedicated sensor credentials for {email} (password hidden).")
        except RuntimeError as exc:
            print(f"Cannot load project credentials: {exc}", file=sys.stderr)
            return 2
    else:
        email = input("SentinelAI login email: ").strip()
        password = getpass.getpass("SentinelAI login password: ")
    try:
        sensor_id = args.sensor_id or get_or_create_sensor_id()
        api = ApiClient(args.server, email, password, sensor_id)
        capabilities = ["network.headers"]
        if args.windows_events:
            capabilities.append("windows.logon_events")
        if args.process_events:
            capabilities.append("windows.process_events")
        if args.endpoint_events:
            capabilities.append("windows.security_change_events")
        job = api.post(
            "/api/v1/ingest/live/start",
            {
                "source_name": args.source_name,
                "sensor_id": sensor_id,
                "sensor_public_key": api.public_key,
                "host_name": platform.node()[:255],
                "sensor_version": SENSOR_VERSION,
                "capabilities": capabilities,
            },
        )
    except (httpx.HTTPError, RuntimeError, KeyError) as exc:
        print(f"Cannot start sensor session: {exc}", file=sys.stderr)
        return 2

    job_id = str(job["id"])
    host = platform.node()[:255]
    pending: queue.SimpleQueue = queue.SimpleQueue()
    seen: dict = {}
    sniffer = AsyncSniffer(
        iface=args.interface,
        filter="tcp or udp",
        store=False,
        prn=lambda packet: parse_packet(
            packet, interface=args.interface, host=host, seen=seen, output=pending
        ),
    )
    spool = Path(__file__).resolve().parent / "spool"
    replay_spool(api, job_id, spool, args.batch_size)
    total_sent = 0
    network_sent = 0
    windows_logons_sent = 0
    process_events_sent = 0
    endpoint_events_sent = 0
    forwarded_event_counts: dict[str, int] = {}
    windows_event_ids_seen: set[int] = set()
    last_event_forwarded_at: str | None = None
    windows_collection_state = "enabled" if windows_log else "disabled"
    windows_event_ids_configured = windows_log.event_ids.copy() if windows_log else []

    def mark_forwarded(events: list[dict]) -> None:
        nonlocal total_sent, network_sent, windows_logons_sent, process_events_sent, endpoint_events_sent, last_event_forwarded_at
        total_sent += len(events)
        network_sent += sum(1 for event in events if event.get("event_type") == "net.conn")
        windows_logons_sent += sum(
            1 for event in events if event.get("event_type") in ("auth.success", "auth.failure")
        )
        process_events_sent += sum(1 for event in events if event.get("event_type") == "process.start")
        endpoint_events_sent += sum(1 for event in events if str(event.get("event_type", "")).startswith("endpoint."))
        for event in events:
            event_type = str(event.get("event_type", "unknown"))[:64]
            forwarded_event_counts[event_type] = forwarded_event_counts.get(event_type, 0) + 1
            event_id = event.get("windows_event_id")
            if isinstance(event_id, int) and 0 < event_id <= 65535:
                windows_event_ids_seen.add(event_id)
        if events:
            last_event_forwarded_at = datetime.now(UTC).isoformat()

    batch: list[dict] = []
    last_flush = time.monotonic()
    last_windows_poll = last_flush
    last_spool_retry = last_flush
    last_heartbeat = last_flush
    authorization_lost = False
    deadline = last_flush + args.duration_seconds if args.duration_seconds else None

    try:
        sniffer.start()
        print(f"Passive capture started on {args.interface}. Session {job_id}")
        if windows_log:
            print(
                "Network packets are header-only. Windows collection excludes passwords and "
                "process command lines."
            )
        else:
            print("Only IP/port/protocol/time network headers are collected. Press Ctrl+C to stop.")
        while True:
            now = time.monotonic()
            if now - last_heartbeat >= 10.0:
                try:
                    api.post(
                        f"/api/v1/ingest/live/{job_id}/heartbeat",
                        {
                            "interface": args.interface[:255],
                            "events_forwarded": total_sent,
                            "event_counts": dict(list(forwarded_event_counts.items())[:16]),
                            "windows_event_ids_configured": windows_event_ids_configured,
                            "windows_event_ids_seen": sorted(windows_event_ids_seen)[:64],
                            "last_event_forwarded_at": last_event_forwarded_at,
                            "windows_collection_state": windows_collection_state,
                        },
                    )
                except SensorAuthorizationError as exc:
                    authorization_lost = True
                    print(f"Sensor access was revoked; stopping capture: {exc}", file=sys.stderr)
                    raise
                except (httpx.HTTPError, RuntimeError) as exc:
                    print(f"Sensor heartbeat failed; it will retry: {exc}", file=sys.stderr)
                last_heartbeat = now
            if windows_log and now - last_windows_poll >= 5.0:
                try:
                    pending_events = windows_log.poll()
                    for event in pending_events:
                        pending.put(event)
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    print(f"Windows Security log polling failed: {exc}", file=sys.stderr)
                    windows_collection_state = "error"
                    windows_log = None
                last_windows_poll = now
            while not pending.empty() and len(batch) < args.batch_size:
                batch.append(pending.get())
            should_flush = len(batch) >= args.batch_size or (batch and now - last_flush >= args.flush_seconds)
            if should_flush:
                try:
                    api.post(f"/api/v1/ingest/live/{job_id}/events", {"events": batch})
                    mark_forwarded(batch)
                    replay_spool(api, job_id, spool, args.batch_size)
                except SensorAuthorizationError as exc:
                    authorization_lost = True
                    print(f"Sensor access was revoked; stopping capture: {exc}", file=sys.stderr)
                    raise
                except (httpx.HTTPError, RuntimeError) as exc:
                    path = spool_events(spool, batch)
                    print(f"Upload failed; header-only batch saved to {path}: {exc}", file=sys.stderr)
                batch.clear()
                last_flush = now
                print(
                    f"Forwarded {network_sent} network flows and "
                    f"{windows_logons_sent} Windows logon events and "
                    f"{process_events_sent} process-start events and {endpoint_events_sent} endpoint/security events"
                )
            elif spool.exists() and now - last_spool_retry >= args.flush_seconds:
                replay_spool(api, job_id, spool, args.batch_size)
                last_spool_retry = now
            if deadline and now >= deadline:
                break
            if args.stop_file and Path(args.stop_file).is_file():
                Path(args.stop_file).unlink(missing_ok=True)
                print("Stop requested from SentinelAI; finishing queued events.")
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("Stopping capture…")
    except Exception as exc:
        print(f"Capture stopped: {exc}. Check Npcap, adapter name, and elevated terminal.", file=sys.stderr)
        return_code = 3
    else:
        return_code = 0
    finally:
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            pass
        if authorization_lost:
            while not pending.empty():
                pending.get()
            batch.clear()
        while not pending.empty():
            batch.append(pending.get())
            if len(batch) >= args.batch_size:
                try:
                    api.post(f"/api/v1/ingest/live/{job_id}/events", {"events": batch})
                    mark_forwarded(batch)
                except SensorAuthorizationError as exc:
                    authorization_lost = True
                    print(f"Sensor access was revoked; discarding unsent records: {exc}", file=sys.stderr)
                    batch.clear()
                    break
                except (httpx.HTTPError, RuntimeError) as exc:
                    path = spool_events(spool, batch)
                    print(f"Final upload failed; saved to {path}: {exc}", file=sys.stderr)
                batch.clear()
        if batch:
            try:
                api.post(f"/api/v1/ingest/live/{job_id}/events", {"events": batch})
                mark_forwarded(batch)
            except SensorAuthorizationError as exc:
                authorization_lost = True
                batch.clear()
                print(f"Sensor access was revoked; discarding unsent records: {exc}", file=sys.stderr)
            except (httpx.HTTPError, RuntimeError) as exc:
                path = spool_events(spool, batch)
                print(f"Final upload failed; saved to {path}: {exc}", file=sys.stderr)
        try:
            api.post(f"/api/v1/ingest/live/{job_id}/finish", {})
        except (httpx.HTTPError, RuntimeError) as exc:
            print(f"Could not mark the capture session complete: {exc}", file=sys.stderr)

    print(
        f"Capture ended. Forwarded {network_sent} network flows, "
        f"{windows_logons_sent} Windows logon events, {process_events_sent} process-start events, "
        f"and {endpoint_events_sent} endpoint/security events. View the job in Ingestion."
    )
    return locals().get("return_code", 0)


if __name__ == "__main__":
    raise SystemExit(main())
