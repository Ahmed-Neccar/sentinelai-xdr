"""Loopback-only bridge that lets the local SentinelAI UI control its Windows sensor."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import threading
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from live_sensor import ApiClient, SENSOR_VERSION, get_or_create_sensor_id, list_interfaces_data
from network_discovery import ALLOWED_PORTS, MAX_HOSTS, scan_network, validate_scan_request

WEB_ORIGIN = "http://127.0.0.1:8080"
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 8765
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIR = PROJECT_ROOT / "sensor" / "runtime"


class SensorSupervisor:
    def __init__(self) -> None:
        self.sensor_id = get_or_create_sensor_id()
        self.process: subprocess.Popen[bytes] | None = None
        self.stop_file: Path | None = None
        self.interface: str | None = None
        self.options: dict[str, bool] = {}
        self.last_error: str | None = None
        self.lock = threading.RLock()
        self.discovery_lock = threading.RLock()
        self.discovery_cancel = threading.Event()
        self.discovery_thread: threading.Thread | None = None
        self.discovery_started_monotonic = 0.0
        self.discovery: dict[str, Any] = {"state": "idle", "target": None, "ports": [], "completed_hosts": 0, "total_hosts": 0, "results": [], "error": None}

    def status(self) -> dict[str, Any]:
        with self.lock:
            running = self.process is not None and self.process.poll() is None
            if not running and self.process is not None:
                if self.process.returncode not in (0, None):
                    detail = ""
                    log_path = RUNTIME_DIR / "capture.log"
                    try:
                        lines = [line.strip() for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
                        # Surface actionable startup errors without exposing arbitrary log contents.
                        detail = next(
                            (line for line in reversed(lines) if line.startswith((
                                "Cannot enable Windows Security log collection:",
                                "Packet capture is unavailable:",
                                "Cannot load project credentials:",
                                "Cannot start sensor session:",
                                "Capture stopped:",
                            ))),
                            "",
                        )
                    except OSError:
                        pass
                    self.last_error = detail or (
                        "The sensor exited unexpectedly. Check Npcap, the selected adapter, "
                        "Windows elevation, and the local API."
                    )
                self.process = None
                self.stop_file = None
            return {
                "available": True,
                "running": running,
                "host_name": platform.node(),
                "sensor_id": self.sensor_id,
                "sensor_version": SENSOR_VERSION,
                "interface": self.interface if running else None,
                "options": self.options if running else {},
                "last_error": self.last_error,
            }

    def start(self, payload: dict[str, Any]) -> dict[str, Any]:
        interface = payload.get("interface")
        if not isinstance(interface, str) or not interface:
            raise ValueError("Choose an active network adapter first.")
        available = {item["capture_interface"] for item in list_interfaces_data()}
        if interface not in available:
            raise ValueError("The selected network adapter is no longer available. Refresh the list.")

        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise RuntimeError("The sensor is already running on this computer.")
            self.process = None

            email, password = read_project_credentials()
            api = ApiClient("http://127.0.0.1:8001", email, password)
            sessions = api.get("/api/v1/ingest/live/sessions?page_size=100")
            legacy_source_name = f"{platform.node()}-live-sensor"
            source_name = f"{legacy_source_name}-{self.sensor_id[:8]}"
            if any(
                row.get("state") == "online"
                and (
                    row.get("sensor_id") == self.sensor_id
                    or row.get("source_name") in {source_name, legacy_source_name}
                )
                for row in sessions
            ):
                raise RuntimeError(
                    "A sensor session from this computer is already online. Stop the existing sensor first."
                )

            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            self.stop_file = RUNTIME_DIR / "stop-capture.request"
            self.stop_file.unlink(missing_ok=True)
            log_path = RUNTIME_DIR / "capture.log"
            args = [
                sys.executable,
                str(Path(__file__).with_name("live_sensor.py").resolve()),
                "--server",
                "http://127.0.0.1:8001",
                "--interface",
                interface,
                "--source-name",
                source_name,
                "--sensor-id",
                self.sensor_id,
                "--duration-seconds",
                "0",
                "--use-project-env",
                "--stop-file",
                str(self.stop_file),
            ]
            windows_events = payload.get("windows_events") is True
            process_events = payload.get("process_events") is True
            endpoint_events = payload.get("endpoint_events") is True
            if windows_events:
                args.append("--windows-events")
            if process_events:
                args.append("--process-events")
            if endpoint_events:
                args.append("--endpoint-events")
            with log_path.open("w", encoding="utf-8") as log:
                self.process = subprocess.Popen(
                    args,
                    cwd=PROJECT_ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            self.interface = interface
            self.options = {
                "windows_events": windows_events,
                "process_events": process_events,
                "endpoint_events": endpoint_events,
            }
            self.last_error = None
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self.lock:
            if self.process is None or self.process.poll() is not None:
                return {"running": False, "message": "No sensor process is running."}
            if self.stop_file is not None:
                self.stop_file.write_text("stop", encoding="utf-8")
            return {"running": True, "message": "Stop requested; the sensor is finishing queued records."}

    def discovery_status(self) -> dict[str, Any]:
        with self.discovery_lock:
            return {**self.discovery, "available_ports": [{"port": port, "service": name} for port, name in ALLOWED_PORTS.items()]}

    def start_discovery(self, payload: dict[str, Any]) -> dict[str, Any]:
        target = payload.get("target")
        ports = payload.get("ports")
        if not isinstance(target, str) or not isinstance(ports, list):
            raise ValueError("Provide a network range and selected common service ports.")
        network, selected_ports = validate_scan_request(target, ports, payload.get("authorized") is True)
        total_hosts = max(1, len(list(network.hosts())))
        with self.discovery_lock:
            if self.discovery_thread is not None and self.discovery_thread.is_alive():
                raise RuntimeError("A network discovery scan is already running.")
            self.discovery_cancel = threading.Event()
            self.discovery = {
                "scan_id": str(uuid.uuid4()), "state": "running", "target": str(network), "ports": selected_ports,
                "completed_hosts": 0, "total_hosts": total_hosts, "responsive_hosts": 0,
                "no_response_addresses": total_hosts, "results": [], "error": None,
                "started_at": datetime.now(UTC).isoformat(), "finished_at": None,
                "duration_seconds": None,
                "discovery_scope": "ARP is attempted for directly connected IPv4 ranges; selected TCP ports are checked at every target address.",
            }
            self.discovery_started_monotonic = time.monotonic()
            self.discovery_thread = threading.Thread(
                target=self._run_discovery, args=(str(network), selected_ports),
                name="sentinel-network-discovery", daemon=True,
            )
            self._audit_discovery("started", {
                "scan_id": self.discovery["scan_id"], "target": str(network),
                "ports": selected_ports, "address_limit": MAX_HOSTS,
            })
            self.discovery_thread.start()
            return self.discovery_status()

    def _run_discovery(self, target: str, ports: list[int]) -> None:
        def update(completed: int, results: list[dict[str, Any]]) -> None:
            with self.discovery_lock:
                self.discovery["completed_hosts"] = completed
                self.discovery["results"] = results.copy()
                self.discovery["responsive_hosts"] = len(results)
                self.discovery["no_response_addresses"] = max(self.discovery["total_hosts"] - len(results), 0)

        try:
            results = scan_network(target, ports, self.discovery_cancel, update)
            with self.discovery_lock:
                self.discovery["results"] = results
                self.discovery["state"] = "stopped" if self.discovery_cancel.is_set() else "completed"
                if not self.discovery_cancel.is_set():
                    self.discovery["completed_hosts"] = self.discovery["total_hosts"]
                self.discovery["responsive_hosts"] = len(results)
                self.discovery["no_response_addresses"] = max(self.discovery["total_hosts"] - len(results), 0)
                self.discovery["finished_at"] = datetime.now(UTC).isoformat()
                self.discovery["duration_seconds"] = round(time.monotonic() - self.discovery_started_monotonic, 2)
                state = self.discovery["state"]
                details = {
                    "scan_id": self.discovery["scan_id"], "target": target, "ports": ports,
                    "responsive_devices": len(results),
                    "checked_addresses": self.discovery["completed_hosts"],
                    "duration_seconds": self.discovery["duration_seconds"],
                }
            self._audit_discovery(state, details)
        except Exception as exc:
            with self.discovery_lock:
                self.discovery["state"] = "failed"
                self.discovery["error"] = str(exc)[:250]
                self.discovery["finished_at"] = datetime.now(UTC).isoformat()
                self.discovery["duration_seconds"] = round(time.monotonic() - self.discovery_started_monotonic, 2)
                scan_id = self.discovery["scan_id"]
            self._audit_discovery("failed", {"scan_id": scan_id, "target": target, "ports": ports, "error": str(exc)[:200]})

    @staticmethod
    def _audit_discovery(action: str, details: dict[str, Any]) -> None:
        try:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            with (RUNTIME_DIR / "network-discovery.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps({"time": datetime.now(UTC).isoformat(), "action": action, **details}) + "\n")
        except OSError:
            pass

    def stop_discovery(self) -> dict[str, Any]:
        with self.discovery_lock:
            if self.discovery.get("state") != "running":
                return self.discovery_status()
            self.discovery_cancel.set()
            return {**self.discovery, "message": "Stopping the scan safely…"}


def read_project_credentials() -> tuple[str, str]:
    values: dict[str, str] = {}
    env_path = PROJECT_ROOT / ".env"
    if not env_path.is_file():
        raise RuntimeError("Project .env file is missing. Configure the local app first.")
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        row = line.strip()
        if not row or row.startswith("#") or "=" not in row:
            continue
        key, value = row.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    email = values.get("SENTINEL_SENSOR_EMAIL", "").strip()
    password = values.get("SENTINEL_SENSOR_PASSWORD", "")
    if not email or not password:
        raise RuntimeError(
            "Configure SENTINEL_SENSOR_EMAIL and SENTINEL_SENSOR_PASSWORD for a dedicated "
            "ingestion_service account in .env. Do not use the administrator account for a sensor."
        )
    return email, password


class ControllerHandler(BaseHTTPRequestHandler):
    server_version = "SentinelSensorController/1.0"

    @property
    def supervisor(self) -> SensorSupervisor:
        return self.server.supervisor  # type: ignore[attr-defined]

    def _authorize_local_origin(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "").lower()
        return origin == WEB_ORIGIN and host == f"{CONTROL_HOST}:{CONTROL_PORT}"

    def _send(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", WEB_ORIGIN)
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        if not self._authorize_local_origin():
            self._send(403, {"error": "Local SentinelAI origin required."})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", WEB_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "300")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._authorize_local_origin():
            self._send(403, {"error": "Local SentinelAI origin required."})
            return
        path = urlparse(self.path).path
        if path == "/status":
            self._send(200, self.supervisor.status())
        elif path == "/interfaces":
            try:
                self._send(200, {"items": list_interfaces_data()})
            except Exception as exc:
                self._send(500, {"error": str(exc)[:250]})
        elif path == "/network-scan/status":
            self._send(200, self.supervisor.discovery_status())
        else:
            self._send(404, {"error": "Not found."})

    def do_POST(self) -> None:
        if not self._authorize_local_origin():
            self._send(403, {"error": "Local SentinelAI origin required."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 4096:
                self._send(413, {"error": "Request is too large."})
                return
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("Invalid request.")
            path = urlparse(self.path).path
            if path == "/capture/start":
                self._send(200, self.supervisor.start(payload))
            elif path == "/capture/stop":
                self._send(200, self.supervisor.stop())
            elif path == "/network-scan/start":
                self._send(202, self.supervisor.start_discovery(payload))
            elif path == "/network-scan/stop":
                self._send(200, self.supervisor.stop_discovery())
            else:
                self._send(404, {"error": "Not found."})
        except ValueError as exc:
            self._send(400, {"error": str(exc)[:250]})
        except RuntimeError as exc:
            self._send(409, {"error": str(exc)[:250]})
        except Exception as exc:
            self._send(500, {"error": f"Unable to control sensor: {str(exc)[:200]}"})

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def main() -> int:
    if sys.platform != "win32":
        print("The local sensor controller is intended for Windows.", file=sys.stderr)
        return 2
    server = HTTPServer((CONTROL_HOST, CONTROL_PORT), ControllerHandler)
    server.supervisor = SensorSupervisor()  # type: ignore[attr-defined]
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    with (RUNTIME_DIR / "controller.log").open("a", encoding="utf-8") as log:
        with redirect_stdout(log), redirect_stderr(log):
            print(f"SentinelAI sensor controller listening on {CONTROL_HOST}:{CONTROL_PORT}.", flush=True)
            print("Capture data remains header-only and passive.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.supervisor.stop()  # type: ignore[attr-defined]
                server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
