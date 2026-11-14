import http.client
import json
import sys
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

# controller imports its sibling modules by bare name, as it does when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import controller  # noqa: E402
from controller import ControllerHandler, read_project_credentials  # noqa: E402

GOOD_ORIGIN = "http://127.0.0.1:8080"
GOOD_HOST = "127.0.0.1:8765"


class FakeSupervisor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.error: Exception | None = None

    def _record(self, name: str, payload: dict | None = None) -> dict:
        if self.error is not None:
            raise self.error
        self.calls.append((name, payload or {}))
        return {"called": name}

    def status(self) -> dict:
        return {"running": False}

    def start(self, payload: dict) -> dict:
        return self._record("start", payload)

    def stop(self) -> dict:
        return self._record("stop")

    def start_discovery(self, payload: dict) -> dict:
        return self._record("start_discovery", payload)

    def stop_discovery(self) -> dict:
        return self._record("stop_discovery")

    def discovery_status(self) -> dict:
        return {"state": "idle"}


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), ControllerHandler)
    httpd.supervisor = FakeSupervisor()  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def call(server, method: str, path: str, *, origin=GOOD_ORIGIN, host=GOOD_HOST, body=b"", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    connection.putrequest(method, path, skip_host=True)
    if host is not None:
        connection.putheader("Host", host)
    if origin is not None:
        connection.putheader("Origin", origin)
    connection.putheader("Content-Length", str(len(body)))
    for key, value in (headers or {}).items():
        connection.putheader(key, value)
    connection.endheaders(body)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, dict(response.getheaders()), (json.loads(payload) if payload else None)


@pytest.mark.parametrize(
    ("origin", "host"),
    [
        (None, GOOD_HOST),
        ("http://evil.example", GOOD_HOST),
        ("https://localhost:8443", GOOD_HOST),
        (GOOD_ORIGIN, "evil.example:8765"),
        (GOOD_ORIGIN, "127.0.0.1:9999"),
        (GOOD_ORIGIN, None),
    ],
)
def test_only_the_local_panel_origin_and_host_are_accepted(server, origin, host) -> None:
    for method, path in (("GET", "/status"), ("POST", "/capture/start"), ("OPTIONS", "/status")):
        status, _, body = call(server, method, path, origin=origin, host=host, body=b"{}" if method == "POST" else b"")
        assert status == 403, (method, origin, host)
        assert body == {"error": "Local SentinelAI origin required."}
    assert server.supervisor.calls == []  # nothing was started


def test_preflight_and_reads_for_the_panel(server) -> None:
    status, headers, _ = call(server, "OPTIONS", "/capture/start")
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == GOOD_ORIGIN
    assert headers["Access-Control-Allow-Private-Network"] == "true"
    assert call(server, "GET", "/status")[2] == {"running": False}
    assert call(server, "GET", "/network-scan/status")[2] == {"state": "idle"}
    status, headers, body = call(server, "GET", "/nope")
    assert status == 404 and headers["Cache-Control"] == "no-store"


def test_post_routes_reach_the_supervisor_with_the_payload(server) -> None:
    payload = json.dumps({"interface": "Wi-Fi", "enforce_blocks": True}).encode()
    status, _, body = call(server, "POST", "/capture/start", body=payload)
    assert status == 200 and body == {"called": "start"}
    assert call(server, "POST", "/capture/stop", body=b"")[2] == {"called": "stop"}
    assert call(server, "POST", "/network-scan/start", body=b'{"target": "192.168.1.0/24"}')[0] == 202
    assert call(server, "POST", "/network-scan/stop", body=b"{}")[2] == {"called": "stop_discovery"}
    assert call(server, "POST", "/unknown", body=b"{}")[0] == 404
    assert server.supervisor.calls[0] == ("start", {"interface": "Wi-Fi", "enforce_blocks": True})


def test_bad_requests_are_refused_without_reaching_the_supervisor(server) -> None:
    assert call(server, "POST", "/capture/start", body=b"x" * 5000)[0] == 413
    assert call(server, "POST", "/capture/start", body=b"not json")[0] == 400
    assert call(server, "POST", "/capture/start", body=b"[1, 2]")[0] == 400
    assert server.supervisor.calls == []


def test_errors_map_to_status_codes(server) -> None:
    server.supervisor.error = ValueError("Choose an active network adapter first.")
    assert call(server, "POST", "/capture/start", body=b"{}")[0] == 400
    server.supervisor.error = RuntimeError("The sensor is already running on this computer.")
    status, _, body = call(server, "POST", "/capture/start", body=b"{}")
    assert status == 409 and "already running" in body["error"]
    server.supervisor.error = KeyError("boom")
    status, _, body = call(server, "POST", "/capture/stop", body=b"{}")
    assert status == 500 and len(body["error"]) < 260


def test_project_credentials_are_read_from_env_without_being_exposed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(controller, "PROJECT_ROOT", tmp_path)
    with pytest.raises(RuntimeError, match=".env file is missing"):
        read_project_credentials()
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "SECRET_KEY=not-the-sensor\n"
        'SENTINEL_SENSOR_EMAIL="sensor@example.test"\n'
        "SENTINEL_SENSOR_PASSWORD='p@ss=word'\n",
        encoding="utf-8-sig",
    )
    assert read_project_credentials() == ("sensor@example.test", "p@ss=word")
    env.write_text("SENTINEL_SENSOR_EMAIL=sensor@example.test\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as error:
        read_project_credentials()
    assert "SENTINEL_SENSOR_PASSWORD" in str(error.value)
