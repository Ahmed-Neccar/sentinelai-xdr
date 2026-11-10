# ruff: noqa: S311, S603, S607 - seeded test data and a fixed local docker command
"""Synthetic load test for an ISOLATED SentinelAI stack.

Run it through run_load_test.ps1, which starts a separate Compose project with
its own database. Never point it at a deployment that holds real telemetry: it
uploads synthetic events and would trigger detections and notifications.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import httpx

PORTS = (22, 53, 80, 123, 443, 445, 3389, 8080)


def make_events(count: int, seed: int, file_index: int) -> bytes:
    """Mostly routine traffic from 200 sources inside the 2-hour detection window."""
    rng = random.Random(seed * 1000 + file_index)
    now = datetime.now(UTC)
    events = []
    for index in range(count):
        source = f"10.{20 + rng.randrange(4)}.{rng.randrange(50)}.{1 + rng.randrange(200) % 250}"
        moment = now - timedelta(seconds=rng.uniform(60, 5400))
        roll = rng.random()
        event = {
            "event_time": moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "src_ip": source,
            "host_id": f"load-host-{rng.randrange(200):03d}",
            "severity": "low",
            "message": f"synthetic load f{file_index} n{index} s{seed}",
        }
        if roll < 0.90:
            event.update(
                event_type="net.conn",
                dst_ip=f"192.0.2.{1 + rng.randrange(40)}",
                dst_port=rng.choice(PORTS),
            )
        elif roll < 0.98:
            event.update(event_type="auth.success", username=f"user{rng.randrange(300)}")
        else:
            event.update(event_type="auth.failure", username=f"user{rng.randrange(300)}")
        events.append(event)
    return json.dumps({"dataset": "load-test", "events": events}, separators=(",", ":")).encode()


class Api:
    def __init__(self, base: str, email: str, password: str) -> None:
        self.base, self.email, self.password = base.rstrip("/"), email, password
        self.client = httpx.Client(timeout=60, limits=httpx.Limits(max_connections=80))
        self.lock = threading.Lock()
        self.token = ""
        deadline = time.perf_counter() + 120
        while True:  # `compose up -d` returns before the API accepts connections
            try:
                if self.client.get(f"{self.base}/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.perf_counter() > deadline:
                raise SystemExit("The test API did not become ready within 120 seconds.")
            time.sleep(1)
        self.login()

    def login(self) -> None:
        with self.lock:
            response = self.client.post(
                f"{self.base}/auth/login",
                json={
                    "email": self.email,
                    "password": self.password,
                    "organization_slug": "default",
                },
            )
            response.raise_for_status()
            self.token = response.json()["access_token"]

    def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        for _ in range(2):
            response = self.client.request(
                method,
                f"{self.base}{path}",
                headers={"Authorization": f"Bearer {self.token}"},
                **kwargs,
            )
            if response.status_code != 401:
                return response
            self.login()
        return response


def ingest_file(api: Api, payload: bytes, name: str, timeout: float) -> dict:
    started = time.perf_counter()
    response = api.request(
        "POST",
        "/ingest/upload",
        files={"file": (name, payload, "application/json")},
        data={"adapter": "generic_json"},
    )
    response.raise_for_status()
    job_id = response.json()["id"]
    accepted_at = time.perf_counter()
    status, stats = "queued", {}
    while time.perf_counter() - started < timeout:
        job = api.request("GET", f"/ingest/jobs/{job_id}").json()
        status, stats = job.get("status"), job.get("stats") or {}
        if status in {"completed", "failed"}:
            break
        time.sleep(0.5)
    return {
        "status": status if status in {"completed", "failed"} else "timeout",
        "upload_s": round(accepted_at - started, 2),
        "total_s": round(time.perf_counter() - started, 2),
        "accepted": stats.get("accepted"),
        "detections": stats.get("detections_created", stats.get("detections")),
    }


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))]


def read_load(api: Api, path: str, concurrency: int, seconds: float) -> dict:
    latencies: list[float] = []
    errors = 0
    lock = threading.Lock()
    deadline = time.perf_counter() + seconds

    def worker() -> None:
        nonlocal errors
        while time.perf_counter() < deadline:
            started = time.perf_counter()
            try:
                ok = api.request("GET", path).status_code == 200
            except httpx.HTTPError:
                ok = False
            elapsed = (time.perf_counter() - started) * 1000
            with lock:
                if ok:
                    latencies.append(elapsed)
                else:
                    errors += 1

    with ThreadPoolExecutor(concurrency) as pool:
        for _ in range(concurrency):
            pool.submit(worker)
    if not latencies:
        return {"path": path, "concurrency": concurrency, "requests": 0, "errors": errors}
    return {
        "path": path,
        "concurrency": concurrency,
        "requests": len(latencies),
        "errors": errors,
        "rps": round(len(latencies) / seconds, 1),
        "p50_ms": round(statistics.median(latencies)),
        "p95_ms": round(percentile(latencies, 95)),
        "p99_ms": round(percentile(latencies, 99)),
        "max_ms": round(max(latencies)),
    }


class StatsSampler(threading.Thread):
    """Record peak CPU and memory per container of the test project."""

    def __init__(self, project: str) -> None:
        super().__init__(daemon=True)
        self.project, self.peaks, self.stop_flag = project, {}, threading.Event()

    def run(self) -> None:
        while not self.stop_flag.is_set():
            try:
                output = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                ).stdout
                for line in output.splitlines():
                    row = json.loads(line)
                    name = row.get("Name", "")
                    if not name.startswith(self.project + "-"):
                        continue
                    cpu = float(row["CPUPerc"].rstrip("%") or 0)
                    mem = row["MemUsage"].split("/")[0].strip()
                    factor = 1024 if mem.endswith("GiB") else 1 if mem.endswith("MiB") else 0.001
                    mem_mib = float("".join(c for c in mem if c.isdigit() or c == ".")) * factor
                    peak = self.peaks.setdefault(name, {"cpu_pct": 0.0, "mem_mib": 0.0})
                    peak["cpu_pct"] = max(peak["cpu_pct"], cpu)
                    peak["mem_mib"] = round(max(peak["mem_mib"], mem_mib))
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            self.stop_flag.wait(3)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:18001/api/v1")
    parser.add_argument("--project", default="sentinelai-loadtest")
    parser.add_argument("--files", type=int, default=8)
    parser.add_argument("--events-per-file", type=int, default=20000)
    parser.add_argument("--job-timeout", type=float, default=300)
    parser.add_argument("--stop-after", type=float, default=150)
    parser.add_argument("--read-seconds", type=float, default=12)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if ":8001" in args.base:
        raise SystemExit("Refusing to run against the default API port; use the isolated stack.")

    api = Api(args.base, os.environ["LOADTEST_ADMIN_EMAIL"], os.environ["LOADTEST_ADMIN_PASSWORD"])
    sampler = StatsSampler(args.project)
    sampler.start()
    report: dict = {
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "args": vars(args),
    }

    ingestion = []
    total_events = 0
    for index in range(args.files):
        payload = make_events(args.events_per_file, args.seed, index)
        result = ingest_file(api, payload, f"load-{index}.json", args.job_timeout)
        result["file"], result["bytes"] = index, len(payload)
        result["events_before"] = total_events
        if result["status"] == "completed" and result["accepted"]:
            total_events += int(result["accepted"])
            result["events_per_s"] = round(int(result["accepted"]) / result["total_s"])
        ingestion.append(result)
        print("ingest", result, flush=True)
        if result["status"] != "completed" or result["total_s"] > args.stop_after:
            break
    report["ingestion_sequential"] = ingestion
    report["events_loaded"] = total_events

    reads = []
    for path in (
        "/events?page_size=50",
        "/events?page_size=50&event_type=auth.failure",
        "/events?page_size=50&q=n123",
        "/detections",
        "/cases",
        "/hosts",
    ):
        for concurrency in (1, 8, 32):
            result = read_load(api, path, concurrency, args.read_seconds)
            reads.append(result)
            print("read", result, flush=True)
    report["reads"] = reads

    payload = make_events(args.events_per_file, args.seed, 900)
    with ThreadPoolExecutor(2) as pool:
        ingest_future = pool.submit(ingest_file, api, payload, "load-mixed.json", args.job_timeout)
        read_future = pool.submit(read_load, api, "/events?page_size=50", 8, args.read_seconds * 2)
        report["mixed"] = {"ingest": ingest_future.result(), "reads": read_future.result()}
    print("mixed", report["mixed"], flush=True)

    sampler.stop_flag.set()
    sampler.join(timeout=25)
    report["container_peaks"] = sampler.peaks
    report["finished_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print("report written", args.output)


if __name__ == "__main__":
    main()
