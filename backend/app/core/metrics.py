"""Small, dependency-free Prometheus exposition for HTTP service metrics."""

import threading
from collections import defaultdict
from typing import TypedDict

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class HistogramState(TypedDict):
    count: int
    sum: float
    buckets: list[int]


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class HttpMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: defaultdict[tuple[str, str, str], int] = defaultdict(int)
        self._durations: dict[tuple[str, str, str], HistogramState] = {}

    def observe(self, method: str, route: str, status: int, duration: float) -> None:
        key = (method, route, str(status))
        with self._lock:
            self._requests[key] += 1
            histogram = self._durations.setdefault(
                key,
                {
                    "count": 0,
                    "sum": 0.0,
                    "buckets": [0] * (len(BUCKETS) + 1),
                },
            )
            histogram["count"] += 1
            histogram["sum"] += duration
            counts = histogram["buckets"]
            for index, bound in enumerate(BUCKETS):
                if duration <= bound:
                    counts[index] += 1
            counts[-1] += 1

    def render(self) -> str:
        with self._lock:
            requests = list(self._requests.items())
            durations: list[tuple[tuple[str, str, str], HistogramState]] = [
                (
                    key,
                    {
                        "count": value["count"],
                        "sum": value["sum"],
                        "buckets": list(value["buckets"]),
                    },
                )
                for key, value in self._durations.items()
            ]

        lines = [
            "# HELP sentinel_http_requests_total Total HTTP requests handled by this process.",
            "# TYPE sentinel_http_requests_total counter",
        ]
        for (method, route, status), count in requests:
            labels = (
                f'method="{_escape_label(method)}",route="{_escape_label(route)}",'
                f'status="{_escape_label(status)}"'
            )
            lines.append(f"sentinel_http_requests_total{{{labels}}} {count}")

        lines.extend(
            [
                "# HELP sentinel_http_request_duration_seconds HTTP request duration in seconds.",
                "# TYPE sentinel_http_request_duration_seconds histogram",
            ]
        )
        for (method, route, status), histogram in durations:
            labels = (
                f'method="{_escape_label(method)}",route="{_escape_label(route)}",'
                f'status="{_escape_label(status)}"'
            )
            counts = histogram["buckets"]
            for index, bound in enumerate(BUCKETS):
                lines.append(
                    f'sentinel_http_request_duration_seconds_bucket{{{labels},le="{bound:g}"}} '
                    f"{counts[index]}"
                )
            lines.append(
                f'sentinel_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} '
                f"{counts[-1]}"
            )
            lines.append(
                f"sentinel_http_request_duration_seconds_count{{{labels}}} "
                f"{histogram['count']}"
            )
            lines.append(
                f"sentinel_http_request_duration_seconds_sum{{{labels}}} "
                f"{histogram['sum']:.9f}"
            )
        return "\n".join(lines) + "\n"


http_metrics = HttpMetrics()
