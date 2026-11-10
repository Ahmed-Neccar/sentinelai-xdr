# ruff: noqa: S311 - seeded synthetic data, not a security use of random
"""Offline evaluation of the optional Isolation Forest anomaly score.

Uses the project's own feature extractor and the same model settings as
app/detection/ml/train.py (100 trees, contamination 0.15, threshold 0.0), on a
seeded SYNTHETIC labelled population. Results describe behaviour under this
generator's assumptions. They are not a false-positive rate for a real network.

Optionally scores per-entity feature vectors exported from a real deployment
(--real-vectors, a CSV of the six feature counts without identifiers). Those
rows are unlabelled, so only a flag rate is reported for them.

Needs scikit-learn and numpy (backend/requirements-ml.txt).
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.detection.ml.features import FEATURE_NAMES, extract_entity_features  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402

COMMON_PORTS = (53, 80, 123, 443)
SERVICE_PORTS = (22, 25, 53, 80, 110, 123, 143, 389, 443, 445, 993, 3306, 3389, 5432, 8080, 8443)
BENIGN_MIX = (
    ("workstation", 0.60),
    ("server", 0.15),
    ("forgetful_user", 0.13),
    ("nat_gateway", 0.08),
    ("monitoring_scanner", 0.04),
)
ATTACKS = ("brute_force", "port_scan", "slow_brute_force", "lateral_sweep")
START = datetime(2026, 1, 1, tzinfo=UTC)


def _conns(rng: random.Random, entity: str, count: int, ips: int, ports: list[int]) -> list[dict]:
    targets = [f"192.0.2.{rng.randrange(1, 255)}.{i}" for i in range(max(ips, 1))]
    return [
        {
            "src_ip": entity,
            "event_type": "net.conn",
            "dst_ip": rng.choice(targets),
            "dst_port": rng.choice(ports),
            "severity": "low",
            "event_time": START + timedelta(seconds=rng.randrange(7200)),
        }
        for _ in range(count)
    ]


def _auth(entity: str, failures: int, successes: int) -> list[dict]:
    return [
        {"src_ip": entity, "event_type": kind, "severity": "low", "event_time": START}
        for kind, total in (("auth.failure", failures), ("auth.success", successes))
        for _ in range(total)
    ]


def entity_events(rng: random.Random, entity: str, profile: str) -> list[dict]:
    r = rng.randint
    if profile == "workstation":
        events = _conns(rng, entity, r(20, 150), r(3, 15), rng.sample(COMMON_PORTS, r(2, 4)))
        events += _auth(entity, r(0, 2), r(1, 6))
    elif profile == "forgetful_user":
        events = _conns(rng, entity, r(20, 150), r(3, 15), rng.sample(COMMON_PORTS, r(2, 4)))
        events += _auth(entity, r(3, 8), r(1, 6))
    elif profile == "server":
        events = _conns(rng, entity, r(100, 600), r(5, 40), rng.sample(SERVICE_PORTS, r(3, 8)))
        events += _auth(entity, r(0, 1), r(0, 3))
    elif profile == "nat_gateway":
        events = _conns(rng, entity, r(500, 2000), r(40, 150), rng.sample(SERVICE_PORTS, r(5, 12)))
        events += _auth(entity, r(0, 6), r(5, 30))
    elif profile == "monitoring_scanner":
        ports = rng.sample(range(1, 1024), r(20, 60))
        events = _conns(rng, entity, r(100, 300), r(10, 30), ports)
    elif profile == "brute_force":
        events = _conns(rng, entity, r(0, 20), r(1, 2), [22]) + _auth(entity, r(30, 300), r(0, 1))
    elif profile == "port_scan":
        ports = rng.sample(range(1, 10000), r(80, 800))
        events = _conns(rng, entity, len(ports) + r(0, 200), r(1, 3), ports)
    elif profile == "slow_brute_force":
        events = _conns(rng, entity, r(20, 150), r(3, 15), rng.sample(COMMON_PORTS, r(2, 4)))
        events += _auth(entity, r(6, 12), r(0, 2))
    elif profile == "lateral_sweep":
        events = _conns(rng, entity, r(50, 250), r(40, 200), rng.sample((445, 3389), r(1, 2)))
    else:
        raise ValueError(profile)
    return events


def population(rng: random.Random, size: int, prevalence: float) -> list[dict]:
    """Return feature rows (project extractor) with profile and label attached."""
    malicious = round(size * prevalence)
    profiles = [ATTACKS[i % len(ATTACKS)] for i in range(malicious)]
    names, weights = zip(*BENIGN_MIX, strict=True)
    profiles += rng.choices(names, weights=weights, k=size - malicious)
    events: list[dict] = []
    by_entity = {}
    for index, profile in enumerate(profiles):
        entity = f"e{index:05d}"
        by_entity[entity] = profile
        events += entity_events(rng, entity, profile)
    rows = extract_entity_features(events)
    for row in rows:
        row["profile"] = by_entity[row["entity"]]
        row["malicious"] = row["profile"] in ATTACKS
    return rows


def baseline_flags(row: dict) -> bool:
    """Plain thresholds as a reference point. Not the project's rule engine."""
    features = row["features"]
    return features["auth_failure_count"] >= 10 or features["unique_dst_ports"] >= 20


def evaluate(seed: int, size: int, prevalence: float, contamination: float) -> dict:
    rng = random.Random(seed)
    rows = population(rng, size, prevalence)
    rng.shuffle(rows)
    cut = int(len(rows) * 0.7)
    train, test = rows[:cut], rows[cut:]
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit([row["vector"] for row in train])
    flagged = [score < 0.0 for score in model.decision_function([row["vector"] for row in test])]
    result: dict = {"per_profile": {}}
    for name, flags in (("model", flagged), ("baseline", [baseline_flags(row) for row in test])):
        tp = sum(f and row["malicious"] for f, row in zip(flags, test, strict=True))
        fp = sum(f and not row["malicious"] for f, row in zip(flags, test, strict=True))
        positives = sum(row["malicious"] for row in test)
        negatives = len(test) - positives
        result[name] = {
            "false_positive_rate": fp / negatives if negatives else 0.0,
            "recall": tp / positives if positives else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "flag_rate": (tp + fp) / len(test),
        }
    for profile in [name for name, _ in BENIGN_MIX] + list(ATTACKS):
        hits = [f for f, row in zip(flagged, test, strict=True) if row["profile"] == profile]
        if hits:
            result["per_profile"][profile] = sum(hits) / len(hits)
    return result


def summarise(values: list[float | None]) -> dict | None:
    numbers = [value for value in values if value is not None]
    if not numbers:
        return None
    return {
        "mean": round(statistics.fmean(numbers), 4),
        "sd": round(statistics.pstdev(numbers), 4),
        "min": round(min(numbers), 4),
        "max": round(max(numbers), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entities", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--real-vectors", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report: dict = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "features": FEATURE_NAMES,
        "entities_per_run": args.entities,
        "seeds": args.seeds,
        "threshold": 0.0,
        "synthetic": [],
    }
    for contamination in (0.15, 0.05, 0.01):
        for prevalence in (0.0, 0.01, 0.05, 0.15):
            runs = [
                evaluate(seed, args.entities, prevalence, contamination)
                for seed in range(args.seeds)
            ]
            entry = {"contamination": contamination, "prevalence": prevalence}
            for name in ("model", "baseline"):
                entry[name] = {
                    metric: summarise([run[name][metric] for run in runs])
                    for metric in ("false_positive_rate", "recall", "precision", "flag_rate")
                }
            profiles = sorted({key for run in runs for key in run["per_profile"]})
            entry["model_flag_rate_by_profile"] = {
                key: round(statistics.fmean(run["per_profile"].get(key, 0.0) for run in runs), 3)
                for key in profiles
            }
            report["synthetic"].append(entry)
            model = entry["model"]
            print(
                f"contamination={contamination:<5} prevalence={prevalence:<5} "
                f"FPR={model['false_positive_rate']['mean']:.3f} "
                f"recall={(model['recall'] or {}).get('mean')} "
                f"precision={(model['precision'] or {}).get('mean')}",
                flush=True,
            )

    if args.real_vectors:
        with args.real_vectors.open(encoding="utf-8-sig", newline="") as stream:
            vectors = [[float(value) for value in line] for line in csv.reader(stream) if line]
        real: dict = {"entities": len(vectors), "labelled": False, "results": []}
        for contamination in (0.15, 0.05, 0.01):
            own = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
            own.fit(vectors)
            synthetic_rows = population(random.Random(0), args.entities, 0.0)
            transfer = IsolationForest(
                n_estimators=100, contamination=contamination, random_state=42
            ).fit([row["vector"] for row in synthetic_rows])
            real["results"].append(
                {
                    "contamination": contamination,
                    "flag_rate_trained_on_same_real_data": round(
                        sum(s < 0 for s in own.decision_function(vectors)) / len(vectors), 4
                    ),
                    "flag_rate_trained_on_synthetic_benign": round(
                        sum(s < 0 for s in transfer.decision_function(vectors)) / len(vectors), 4
                    ),
                }
            )
        real["baseline_flag_rate"] = round(
            sum(v[0] >= 10 or v[3] >= 20 for v in vectors) / len(vectors), 4
        )
        report["real_unlabelled"] = real
        print("real", json.dumps(real), flush=True)

    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("report written", args.output)


if __name__ == "__main__":
    main()
