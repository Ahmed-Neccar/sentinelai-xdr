"""Offline training. Never invoked from HTTP handlers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import settings
from app.detection.ml.features import FEATURE_NAMES, FEATURE_VERSION, extract_entity_features
from app.detection.ml.leakage import entity_aware_split


def _require_sklearn():
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
    except ImportError as exc:
        raise SystemExit("scikit-learn is required. Install backend/requirements-ml.txt") from exc
    return IsolationForest, confusion_matrix, precision_recall_fscore_support


def train_from_events(events: list[dict], output_dir: str | None = None) -> dict:
    IsolationForest, confusion_matrix, prfs = _require_sklearn()
    import joblib

    rows = extract_entity_features(events)
    train_rows, test_rows = entity_aware_split(rows)
    if len(train_rows) < 4 or not test_rows:
        raise ValueError("Not enough distinct entities for an entity-aware train/test split")
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit([row["vector"] for row in train_rows])
    threshold = 0.0
    pred = [
        int(v < threshold) for v in model.decision_function([row["vector"] for row in test_rows])
    ]
    labels = [int(bool(row.get("label"))) for row in test_rows]
    precision, recall, f1, _ = prfs(labels, pred, average="binary", zero_division=0)
    cm = confusion_matrix(labels, pred, labels=[0, 1]).tolist()
    out = Path(output_dir or settings.ml_artifact_dir)
    out.mkdir(parents=True, exist_ok=True)
    artifact = out / "isolation_forest.joblib"
    joblib.dump(model, artifact)
    checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
    meta = {
        "model_version": "iforest-v1",
        "algorithm": "IsolationForest",
        "preprocessing_version": FEATURE_VERSION,
        "dataset_version": "synthetic-v1",
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "checksum_sha256": checksum,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "confusion_matrix": cm,
            "note": (
                "Metrics require labels on synthetic entities. "
                "Decision scores are not probabilities."
            ),
        },
        "split": {
            "method": "entity_aware",
            "train_entities": len(train_rows),
            "test_entities": len(test_rows),
        },
        "limitations": (
            "Trained on synthetic or operator-supplied labels. Isolation Forest is unsupervised; "
            "binary metrics here treat 'label' as a lab tag for comparison only."
        ),
    }
    (out / "isolation_forest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


if __name__ == "__main__":
    print("Use scripts/train_ml.py with a labeled JSON dataset.")
