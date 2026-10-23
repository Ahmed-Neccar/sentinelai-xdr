from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.detection.ml.features import FEATURE_VERSION, extract_entity_features


def score_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Isolation Forest scoring. Score is not a probability."""
    artifact = Path(settings.ml_artifact_dir) / "isolation_forest.json"
    model_path = Path(settings.ml_artifact_dir) / "isolation_forest.joblib"
    if not artifact.exists() or not model_path.exists():
        return []
    try:
        import joblib
    except ImportError:
        return []
    try:
        meta = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    if not isinstance(meta, dict) or meta.get("preprocessing_version") != FEATURE_VERSION:
        return []
    expected_checksum = meta.get("checksum_sha256")
    if not isinstance(expected_checksum, str) or len(expected_checksum) != 64:
        return []
    try:
        actual_checksum = hashlib.sha256(model_path.read_bytes()).hexdigest()
    except OSError:
        return []
    if not hmac.compare_digest(actual_checksum, expected_checksum.lower()):
        return []
    try:
        model = joblib.load(model_path)
    except Exception:
        return []
    rows = extract_entity_features(events)
    if not rows:
        return []
    matrix = [row["vector"] for row in rows]
    try:
        scores = model.decision_function(matrix)
        raw = model.score_samples(matrix)
    except Exception:
        return []
    threshold = float(meta.get("threshold", -0.2))
    findings = []
    for row, decision, sample in zip(rows, scores, raw, strict=True):
        if decision >= threshold:
            continue
        findings.append(
            {
                "rule_id": None,
                "rule_version": None,
                "model_version": meta.get("model_version"),
                "title": "Experimental anomaly score (Isolation Forest)",
                "severity": "low",
                "summary": (
                    f"Entity {row['entity']} received an Isolation Forest decision score of "
                    f"{float(decision):.4f} (threshold {threshold}). This is not a probability "
                    "and is not proof of malicious activity."
                ),
                "fingerprint": (
                    f"iforest|{meta.get('model_version')}|{row['entity']}|{row['window']}"
                ),
                "evidence": {
                    "entity": row["entity"],
                    "features": row["features"],
                    "decision_score": float(decision),
                    "score_samples": float(sample),
                    "threshold": threshold,
                    "explanation_note": "Feature values are inputs to the model, not causal proof.",
                },
                "mitre": [],
                "event_ids": row.get("event_ids") or [],
                "score": float(decision),
                "score_kind": "isolation_forest_decision_function",
            }
        )
    return findings
