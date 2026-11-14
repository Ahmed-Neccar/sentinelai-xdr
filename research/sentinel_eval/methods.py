"""The detection methods that are compared.

* ``rules``     the project's built-in rules, run through the same evaluators as ingestion
* ``threshold`` plain whole-period thresholds on sign-in failures and distinct ports, the kind of
                check a log-searching analyst writes first (blind to endpoint and cloud events)
* ``forest``    Isolation Forest on six per-entity counts, unsupervised, the project's optional model
* ``hybrid``    an entity flagged by the rules or by the forest

Each method returns the set of entity ids it flags and, for the rules, which rules fired.
"""

from __future__ import annotations

from collections import defaultdict

from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.evaluate import EventIndex, evaluate_spec
from app.detection.ml.features import extract_entity_features

THRESHOLD_FAILURES = 10
THRESHOLD_PORTS = 20


PROCESS_RULE_PREFIXES = ("wmi_spawns_", "process_from_")
PROCESS_RULE_SUFFIX = "_spawns_powershell"
SUPPRESS_AFTER = 3  # findings of the same process rule on one computer, in different windows


def is_process_rule(rule_id: str) -> bool:
    return rule_id.startswith(PROCESS_RULE_PREFIXES) or rule_id.endswith(PROCESS_RULE_SUFFIX)


def run_rules(events: list[dict], specs: list[dict] | None = None) -> dict[str, dict[str, int]]:
    """Map entity id to {rule id: number of findings (windows)} backed by the entity's events."""
    if specs is None:
        # What a fresh installation runs: rules that ship switched off are left out.
        specs = [spec for spec in BUILTIN_RULES if spec.get("default_enabled", True)]
    owner = {event["id"]: event["entity"] for event in events}
    index = EventIndex(events)
    fired: dict[str, dict[str, int]] = defaultdict(dict)
    for spec in specs:
        for finding in evaluate_spec(spec, index.for_spec(spec)):
            entities = {owner[i] for i in finding.get("event_ids") or [] if i in owner}
            for entity in entities:
                fired[entity][spec["rule_id"]] = fired[entity].get(spec["rule_id"], 0) + 1
    return fired


def suppress_recurring(fired: dict[str, dict[str, int]], after: int = SUPPRESS_AFTER) -> set[str]:
    """Entities still flagged when recurring process-rule findings are treated as routine.

    A process rule that keeps firing on the same computer in `after` or more different windows
    is taken for scheduled or habitual activity (login scripts, management tooling) and ignored;
    every other finding stands. This is a hypothesis to test, not a shipped feature.
    """
    flagged = set()
    for entity, rules in fired.items():
        if any(not (is_process_rule(rule) and count >= after) for rule, count in rules.items()):
            flagged.add(entity)
    return flagged


def entity_vectors(events: list[dict]) -> dict[str, list[float]]:
    """Feature vectors of the project's anomaly model, keyed by the entity id."""
    rows = extract_entity_features(events)
    owner: dict[str, str] = {}
    for event in events:
        owner.setdefault(str(event.get("src_ip") or event.get("host_id")), event["entity"])
    return {owner[row["entity"]]: row["vector"] for row in rows if row["entity"] in owner}


def run_threshold(vectors: dict[str, list[float]]) -> set[str]:
    # FEATURE_NAMES: failures, successes, conns, unique ports, unique ips, high severity
    return {
        entity for entity, v in vectors.items()
        if v[0] >= THRESHOLD_FAILURES or v[3] >= THRESHOLD_PORTS
    }


def fit_forest(train_vectors: list[list[float]], contamination: float, seed: int = 42):
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=seed)
    model.fit(train_vectors)
    return model


def run_forest(model, vectors: dict[str, list[float]]) -> set[str]:
    entities = list(vectors)
    if not entities:
        return set()
    scores = model.decision_function([vectors[entity] for entity in entities])
    return {entity for entity, score in zip(entities, scores, strict=True) if score < 0.0}
