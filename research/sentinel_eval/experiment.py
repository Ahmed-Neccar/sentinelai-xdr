"""Runs the comparison over many seeded simulations and pools the counts."""

from __future__ import annotations

import random
import statistics
from collections import defaultdict

from sentinel_eval import methods
from sentinel_eval.metrics import Confusion, precision_at_prevalence, summarise
from sentinel_eval.simulate import ATTACKS, BENIGN_ROLES, Simulation, hard_share

METHODS = ("rules", "suppressed", "threshold", "forest", "hybrid")


def one_run(seed: int, size: int, prevalence: float, contamination: float, use_forest: bool = True,
            hard_scale: float = 1.0) -> dict:
    """Simulate once; return per-method flags for the held-out entities."""
    sim = Simulation(seed, size, prevalence, hard_scale)
    fired = methods.run_rules(sim.events)
    vectors = methods.entity_vectors(sim.events)

    rng = random.Random(seed * 7919 + 1)  # noqa: S311 - seeded split
    ids = [entity.entity_id for entity in sim.entities]
    rng.shuffle(ids)
    cut = int(len(ids) * 0.7)
    train_ids, test_ids = set(ids[:cut]), set(ids[cut:])

    flagged: dict[str, set[str]] = {
        "rules": set(fired),
        "suppressed": methods.suppress_recurring(fired),
        "threshold": methods.run_threshold(vectors),
    }
    if use_forest:
        training = [vector for entity, vector in vectors.items() if entity in train_ids]
        model = methods.fit_forest(training, contamination)
        flagged["forest"] = methods.run_forest(model, {k: v for k, v in vectors.items() if k in test_ids})
        flagged["hybrid"] = flagged["rules"] | flagged["forest"]
    return {
        "entities": [e for e in sim.entities if e.entity_id in test_ids],
        "flagged": flagged,
        "fired": {entity: sorted(rules) for entity, rules in fired.items() if entity in test_ids},
    }


def evaluate(seeds: int, size: int, prevalence: float, contamination: float = 0.05, hard_scale: float = 1.0) -> dict:
    total = {name: Confusion() for name in METHODS}
    per_seed_f1: dict[str, list[float]] = defaultdict(list)
    by_family: dict[str, dict[str, Confusion]] = {name: defaultdict(Confusion) for name in METHODS}
    by_role: dict[str, dict[str, Confusion]] = {name: defaultdict(Confusion) for name in METHODS}
    rule_hits: dict[str, dict[str, int]] = defaultdict(lambda: {"true_positive_entities": 0, "false_positive_entities": 0})

    for seed in range(seeds):
        run = one_run(seed, size, prevalence, contamination, hard_scale=hard_scale)
        seed_counts = {name: Confusion() for name in METHODS}
        for entity in run["entities"]:
            for name in METHODS:
                predicted = entity.entity_id in run["flagged"][name]
                total[name].add(predicted, entity.malicious)
                seed_counts[name].add(predicted, entity.malicious)
                (by_family if entity.malicious else by_role)[name][entity.role].add(predicted, entity.malicious)
            for rule_id in run["fired"].get(entity.entity_id, []):
                key = "true_positive_entities" if entity.malicious else "false_positive_entities"
                rule_hits[rule_id][key] += 1
        for name in METHODS:
            f1 = seed_counts[name].f1
            if f1 is not None:
                per_seed_f1[name].append(f1)

    result: dict = {
        "seeds": seeds,
        "entities_per_run": size,
        "prevalence": prevalence,
        "contamination": contamination,
        "hard_scale": hard_scale,
        "hard_share_of_benign": round(hard_share(hard_scale), 3),
        "methods": {},
        "rule_hits": dict(sorted(rule_hits.items())),
    }
    for name in METHODS:
        confusion = total[name]
        entry = summarise(confusion)
        spread = per_seed_f1.get(name) or []
        entry["f1_seed_sd"] = round(statistics.pstdev(spread), 4) if len(spread) > 1 else None
        entry["recall_by_attack"] = {
            role: round(c.recall, 3) for role, c in sorted(by_family[name].items()) if c.recall is not None
        }
        entry["false_positive_rate_by_benign_role"] = {
            role: round(c.false_positive_rate, 3)
            for role, c in sorted(by_role[name].items()) if c.false_positive_rate is not None
        }
        result["methods"][name] = entry
    result["attack_families"] = ATTACKS
    result["benign_roles"] = list(BENIGN_ROLES)
    return result


def prevalence_sweep(seeds: int, size: int, measured: dict, prevalences=(0.001, 0.01, 0.05, 0.10, 0.20)) -> dict:
    """Precision each method would have if attackers were rarer or more common than in the test."""
    sweep: dict = {}
    for name in METHODS:
        entry = measured["methods"][name]
        sweep[name] = {
            str(p): (None if (v := precision_at_prevalence(entry["recall"], entry["false_positive_rate"], p)) is None
                     else round(v, 4))
            for p in prevalences
        }
    return sweep


def evaluate_events(events: list[dict], labels: dict[str, str], contamination: float = 0.05, seed: int = 0) -> dict:
    """Same comparison on an existing labelled event set (for example converted public data).

    `events` carry an `entity` field; `labels` maps each entity to "benign" or an attack family.
    One run, a 70/30 split of the entities, no repetition.
    """
    fired = methods.run_rules(events)
    vectors = methods.entity_vectors(events)
    rng = random.Random(seed)  # noqa: S311 - seeded split
    ids = sorted(labels)
    rng.shuffle(ids)
    cut = int(len(ids) * 0.7)
    train_ids, test_ids = set(ids[:cut]), set(ids[cut:])
    model = methods.fit_forest([v for e, v in vectors.items() if e in train_ids], contamination)
    flagged = {
        "rules": set(fired),
        "suppressed": methods.suppress_recurring(fired),
        "threshold": methods.run_threshold(vectors),
        "forest": methods.run_forest(model, {k: v for k, v in vectors.items() if k in test_ids}),
    }
    flagged["hybrid"] = flagged["rules"] | flagged["forest"]
    total = {name: Confusion() for name in METHODS}
    by_family: dict[str, dict[str, Confusion]] = {name: defaultdict(Confusion) for name in METHODS}
    by_role: dict[str, dict[str, Confusion]] = {name: defaultdict(Confusion) for name in METHODS}
    for entity in sorted(test_ids):
        malicious = labels[entity] != "benign"
        for name in METHODS:
            predicted = entity in flagged[name]
            total[name].add(predicted, malicious)
            (by_family if malicious else by_role)[name][labels[entity]].add(predicted, malicious)
    result: dict = {
        "seeds": 1, "entities_per_run": len(test_ids), "prevalence": None, "contamination": contamination,
        "methods": {}, "rule_hits": {},
        "attack_families": {family: "dataset" for family in sorted(set(labels.values()) - {"benign"})},
        "benign_roles": ["benign"],
    }
    for name in METHODS:
        entry = summarise(total[name])
        entry["f1_seed_sd"] = None
        entry["recall_by_attack"] = {k: round(c.recall, 3) for k, c in sorted(by_family[name].items()) if c.recall is not None}
        entry["false_positive_rate_by_benign_role"] = {
            k: round(c.false_positive_rate, 3) for k, c in sorted(by_role[name].items()) if c.false_positive_rate is not None
        }
        result["methods"][name] = entry
    return result


# What each count-based rule is meant to catch, for the threshold sweep.
RULE_TARGETS = {
    "auth_bruteforce": ("brute_force_fast", "brute_force_then_success"),
    "auth_bruteforce_username": ("brute_force_fast", "slow_brute_force"),
    "suspicious_login_pattern": ("brute_force_then_success",),
    "password_spray": ("password_spray", "slow_spray"),
    "port_scan_like": ("port_scan_fast", "port_scan_slow"),
    "unusual_conn_volume": ("lateral_sweep", "port_scan_fast"),
}
SWEEP_GRIDS = {
    "auth_bruteforce": ("threshold", (3, 5, 8, 12, 20, 40)),
    "auth_bruteforce_username": ("threshold", (3, 5, 10, 20, 40)),
    "suspicious_login_pattern": ("min_failures", (2, 3, 5, 8, 12)),
    "password_spray": ("threshold", (3, 4, 6, 8, 12, 16)),
    "port_scan_like": ("threshold", (5, 8, 12, 20, 40, 80)),
    "unusual_conn_volume": ("threshold", (20, 40, 80, 160, 320)),
}


def threshold_sweep(seeds: int, size: int, prevalence: float, hard_scale: float = 1.0) -> dict:
    """Move one rule's threshold at a time and measure it on the families it is meant for.

    Recall is taken over the attack families the rule targets, the false positive rate over every
    benign entity. Plotting one against the other shows the trade-off the default threshold sits on.
    The same simulated networks are used for every threshold value.
    """
    from app.detection.builtin_rules import BUILTIN_RULES

    base = {spec["rule_id"]: spec for spec in BUILTIN_RULES}
    sims = [Simulation(seed, size, prevalence, hard_scale) for seed in range(seeds)]
    result: dict = {}
    for rule_id, (parameter, grid) in SWEEP_GRIDS.items():
        points = []
        for value in grid:
            spec = {**base[rule_id], parameter: value}
            confusion = Confusion()
            for sim in sims:
                fired = methods.run_rules(sim.events, [spec])
                for entity in sim.entities:
                    if entity.malicious and entity.role not in RULE_TARGETS[rule_id]:
                        continue
                    confusion.add(entity.entity_id in fired, entity.malicious)
            entry = summarise(confusion)
            points.append({
                "value": value,
                "default": value == base[rule_id].get(parameter),
                "recall": entry["recall"],
                "false_positive_rate": entry["false_positive_rate"],
                "false_positive_rate_ci95": entry["false_positive_rate_ci95"],
                "precision": entry["precision"],
            })
        result[rule_id] = {"parameter": parameter, "targets": list(RULE_TARGETS[rule_id]), "points": points}
    return result
