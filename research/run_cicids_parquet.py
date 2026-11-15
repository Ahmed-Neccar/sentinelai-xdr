"""Measure the network rules on the full CIC-IDS2017 flow data (benign and attack, real timestamps).

    pip install pyarrow numpy scikit-learn
    python research/run_cicids_parquet.py flows.parquet --output-dir research/results

The input is the ``Network-Flows/CICIDS_Flow.parquet`` file of the Hugging Face copy
``rdpahalavan/CIC-IDS2017`` (2,827,677 flows with source and destination address, destination
port, a date-and-time stamp and a label). Each flow becomes one ``net.conn`` event; the entity is
the source address; an entity is an attacker if any of its flows carries an attack label.

Windowed rules need real time, so the timestamps are handled with care: they are day-first, not
zero padded, sometimes without seconds, and the afternoon hours are on a 12-hour clock without
AM/PM (the capture ran from about 09:00 to 17:00, so hours 1 to 7 are taken as 13 to 19).

What this can show: how the *network* rules (port scan, connection volume, DNS volume, and the
experimental slow rules) behave on real traffic with real benign hosts. What it cannot: anything
about sign-in, process or cloud rules (flow data has none of those events). SSH-Patator and
FTP-Patator are brute-force attacks, but flows carry no failed-login events, so the sign-in rules
cannot see them.

Citation: I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, "Toward generating a new intrusion
detection dataset and intrusion traffic characterization", ICISSP 2018.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "backend"))

from app.detection.builtin_rules import BUILTIN_RULES  # noqa: E402
from sentinel_eval import methods  # noqa: E402
from sentinel_eval.metrics import Confusion, summarise  # noqa: E402

PATTERN = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?$")
SLOW_RULES = ("auth_bruteforce_username_slow", "password_spray_slow", "port_scan_slow")

# Flow-direction preprocessing candidates, fixed before any result was seen. In this data many flows
# have the remote server as "source", so the destination port is the internal client's ephemeral
# port. A candidate keeps only flows whose destination port looks like a service port.
#   none      - all flows (the first measurement)
#   below1024 - IANA system ports
#   below32768 - everything under the Linux ephemeral range start (32768)
#   below49152 - everything under the IANA dynamic range start (registered ports kept)
CANDIDATES = ("none", "below1024", "below32768", "below49152")
CUTOFFS = {"below1024": 1024, "below32768": 32768, "below49152": 49152}


def keep_flow(candidate: str, port) -> bool:
    if candidate == "none":
        return True
    if port is None:
        return False
    return int(port) < CUTOFFS[candidate]


def parse(stamp: str) -> float | None:
    match = PATTERN.match(stamp.strip())
    if not match:
        return None
    day, month, year, hour, minute, second = match.groups()
    hour = int(hour)
    if hour < 8:  # 12-hour clock without AM/PM: the afternoon
        hour += 12
    try:
        return datetime(int(year), int(month), int(day), hour, int(minute), int(second or 0), tzinfo=UTC).timestamp()
    except ValueError:
        return None


def pct(value: float | None) -> str:
    return "-" if value is None else f"%{value * 100:.1f}".replace(".", ",")


def pct_ci(value: float | None, ci: list[float] | None) -> str:
    if value is None:
        return "-"
    return pct(value) if not ci else f"{pct(value)} [{pct(ci[0])}–{pct(ci[1])}]"


def main() -> int:
    import pyarrow.parquet as pq

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("parquet", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--candidates", nargs="+", default=list(CANDIDATES), choices=list(CANDIDATES),
                        help="preprocessing candidates; the first is the unprocessed baseline")
    args = parser.parse_args()

    table = pq.read_table(args.parquet, columns=["source_ip", "destination_ip", "destination_port", "Timestamp", "attack_label"])
    src = table.column("source_ip").to_pylist()
    dst = table.column("destination_ip").to_pylist()
    port = table.column("destination_port").to_pylist()
    stamps = table.column("Timestamp").to_pylist()
    label = table.column("attack_label").to_pylist()
    total = len(src)
    print("flows", total, flush=True)

    epochs: list[float | None] = [parse(s) for s in stamps]
    unparsed = sum(e is None for e in epochs)
    order = sorted((i for i in range(total) if epochs[i] is not None), key=lambda i: epochs[i])
    print("unparsed timestamps", unparsed, flush=True)

    attack_labels: dict[str, Counter] = defaultdict(Counter)
    flows_per_entity: Counter = Counter()
    for i in range(total):
        flows_per_entity[src[i]] += 1
        if label[i] != "BENIGN":
            attack_labels[src[i]][label[i]] += 1
    entities = sorted(flows_per_entity)
    malicious = {e: bool(attack_labels.get(e)) for e in entities}
    family = {e: attack_labels[e].most_common(1)[0][0] for e in entities if malicious[e]}

    # Same seeded 70/30 split as the first measurement (the test set is unchanged, so results stay
    # comparable); the 70 % is split again into training (70 %) and validation (30 %). Candidate
    # preprocessing is chosen on the validation set only; the test set is read once, afterwards.
    rng = random.Random(0)  # noqa: S311 - seeded split
    shuffled = entities[:]
    rng.shuffle(shuffled)
    cut = int(len(shuffled) * 0.7)
    rest, test = shuffled[:cut], set(shuffled[cut:])
    rng2 = random.Random(1)  # noqa: S311 - seeded split
    rest = sorted(rest)
    rng2.shuffle(rest)
    cut2 = int(len(rest) * 0.7)
    train, validation = set(rest[:cut2]), set(rest[cut2:])

    default_rules = {spec["rule_id"] for spec in BUILTIN_RULES if spec.get("default_enabled", True)}
    specs = [spec for spec in BUILTIN_RULES]
    names = ("rules", "rules_slow", "threshold", "forest")
    per_candidate: dict[str, dict] = {}
    for candidate in args.candidates:
        keep = [i for i in order if keep_flow(candidate, port[i])]
        print("candidate", candidate, "flows kept", len(keep), flush=True)
        fired: dict[str, Counter] = defaultdict(Counter)
        chunk: list[dict] = []
        current = int(epochs[keep[0]] // 3600)

        def flush() -> None:
            if chunk:
                for entity, rules in methods.run_rules(chunk, specs).items():
                    fired[entity].update(rules)
                chunk.clear()

        ports: dict[str, set] = defaultdict(set)
        dsts: dict[str, set] = defaultdict(set)
        flows_kept: Counter = Counter()
        for n, i in enumerate(keep):
            hour = int(epochs[i] // 3600)
            if hour != current:
                flush()
                current = hour
            chunk.append({
                "id": str(i), "event_time": datetime.fromtimestamp(epochs[i], tz=UTC), "event_type": "net.conn",
                "src_ip": src[i], "dst_ip": dst[i], "dst_port": port[i], "host_id": None, "username": None,
                "severity": "low", "attributes": {}, "entity": src[i],
            })
            flows_kept[src[i]] += 1
            if port[i] is not None:
                ports[src[i]].add(port[i])
            dsts[src[i]].add(dst[i])
        flush()
        vectors = {e: [0, 0, flows_kept[e], len(ports[e]), len(dsts[e]), 0] for e in entities}
        flagged = {
            "rules": {e for e, rules in fired.items() if any(r in default_rules for r in rules)},
            "rules_slow": {e for e, rules in fired.items() if any(r in default_rules or r in SLOW_RULES for r in rules)},
            "threshold": methods.run_threshold(vectors),
        }
        try:
            model = methods.fit_forest([v for e, v in vectors.items() if e in train], args.contamination)
            flagged["forest"] = methods.run_forest(model, {e: v for e, v in vectors.items() if e in (validation | test)})
        except ImportError:
            flagged["forest"] = set()
        hits: dict[str, dict[str, int]] = defaultdict(lambda: {"attacker_entities": 0, "benign_entities": 0})
        for entity, rules in fired.items():
            for rule in rules:
                hits[rule]["attacker_entities" if malicious.get(entity) else "benign_entities"] += 1
        per_candidate[candidate] = {"flows_kept": len(keep), "flagged": flagged, "rule_hits": dict(sorted(hits.items()))}

    def confusion(candidate: str, name: str, population: set[str]) -> Confusion:
        c = Confusion()
        for entity in sorted(population):
            c.add(entity in per_candidate[candidate]["flagged"][name], malicious[entity])
        return c

    # Selection on the validation set, by a rule fixed before looking at any result: among the
    # candidates whose rule-based recall on validation is not below that of "none", take the one with
    # the lowest validation false positive rate; ties go to the earlier candidate in the list.
    validation_rows = {}
    for candidate in args.candidates:
        c = confusion(candidate, "rules", validation)
        validation_rows[candidate] = summarise(c)
    base_recall = validation_rows[args.candidates[0]]["recall"] or 0.0
    eligible = [c for c in args.candidates if (validation_rows[c]["recall"] or 0.0) >= base_recall]
    chosen = min(eligible, key=lambda c: (validation_rows[c]["false_positive_rate"] or 0.0, args.candidates.index(c)))
    print("validation:", {c: (r["recall"], r["false_positive_rate"]) for c, r in validation_rows.items()}, "chosen", chosen, flush=True)

    # The test set is read once: the unprocessed baseline and the chosen preprocessing.
    shown = [args.candidates[0]] if chosen == args.candidates[0] else [args.candidates[0], chosen]
    test_tables: dict[str, dict] = {}
    by_family: dict[str, dict[str, dict[str, Confusion]]] = {}
    for candidate in shown:
        totals = {n: Confusion() for n in names}
        fam = {n: defaultdict(Confusion) for n in names}
        for entity in sorted(test):
            for name in names:
                hit = entity in per_candidate[candidate]["flagged"][name]
                totals[name].add(hit, malicious[entity])
                if malicious[entity]:
                    fam[name][family[entity]].add(hit, True)
        test_tables[candidate] = {n: summarise(totals[n]) for n in names}
        by_family[candidate] = {n: {f: [c.tp, c.tp + c.fn] for f, c in fam[n].items()} for n in names}
    result = {
        "flows": total, "unparsed_timestamps": unparsed, "entities": len(entities),
        "attacker_entities": sum(malicious.values()), "test_entities": len(test),
        "test_attackers": sum(malicious[e] for e in test),
        "validation_entities": len(validation), "validation_attackers": sum(malicious[e] for e in validation),
        "train_entities": len(train), "train_attackers": sum(malicious[e] for e in train),
        "attacker_labels": {e: dict(attack_labels[e]) for e in entities if malicious[e]},
        "candidates": list(args.candidates), "chosen": chosen,
        "flows_kept": {c: per_candidate[c]["flows_kept"] for c in args.candidates},
        "validation_rules": validation_rows,
        "test_methods": test_tables, "recall_by_family": by_family,
        "rule_hits": {c: per_candidate[c]["rule_hits"] for c in shown},
    }
    # Whole population (not only the test split): which kinds of benign hosts did the rules flag?
    internal = lambda ip: ip.startswith("192.168.10.")  # noqa: E731 - the capture's victim network
    for candidate in shown:
        flagged_rules = per_candidate[candidate]["flagged"]["rules"]
        flagged_benign = [e for e in flagged_rules if not malicious[e]]
        result.setdefault("flagged_benign", {})[candidate] = {
            "internal": sum(internal(e) for e in flagged_benign), "external": len(flagged_benign) - sum(internal(e) for e in flagged_benign),
        }
    result["benign_internal"] = sum(1 for e in entities if not malicious[e] and internal(e))
    result["benign_external"] = sum(1 for e in entities if not malicious[e] and not internal(e))

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "cicids2017.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "CICIDS2017.md").write_text(markdown(result), encoding="utf-8")
    for candidate, table_ in test_tables.items():
        for n in names:
            m = table_[n]
            print("test", candidate, n, "P", m["precision"], "R", m["recall"], "F1", m["f1"], "FPR", m["false_positive_rate"], flush=True)
    return 0


LABELS = {
    "rules": "SentinelAI ağ kuralları (varsayılan açık)",
    "rules_slow": "Ağ kuralları + 3 yavaş saldırı kuralı",
    "threshold": "Basit eşik (20+ farklı hedef port)",
    "forest": "Isolation Forest",
}


def num(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def markdown(r: dict) -> str:
    chosen = r["chosen"]
    lines = [
        "# CIC-IDS2017 üzerinde ağ kurallarının ölçümü: akış yönü ön işlemesi (etiketli gerçek veri)",
        "",
        f"Veri: CIC-IDS2017 akış kayıtları ({num(r['flows'])} akış, {num(r['entities'])} kaynak adresi; {r['attacker_entities']} adres en az bir saldırı akışı taşıyor). "
        "Her akış bir `net.conn` olayıdır, varlık kaynak adrestir. Zaman damgaları 12 saatlik saatten düzeltildi (bkz. `run_cicids_parquet.py`). "
        "Kaynak: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Hugging Face kopyası `rdpahalavan/CIC-IDS2017`.",
        "",
        "## Yöntem",
        "",
        "İlk ölçümde yanlış alarmların büyük kısmının akış yönü yapaylığı olduğu görüldü (hedef port, içerideki istemcinin geçici portu). "
        "Bu ölçümde **sonucu görmeden belirlenmiş dört ön işleme adayı** denendi: `none` (tüm akışlar), `below1024`, `below32768`, `below49152` "
        "(yalnızca hedef portu bu sınırın altında olan akışlar tutulur). Adresler üç kümeye bölündü: "
        f"eğitim ({num(r['train_entities'])} adres, {r['train_attackers']} saldırgan; yalnızca Isolation Forest için), "
        f"**doğrulama** ({num(r['validation_entities'])} adres, {r['validation_attackers']} saldırgan) ve "
        f"**sınama** ({num(r['test_entities'])} adres, {r['test_attackers']} saldırgan; ilk ölçümdeki sınama kümesiyle aynıdır). "
        "Seçim kuralı sonuçlar görülmeden yazıldı: doğrulama kümesinde kural duyarlılığı `none`'ınkinden düşük olmayan adaylar arasında en düşük yanlış pozitif oranlı olan seçilir; eşitlikte listedeki ilk aday. "
        "Sınama kümesi seçimden sonra **bir kez** okundu ve yalnızca `none` ile seçilen aday gösterilir.",
        "",
        "## Doğrulama kümesi (seçim burada yapıldı)",
        "",
        "| Aday | Tutulan akış | Duyarlılık | Yanlış pozitif oranı | TP | FP | FN | TN |",
        "|---|---:|---|---|---:|---:|---:|---:|",
    ]
    for cand in r["candidates"]:
        m = r["validation_rules"][cand]
        lines.append(f"| `{cand}` | {num(r['flows_kept'][cand])} | {pct_ci(m['recall'], m['recall_ci95'])} | "
                     f"{pct_ci(m['false_positive_rate'], m['false_positive_rate_ci95'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    lines += ["", f"Seçilen: **`{chosen}`**.", "", "## Sınama kümesi (bir kez okundu)", ""]
    for cand, table_ in r["test_methods"].items():
        lines += [f"### Ön işleme: `{cand}`", "",
                  "| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |",
                  "|---|---|---|---|---|---:|---:|---:|---:|"]
        for name, label in LABELS.items():
            m = table_[name]
            lines.append(f"| {label} | {pct_ci(m['precision'], m['precision_ci95'])} | {pct_ci(m['recall'], m['recall_ci95'])} | {pct(m['f1'])} | "
                         f"{pct_ci(m['false_positive_rate'], m['false_positive_rate_ci95'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
        fb = r["flagged_benign"][cand]
        lines += ["", f"Tüm adreslerde varsayılan kuralların işaretlediği iyi huylu adresler: iç ağdan {fb['internal']} / {r['benign_internal']}, dış adreslerden {fb['external']} / {r['benign_external']}.", ""]
    lines += ["## Kural bazında bulgular (tüm adresler)", "", "| Ön işleme | Kural | Saldırgan adres | İyi huylu adres |", "|---|---|---:|---:|"]
    for cand, hits in r["rule_hits"].items():
        for rule, hit in sorted(hits.items(), key=lambda kv: -(kv[1]["attacker_entities"] + kv[1]["benign_entities"])):
            lines.append(f"| `{cand}` | `{rule}` | {hit['attacker_entities']} | {hit['benign_entities']} |")
    lines += ["", "## Sınırlılıklar", "",
        "- Saldırgan adres yalnızca 10'dur; doğrulama kümesinde çok azı kalır, bu yüzden **seçim istatistiksel olarak zayıftır** ve sınama kümesinde 3 saldırgan vardır. Aralıklar geniştir; sonuç bir sıralama kanıtı değil, bir yön göstergesidir.",
        "- Port sınırına göre süzmek yönü tahmin eder: uzak sunucunun hizmet portuna giden gerçek saldırı akışları da (ör. yüksek portlu hizmetlere tarama) elenebilir. Süzme, ürünün sensörünün gerçekte ürettiği akışlara uygulanacak bir işleme değildir; bu, veri kümesinin yapaylığını gidermeye yönelik bir ön işlemdir.",
        "- Duyarlılık adres düzeyindedir ve atıf değildir. Akış verisinde oturum açma, süreç ve bulut olayı yoktur; yalnızca ağ kuralları denenebildi.",
        "- Bu veri kümesi tek bir laboratuvar ağında, beş günde toplandı; etiket ve akış üretimi hataları bildirilmiştir (Engelen ve ark., 2021). Saat düzeltmesi (12 saatlik saatten) bir varsayımdır.",
        "- Kural eşikleri değiştirilmedi; yalnızca girdi akışları süzüldü.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
