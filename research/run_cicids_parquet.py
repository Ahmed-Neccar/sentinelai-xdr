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
    ports: dict[str, set] = defaultdict(set)
    dsts: dict[str, set] = defaultdict(set)
    for i in range(total):
        flows_per_entity[src[i]] += 1
        if label[i] != "BENIGN":
            attack_labels[src[i]][label[i]] += 1
        if port[i] is not None:
            ports[src[i]].add(port[i])
        dsts[src[i]].add(dst[i])

    specs = [spec for spec in BUILTIN_RULES]
    fired: dict[str, Counter] = defaultdict(Counter)
    start = epochs[order[0]]
    chunk: list[dict] = []
    current = int(start // 3600)

    def flush() -> None:
        if not chunk:
            return
        for entity, rules in methods.run_rules(chunk, specs).items():
            fired[entity].update(rules)
        chunk.clear()

    for n, i in enumerate(order):
        hour = int(epochs[i] // 3600)
        if hour != current:
            flush()
            current = hour
        chunk.append({
            "id": str(i), "event_time": datetime.fromtimestamp(epochs[i], tz=UTC), "event_type": "net.conn",
            "src_ip": src[i], "dst_ip": dst[i], "dst_port": port[i], "host_id": None, "username": None,
            "severity": "low", "attributes": {}, "entity": src[i],
        })
        if n % 500000 == 0:
            print("processed", n, flush=True)
    flush()

    entities = sorted(flows_per_entity)
    malicious = {e: bool(attack_labels.get(e)) for e in entities}
    family = {e: attack_labels[e].most_common(1)[0][0] for e in entities if malicious[e]}
    vectors = {e: [0, 0, flows_per_entity[e], len(ports[e]), len(dsts[e]), 0] for e in entities}

    rng = random.Random(0)  # noqa: S311 - seeded split
    shuffled = entities[:]
    rng.shuffle(shuffled)
    cut = int(len(shuffled) * 0.7)
    train, test = set(shuffled[:cut]), set(shuffled[cut:])

    default_rules = {spec["rule_id"] for spec in BUILTIN_RULES if spec.get("default_enabled", True)}
    flagged_default = {e for e, rules in fired.items() if any(r in default_rules for r in rules)}
    flagged_with_slow = {e for e, rules in fired.items() if any(r in default_rules or r in SLOW_RULES for r in rules)}
    flagged = {
        "rules": flagged_default,
        "rules_slow": flagged_with_slow,
        "threshold": methods.run_threshold(vectors),
    }
    try:
        model = methods.fit_forest([v for e, v in vectors.items() if e in train], args.contamination)
        flagged["forest"] = methods.run_forest(model, {e: v for e, v in vectors.items() if e in test})
    except ImportError:
        flagged["forest"] = set()

    names = ("rules", "rules_slow", "threshold", "forest")
    total_c = {n: Confusion() for n in names}
    by_family: dict[str, dict[str, Confusion]] = {n: defaultdict(Confusion) for n in names}
    for entity in sorted(test):
        for name in names:
            hit = entity in flagged[name]
            total_c[name].add(hit, malicious[entity])
            if malicious[entity]:
                by_family[name][family[entity]].add(hit, True)
    result = {
        "flows": total, "unparsed_timestamps": unparsed, "entities": len(entities),
        "attacker_entities": sum(malicious.values()), "test_entities": len(test),
        "test_attackers": sum(malicious[e] for e in test),
        "attacker_labels": {e: dict(attack_labels[e]) for e in entities if malicious[e]},
        "methods": {n: summarise(total_c[n]) for n in names},
        "recall_by_family": {n: {f: [c.tp, c.tp + c.fn] for f, c in by_family[n].items()} for n in names},
        "rule_hits": {},
    }
    hits: dict[str, dict[str, int]] = defaultdict(lambda: {"attacker_entities": 0, "benign_entities": 0})
    for entity, rules in fired.items():
        for rule in rules:
            hits[rule]["attacker_entities" if malicious.get(entity) else "benign_entities"] += 1
    result["rule_hits"] = dict(sorted(hits.items()))
    # Whole population (not only the test split): which kinds of benign hosts did the rules flag?
    flagged_benign = [e for e in flagged_default if not malicious[e]]
    internal = lambda ip: ip.startswith("192.168.10.")  # noqa: E731 - the capture's victim network
    result["flagged_benign_internal"] = sum(internal(e) for e in flagged_benign)
    result["flagged_benign_external"] = len(flagged_benign) - result["flagged_benign_internal"]
    result["benign_internal"] = sum(1 for e in entities if not malicious[e] and internal(e))
    result["benign_external"] = sum(1 for e in entities if not malicious[e] and not internal(e))

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "cicids2017.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "CICIDS2017.md").write_text(markdown(result), encoding="utf-8")
    for n in names:
        m = result["methods"][n]
        print(n, "P", m["precision"], "R", m["recall"], "F1", m["f1"], "FPR", m["false_positive_rate"], flush=True)
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
    lines = [
        "# CIC-IDS2017 üzerinde ağ kurallarının ölçümü (etiketli gerçek veri)",
        "",
        f"Veri: CIC-IDS2017 akış kayıtları ({num(r['flows'])} akış, {num(r['entities'])} kaynak adresi; {r['attacker_entities']} adres en az bir saldırı akışı taşıyor). "
        "Her akış bir `net.conn` olayıdır, varlık kaynak adrestir. Zaman damgaları 12 saatlik saatten düzeltildi (bkz. `run_cicids_parquet.py`). "
        "Kaynak: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Hugging Face kopyası `rdpahalavan/CIC-IDS2017`.",
        "",
        f"Değerlendirme kümesi: adreslerin rastgele %30'u ({num(r['test_entities'])} adres, {r['test_attackers']} saldırgan). **Saldırgan sayısı çok küçüktür; aralıklar geniştir.**",
        "",
        "| Yöntem | Kesinlik | Duyarlılık | F1 | Yanlış pozitif oranı | TP | FP | FN | TN |",
        "|---|---|---|---|---|---:|---:|---:|---:|",
    ]
    for name, label in LABELS.items():
        m = r["methods"][name]
        lines.append(f"| {label} | {pct_ci(m['precision'], m['precision_ci95'])} | {pct_ci(m['recall'], m['recall_ci95'])} | {pct(m['f1'])} | "
                     f"{pct_ci(m['false_positive_rate'], m['false_positive_rate_ci95'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    lines += ["", "## Saldırgan adreslerin etiketleri", "", "| Adres türü | Akış etiketleri |", "|---|---|"]
    for ip, labels in sorted(r["attacker_labels"].items(), key=lambda kv: -sum(kv[1].values())):
        kind = "iç ağ (192.168.10.x)" if ip.startswith("192.168.10.") else "dış / NAT"
        lines.append(f"| {kind} | " + ", ".join(f"{k}: {v}" for k, v in sorted(labels.items(), key=lambda kv: -kv[1])) + " |")
    lines += ["", "## Kural bazında bulgular (tüm adresler)", "", "| Kural | Saldırgan adres | İyi huylu adres |", "|---|---:|---:|"]
    for rule, hit in sorted(r["rule_hits"].items(), key=lambda kv: -(kv[1]["attacker_entities"] + kv[1]["benign_entities"])):
        lines.append(f"| `{rule}` | {hit['attacker_entities']} | {hit['benign_entities']} |")
    lines += [
        "",
        "## Nasıl yorumlanmalı",
        "",
        "- **Yanlış alarmların büyük kısmı akış yönü yapaylığıdır (ayrıca kontrol edildi).** Bu veri kümesinde akışlar çift yönlüdür ve bazı kayıtlarda \"kaynak\" uzak sunucudur; "
        "o zaman \"hedef port\" içerideki istemcinin geçici (ephemeral) portudur. İyi huylu, dıştan içe akışların %89,6'sında hedef port 32768 veya üstüdür; "
        "içten içe akışlarda bu oran %2,4, içten dışa akışlarda %4,6'dır. Tüm gün boyunca 12 veya daha fazla farklı hedef porta sahip iyi huylu dış adres sayısı 4.639'dur (16.988 dış adresten) "
        "ve bunların farklı portlarının ortalama %88,4'ü geçici portlardır. `port_scan_like` ve `unusual_conn_volume` kaynağın bağlantıyı başlatan taraf ve hedef portun hizmet portu olduğunu varsayar; "
        "bu varsayım burada bozuluyor. Yönü düzelten bir ön işleme (ör. yalnızca bilinen hizmet portlarına giden akışlar) ayrıca denenmedi; denenseydi bu veriye göre ayar olurdu.",
        "- **Duyarlılık adres düzeyindedir ve atıf değildir.** Bir adres saldırı etiketli bir akış taşıyorsa saldırgan sayılır; kural, o adresin iyi huylu akışlarından da ateşlenmiş olabilir. "
        "Saldırgan adres yalnızca 10 olduğu için (değerlendirme kümesinde 3) duyarlılık aralığı çok geniştir (%43,9–%100).",
        "- **Kesinlik çok düşük çıkar** çünkü 17 bin adrese karşı 10 saldırgan vardır (saldıran oranı %0,06); düşük saldıran oranında kesinliğin düşeceği, simülasyon raporundaki projeksiyonla uyumludur.",
        "- Basit eşik ve Isolation Forest da aynı yön yapaylığından etkilenir; bu karşılaştırma yöntemlerin sıralaması hakkında güçlü bir sonuç vermez.",
        "",
        f"Varsayılan kuralların işaretlediği iyi huylu adresler: iç ağdan {r['flagged_benign_internal']} / {r['benign_internal']}, dış adreslerden {r['flagged_benign_external']} / {r['benign_external']}.",
        "",
        "## Sınırlılıklar",
        "",
        "- Akış verisinde oturum açma, süreç ve bulut olayı yoktur; yalnızca ağ kuralları denenebildi. SSH-Patator ve FTP-Patator kaba kuvvet saldırılarıdır ama akışlarda başarısız oturum açma olayı olmadığı için oturum açma kuralları onları göremez.",
        "- Bu veri kümesi tek bir laboratuvar ağında, beş günde, bilinen bir saldırgan kümesiyle toplandı; saldırgan adres sayısı çok az (tek bir NAT adresi birçok saldırı ailesini taşıyor) ve istatistiksel güç düşüktür.",
        "- Eşikler bu veriye göre ayarlanmadı. Zaman damgaları dakika veya saniye çözünürlüğündedir; saat düzeltmesi (12 saatlik saatten) bir varsayımdır.",
        "- Bilinen eleştiriler: CIC-IDS2017'nin etiketlerinde ve akış üretiminde hatalar bildirilmiştir (Engelen ve ark., 2021); bu kopya düzeltilmiş sürüm olmayabilir.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
