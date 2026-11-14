"""Try candidate rules against the simulator on seeds the earlier reports did not use.

    python research/run_candidates.py [--seeds 20] [--entities 500] [--seed-offset 1000]

The candidates are long-window variants of existing rules, written after the main evaluation showed
that every slow attack is missed. To keep that from becoming tuning on the data that exposed the
problem, they are measured on different seeds (`--seed-offset`, default 1000) and both difficulty
scenarios. Each candidate is judged alone: recall on the families it targets and the false positive
rate over all benign entities, with 95 % intervals. Nothing is enabled by this script.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "backend"))

from sentinel_eval import methods  # noqa: E402
from sentinel_eval.metrics import Confusion, summarise  # noqa: E402
from sentinel_eval.simulate import Simulation  # noqa: E402

SLOW = ("slow_brute_force", "slow_spray", "port_scan_slow")

CANDIDATES = {
    "auth_bruteforce_username_slow": {
        "rule_id": "auth_bruteforce_username_slow", "title": "Slow brute force against one username",
        "severity": "medium", "version": 1, "window_seconds": 3600, "group_by": ["username"],
        "threshold": 10, "match": {"event_type": "auth.failure"}, "mitre": [],
        "targets": ("slow_brute_force", "brute_force_fast"),
    },
    "password_spray_slow": {
        "rule_id": "password_spray_slow", "title": "Slow password spraying", "severity": "medium",
        "version": 1, "window_seconds": 3600, "group_by": ["src_ip"], "distinct_field": "username",
        "threshold": 8, "match": {"event_type": "auth.failure"}, "mitre": [],
        "targets": ("slow_spray", "password_spray"),
    },
    "port_scan_slow": {
        "rule_id": "port_scan_slow", "title": "Slow port scan", "severity": "low", "version": 1,
        "window_seconds": 3600, "group_by": ["src_ip"], "threshold": 40,
        "match": {"event_type": ["net.conn", "zeek.conn", "suricata.flow"]}, "mitre": [],
        "unique_field": "dst_port", "targets": ("port_scan_slow", "port_scan_fast"),
    },
}


def measure(spec: dict, seeds: range, size: int, prevalence: float, hard_scale: float) -> dict:
    targets = spec["targets"]
    run_spec = {k: v for k, v in spec.items() if k != "targets"}
    slow = Confusion()
    overall = Confusion()
    for seed in seeds:
        sim = Simulation(seed, size, prevalence, hard_scale)
        fired = methods.run_rules(sim.events, [run_spec])
        for entity in sim.entities:
            flagged = entity.entity_id in fired
            if entity.malicious and entity.role in targets:
                overall.add(flagged, True)
                if entity.role in SLOW:
                    slow.add(flagged, True)
            elif not entity.malicious:
                overall.add(flagged, False)
    return {"targets": list(targets), "all_targets": summarise(overall), "slow_only_recall": summarise(slow)["recall"]}


def pct(value: float | None) -> str:
    return "-" if value is None else f"%{value * 100:.1f}".replace(".", ",")


def markdown(result: dict) -> str:
    lines = [
        "# Yavaş saldırılar için aday kurallar",
        "",
        "Ana değerlendirme (RAPOR.md), 5 ve 10 dakikalık pencerelerin **her yavaş saldırıyı ıskaladığını** gösterdi (yavaş kaba kuvvet, yavaş parola püskürtme, yavaş port taraması). "
        "Bu sayfa, bu boşluğu kapatmak için yazılan 1 saatlik pencereli üç adayı ölçer.",
        "",
        f"**Ölçüm ayrı tohumlarda yapıldı** ({result['seeds'][0]}–{result['seeds'][1]}; ana değerlendirmede 0–19 kullanıldı) ve iki zorluk senaryosunda tekrarlandı; "
        "adaylar, açığı gösteren veriye göre ayarlanmış olmasın diye eşikler ayrıca aranmadı. Yine de açık yavaş saldırı ailelerinin tanımına göre yazıldığı için döngüsellik vardır.",
        "",
        "| Aday | Senaryo | Yavaş saldırıda duyarlılık | Hedef ailelerde duyarlılık | Yanlış pozitif oranı |",
        "|---|---|---:|---:|---|",
    ]
    for label, entries in result["scenarios"].items():
        for name, entry in entries.items():
            a = entry["all_targets"]
            ci = a["false_positive_rate_ci95"]
            fpr = f"{pct(a['false_positive_rate'])} [{pct(ci[0])}–{pct(ci[1])}]" if ci else pct(a["false_positive_rate"])
            lines.append(f"| `{name}` | {label} | {pct(entry['slow_only_recall'])} | {pct(a['recall'])} | {fpr} |")
    lines += [
        "",
        "## Karar",
        "",
        "Üç kural `BUILTIN_RULES` içine **varsayılan olarak kapalı** eklendi (`default_enabled: False`); Kurallar sayfasından bir yönetici açabilir. "
        "Simülasyon, gerçek ağdaki gürültüyü içermez (örneğin sürekli eski parolayla yeniden deneyen bir telefon), bu yüzden gerçek veride yanlış alarm beklenir ve "
        "açılmadan önce kendi ağınızda bir süre izlenmelidir.",
        "",
        "## Sınırlılıklar",
        "",
        "- Sentetik veri; yavaş saldırının “yavaş” tanımı simülatörü yazanlarındır.",
        "- Kurallar sabit, saat sınırlarına hizalı 1 saatlik pencereler kullanır; pencere sınırını aşan bir saldırı iki parçaya bölünür.",
        "- Yalnızca her aday kendi başına ölçüldü; birlikte çalıştıklarında çakışan bulgular ve vaka sayısı ölçülmedi.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--entities", type=int, default=500)
    parser.add_argument("--prevalence", type=float, default=0.10)
    parser.add_argument("--seed-offset", type=int, default=1000)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results")
    args = parser.parse_args()
    seeds = range(args.seed_offset, args.seed_offset + args.seeds)
    result: dict = {"seeds": [seeds.start, seeds.stop - 1], "entities": args.entities, "prevalence": args.prevalence, "scenarios": {}}
    for label, scale in (("ana (zor durumlar az)", 0.25), ("stres (zor durumlar çok)", 1.0)):
        result["scenarios"][label] = {
            name: measure(spec, seeds, args.entities, args.prevalence, scale) for name, spec in CANDIDATES.items()
        }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "aday_kurallar.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    (args.output_dir / "ADAY_KURALLAR.md").write_text(markdown(result), encoding="utf-8")
    for label, entries in result["scenarios"].items():
        print(label)
        for name, entry in entries.items():
            a = entry["all_targets"]
            print(f"  {name}: recall(slow)={entry['slow_only_recall']} recall(all targets)={a['recall']} fpr={a['false_positive_rate']} ci={a['false_positive_rate_ci95']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
