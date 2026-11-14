"""Compare the detection methods on labelled data and write the results.

    python research/run_evaluation.py                      # simulated data, default settings
    python research/run_evaluation.py --seeds 5 --entities 300 --output-dir /tmp/eval
    python research/run_evaluation.py --dataset events.jsonl --output-dir /tmp/real

Needs scikit-learn and numpy (backend/requirements-ml.txt) next to the backend's own
requirements. The easiest way is the container recipe in research/README.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "backend"))

from sentinel_eval import report  # noqa: E402
from sentinel_eval.datasets import load_labelled_events  # noqa: E402
from sentinel_eval.experiment import evaluate, evaluate_events, prevalence_sweep, threshold_sweep  # noqa: E402


def write_outputs(out: Path, main_result: dict, sweep: dict, sensitivity: list[dict], generated: str,
                  thresholds: dict | None, stress: dict | None) -> None:
    (out / "figures" / "performans.svg").write_text(report.bar_chart(main_result), encoding="utf-8")
    (out / "figures" / "duyarlilik_haritasi.svg").write_text(report.heatmap(main_result), encoding="utf-8")
    (out / "figures" / "kesinlik_oran.svg").write_text(report.prevalence_chart(sweep), encoding="utf-8")
    if thresholds:
        (out / "figures" / "esik_taramasi.svg").write_text(report.sweep_chart(thresholds), encoding="utf-8")
    (out / "RAPOR.md").write_text(report.markdown(main_result, sweep, sensitivity, generated, thresholds, stress), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--entities", type=int, default=600)
    parser.add_argument("--prevalence", type=float, default=0.10)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--hard-scale", type=float, default=0.25,
                        help="scale of the benign roles that look like attacks (1.0 = the full set of hard cases)")
    parser.add_argument("--stress-scale", type=float, default=1.0, help="second scenario shown for comparison")
    parser.add_argument("--dataset", type=Path, help="labelled JSON Lines file instead of the simulation")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--render-only", action="store_true",
                        help="rebuild the report and figures from results.json without running anything")
    args = parser.parse_args()

    out: Path = args.output_dir
    (out / "figures").mkdir(parents=True, exist_ok=True)
    generated = datetime.now(UTC).strftime("%Y-%m-%d")

    if args.render_only:
        saved = json.loads((out / "results.json").read_text(encoding="utf-8"))
        main_result, sweep, thresholds = saved["main"], saved["projection"], saved.get("threshold_sweep")
        stress = saved.get("stress")
        if stress:
            stress = {**stress, "attack_families": main_result["attack_families"]}
        sensitivity = [{"contamination": item["contamination"], "methods": {"forest": item["forest"]}}
                       for item in saved["forest_sensitivity"]]
        write_outputs(out, main_result, sweep, sensitivity, saved["generated"], thresholds, stress)
        print(f"rendered from {out / 'results.json'}")
        return 0

    if args.dataset:
        events, labels = load_labelled_events(args.dataset)
        main_result = evaluate_events(events, labels, args.contamination)
        sensitivity = [evaluate_events(events, labels, c) for c in (0.01, 0.05, 0.15)]
    else:
        main_result = evaluate(args.seeds, args.entities, args.prevalence, args.contamination, args.hard_scale)
        sensitivity = [evaluate(args.seeds, args.entities, args.prevalence, c, args.hard_scale) for c in (0.01, 0.15)]
        sensitivity.insert(1, main_result)
        stress = evaluate(args.seeds, args.entities, args.prevalence, args.contamination, args.stress_scale)

    sweep = prevalence_sweep(args.seeds, args.entities, main_result)
    thresholds = None if args.dataset else threshold_sweep(args.seeds, args.entities, args.prevalence, args.hard_scale)
    if args.dataset:
        stress = None
    (out / "results.json").write_text(
        json.dumps({"generated": generated, "main": main_result, "projection": sweep, "threshold_sweep": thresholds,
                    "stress": None if stress is None else {k: stress[k] for k in ("hard_scale", "hard_share_of_benign", "methods")},
                    "forest_sensitivity": [{"contamination": s["contamination"], "forest": s["methods"]["forest"]} for s in sensitivity]},
                   indent=1, ensure_ascii=False),
        encoding="utf-8",
    )
    write_outputs(out, main_result, sweep, sensitivity, generated, thresholds, stress)

    for name, entry in main_result["methods"].items():
        print(f"{name:10s} precision={entry['precision']} recall={entry['recall']} f1={entry['f1']} fpr={entry['false_positive_rate']}")
    print(f"written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
