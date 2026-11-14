"""Run the rules on public attack captures (OTRF Security-Datasets) and report hits.

    python research/fetch_otrf.py <folder>            # download the captures listed below
    python research/run_otrf.py <folder> --output-dir research/results

Reads the zip files as data only. See sentinel_eval/otrf.py for what the measurement means.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "backend"))

from sentinel_eval import methods  # noqa: E402
from sentinel_eval.otrf import CAPTURES, load_capture  # noqa: E402


def run(folder: Path) -> list[dict]:
    rows = []
    for capture in CAPTURES:
        path = folder / capture.file
        if not path.is_file():
            rows.append({"file": capture.file, "missing": True})
            continue
        events, counts = load_capture(path)
        fired = methods.run_rules(events)
        totals: Counter[str] = Counter()
        for rules in fired.values():
            totals.update(rules)
        hit = [rule for rule in capture.expected if totals.get(rule)]
        rows.append({
            "file": capture.file,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "technique": capture.technique,
            "note": capture.note,
            "expected": list(capture.expected),
            "diagnosis": capture.diagnosis,
            "hit": bool(hit),
            "hit_rules": hit,
            "windows_event_lines": counts["lines"],
            "security_events": counts["security_events"],
            "converted_events": len(events),
            "findings_by_rule": dict(sorted(totals.items())),
            "other_rule_findings": sum(n for rule, n in totals.items() if rule not in capture.expected),
        })
    return rows


def markdown(rows: list[dict]) -> str:
    done = [r for r in rows if not r.get("missing")]
    hits = sum(r["hit"] for r in done)
    lines = [
        "# Gerçek saldırı kayıtlarında kural denemesi (OTRF Security-Datasets)",
        "",
        f"{len(done)} halka açık Windows saldırı kaydı (https://github.com/OTRF/Security-Datasets) üzerinde, yalnızca SentinelAI sensörünün topladığı "
        "Güvenlik günlüğü olayları dönüştürülerek yerleşik kurallar çalıştırıldı. **Beklenen kural, kayıt çalıştırılmadan önce, belgelenmiş tekniğe göre belirlendi.**",
        "",
        f"**Sonuç: {hits} / {len(done)} kayıtta beklenen kural en az bir bulgu üretti.** Bu bir duyarlılık ölçümüdür; kayıtlarda olay başına etiket olmadığı için "
        "yanlış pozitif oranı hesaplanamaz. \"Diğer bulgular\" sütunu laboratuvar ana bilgisayarının olağan gürültüsü ile saldırının diğer adımlarını karıştırır; "
        "yanlış alarm sayısı olarak okunmamalıdır.",
        "",
        "| Kayıt | Teknik | Beklenen kural | Isabet | Dönüştürülen olay | Diğer bulgu sayısı |",
        "|---|---|---|:-:|---:|---:|",
    ]
    for r in done:
        lines.append(
            f"| `{r['file']}` | {r['technique']} | {', '.join('`' + x + '`' for x in r['expected'])} | "
            f"{'evet' if r['hit'] else '**hayır**'} | {r['converted_events']} / {r['security_events']} | {r['other_rule_findings']} |"
        )
    lines += ["", "## Kural bazında bulgular", ""]
    for r in done:
        findings = ", ".join(f"`{rule}`: {n}" for rule, n in r["findings_by_rule"].items()) or "bulgu yok"
        lines.append(f"- `{r['file']}`: {findings}")
    misses = [r for r in done if not r["hit"] and r.get("diagnosis")]
    if misses:
        lines += ["", "## Iskalanan kayıtların çözümlemesi", "",
                  "Bu çözümlemeler kayıtlar incelendikten **sonra** yazıldı (beklenen kurallar ise önceden belirlenmişti):", ""]
        for r in misses:
            lines.append(f"- `{r['file']}`: {r['diagnosis']}")
    missing = [r["file"] for r in rows if r.get("missing")]
    if missing:
        lines += ["", "İndirilmemiş: " + ", ".join(f"`{m}`" for m in missing)]
    lines += [
        "",
        "## Sınırlılıklar",
        "",
        "- Yalnızca saldırı kayıtları kullanıldı; iyi huylu karşılık yok. Yanlış alarm ölçülmedi.",
        f"- {len(done)} kayıt küçük bir örnektir ve her kural için tek bir teknik örneği vardır; genelleme yapılamaz.",
        "- Kayıtlar laboratuvar ortamında (Windows 10 / Server 2016, Güvenlik günlüğünde süreç oluşturma denetimi açık) alınmıştır; "
        "süreç adları kayıtlardaki tam yollardır. Gerçek bir kurumda denetim ayarları farklı olabilir.",
        "- Sensörün gerçek XML işleme yolu kullanılmadı; olaylar kayıtlardaki alanlardan aynı olay türü ve öznitelik adlarına dönüştürüldü.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results")
    args = parser.parse_args()
    rows = run(args.folder)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "gercek_veri.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False), encoding="utf-8")
    (args.output_dir / "GERCEK_VERI.md").write_text(markdown(rows), encoding="utf-8")
    for r in rows:
        print(r["file"], "MISSING" if r.get("missing") else ("HIT" if r["hit"] else "miss"),
              {} if r.get("missing") else r["findings_by_rule"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
