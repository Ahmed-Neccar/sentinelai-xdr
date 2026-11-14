"""Turn a labelled flow CSV (CICIDS2017 style) into the JSON Lines file run_evaluation.py reads.

    python research/convert_flows_csv.py flows.csv events.jsonl \
        --src "Source IP" --dst "Destination IP" --dport "Destination Port" \
        --time "Timestamp" --label "Label"

Each flow becomes one `net.conn` event whose entity is the source address. A flow whose label is
the benign label becomes "benign"; any other label is kept as the attack family. Then:

    python research/run_evaluation.py --dataset events.jsonl --output-dir out

Things to check before trusting a result:

* The timestamp column must carry a full date and time. Some public copies of CICIDS2017 keep only
  minutes and seconds and are shuffled, which makes every windowed rule meaningless (a copy with
  that flaw was tried and rejected for this reason).
* Flow data has no sign-in or process events, so only the network rules can fire.
* Read the data set's licence and cite its authors.

Addresses given as decimal integers (``--ip-format int``) are converted to dotted form.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
)


def parse_time(value: str, formats: tuple[str, ...] = TIME_FORMATS) -> datetime:
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
        for fmt in formats:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            raise ValueError(f"unrecognised time: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def address(value: str, ip_format: str) -> str:
    text = value.strip()
    if ip_format == "int":
        return str(ipaddress.ip_address(int(float(text))))
    return str(ipaddress.ip_address(text))


def convert(source: Path, target: Path, *, src: str, dst: str, dport: str, time_col: str, label: str,
            benign: str = "BENIGN", ip_format: str = "dotted", max_rows: int | None = None) -> dict:
    counts = {"rows": 0, "written": 0, "skipped": 0, "attack_rows": 0}
    with source.open(newline="", encoding="utf-8-sig") as handle, target.open("w", encoding="utf-8") as out:
        reader = csv.DictReader(handle)
        reader.fieldnames = [name.strip() for name in (reader.fieldnames or [])]
        missing = [c for c in (src, dst, dport, time_col, label) if c not in reader.fieldnames]
        if missing:
            raise SystemExit(f"columns not found: {missing}; the file has {reader.fieldnames[:12]}...")
        for row in reader:
            counts["rows"] += 1
            if max_rows and counts["rows"] > max_rows:
                break
            try:
                when = parse_time(row[time_col])
                source_ip = address(row[src], ip_format)
                destination_ip = address(row[dst], ip_format)
                port = int(float(row[dport]))
            except (ValueError, KeyError):
                counts["skipped"] += 1
                continue
            raw_label = row[label].strip()
            is_benign = raw_label.upper() == benign.upper()
            counts["attack_rows"] += 0 if is_benign else 1
            out.write(json.dumps({
                "event_time": when.isoformat(), "event_type": "net.conn", "entity": source_ip,
                "label": "benign" if is_benign else raw_label, "src_ip": source_ip,
                "dst_ip": destination_ip, "dst_port": port,
            }) + "\n")
            counts["written"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--src", default="Source IP")
    parser.add_argument("--dst", default="Destination IP")
    parser.add_argument("--dport", default="Destination Port")
    parser.add_argument("--time", dest="time_col", default="Timestamp")
    parser.add_argument("--label", default="Label")
    parser.add_argument("--benign-label", default="BENIGN")
    parser.add_argument("--ip-format", choices=("dotted", "int"), default="dotted")
    parser.add_argument("--max-rows", type=int)
    args = parser.parse_args()
    counts = convert(args.source, args.target, src=args.src, dst=args.dst, dport=args.dport,
                     time_col=args.time_col, label=args.label, benign=args.benign_label,
                     ip_format=args.ip_format, max_rows=args.max_rows)
    print(json.dumps(counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
