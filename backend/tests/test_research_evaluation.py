"""The evaluation framework in research/: metrics, simulator, rule runner and dataset loader."""

import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

RESEARCH = Path(__file__).resolve().parents[2] / "research"
sys.path.insert(0, str(RESEARCH))

sys.path.insert(0, str(RESEARCH))
from sentinel_eval import methods  # noqa: E402
from sentinel_eval.datasets import load_labelled_events  # noqa: E402
from sentinel_eval.metrics import (  # noqa: E402
    Confusion,
    precision_at_prevalence,
    summarise,
    wilson_interval,
)
from sentinel_eval.simulate import (  # noqa: E402
    ATTACKS,
    BENIGN_ROLES,
    HARD_ROLES,
    START,
    Simulation,
    hard_share,
)


def test_confusion_metrics_match_a_hand_calculation() -> None:
    c = Confusion(tp=8, fp=2, fn=2, tn=88)
    assert c.precision == pytest.approx(0.8)
    assert c.recall == pytest.approx(0.8)
    assert c.f1 == pytest.approx(0.8)
    assert c.false_positive_rate == pytest.approx(2 / 90)
    assert c.accuracy == pytest.approx(0.96)
    empty = Confusion()
    assert empty.precision is None and empty.recall is None and empty.f1 is None


def test_confusion_add_and_merge() -> None:
    c = Confusion()
    for predicted, actual in ((True, True), (True, False), (False, True), (False, False)):
        c.add(predicted, actual)
    assert (c.tp, c.fp, c.fn, c.tn) == (1, 1, 1, 1)
    assert c.merge(c) == Confusion(2, 2, 2, 2)


def test_wilson_interval_is_a_sensible_interval() -> None:
    low, high = wilson_interval(50, 100)
    assert low < 0.5 < high and 0.39 < low < 0.41 and 0.59 < high < 0.61
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(0, 20)
    assert low == 0.0 and 0.0 < high < 0.2  # no events is not "zero risk"
    wide = wilson_interval(50, 100)
    narrow = wilson_interval(500, 1000)
    assert narrow[1] - narrow[0] < wide[1] - wide[0]  # more data, tighter interval


def test_summary_has_intervals_for_the_proportions() -> None:
    summary = summarise(Confusion(tp=8, fp=2, fn=2, tn=88))
    assert summary["precision_ci95"][0] < 0.8 < summary["precision_ci95"][1]
    assert summary["false_positive_rate_ci95"] is not None


def test_precision_projection_follows_bayes() -> None:
    # recall 0.8, FPR 0.1: at 10 % attackers precision = 0.08 / (0.08 + 0.09)
    assert precision_at_prevalence(0.8, 0.1, 0.10) == pytest.approx(0.08 / 0.17)
    assert precision_at_prevalence(0.8, 0.1, 0.001) < 0.01  # rare attacks drown in false alarms
    assert precision_at_prevalence(None, 0.1, 0.1) is None
    assert precision_at_prevalence(0.8, 0.1, 0.0) is None


def test_the_simulation_is_reproducible_and_labelled() -> None:
    first = Simulation(seed=5, size=120, prevalence=0.2)
    again = Simulation(seed=5, size=120, prevalence=0.2)
    other = Simulation(seed=6, size=120, prevalence=0.2)
    assert [e.entity_id for e in first.entities] == [e.entity_id for e in again.entities]
    assert [ev["id"] for ev in first.events] == [ev["id"] for ev in again.events]
    assert [ev["event_time"] for ev in first.events] == [ev["event_time"] for ev in again.events]
    assert [e.role for e in first.entities] != [e.role for e in other.entities]
    assert sum(e.malicious for e in first.entities) == 24
    assert {e.role for e in first.entities if e.malicious} <= set(ATTACKS)
    assert {e.role for e in first.entities if not e.malicious} <= set(BENIGN_ROLES)
    owners = {ev["entity"] for ev in first.events}
    assert owners <= {e.entity_id for e in first.entities}
    assert all(ev["event_time"] >= START for ev in first.events)
    assert len({ev["id"] for ev in first.events}) == len(first.events)


def test_hard_scale_changes_the_share_of_hard_cases() -> None:
    assert 0 < hard_share(0.25) < hard_share(1.0) < 0.5
    sim = Simulation(seed=1, size=2000, prevalence=0.0, hard_scale=0.0)
    assert not any(e.role in HARD_ROLES for e in sim.entities)


def test_every_non_evasive_attack_family_is_caught_by_some_rule() -> None:
    # One entity of each family, no noise: the families meant to be visible must fire a rule.
    evasive = {"slow_brute_force", "slow_spray", "port_scan_slow"}
    sim = Simulation(seed=3, size=len(ATTACKS), prevalence=1.0)
    fired = methods.run_rules(sim.events)
    for entity in sim.entities:
        if entity.role not in evasive:
            assert entity.entity_id in fired, entity.role


def test_slow_attacks_stay_below_the_default_thresholds() -> None:
    sim = Simulation(seed=2, size=len(ATTACKS) * 4, prevalence=1.0)
    fired = methods.run_rules(sim.events)
    for entity in sim.entities:
        if entity.role in {"slow_brute_force", "slow_spray", "port_scan_slow"}:
            rules = fired.get(entity.entity_id, {})
            # A slow scan or spray should not trip the burst rules designed for fast ones.
            assert "auth_bruteforce" not in rules
            assert "password_spray" not in rules and "port_scan_like" not in rules


def test_ordinary_workstations_and_servers_raise_no_process_or_cloud_rule() -> None:
    sim = Simulation(seed=4, size=200, prevalence=0.0, hard_scale=0.0)
    fired = methods.run_rules(sim.events)
    quiet = {"ordinary_endpoint", "cloud_reader", "dns_resolver"}
    for entity in sim.entities:
        if entity.role in quiet:
            assert entity.entity_id not in fired, entity.role


def test_recurring_process_findings_are_suppressed_but_other_findings_stand() -> None:
    fired = {
        "pc-1": {"wmi_spawns_cmd": 5},  # routine: recurring process rule only
        "pc-2": {"wmi_spawns_cmd": 1},  # once: still flagged
        "pc-3": {"wmi_spawns_cmd": 6, "windows_security_log_cleared": 1},  # other finding stands
        "10.0.0.1": {"auth_bruteforce": 9},
    }
    assert methods.suppress_recurring(fired) == {"pc-2", "pc-3", "10.0.0.1"}
    assert methods.is_process_rule("excel_spawns_powershell")
    assert methods.is_process_rule("process_from_temp_folder")
    assert not methods.is_process_rule("password_spray")


def test_threshold_method_uses_failures_and_ports() -> None:
    vectors = {"a": [10, 0, 0, 0, 0, 0], "b": [0, 0, 5, 20, 0, 0], "c": [9, 0, 100, 19, 3, 0]}
    assert methods.run_threshold(vectors) == {"a", "b"}


def test_dataset_loader_reads_labelled_events(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    rows = [
        {
            "event_time": "2026-11-14T10:00:00Z",
            "event_type": "auth.failure",
            "entity": "10.0.0.1",
            "label": "benign",
            "src_ip": "10.0.0.1",
            "username": "ann",
        },
        {
            "event_time": "2026-11-14T10:00:05",
            "event_type": "auth.failure",
            "entity": "10.0.0.2",
            "label": "brute_force",
            "src_ip": "10.0.0.2",
            "username": "bob",
            "id": "x1",
        },
        {
            "event_time": "2026-11-14T10:00:06Z",
            "event_type": "auth.failure",
            "entity": "10.0.0.2",
            "label": "benign",
            "src_ip": "10.0.0.2",
            "username": "bob",
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n\n", encoding="utf-8")
    events, labels = load_labelled_events(path)
    assert len(events) == 3 and events[1]["id"] == "x1"
    assert events[0]["event_time"] == datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
    assert events[1]["event_time"].tzinfo is not None
    assert labels == {
        "10.0.0.1": "benign",
        "10.0.0.2": "brute_force",
    }  # any attack event labels the entity
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"event_type": "x"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        load_labelled_events(bad)


def test_the_evaluation_runs_end_to_end_on_a_small_simulation() -> None:
    pytest.importorskip("sklearn")
    from sentinel_eval import report
    from sentinel_eval.experiment import evaluate, prevalence_sweep

    result = evaluate(seeds=2, size=150, prevalence=0.2, hard_scale=0.5)
    assert set(result["methods"]) == {"rules", "suppressed", "threshold", "forest", "hybrid"}
    for entry in result["methods"].values():
        assert entry["tp"] + entry["fn"] > 0 and entry["fp"] + entry["tn"] > 0
        assert entry["recall"] is not None
    # The hybrid flags everything the rules flag, so it can only gain recall.
    assert result["methods"]["hybrid"]["recall"] >= result["methods"]["rules"]["recall"]
    assert result["methods"]["suppressed"]["fp"] <= result["methods"]["rules"]["fp"]
    sweep = prevalence_sweep(2, 150, result)
    figures = [report.bar_chart(result), report.heatmap(result), report.prevalence_chart(sweep)]
    assert all(figure.startswith("<svg") and figure.endswith("</svg>") for figure in figures)
    text = report.markdown(result, sweep, [result], "2026-11-14")
    assert "Kesinlik" in text and "Sınırlılıklar" in text
    assert not math.isnan(result["methods"]["rules"]["f1"] or 0)


def _capture_zip(path, rows) -> None:
    import zipfile

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("capture.json", "\n".join(json.dumps(r) for r in rows) + "\n")


def test_otrf_conversion_keeps_only_what_the_sensor_collects(tmp_path) -> None:
    from sentinel_eval.otrf import convert, load_capture

    process = {
        "Channel": "Security",
        "EventID": 4688,
        "Hostname": "pc1",
        "@timestamp": "2020-09-14T12:06:03.849Z",
        "NewProcessName": r"C:\Windows\System32\mshta.exe",
        "ParentProcessName": r"C:\Windows\explorer.exe",
    }
    event = convert(process, 1)
    assert event["event_type"] == "process.start" and event["host_id"] == "pc1"
    assert event["attributes"]["process_name"].endswith("mshta.exe")
    assert event["event_time"].tzinfo is not None
    account = convert(
        {
            "Channel": "Security",
            "EventID": 4720,
            "Hostname": "pc1",
            "EventTime": "2020-09-14 08:06:02",
        },
        2,
    )
    assert account["event_type"] == "endpoint.identity.account_created"
    assert (
        convert(
            {
                "Channel": "Sysmon",
                "EventID": 1,
                "Hostname": "pc1",
                "@timestamp": "2020-09-14T12:06:03Z",
            },
            3,
        )
        is None
    )
    assert (
        convert(
            {
                "Channel": "Security",
                "EventID": 4663,
                "Hostname": "pc1",
                "@timestamp": "2020-09-14T12:06:03Z",
            },
            4,
        )
        is None
    )
    assert (
        convert({"Channel": "Security", "EventID": 4688, "Hostname": "pc1", "@timestamp": "bad"}, 5)
        is None
    )

    path = tmp_path / "x.zip"
    _capture_zip(
        path,
        [
            process,
            {
                "Channel": "Security",
                "EventID": 4663,
                "Hostname": "pc1",
                "@timestamp": "2020-09-14T12:06:04Z",
            },
        ],
    )
    events, counts = load_capture(path)
    assert len(events) == 1 and counts == {"lines": 2, "security_events": 2}


def test_run_otrf_reports_a_hit_and_a_miss(tmp_path, monkeypatch) -> None:
    import run_otrf
    from sentinel_eval.otrf import Capture

    monkeypatch.setattr(
        run_otrf,
        "CAPTURES",
        (
            Capture("hit.zip", "T1218.005", ("mshta_spawns_powershell",), "mshta"),
            Capture("miss.zip", "T1047", ("wmi_spawns_cmd",), "wmi", diagnosis="not logged"),
            Capture("absent.zip", "T0000", ("x",), "not downloaded"),
        ),
    )
    spawn = {
        "Channel": "Security",
        "EventID": 4688,
        "Hostname": "pc1",
        "@timestamp": "2020-09-14T12:06:03Z",
        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentProcessName": r"C:\Windows\System32\mshta.exe",
    }
    _capture_zip(tmp_path / "hit.zip", [spawn])
    _capture_zip(tmp_path / "miss.zip", [spawn])
    rows = run_otrf.run(tmp_path)
    by_name = {row["file"]: row for row in rows}
    assert by_name["hit.zip"]["hit"] is True and by_name["miss.zip"]["hit"] is False
    assert by_name["absent.zip"]["missing"] is True
    text = run_otrf.markdown(rows)
    assert "1 / 2" in text and "not logged" in text and "absent.zip" in text


def test_flow_csv_converter_round_trips_into_the_evaluation_format(tmp_path) -> None:
    import csv

    import convert_flows_csv
    from sentinel_eval import methods
    from sentinel_eval.datasets import load_labelled_events

    source = tmp_path / "flows.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Source IP", "Destination IP", "Destination Port", "Timestamp", "Label"])
        for i in range(60):  # a fast scan from one address
            writer.writerow(
                ["203.0.113.5", "192.0.2.10", 1000 + i, f"2017-07-07 10:00:{i:02d}", "PortScan"]
            )
        for i in range(20):  # ordinary traffic from another
            writer.writerow(["10.0.0.2", "192.0.2.20", 443, f"2017-07-07 10:00:{i:02d}", "BENIGN"])
        writer.writerow(["not-an-ip", "192.0.2.20", 80, "2017-07-07 10:01:00", "BENIGN"])
    target = tmp_path / "events.jsonl"
    counts = convert_flows_csv.convert(
        source,
        target,
        src="Source IP",
        dst="Destination IP",
        dport="Destination Port",
        time_col="Timestamp",
        label="Label",
    )
    assert counts == {"rows": 81, "written": 80, "skipped": 1, "attack_rows": 60}
    events, labels = load_labelled_events(target)
    assert labels == {"203.0.113.5": "PortScan", "10.0.0.2": "benign"}
    fired = methods.run_rules(events)
    assert "port_scan_like" in fired.get("203.0.113.5", {})
    assert "10.0.0.2" not in fired


def test_flow_converter_handles_decimal_addresses_and_odd_time_formats() -> None:
    import convert_flows_csv

    assert convert_flows_csv.address("3232238085", "int") == "192.168.10.5"
    assert convert_flows_csv.address(" 10.0.0.1 ", "dotted") == "10.0.0.1"
    assert convert_flows_csv.parse_time("7/7/2017 15:30").hour == 15
    assert convert_flows_csv.parse_time("2017-07-07T15:30:00Z").tzinfo is not None
    import pytest

    with pytest.raises(ValueError):
        convert_flows_csv.parse_time("53:44.4")  # minutes and seconds only: not a usable timestamp
