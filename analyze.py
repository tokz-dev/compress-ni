#!/usr/bin/env python3
"""Summarize a COMPRESS-NI hosted rerun without third-party dependencies."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


SUMMARY_FIELDS = (
    "firewallFixedStable", "firewallProtectedRetention", "firewallControlRetention",
    "firewallEvidenceRetention", "firewallMeanKeptRatio", "firewallBudgetExceededRate",
    "firewallMeanBudgetOvershootBytes", "firewallP95BudgetOvershootBytes",
    "flatProtectedRetention", "flatControlRetention", "flatEvidenceRetention",
    "flatMeanKeptRatio", "flatMeanRatioAbsoluteError", "flatMaxRatioAbsoluteError",
    "reserveHeadEvidenceRetention", "reserveHeadMeanKeptRatio",
)
RATE_FIELDS = {
    "firewallFixedStable", "firewallProtectedRetention", "firewallControlRetention",
    "firewallEvidenceRetention", "firewallMeanKeptRatio", "firewallBudgetExceededRate",
    "flatProtectedRetention", "flatControlRetention", "flatEvidenceRetention",
    "flatMeanKeptRatio", "flatMeanRatioAbsoluteError", "flatMaxRatioAbsoluteError",
    "reserveHeadEvidenceRetention", "reserveHeadMeanKeptRatio",
}


def mean(values: list[float]) -> float:
    if not values:
        raise ValueError("cannot average an empty sequence")
    return sum(values) / len(values)


def percentile(values: list[float], q: float) -> float:
    if not values or not 0 <= q <= 1:
        raise ValueError("invalid percentile input")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))]


def _number(row: dict[str, Any], key: str) -> float:
    value = row.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"observation has invalid {key}")
    return float(value)


def summarize_run(report: dict[str, Any]) -> dict[str, Any]:
    comparison = report.get("comparison")
    stress = report.get("stress")
    if not isinstance(comparison, list) or not comparison:
        raise ValueError("hosted report needs a non-empty comparison list")
    if not isinstance(stress, list) or not stress:
        raise ValueError("hosted report needs a non-empty stress list")

    flags = lambda key: sum(row.get(key) is True for row in comparison) / len(comparison)
    values = lambda key: [_number(row, key) for row in comparison]
    summary = {
        "firewallFixedStable": flags("firewallFixedStable"),
        "firewallProtectedRetention": mean(values("firewallProtectedRetention")),
        "firewallControlRetention": mean(values("firewallControlRetention")),
        "firewallEvidenceRetention": flags("firewallEvidenceRetained"),
        "firewallMeanKeptRatio": mean(values("firewallKeptRatio")),
        "firewallBudgetExceededRate": flags("firewallBudgetExceeded"),
        "firewallMeanBudgetOvershootBytes": mean(values("budgetOvershootBytes")),
        "firewallP95BudgetOvershootBytes": percentile(values("budgetOvershootBytes"), 0.95),
        "flatProtectedRetention": mean(values("flatProtectedRetention")),
        "flatControlRetention": mean(values("flatControlRetention")),
        "flatEvidenceRetention": flags("flatEvidenceRetained"),
        "flatMeanKeptRatio": mean(values("flatKeptRatio")),
        "flatMeanRatioAbsoluteError": mean(values("flatRatioAbsoluteError")),
        "flatMaxRatioAbsoluteError": max(values("flatRatioAbsoluteError")),
        "reserveHeadEvidenceRetention": flags("reserveHeadEvidenceRetained"),
        "reserveHeadMeanKeptRatio": mean(values("reserveHeadKeptRatio")),
    }
    formats: dict[str, int] = {}
    methods: dict[str, dict[str, int]] = {}
    violations = 0
    replay_trials = 0
    replay_mismatches = 0
    for row in stress:
        fmt = row.get("format")
        method = row.get("dataMethod")
        if not isinstance(fmt, str) or not isinstance(method, str):
            raise ValueError("stress observation has invalid format or method")
        formats[fmt] = formats.get(fmt, 0) + 1
        bucket = methods.setdefault(fmt, {})
        bucket[method] = bucket.get(method, 0) + 1
        violations += row.get("violated") is True
        replay_trials += row.get("replayChecked") is True
        replay_mismatches += row.get("replayMismatch") is True
    return {
        "comparison": {"cases": len(comparison), "summary": summary},
        "stress": {
            "trials": len(stress),
            "formats": formats,
            "methods": methods,
            "violations": violations,
            "replayTrials": replay_trials,
            "replayMismatches": replay_mismatches,
        },
    }


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def validate_paper_summary(summary: dict[str, Any]) -> None:
    try:
        paper = summary["paperRun"]
        comparison = paper["comparison"]
        metrics = comparison["summary"]
        stress = paper["stress"]
    except (KeyError, TypeError) as error:
        raise ValueError("summary does not have the COMPRESS-NI paper schema") from error
    protocol = comparison.get("protocol")
    if not isinstance(protocol, dict) or protocol.get("cases") != 500 or stress.get("trials") != 2000:
        raise ValueError("summary protocol counts do not match the paper")
    if any(
        not isinstance(metrics.get(field), (int, float)) or isinstance(metrics.get(field), bool)
        for field in SUMMARY_FIELDS
    ):
        raise ValueError("summary has missing or invalid comparison metric")
    if any(not 0 <= float(metrics[field]) <= 1 for field in RATE_FIELDS):
        raise ValueError("summary contains a rate outside [0, 1]")
    formats = stress.get("formats")
    methods = stress.get("methods")
    if not isinstance(formats, dict) or sum(formats.values()) != stress["trials"]:
        raise ValueError("stress format counts do not sum to the trial count")
    if not isinstance(methods, dict) or set(methods) != set(formats):
        raise ValueError("stress method buckets do not match the formats")
    for name, count in formats.items():
        bucket = methods.get(name)
        if not isinstance(bucket, dict) or sum(bucket.values()) != count:
            raise ValueError(f"stress method counts do not sum for {name}")
    if stress.get("violations") != 0 or stress.get("replayMismatches") != 0:
        raise ValueError("paper summary invariant result is inconsistent")
    if stress.get("replayTrials") != 250:
        raise ValueError("paper summary replay count is inconsistent")
    latency = paper.get("localLatencyMs")
    if not isinstance(latency, list) or len(latency) != 5:
        raise ValueError("paper summary must contain five local latency rows")
    for row in latency:
        if not isinstance(row, dict) or row.get("actualDataBytes", 0) <= 0:
            raise ValueError("paper summary has an invalid latency row")
        for prefix in ("firewall", "direct"):
            p50 = row.get(f"{prefix}P50Ms")
            p95 = row.get(f"{prefix}P95Ms")
            invalid = (
                not isinstance(p50, (int, float))
                or not isinstance(p95, (int, float))
                or p50 < 0
                or p95 < p50
            )
            if invalid:
                raise ValueError("paper summary has invalid latency percentiles")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="hosted result JSON from reproduce.py")
    parser.add_argument("--summary", type=Path, help="checked-in compact paper summary")
    parser.add_argument("--validate", action="store_true", help="validate the compact paper summary")
    args = parser.parse_args()
    if bool(args.input) == bool(args.summary):
        parser.error("pass exactly one of --input or --summary")
    source = load_json(args.input or args.summary)
    if args.input:
        print(json.dumps(summarize_run(source), indent=2, sort_keys=True))
    else:
        validate_paper_summary(source)
        paper = source["paperRun"]
        metrics = paper["comparison"]["summary"]
        print("PASS: compact paper summary is internally consistent")
        print(f"  comparison cases: {paper['comparison']['protocol']['cases']}")
        print(
            "  protected/control retention: "
            f"{metrics['firewallProtectedRetention']:.1%} / "
            f"{metrics['firewallControlRetention']:.1%}"
        )
        print(f"  stress violations: {paper['stress']['violations']} / {paper['stress']['trials']}")


if __name__ == "__main__":
    main()
