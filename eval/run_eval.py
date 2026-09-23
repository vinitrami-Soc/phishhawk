#!/usr/bin/env python3
"""Measure PhishHawk against labelled email, offline and deterministically.

    python eval/run_eval.py --synthetic                  score the synthetic corpus (built in a temp dir)
    python eval/run_eval.py --phish DIR --benign DIR     score your own labelled folders
    python eval/run_eval.py --synthetic --json           machine-readable results

"Flagged" means a verdict of SUSPICIOUS or worse: the point at which a human
should look. "Strict" means LIKELY PHISHING or worse.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

from phishhawk.pipeline import triage_file  # noqa: E402

FLAGGED = {"SUSPICIOUS", "LIKELY PHISHING", "MALICIOUS"}
STRICT = {"LIKELY PHISHING", "MALICIOUS"}


def scenario_of(name: str) -> str:
    stem = os.path.splitext(name)[0]
    return re.sub(r"-\d+$", "", stem) if re.search(r"-\d+$", stem) else "(unlabelled)"


def score_folder(path: str, label: str) -> list[dict]:
    rows = []
    for name in sorted(os.listdir(path)):
        if not name.lower().endswith((".eml", ".txt")):
            continue
        started = time.perf_counter()
        try:
            analysis = triage_file(os.path.join(path, name))
            verdict, score, error = analysis.verdict, analysis.score, ""
        except Exception as exc:  # a crash is a result worth reporting, not a reason to stop
            verdict, score, error = "ERROR", 0, "%s: %s" % (type(exc).__name__, exc)
        rows.append(
            {
                "file": name,
                "label": label,
                "scenario": scenario_of(name),
                "verdict": verdict,
                "score": score,
                "seconds": time.perf_counter() - started,
                "error": error,
            }
        )
    return rows


def metrics(rows: list[dict], positive: set[str]) -> dict:
    tp = sum(r["label"] == "phish" and r["verdict"] in positive for r in rows)
    fn = sum(r["label"] == "phish" and r["verdict"] not in positive for r in rows)
    fp = sum(r["label"] == "benign" and r["verdict"] in positive for r in rows)
    tn = sum(r["label"] == "benign" and r["verdict"] not in positive for r in rows)
    ratio = lambda a, b: round(a / b, 4) if b else None  # noqa: E731
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "precision": ratio(tp, tp + fp),
    }


def summarise(rows: list[dict]) -> dict:
    times = sorted(r["seconds"] for r in rows) or [0.0]
    scenarios: dict[str, dict] = {}
    for r in rows:
        entry = scenarios.setdefault(r["scenario"], {"label": r["label"], "n": 0, "flagged": 0})
        entry["n"] += 1
        entry["flagged"] += r["verdict"] in FLAGGED
    return {
        "emails": len(rows),
        "phish": sum(r["label"] == "phish" for r in rows),
        "benign": sum(r["label"] == "benign" for r in rows),
        "errors": [r for r in rows if r["error"]],
        "flagged": metrics(rows, FLAGGED),
        "strict": metrics(rows, STRICT),
        "scenarios": scenarios,
        "timing_ms": {
            "median": round(statistics.median(times) * 1000, 1),
            "p95": round(times[int(0.95 * (len(times) - 1))] * 1000, 1),
            "max": round(times[-1] * 1000, 1),
        },
    }


def pct(value) -> str:
    return "  n/a" if value is None else "%5.1f%%" % (100 * value)


def print_report(title: str, result: dict) -> None:
    print(
        "\n== %s: %d emails (%d phishing, %d legitimate)"
        % (title, result["emails"], result["phish"], result["benign"])
    )
    for name in ("flagged", "strict"):
        m = result[name]
        print(
            "   %-8s recall %s   false-positive rate %s   precision %s   (TP %d FN %d FP %d TN %d)"
            % (
                name,
                pct(m["recall"]),
                pct(m["false_positive_rate"]),
                pct(m["precision"]),
                m["tp"],
                m["fn"],
                m["fp"],
                m["tn"],
            )
        )
    t = result["timing_ms"]
    print(
        "   timing   median %.1f ms   p95 %.1f ms   max %.1f ms   errors %d"
        % (t["median"], t["p95"], t["max"], len(result["errors"]))
    )
    if len(result["scenarios"]) > 1:
        for name, entry in sorted(result["scenarios"].items(), key=lambda kv: (kv[1]["label"], kv[0])):
            rate = entry["flagged"] / entry["n"]
            print(
                "     %-7s %-22s %3d/%-3d flagged %s"
                % (
                    entry["label"],
                    name,
                    entry["flagged"],
                    entry["n"],
                    ""
                    if (rate == 1 and entry["label"] == "phish") or (rate == 0 and entry["label"] == "benign")
                    else "<-",
                )
            )
    for row in result["errors"]:
        print("   ERROR %s: %s" % (row["file"], row["error"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--synthetic", action="store_true", help="build and score the synthetic corpus")
    parser.add_argument("--seed", type=int, default=7, help="seed for the synthetic corpus")
    parser.add_argument("--phish", action="append", default=[], metavar="DIR")
    parser.add_argument("--benign", action="append", default=[], metavar="DIR")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = {}
    if args.synthetic:
        from make_corpus import build

        with tempfile.TemporaryDirectory() as tmp:
            build(tmp, args.seed)
            rows = score_folder(os.path.join(tmp, "phish"), "phish") + score_folder(
                os.path.join(tmp, "benign"), "benign"
            )
        results["synthetic (seed %d)" % args.seed] = summarise(rows)
    if args.phish or args.benign:
        rows = []
        for folder in args.phish:
            rows += score_folder(folder, "phish")
        for folder in args.benign:
            rows += score_folder(folder, "benign")
        results["labelled folders"] = summarise(rows)
    if not results:
        parser.error("give --synthetic and/or --phish/--benign folders")

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for title, result in results.items():
            print_report(title, result)
    return 1 if any(r["errors"] for r in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
