"""The synthetic corpus as a regression gate. These thresholds describe
synthetic mail the detectors were designed against, so they are a floor
against regressions, not a claim about real-world accuracy (see
eval/README.md for the real-mail numbers)."""

import os
import sys

EVAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval")
sys.path.insert(0, EVAL)

import make_corpus  # noqa: E402
import run_eval  # noqa: E402


def test_synthetic_corpus_regression_gate(tmp_path):
    counts = make_corpus.build(str(tmp_path), seed=7)
    assert sum(counts.values()) >= 150
    rows = run_eval.score_folder(str(tmp_path / "phish"), "phish") + run_eval.score_folder(
        str(tmp_path / "benign"), "benign"
    )
    result = run_eval.summarise(rows)
    assert result["errors"] == []
    assert result["flagged"]["recall"] >= 0.95
    assert result["flagged"]["false_positive_rate"] <= 0.02
    assert result["timing_ms"]["max"] < 2000
