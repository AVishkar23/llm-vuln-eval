"""Metric math, checked against a hand-computed toy example."""

import pytest

from vulneval.metrics import precision_recall_f1, summarize


def _row(pair_id, category, is_vulnerable, detected=False, flagged=False,
         patch_attempted=False, patch_succeeded=None):
    return {
        "pair_id": pair_id,
        "category": category,
        "is_vulnerable": is_vulnerable,
        "detected": detected,
        "flagged": flagged,
        "patch_attempted": patch_attempted,
        "patch_succeeded": patch_succeeded,
    }


def test_precision_recall_f1_toy():
    # 2 TP, 1 FP, 1 FN -> P = R = F1 = 2/3
    precision, recall, f1 = precision_recall_f1(tp=2, fp=1, fn=1)
    assert precision == pytest.approx(2 / 3)
    assert recall == pytest.approx(2 / 3)
    assert f1 == pytest.approx(2 / 3)


def test_precision_recall_f1_zero_division_is_zero():
    assert precision_recall_f1(0, 0, 0) == (0.0, 0.0, 0.0)


def test_summarize_toy_example():
    results = [
        # vulnerable: A and B detected, C missed
        _row("a", "sql_injection", True, detected=True, flagged=True,
             patch_attempted=True, patch_succeeded=True),
        _row("b", "sql_injection", True, detected=True, flagged=True,
             patch_attempted=True, patch_succeeded=False),
        _row("c", "path_traversal", True, detected=False, flagged=False),
        # clean: D wrongly flagged, E left alone
        _row("d", "sql_injection", False, flagged=True),
        _row("e", "path_traversal", False, flagged=False),
    ]
    summary = summarize(results)
    overall = summary["overall"]
    assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (2, 1, 1, 1)
    assert overall["precision"] == pytest.approx(2 / 3)
    assert overall["recall"] == pytest.approx(2 / 3)
    # headline workload metric: 1 false alarm per 2 true findings
    assert overall["fp_burden"] == pytest.approx(0.5)

    sqli = summary["per_category"]["sql_injection"]
    assert (sqli["tp"], sqli["fp"], sqli["fn"], sqli["tn"]) == (2, 1, 0, 0)
    traversal = summary["per_category"]["path_traversal"]
    assert (traversal["tp"], traversal["fn"], traversal["tn"]) == (0, 1, 1)

    patch = summary["patch"]
    assert patch["attempted"] == 2
    assert patch["succeeded"] == 1
    assert patch["success_rate"] == pytest.approx(0.5)
    assert patch["coverage"] == pytest.approx(1.0)  # 2 attempted / 2 true positives
