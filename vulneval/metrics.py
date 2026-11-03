"""Metric computation.

Input is one result dict per evaluated sample:

    {
        "pair_id": str, "category": str,
        "is_vulnerable": bool,
        "detected": bool,        # vulnerable sample flagged *with its own category*
        "flagged": bool,         # any finding at all (used for clean samples)
        "patch_attempted": bool,
        "patch_succeeded": bool | None,
    }

Definitions:
- TP: vulnerable sample detected with its correct category.
- FN: vulnerable sample not detected (missed, or flagged only with a
  wrong category).
- FP: fixed (clean) sample flagged with anything.
- TN: fixed sample left alone.
- False-positive burden = FP / TP: how many false alarms a reviewer
  processes per true finding. This is the workload metric — in production
  triage, reviewer time is the scarce resource, not model calls.
"""

from __future__ import annotations


def precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _counts(results: list[dict]) -> dict:
    tp = sum(1 for r in results if r["is_vulnerable"] and r["detected"])
    fn = sum(1 for r in results if r["is_vulnerable"] and not r["detected"])
    fp = sum(1 for r in results if not r["is_vulnerable"] and r["flagged"])
    tn = sum(1 for r in results if not r["is_vulnerable"] and not r["flagged"])
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _block(results: list[dict]) -> dict:
    counts = _counts(results)
    precision, recall, f1 = precision_recall_f1(counts["tp"], counts["fp"], counts["fn"])
    return {**counts, "precision": precision, "recall": recall, "f1": f1}


def summarize(results: list[dict]) -> dict:
    overall = _block(results)
    overall["fp_burden"] = (
        overall["fp"] / overall["tp"] if overall["tp"] else None
    )

    categories = sorted({r["category"] for r in results})
    per_category = {
        category: _block([r for r in results if r["category"] == category])
        for category in categories
    }

    attempted = [r for r in results if r["patch_attempted"]]
    succeeded = [r for r in attempted if r["patch_succeeded"]]
    true_positives = [r for r in results if r["is_vulnerable"] and r["detected"]]
    patch = {
        "attempted": len(attempted),
        "succeeded": len(succeeded),
        "success_rate": (len(succeeded) / len(attempted)) if attempted else None,
        "coverage": (len(attempted) / len(true_positives)) if true_positives else None,
    }

    return {"overall": overall, "per_category": per_category, "patch": patch}
