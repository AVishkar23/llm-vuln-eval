"""Markdown report generation.

Two shapes:
- ``render_markdown`` — a single detector's report.
- ``render_combined_markdown`` — every offline baseline in one document,
  plus a disagreement section: the samples where the detectors differ are
  the analytically interesting output of running two baselines, because
  they separate "this failure is a scope limit" from "this failure is a
  blind spot in the method itself."
"""

from __future__ import annotations


def _pct(x: float) -> str:
    return f"{x:.2f}"


def _detector_body(summary: dict, misses, false_positives, patch_rows) -> list[str]:
    """Headline + detection tables + patch table + miss/FP lists for one detector."""
    o = summary["overall"]
    p = summary["patch"]
    burden = o["fp_burden"]
    burden_text = "n/a (no true positives)" if burden is None else f"{burden:.2f}"

    lines = [
        "### Headline",
        "",
        f"**False-positive burden: {burden_text} false positives per true finding.**",
        "",
        "That ratio is the reviewer-workload metric: every false positive is an alert a "
        "human has to open, read, and dismiss before reaching real work.",
        "",
        "### Detection — overall",
        "",
        "| TP | FP | FN | TN | Precision | Recall | F1 |",
        "|----|----|----|----|-----------|--------|----|",
        f"| {o['tp']} | {o['fp']} | {o['fn']} | {o['tn']} | {_pct(o['precision'])} | {_pct(o['recall'])} | {_pct(o['f1'])} |",
        "",
        "### Detection — per category",
        "",
        "| Category | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|----------|----|----|----|----|-----------|--------|----|",
    ]
    for category, b in summary["per_category"].items():
        lines.append(
            f"| {category} | {b['tp']} | {b['fp']} | {b['fn']} | {b['tn']} | "
            f"{_pct(b['precision'])} | {_pct(b['recall'])} | {_pct(b['f1'])} |"
        )

    lines += [
        "",
        "### Patch quality (proxy)",
        "",
        "A patch counts as successful if (1) the harness's own pattern check no longer "
        "fires on the patched code, and (2) at least one marker of the reference fix "
        "(from the dataset labels) is present. This is a proxy, not a proof of correctness. "
        "A detector that does not propose patches reports 0 attempted — that is a scope "
        "statement, not a failure.",
        "",
        "| Patches attempted | Succeeded | Success rate (of attempted) | Coverage (of true positives) |",
        "|----|----|----|----|",
        f"| {p['attempted']} | {p['succeeded']} | "
        f"{'n/a' if p['success_rate'] is None else _pct(p['success_rate'])} | "
        f"{'n/a' if p['coverage'] is None else _pct(p['coverage'])} |",
        "",
    ]
    if patch_rows:
        lines += [
            "| Sample | Attempted | Pattern removed | Fix marker present | Success |",
            "|--------|-----------|-----------------|--------------------|---------|",
        ]
        for row in patch_rows:
            lines.append(
                f"| {row['sample_id']} | {'yes' if row['attempted'] else 'no'} | "
                f"{'yes' if row['pattern_removed'] else 'no' if row['attempted'] else '—'} | "
                f"{'yes' if row['marker_present'] else 'no' if row['attempted'] else '—'} | "
                f"{'yes' if row['succeeded'] else 'no'} |"
            )
        lines.append("")

    lines += ["### Misses (false negatives)", ""]
    if misses:
        for miss in misses:
            lines.append(
                f"- **{miss['sample_id']}** ({miss['category']}, {miss['language']}): {miss['explanation']}"
            )
    else:
        lines.append("- None.")
    lines += ["", "### False positives", ""]
    if false_positives:
        for fp in false_positives:
            lines.append(
                f"- **{fp['sample_id']}** (clean sample) flagged as: {', '.join(fp['flagged_as'])}"
            )
    else:
        lines.append("- None.")
    lines.append("")
    return lines


_HOW_TO_READ_SINGLE = [
    "## How to read these numbers",
    "",
    "- The dataset is small and synthetic by design (self-authored teaching samples, "
    "not real CVE code), so treat the metrics as a methodology demonstration and a "
    "baseline reference point — not as a benchmark of any production tool or model.",
    "- The heuristic baseline is *not* an LLM. Its blind spots are the interesting "
    "part: they show the classes of vulnerability that pure pattern matching "
    "structurally cannot catch, which is the gap an LLM detector is evaluated against.",
    "- Detection credit requires the *correct category*: flagging a sample with the "
    "wrong label counts as a miss, because a mislabeled alert sends the reviewer to "
    "the wrong fix.",
    "",
]

_HOW_TO_READ_COMBINED = [
    "## How to read these numbers",
    "",
    "- The dataset is small and synthetic by design (self-authored teaching samples, "
    "not real CVE code), so treat the metrics as a methodology demonstration and "
    "baseline reference points — not as a benchmark of any production tool or model.",
    "- Neither baseline is an LLM. Both exist to define the floor an LLM detector "
    "must beat, and to show *where* non-LLM methods fail — the failure location is "
    "the argument for what the LLM has to add (data-flow and semantic reasoning).",
    "- The AST baseline's scope is deliberately narrower: Python only, and only "
    "dataflow categories (SQL injection, SSRF, path traversal, insecure "
    "deserialization). Its misses on Java samples and on API-misuse categories "
    "(hardcoded credentials, weak cryptography, XXE) are scope statements, not "
    "signal — compare it per-category and within Python, not just on the overall row.",
    "- Detection credit requires the *correct category*: flagging a sample with the "
    "wrong label counts as a miss, because a mislabeled alert sends the reviewer to "
    "the wrong fix.",
    "",
]


def _header(dataset_version, run_date, n_vulnerable, n_fixed, n_categories) -> list[str]:
    return [
        "# LLM Vulnerability-Detection Eval — Results",
        "",
        f"- **Run date:** {run_date}",
        f"- **Dataset:** v{dataset_version} — {n_vulnerable + n_fixed} samples "
        f"({n_vulnerable} vulnerable / {n_fixed} fixed), {n_categories} categories, Python + Java",
        "",
    ]


def render_markdown(
    *,
    detector_name: str,
    dataset_version: str,
    run_date: str,
    n_vulnerable: int,
    n_fixed: int,
    n_categories: int,
    summary: dict,
    misses: list[dict],
    false_positives: list[dict],
    patch_rows: list[dict],
) -> str:
    lines = _header(dataset_version, run_date, n_vulnerable, n_fixed, n_categories)
    lines.insert(2, f"- **Detector:** `{detector_name}`")
    # Promote the single-detector body from ### to ## headings.
    body = _detector_body(summary, misses, false_positives, patch_rows)
    lines += [line.replace("### ", "## ", 1) if line.startswith("### ") else line
              for line in body]
    lines += _HOW_TO_READ_SINGLE
    return "\n".join(lines)


def _verdict(sample_verdict: dict) -> str:
    if sample_verdict["is_vulnerable"]:
        return "caught" if sample_verdict["detected"] else "missed"
    return "flagged (FP)" if sample_verdict["flagged"] else "clean"


def render_combined_markdown(
    *,
    dataset_version: str,
    run_date: str,
    n_vulnerable: int,
    n_fixed: int,
    n_categories: int,
    sections: list[dict],
    verdicts: dict[str, dict[str, dict]],
) -> str:
    """sections: [{detector_name, summary, misses, false_positives, patch_rows}]
    verdicts: {detector_name: {sample_id: {is_vulnerable, detected, flagged, category}}}"""
    lines = _header(dataset_version, run_date, n_vulnerable, n_fixed, n_categories)
    names = [s["detector_name"] for s in sections]
    lines.insert(2, "- **Detectors:** " + ", ".join(f"`{n}`" for n in names))
    for section in sections:
        lines += [f"## Detector: `{section['detector_name']}`", ""]
        lines += _detector_body(
            section["summary"],
            section["misses"],
            section["false_positives"],
            section["patch_rows"],
        )

    # ---- disagreement analysis ----
    lines += [
        "## Where the detectors disagree",
        "",
        "Samples where the two baselines reach different verdicts. Agreement is "
        "not shown — the disagreements are where the methods' actual difference "
        "lives.",
        "",
        "| Sample | Category | " + " | ".join(f"`{n}`" for n in names) + " |",
        "|--------|----------|" + "---|" * len(names),
    ]
    sample_ids = sorted(next(iter(verdicts.values())).keys()) if verdicts else []
    disagreements = 0
    for sample_id in sample_ids:
        row_verdicts = {name: _verdict(verdicts[name][sample_id]) for name in names}
        if len(set(row_verdicts.values())) == 1:
            continue
        disagreements += 1
        category = next(iter(verdicts.values()))[sample_id]["category"]
        lines.append(
            f"| {sample_id} | {category} | "
            + " | ".join(row_verdicts[name] for name in names)
            + " |"
        )
    if not disagreements:
        lines.append("| (none) | — | " + " | ".join("—" for _ in names) + " |")
    lines += [
        "",
        "Reading the disagreements: a sample *missed by the AST baseline and caught "
        "by the heuristic* is almost always outside the AST detector's declared "
        "scope (Java, or an API-misuse category). A sample *caught by the AST "
        "baseline and missed by the heuristic* is a data-flow variant — the flaw "
        "only exists as a flow from source to sink, not as a suspicious line of "
        "text. The second kind is the one an LLM detector is expected to win on "
        "too; the first kind is a reminder that 'use an LLM' does not retire the "
        "linter.",
        "",
    ]
    lines += _HOW_TO_READ_COMBINED
    return "\n".join(lines)
