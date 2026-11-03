"""Markdown report generation."""

from __future__ import annotations


def _pct(x: float) -> str:
    return f"{x:.2f}"


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
    o = summary["overall"]
    p = summary["patch"]
    burden = o["fp_burden"]
    burden_text = "n/a (no true positives)" if burden is None else f"{burden:.2f}"

    lines = [
        "# LLM Vulnerability-Detection Eval — Results",
        "",
        f"- **Detector:** `{detector_name}`",
        f"- **Run date:** {run_date}",
        f"- **Dataset:** v{dataset_version} — {n_vulnerable + n_fixed} samples "
        f"({n_vulnerable} vulnerable / {n_fixed} fixed), {n_categories} categories, Python + Java",
        "",
        "## Headline",
        "",
        f"**False-positive burden: {burden_text} false positives per true finding.**",
        "",
        "That ratio is the reviewer-workload metric: every false positive is an alert a "
        "human has to open, read, and dismiss before reaching real work.",
        "",
        "## Detection — overall",
        "",
        "| TP | FP | FN | TN | Precision | Recall | F1 |",
        "|----|----|----|----|-----------|--------|----|",
        f"| {o['tp']} | {o['fp']} | {o['fn']} | {o['tn']} | {_pct(o['precision'])} | {_pct(o['recall'])} | {_pct(o['f1'])} |",
        "",
        "## Detection — per category",
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
        "## Patch quality (proxy)",
        "",
        "A patch counts as successful if (1) the harness's own pattern check no longer "
        "fires on the patched code, and (2) at least one marker of the reference fix "
        "(from the dataset labels) is present. This is a proxy, not a proof of correctness.",
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

    lines += ["## Misses (false negatives)", ""]
    if misses:
        for miss in misses:
            lines.append(
                f"- **{miss['sample_id']}** ({miss['category']}, {miss['language']}): {miss['explanation']}"
            )
    else:
        lines.append("- None.")
    lines += ["", "## False positives", ""]
    if false_positives:
        for fp in false_positives:
            lines.append(
                f"- **{fp['sample_id']}** (clean sample) flagged as: {', '.join(fp['flagged_as'])}"
            )
    else:
        lines.append("- None.")

    lines += [
        "",
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
    return "\n".join(lines)
