"""Command-line entry point.

    python -m vulneval run [--detector heuristic|anthropic] [--out results/REPORT.md]
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .dataset import load_dataset, load_manifest
from .detectors import DETECTORS
from .detectors.anthropic import AnthropicDetector
from .metrics import summarize
from .patterns import pattern_fires
from .report import render_markdown

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _evaluate(detector, samples):
    results = []
    misses, false_positives, patch_rows = [], [], []
    for sample in samples:
        findings = detector.detect(sample)
        detected = sample.is_vulnerable and any(
            f.category == sample.category for f in findings
        )
        row = {
            "pair_id": sample.pair_id,
            "category": sample.category,
            "is_vulnerable": sample.is_vulnerable,
            "detected": detected,
            "flagged": bool(findings),
            "patch_attempted": False,
            "patch_succeeded": None,
        }
        if sample.is_vulnerable and not detected:
            misses.append(
                {
                    "sample_id": sample.sample_id,
                    "category": sample.category,
                    "language": sample.language,
                    "explanation": sample.explanation,
                }
            )
        if not sample.is_vulnerable and findings:
            false_positives.append(
                {
                    "sample_id": sample.sample_id,
                    "flagged_as": sorted({f.category for f in findings}),
                }
            )
        if sample.is_vulnerable and detected:
            patch = detector.propose_patch(sample)
            patch_row = {
                "sample_id": sample.sample_id,
                "attempted": patch is not None,
                "pattern_removed": False,
                "marker_present": False,
                "succeeded": False,
            }
            if patch is not None:
                pattern_removed = not pattern_fires(sample.category, patch)
                marker_present = any(m in patch for m in sample.fix_markers)
                patch_row.update(
                    pattern_removed=pattern_removed,
                    marker_present=marker_present,
                    succeeded=pattern_removed and marker_present,
                )
                row["patch_attempted"] = True
                row["patch_succeeded"] = patch_row["succeeded"]
            patch_rows.append(patch_row)
        results.append(row)
    return results, misses, false_positives, patch_rows


def cmd_run(args) -> int:
    data_dir = Path(args.data) if args.data else PROJECT_ROOT / "data"
    out_path = Path(args.out) if args.out else PROJECT_ROOT / "results" / "REPORT.md"

    if args.detector == "anthropic" and not AnthropicDetector.available():
        print(AnthropicDetector.unavailable_reason(), file=sys.stderr)
        return 2

    detector = DETECTORS[args.detector]()
    manifest = load_manifest(data_dir)
    samples = load_dataset(data_dir)
    results, misses, false_positives, patch_rows = _evaluate(detector, samples)
    summary = summarize(results)

    markdown = render_markdown(
        detector_name=detector.name,
        dataset_version=manifest["dataset_version"],
        run_date=date.today().isoformat(),
        n_vulnerable=sum(1 for s in samples if s.is_vulnerable),
        n_fixed=sum(1 for s in samples if not s.is_vulnerable),
        n_categories=len({s.category for s in samples}),
        summary=summary,
        misses=misses,
        false_positives=false_positives,
        patch_rows=patch_rows,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown)

    o = summary["overall"]
    burden = o["fp_burden"]
    print(f"Detector:            {detector.name}")
    print(f"Samples:             {len(samples)}")
    print(f"TP/FP/FN/TN:         {o['tp']}/{o['fp']}/{o['fn']}/{o['tn']}")
    print(f"Precision / Recall / F1: {o['precision']:.2f} / {o['recall']:.2f} / {o['f1']:.2f}")
    print(f"FP burden (FP per true finding): {'n/a' if burden is None else f'{burden:.2f}'}")
    print(f"Report written to:   {out_path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulneval", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the evaluation and write a Markdown report")
    run.add_argument("--detector", choices=sorted(DETECTORS), default="heuristic")
    run.add_argument("--data", default=None, help="dataset directory (default: project data/)")
    run.add_argument("--out", default=None, help="report path (default: results/REPORT.md)")
    run.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
