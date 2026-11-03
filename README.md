# LLM Vulnerability-Detection Evaluation Harness

**Problem.** Point an LLM (or any automated tool) at code and ask "is this
vulnerable?" and it will happily answer — the hard part is knowing whether to
believe it. Two failure modes matter in practice, and demos measure neither:

1. **Misses** — a real vulnerability the detector walks past.
2. **False alarms** — clean code flagged as vulnerable. Every false alarm is
   paid for in human reviewer time: someone has to open it, understand it,
   and dismiss it before reaching real work.

This project is a small, fully reproducible evaluation harness that measures
both, plus a third question that matters once detectors start proposing
fixes: **when the detector patches the code, is the patch actually the fix?**

It grows out of production questions, not benchmark-chasing: on a bank
fraud-risk engineering team, the author found and patched vulnerabilities in
live services and worked on GenAI-assisted detection for fraud-risk
workflows. The operational question there is identical to the one here —
*how much can we trust automated detection, and what does it cost the humans
who review its output?*

## What it measures

| Metric | Meaning |
|---|---|
| Precision / recall / F1 | Detection quality, per category and overall. Credit requires the **correct category** — a mislabeled alert sends a reviewer to the wrong fix. |
| **False-positive burden** | **False positives per true finding** — the headline metric. It converts model error into reviewer workload. |
| Patch quality (proxy) | A proposed patch passes if the vulnerable pattern is gone from the patched code **and** at least one marker of the reference fix is present. |

## Dataset

22 samples: **11 vulnerable/fixed pairs** across **7 categories**, in Python
and Java (`data/manifest.json`, `data/samples/`).

Categories: SQL injection, XXE, insecure deserialization, path traversal,
SSRF, hardcoded credentials, weak cryptography.

Each pair is labeled with the category, severity, the exact vulnerable
line(s), an explanation of the flaw, a summary of the fix, and *fix markers*
— strings a correct fix is expected to contain, used by the patch scorer.

**The samples are small, synthetic, and self-authored for this project.**
They are teaching examples, not copies of real CVE code and not excerpts
from any production codebase. That is deliberate: the dataset is safe to
publish, every label is known-good, and the fixed counterpart of each sample
doubles as a clean negative control. The cost — realism — is stated plainly
in the limitations below.

## Detectors

Detectors implement one small interface (`vulneval/detectors/base.py`):
`detect(sample) -> [Finding]` and optionally `propose_patch(sample)`.

- **`heuristic` (default, fully offline).** Mitigation-aware regex rules
  (`vulneval/patterns.py`): a rule fires when its pattern matches *and* no
  mitigation token is present — which is why it (correctly) stays quiet on
  the fixed samples. Its patcher is template-based and only attempts
  categories with a known mechanical fix. Think of it as the floor an LLM
  has to beat — the automated equivalent of a linter.
- **`anthropic` (optional, needs a key).** Sends each sample to the
  Anthropic API and asks for structured JSON findings plus a patch. It
  activates only when `ANTHROPIC_API_KEY` is set; without one it stops with
  setup instructions rather than silently falling back to another detector.

## How to run

```bash
# Offline baseline run (standard library only) — writes results/REPORT.md
make run
# equivalently:
python3 -m vulneval run --detector heuristic --out results/REPORT.md

# Evaluate a real LLM
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m vulneval run --detector anthropic --out results/REPORT-LLM.md

# Tests (dataset integrity + metric math + detector behavior)
python3 -m venv .venv && .venv/bin/pip install pytest   # one-time
make test
```

## Baseline results (heuristic detector, dataset v1.0)

From `results/REPORT.md` (regenerate it any time with `make run`):

| TP | FP | FN | TN | Precision | Recall | F1 | FP burden |
|----|----|----|----|-----------|--------|----|-----------|
| 10 | 0 | 1 | 11 | 1.00 | 0.91 | 0.95 | **0.00** |

- **The one miss is the instructive one:** the Java path-traversal sample
  builds its path with the `Paths`/`resolve` API instead of
  `File`/`open`, so the pattern rule never fires. Pattern matching
  structurally cannot chase API variants — that gap is exactly what an LLM
  detector is being evaluated to close.
- **Patching:** 5 of 10 true positives had a template patch attempted; all
  5 passed the proxy check (coverage 0.50). SQL injection, path traversal,
  and SSRF fixes were *not* attempted — they need semantic rewriting, not
  templates.
- Per-category detail, the miss list, and methodology notes are in the
  generated report.

## Limitations — read this before quoting any number

- **Small synthetic dataset.** 22 hand-written samples cannot represent
  real-world code. These numbers demonstrate a methodology and pin down a
  reproducible baseline; they are not a benchmark of any tool or model and
  would not survive contact with a production codebase unchanged.
- **The baseline is not an LLM.** The heuristic detector's scores say
  something about regex rules on this dataset — nothing about LLM
  capability. LLM numbers exist only after a run with `--detector anthropic`.
- **FP burden of 0.00 is a property of this setup, not a promise.** The
  rules are conservative and the negative controls are the dataset's own
  reference fixes — cleaner than real "clean" code. On real codebases,
  expect false positives; measuring how many is the point of the harness.
- **The patch metric is a proxy.** Pattern-gone + marker-present does not
  prove a patch compiles, preserves behavior, or is complete. It is a
  cheap, deterministic screen — the honest next step is compiling and
  testing patched code.
- **Self-authored samples risk self-deception:** the same person wrote the
  flaws, the fixes, and the rules. The test suite guards label integrity
  (counterparts exist, markers discriminate, lines point at the flaw), but
  an external dataset (e.g. a curated CVE corpus) is the obvious hardening
  step.

## Layout

```
data/            manifest.json (labels) + samples/ (vulnerable/fixed pairs)
vulneval/        dataset loading, patterns, detectors, metrics, report, CLI
tests/           dataset integrity, metric math, detector behavior
results/         generated reports (REPORT.md is the current baseline run)
WALKTHROUGH.md   author's notes: design decisions and how to explain them
```
