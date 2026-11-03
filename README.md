# LLM Vulnerability-Detection Evaluation Harness

[![CI](https://github.com/AVishkar23/llm-vuln-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/AVishkar23/llm-vuln-eval/actions/workflows/ci.yml)

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

## Results at a glance

Two offline baselines, dataset v1.1 (28 samples), from
[`results/REPORT.md`](results/REPORT.md) — regenerate any time with
`make run`:

| Baseline | TP | FP | FN | TN | Precision | Recall | F1 | FP burden |
|----------|----|----|----|----|-----------|--------|----|-----------|
| Regex heuristics (line patterns) | 11 | 0 | 3 | 14 | 1.00 | 0.79 | 0.88 | 0.00 |
| AST taint tracking (data flow) | 7 | 0 | 7 | 14 | 1.00 | 0.50 | 0.67 | 0.00 |

Read the second row carefully before concluding the regex "wins":

- The dataset is half Java, and the AST baseline is **Python-only by
  design**. It also deliberately does not cover API-misuse categories
  (hardcoded credentials, weak crypto, XXE). **Within its scope — the 7
  Python data-flow samples — it catches 7 of 7**, including the two
  samples built specifically to defeat pattern matching (below).
- The baselines disagree on **8 of 28 samples**, and the disagreements are
  the finding: 6 are scope cases only the patterns catch; 2 are data-flow
  variants only taint tracking catches — a second-order SQL injection
  whose payload round-trips through the database, and an SSRF whose
  allowlist check is genuine but whose *redirect target* is never
  re-validated.
- One sample defeats **both**: a Java path traversal written with the
  `Paths`/`resolve` API — invisible to line patterns, and outside the AST
  detector's language. Naming the shared blind spot is part of the point.
- An LLM detector is wired to the same interface (Anthropic API) and runs
  when a key is provided. **No LLM numbers are reported here, because none
  have been measured yet** — baselines are labeled as baselines.

## What it measures

| Metric | Meaning |
|---|---|
| Precision / recall / F1 | Detection quality, per category and overall. Credit requires the **correct category** — a mislabeled alert sends a reviewer to the wrong fix. |
| **False-positive burden** | **False positives per true finding** — the headline metric. It converts detector error into reviewer workload. |
| Patch quality (proxy) | A proposed patch passes if the vulnerable pattern is gone from the patched code **and** at least one marker of the reference fix is present. |
| Detector disagreement | In combined reports, the samples where two detectors reach different verdicts — the fastest route to *why* each method fails. |

## Dataset

28 samples: **14 vulnerable/fixed pairs** across **7 categories**, in Python
and Java (`data/manifest.json`, `data/samples/`).

Categories: SQL injection, XXE, insecure deserialization, path traversal,
SSRF, hardcoded credentials, weak cryptography.

Each pair is labeled with the category, severity, the exact vulnerable
line(s), an explanation of the flaw, a summary of the fix, and *fix markers*
— strings a correct fix is expected to contain, used by the patch scorer.

Dataset v1.1 added three pairs chosen to be hard for line-oriented methods:
**second-order SQL injection** (payload stored safely, exploited on read
back), **SSRF via an unvalidated redirect target** (the initial URL *is*
allowlist-checked), and **`yaml.load` deserialization**.

**The samples are small, synthetic, and self-authored for this project.**
They are teaching examples, not copies of real CVE code and not excerpts
from any production codebase. That is deliberate: the dataset is safe to
publish, every label is known-good, and the fixed counterpart of each sample
doubles as a clean negative control. The cost — realism — is stated plainly
in the limitations below.

## Detectors

Detectors implement one small interface (`vulneval/detectors/base.py`):
`detect(sample) -> [Finding]` and optionally `propose_patch(sample)`.

- **`heuristic` (offline).** Mitigation-aware regex rules
  (`vulneval/patterns.py`): a rule fires when its pattern matches *and* no
  mitigation token is present — which is why it (correctly) stays quiet on
  the fixed samples. Its patcher is template-based and only attempts
  categories with a known mechanical fix (5 of its 11 true positives
  attempted, 5 passed the proxy check). Think of it as the floor an LLM
  has to beat — the automated equivalent of a linter.
- **`ast` (offline).** A taint-tracking static analyzer for Python
  (`vulneval/detectors/ast_taint.py`). Instead of matching text, it tracks
  **provenance**: values carry where they came from (parameters, `input()`,
  database reads, HTTP responses) through assignments, string building,
  and calls — including into and out of helper functions via summaries.
  Sanitizers are category-specific facts: `basename()` neutralizes a value
  *for path sinks* while leaving it tainted for SQL; an allowlist check
  only "covers" the provenance it actually inspected, which is exactly
  what unvalidated redirect targets violate. It proposes no patches —
  detection only, by design.
- **`anthropic` (optional, needs a key).** Sends each sample to the
  Anthropic API and asks for structured JSON findings plus a patch. It
  activates only when `ANTHROPIC_API_KEY` is set; without one it stops
  with setup instructions rather than silently falling back to another
  detector. An eval that quietly swaps detectors produces numbers nobody
  can trust.

## How to run

```bash
# Both offline baselines + disagreement analysis -> results/REPORT.md
make run
# equivalently:
python3 -m vulneval run --detector all --out results/REPORT.md

# A single baseline
python3 -m vulneval run --detector heuristic --out results/REPORT-heuristic.md
python3 -m vulneval run --detector ast       --out results/REPORT-ast.md

# Evaluate a real LLM
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m vulneval run --detector anthropic --out results/REPORT-LLM.md

# Tests (dataset integrity + metric math + both detectors' behavior)
python3 -m venv .venv && .venv/bin/pip install pytest   # one-time
make test        # uses .venv if present, else system pytest (as in CI)
```

The core harness is **Python standard library only**; pytest is the only
test dependency. CI (GitHub Actions) runs the test suite and a smoke run
of both baselines on every push.

## What the baselines teach

- **Patterns fail on flows, not on lines.** The heuristic baseline's three
  misses are a f-string with no `+` for its SQL rule to match, a redirect
  target hidden behind a genuine allowlist check, and an API variant
  (`Paths.resolve`) its path rule was never written for. None of these is
  a tuning problem; they are what "the flaw is a flow, not a string"
  means in practice.
- **Data flow has a scope price.** The AST baseline is flawless inside
  its scope and silent outside it: no Java front end, no rules for
  credential literals or weak primitives. An honest overall F1 (0.67)
  next to a perfect in-scope recall (7/7) is the correct way to report a
  scoped tool — and the disagreement table makes the scope visible
  instead of letting it hide in an average.
- **Patching is where templates run out.** The heuristic patcher only
  attempts mechanical fixes (coverage 0.45 of its true positives) and
  passes its proxy check on all of them. SQL injection, traversal, and
  SSRF fixes need semantic rewriting — the strongest concrete argument in
  this repo for evaluating LLM patching separately from LLM detection.

## Limitations — read this before quoting any number

- **Small synthetic dataset.** 28 hand-written samples cannot represent
  real-world code. These numbers demonstrate a methodology and pin down
  reproducible baselines; they are not a benchmark of any tool or model
  and would not survive contact with a production codebase unchanged.
- **The baselines are not LLMs.** Their scores say something about regex
  rules and a teaching-grade taint analyzer on this dataset — nothing
  about LLM capability. LLM numbers will exist only after a run with
  `--detector anthropic`, and will be labeled with the model that
  produced them.
- **FP burden of 0.00 is a property of this setup, not a promise.** Both
  baselines are conservative and the negative controls are the dataset's
  own reference fixes — cleaner than real "clean" code. On real
  codebases, expect false positives; measuring how many is the point of
  the harness.
- **The AST analyzer is teaching-grade.** Intra-procedural analysis with
  one level of function summaries; summaries track provenance only, so
  path sanitization is credited only in the function that performs it;
  no aliasing, no attribute-level tracking, no Java. Its design document
  is its module docstring.
- **The patch metric is a proxy.** Pattern-gone + marker-present does not
  prove a patch compiles, preserves behavior, or is complete. It is a
  cheap, deterministic screen — the honest next step is compiling and
  testing patched code.
- **Self-authored samples risk self-deception:** the same person wrote
  the flaws, the fixes, and both detectors. The test suite guards label
  integrity (counterparts exist, markers discriminate, lines point at
  the flaw) and pins the baselines' known blind spots as documented
  behavior — but an external dataset (e.g. a curated CVE corpus) is the
  obvious hardening step.

## Layout

```
data/            manifest.json (labels) + samples/ (vulnerable/fixed pairs)
vulneval/        dataset loading, patterns, detectors, metrics, report, CLI
  detectors/       heuristic (regex) · ast_taint (taint tracking) · anthropic (LLM)
tests/           dataset integrity, metric math, detector behavior (both baselines)
results/         generated reports (REPORT.md is the current two-baseline run)
WALKTHROUGH.md   author's notes: design decisions and how to explain them
```
