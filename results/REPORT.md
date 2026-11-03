# LLM Vulnerability-Detection Eval — Results

- **Detector:** `heuristic-baseline`
- **Run date:** 2026-11-03
- **Dataset:** v1.0 — 22 samples (11 vulnerable / 11 fixed), 7 categories, Python + Java

## Headline

**False-positive burden: 0.00 false positives per true finding.**

That ratio is the reviewer-workload metric: every false positive is an alert a human has to open, read, and dismiss before reaching real work.

## Detection — overall

| TP | FP | FN | TN | Precision | Recall | F1 |
|----|----|----|----|-----------|--------|----|
| 10 | 0 | 1 | 11 | 1.00 | 0.91 | 0.95 |

## Detection — per category

| Category | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| hardcoded_credentials | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| insecure_deserialization | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| path_traversal | 1 | 0 | 1 | 2 | 1.00 | 0.50 | 0.67 |
| sql_injection | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| ssrf | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |
| weak_cryptography | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| xxe | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |

## Patch quality (proxy)

A patch counts as successful if (1) the harness's own pattern check no longer fires on the patched code, and (2) at least one marker of the reference fix (from the dataset labels) is present. This is a proxy, not a proof of correctness.

| Patches attempted | Succeeded | Success rate (of attempted) | Coverage (of true positives) |
|----|----|----|----|
| 5 | 5 | 1.00 | 0.50 |

| Sample | Attempted | Pattern removed | Fix marker present | Success |
|--------|-----------|-----------------|--------------------|---------|
| sqli_py:vuln | no | — | — | no |
| sqli_java:vuln | no | — | — | no |
| xxe_java:vuln | yes | yes | yes | yes |
| deser_py:vuln | yes | yes | yes | yes |
| traversal_py:vuln | no | — | — | no |
| ssrf_py:vuln | no | — | — | no |
| creds_py:vuln | yes | yes | yes | yes |
| creds_java:vuln | yes | yes | yes | yes |
| weakcrypto_py:vuln | yes | yes | yes | yes |
| weakcrypto_java:vuln | no | — | — | no |

## Misses (false negatives)

- **traversal_java:vuln** (path_traversal, java): baseDir.resolve(fileName) trusts the caller-supplied name; a name containing '..' segments resolves outside baseDir.

## False positives

- None.

## How to read these numbers

- The dataset is small and synthetic by design (self-authored teaching samples, not real CVE code), so treat the metrics as a methodology demonstration and a baseline reference point — not as a benchmark of any production tool or model.
- The heuristic baseline is *not* an LLM. Its blind spots are the interesting part: they show the classes of vulnerability that pure pattern matching structurally cannot catch, which is the gap an LLM detector is evaluated against.
- Detection credit requires the *correct category*: flagging a sample with the wrong label counts as a miss, because a mislabeled alert sends the reviewer to the wrong fix.
