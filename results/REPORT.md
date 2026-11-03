# LLM Vulnerability-Detection Eval — Results

- **Detectors:** `heuristic-baseline`, `ast-taint-baseline`
- **Run date:** 2026-11-03
- **Dataset:** v1.1 — 28 samples (14 vulnerable / 14 fixed), 7 categories, Python + Java

## Detector: `heuristic-baseline`

### Headline

**False-positive burden: 0.00 false positives per true finding.**

That ratio is the reviewer-workload metric: every false positive is an alert a human has to open, read, and dismiss before reaching real work.

### Detection — overall

| TP | FP | FN | TN | Precision | Recall | F1 |
|----|----|----|----|-----------|--------|----|
| 11 | 0 | 3 | 14 | 1.00 | 0.79 | 0.88 |

### Detection — per category

| Category | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| hardcoded_credentials | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| insecure_deserialization | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| path_traversal | 1 | 0 | 1 | 2 | 1.00 | 0.50 | 0.67 |
| sql_injection | 2 | 0 | 1 | 3 | 1.00 | 0.67 | 0.80 |
| ssrf | 1 | 0 | 1 | 2 | 1.00 | 0.50 | 0.67 |
| weak_cryptography | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| xxe | 1 | 0 | 0 | 1 | 1.00 | 1.00 | 1.00 |

### Patch quality (proxy)

A patch counts as successful if (1) the harness's own pattern check no longer fires on the patched code, and (2) at least one marker of the reference fix (from the dataset labels) is present. This is a proxy, not a proof of correctness. A detector that does not propose patches reports 0 attempted — that is a scope statement, not a failure.

| Patches attempted | Succeeded | Success rate (of attempted) | Coverage (of true positives) |
|----|----|----|----|
| 5 | 5 | 1.00 | 0.45 |

| Sample | Attempted | Pattern removed | Fix marker present | Success |
|--------|-----------|-----------------|--------------------|---------|
| sqli_py:vuln | no | — | — | no |
| sqli_java:vuln | no | — | — | no |
| xxe_java:vuln | yes | yes | yes | yes |
| deser_py:vuln | yes | yes | yes | yes |
| deser_yaml_py:vuln | no | — | — | no |
| traversal_py:vuln | no | — | — | no |
| ssrf_py:vuln | no | — | — | no |
| creds_py:vuln | yes | yes | yes | yes |
| creds_java:vuln | yes | yes | yes | yes |
| weakcrypto_py:vuln | yes | yes | yes | yes |
| weakcrypto_java:vuln | no | — | — | no |

### Misses (false negatives)

- **sqli2_py:vuln** (sql_injection, python): Second-order SQL injection: the username is stored with a safe parameterized insert, then read back from the database and interpolated into a new query with an f-string. Storage did not sanitize it -- the value was attacker-controlled at write time and stays attacker-controlled when it comes back out.
- **traversal_java:vuln** (path_traversal, java): baseDir.resolve(fileName) trusts the caller-supplied name; a name containing '..' segments resolves outside baseDir.
- **ssrf_redirect_py:vuln** (ssrf, python): The allowlist check validates only the original URL. The redirect target from the Location header is fetched without re-validation, so an allowlisted host (or an attacker page on one) can bounce the server-side request to a link-local metadata endpoint or an intranet service.

### False positives

- None.

## Detector: `ast-taint-baseline`

### Headline

**False-positive burden: 0.00 false positives per true finding.**

That ratio is the reviewer-workload metric: every false positive is an alert a human has to open, read, and dismiss before reaching real work.

### Detection — overall

| TP | FP | FN | TN | Precision | Recall | F1 |
|----|----|----|----|-----------|--------|----|
| 7 | 0 | 7 | 14 | 1.00 | 0.50 | 0.67 |

### Detection — per category

| Category | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| hardcoded_credentials | 0 | 0 | 2 | 2 | 0.00 | 0.00 | 0.00 |
| insecure_deserialization | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| path_traversal | 1 | 0 | 1 | 2 | 1.00 | 0.50 | 0.67 |
| sql_injection | 2 | 0 | 1 | 3 | 1.00 | 0.67 | 0.80 |
| ssrf | 2 | 0 | 0 | 2 | 1.00 | 1.00 | 1.00 |
| weak_cryptography | 0 | 0 | 2 | 2 | 0.00 | 0.00 | 0.00 |
| xxe | 0 | 0 | 1 | 1 | 0.00 | 0.00 | 0.00 |

### Patch quality (proxy)

A patch counts as successful if (1) the harness's own pattern check no longer fires on the patched code, and (2) at least one marker of the reference fix (from the dataset labels) is present. This is a proxy, not a proof of correctness. A detector that does not propose patches reports 0 attempted — that is a scope statement, not a failure.

| Patches attempted | Succeeded | Success rate (of attempted) | Coverage (of true positives) |
|----|----|----|----|
| 0 | 0 | n/a | 0.00 |

| Sample | Attempted | Pattern removed | Fix marker present | Success |
|--------|-----------|-----------------|--------------------|---------|
| sqli_py:vuln | no | — | — | no |
| sqli2_py:vuln | no | — | — | no |
| deser_py:vuln | no | — | — | no |
| deser_yaml_py:vuln | no | — | — | no |
| traversal_py:vuln | no | — | — | no |
| ssrf_py:vuln | no | — | — | no |
| ssrf_redirect_py:vuln | no | — | — | no |

### Misses (false negatives)

- **sqli_java:vuln** (sql_injection, java): A Statement is executed with a query built by string concatenation, allowing injection through the username parameter.
- **xxe_java:vuln** (xxe, java): DocumentBuilderFactory is used with default settings, so a crafted XML document can define external entities and make the parser read local files or make network requests (XXE).
- **traversal_java:vuln** (path_traversal, java): baseDir.resolve(fileName) trusts the caller-supplied name; a name containing '..' segments resolves outside baseDir.
- **creds_py:vuln** (hardcoded_credentials, python): A live-looking API key is embedded in source code, where it leaks through repos, logs, and screenshots and cannot be rotated without a deploy.
- **creds_java:vuln** (hardcoded_credentials, java): The production database password is a string constant in the codebase; anyone with source access has the credential.
- **weakcrypto_py:vuln** (weak_cryptography, python): MD5 is a fast, unsalted hash, so stolen password hashes can be brute-forced or rainbow-tabled at billions of guesses per second.
- **weakcrypto_java:vuln** (weak_cryptography, java): DES has a 56-bit key that is brute-forceable, and ECB mode leaks plaintext patterns because identical blocks encrypt identically.

### False positives

- None.

## Where the detectors disagree

Samples where the two baselines reach different verdicts. Agreement is not shown — the disagreements are where the methods' actual difference lives.

| Sample | Category | `heuristic-baseline` | `ast-taint-baseline` |
|--------|----------|---|---|
| creds_java:vuln | hardcoded_credentials | caught | missed |
| creds_py:vuln | hardcoded_credentials | caught | missed |
| sqli2_py:vuln | sql_injection | missed | caught |
| sqli_java:vuln | sql_injection | caught | missed |
| ssrf_redirect_py:vuln | ssrf | missed | caught |
| weakcrypto_java:vuln | weak_cryptography | caught | missed |
| weakcrypto_py:vuln | weak_cryptography | caught | missed |
| xxe_java:vuln | xxe | caught | missed |

Reading the disagreements: a sample *missed by the AST baseline and caught by the heuristic* is almost always outside the AST detector's declared scope (Java, or an API-misuse category). A sample *caught by the AST baseline and missed by the heuristic* is a data-flow variant — the flaw only exists as a flow from source to sink, not as a suspicious line of text. The second kind is the one an LLM detector is expected to win on too; the first kind is a reminder that 'use an LLM' does not retire the linter.

## How to read these numbers

- The dataset is small and synthetic by design (self-authored teaching samples, not real CVE code), so treat the metrics as a methodology demonstration and baseline reference points — not as a benchmark of any production tool or model.
- Neither baseline is an LLM. Both exist to define the floor an LLM detector must beat, and to show *where* non-LLM methods fail — the failure location is the argument for what the LLM has to add (data-flow and semantic reasoning).
- The AST baseline's scope is deliberately narrower: Python only, and only dataflow categories (SQL injection, SSRF, path traversal, insecure deserialization). Its misses on Java samples and on API-misuse categories (hardcoded credentials, weak cryptography, XXE) are scope statements, not signal — compare it per-category and within Python, not just on the overall row.
- Detection credit requires the *correct category*: flagging a sample with the wrong label counts as a miss, because a mislabeled alert sends the reviewer to the wrong fix.
