# Walkthrough — how to explain this project

*Private prep notes. The goal: be able to defend every design decision and
every number, out loud, without bluffing.*

## The 2-minute explanation

> "This is an evaluation harness for automated vulnerability detection —
> the kind of tooling people point at code and ask, 'is this vulnerable,
> and can you fix it?'
>
> I built a labeled dataset: fourteen vulnerable/fixed pairs across seven
> categories — SQL injection, XXE, deserialization, path traversal, SSRF,
> hardcoded credentials, weak crypto — in Python and Java. Each sample is
> labeled with the exact vulnerable lines, an explanation, and markers a
> correct fix should contain.
>
> Then I built **two** baselines against the same detector interface,
> because one baseline only tells you its own failure mode. The first is
> mitigation-aware regex rules — the linter floor. The second is a real
> taint-tracking analyzer I wrote on Python's AST: it tracks where data
> came from — parameters, database reads, HTTP responses — through
> assignments, f-strings, and helper functions, and asks whether tainted
> data can reach a sink without the sanitization that category needs.
>
> The results are the interesting part. The regex gets F1 0.88 overall.
> The AST detector's overall F1 is lower, 0.67 — and I report it that
> way — but every one of its misses is outside its declared scope: it's
> Python-only and it doesn't do API-misuse categories. Inside its scope
> it catches seven of seven, including two samples I built specifically
> to beat pattern matching: a second-order SQL injection whose payload
> round-trips through the database, and an SSRF where the allowlist
> check is real but the redirect target is never re-validated. The
> harness prints a disagreement table — the eight samples where the two
> detectors differ — because the disagreements are where the methods'
> actual difference lives.
>
> The harness also scores proposed patches with a proxy check, and
> reports one headline metric I care about most: **false positives per
> true finding**, because in real triage the scarce resource isn't model
> calls, it's reviewer attention. An LLM detector plugs into the same
> interface; I report baseline numbers as baseline numbers, never as
> model results."

## Where it comes from (the honest motivation)

On Citizens Bank's fraud-risk engineering team, my day job involved Java
services: I found and patched vulnerabilities in production code, built an
organization-wide Maven dependency-automation tool, and worked on
GenAI-powered anomaly detection in fraud-risk workflows. In that world,
every automated finding lands on a human's desk — so "how good is the
detector?" is really two questions: what does it miss, and how much noise
does it make a reviewer wade through? This project is that production
question, turned into a small reproducible experiment I can run and show.

## Design decisions — and why

- **Vulnerable/fixed pairs.** The fixed twin of each sample is a built-in
  negative control: a detector that flags the fix is crying wolf in a way
  I can measure exactly, on code whose ground truth I know.
- **Two baselines, deliberately different in kind.** A regex baseline and
  a data-flow baseline fail in *different places*. Running both turns
  "the tool got 0.88" into an analysis: which failures are scope, which
  are method limits, and which are shared blind spots. One number can't
  tell you that; a disagreement table can.
- **Mitigation-aware rules.** The regex baseline doesn't just grep for
  scary strings; a rule stays silent when a mitigation is present (e.g.
  XXE hardening). Otherwise it would flag every fixed sample and the eval
  would measure nothing.
- **Provenance, not booleans, in the AST detector.** Each value carries
  the set of sources it came from. That one choice buys three things:
  second-order flows (data out of a database is a source, not a
  sanitizer), inter-procedural summaries (the set of parameters that
  reach a return value), and category-specific sanitization —
  `basename()` marks a value safe *for path sinks* while it stays
  tainted for SQL, because that's what basename actually does.
- **Allowlist checks cover provenance, not variables.** For SSRF, a URL
  is validated only if every provenance label in it was inspected by a
  hostname check. The initial URL passes; a redirect `Location` header
  doesn't, because its provenance includes response data nobody checked.
  That's the redirect sample, and it's a modeling decision I can defend
  line by line.
- **Credit requires the correct category.** Flagging SQL injection as
  "weak crypto" is a miss in my scoring, because a mislabeled alert sends
  the reviewer to the wrong remediation.
- **FP burden as the headline.** Accuracy metrics are abstract; "false
  alarms per true finding" is a staffing number. It reframes eval results
  in the unit a security team actually budgets: reviewer hours.
- **Template patcher refuses hard categories.** It only attempts fixes
  that are mechanical (env vars for credentials, `json` for `pickle`,
  PBKDF2 for MD5, XXE factory hardening) and returns "no attempt" for
  SQL injection/traversal/SSRF. Reporting coverage (5 of 11) next to the
  success rate (5 of 5) keeps me honest about the difference between
  "everything I tried worked" and "I can fix everything." The AST
  detector doesn't patch at all — detection only, stated up front.
- **The LLM detector degrades loudly.** No API key → it stops and prints
  setup instructions. An eval that silently swaps detectors produces
  numbers nobody can trust, including me.
- **Tests guard the labels and the story.** Dataset-integrity tests are
  the strictest in the repo (counterparts exist, markers discriminate,
  vulnerable lines point at the flaw). And the baselines' known blind
  spots are pinned as tests: if a future rule change starts catching the
  second-order sample, the test forces a deliberate edit, not a silent
  drift in what the numbers mean.

## Stories worth telling

1. **The eval caught a bug in my own rule.** The first run (dataset v1.0)
   missed the Java hardcoded-password sample: my regex used a
   word-boundary anchor, and `DB_PASSWORD` has an underscore prefix, so
   the boundary never matched. That's the evaluation working as intended
   — it falsified my assumption with a concrete counterexample. I fixed
   the rule (identifiers *containing* the keyword).
2. **The miss both baselines share.** A Java path traversal built with
   `baseDir.resolve(fileName)` contains no `open(` or `new File(` for the
   regex to match, and Java is outside the AST detector's front end. Two
   different methods, same blind spot, different reasons: pattern
   coverage on one side, language scope on the other. Knowing *which*
   failures are typos, which are scope, and which are structural is most
   of what evaluation is for.
3. **The redirect sample is the thesis in one file.** The check is real
   code — parse the URL, compare the hostname to an allowlist, raise if
   it fails. A line-pattern tool sees the mitigations and stays silent; a
   human skimming sees a validated fetch. The flaw only exists as a
   *flow*: response data reaching a sink unchecked. If your eval can't
   represent that, it will certify this code as safe.
4. **Second-order injection is the same lesson for storage.** The write
   path is textbook-safe — parameterized insert. The bug is the
   assumption that what comes back out of your own database is clean.
   Modeling DB reads as a taint source is one line in the analyzer and
   the entire difference in outcome.

## Likely questions — honest answers

- **"Are either of the baselines an LLM?"** No. One is regex rules, one
  is a taint analyzer I wrote. The LLM path is implemented behind the
  same interface and runs with an API key; I have not published LLM
  numbers because I haven't run that evaluation yet, and I won't quote
  numbers I didn't measure.
- **"Your regex beats your AST detector on F1. Why build the AST one?"**
  Because the aggregate hides the structure. The AST detector's misses
  are 100% declared scope — five Java samples and two API-misuse
  categories it never claimed to cover. Inside its scope it's 7-for-7,
  including the two flow variants the regex structurally cannot see.
  The right question about a scoped tool is per-category, in-scope
  performance — and the disagreement table exists so a reviewer doesn't
  have to take my word for any of this.
- **"Why synthetic data instead of real CVEs?"** Safety and label
  quality: I wrote every flaw and fix, so ground truth is certain and
  nothing is copied from real vulnerability code or a production system.
  The trade-off is realism, and I say so in the README. Pointing the
  same harness at a curated CVE corpus is the obvious next step.
- **"Zero false positives — really?"** On *this* dataset, from both
  baselines, yes: both are conservative and the negatives are my own
  reference fixes, which are cleaner than real-world clean code. I
  present 0.00 as a property of the setup, not a capability claim — the
  harness exists to measure the FP burden where it isn't zero.
- **"Does a passing patch actually work?"** The check is a proxy:
  pattern removed + fix marker present. It doesn't compile or run the
  patched code. I'd rather name that limitation than dress the metric up.
- **"How good is the taint analyzer, really?"** Teaching-grade, and the
  docstring says so: intra-procedural with one level of summaries, no
  aliasing or attribute tracking, sanitization credited only in the
  function that performs it, Python only. It's real static analysis —
  provenance genuinely flows through the AST — but it is not a
  production SAST tool and I don't present it as one.
- **"What would you do next?"** Three things: run the LLM detector on
  the same dataset and put it in the disagreement table (the prediction
  to test: it should catch the flow variants *and* the Java `Paths`
  sample, and the interesting question becomes its FP burden); add
  compile/test verification for patches; grow the dataset with an
  external corpus and with cross-function flows, where one-level
  summaries start to fail by construction.
- **"How does this relate to AI safety work?"** Vulnerability detection
  is a dual-use capability evaluation: the same measurement discipline —
  labeled tasks, per-category error analysis, cost-of-error in human
  review time, and honest scoping of what a number covers — is what
  safeguards and frontier red-teaming evaluations need. The FP-burden
  framing is my attempt to price errors in the unit that matters
  operationally, and the two-baseline disagreement analysis is how you
  keep an eval from certifying a blind spot as a capability.

## GUARDRAIL — keep the two stories separate

- **Citizens Bank work** = Java backend services and internal tooling on
  the fraud-risk team (dependency automation, vulnerability remediation,
  GenAI anomaly detection). That is employment experience.
- **This harness** = a personal project, built on my own time, with
  self-authored synthetic samples. It never ran at the bank, never touched
  bank code or data, and its dataset contains nothing from any employer.

Never merge them: don't say or imply the harness was used at Citizens,
that its samples come from production, or that its results reflect any
employer's systems. The honest sentence is: *"My production work is why I
care about the question; this project is how I explored it rigorously on
my own."*
