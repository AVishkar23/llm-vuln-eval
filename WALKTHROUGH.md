# Walkthrough — how to explain this project

*Private prep notes. The goal: be able to defend every design decision and
every number, out loud, without bluffing.*

## The 2-minute explanation

> "This is an evaluation harness for automated vulnerability detection —
> the kind of tooling people point at code and ask, 'is this vulnerable,
> and can you fix it?'
>
> I built a small labeled dataset: eleven vulnerable/fixed pairs across
> seven categories — SQL injection, XXE, deserialization, path traversal,
> SSRF, hardcoded credentials, weak crypto — in Python and Java. Each
> sample is labeled with the exact vulnerable lines, an explanation, and
> markers a correct fix should contain.
>
> Then I defined a detector interface with two implementations: a static
> heuristic baseline that runs completely offline, and an LLM detector
> wired to the Anthropic API that only activates when a key is present.
> The harness scores detection with precision/recall/F1 per category,
> scores patches with a proxy check — is the vulnerable pattern gone, and
> is the real fix present — and it reports one headline metric I care
> about most: **false positives per true finding**, because in real triage
> the scarce resource isn't model calls, it's reviewer attention.
>
> The baseline gets F1 of 0.95 on this dataset, and its one miss is the
> interesting part — a Java path traversal written with the `Paths` API
> that regex rules structurally can't see. That blind spot is the whole
> argument for evaluating LLMs on this task instead of just trusting
> pattern matching."

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
- **Mitigation-aware rules.** The baseline doesn't just grep for scary
  strings; a rule stays silent when a mitigation is present (e.g. XXE
  hardening). Otherwise the baseline would flag every fixed sample and the
  eval would measure nothing.
- **Credit requires the correct category.** Flagging SQL injection as
  "weak crypto" is a miss in my scoring, because a mislabeled alert sends
  the reviewer to the wrong remediation.
- **FP burden as the headline.** Accuracy metrics are abstract; "false
  alarms per true finding" is a staffing number. It reframes eval results
  in the unit a security team actually budgets: reviewer hours.
- **Template patcher refuses hard categories.** It only attempts fixes
  that are mechanical (env vars for credentials, `json` for `pickle`,
  PBKDF2 for MD5, XXE factory hardening) and returns "no attempt" for
  SQL injection/traversal/SSRF. Reporting coverage (5 of 10) next to the
  success rate (5 of 5) keeps me honest about the difference between
  "everything I tried worked" and "I can fix everything."
- **The LLM detector degrades loudly.** No API key → it stops and prints
  setup instructions. An eval that silently swaps detectors produces
  numbers nobody can trust, including me.
- **Tests guard the labels, not just the code.** If a fixed sample lost
  its fix markers, or a vulnerable line number drifted, every metric
  downstream would be garbage — so dataset integrity has the strictest
  tests in the repo.

## Two stories worth telling

1. **The eval caught a bug in my own rule.** The first run missed the
   Java hardcoded-password sample: my regex used a word-boundary anchor,
   and `DB_PASSWORD` has an underscore prefix, so the boundary never
   matched. That's the evaluation working as intended — it falsified my
   assumption with a concrete counterexample. I fixed the rule (identifiers
   *containing* the keyword) and the miss became the Java `Paths`
   traversal, which is a genuine capability limit rather than a typo.
2. **The remaining miss is principled.** `baseDir.resolve(fileName)`
   doesn't contain the string `open(` or `new File(` — no regex edit
   fixes that class of problem; you need data-flow reasoning. Knowing
   *which* of your failures are typos and which are structural is most of
   what evaluation is for.

## Likely questions — honest answers

- **"Is the baseline an LLM?"** No — it's a static heuristic, the floor.
  The LLM path is implemented and runs with an API key; I report baseline
  numbers as baseline numbers, never as model results.
- **"Why synthetic data instead of real CVEs?"** Safety and label
  quality: I wrote every flaw and fix, so ground truth is certain and
  nothing is copied from real vulnerability code or a production system.
  The trade-off is realism, and I say so in the README. Pointing the same
  harness at a curated CVE corpus is the obvious next step.
- **"Zero false positives — really?"** On *this* dataset, yes: the rules
  are conservative and the negatives are my own reference fixes, which are
  cleaner than real-world clean code. I present 0.00 as a property of the
  setup, not a capability claim — the harness exists to measure the FP
  burden where it isn't zero.
- **"Does a passing patch actually work?"** The check is a proxy:
  pattern removed + fix marker present. It doesn't compile or run the
  patched code. I'd rather name that limitation than dress the metric up.
- **"What would you do next?"** Three things: run the LLM detector and
  compare per-category (especially whether it catches the `Paths`
  traversal); add compile/test verification for patches; grow the dataset
  with adversarial samples — vulnerabilities spread across functions,
  where line-based patterns fail by construction.
- **"How does this relate to AI safety work?"** Vulnerability detection
  is a dual-use capability evaluation: the same measurement discipline —
  labeled tasks, per-category error analysis, cost-of-error in human
  review time — is what safeguards and frontier red-teaming evaluations
  need. The FP-burden framing is my attempt to price errors in the unit
  that matters operationally.

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
