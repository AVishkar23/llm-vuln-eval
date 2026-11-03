"""vulneval: an evaluation harness for LLM vulnerability detection and patching.

Measures how well a detector (a static heuristic baseline, or an LLM via the
Anthropic API) finds vulnerabilities in small labeled code samples, how good
its proposed patches are, and — the headline metric — how many false alarms a
human reviewer has to wade through per true finding.
"""

__version__ = "1.0.0"
