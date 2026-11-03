"""LLM detector backed by the Anthropic API.

This detector is *wired but optional*: it activates only when the
``ANTHROPIC_API_KEY`` environment variable is set. Without a key it refuses
to run and explains how to enable it — the harness never silently falls
back to something else, because an eval that quietly swaps detectors
produces numbers nobody can trust.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python -m vulneval run --detector anthropic

Optionally set ANTHROPIC_MODEL to override the default model.
Only the Python standard library is used (urllib), like the rest of the
harness.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

from ..dataset import Sample
from ..patterns import RULES
from .base import Detector, Finding

_API_URL = "https://api.anthropic.com/v1/messages"
_DEFAULT_MODEL = "claude-sonnet-4-5"

_PROMPT = """You are a security code reviewer. Analyze the {language} code below.

Decide whether it contains any of these vulnerability categories:
{categories}

Respond with ONLY a JSON object (no prose, no markdown fences):
{{"findings": [{{"category": "<one of the categories>", "line": <1-based line number or null>, "rationale": "<one sentence>"}}], "patch": "<the full corrected code, or null if the code is clean or you cannot fix it>"}}

If the code is clean, return {{"findings": [], "patch": null}}.

Code:
```
{code}
```"""


class AnthropicDetector(Detector):
    name = "anthropic-llm"

    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("ANTHROPIC_MODEL", _DEFAULT_MODEL)
        self._cache: dict[str, dict] = {}

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    @staticmethod
    def unavailable_reason() -> str:
        return (
            "ANTHROPIC_API_KEY is not set, so the LLM detector cannot run.\n"
            "To evaluate a real LLM:  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "Then re-run:  python -m vulneval run --detector anthropic\n"
            "(Or run the offline baseline instead: --detector heuristic)"
        )

    def _ask(self, sample: Sample) -> dict:
        if sample.sample_id in self._cache:
            return self._cache[sample.sample_id]
        if not self.available():
            raise RuntimeError(self.unavailable_reason())
        prompt = _PROMPT.format(
            language=sample.language,
            categories=", ".join(sorted(RULES)),
            code=sample.code,
        )
        body = {
            "model": self.model,
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }
        request = urllib.request.Request(
            _API_URL,
            data=json.dumps(body).encode(),
            headers={
                "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(response.read())
        text = payload["content"][0]["text"]
        parsed = _parse_json(text)
        self._cache[sample.sample_id] = parsed
        return parsed

    def detect(self, sample: Sample) -> list[Finding]:
        result = self._ask(sample)
        return [
            Finding(
                category=item["category"],
                line=item.get("line"),
                rationale=item.get("rationale", ""),
            )
            for item in result.get("findings", [])
            if item.get("category") in RULES
        ]

    def propose_patch(self, sample: Sample) -> str | None:
        patch = self._ask(sample).get("patch")
        return patch if isinstance(patch, str) and patch.strip() else None


def _parse_json(text: str) -> dict:
    """Best-effort extraction of the JSON object from a model response."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return {"findings": [], "patch": None}
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {"findings": [], "patch": None}
