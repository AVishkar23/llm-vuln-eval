"""Offline heuristic baseline detector.

Detection is purely pattern-based (see ``vulneval.patterns``): fast, free,
deterministic, and completely offline — and limited in exactly the ways
pattern matching is always limited. It cannot reason about data flow, and it
misses API variants its regexes were not written for. Treat its scores as
the floor an LLM detector must beat, not as a target.

Patching is template-based and deliberately conservative: it only attempts
categories with a known mechanical fix (hardcoded credentials, pickle
deserialization, MD5 password hashing, XXE factory hardening). For
everything else it returns None — those fixes need semantic rewriting,
which is precisely the case for using an LLM.
"""

from __future__ import annotations

import re

from ..dataset import Sample
from ..patterns import RULES
from .base import Detector, Finding

_RATIONALES = {
    "sql_injection": "SQL statement built with string concatenation from caller input.",
    "xxe": "XML parser factory used without disabling DOCTYPE / external entities.",
    "insecure_deserialization": "Deserialization of untrusted data with an unsafe loader.",
    "path_traversal": "File path built from caller input without confinement to a base directory.",
    "ssrf": "Server fetches a caller-supplied URL without an allowlist check.",
    "hardcoded_credentials": "Credential assigned as a string literal in source code.",
    "weak_cryptography": "Broken or fast/obsolete cryptographic primitive (MD5/SHA1/DES/ECB).",
}


class HeuristicDetector(Detector):
    name = "heuristic-baseline"

    def detect(self, sample: Sample) -> list[Finding]:
        findings = []
        for category, rule in RULES.items():
            if rule.fires(sample.code):
                findings.append(
                    Finding(
                        category=category,
                        line=rule.first_match_line(sample.code),
                        rationale=_RATIONALES[category],
                    )
                )
        return findings

    def propose_patch(self, sample: Sample) -> str | None:
        patcher = _PATCHERS.get(sample.category)
        if patcher is None:
            return None
        return patcher(sample)


# --- template patchers -------------------------------------------------------
# Each returns the full patched source, or None if its rewrite does not apply.


def _patch_hardcoded_credentials(sample: Sample) -> str | None:
    code = sample.code
    if sample.language == "python":
        new = re.sub(
            r'^(\s*)([A-Za-z_]*?(?:KEY|PASSWORD|SECRET|TOKEN)[A-Za-z_]*)\s*=\s*"[^"]*"',
            r'\1\2 = os.environ["\2"]',
            code,
            flags=re.M,
        )
        if new != code and "import os" not in new:
            new = "import os\n\n" + new
    else:  # java
        new = re.sub(
            r'(\b\w*(?:PASSWORD|KEY|SECRET|TOKEN)\w*)\s*=\s*"[^"]*"',
            r'\1 = System.getenv("\1")',
            code,
        )
    return new if new != code else None


def _patch_insecure_deserialization(sample: Sample) -> str | None:
    if sample.language != "python":
        return None
    new = sample.code.replace("import pickle", "import json")
    new = re.sub(r'pickle\.loads\((\w+)\)', r'json.loads(\1.decode("utf-8"))', new)
    return new if new != sample.code else None


def _patch_weak_cryptography(sample: Sample) -> str | None:
    if sample.language != "python":
        return None
    new = re.sub(
        r"hashlib\.md5\((\w+)\.encode\(\)\)\.hexdigest\(\)",
        r'hashlib.pbkdf2_hmac("sha256", \1.encode(), os.urandom(16), 200_000).hex()',
        sample.code,
    )
    if new != sample.code and "import os" not in new:
        new = new.replace("import hashlib", "import hashlib\nimport os")
    return new if new != sample.code else None


def _patch_xxe(sample: Sample) -> str | None:
    match = re.search(r"(\w+)\s*=\s*DocumentBuilderFactory\.newInstance\(\)", sample.code)
    if not match:
        return None
    var = match.group(1)
    out_lines = []
    for line in sample.code.splitlines():
        out_lines.append(line)
        if "DocumentBuilderFactory.newInstance()" in line:
            indent = line[: len(line) - len(line.lstrip())]
            out_lines.append(
                f'{indent}{var}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
            )
            out_lines.append(f"{indent}{var}.setXIncludeAware(false);")
            out_lines.append(f"{indent}{var}.setExpandEntityReferences(false);")
    return "\n".join(out_lines) + "\n"


_PATCHERS = {
    "hardcoded_credentials": _patch_hardcoded_credentials,
    "insecure_deserialization": _patch_insecure_deserialization,
    "weak_cryptography": _patch_weak_cryptography,
    "xxe": _patch_xxe,
}
