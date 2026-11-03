"""Static vulnerability patterns, shared by the heuristic baseline detector
and by the patch-quality check.

A rule *fires* on a piece of code when its regex matches AND none of its
mitigation tokens are present. The mitigation tokens are what keep the fixed
samples clean: e.g. the XXE rule matches any ``DocumentBuilderFactory`` use,
but stays silent when the code disables DOCTYPE declarations.

These rules are deliberately simple line-oriented patterns. They are the
baseline an LLM has to beat, and their blind spots (see the path-traversal
miss on the Java ``Paths`` API in the results report) are part of what the
evaluation is designed to surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    regex: re.Pattern
    mitigations: tuple[str, ...] = ()

    def fires(self, code: str) -> bool:
        if not self.regex.search(code):
            return False
        return not any(token in code for token in self.mitigations)

    def first_match_line(self, code: str) -> int | None:
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self.regex.search(line):
                return lineno
        return None


RULES: dict[str, Rule] = {
    "sql_injection": Rule(
        regex=re.compile(r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]*\+"),
    ),
    "xxe": Rule(
        regex=re.compile(r"DocumentBuilderFactory\.newInstance"),
        mitigations=("disallow-doctype-decl",),
    ),
    "insecure_deserialization": Rule(
        regex=re.compile(r"pickle\.loads?\b|yaml\.load\s*\(|ObjectInputStream|readObject\s*\("),
        mitigations=("SafeLoader",),
    ),
    "path_traversal": Rule(
        regex=re.compile(r"(?<![\w.])open\s*\(|new File\s*\("),
        mitigations=("basename", "realpath", "commonpath", "normalize(", "startsWith"),
    ),
    "ssrf": Rule(
        regex=re.compile(r"requests\.get\s*\(|urlopen\s*\("),
        mitigations=("urlparse", "ALLOWED_HOSTS", "allowlist"),
    ),
    "hardcoded_credentials": Rule(
        # Identifier must *contain* the keyword (DB_PASSWORD, SERVICE_API_KEY),
        # not start with it — a \b anchor here silently misses prefixed names.
        regex=re.compile(r'(?i)\w*(password|passwd|api_key|apikey|secret|access_token)\w*\s*=\s*"[^"\n]{4,}"'),
    ),
    "weak_cryptography": Rule(
        regex=re.compile(r'hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|Cipher\.getInstance\(\s*"DES|\bECB\b'),
    ),
}


def pattern_fires(category: str, code: str) -> bool:
    """True if the (mitigation-aware) vulnerable pattern for a category is present."""
    return RULES[category].fires(code)
