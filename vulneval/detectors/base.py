"""The detector interface.

A detector reads one sample and returns a list of findings. It may also
propose a patch for a vulnerable sample; patches are scored separately by
the harness (pattern removed? correct-fix markers present?).

To evaluate a different model or tool, implement this interface — the
runner, metrics, and report generator work unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..dataset import Sample


@dataclass(frozen=True)
class Finding:
    category: str
    line: int | None
    rationale: str


class Detector(ABC):
    name: str = "abstract-detector"

    @abstractmethod
    def detect(self, sample: Sample) -> list[Finding]:
        """Return all findings for one sample (empty list = looks clean)."""

    def propose_patch(self, sample: Sample) -> str | None:
        """Return a patched version of the sample's code, or None if this
        detector does not attempt a patch for it."""
        return None
