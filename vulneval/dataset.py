"""Loading and representing the labeled sample dataset.

The dataset is a set of vulnerable/fixed pairs described by
``data/manifest.json``. Every sample is a small, self-authored teaching
example (not copied from real CVE code), stored as a real source file under
``data/samples/`` so detectors read exactly what a reviewer would read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Sample:
    pair_id: str
    category: str
    language: str
    severity: str
    is_vulnerable: bool
    code: str
    source_name: str
    vulnerable_lines: tuple[int, ...]
    explanation: str
    fix_summary: str
    fix_markers: tuple[str, ...]

    @property
    def sample_id(self) -> str:
        kind = "vuln" if self.is_vulnerable else "fixed"
        return f"{self.pair_id}:{kind}"


def load_manifest(data_dir: Path) -> dict:
    return json.loads((data_dir / "manifest.json").read_text())


def load_dataset(data_dir: Path) -> list[Sample]:
    """Load every sample (vulnerable and fixed) described by the manifest."""
    manifest = load_manifest(data_dir)
    samples: list[Sample] = []
    for pair in manifest["pairs"]:
        for is_vulnerable, key in ((True, "vulnerable_file"), (False, "fixed_file")):
            source_name = pair[key]
            code = (data_dir / "samples" / source_name).read_text()
            samples.append(
                Sample(
                    pair_id=pair["pair_id"],
                    category=pair["category"],
                    language=pair["language"],
                    severity=pair["severity"],
                    is_vulnerable=is_vulnerable,
                    code=code,
                    source_name=source_name,
                    vulnerable_lines=tuple(pair["vulnerable_lines"]),
                    explanation=pair["explanation"],
                    fix_summary=pair["fix_summary"],
                    fix_markers=tuple(pair["fix_markers"]),
                )
            )
    return samples
