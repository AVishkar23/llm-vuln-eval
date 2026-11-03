"""Detector behavior: baseline smoke tests and the LLM stub's safety rails."""

from pathlib import Path

from vulneval.dataset import load_dataset
from vulneval.detectors.anthropic import AnthropicDetector
from vulneval.detectors.heuristic import HeuristicDetector

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _sample(samples, pair_id, vulnerable):
    return next(
        s for s in samples if s.pair_id == pair_id and s.is_vulnerable == vulnerable
    )


def test_heuristic_detects_python_sqli_and_not_its_fix():
    samples = load_dataset(DATA_DIR)
    detector = HeuristicDetector()
    vuln = _sample(samples, "sqli_py", True)
    fixed = _sample(samples, "sqli_py", False)
    assert any(f.category == "sql_injection" for f in detector.detect(vuln))
    assert detector.detect(fixed) == []


def test_heuristic_flags_no_fixed_sample_in_dataset():
    """The baseline must be FP-clean on the reference fixes; if a rule starts
    firing on fixed code, either the rule or the fix regressed."""
    samples = load_dataset(DATA_DIR)
    detector = HeuristicDetector()
    for sample in samples:
        if not sample.is_vulnerable:
            assert detector.detect(sample) == [], sample.sample_id


def test_anthropic_detector_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert AnthropicDetector.available() is False
    assert "ANTHROPIC_API_KEY" in AnthropicDetector.unavailable_reason()
