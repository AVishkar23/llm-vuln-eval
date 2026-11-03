"""Dataset integrity: if the labels are wrong, every metric is meaningless,
so the dataset gets the strictest tests in the project."""

from pathlib import Path

import pytest

from vulneval.dataset import load_dataset, load_manifest

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(DATA_DIR)


@pytest.fixture(scope="module")
def samples():
    return load_dataset(DATA_DIR)


def test_manifest_parses_and_has_required_fields(manifest):
    assert manifest["dataset_version"]
    for pair in manifest["pairs"]:
        for field in (
            "pair_id", "category", "language", "severity",
            "vulnerable_file", "fixed_file", "vulnerable_lines",
            "explanation", "fix_summary", "fix_markers",
        ):
            assert pair[field], f"{pair.get('pair_id')}: missing {field}"


def test_at_least_six_categories(manifest):
    categories = {pair["category"] for pair in manifest["pairs"]}
    assert len(categories) >= 6, categories


def test_both_languages_present(manifest):
    languages = {pair["language"] for pair in manifest["pairs"]}
    assert {"python", "java"} <= languages


def test_every_vulnerable_sample_has_a_fixed_counterpart(samples):
    vuln_pairs = {s.pair_id for s in samples if s.is_vulnerable}
    fixed_pairs = {s.pair_id for s in samples if not s.is_vulnerable}
    assert vuln_pairs == fixed_pairs
    assert len(samples) == 2 * len(vuln_pairs)


def test_vulnerable_lines_point_inside_the_file(samples):
    for sample in samples:
        if not sample.is_vulnerable:
            continue
        lines = sample.code.splitlines()
        assert sample.vulnerable_lines, sample.sample_id
        for lineno in sample.vulnerable_lines:
            assert 1 <= lineno <= len(lines), sample.sample_id
            assert lines[lineno - 1].strip(), f"{sample.sample_id}:{lineno} is blank"


def test_fix_markers_appear_in_fixed_samples(samples):
    """The reference fix must actually contain the markers the patch scorer
    will look for — otherwise no patch could ever pass."""
    for sample in samples:
        if sample.is_vulnerable:
            continue
        for marker in sample.fix_markers:
            assert marker in sample.code, f"{sample.sample_id} lacks fix marker {marker!r}"


def test_fix_markers_discriminate(samples):
    """Markers must be absent from the vulnerable version — otherwise the
    patch scorer cannot tell a real fix from the original flaw."""
    fixed_markers = {
        s.pair_id: s.fix_markers for s in samples if not s.is_vulnerable
    }
    for sample in samples:
        if not sample.is_vulnerable:
            continue
        for marker in fixed_markers[sample.pair_id]:
            assert marker not in sample.code, (
                f"{sample.sample_id} already contains fix marker {marker!r}"
            )
