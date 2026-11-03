"""Detector registry."""

from .anthropic import AnthropicDetector
from .ast_taint import AstTaintDetector
from .base import Detector, Finding
from .heuristic import HeuristicDetector

DETECTORS = {
    "heuristic": HeuristicDetector,
    "ast": AstTaintDetector,
    "anthropic": AnthropicDetector,
}

# Detectors that run fully offline (used by `run --detector all`).
OFFLINE_DETECTORS = ["heuristic", "ast"]

__all__ = [
    "DETECTORS",
    "OFFLINE_DETECTORS",
    "Detector",
    "Finding",
    "HeuristicDetector",
    "AstTaintDetector",
    "AnthropicDetector",
]
