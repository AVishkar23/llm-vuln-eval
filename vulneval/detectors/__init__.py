"""Detector registry."""

from .anthropic import AnthropicDetector
from .base import Detector, Finding
from .heuristic import HeuristicDetector

DETECTORS = {
    "heuristic": HeuristicDetector,
    "anthropic": AnthropicDetector,
}

__all__ = ["DETECTORS", "Detector", "Finding", "HeuristicDetector", "AnthropicDetector"]
