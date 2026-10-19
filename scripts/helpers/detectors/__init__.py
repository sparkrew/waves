"""detectors package — decision-tree weakness detectors for GitHub Actions workflows."""

from detectors.registry import ALL_DETECTORS, detect_all

__all__ = ["ALL_DETECTORS", "detect_all"]
