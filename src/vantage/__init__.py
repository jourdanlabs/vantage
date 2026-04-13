"""VANTAGE X — Static code analysis pipeline."""

from .analyzer import VantageAnalyzer, analyze
from .models import VantageReport, AuroraVerdict, Issue

__all__ = ["VantageAnalyzer", "analyze", "VantageReport", "AuroraVerdict", "Issue"]
__version__ = "1.0.0"
