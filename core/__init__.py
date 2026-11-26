"""
PromptWars Sentinel Core Engine Package.
High-performance, explainable prompt security audit, battle simulation, and hardening engine.
"""

from __future__ import annotations

from .adversary import conduct_prompt_battle
from .analyzer import analyze_prompt
from .exceptions import (
    InvalidPersonaError,
    PayloadTooLargeError,
    PromptWarsError,
    SecurityScanError,
    ValidationError,
)
from .models import (
    AnalysisResult,
    BattleRoundResult,
    BattleSummary,
    MetricDetails,
    OptimizationResult,
    ScoreMetrics,
    ThreatDetail,
    ThreatScanReport,
)
from .optimizer import optimize_prompt
from .security import sanitize_input, scan_threats

__all__ = [
    # Core Engine APIs
    "analyze_prompt",
    "conduct_prompt_battle",
    "optimize_prompt",
    "sanitize_input",
    "scan_threats",
    # Domain Models
    "AnalysisResult",
    "BattleRoundResult",
    "BattleSummary",
    "MetricDetails",
    "OptimizationResult",
    "ScoreMetrics",
    "ThreatDetail",
    "ThreatScanReport",
    # Exceptions
    "InvalidPersonaError",
    "PayloadTooLargeError",
    "PromptWarsError",
    "SecurityScanError",
    "ValidationError",
]
