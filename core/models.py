"""
Core domain models and typed data transfer objects for PromptWars Sentinel.
Provides strict type annotations and schemas for static analysis and IDE autocompletion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict


class ThreatDetail(TypedDict):
    category: str
    matched_pattern: str
    severity: str


class ThreatScanReport(TypedDict):
    security_score: float
    is_safe: bool
    threat_count: int
    threats: List[ThreatDetail]
    categories_triggered: List[str]
    risk_level: str


class ScoreMetrics(TypedDict):
    security: float
    clarity: float
    robustness: float
    efficiency: float
    composite: float
    overall_elo: int
    rank_tier: str
    badge_color: str


class MetricDetails(TypedDict):
    word_count: int
    estimated_tokens: int
    has_role_definition: bool
    has_task_definition: bool
    has_output_specification: bool
    has_delimiters: bool
    constraint_rules_count: int
    sentence_count: int


class AnalysisResult(TypedDict):
    persona_applied: str
    metrics: MetricDetails
    scores: ScoreMetrics
    security_details: ThreatScanReport
    recommendations: List[str]


class BattleRoundResult(TypedDict):
    round: int
    attack_name: str
    attack_vector: str
    defense_held: bool
    outcome: str
    damage_taken: int
    combat_log: str


class BattleSummary(TypedDict):
    verdict: str
    status: str
    rounds_won: int
    total_rounds: int
    win_rate_percent: float
    remaining_hp: int
    total_damage_taken: int
    battle_rounds: List[BattleRoundResult]


class OptimizationResult(TypedDict):
    original_prompt: str
    hardened_prompt: str
    persona_used: str
    improvements: List[str]
    before_scores: ScoreMetrics
    after_scores: ScoreMetrics
    elo_gain: int
