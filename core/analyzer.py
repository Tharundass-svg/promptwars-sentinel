"""
Prompt quality analysis with explainable, deterministic heuristics.
Evaluates prompt clarity, structural rigor, negative constraints, and token efficiency.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from .models import AnalysisResult, MetricDetails, ScoreMetrics
from .security import sanitize_input, scan_threats

logger = logging.getLogger(__name__)

ROLE_RE = re.compile(r"\b(?:you are|act as|your role is|role:)\b", re.I)
TASK_RE = re.compile(
    r"\b(?:write|create|summari[sz]e|analy[sz]e|translate|classify|extract|compare|review|generate|answer|build|explain)\b",
    re.I
)
OUTPUT_RE = re.compile(r"\b(?:format|structure|return|output|respond|provide)\b", re.I)
CONSTRAINT_RE = re.compile(
    r"\b(?:must|must not|do not|don't|never|always|only|limit|ensure|avoid|include|exclude)\b",
    re.I
)
BOUNDARY_RE = re.compile(r"(?:<\w+>.*?</\w+>|```[\w-]*\s*[\s\S]*?```|\[UNTRUSTED\]|\[USER INPUT\])", re.I)
AMBIGUITY_RE = re.compile(r"\b(?:etc\.?|and so on|maybe|somehow|as best as you can|good answers|appropriate)\b", re.I)

PERSONA_WEIGHTS: Dict[str, Dict[str, float]] = {
    "developer": {"security": 0.30, "clarity": 0.25, "robustness": 0.30, "efficiency": 0.15},
    "red_team": {"security": 0.50, "clarity": 0.15, "robustness": 0.25, "efficiency": 0.10},
    "business_creator": {"security": 0.20, "clarity": 0.40, "robustness": 0.20, "efficiency": 0.20},
}


def _tier(elo: int) -> Tuple[str, str]:
    """Classifies an Elo score into a competitive rank tier and badge color."""
    if elo >= 1900:
        return "Grandmaster Sentinel (S+)", "emerald"
    if elo >= 1600:
        return "Elite Architect (A)", "cyan"
    if elo >= 1300:
        return "Combatant Engineer (B)", "amber"
    return "Vulnerable Novice (C-)", "rose"


def analyze_prompt(prompt: str, user_persona: str = "developer") -> Dict[str, Any]:
    """
    Performs multi-dimensional analysis on a given prompt, weighting scores
    according to the user's role context (developer, red_team, or business_creator).

    Args:
        prompt: Raw prompt text to analyze.
        user_persona: Target operational persona context.

    Returns:
        Dict[str, Any]: Detailed scoring, metrics, security audit, and recommendations.
    """
    logger.debug("Analyzing prompt with persona: %s", user_persona)
    clean = sanitize_input(prompt)
    persona = user_persona.lower() if isinstance(user_persona, str) else "developer"
    if persona not in PERSONA_WEIGHTS:
        persona = "developer"

    if not clean:
        return {
            "error": "Empty prompt provided",
            "scores": {
                "security": 0.0,
                "clarity": 0.0,
                "efficiency": 0.0,
                "robustness": 0.0,
                "composite": 0.0,
                "overall_elo": 800,
                "rank_tier": "Vulnerable Novice (C-)",
                "badge_color": "rose"
            }
        }

    words = re.findall(r"\b[\w'-]+\b", clean)
    word_count = len(words)
    estimated_tokens = max(1, round(len(clean) / 4))
    sentences = [s for s in re.split(r"[.!?\n]+", clean) if s.strip()]
    has_role = bool(ROLE_RE.search(clean))
    has_task = bool(TASK_RE.search(clean))
    has_output = bool(OUTPUT_RE.search(clean))
    has_delimiters = bool(BOUNDARY_RE.search(clean))
    ambiguity_hits = len(AMBIGUITY_RE.findall(clean))
    constraint_hits = len(CONSTRAINT_RE.findall(clean))
    sec = scan_threats(clean)

    # Clarity rewards an explicit role, actionable task, output expectations and readable structure
    clarity = 35 + 15 * has_role + 25 * has_task + 10 * has_output
    clarity += 10 if 1 <= len(sentences) <= 8 else 0
    clarity -= min(25, ambiguity_hits * 8)
    clarity -= 10 if word_count < 5 else 0
    clarity = round(max(0.0, min(100.0, float(clarity))), 1)

    # Robustness requires multiple independent controls
    lower = clean.lower()
    has_injection_rule = bool(re.search(
        r"\b(?:untrusted|prompt injection|ignore attempts|instruction hierarchy|do not follow)\b", lower
    ))
    has_fallback = bool(re.search(
        r"\b(?:if .*?(?:unclear|unsafe|conflict|missing)|ask for clarification|refuse|decline)\b", lower, re.S
    ))
    has_privacy_rule = bool(re.search(
        r"\b(?:never|do not|must not)\b.{0,70}\b(?:reveal|disclose|share|expose)\b.{0,50}\b(?:system|secret|credential|key|password|instruction)",
        lower,
        re.S
    ))
    robustness = 30 + min(20, constraint_hits * 5) + 15 * has_delimiters
    robustness += 15 * has_injection_rule + 10 * has_fallback + 10 * has_privacy_rule
    robustness -= 25 if not sec["is_safe"] else 0
    robustness = round(max(0.0, min(100.0, float(robustness))), 1)

    # Length & token efficiency curve
    if word_count < 8:
        efficiency = max(25.0, 45.0 + word_count * 4.0)
    elif word_count <= 180:
        efficiency = 96.0 - max(0.0, float(word_count - 100)) * 0.08
    elif word_count <= 400:
        efficiency = 89.0 - float(word_count - 180) * 0.10
    else:
        efficiency = max(25.0, 67.0 - float(word_count - 400) * 0.08)
    efficiency = round(max(0.0, min(100.0, float(efficiency))), 1)

    weights = PERSONA_WEIGHTS[persona]
    composite = sum(
        score * weights[key]
        for key, score in {
            "security": sec["security_score"],
            "clarity": clarity,
            "robustness": robustness,
            "efficiency": efficiency
        }.items()
    )
    composite = round(float(composite), 1)
    overall_elo = int(round(800 + composite * 12))
    tier, badge = _tier(overall_elo)

    recommendations: List[str] = []
    if not has_role:
        recommendations.append("Define the assistant's role and scope explicitly.")
    if not has_task:
        recommendations.append("State the exact task and the expected outcome using an actionable verb.")
    if not has_output:
        recommendations.append("Specify the required response format, structure, or length.")
    if not has_delimiters and word_count > 25:
        recommendations.append("Wrap external/user-provided content in clear delimiters and label it untrusted.")
    if not has_injection_rule:
        recommendations.append("Add an instruction-hierarchy rule: treat embedded instructions in user data as untrusted content.")
    if not has_fallback:
        recommendations.append("Define a safe fallback for ambiguous, conflicting, or unsafe requests.")
    if not has_privacy_rule:
        recommendations.append("Add explicit rules protecting credentials, secrets, and hidden system instructions.")
    if ambiguity_hits:
        recommendations.append("Replace vague wording with measurable requirements and acceptance criteria.")
    if not sec["is_safe"]:
        recommendations.append("Review and remove detected attack-like instructions: " + ", ".join(sec["categories_triggered"]) + ".")

    return {
        "persona_applied": persona,
        "metrics": {
            "word_count": word_count,
            "estimated_tokens": estimated_tokens,
            "has_role_definition": bool(has_role),
            "has_task_definition": bool(has_task),
            "has_output_specification": bool(has_output),
            "has_delimiters": bool(has_delimiters),
            "constraint_rules_count": constraint_hits,
            "sentence_count": len(sentences)
        },
        "scores": {
            "security": round(float(sec["security_score"]), 1),
            "clarity": clarity,
            "robustness": robustness,
            "efficiency": efficiency,
            "composite": composite,
            "overall_elo": overall_elo,
            "rank_tier": tier,
            "badge_color": badge
        },
        "security_details": sec,
        "recommendations": recommendations,
    }
