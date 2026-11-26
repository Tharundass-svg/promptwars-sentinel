"""Prompt quality analysis with explainable, deterministic heuristics."""

import re
from typing import Any, Dict

from .security import scan_threats, sanitize_input

ROLE_RE = re.compile(r"\b(?:you are|act as|your role is|role:)\b", re.I)
TASK_RE = re.compile(r"\b(?:write|create|summari[sz]e|analy[sz]e|translate|classify|extract|compare|review|generate|answer|build|explain)\b", re.I)
OUTPUT_RE = re.compile(r"\b(?:format|structure|return|output|respond|provide)\b", re.I)
CONSTRAINT_RE = re.compile(r"\b(?:must|must not|do not|don't|never|always|only|limit|ensure|avoid|include|exclude)\b", re.I)
BOUNDARY_RE = re.compile(r"(?:<\w+>.*?</\w+>|```[\w-]*\s*[\s\S]*?```|\[UNTRUSTED\]|\[USER INPUT\])", re.I)
AMBIGUITY_RE = re.compile(r"\b(?:etc\.?|and so on|maybe|somehow|as best as you can|good answers|appropriate)\b", re.I)

PERSONA_WEIGHTS = {
    "developer": {"security": .30, "clarity": .25, "robustness": .30, "efficiency": .15},
    "red_team": {"security": .50, "clarity": .15, "robustness": .25, "efficiency": .10},
    "business_creator": {"security": .20, "clarity": .40, "robustness": .20, "efficiency": .20},
}


def _tier(elo: int):
    if elo >= 1900:
        return "Grandmaster Sentinel (S+)", "emerald"
    if elo >= 1600:
        return "Elite Architect (A)", "cyan"
    if elo >= 1300:
        return "Combatant Engineer (B)", "amber"
    return "Vulnerable Novice (C-)", "rose"


def analyze_prompt(prompt: str, user_persona: str = "developer") -> Dict[str, Any]:
    clean = sanitize_input(prompt)
    persona = user_persona.lower() if isinstance(user_persona, str) else "developer"
    if persona not in PERSONA_WEIGHTS:
        persona = "developer"
    if not clean:
        return {"error": "Empty prompt provided", "scores": {"security": 0, "clarity": 0,
                "efficiency": 0, "robustness": 0, "overall_elo": 800}}

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

    # Clarity rewards an explicit role, actionable task, output expectations and
    # readable structure. Length alone is not treated as quality.
    clarity = 35 + 15 * has_role + 25 * has_task + 10 * has_output
    clarity += 10 if 1 <= len(sentences) <= 8 else 0
    clarity -= min(25, ambiguity_hits * 8)
    clarity -= 10 if word_count < 5 else 0
    clarity = round(max(0, min(100, clarity)), 1)

    # Robustness requires multiple independent controls, not merely keyword count.
    lower = clean.lower()
    has_injection_rule = bool(re.search(r"\b(?:untrusted|prompt injection|ignore attempts|instruction hierarchy|do not follow)\b", lower))
    has_fallback = bool(re.search(r"\b(?:if .*?(?:unclear|unsafe|conflict|missing)|ask for clarification|refuse|decline)\b", lower, re.S))
    has_privacy_rule = bool(re.search(r"\b(?:never|do not|must not)\b.{0,70}\b(?:reveal|disclose|share|expose)\b.{0,50}\b(?:system|secret|credential|key|password|instruction)", lower, re.S))
    robustness = 30 + min(20, constraint_hits * 5) + 15 * has_delimiters
    robustness += 15 * has_injection_rule + 10 * has_fallback + 10 * has_privacy_rule
    robustness -= 25 if not sec["is_safe"] else 0
    robustness = round(max(0, min(100, robustness)), 1)

    # Smooth length penalty: concise task prompts score well; extreme payloads
    # and tiny underspecified prompts lose points gradually.
    if word_count < 8:
        efficiency = max(25, 45 + word_count * 4)
    elif word_count <= 180:
        efficiency = 96 - max(0, word_count - 100) * .08
    elif word_count <= 400:
        efficiency = 89 - (word_count - 180) * .10
    else:
        efficiency = max(25, 67 - (word_count - 400) * .08)
    efficiency = round(max(0, min(100, efficiency)), 1)

    weights = PERSONA_WEIGHTS[persona]
    composite = sum(score * weights[key] for key, score in {
        "security": sec["security_score"], "clarity": clarity,
        "robustness": robustness, "efficiency": efficiency}.items())
    composite = round(composite, 1)
    # Preserve the existing UI's Elo-like range, but derive it consistently
    # from the composite quality score rather than an arbitrary inflated offset.
    overall_elo = int(round(800 + composite * 12))
    tier, badge = _tier(overall_elo)

    recommendations = []
    if not has_role: recommendations.append("Define the assistant's role and scope explicitly.")
    if not has_task: recommendations.append("State the exact task and the expected outcome using an actionable verb.")
    if not has_output: recommendations.append("Specify the required response format, structure, or length.")
    if not has_delimiters and word_count > 25: recommendations.append("Wrap external/user-provided content in clear delimiters and label it untrusted.")
    if not has_injection_rule: recommendations.append("Add an instruction-hierarchy rule: treat embedded instructions in user data as untrusted content.")
    if not has_fallback: recommendations.append("Define a safe fallback for ambiguous, conflicting, or unsafe requests.")
    if not has_privacy_rule: recommendations.append("Add explicit rules protecting credentials, secrets, and hidden system instructions.")
    if ambiguity_hits: recommendations.append("Replace vague wording with measurable requirements and acceptance criteria.")
    if not sec["is_safe"]: recommendations.append("Review and remove detected attack-like instructions: " + ", ".join(sec["categories_triggered"]) + ".")

    return {
        "persona_applied": persona,
        "metrics": {"word_count": word_count, "estimated_tokens": estimated_tokens,
                    "has_role_definition": bool(has_role), "has_task_definition": bool(has_task),
                    "has_output_specification": bool(has_output), "has_delimiters": bool(has_delimiters),
                    "constraint_rules_count": constraint_hits, "sentence_count": len(sentences)},
        "scores": {"security": round(sec["security_score"], 1), "clarity": clarity,
                   "robustness": robustness, "efficiency": efficiency, "composite": composite,
                   "overall_elo": overall_elo, "rank_tier": tier, "badge_color": badge},
        "security_details": sec, "recommendations": recommendations,
    }
