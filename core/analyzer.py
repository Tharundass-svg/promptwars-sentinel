"""
Prompt Analysis Engine for PromptWars Sentinel.
Evaluates prompts across clarity, context efficiency, constraint rigor,
and security to calculate comprehensive scores and Elo rating.
"""

import re
from typing import Dict, Any, List
from .security import scan_threats, sanitize_input

ROLE_INDICATORS = [
    r"(?i)\byou\s+are\s+a(n)?\s+[a-z\s]+",
    r"(?i)\bact\s+as\s+[a-z\s]+",
    r"(?i)\byour\s+role\s+is\b",
    r"(?i)\bas\s+a(n)?\s+[a-z\s]+,\s+you",
]

CONSTRAINT_INDICATORS = [
    r"(?i)\bmust\s+not\b",
    r"(?i)\bdo\s+not\b",
    r"(?i)\bonly\s+respond\s+with\b",
    r"(?i)\boutput\s+format\b",
    r"(?i)\bjson\b",
    r"(?i)\blimit\s+your\s+response\s+to\b",
    r"(?i)\balways\b",
    r"(?i)\bnever\b",
]

AMBIGUITY_INDICATORS = [
    r"(?i)\betc\b",
    r"(?i)\band\s+so\s+on\b",
    r"(?i)\bmaybe\b",
    r"(?i)\bsomehow\b",
    r"(?i)\bas\s+best\s+as\s+you\s+can\b",
    r"(?i)\bgive\s+good\s+answers\b",
]

def analyze_prompt(prompt: str, user_persona: str = "developer") -> Dict[str, Any]:
    """
    Performs multi-dimensional analysis on a given prompt, weighting scores
    according to the user's role context (developer, red_team, or business_creator).
    """
    clean_prompt = sanitize_input(prompt)
    if not clean_prompt:
        return {
            "error": "Empty prompt provided",
            "scores": {
                "security": 0,
                "clarity": 0,
                "efficiency": 0,
                "robustness": 0,
                "overall_elo": 800
            }
        }

    # Word & Token Metrics
    words = re.findall(r"\b\w+\b", clean_prompt)
    word_count = len(words)
    estimated_tokens = int(word_count * 1.3)

    # 1. Security Scan
    sec_report = scan_threats(clean_prompt)
    security_score = sec_report["security_score"]

    # 2. Clarity & Specificity Analysis
    has_role = any(re.search(pat, clean_prompt) for pat in ROLE_INDICATORS)
    has_delimiters = bool(re.search(r"(\"\"\".*?\"\"\"|```.*?```|<context>.*?</context>|\[.*?\])", clean_prompt, re.DOTALL))
    
    # Ambiguity check
    ambiguity_hits = sum(1 for pat in AMBIGUITY_INDICATORS if re.search(pat, clean_prompt))
    
    clarity_base = 60
    if has_role:
        clarity_base += 20
    if has_delimiters:
        clarity_base += 15
    if word_count > 25:
        clarity_base += 10
    clarity_base -= (ambiguity_hits * 10)
    clarity_score = max(10, min(100, clarity_base))

    # 3. Constraint & Robustness Analysis
    constraint_hits = sum(1 for pat in CONSTRAINT_INDICATORS if re.search(pat, clean_prompt))
    robustness_base = 50 + (constraint_hits * 12)
    if not sec_report["is_safe"]:
        robustness_base -= 30
    robustness_score = max(10, min(100, robustness_base))

    # 4. Token & Context Efficiency
    # Ideal sweet spot: 30 - 300 words for instruction prompts
    if word_count < 10:
        efficiency_score = 40  # Under-specified
    elif 10 <= word_count <= 250:
        efficiency_score = 95
    elif 250 < word_count <= 600:
        efficiency_score = 80
    else:
        efficiency_score = 65  # Bloated / high token cost

    # Contextual Weighting Based on Persona
    persona_weights = {
        "developer": {
            "security": 0.30,
            "clarity": 0.25,
            "robustness": 0.30,
            "efficiency": 0.15
        },
        "red_team": {
            "security": 0.50,
            "clarity": 0.15,
            "robustness": 0.25,
            "efficiency": 0.10
        },
        "business_creator": {
            "security": 0.20,
            "clarity": 0.40,
            "robustness": 0.20,
            "efficiency": 0.20
        }
    }
    
    weights = persona_weights.get(user_persona.lower(), persona_weights["developer"])
    
    composite_index = (
        (security_score * weights["security"]) +
        (clarity_score * weights["clarity"]) +
        (robustness_score * weights["robustness"]) +
        (efficiency_score * weights["efficiency"])
    )

    # Elo Rating Calculation (Base 1000 + composite * 10)
    overall_elo = int(900 + (composite_index * 12))

    # Tier Classification
    if overall_elo >= 1900:
        rank_tier = "Grandmaster Sentinel (S+)"
        badge_color = "emerald"
    elif overall_elo >= 1600:
        rank_tier = "Elite Architect (A)"
        badge_color = "cyan"
    elif overall_elo >= 1300:
        rank_tier = "Combatant Engineer (B)"
        badge_color = "amber"
    else:
        rank_tier = "Vulnerable Novice (C-)"
        badge_color = "rose"

    # Contextual dynamic recommendations
    recommendations = []
    if not has_role:
        recommendations.append("Define an explicit persona/system role (e.g. 'You are an expert security auditor...').")
    if constraint_hits == 0:
        recommendations.append("Specify negative boundaries or output rules (e.g. 'Never disclose internal API keys').")
    if not has_delimiters and word_count > 40:
        recommendations.append("Use structural delimiters (like XML tags <input>...</input> or triple quotes) to separate instructions from user input.")
    if ambiguity_hits > 0:
        recommendations.append("Eliminate open-ended ambiguity words like 'etc.' or 'as best as you can'.")
    if not sec_report["is_safe"]:
        recommendations.append(f"Security Alert: Resolved threat triggers: {', '.join(sec_report['categories_triggered'])}.")

    return {
        "persona_applied": user_persona,
        "metrics": {
            "word_count": word_count,
            "estimated_tokens": estimated_tokens,
            "has_role_definition": has_role,
            "has_delimiters": has_delimiters,
            "constraint_rules_count": constraint_hits
        },
        "scores": {
            "security": round(security_score, 1),
            "clarity": round(clarity_score, 1),
            "robustness": round(robustness_score, 1),
            "efficiency": round(efficiency_score, 1),
            "composite": round(composite_index, 1),
            "overall_elo": overall_elo,
            "rank_tier": rank_tier,
            "badge_color": badge_color
        },
        "security_details": sec_report,
        "recommendations": recommendations
    }
