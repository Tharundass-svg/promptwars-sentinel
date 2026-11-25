"""
Security module for PromptWars Sentinel.
Provides input sanitization, adversarial attack pattern matching,
and risk categorization to protect against prompt injection, data exfiltration,
and jailbreak vulnerabilities.
"""

import re
import html
from typing import Dict, List, Tuple, Any

# Threat signatures for prompt injection and jailbreaks
THREAT_PATTERNS = {
    "direct_instruction_override": [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(rules|guidelines|constraints)",
        r"(?i)forget\s+(everything|all\s+rules|your\s+identity)",
        r"(?i)system\s*override",
    ],
    "jailbreak_personas": [
        r"(?i)\byou\s+are\s+(now\s+)?(dan|dude|developer\s+mode|unconstrained|chaos\s*gpt)\b",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)\bact\s+as\s+an\s+unfiltered\b",
        r"(?i)\bbypass\s+(all\s+)?(ethical|safety|content)?\s*filters\b",
    ],
    "system_prompt_leakage": [
        r"(?i)repeat\s+(everything|the\s+words|the\s+text)\s+(above|before|from\s+the\s+beginning)",
        r"(?i)(output|print|reveal|display|echo|repeat|leak|dump)\s+(your\s+)?((initial|original|system)\s+)*(prompt|instructions)",
        r"(?i)what\s+were\s+the\s+instructions\s+given\s+to\s+you",
    ],
    "delimiter_collision": [
        r"```system",
        r"<\s*/?\s*system\s*>",
        r"\[INST\]\s*<<SYS>>",
        r"---+\s*END\s+(OF\s+)?SYSTEM\s+PROMPT\s*---+",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
    ],
    "privilege_escalation": [
        r"(?i)you\s+are\s+(the\s+)?(root|admin|superuser|developer|creator)\b",
        r"(?i)authorize\s+(maintenance|debug|override)\s+mode",
        r"(?i)enter\s+(god|sudo|unrestricted)\s+mode",
    ],
    "obfuscation_encoding": [
        r"(?i)base64\s*(decode|encoded|string)?:\s*[A-Za-z0-9+/=]{20,}",
        r"(?i)rot13\b",
        r"(?i)hex\s*encoded",
    ]
}

def sanitize_input(text: str, max_length: int = 8000) -> str:
    """
    Sanitizes user input to prevent HTML injection and excessive payload sizes.
    """
    if not isinstance(text, str):
        return ""
    # Strip null bytes and normalize whitespace
    cleaned = text.replace("\x00", "").strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned

def scan_threats(prompt: str) -> Dict[str, Any]:
    """
    Scans a prompt against threat signatures and returns detected vulnerabilities,
    threat category counts, and a security risk score (0 to 100).
    Ignores defensive guardrail contexts (e.g. 'Never reveal instructions').
    """
    detected_threats: List[Dict[str, str]] = []
    category_matches: Dict[str, int] = {}
    total_penalty = 0

    category_weights = {
        "direct_instruction_override": 35,
        "jailbreak_personas": 40,
        "system_prompt_leakage": 30,
        "delimiter_collision": 25,
        "privilege_escalation": 25,
        "obfuscation_encoding": 20
    }

    # Defensive boundary pattern: if preceded by negative assertion, it's a defensive rule
    defensive_prefix = r"(?i)(never|do\s+not|must\s+not|refuse\s+to|reject|cannot|prohibit(ed)?)\s+[^.!?\n]*?"

    for category, patterns in THREAT_PATTERNS.items():
        matches_in_cat = 0
        for pattern in patterns:
            for match in re.finditer(pattern, prompt):
                # Check if this occurrence is part of a defensive guardrail rule
                start_idx = match.start()
                preceding_text = prompt[max(0, start_idx - 60):start_idx]
                if re.search(r"(?i)\b(never|do\s+not|must\s+not|refuse\s+to|reject|cannot|prohibit(ed)?)\b", preceding_text):
                    # It's an explicit protective constraint!
                    continue

                matches_in_cat += 1
                detected_threats.append({
                    "category": category,
                    "matched_pattern": match.group(0),
                    "severity": "HIGH" if category_weights[category] >= 30 else "MEDIUM"
                })
        if matches_in_cat > 0:
            category_matches[category] = matches_in_cat
            total_penalty += category_weights.get(category, 20) * min(matches_in_cat, 2)

    security_score = max(0, 100 - total_penalty)

    return {
        "security_score": security_score,
        "is_safe": len(detected_threats) == 0,
        "threat_count": len(detected_threats),
        "threats": detected_threats,
        "categories_triggered": list(category_matches.keys()),
        "risk_level": "CRITICAL" if security_score < 40 else ("MEDIUM" if security_score < 75 else "LOW")
    }
