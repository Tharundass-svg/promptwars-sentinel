"""Defensive prompt-injection screening.

This is a deterministic heuristic scanner, not a substitute for model-side
isolation, authorization, or a dedicated security classifier. It normalizes
common obfuscations, detects multiple attack families, and avoids treating a
nearby negative sentence as blanket permission to suppress a finding.
"""

import html
import re
import unicodedata
from typing import Any, Dict, List

MAX_INPUT_LENGTH = 8000

# Patterns are deliberately grouped by attack objective. Keep them reasonably
# specific: broad words such as "admin" or "system" alone create false alarms.
THREAT_PATTERNS = {
    "direct_instruction_override": [
        r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:system\s+)?(?:instructions?|directives?|rules?|prompts?)\b",
        r"\bdisregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|guidelines?)\b",
        r"\bforget\s+(?:everything|all\s+(?:previous\s+)?(?:rules|instructions)|your\s+identity)\b",
        r"\b(?:new|override|replace)\s+(?:system\s+)?instructions?\s*[:=]",
    ],
    "jailbreak_personas": [
        r"\byou\s+are\s+(?:now\s+)?(?:dan|d\.?a\.?n\.?|chaos\s*gpt|unrestricted\s+ai)\b",
        r"\bdo\s+anything\s+now\b",
        r"\b(?:enter|enable|activate)\s+(?:developer|unfiltered|unrestricted|god)\s+mode\b",
        r"\bact\s+as\s+(?:an?\s+)?(?:unfiltered|unrestricted)\b",
        r"\bbypass\s+(?:all\s+)?(?:the\s+)?(?:safety|ethical|content)\s+filters?\b",
    ],
    "system_prompt_leakage": [
        r"\b(?:reveal|print|repeat|output|dump|show|leak| disclose)\s+(?:your\s+)?(?:hidden\s+|initial\s+|original\s+|full\s+)?(?:system\s+prompt|system\s+instructions|developer\s+instructions)\b",
        r"\bwhat\s+(?:are|were)\s+your\s+(?:hidden\s+)?(?:system\s+)?instructions\b",
        r"\b(?:verbatim|word\s+for\s+word)\s+(?:copy|repeat|provide)\b.{0,50}\b(?:prompt|instructions)\b",
    ],
    "delimiter_collision": [
        r"<\s*/?\s*system\s*>", r"\[\s*INST\s*\].{0,40}<<\s*SYS\s*>>",
        r"<\|im_(?:start|end)\|>", r"<\|(?:system|assistant|developer)\|>",
        r"```\s*(?:system|developer)\b", r"-{3,}\s*END\s+(?:OF\s+)?SYSTEM\s+PROMPT\s*-{3,}",
    ],
    "privilege_escalation": [
        r"\b(?:grant|give|assume)\s+(?:me\s+)?(?:root|admin|administrator|superuser)\s+(?:access|privileges?|clearance)\b",
        r"\b(?:authorize|enable|enter)\s+(?:the\s+)?(?:maintenance|debug|sudo|root|superuser)\s+mode\b",
        r"\b(?:you\s+are\s+now\s+)?(?:the\s+)?(?:root|superuser)\s+administrator\b",
    ],
    "obfuscation_encoding": [
        r"\bbase\s*64\s*(?:decode|decoded|payload)\b", r"\brot\s*13\b",
        r"\bhex(?:adecimal)?\s*encoded\s+(?:payload|instruction|text)\b",
        r"\bdecode\s+(?:this|the\s+following)\s+(?:base64|rot13|hex)\b",
    ],
    "data_exfiltration": [
        r"\b(?:send|exfiltrate|upload|transmit)\b.{0,60}\b(?:secrets?|credentials?|api\s*keys?|passwords?|private\s+data)\b",
        r"\b(?:list|print|dump|export)\s+(?:all\s+)?(?:environment\s+variables|api\s*keys?|credentials|passwords)\b",
    ],
    "tool_misuse": [
        r"\b(?:run|execute|call)\s+(?:this\s+)?(?:shell|terminal|system)\s+command\b",
        r"\b(?:ignore|bypass)\s+(?:the\s+)?(?:tool|function)\s+authorization\b",
    ],
}

WEIGHTS = {
    "direct_instruction_override": 30, "jailbreak_personas": 35,
    "system_prompt_leakage": 35, "delimiter_collision": 25,
    "privilege_escalation": 30, "obfuscation_encoding": 20,
    "data_exfiltration": 40, "tool_misuse": 35,
}

_NEGATION = re.compile(r"\b(?:never|do\s+not|don't|must\s+not|mustn't|refuse\s+to|reject\s+requests?\s+to|prevent)\b", re.I)


def sanitize_input(text: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    """Normalize Unicode, remove NUL/control chars, and enforce a hard limit."""
    if not isinstance(text, str):
        return ""
    if not isinstance(max_length, int) or max_length < 0:
        raise ValueError("max_length must be a non-negative integer")
    text = unicodedata.normalize("NFKC", text).replace("\x00", "")
    text = "".join(ch for ch in text if ch in "\n\r\t" or unicodedata.category(ch) != "Cc")
    return text.strip()[:max_length]


def _normalized_for_detection(text: str) -> str:
    text = html.unescape(unicodedata.normalize("NFKC", text)).lower()
    # Normalize common separator obfuscation without deleting meaningful words.
    text = re.sub(r"(?<=\w)[\u200b\ufeff]", "", text)
    text = re.sub(r"\bi\u200bgnore\b", "ignore", text)
    return text


def _is_explicitly_defensive(text: str, start: int) -> bool:
    """Only suppress a hit when a clear negation governs the same short clause."""
    clause_start = max(text.rfind(".", 0, start), text.rfind(";", 0, start), text.rfind("\n", 0, start)) + 1
    prefix = text[clause_start:start]
    # A negation more than 100 chars away is unlikely to govern this occurrence.
    matches = list(_NEGATION.finditer(prefix[-120:]))
    if not matches:
        return False
    tail = prefix[-120:]
    neg = matches[-1]
    return len(tail[neg.end():]) <= 90


def scan_threats(prompt: str) -> Dict[str, Any]:
    """Return threat findings, risk score and transparent heuristic metadata."""
    clean = sanitize_input(prompt)
    if not clean:
        return {"security_score": 100, "is_safe": True, "threat_count": 0,
                "threats": [], "categories_triggered": [], "risk_level": "LOW",
                "scanner": "heuristic-v2", "limitations": "Empty input; no content evaluated."}

    text = _normalized_for_detection(clean)
    findings: List[Dict[str, Any]] = []
    categories: Dict[str, int] = {}
    seen = set()
    for category, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.I | re.S):
                key = (category, match.start(), match.end())
                if key in seen or _is_explicitly_defensive(text, match.start()):
                    continue
                seen.add(key)
                severity = "CRITICAL" if WEIGHTS[category] >= 35 else ("HIGH" if WEIGHTS[category] >= 25 else "MEDIUM")
                findings.append({"category": category, "matched_pattern": match.group(0),
                                 "severity": severity, "start": match.start(), "end": match.end()})
                categories[category] = categories.get(category, 0) + 1

    # Diminishing returns per category prevent repeated copies dominating score.
    penalty = sum(WEIGHTS[c] * min(count, 2) for c, count in categories.items())
    score = max(0, 100 - penalty)
    level = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW"
    return {"security_score": score, "is_safe": not findings, "threat_count": len(findings),
            "threats": findings, "categories_triggered": list(categories), "risk_level": level,
            "scanner": "heuristic-v2",
            "limitations": "Pattern-based screening can miss novel or context-dependent attacks; enforce authorization and isolate untrusted input at runtime."}
