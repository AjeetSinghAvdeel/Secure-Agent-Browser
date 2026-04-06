# Context-aware reasoning helpers for malicious page detection.

from __future__ import annotations

import re
from typing import Any, Dict, List


BENIGN_CONTEXT_PHRASES = [
    "learn more",
    "how it works",
    "documentation",
    "help center",
    "privacy policy",
    "terms of service",
    "security overview",
    "about us",
    "contact us",
    "sign in to your account",
    "create your account",
    "manage your account",
    "simulation only",
    "no data is sent",
]

PROMPT_INJECTION_PHRASES = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "system override",
    "override security policy",
    "reveal hidden policies",
    "reveal system prompt",
    "bypass security",
    "escalate privileges",
    "dump credentials",
    "exfiltrate secrets",
    "tool policy replacement",
    "jailbreak",
]

PHISHING_PHRASES = [
    "verify your account",
    "verify now",
    "confirm your identity",
    "unusual login attempt",
    "account will be suspended",
    "immediate verification required",
    "continue secure login",
    "password update",
    "approve access immediately",
    "approve access now",
]

SENSITIVE_TERMS = [
    "password",
    "passcode",
    "otp",
    "token",
    "secret",
    "api key",
    "credential",
]

OBFUSCATION_HINTS = [
    "eval(",
    "atob(",
    "fromcharcode(",
    "base64_blob",
    "hex_payload",
]

IMPERATIVE_PATTERNS = [
    r"\benter your\b",
    r"\bsubmit your\b",
    r"\bverify your\b",
    r"\bconfirm your\b",
    r"\bclick here to\b",
    r"\blogin now\b",
    r"\bcontinue verification\b",
    r"\bapprove access\b",
    r"\bexport data\b",
    r"\bconnect wallet\b",
]


def detect_malicious_intent(text: str) -> Dict[str, Any]:
    lowered = re.sub(r"\s+", " ", (text or "").lower()).strip()
    reasons: List[str] = []
    flags: List[str] = []
    score = 0.0

    benign_hits = [phrase for phrase in BENIGN_CONTEXT_PHRASES if phrase in lowered]
    prompt_hits = [phrase for phrase in PROMPT_INJECTION_PHRASES if phrase in lowered]
    phishing_hits = [phrase for phrase in PHISHING_PHRASES if phrase in lowered]
    sensitive_hits = [term for term in SENSITIVE_TERMS if term in lowered]
    obfuscation_hits = [term for term in OBFUSCATION_HINTS if term in lowered]
    imperative_hits = sum(
        1 for pattern in IMPERATIVE_PATTERNS if re.search(pattern, lowered)
    )

    if prompt_hits:
        flags.append("prompt_injection")
        score += min(0.55, 0.18 * len(prompt_hits))
        reasons.append("Prompt-injection style instructions detected")

    if phishing_hits:
        flags.append("phishing_intent")
        score += min(0.45, 0.12 * len(phishing_hits))
        reasons.append("Urgent verification or account recovery language detected")

    if len(sensitive_hits) >= 2 and not (benign_hits and not prompt_hits and not phishing_hits and imperative_hits == 0):
        flags.append("credential_request")
        score += 0.18
        reasons.append("Sensitive credential fields are requested")
    elif sensitive_hits:
        score += 0.08

    if obfuscation_hits:
        flags.append("obfuscation_intent")
        score += min(0.25, 0.08 * len(obfuscation_hits))
        reasons.append("Obfuscation-oriented script markers detected")

    if imperative_hits:
        flags.append("imperative_manipulation")
        score += min(0.20, 0.05 * imperative_hits)
        reasons.append("The page pressures the agent/user to perform actions")

    if "approve access" in lowered and any(token in lowered for token in ("account data", "team permissions", "workspace active")):
        if "phishing_intent" not in flags:
            flags.append("phishing_intent")
        score += 0.24
        reasons.append("The page pushes high-impact consent or permission approval")

    if "export all" in lowered and any(token in lowered for token in ("secret", "credential", "token")):
        if "prompt_injection" not in flags:
            flags.append("prompt_injection")
        score += 0.24
        reasons.append("The page attempts to redirect the agent toward sensitive data export")

    # Benign context can reduce generic suspicion but should not neutralize
    # explicit prompt injection or phishing markers.
    if benign_hits and not prompt_hits and not phishing_hits:
        score = max(0.0, score - 0.20)
        reasons.append("Benign informational context detected")

    attack_type = "Suspicious Content"
    if "prompt_injection" in flags:
        attack_type = "Prompt Injection"
    elif "phishing_intent" in flags or "credential_request" in flags:
        attack_type = "Phishing"
    elif "obfuscation_intent" in flags:
        attack_type = "Obfuscation"

    score = max(0.0, min(1.0, round(score, 4)))
    return {
        "score": score,
        "flags": flags,
        "reasons": reasons,
        "attack_type": attack_type,
        "sensitive_terms": sensitive_hits,
        "imperative_hits": imperative_hits,
        "benign_hits": benign_hits,
        "malicious": score >= 0.45 or "prompt_injection" in flags,
    }


def analyze_intent(text: str):
    """
    Backward-compatible interface.

    Returns:
        (is_malicious: int, reasons: list[str])
    """
    result = detect_malicious_intent(text)
    return (1 if result["malicious"] else 0), result["reasons"]
