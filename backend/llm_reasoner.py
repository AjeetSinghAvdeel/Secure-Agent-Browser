# Context-Aware LLM Reasoning Engine
# Purpose: Detect malicious intent while avoiding false positives on
# legitimate security, documentation, and login pages.

import re


def analyze_intent(text):
    text = text.lower()

    # ----------------------------------
    # 1. BENIGN CONTEXT INDICATORS
    # ----------------------------------
    # If these exist, the page is likely informational, not malicious
    benign_context_phrases = [
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
    ]

    for phrase in benign_context_phrases:
        if phrase in text:
            # Immediately reduce suspicion
            return 0, []

    # ----------------------------------
    # 2. INTENT FRAMING ANALYSIS
    # ----------------------------------
    # Malicious pages usually COMMAND the user
    # Legit pages DESCRIBE or INFORM
    imperative_patterns = [
        r"\benter your\b",
        r"\bsubmit your\b",
        r"\bverify your\b",
        r"\bconfirm your\b",
        r"\bclick here to\b",
        r"\blogin now\b",
    ]

    imperative_hits = 0
    for pattern in imperative_patterns:
        if re.search(pattern, text):
            imperative_hits += 1

    # ----------------------------------
    # 3. RISK KEYWORDS (WEIGHTED)
    # ----------------------------------

    high_risk_phrases = [
        "bypass security",
        "override system",
        "dump database",
        "grant access",
        "disable firewall",
        "root access",
    ]

    medium_risk_phrases = [
        "credentials",
        "password",
        "token",
        "secret",
        "database",
    ]

    score = 0
    reasons = []

    for phrase in high_risk_phrases:
        if phrase in text:
            score += 2
            reasons.append(f"High-risk intent phrase detected: '{phrase}'")

    for phrase in medium_risk_phrases:
        if phrase in text:
            score += 1
            reasons.append(f"Sensitive keyword detected: '{phrase}'")

    # ----------------------------------
    # 4. FINAL DECISION LOGIC
    # ----------------------------------
    # Rules:
    # - Risk keywords alone are NOT enough
    # - Imperative framing is REQUIRED for malicious intent
    # - This mirrors real browser behavior

    if score >= 3 and imperative_hits >= 1:
        reasons.append("Imperative language detected targeting user actions")
        return 1, reasons

    return 0, []
