# Simulated LLM Reasoning Engine


def analyze_intent(text):

    text = text.lower()

    suspicious_phrases = [

        "ignore",
        "override",
        "bypass",
        "root",
        "admin",
        "password",
        "credentials",
        "token",
        "dump",
        "database",
        "secret",
        "firewall",
        "disable",
        "grant access"
    ]

    score = 0
    reasons = []

    for phrase in suspicious_phrases:

        if phrase in text:
            score += 1
            reasons.append(f"Suspicious intent: '{phrase}'")


    # More sensitive detection
    if score >= 1:
        return 1, reasons
    else:
        return 0, reasons
