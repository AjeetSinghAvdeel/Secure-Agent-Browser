def calculate_risk(injection, hidden, phishing):
    score = 0
    reasons = []

    if injection:
        score += 40
        reasons.append("Prompt injection detected")

    if hidden:
        score += 30
        reasons.append("Hidden content found")

    if phishing:
        score += 30
        reasons.append("Suspicious login form")

    return score, reasons
