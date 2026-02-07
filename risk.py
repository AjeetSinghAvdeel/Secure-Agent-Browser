def calculate_risk(injection, hidden, phishing):

    risk = 0
    reasons = []

    # -----------------------
    # Injection Scoring
    # -----------------------

    if len(injection) > 0:

        score = min(len(injection) * 25, 75)
        risk += score

        reasons.append(f"Prompt injection detected ({len(injection)} patterns)")


    # -----------------------
    # Hidden Content Scoring
    # -----------------------

    if len(hidden) > 0:

        score = min(len(hidden) * 25, 70)
        risk += score

        reasons.append("Hidden malicious content detected")


    # -----------------------
    # Phishing Scoring
    # -----------------------

    if len(phishing) > 0:

        risk += 60
        reasons.append("Phishing credential harvesting detected")


    # -----------------------
    # Cap Risk
    # -----------------------

    if risk > 100:
        risk = 100


    return risk, reasons
