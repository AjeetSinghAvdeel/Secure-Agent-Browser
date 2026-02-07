def calculate_risk(injection, hidden, phishing, ml_result, llm_result):

    risk = 0
    reasons = []


    # -----------------------
    # Injection
    # -----------------------

    if len(injection) > 0:

        score = min(len(injection) * 25, 75)
        risk += score

        reasons.append(
            f"Prompt injection detected ({len(injection)} patterns)"
        )


    # -----------------------
    # Hidden / Clickjacking
    # -----------------------

    if len(hidden) > 0:

        score = min(len(hidden) * 30, 80)
        risk += score

        reasons.append("Hidden content / clickjacking detected")


    # -----------------------
    # Phishing
    # -----------------------

    if len(phishing) > 0:

        risk += 60
        reasons.append("Phishing credential harvesting detected")


    # -----------------------
    # ML Detection
    # -----------------------

    if ml_result == 1:

        risk += 40
        reasons.append("ML model detected suspicious content")


    # -----------------------
    # LLM Reasoning (NEW)
    # -----------------------

    if llm_result == 1:

        risk += 35
        reasons.append("LLM reasoning: malicious intent detected")


    # -----------------------
    # Cap Risk
    # -----------------------

    if risk > 100:
        risk = 100


    return risk, reasons
