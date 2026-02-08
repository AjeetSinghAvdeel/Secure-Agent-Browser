def calculate_risk(
    injection,
    hidden,
    phishing,
    ml_result,
    llm_result,
    behavior_risk=0,
    behavior_findings=None,
):
    """
    Runtime-aware risk scoring engine.

    Principles:
    - Runtime behavior has highest authority
    - ML / LLM are supporting signals only
    - Legitimate sites should never be blocked by language alone
    """

    risk = 0
    reasons = []
    behavior_findings = behavior_findings or []

    # --------------------------------------------------
    # 1. Prompt Injection (language-based, weak alone)
    # --------------------------------------------------
    if injection:
        score = min(len(injection) * 20, 50)
        risk += score
        reasons.append(
            f"Prompt injection indicators detected ({len(injection)})"
        )

    # --------------------------------------------------
    # 2. Hidden Elements (common on modern sites)
    # --------------------------------------------------
    if hidden:
        risk += min(len(hidden) * 5, 15)
        reasons.append(
            "Hidden UI elements detected (modern site behavior)"
        )

    # --------------------------------------------------
    # 3. Phishing / Credential Harvesting
    # --------------------------------------------------
    if phishing:
        risk += 20
        reasons.append("Password input detected")

        # Escalate only if combined with intent
        if injection or llm_result == 1:
            risk += 30
            reasons.append(
                "Credential input combined with suspicious intent"
            )

    # --------------------------------------------------
    # 4. ML Signal (supporting only)
    # --------------------------------------------------
    if ml_result == 1:
        risk += 10
        reasons.append(
            "ML model flagged statistically suspicious patterns"
        )

    # --------------------------------------------------
    # 5. LLM Intent Reasoning (contextual)
    # --------------------------------------------------
    if llm_result == 1:
        risk += 15
        reasons.append(
            "Contextual intent analysis suggests elevated risk"
        )

    # --------------------------------------------------
    # 6. Runtime Behavior (HIGHEST AUTHORITY)
    # --------------------------------------------------
    if behavior_risk > 0:
        risk += behavior_risk
        reasons.extend(behavior_findings)

        # Runtime behavior overrides confidence
        confidence = "high"

        # Hard cap escalation
        if risk < 70:
            risk = 70

    # --------------------------------------------------
    # Cap Risk
    # --------------------------------------------------
    if risk > 100:
        risk = 100

    # --------------------------------------------------
    # Confidence Estimation (if not forced by runtime)
    # --------------------------------------------------
    if behavior_risk == 0:
        if risk >= 75:
            confidence = "high"
        elif risk >= 40:
            confidence = "medium"
        else:
            confidence = "low"

    return risk, reasons, confidence
