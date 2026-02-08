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
    Runtime-aware risk scoring engine (EXPLAINABLE).

    Principles:
    - Runtime & network behavior have highest authority
    - ML / LLM are supporting signals only
    - Legitimate sites should never be blocked by language alone
    """

    risk = 0
    reasons = []
    behavior_findings = behavior_findings or []

    # -------------------------------
    # Signal Buckets (Explainability)
    # -------------------------------
    signal_scores = {
        "language": 0,
        "ui_behavior": 0,
        "credential": 0,
        "ml": 0,
        "runtime": 0,
    }

    attack_chain = []

    # --------------------------------------------------
    # 1. Prompt Injection / Language Abuse
    # --------------------------------------------------
    if injection:
        score = min(len(injection) * 20, 50)
        risk += score
        signal_scores["language"] += score
        reasons.append(
            f"Prompt injection indicators detected ({len(injection)})"
        )
        attack_chain.append("Language-based manipulation detected")

    # --------------------------------------------------
    # 2. Hidden UI / Clickjacking (low alone)
    # --------------------------------------------------
    if hidden:
        score = min(len(hidden) * 5, 15)
        risk += score
        signal_scores["ui_behavior"] += score
        reasons.append(
            "Hidden UI elements detected (modern site behavior)"
        )
        attack_chain.append("Hidden UI elements present")

    # --------------------------------------------------
    # 3. Credential Harvesting
    # --------------------------------------------------
    if phishing:
        risk += 20
        signal_scores["credential"] += 20
        reasons.append("Password input detected")
        attack_chain.append("Credential input surface detected")

        if injection or llm_result == 1:
            risk += 30
            signal_scores["credential"] += 30
            reasons.append(
                "Credential input combined with suspicious intent"
            )
            attack_chain.append("Credential harvesting intent confirmed")

    # --------------------------------------------------
    # 4. ML Signal (supporting only)
    # --------------------------------------------------
    if ml_result == 1:
        risk += 10
        signal_scores["ml"] += 10
        reasons.append(
            "ML model flagged statistically suspicious patterns"
        )

    # --------------------------------------------------
    # 5. LLM Intent Reasoning
    # --------------------------------------------------
    if llm_result == 1:
        risk += 15
        signal_scores["language"] += 15
        reasons.append(
            "Contextual intent analysis suggests elevated risk"
        )
        attack_chain.append("Malicious intent inferred")

    # --------------------------------------------------
    # 6. Runtime / Network Behavior (HIGHEST AUTHORITY)
    # --------------------------------------------------
    if behavior_risk > 0:
        risk += behavior_risk
        signal_scores["runtime"] += behavior_risk
        reasons.extend(behavior_findings)
        attack_chain.extend(behavior_findings)

        confidence = "high"

        # Runtime overrides soft scores
        if risk < 70:
            risk = 70

    # --------------------------------------------------
    # Cap Risk
    # --------------------------------------------------
    if risk > 100:
        risk = 100

    # --------------------------------------------------
    # Confidence Estimation (if not runtime-forced)
    # --------------------------------------------------
    if behavior_risk == 0:
        if risk >= 75:
            confidence = "high"
        elif risk >= 40:
            confidence = "medium"
        else:
            confidence = "low"

    # --------------------------------------------------
    # Primary Decision Driver (for judges)
    # --------------------------------------------------
    if signal_scores["runtime"] > 0:
        primary_signal = "runtime_behavior"
    elif signal_scores["credential"] > 0:
        primary_signal = "credential_harvesting"
    elif signal_scores["language"] > 0:
        primary_signal = "language_manipulation"
    else:
        primary_signal = "benign"

    decision = {
        "primary_signal": primary_signal,
        "signal_breakdown": signal_scores,
        "attack_chain": attack_chain,
    }

    return risk, reasons, confidence, decision
