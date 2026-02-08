def evaluate_action(action, scan_result):
    """
    Agent Action Mediation Engine

    action: dict describing agent intent
    scan_result: full scan output
    """

    risk = scan_result.get("risk", 0)
    decision = scan_result.get("decision", {})
    primary_signal = decision.get("primary_signal", "benign")

    # -----------------------------
    # HARD BLOCK CONDITIONS
    # -----------------------------
    if risk >= 70:
        return {
            "decision": "BLOCK",
            "reason": "High-risk malicious environment detected"
        }

    if (
        action["type"] == "submit_form"
        and primary_signal == "credential_harvesting"
    ):
        return {
            "decision": "BLOCK",
            "reason": "Credential submission on suspected phishing site"
        }

    # -----------------------------
    # WARN CONDITIONS
    # -----------------------------
    if risk >= 40:
        return {
            "decision": "WARN",
            "reason": "Suspicious activity detected, agent caution advised"
        }

    # -----------------------------
    # ALLOW
    # -----------------------------
    return {
        "decision": "ALLOW",
        "reason": "No malicious indicators detected"
    }
