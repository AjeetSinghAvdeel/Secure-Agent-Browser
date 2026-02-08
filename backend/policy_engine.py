def evaluate_action(action, scan_result):
    """
    Policy-Governed Agent Decision Engine (Explainable)
    """

    risk = scan_result.get("risk", 0)
    decision_meta = scan_result.get("decision", {})
    primary_signal = decision_meta.get("primary_signal", "benign")

    explanation = []
    enforced_action = action["type"]

    # -----------------------------
    # HARD BLOCK CONDITIONS
    # -----------------------------
    if risk >= 70:
        explanation.append("Overall risk score exceeds safe threshold")
        explanation.append(f"Primary threat signal: {primary_signal}")

        return {
            "decision": "BLOCK",
            "enforced_action": "terminate_session",
            "reason": "High-risk malicious environment detected",
            "explanation": explanation
        }

    if (
        action["type"] == "submit_form"
        and primary_signal == "credential_harvesting"
    ):
        explanation.append("Agent intended to submit credentials")
        explanation.append("Site identified as credential harvesting threat")

        return {
            "decision": "BLOCK",
            "enforced_action": "disable_form_submission",
            "reason": "Credential submission blocked on phishing site",
            "explanation": explanation
        }

    # -----------------------------
    # WARN CONDITIONS
    # -----------------------------
    if risk >= 40:
        explanation.append("Suspicious indicators detected")
        explanation.append("Agent allowed to proceed with caution")

        return {
            "decision": "WARN",
            "enforced_action": "read_only_mode",
            "reason": "Suspicious activity detected",
            "explanation": explanation
        }

    # -----------------------------
    # ALLOW
    # -----------------------------
    explanation.append("No significant malicious indicators detected")

    return {
        "decision": "ALLOW",
        "enforced_action": enforced_action,
        "reason": "Environment assessed as safe",
        "explanation": explanation
    }
