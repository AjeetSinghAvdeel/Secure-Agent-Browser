def infer_agent_action(scan_result):
    """
    Infer what an autonomous agent would attempt to do
    based on derived environment context (NOT raw signals)
    """

    context = scan_result.get("agent_context", {})

    credential_surface = context.get("credential_surface", False)
    language_manipulation = context.get("language_manipulation", False)
    runtime_manipulation = context.get("runtime_manipulation", False)
    data_exfiltration = context.get("data_exfiltration", False)

    # ------------------------------------------------
    # High-risk environment → agent attempts sensitive action
    # ------------------------------------------------
    if credential_surface:
        return {
            "type": "submit_form",
            "fields": ["username", "password"],
            "confidence": "high",
            "reason": "Credential input surface detected"
        }

    # ------------------------------------------------
    # Manipulated environment → agent restricts behavior
    # ------------------------------------------------
    if language_manipulation or runtime_manipulation:
        return {
            "type": "read_only",
            "confidence": "medium",
            "reason": "Page manipulation detected"
        }

    # ------------------------------------------------
    # Network exfiltration → agent aborts interaction
    # ------------------------------------------------
    if data_exfiltration:
        return {
            "type": "abort",
            "confidence": "high",
            "reason": "Active data exfiltration detected"
        }

    # ------------------------------------------------
    # Benign environment
    # ------------------------------------------------
    return {
        "type": "browse",
        "confidence": "low",
        "reason": "No malicious indicators detected"
    }
