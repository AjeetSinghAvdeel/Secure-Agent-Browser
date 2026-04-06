from __future__ import annotations

from typing import Any, Dict, List


def _to_points(value: float, weight: float) -> int:
    return max(0, int(round(float(value) * float(weight) * 100)))


def generate_explanation(
    ml_score: float,
    domain_flags: Dict[str, Any],
    obfuscation_flags: Dict[str, Any],
    risk_data: Dict[str, Any],
    policy_decision: Dict[str, Any],
    *,
    ui_score: float = 0.0,
) -> Dict[str, Any]:
    breakdown_raw = risk_data.get("breakdown", {}) or {}
    ml_points = _to_points(ml_score, 0.35)
    domain_points = _to_points(breakdown_raw.get("dom_suspicion_score", 0.0), 0.25)
    ui_points = _to_points(ui_score, 0.15)
    obfuscation_points = _to_points(breakdown_raw.get("obfuscation_score", 0.0), 0.15)
    total_score = int(risk_data.get("risk_percent", ml_points + domain_points + ui_points + obfuscation_points))

    reasons: List[str] = []
    reasoning_steps: List[str] = []

    if ml_score >= 0.75:
        reasons.append("ML model detected high-confidence malicious content patterns.")
    elif ml_score >= 0.4:
        reasons.append("ML model detected suspicious language or page structure.")

    domain_flags = domain_flags or {}
    if any(domain_flags.values()):
        reasons.append("Domain intelligence contributed risk through reputation or URL anomalies.")

    obfuscation_flags = obfuscation_flags or {}
    if any(obfuscation_flags.values()):
        reasons.append("Obfuscation analysis found hidden or encoded content patterns.")

    if ui_score >= 0.2:
        reasons.append("UI deception analysis found misleading or hidden interaction elements.")

    for label, points, detail in (
        ("ML", ml_points, "content and language classification"),
        ("Domain", domain_points, "domain reputation and URL heuristics"),
        ("UI", ui_points, "deceptive interface and clickjacking heuristics"),
        ("Obfuscation", obfuscation_points, "hidden elements and encoded payloads"),
    ):
        reasoning_steps.append(f"{label} contributed {points} points from {detail}.")

    policy_name = str(policy_decision.get("violated_policy") or "risk_threshold")
    recommended_action = "Allow page to load normally"
    if policy_decision.get("policy_violated"):
        reasons.append(f"Policy evaluation escalated the decision under {policy_name}.")

    final_decision = str(policy_decision.get("decision") or "ALLOW").upper()
    if final_decision == "BLOCK":
        recommended_action = "Block the page or action immediately."
    elif final_decision == "REQUIRE_CONFIRMATION":
        recommended_action = "Require explicit user confirmation before the action executes."
    elif final_decision == "WARN":
        recommended_action = "Warn the user and continue only with caution."

    if total_score >= 85:
        risk_level = "CRITICAL"
    elif total_score >= 65:
        risk_level = "HIGH"
    elif total_score >= 40:
        risk_level = "MEDIUM"
    elif total_score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    confidence_score = max(
        0.0,
        min(
            1.0,
            round(
                (
                    float(ml_score)
                    + float(ui_score)
                    + float(breakdown_raw.get("obfuscation_score", 0.0))
                    + float(total_score) / 100.0
                )
                / 4.0,
                4,
            ),
        ),
    )

    human_explanation = (
        f"SecureAgent assigned a total score of {total_score} because the page combined "
        f"{ml_points} ML points, {domain_points} domain points, {ui_points} UI deception points, "
        f"and {obfuscation_points} obfuscation points."
    )

    summary = reasons[0] if reasons else "Website appears safe with no significant risk indicators detected."

    return {
        "summary": summary,
        "human_explanation": human_explanation,
        "reasons": reasons,
        "reasoning_steps": reasoning_steps,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "confidence_score": confidence_score,
        "total_score": total_score,
        "breakdown": {
            "ml": ml_points,
            "domain": domain_points,
            "ui": ui_points,
            "obfuscation": obfuscation_points,
        },
        "ui_design_suggestions": [
            "Use a horizontal bar chart for ML, domain, UI, and obfuscation contributions.",
            "Render an explanation panel with ordered reasoning steps and confidence score.",
        ],
    }
