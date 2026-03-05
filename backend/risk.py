"""Risk scoring utilities for Secure Agent Browser."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

WEIGHTS = {
    "ml_score": 0.40,
    "semantic_score": 0.25,
    "domain_penalty": 0.20,
    "obfuscation_score": 0.15,
}


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _severity_from_risk(risk: float) -> str:
    if risk < 0.25:
        return "LOW"
    if risk < 0.50:
        return "MEDIUM"
    if risk < 0.75:
        return "HIGH"
    return "CRITICAL"


def calculate_weighted_risk(
    ml_score: float,
    semantic_score: float,
    domain_penalty: float,
    obfuscation_score: float,
) -> Dict[str, Any]:
    """
    Compute weighted multi-factor risk score.

    Inputs are expected in range [0, 1].
    """
    ml_score = _clamp01(ml_score)
    semantic_score = _clamp01(semantic_score)
    domain_penalty = _clamp01(domain_penalty)
    obfuscation_score = _clamp01(obfuscation_score)

    total_risk = (
        WEIGHTS["ml_score"] * ml_score
        + WEIGHTS["semantic_score"] * semantic_score
        + WEIGHTS["domain_penalty"] * domain_penalty
        + WEIGHTS["obfuscation_score"] * obfuscation_score
    )
    total_risk = _clamp01(total_risk)

    return {
        "total_risk": round(total_risk, 4),
        "severity": _severity_from_risk(total_risk),
        "confidence": round(total_risk * 100, 2),
        "breakdown": {
            "ml_score": round(ml_score, 4),
            "semantic_score": round(semantic_score, 4),
            "domain_penalty": round(domain_penalty, 4),
            "obfuscation_score": round(obfuscation_score, 4),
        },
    }


def _legacy_to_weighted_inputs(
    injection: Any,
    hidden: Any,
    phishing: Any,
    ml_result: Any,
    llm_result: Any,
    behavior_risk: float = 0,
) -> Tuple[float, float, float, float, List[str]]:
    reasons: List[str] = []

    ml_score = 1.0 if bool(ml_result) else 0.0
    semantic_score = 1.0 if bool(llm_result) else 0.0

    domain_penalty = 0.6 if bool(phishing) else 0.0
    obfuscation_score = 0.0

    injection_count = len(injection) if isinstance(injection, list) else 0
    hidden_count = len(hidden) if isinstance(hidden, list) else 0

    if injection_count:
        obfuscation_score += min(0.6, injection_count * 0.2)
        reasons.append("Prompt-injection indicators detected")
    if hidden_count:
        obfuscation_score += min(0.4, hidden_count * 0.1)
        reasons.append("Hidden/obfuscated UI elements detected")
    if phishing:
        reasons.append("Credential/phishing surface detected")

    if behavior_risk > 0:
        obfuscation_score += min(0.5, behavior_risk / 100.0)
        reasons.append("Runtime behavior elevated risk")

    obfuscation_score = _clamp01(obfuscation_score)

    return ml_score, semantic_score, domain_penalty, obfuscation_score, reasons


def calculate_risk(*args: Any, **kwargs: Any) -> Any:
    """
    Primary risk API.

    New usage:
        calculate_risk(ml_score, semantic_score, domain_penalty, obfuscation_score)
        -> dict (weighted risk structure)

    Legacy compatibility usage:
        calculate_risk(injection, hidden, phishing, ml_result, llm_result, ...)
        -> (risk_percent, reasons, confidence, decision)
    """
    # New-style API: exactly 4 numeric inputs and no legacy kwargs.
    legacy_kwarg_present = "behavior_risk" in kwargs or "behavior_findings" in kwargs
    if len(args) == 4 and not legacy_kwarg_present and all(
        isinstance(v, (int, float)) for v in args
    ):
        return calculate_weighted_risk(
            ml_score=float(args[0]),
            semantic_score=float(args[1]),
            domain_penalty=float(args[2]),
            obfuscation_score=float(args[3]),
        )

    # Legacy API fallback for existing scanner integration.
    if len(args) < 5:
        raise TypeError(
            "calculate_risk expects either 4 numeric scores (new API) "
            "or legacy signature with at least 5 positional args."
        )

    injection, hidden, phishing, ml_result, llm_result = args[:5]
    behavior_risk = float(kwargs.get("behavior_risk", 0) or 0)
    behavior_findings = list(kwargs.get("behavior_findings", []) or [])

    ml_score, semantic_score, domain_penalty, obfuscation_score, reasons = _legacy_to_weighted_inputs(
        injection=injection,
        hidden=hidden,
        phishing=phishing,
        ml_result=ml_result,
        llm_result=llm_result,
        behavior_risk=behavior_risk,
    )
    weighted = calculate_weighted_risk(
        ml_score=ml_score,
        semantic_score=semantic_score,
        domain_penalty=domain_penalty,
        obfuscation_score=obfuscation_score,
    )

    risk_percent = int(round(weighted["total_risk"] * 100))

    if weighted["confidence"] >= 75:
        confidence = "high"
    elif weighted["confidence"] >= 40:
        confidence = "medium"
    else:
        confidence = "low"

    reasons.extend(behavior_findings)

    decision = {
        "primary_signal": weighted["severity"].lower(),
        "signal_breakdown": weighted["breakdown"],
        "attack_chain": reasons,
        "weighted": weighted,
    }

    return risk_percent, reasons, confidence, decision


if __name__ == "__main__":
    print("New API examples")
    print(calculate_risk(0.9, 0.8, 0.7, 0.6))
    print(calculate_risk(0.1, 0.2, 0.0, 0.1))
    print("-" * 60)
    print("Legacy API compatibility example")
    print(
        calculate_risk(
            ["ignore previous instructions"],
            ["display:none form"],
            True,
            1,
            1,
            behavior_risk=25,
            behavior_findings=["Suspicious cross-origin POST observed"],
        )
    )
