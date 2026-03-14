"""Risk scoring utilities for Secure Agent Browser."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

WEIGHTS = {
    "ml_score": 0.40,
    "dom_suspicion_score": 0.30,
    "obfuscation_score": 0.20,
    "threat_intel_score": 0.10,
}

TRUST_MULTIPLIERS = (
    (90, 0.4),
    (75, 0.6),
    (50, 0.8),
)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _clamp100(value: float) -> int:
    return max(0, min(100, int(round(float(value)))))


def _severity_from_risk_percent(risk_percent: int) -> str:
    if risk_percent < 25:
        return "LOW"
    if risk_percent < 50:
        return "MEDIUM"
    if risk_percent < 75:
        return "HIGH"
    return "CRITICAL"


def _confidence_weight(level: str) -> float:
    mapping = {
        "low": 0.2,
        "medium": 0.5,
        "high": 0.85,
        "critical": 1.0,
    }
    return mapping.get(str(level or "").strip().lower(), 0.3)


def _signal_synergy_bonus(signals: List[Dict[str, Any]]) -> int:
    names = {str(signal.get("type", "")).lower() for signal in signals}
    bonus = 0

    if "prompt_injection" in names and "hidden_dom_element" in names:
        bonus += 40
    if "base64_blob" in names and "hex_payload" in names:
        bonus += 20
    if "base64_blob" in names and len(names) == 1:
        bonus += 5

    return bonus


def _signal_pressure(signals: List[Dict[str, Any]]) -> int:
    total = 0
    for signal in signals:
        signal_type = str(signal.get("type", "")).lower()
        confidence = _confidence_weight(str(signal.get("confidence", "medium")))

        if signal_type == "prompt_injection":
            base = 35
        elif signal_type in {"credential_request", "phishing_intent"}:
            base = 24
        elif signal_type in {"hidden_dom_element", "hex_payload"}:
            base = 12
        elif signal_type == "base64_blob":
            base = 5
        else:
            base = 8

        total += int(round(base * confidence))

    total += _signal_synergy_bonus(signals)
    return min(total, 100)


def _apply_domain_trust_modifier(risk_percent: int, domain_trust: float) -> int:
    trust = float(domain_trust)
    adjusted = float(risk_percent)

    for threshold, multiplier in TRUST_MULTIPLIERS:
        if trust >= threshold:
            adjusted *= multiplier
            break

    return _clamp100(adjusted)


def calculate_weighted_risk(
    ml_score: float,
    dom_suspicion_score: float,
    obfuscation_score: float,
    threat_intel_score: float,
    *,
    domain_trust: float = 50.0,
    signals: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Compute weighted multi-factor risk score with domain trust modifier
    and signal-confidence/synergy bonuses.
    """
    ml_score = _clamp01(ml_score)
    dom_suspicion_score = _clamp01(dom_suspicion_score)
    obfuscation_score = _clamp01(obfuscation_score)
    threat_intel_score = _clamp01(threat_intel_score)
    signal_details = list(signals or [])

    weighted = (
        WEIGHTS["ml_score"] * ml_score
        + WEIGHTS["dom_suspicion_score"] * dom_suspicion_score
        + WEIGHTS["obfuscation_score"] * obfuscation_score
        + WEIGHTS["threat_intel_score"] * threat_intel_score
    )
    weighted_percent = _clamp100(weighted * 100)
    signal_bonus = _signal_pressure(signal_details)
    combined_percent = _clamp100(weighted_percent + signal_bonus)
    adjusted_percent = _apply_domain_trust_modifier(combined_percent, domain_trust)
    total_risk = round(adjusted_percent / 100.0, 4)

    return {
        "total_risk": total_risk,
        "risk_percent": adjusted_percent,
        "severity": _severity_from_risk_percent(adjusted_percent),
        "confidence": adjusted_percent,
        "breakdown": {
            "ml_score": round(ml_score, 4),
            "dom_suspicion_score": round(dom_suspicion_score, 4),
            "obfuscation_score": round(obfuscation_score, 4),
            "threat_intel_score": round(threat_intel_score, 4),
            "weighted_percent": weighted_percent,
            "signal_bonus": signal_bonus,
            "domain_trust": round(float(domain_trust), 2),
        },
    }


def _legacy_to_weighted_inputs(
    injection: Any,
    hidden: Any,
    phishing: Any,
    ml_result: Any,
    llm_result: Any,
    behavior_risk: float = 0,
) -> Tuple[float, float, float, float, List[Dict[str, Any]], List[str]]:
    reasons: List[str] = []
    signals: List[Dict[str, Any]] = []

    ml_score = 1.0 if bool(ml_result) else 0.0
    dom_suspicion_score = 0.7 if bool(phishing) else 0.0
    obfuscation_score = 0.0
    threat_intel_score = 1.0 if bool(llm_result) else 0.0

    injection_count = len(injection) if isinstance(injection, list) else 0
    hidden_count = len(hidden) if isinstance(hidden, list) else 0

    if injection_count:
        signals.append({"type": "prompt_injection", "confidence": "high"})
        reasons.append("Prompt-injection indicators detected")
    if hidden_count:
        signals.append({"type": "hidden_dom_element", "confidence": "medium"})
        obfuscation_score = 0.4
        reasons.append("Hidden/obfuscated UI elements detected")
    if phishing:
        signals.append({"type": "phishing_intent", "confidence": "high"})
        reasons.append("Credential/phishing surface detected")

    if behavior_risk > 0:
        obfuscation_score = max(obfuscation_score, _clamp01(behavior_risk / 100.0))
        reasons.append("Runtime behavior elevated risk")

    return (
        ml_score,
        dom_suspicion_score,
        obfuscation_score,
        threat_intel_score,
        signals,
        reasons,
    )


def calculate_risk(*args: Any, **kwargs: Any) -> Any:
    """
    Primary risk API.

    New usage:
        calculate_risk(ml_score, dom_suspicion_score, obfuscation_score, threat_intel_score, ...)
        -> dict

    Legacy compatibility usage:
        calculate_risk(injection, hidden, phishing, ml_result, llm_result, ...)
        -> (risk_percent, reasons, confidence, decision)
    """
    legacy_kwarg_present = "behavior_risk" in kwargs or "behavior_findings" in kwargs
    if len(args) == 4 and all(isinstance(v, (int, float)) for v in args):
        return calculate_weighted_risk(
            ml_score=float(args[0]),
            dom_suspicion_score=float(args[1]),
            obfuscation_score=float(args[2]),
            threat_intel_score=float(args[3]),
            domain_trust=float(kwargs.get("domain_trust", 50.0)),
            signals=list(kwargs.get("signals", []) or []),
        )

    if len(args) < 5:
        raise TypeError(
            "calculate_risk expects either 4 numeric scores (new API) "
            "or legacy signature with at least 5 positional args."
        )

    injection, hidden, phishing, ml_result, llm_result = args[:5]
    behavior_risk = float(kwargs.get("behavior_risk", 0) or 0)
    behavior_findings = list(kwargs.get("behavior_findings", []) or [])

    (
        ml_score,
        dom_suspicion_score,
        obfuscation_score,
        threat_intel_score,
        signals,
        reasons,
    ) = _legacy_to_weighted_inputs(
        injection=injection,
        hidden=hidden,
        phishing=phishing,
        ml_result=ml_result,
        llm_result=llm_result,
        behavior_risk=behavior_risk,
    )

    weighted = calculate_weighted_risk(
        ml_score=ml_score,
        dom_suspicion_score=dom_suspicion_score,
        obfuscation_score=obfuscation_score,
        threat_intel_score=threat_intel_score,
        domain_trust=float(kwargs.get("domain_trust", 50.0)),
        signals=signals,
    )

    risk_percent = int(weighted["risk_percent"])
    if risk_percent >= 70:
        confidence = "high"
    elif risk_percent >= 40:
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
