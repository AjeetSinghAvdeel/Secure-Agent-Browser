"""Policy-as-code engine for risk response decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULT_POLICY_MODE = "balanced"
POLICY_DIR = Path(__file__).resolve().parent / "policies"
ALLOWED_DECISIONS = ("ALLOW", "WARN", "BLOCK")


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_risk(risk_score: float) -> float:
    """
    Normalize risk score into [0, 1].
    Supports both normalized (0-1) and percent-like (0-100) inputs.
    """
    risk = float(risk_score)
    if risk > 1.0:
        risk = risk / 100.0
    return _clamp01(risk)


def load_policy(policy_mode: str = DEFAULT_POLICY_MODE) -> Dict[str, float]:
    """
    Load policy thresholds from YAML for the selected mode.
    """
    mode = (policy_mode or DEFAULT_POLICY_MODE).strip().lower()
    policy_path = POLICY_DIR / f"{mode}.yaml"

    if not policy_path.exists():
        raise ValueError(
            f"Unknown policy mode '{policy_mode}'. "
            f"Expected one of: strict, balanced, research."
        )

    with policy_path.open("r", encoding="utf-8") as f:
        policy = yaml.safe_load(f) or {}

    if "block_if_risk_above" not in policy or "warn_if_risk_above" not in policy:
        raise ValueError(f"Policy file '{policy_path.name}' is missing required keys.")

    block_threshold = _clamp01(policy["block_if_risk_above"])
    warn_threshold = _clamp01(policy["warn_if_risk_above"])

    if warn_threshold >= block_threshold:
        raise ValueError(
            f"Invalid policy '{policy_path.name}': warn_if_risk_above must be lower "
            "than block_if_risk_above."
        )

    return {
        "block_if_risk_above": block_threshold,
        "warn_if_risk_above": warn_threshold,
    }


def evaluate_risk_policy(
    risk_score: float,
    policy_mode: str = DEFAULT_POLICY_MODE,
) -> Dict[str, str]:
    """
    Evaluate risk score against a selected policy.

    Returns:
        {
          "decision": "ALLOW | WARN | BLOCK",
          "policy_mode": "...",
          "reason": "..."
        }
    """
    risk = _normalize_risk(risk_score)
    mode = (policy_mode or DEFAULT_POLICY_MODE).strip().lower()
    risk_percent = int(round(risk * 100))
    warn_threshold = 40
    block_threshold = 70

    if risk_percent >= block_threshold:
        decision = "BLOCK"
        reason = (
            f"Risk score {risk_percent} exceeds block threshold {block_threshold} "
            f"for '{mode}' policy."
        )
    elif risk_percent >= warn_threshold:
        decision = "WARN"
        reason = (
            f"Risk score {risk_percent} exceeds warn threshold {warn_threshold} "
            f"for '{mode}' policy."
        )
    else:
        decision = "ALLOW"
        reason = (
            f"Risk score {risk_percent} is below warn threshold {warn_threshold} "
            f"for '{mode}' policy."
        )

    return {
        "decision": decision,
        "policy_mode": mode,
        "reason": reason,
    }


def evaluate_action(
    action: Dict[str, Any],
    scan_result: Dict[str, Any],
    policy_mode: str = DEFAULT_POLICY_MODE,
) -> Dict[str, str]:
    """
    Backward-compatible wrapper used by API flow.
    Reads risk from scan result and applies selected policy mode.
    """
    _ = action  # Action-specific controls can be layered here later.
    risk_score = scan_result.get("risk", 0)
    return evaluate_risk_policy(risk_score=risk_score, policy_mode=policy_mode)


if __name__ == "__main__":
    test_cases = [
        ("strict", 0.2),
        ("strict", 0.4),
        ("strict", 0.8),
        ("balanced", 0.55),
        ("research", 0.85),
        ("research", 0.95),
    ]

    for mode, risk in test_cases:
        result = evaluate_risk_policy(risk_score=risk, policy_mode=mode)
        print(f"mode={mode}, risk={risk:.2f} -> {result}")
