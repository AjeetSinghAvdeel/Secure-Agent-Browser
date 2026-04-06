from __future__ import annotations

import math
import time
from typing import Any, Dict, List

try:
    import llm_reasoner
    import ml_model
    import obfuscation
    import risk
    import ui_deception
except Exception:  # pragma: no cover - package import fallback
    from . import llm_reasoner, ml_model, obfuscation, risk, ui_deception  # type: ignore


def _build_large_html(target_kb: int, malicious: bool) -> str:
    chunk = (
        "verify your account now and continue secure login password otp token "
        if malicious
        else "documentation guide security overview privacy policy platform dashboard "
    )
    repeated = (chunk * max(1, (target_kb * 1024) // max(len(chunk), 1)))[: target_kb * 1024]
    overlay = (
        '<div style="position:fixed;inset:0;opacity:0;z-index:9999;pointer-events:auto"></div>'
        if malicious
        else ""
    )
    paragraph = "<p>" + repeated[:1200] + "</p>"
    paragraphs = paragraph * max(1, math.ceil((target_kb * 1024) / 1200))
    return (
        "<html><body><main><h1>Stress Fixture</h1>"
        f"{overlay}<section data-size-kb=\"{target_kb}\">{paragraphs}</section></main></body></html>"
    )


def _percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.ceil((percentile / 100.0) * len(ordered))) - 1))
    return ordered[index]


def run_stress_suite() -> Dict[str, Any]:
    cases = [
        {"size_kb": 64, "malicious": False},
        {"size_kb": 64, "malicious": True},
        {"size_kb": 256, "malicious": False},
        {"size_kb": 256, "malicious": True},
        {"size_kb": 512, "malicious": False},
        {"size_kb": 512, "malicious": True},
        {"size_kb": 1024, "malicious": False},
        {"size_kb": 1024, "malicious": True},
    ]
    results: List[Dict[str, Any]] = []

    for case in cases:
        html = _build_large_html(case["size_kb"], case["malicious"])
        started = time.perf_counter()
        ml_score = float(ml_model.predict_attack_score(html))
        after_ml = time.perf_counter()
        llm = llm_reasoner.detect_malicious_intent(html)
        after_llm = time.perf_counter()
        obf = obfuscation.analyze_obfuscation(html)
        after_obf = time.perf_counter()
        ui = ui_deception.analyze_ui_deception(html, {})
        after_ui = time.perf_counter()
        risk_data = risk.calculate_weighted_risk(
            ml_score=max(ml_score, float(llm.get("score", 0.0))),
            dom_suspicion_score=0.65 if case["malicious"] else 0.1,
            ui_risk_score=float(ui.get("ui_risk_score", 0.0)),
            obfuscation_score=float(obf.get("obfuscation_score", 0.0)),
            threat_intel_score=float(llm.get("score", 0.0)),
            domain_trust=20.0 if case["malicious"] else 95.0,
            signals=[],
        )
        total_ms = round((time.perf_counter() - started) * 1000.0, 3)
        results.append(
            {
                "size_kb": case["size_kb"],
                "malicious": case["malicious"],
                "dom_nodes_estimate": max(1, html.count("<p>")) + 5,
                "risk_percent": int(risk_data["risk_percent"]),
                "severity": risk_data["severity"],
                "latency_ms": total_ms,
                "ml_latency_ms": round((after_ml - started) * 1000.0, 3),
                "llm_latency_ms": round((after_llm - after_ml) * 1000.0, 3),
                "obfuscation_latency_ms": round((after_obf - after_llm) * 1000.0, 3),
                "ui_latency_ms": round((after_ui - after_obf) * 1000.0, 3),
                "llm_score": float(llm.get("score", 0.0)),
                "ml_score": ml_score,
            }
        )

    latencies = [item["latency_ms"] for item in results]
    return {
        "cases": results,
        "summary": {
            "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "p95_latency_ms": round(_percentile(latencies, 95), 3) if latencies else 0.0,
            "largest_case_kb": max(item["size_kb"] for item in results) if results else 0,
            "case_count": len(results),
        },
    }
