"""
Explainability Engine for Risk Classification

This module generates human-readable explanations for why a webpage 
was classified as risky based on multiple detection signals.
"""

from typing import Any, Dict, List, Optional


def generate_explanation(
    ml_score: float,
    domain_flags: Dict[str, Any],
    obfuscation_flags: Dict[str, Any],
    risk_data: Dict[str, Any],
    policy_decision: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a human-readable explanation for risk classification.
    
    Args:
        ml_score: ML model confidence score (0.0 to 1.0) where 1.0 is highest risk
        domain_flags: Dictionary with domain intelligence indicators
                     e.g., {"suspicious_tld": True, "brand_spoofing": False, ...}
        obfuscation_flags: Dictionary with obfuscation detection results
                          e.g., {"hidden_dom": True, "obfuscated_js": False, ...}
        risk_data: Dictionary from risk engine with risk assessment details
                  e.g., {"threat_type": "prompt_injection", "indicators": [...], ...}
        policy_decision: Dictionary from policy engine with policy check results
                        e.g., {"policy_violated": True, "violated_policy": "injection", ...}
    
    Returns:
        Dictionary with:
            - summary: Brief human-readable explanation
            - reasons: List of specific risk factors found
            - risk_level: Classification level (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
            - recommended_action: What should be done with the page
    """
    
    reasons: List[str] = []
    risk_score = 0.0
    
    # Analyze ML score
    if ml_score >= 0.8:
        reasons.append("ML model detected high-confidence malicious patterns")
        risk_score += 0.3
    elif ml_score >= 0.5:
        reasons.append("ML model detected suspicious behavior indicators")
        risk_score += 0.2
    elif ml_score >= 0.3:
        reasons.append("ML model flagged potential security concerns")
        risk_score += 0.1
    
    # Analyze domain flags
    domain_flags = domain_flags or {}
    if domain_flags.get("suspicious_tld"):
        reasons.append("Domain uses suspicious or non-standard top-level domain")
        risk_score += 0.2
    
    if domain_flags.get("brand_spoofing"):
        reasons.append("Domain appears to spoof legitimate brand")
        risk_score += 0.25
    
    if domain_flags.get("newly_registered"):
        reasons.append("Domain was recently registered (potential phishing)")
        risk_score += 0.15
    
    if domain_flags.get("blacklisted"):
        reasons.append("Domain is on security blacklist")
        risk_score += 0.25
    
    if domain_flags.get("no_ssl"):
        reasons.append("Website lacks SSL/TLS encryption")
        risk_score += 0.15
    
    if domain_flags.get("dga_domain"):
        reasons.append("Domain matches Domain Generation Algorithm (DGA) patterns")
        risk_score += 0.2
    
    # Analyze obfuscation flags
    obfuscation_flags = obfuscation_flags or {}
    if obfuscation_flags.get("hidden_dom"):
        reasons.append("Hidden DOM elements detected (often used for malicious purposes)")
        risk_score += 0.2
    
    if obfuscation_flags.get("obfuscated_js"):
        reasons.append("JavaScript code is heavily obfuscated, masking intent")
        risk_score += 0.15
    
    if obfuscation_flags.get("base64_encoded"):
        reasons.append("Suspicious Base64-encoded content detected")
        risk_score += 0.1
    
    if obfuscation_flags.get("evasion_techniques"):
        reasons.append("Detection evasion techniques detected")
        risk_score += 0.2
    
    if obfuscation_flags.get("unicode_tricks"):
        reasons.append("Unicode homograph tricks detected (could be phishing)")
        risk_score += 0.15
    
    # Analyze risk engine output
    risk_data = risk_data or {}
    threat_type = risk_data.get("threat_type", "unknown").lower() if risk_data.get("threat_type") else "unknown"
    
    if threat_type == "prompt_injection":
        reasons.append("Prompt injection attack patterns identified")
        risk_score += 0.25
    elif threat_type == "xss":
        reasons.append("Cross-Site Scripting (XSS) vulnerability indicators detected")
        risk_score += 0.2
    elif threat_type == "phishing":
        reasons.append("Phishing attack indicators present")
        risk_score += 0.2
    elif threat_type == "malware":
        reasons.append("Malware distribution indicators detected")
        risk_score += 0.25
    elif threat_type == "credential_theft":
        reasons.append("Credential theft mechanisms detected")
        risk_score += 0.2
    elif threat_type == "exploit":
        reasons.append("Known exploit patterns detected")
        risk_score += 0.25
    
    # Analyze policy engine decision
    policy_decision = policy_decision or {}
    if policy_decision.get("policy_violated"):
        violated_policy = policy_decision.get("violated_policy", "unknown policy")
        reasons.append(f"Violates security policy: {violated_policy}")
        risk_score += 0.2
    
    if policy_decision.get("restricted_content"):
        reasons.append("Page contains restricted or prohibited content")
        risk_score += 0.15
    
    # Calculate final risk level (normalize score to ensure it's between 0 and 1)
    final_risk_score = min(risk_score, 1.0)
    
    if final_risk_score >= 0.85:
        risk_level = "CRITICAL"
    elif final_risk_score >= 0.65:
        risk_level = "HIGH"
    elif final_risk_score >= 0.40:
        risk_level = "MEDIUM"
    elif final_risk_score >= 0.15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    # Generate summary
    if not reasons:
        summary = "Website appears safe with no significant risk indicators detected."
        risk_level = "SAFE"
    elif risk_level == "CRITICAL":
        primary_reason = reasons[0]
        summary = f"Critical risk webpage identified. {primary_reason}"
    elif risk_level == "HIGH":
        primary_reason = reasons[0]
        summary = f"High-risk webpage detected. {primary_reason}"
    elif risk_level == "MEDIUM":
        primary_reason = reasons[0]
        summary = f"Potential security concerns found. {primary_reason}"
    elif risk_level == "LOW":
        primary_reason = reasons[0]
        summary = f"Minor security concerns detected. {primary_reason}"
    else:
        summary = "Website appears to be safe."
    
    # Generate recommended action based on risk level
    if risk_level == "CRITICAL":
        recommended_action = "Block page and alert user immediately"
    elif risk_level == "HIGH":
        recommended_action = "Block page or show strong warning to user"
    elif risk_level == "MEDIUM":
        recommended_action = "Show warning and require user confirmation"
    elif risk_level == "LOW":
        recommended_action = "Show informational alert to user"
    else:
        recommended_action = "Allow page to load normally"
    
    return {
        "summary": summary,
        "reasons": reasons,
        "risk_level": risk_level,
        "recommended_action": recommended_action
    }


# Test block for standalone execution
if __name__ == "__main__":
    # Test case 1: Critical risk - prompt injection
    print("=" * 80)
    print("TEST 1: Critical Risk - Prompt Injection Attack")
    print("=" * 80)
    
    result = generate_explanation(
        ml_score=0.95,
        domain_flags={
            "suspicious_tld": True,
            "newly_registered": True,
            "blacklisted": False
        },
        obfuscation_flags={
            "hidden_dom": True,
            "obfuscated_js": True,
            "evasion_techniques": True
        },
        risk_data={
            "threat_type": "prompt_injection",
            "indicators": ["suspicious_input", "filter_bypass"]
        },
        policy_decision={
            "policy_violated": True,
            "violated_policy": "input_validation"
        }
    )
    
    print(f"Summary: {result['summary']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons:")
    for i, reason in enumerate(result['reasons'], 1):
        print(f"  {i}. {reason}")
    print(f"Recommended Action: {result['recommended_action']}")
    print()
    
    # Test case 2: Medium risk - suspicious domain
    print("=" * 80)
    print("TEST 2: Medium Risk - Suspicious Domain")
    print("=" * 80)
    
    result = generate_explanation(
        ml_score=0.45,
        domain_flags={
            "brand_spoofing": True,
            "newly_registered": False,
            "blacklisted": False
        },
        obfuscation_flags={
            "hidden_dom": False,
            "obfuscated_js": False
        },
        risk_data={
            "threat_type": "phishing"
        },
        policy_decision={
            "policy_violated": False
        }
    )
    
    print(f"Summary: {result['summary']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons:")
    for i, reason in enumerate(result['reasons'], 1):
        print(f"  {i}. {reason}")
    print(f"Recommended Action: {result['recommended_action']}")
    print()
    
    # Test case 3: Low risk
    print("=" * 80)
    print("TEST 3: Low Risk - Minor Concerns")
    print("=" * 80)
    
    result = generate_explanation(
        ml_score=0.25,
        domain_flags={
            "no_ssl": True,
            "suspicious_tld": False
        },
        obfuscation_flags={
            "base64_encoded": True
        },
        risk_data={
            "threat_type": None
        },
        policy_decision={
            "policy_violated": False
        }
    )
    
    print(f"Summary: {result['summary']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons:")
    for i, reason in enumerate(result['reasons'], 1):
        print(f"  {i}. {reason}")
    print(f"Recommended Action: {result['recommended_action']}")
    print()
    
    # Test case 4: Safe website
    print("=" * 80)
    print("TEST 4: Safe Website - No Risk Indicators")
    print("=" * 80)
    
    result = generate_explanation(
        ml_score=0.05,
        domain_flags={},
        obfuscation_flags={},
        risk_data={},
        policy_decision={
            "policy_violated": False
        }
    )
    
    print(f"Summary: {result['summary']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons:")
    if result['reasons']:
        for i, reason in enumerate(result['reasons'], 1):
            print(f"  {i}. {reason}")
    else:
        print("  No risk indicators found")
    print(f"Recommended Action: {result['recommended_action']}")
    print()
    
    # Test case 5: High risk - malware
    print("=" * 80)
    print("TEST 5: High Risk - Malware Distribution")
    print("=" * 80)
    
    result = generate_explanation(
        ml_score=0.75,
        domain_flags={
            "blacklisted": True,
            "dga_domain": True
        },
        obfuscation_flags={
            "evasion_techniques": True
        },
        risk_data={
            "threat_type": "malware"
        },
        policy_decision={
            "policy_violated": True,
            "violated_policy": "malware_distribution"
        }
    )
    
    print(f"Summary: {result['summary']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Reasons:")
    for i, reason in enumerate(result['reasons'], 1):
        print(f"  {i}. {reason}")
    print(f"Recommended Action: {result['recommended_action']}")
