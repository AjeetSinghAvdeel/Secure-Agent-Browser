# SecureAgent: AI-Powered Intelligent Web Threat Detection

SecureAgent is an end-to-end defensive system for detecting malicious webpages, mediating AI-agent browser actions, and auditing every security decision with explainable reasoning.

It combines:
- FastAPI backend threat analysis and policy enforcement
- Chrome extension for page scanning and action interception
- React dashboard with real-time scan and action audit visibility
- Safe malicious simulation lab for local attack testing

---

## What SecureAgent Does

SecureAgent now protects both:
- Browsing decisions: should the page be allowed, warned, or blocked?
- Agent decisions: should an AI/browser agent be allowed to click, type, or submit?

Core flow:

```text
Browser / AI Agent
   ↓
SecureAgent Extension
   ↓
Backend Threat Pipeline
   ↓
Risk Engine + Policy Engine
   ↓
Action Mediation Layer
   ↓
ALLOW / WARN / BLOCK
   ↓
Dashboard + Audit Trail
```

---

## Latest Implemented Features

### 1. Action Mediation

The extension intercepts:
- button clicks
- text entry
- form submissions

Each action is sent to `POST /evaluate_action` before execution. SecureAgent can:
- allow the action
- warn the user / operator
- block the action completely

This makes the system realistic for AI-agent browsing scenarios, not just passive URL scanning.

### 2. Trusted Domain False Positive Reduction

Risk scoring now uses:

```text
risk_score =
    ml_score * 0.4 +
    dom_suspicion_score * 0.3 +
    obfuscation_score * 0.2 +
    threat_intel_score * 0.1
```

Then a domain-trust modifier is applied:
- `domain_trust >= 90` → risk × `0.4`
- `domain_trust >= 75` → risk × `0.6`
- `domain_trust >= 50` → risk × `0.8`

This reduces false positives on legitimate sites such as `github.com`, where normal frontend code may contain:
- Base64 blobs
- hidden DOM nodes
- encoded assets
- hex-like strings

### 3. Signal Confidence and Multi-Signal Risking

Signals now carry confidence and severity metadata.

Examples:
- `base64_blob` → low confidence / low-medium impact
- `hidden_dom_element` → medium confidence
- `prompt_injection` → high severity
- `threat_intel_*` → critical

Risk increases more when signals occur together. Example:
- prompt injection + hidden DOM → strong escalation
- base64 + hex payload → moderate escalation
- base64 alone → minimal increase

### 4. Updated Decision Thresholds

SecureAgent now uses:
- `risk < 40` → `ALLOW`
- `40 <= risk < 70` → `WARN`
- `risk >= 70` → `BLOCK`

### 5. Agent Action Audit Trail

Every mediated action is audited, including approvals.

Audit records include:
- action
- target
- count
- decision
- attack type
- reason
- timestamp

Repeated actions are aggregated within a 2-second window.

Example:

```json
{
  "action": "enter_text",
  "target": "wikipedia search field",
  "count": 6,
  "decision": "ALLOW",
  "attack_type": "None",
  "reason": "Action appears safe"
}
```

Instead of logging every keystroke separately, the dashboard shows:
- `enter_text x6`
- `click_button`
- `submit_form`

### 6. Explainable AI Analysis

Every scan now carries explainability data, including:
- AI Analysis summary
- Key Findings
- Policy Decision
- signal severity and confidence

Example format shown in the dashboard:

```text
AI ANALYSIS

Key Findings:
• Hidden DOM elements detected
• Encoded payload patterns detected
• Domain reputation high

Policy Decision:
WARN
```

### 7. Simulator-Driven Agent Testing

The malicious simulator lab now includes an agent simulation harness.

Each scenario page can trigger realistic agent-style actions through the real mediation pipeline:
- autofill email / password
- click a CTA or button
- submit a form

This allows you to prove that:
- safe actions are approved
- risky actions are warned or blocked
- the outcome is logged in the audit trail

---

## Project Structure

```text
Secure-Agent-Browser/
├── backend/
│   ├── api.py                       # Main API and threat/action pipeline
│   ├── action_mediator.py           # AI-agent action mediation rules
│   ├── scanner.py                   # Page fetcher
│   ├── threat_intel.py              # Threat intel lookups
│   ├── domain_intel.py              # Domain analysis wrapper
│   ├── domain_intelligence.py       # Deterministic domain trust scoring
│   ├── obfuscation.py               # Obfuscation heuristics
│   ├── risk.py                      # Weighted scoring + trust modifiers
│   ├── policy_engine.py             # ALLOW/WARN/BLOCK thresholds
│   ├── explainability.py            # Human-readable AI analysis
│   ├── llm_reasoner.py              # Context-aware malicious intent logic
│   └── ml_model.py                  # Supporting ML signal
│
├── Frontend/Secure-Agent-Browser/
│   ├── src/pages/Dashboard.tsx
│   ├── src/components/
│   │   ├── RiskIntelligencePanel.tsx
│   │   ├── ThreatTimeline.tsx
│   │   └── ThreatAlert.tsx
│   └── src/lib/firebase.ts
│
├── secureagent-extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js                   # Action interception + visible mediation
│   ├── warning.html
│   ├── warning.js
│   └── icons/
│
├── malicious-simulator-lab/
│   ├── index.html
│   ├── assets/
│   │   └── agent-simulator.js       # Local simulated agent harness
│   └── pages/
│       ├── phishing-login.html
│       ├── prompt-injection.html
│       ├── obfuscated-payload.html
│       └── combined-threat.html
│
└── attacks/
```

---

## Backend API

Base URL: `http://localhost:8000`

### `POST /analyze_url`

Analyzes a page and returns the page-level threat decision.

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "url": "https://example.com",
  "risk": 25,
  "decision": "ALLOW",
  "trust": 96,
  "indicators": ["base64_blob"],
  "signal_details": [
    {
      "type": "base64_blob",
      "confidence": "low",
      "severity": "low"
    }
  ],
  "attack_type": "Suspicious Content",
  "analysis": {
    "title": "AI ANALYSIS",
    "summary": "...",
    "key_findings": ["..."],
    "policy_decision": "ALLOW"
  },
  "timestamp": "..."
}
```

### `POST /scan`

Compatibility alias for `/analyze_url`.

### `POST /evaluate_action`

Evaluates an AI/browser agent action before execution.

Request:

```json
{
  "url": "http://localhost:8099/pages/phishing-login.html",
  "action": "submit_form",
  "action_context": {
    "target_text": "Verify Now",
    "input_type": "password"
  }
}
```

Response:

```json
{
  "url": "http://localhost:8099/pages/phishing-login.html",
  "action": "submit_form",
  "decision": "BLOCK",
  "reason": "Possible credential harvesting",
  "risk": 92,
  "attack_type": "Phishing"
}
```

### `GET /scan_history`

Returns recent page scans from in-memory history for local/dev visibility.

### `GET /action_history`

Returns recent mediated action audits, including aggregated repeated actions.

---

## Dashboard

Main page:
`Frontend/Secure-Agent-Browser/src/pages/Dashboard.tsx`

The dashboard now shows:
- real-time scan table
- Risk Intelligence Panel
- domain trust
- security decision
- detected signals with severity and confidence
- AI analysis and policy decision
- Threat Timeline
- latest blocked threat
- Agent Action Audit Trail with aggregated actions

Examples:
- `enter_text x6`
- `click_button`
- `submit_form`

---

## Browser Extension

Folder: `secureagent-extension/`

Behavior:
- scans navigation through the backend
- redirects `WARN` / `BLOCK` page results to the extension warning flow
- intercepts clicks, text entry, and form submissions
- sends actions to `/evaluate_action`
- shows visible action-review toasts
- blocks risky agent actions before execution

This keeps the existing architecture but extends it into active agent defense.

---

## Safe Malicious Simulation Lab

Folder: `malicious-simulator-lab/`

Run locally:

```bash
cd malicious-simulator-lab
python3 -m http.server 8099
```

Test URLs:
- `http://localhost:8099/pages/phishing-login.html`
- `http://localhost:8099/pages/prompt-injection.html`
- `http://localhost:8099/pages/obfuscated-payload.html`
- `http://localhost:8099/pages/combined-threat.html`

Each scenario now includes a local agent simulator panel to test mediated actions through the real extension/backend flow.

Safety notes:
- no real credential exfiltration
- no live malware
- no persistence
- all attack behavior is simulated/inert

---

## Expected Outcomes

Trusted site example:

```text
github.com
Risk Score: 25
Decision: ALLOW
```

Malicious page example:

```text
phishing-login.html
Risk Score: 92
Decision: BLOCK
```

Aggregated audit example:

```text
enter_text x6 wikipedia
click_button search
submit_form search
```

---

## Local Setup

### 1. Backend

From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn requests tldextract pyyaml scikit-learn
uvicorn backend.api:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend

```bash
cd Frontend/Secure-Agent-Browser
npm install
npm run dev
```

### 3. Extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click `Load unpacked`
4. Select `secureagent-extension/`
5. Reload the extension after JS or manifest changes

---

## Detection Signals

High-level signals currently used:
- prompt injection markers
- phishing / credential harvesting patterns
- domain reputation and suspicious URL heuristics
- hidden DOM elements
- Base64 payload-like content
- hex payload-like content
- suspicious unicode usage
- threat intel matches
- context-aware intent reasoning
- supporting ML classification

---

## Security and Ethics

This project is for defensive security testing, browser safety research, and education.

Use only:
- in controlled environments
- with explicit authorization
- against safe local simulations unless you have permission

---

## Troubleshooting

- No scans in dashboard:
  - confirm backend is running on `http://localhost:8000`
  - confirm Firestore config in `Frontend/Secure-Agent-Browser/src/lib/firebase.ts`

- Extension not blocking actions:
  - reload the unpacked extension
  - confirm `http://localhost:8000/evaluate_action` is reachable

- Simulator panel appears but does nothing:
  - confirm the extension content script is loaded on the simulator page
  - verify the backend is running

- Frontend build warning about CSS `@import` order:
  - current project has a non-blocking CSS ordering warning during Vite build
