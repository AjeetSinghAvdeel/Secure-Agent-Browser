# SecureAgent: AI-Powered Intelligent Web Threat Detection

SecureAgent is an end-to-end web threat defense system that analyzes URLs, scores risk, enforces policy decisions (`ALLOW`, `WARN`, `BLOCK`), and visualizes results in a live dashboard.

It includes:
- FastAPI backend threat pipeline
- React dashboard (real-time scan monitoring)
- Chrome extension (pre-navigation threat protection)
- Safe local threat simulation lab

---

## Overview

SecureAgent protects users and AI agents before risky pages are trusted.

Core flow:

```text
User Browser
   ↓
SecureAgent Extension
   ↓
SecureAgent Backend (FastAPI)
   ↓
Threat Detection Pipeline
   ↓
Risk Engine
   ↓
Policy Engine
   ↓
Decision (ALLOW / WARN / BLOCK)
   ↓
Dashboard Visualization
```

---

## Key Features

- Pre-navigation extension scanning
- URL + content risk scoring
- Explainable decisions with indicators
- Real-time scan feed (Firestore-backed dashboard)
- Threat timeline visualization (blocked events)
- Safe simulation pages for testing detections

---

## Project Structure

```text
Secure-Agent-Browser/
├── backend/                         # FastAPI + detection integration
│   ├── api.py                       # Main API (/analyze_url, /scan, /scan_history)
│   ├── scanner.py                   # Page fetcher
│   ├── threat_intel.py              # Threat intel lookups
│   ├── domain_intel.py              # Domain analysis wrapper
│   ├── domain_intelligence.py       # Deterministic domain trust scoring
│   ├── obfuscation.py               # Obfuscation heuristics
│   ├── risk.py                      # Risk scoring engine
│   ├── policy_engine.py             # Policy decision engine
│   ├── explainability.py            # Explanation generation
│   └── ml_model.py                  # ML signal
│
├── Frontend/Secure-Agent-Browser/   # React + Vite dashboard
│   ├── src/pages/Dashboard.tsx
│   ├── src/components/
│   │   ├── RiskIntelligencePanel.tsx
│   │   ├── ThreatTimeline.tsx
│   │   └── ThreatAlert.tsx
│   └── src/lib/firebase.ts
│
├── secureagent-extension/           # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── warning.html
│   ├── warning.js
│   └── icons/
│
├── malicious-simulator-lab/         # Safe local test pages
│   ├── index.html
│   └── pages/
│       ├── phishing-login.html
│       ├── prompt-injection.html
│       ├── obfuscated-payload.html
│       └── combined-threat.html
│
└── attacks/                         # Additional local attack fixtures
```

---

## Backend API

Base URL: `http://localhost:8000`

### `POST /analyze_url`
Analyzes a URL and returns threat decision.

Request:
```json
{ "url": "https://example.com" }
```

Response shape:
```json
{
  "url": "https://example.com",
  "risk": 42,
  "decision": "WARN",
  "trust": 83,
  "indicators": ["..."],
  "explanation": "...",
  "timestamp": "..."
}
```

### `POST /scan`
Compatibility alias to `/analyze_url` (used by extension/dashboard logging flow).

### `GET /scan_history`
Returns in-memory recent scans (local/dev support).

---

## Dashboard (React)

Main page: `Frontend/Secure-Agent-Browser/src/pages/Dashboard.tsx`

Capabilities:
- URL scan input
- Real-time Firestore scan table
- Expandable scan details
- Per-scan risk intelligence panel
- Threat timeline (blocked events)
- Threat banner for latest blocked detection

---

## Extension (Chrome MV3)

Folder: `secureagent-extension/`

Behavior:
- Scans on navigation using backend `/scan`
- `BLOCK` / `WARN` routes to extension warning page
- `ALLOW` keeps browsing and shows safe banner/notification
- Preserves scan logging flow for dashboard visibility

---

## Safe Threat Simulation Lab

Folder: `malicious-simulator-lab/`

Run:
```bash
cd malicious-simulator-lab
python3 -m http.server 8099
```

Test URLs:
- `http://[::1]:8099/pages/phishing-login.html`
- `http://[::1]:8099/pages/prompt-injection.html`
- `http://[::1]:8099/pages/obfuscated-payload.html`
- `http://[::1]:8099/pages/combined-threat.html`

Note: These are safe simulations for detector testing, not live malicious payloads.

---

## Local Setup

## 1) Backend

From repo root:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn requests tldextract pyyaml scikit-learn
uvicorn backend.api:app --reload --host 0.0.0.0 --port 8000
```

## 2) Frontend

```bash
cd Frontend/Secure-Agent-Browser
npm install
npm run dev
```

## 3) Extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click **Load unpacked**
4. Select `secureagent-extension/`
5. Reload extension after script/manifest changes

---

## Detection Signals (High Level)

- Prompt-injection patterns
- Hidden instructions
- Obfuscation markers (base64/hex/hidden DOM/unicode)
- Domain intelligence trust penalties
- Threat intel matches
- ML + semantic risk fusion with policy evaluation

---

## Security + Ethics

This project is for defensive security testing and education.
Use only in controlled/local environments and with explicit authorization.

---

## Troubleshooting

- Extension service worker inactive:
  - Open `chrome://extensions` → SecureAgent → Reload
- No scans showing in dashboard:
  - Verify backend running on `:8000`
  - Verify Firestore config in `src/lib/firebase.ts`
- Extension warning page not appearing:
  - Confirm extension can reach `http://localhost:8000/scan`
- Frontend build warning about CSS `@import` order:
  - Existing non-blocking warning in current project setup

