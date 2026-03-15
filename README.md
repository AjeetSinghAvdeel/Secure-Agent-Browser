# SecureAgent: AI-Powered Intelligent Web Threat Detection

SecureAgent is a multi-user browser security platform for detecting malicious webpages, mediating AI-agent browser actions, and auditing every security decision with explainable reasoning.

It combines:
- FastAPI backend threat analysis and policy enforcement
- Chrome extension for page scanning and action interception
- React dashboard with authenticated, user-scoped visibility
- Firebase Firestore storage and real-time listeners
- Safe malicious simulation lab for local attack testing

---

## Architecture

```text
User Login
   ↓
JWT Authentication
   ↓
SecureAgent Extension
   ↓
Threat Detection Engine
   ↓
Action Mediation Layer
   ↓
Risk Scoring + Policy Engine
   ↓
Firestore (user scoped)
   ↓
Real-time Dashboard
```

SecureAgent now protects both:
- browsing decisions: should the page be allowed, warned, or blocked?
- agent decisions: should an AI/browser agent be allowed to click, type, or submit?

---

## Implemented Features

### Multi-User Authentication

SecureAgent now supports:
- email/password registration and login
- JWT-based sessions
- Google sign-in through Firebase Auth
- user-scoped scans and action history
- protected dashboard and scan routes

Supported roles:
- `user`
- `admin`
- `researcher`

Public sign-up creates standard `user` accounts only. Elevated roles must be provisioned separately.

### Action Mediation

The extension intercepts:
- button clicks
- text entry
- form submissions

Each action is sent to `POST /evaluate_action` before execution. SecureAgent can:
- allow the action
- warn the user / operator
- block the action completely

### Explainable AI Analysis

Every scan carries:
- AI analysis summary
- key findings
- policy decision
- signal severity and confidence

### User-Scoped Dashboard

The dashboard now shows only records for the authenticated user:
- scans
- action audits
- risk reports

It reads from:
- Firestore listeners for real-time updates
- authenticated backend endpoints as a fallback/consistency path

### Extension Authentication

The extension:
- stores the SecureAgent JWT in `chrome.storage.local`
- sends `Authorization: Bearer ...` to backend scan/action endpoints
- syncs its token from the dashboard login flow

### Role-Based Access Control

Backend role checks now protect:
- `GET /admin/all_scans` for `admin`
- `GET /research/analytics` for `admin` and `researcher`
- standard user routes for user-owned data only

---

## Project Structure

```text
Secure-Agent-Browser/
├── backend/
│   ├── api.py
│   ├── auth.py
│   ├── auth_middleware.py
│   ├── action_mediator.py
│   ├── scanner.py
│   ├── threat_intel.py
│   ├── domain_intel.py
│   ├── domain_intelligence.py
│   ├── obfuscation.py
│   ├── risk.py
│   ├── policy_engine.py
│   ├── explainability.py
│   ├── llm_reasoner.py
│   └── ml_model.py
│
├── Frontend/Secure-Agent-Browser/
│   ├── src/context/AuthContext.tsx
│   ├── src/components/ProtectedRoute.tsx
│   ├── src/pages/Login.tsx
│   ├── src/pages/Dashboard.tsx
│   ├── src/pages/ScanPage.tsx
│   ├── src/lib/api.ts
│   └── src/lib/firebase.ts
│
├── secureagent-extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── warning.html
│   ├── warning.js
│   └── icons/
│
├── malicious-simulator-lab/
│   ├── index.html
│   ├── assets/
│   │   └── agent-simulator.js
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

### Auth

#### `POST /auth/register`

```json
{
  "email": "analyst@example.com",
  "password": "qwerty12",
  "role": "user"
}
```

#### `POST /auth/login`

```json
{
  "email": "analyst@example.com",
  "password": "qwerty12"
}
```

#### `POST /auth/google`

Exchanges a Firebase Google ID token for a SecureAgent JWT.

#### `GET /auth/me`

Returns the authenticated user from the JWT.

### Scanning

#### `POST /analyze_url`
#### `POST /scan`

Authenticated page scan endpoints.

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
  "risk_score": 0.25,
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

### Action Mediation

#### `POST /evaluate_action`

Evaluates an AI/browser agent action before execution.

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

### User Data

#### `GET /scans/my`
#### `GET /scan_history`
#### `GET /action_history`

All three are authenticated and user-scoped.

### Restricted Routes

#### `GET /admin/all_scans`

Admin only.

#### `GET /research/analytics`

Admin or researcher only.

---

## Firestore Data Model

Collections:
- `users`
- `scans`
- `agent_actions`

### `users/{user_id}`

```json
{
  "email": "analyst@example.com",
  "role": "user",
  "created_at": "..."
}
```

### `scans/{scan_id}`

```json
{
  "user_id": "...",
  "url": "https://example.com",
  "risk_score": 0.25,
  "domain_trust": 96,
  "decision": "ALLOW",
  "signals": [],
  "ai_analysis": {},
  "timestamp": "..."
}
```

### `agent_actions/{action_id}`

```json
{
  "user_id": "...",
  "action": "submit_form",
  "target": "Verify Now",
  "decision": "BLOCK",
  "attack_type": "Phishing",
  "reason": "Possible credential harvesting",
  "timestamp": "..."
}
```

---

## Frontend

Main app:
- protected routes for `/dashboard`, `/scan`, and `/scan/:id`
- login page at `/login`
- user panel in the top navigation
- backend-driven error messaging for auth
- Google sign-in button backed by Firebase Auth

Dashboard behavior:
- real-time Firestore listeners for `scans` and `agent_actions`
- backend polling fallback for `/scans/my` and `/action_history`
- user-specific records only

---

## Browser Extension

Folder: `secureagent-extension/`

Behavior:
- scans navigation through the backend
- redirects `WARN` / `BLOCK` page results to the extension warning flow
- intercepts clicks, text entry, and form submissions
- sends actions to `/evaluate_action`
- includes the JWT in all protected backend requests
- blocks risky agent actions before execution

Token flow:
- dashboard login stores JWT in local storage
- dashboard posts the token to the page via `window.postMessage`
- content script stores the token in `chrome.storage.local`
- background/content scripts reuse the token for scans and action mediation

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

Each scenario includes a local agent simulator panel to test mediated actions through the real extension/backend flow.

---

## Local Setup

### 1. Backend

From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn requests tldextract pyyaml scikit-learn firebase-admin python-jose bcrypt
uvicorn backend.api:app --reload --host 0.0.0.0 --port 8000
```

Recommended env vars:

```bash
export SECUREAGENT_JWT_SECRET="replace-this-with-a-long-random-secret"
export SECUREAGENT_CORS_ORIGINS="http://localhost:8080,http://127.0.0.1:8080"
```

### 2. Frontend

```bash
cd Frontend/Secure-Agent-Browser
npm install
npm run dev
```

Optional:

```bash
export VITE_API_BASE_URL=http://localhost:8000
```

### 3. Extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click `Load unpacked`
4. Select `secureagent-extension/`
5. Reload the extension after JS or manifest changes

### 4. Google Sign-In

In Firebase Console for project `agent-browser-366c1`:
- enable `Google` under `Authentication` -> `Sign-in method`
- set a support email
- add `localhost` to Authorized Domains

---

## Firestore Indexes

For production, create composite indexes for:
- `scans`: `user_id ASC`, `timestamp DESC`
- `agent_actions`: `user_id ASC`, `timestamp DESC`

The backend now falls back to a non-indexed query plus local sorting if those indexes are missing, but the indexes should still be created for correct production performance.

---

## Troubleshooting

- Registration returns `500`:
  - restart the backend after dependency or auth changes
  - current auth path uses direct `bcrypt`, not `passlib`

- Dashboard is blank:
  - confirm you are logged in
  - confirm the extension is sending authenticated requests
  - confirm backend `/scans/my` and `/action_history` are returning `200`
  - create the Firestore composite indexes for production

- Google login fails with `auth/configuration-not-found`:
  - enable Google sign-in in Firebase Authentication
  - add `localhost` to Authorized Domains

- Extension changes do not appear:
  - reload the unpacked extension in `chrome://extensions`
  - make sure Chrome is loading `/Users/mac/Desktop/Secure-Agent-Browser/secureagent-extension`

---

## Security Notes

This project is for defensive security testing, browser safety research, and education.

Use only:
- in controlled environments
- with explicit authorization
- against safe local simulations unless you have permission

Next follow-up items to remember:
- create Firestore composite indexes
- set a strong production `SECUREAGENT_JWT_SECRET`
- verify deployed Google auth configuration and authorized domains
