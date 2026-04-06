# SecureAgent: AI-Powered Intelligent Web Threat Detection

SecureAgent is a multi-user browser security platform for detecting malicious webpages, mediating AI-agent browser actions, and auditing every security decision with explainable reasoning.

It combines:
- FastAPI backend threat analysis and policy enforcement
- Chrome extension for page scanning and action interception
- Selenium-backed browser runtime analysis with HTTP fallback
- Multi-step protected browser-agent execution with replanning and per-step mediation
- React dashboard with authenticated, user-scoped visibility
- Firebase Firestore storage and real-time listeners
- Safe malicious simulation lab for local attack testing
- Reproducible benchmark fixtures and evaluation reporting
- Stress-suite reporting and exportable metrics tables
- Hardened backend defaults with docs disabled, user-scoped data, and private-host scan blocking

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
- score breakdown and ordered reasoning steps

### Browser-Backed Dynamic Analysis

SecureAgent can now enrich scans with a real browser runtime when Chrome/Selenium is available:
- dynamic DOM mutation monitoring
- runtime overlay and clickjacking inspection
- event hijack detection
- cross-origin request visibility

If a browser runtime is unavailable, the system falls back to HTTP fetching so the prototype still runs.

### Benchmark and Evaluation Evidence

The platform now includes:
- an expanded labeled benchmark corpus for benign and malicious pages
- local malicious simulator pages
- reproducible benchmark report API at `GET /benchmark/report`
- stress-suite API at `GET /benchmark/stress`
- export API at `POST /benchmark/export`
- dashboard benchmark panel with:
  - precision
  - recall
  - F1 score
  - false positive rate
  - benign task success rate
  - malicious task stop rate
  - latency summary

### Protected Autonomous Agent Execution

SecureAgent now exposes `POST /agent/execute`, which:
- perceives current browser state
- extracts actionable elements and sensitive inputs
- replans at each step from the user goal
- scans the page before every action
- mediates each click or text entry
- halts on policy blocks, execution failures, or goal conflicts

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
- re-syncs auth from an open dashboard tab before clearing stale credentials
- avoids failing open into misleading simulator errors when auth refresh is possible

### Role-Based Access Control

Backend role checks now protect:
- `GET /admin/all_scans` for `admin`
- `GET /research/analytics` for `admin` and `researcher`
- standard user routes for user-owned data only

### Hardening Defaults

The current backend defaults are intentionally closed down:
- Swagger/OpenAPI docs are disabled unless `SECUREAGENT_EXPOSE_API_DOCS=true`
- remote scans of private or loopback hosts are blocked by default
- the simulator lab is mounted only when `SECUREAGENT_ENABLE_LOCAL_LAB=true`
- JWT secrets must be explicitly configured in production/staging
- local auth storage starts empty and is safe to regenerate

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
```

---

## Backend API

Base URL: `http://127.0.0.1:8000`

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

#### `POST /agent/execute`

Runs the protected multi-step browser-agent executor against a target page.

#### `GET /benchmark/stress`

Returns large-page handling and latency stress results.

#### `POST /benchmark/export`

Exports JSON, CSV, and Markdown benchmark artifacts into `benchmark-results/latest/`.

### User Data

#### `GET /scans/my`
#### `GET /scan_history`
#### `GET /action_history`

All three are authenticated and user-scoped.

### Public Surface

Public by default:
- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/google`

Protected:
- all scan, action, metrics, performance, history, admin, and research endpoints

Disabled by default:
- `/docs`
- `/redoc`
- `/openapi.json`

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
- shared API client for backend-origin requests
- runtime API base URL persisted for extension reuse

---

## Browser Extension

Folder: `secureagent-extension/`

Behavior:
- scans navigation through the backend
- surfaces `WARN` / `BLOCK` results in-page with the SecureAgent decision overlay
- intercepts clicks, text entry, and form submissions
- sends actions to `/evaluate_action`
- includes the JWT in all protected backend requests
- blocks risky agent actions before execution
- reuses the dashboard-selected backend base URL instead of assuming a single hardcoded host
- ignores stale late-arriving scan results that no longer match the active tab URL
- no longer shows noisy “safe site” banners for normal allowed pages

Token flow:
- dashboard login stores JWT in local storage
- dashboard posts the token to the page via `window.postMessage`
- content script stores the token in `chrome.storage.local`
- background/content scripts reuse the token for scans and action mediation
- the frontend also persists `secureagent_api_base_url`, which the extension reads for backend calls
- when a request receives `401`, the extension attempts one dashboard-token re-sync before treating the session as expired

---

## Safe Malicious Simulation Lab

Folder: `malicious-simulator-lab/`

The lab is already served by the backend at `/lab` when `SECUREAGENT_ENABLE_LOCAL_LAB=true`.

Open locally:

```bash
http://127.0.0.1:8000/lab
```

Test URLs:
- `http://127.0.0.1:8000/lab/pages/phishing-login.html`
- `http://127.0.0.1:8000/lab/pages/prompt-injection.html`
- `http://127.0.0.1:8000/lab/pages/obfuscated-payload.html`
- `http://127.0.0.1:8000/lab/pages/combined-threat.html`

Each scenario includes a local agent simulator panel to test mediated actions through the real extension/backend flow.

---

## Local Setup

### 1. Backend

From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.api:app --reload --host 127.0.0.1 --port 8000
```

Recommended env vars:

```bash
export SECUREAGENT_ENV=development
export SECUREAGENT_JWT_SECRET="replace-this-with-a-long-random-secret"
export SECUREAGENT_CORS_ORIGINS="http://localhost:8080,http://127.0.0.1:8080"
export SECUREAGENT_FIREBASE_CREDENTIALS="./backend/firebase_key.json"
export SECUREAGENT_ENABLE_LOCAL_LAB=true
export SECUREAGENT_EXPOSE_API_DOCS=false
export SECUREAGENT_ALLOW_PRIVATE_SCAN_TARGETS=false
```

### 2. Frontend

```bash
cd Frontend/Secure-Agent-Browser
npm install
npm run dev
```

Optional:

```bash
export VITE_API_BASE_URL=http://127.0.0.1:8000
export VITE_FIREBASE_API_KEY="..."
export VITE_FIREBASE_AUTH_DOMAIN="..."
export VITE_FIREBASE_PROJECT_ID="..."
export VITE_FIREBASE_STORAGE_BUCKET="..."
export VITE_FIREBASE_MESSAGING_SENDER_ID="..."
export VITE_FIREBASE_APP_ID="..."
export VITE_FIREBASE_MEASUREMENT_ID="..."
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

### 5. Optional API Docs

If you explicitly want Swagger during local development:

```bash
export SECUREAGENT_EXPOSE_API_DOCS=true
uvicorn backend.api:app --reload --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/docs`.

### 6. Verification

Backend:

```bash
python3 -m compileall backend
cd backend && python3 test_startup.py
```

Frontend:

```bash
cd Frontend/Secure-Agent-Browser
npm run lint
npm run build
npm test -- --run
```

### 7. One-Command Evaluation

Generate benchmark and stress artifacts:

```bash
python3 scripts/run_benchmark.py
```

Generate the hackathon-ready package plus demo notes:

```bash
python3 scripts/competition_mode.py
```

Outputs land in:
- `benchmark-results/latest/`
- `benchmark-results/<timestamp>/`

---

## Firestore Indexes

For production, create composite indexes for:
- `scans`: `user_id ASC`, `timestamp DESC`
- `agent_actions`: `user_id ASC`, `timestamp DESC`

The backend now falls back to a non-indexed query plus local sorting if those indexes are missing, but the indexes should still be created for correct production performance.

---

## Submission Package

For judging and final submission, include:
- [README.md](/Users/mac/Desktop/Secure-Agent-Browser/README.md)
- [TECHNICAL_DOCUMENTATION.md](/Users/mac/Desktop/Secure-Agent-Browser/TECHNICAL_DOCUMENTATION.md)
- [docs/ARCHITECTURE_DIAGRAM.md](/Users/mac/Desktop/Secure-Agent-Browser/docs/ARCHITECTURE_DIAGRAM.md)
- [docs/DEMO_FLOW.md](/Users/mac/Desktop/Secure-Agent-Browser/docs/DEMO_FLOW.md)
- `benchmark-results/latest/SUMMARY.md`
- `benchmark-results/latest/benchmark-report.json`

---

## Troubleshooting

- Registration returns `500`:
  - restart the backend after dependency or auth changes
  - current auth path uses direct `bcrypt`, not `passlib`
  - confirm `SECUREAGENT_JWT_SECRET` is set in non-dev deployments

- Dashboard is blank:
  - confirm you are logged in
  - confirm the extension is sending authenticated requests
  - confirm backend `/scans/my` and `/action_history` are returning `200`
  - create the Firestore composite indexes for production
  - verify `VITE_API_BASE_URL` points at the running backend
  - if one auxiliary endpoint returns `401`, refresh the dashboard once instead of assuming the whole session is invalid

- Google login fails with `auth/configuration-not-found`:
  - enable Google sign-in in Firebase Authentication
  - add `localhost` to Authorized Domains

- Email/password login fails for a Google-created account:
  - sign in with Google first
  - open the profile menu in the dashboard
  - use the password-enable flow to set a password for that existing account
  - then use the same email with normal email/password login

- Scan requests fail for `localhost`, Docker, or private IPs:
  - this is blocked by default to reduce SSRF exposure
  - only enable `SECUREAGENT_ALLOW_PRIVATE_SCAN_TARGETS=true` in a controlled local environment

- API docs are missing:
  - expected by default
  - set `SECUREAGENT_EXPOSE_API_DOCS=true` only for local development

- Extension changes do not appear:
  - reload the unpacked extension in `chrome://extensions`
  - make sure Chrome is loading `/Users/mac/Desktop/Secure-Agent-Browser/secureagent-extension`

- Malicious-page simulator shows `SecureAgent requires login`:
  - keep the dashboard open in a logged-in tab
  - reload the extension after auth-related changes
  - refresh the malicious page so the extension can re-sync the JWT from the dashboard tab

---

## Security Notes

This project is for defensive security testing, browser safety research, and education.

Use only:
- in controlled environments
- with explicit authorization
- against safe local simulations unless you have permission
