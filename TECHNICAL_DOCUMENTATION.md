# SecureAgent Technical Documentation

## Problem-Statement Alignment

SecureAgent is designed around the core requirements in the hackathon problem statement:

1. Malicious web content detection
2. Safe browser action mediation
3. Explainable risk assessment
4. Protected autonomous browser-agent execution
5. Demo-ready benchmark evidence

The system combines a backend scan pipeline, a browser extension enforcement layer, a protected autonomous agent executor, a dashboard, and a reproducible benchmark + stress suite.

## Architecture

### 1. Browser Runtime and DOM Inspection

- `secureagent-extension/content.js`
  Intercepts clicks, form submissions, and text entry before execution.
- `backend/browser_runtime.py`
  Uses Selenium + Chrome headless instrumentation when available to capture:
  - dynamic DOM mutations
  - overlay and clickjacking signals
  - event hijack patterns
  - cross-origin network activity
- `backend/scanner.py`
  Falls back to HTTP fetching if a browser runtime is unavailable.

### 2. Multi-Signal Detection Pipeline

- `backend/domain_intel.py`
  Domain trust, URL heuristics, suspicious TLDs, IP-host checks
- `backend/ml_model.py`
  ML-based content scoring
- `backend/llm_reasoner.py`
  Intent and coercion reasoning over extracted page text
- `backend/ui_deception.py`
  Detection of hidden overlays, misleading forms, clickjacking, dynamic UI injection
- `backend/obfuscation.py`
  Encoded payload and obfuscated script detection
- `backend/threat_intel.py`
  Threat intelligence enrichment where available

### 3. Policy and Action Mediation

- `backend/risk.py`
  Weighted multi-factor risk scoring
- `backend/policy_engine.py`
  Allow / warn / require confirmation / block decisions
- `backend/action_mediator.py`
  Validates risky actions against page risk, attack type, and action context
- `secureagent-extension/content.js`
  Enforces mediation in the browser before execution

### 4. Agent Protection

- `backend/agent_runtime.py`
  Builds step proposals from:
  - user goal
  - page text
  - detected DOM/runtime surfaces
  - sensitive inputs and verification flows
- `backend/agent_executor.py`
  Runs a real browser-loop executor that:
  - loads pages in Selenium
  - perceives buttons, inputs, and links
  - replans at each step
  - scans current state before execution
  - mediates every proposed action
  - halts on unsafe decisions or execution failures
- `backend/api.py`
  `/agent/plan` validates proposed agent actions against page risk and goal conflict
  `/agent/execute` runs the protected multi-step loop end-to-end

## Decision Logic

Risk decisions are based on:

- ML score
- Domain suspicion
- UI deception score
- Obfuscation score
- Threat-intelligence score
- confidence-weighted signal bonuses
- domain trust modifiers

High-risk or high-severity signals can override base thresholds. Sensitive actions such as password entry or downloads are escalated to confirmation or blocked depending on context.

## Evaluation and Benchmarking

SecureAgent includes a local benchmark suite for reproducible judging:

- `benchmark-fixtures/pages/*.html`
  Benign benchmark pages
- `malicious-simulator-lab/pages/*.html`
  Malicious benchmark pages
- `/benchmark/report`
  Returns:
  - precision
  - recall
  - F1 score
  - false positive and false negative rates
  - benign task success rate
  - malicious task stop rate
  - average latency
  - attack-type coverage
- `/benchmark/stress`
  Returns:
  - large-page latency results
  - p95 latency
  - per-component timing for ML, LLM, obfuscation, and UI analysis
- `/benchmark/export`
  Writes:
  - benchmark JSON report
  - stress JSON report
  - CSV tables for page, action, and stress results
  - Markdown summary for submission use

These metrics are surfaced in the dashboard through the Benchmark Readiness panel.

## Key API Endpoints

- `POST /scan`
  Full page scan with optional DOM/page context
- `POST /evaluate_action`
  Mediated action evaluation
- `POST /agent/plan`
  Goal-aware protected agent planning
- `POST /agent/execute`
  Multi-step protected autonomous execution
- `POST /action_confirmation`
  Confirmation audit log
- `GET /performance`
  Runtime latency summary
- `GET /benchmark/report`
  Reproducible benchmark results
- `GET /benchmark/stress`
  Large-page stress metrics
- `POST /benchmark/export`
  Submission-grade metrics export

## Submission Notes

For the final hackathon submission, the strongest package is:

- Source code repository
- `README.md`
- this `TECHNICAL_DOCUMENTATION.md`
- `docs/ARCHITECTURE_DIAGRAM.md`
- `docs/DEMO_FLOW.md`
- exported files from `benchmark-results/latest/`
- a short demo video covering:
  - benign browsing flow
  - prompt injection defense
  - phishing form defense
  - clickjacking / dynamic UI defense
  - autonomous protected agent execution
  - benchmark panel and exported evidence
