SecureAgent Browser
Runtime-Aware AI System for Detecting and Preventing Malicious Web Environments
🚨 Problem Statement

Modern cyber attacks such as phishing, clickjacking, prompt injection, and credential harvesting no longer rely on obvious malicious code. Instead, they exploit:

Dynamic UI manipulation

Runtime DOM changes

Hidden overlays and event hijacking

Deceptive forms and user flows

Network-level data exfiltration

Traditional static scanners and URL reputation systems fail to detect these threats because the attack only becomes visible during execution.

SecureAgent addresses this gap by analyzing web pages the way a real browser and user would experience them — at runtime.

💡 Our Solution

SecureAgent is an AI-powered, runtime-aware browser security system that:

Opens web pages in a real instrumented browser

Observes actual behavior, not just source code

Detects malicious intent using multiple intelligence layers

Assigns explainable risk scores

Enforces policy-based decisions on what an agent/user should do next

Instead of asking “Is this page malicious?”, SecureAgent asks:

“Is it safe for an agent to interact with this page right now?”

🧠 Key Innovations

Runtime > Static priority (behavior overrides language)

Explainable AI decisions, not black-box scoring

Agent action mediation (ALLOW / WARN / BLOCK)

Realistic attack simulations for validation

End-to-end pipeline from browser to dashboard
```bash
🏗️ System Architecture
User / Agent
     │
     ▼
Frontend (React + TS)
     │
     ▼
FastAPI Backend
     │
     ├─▶ Selenium Browser (Instrumented)
     │        ├─ DOM Mutation Tracking
     │        ├─ Hidden UI Detection
     │        ├─ Event Hijack Detection
     │        └─ Network Interception
     │
     ├─▶ Static Analysis (HTML, Forms, Keywords)
     ├─▶ ML Model (Statistical Risk Patterns)
     ├─▶ LLM Reasoner (Intent & Context)
     ├─▶ Risk Engine (Explainable Scoring)
     └─▶ Policy Engine (Agent Decision)
     │
     ▼
Firestore (Real-time Storage)
     │
     ▼
Security Dashboard (Live Updates)
```
🧰 Technology Stack
Frontend

React + TypeScript

Tailwind CSS (glassmorphism UI)

Framer Motion (animations)

Lucide Icons

Firebase Firestore (real-time updates)

Backend

FastAPI (Python)

Selenium + Chromium (real browser execution)

BeautifulSoup (HTML parsing)

Intelligence Layer

Rule-based detectors (injection, phishing, hidden UI)

Machine Learning model (statistical anomaly detection)

LLM-based intent reasoning

Explainable risk scoring engine

Policy-based agent decision system

🔍 Detection Capabilities
1️⃣ Prompt Injection Detection

Detects malicious instruction patterns such as:

“Ignore previous instructions”

“Act as system / admin”

“Reveal secrets / credentials”

2️⃣ Hidden UI & Clickjacking

Identifies:

Invisible overlays

Zero-opacity elements

Hidden iframes

Runtime UI manipulation

3️⃣ Phishing & Credential Harvesting

Flags pages that:

Impersonate trusted brands

Contain password input forms

Operate outside legitimate domains

4️⃣ Runtime Behavior Analysis

Monitors:

DOM mutation frequency

Click interception

Event listener hijacking

5️⃣ Network Exfiltration Detection

Detects:

Cross-origin POST / beacon requests

Credential-related network traffic

⚖️ Risk Scoring Engine

Each scan produces:

Risk Score (0–100)

Confidence Level (low / medium / high)

Primary Threat Signal

Attack Chain Explanation

Human-readable reasons

Important Design Principle

Runtime and network behavior override ML/LLM signals.
Legitimate websites are never blocked by language alone.

🤖 Agent Action Mediation (Policy Engine)

SecureAgent simulates what an agent might do next, such as:

Submitting credentials

Browsing normally

Switching to read-only mode

The Policy Engine then decides:

Risk / Context	Decision
High risk or credential harvesting	❌ BLOCK
Suspicious environment	⚠️ WARN
No malicious indicators	✅ ALLOW

This goes beyond detection and demonstrates safe autonomous agent behavior.

📊 Security Dashboard

The dashboard provides:

Live scan updates

Status breakdown (Safe / Warning / Blocked)

Expandable analysis per scan

Policy decisions and agent actions

Full explainability for every decision

This makes the system auditable, transparent, and judge-friendly.

🧪 Attack Simulation Pages

The project includes realistic local test websites to demonstrate:

Prompt injection attacks

Hidden UI / clickjacking

Phishing login portals

These are used to:

Validate detection logic

Demonstrate system behavior during evaluation

Prove real-world applicability

🎯 Why This Project Stands Out

✔ Runtime-aware (not static scanning)
✔ Multi-layer intelligence (rules + ML + LLM)
✔ Explainable decisions
✔ Agent-centric security approach
✔ Realistic attack demonstrations
✔ Clean UI + live dashboard

This is not just a detector, but a decision-making security system.

⚠️ Disclaimer

This project is intended strictly for educational and defensive security research purposes.
All malicious pages are simulated and run locally.