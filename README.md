#  SecureAgent Browser: Runtime-Aware AI Security

**A next-generation AI system for detecting and preventing malicious web environments in real-time.**

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Selenium](https://img.shields.io/badge/Selenium-43B02A?style=for-the-badge&logo=selenium&logoColor=white)](https://www.selenium.dev/)

---

##  The Problem

Modern cyber-attacks have evolved beyond simple, detectable malware. Threats like **phishing, clickjacking, prompt injection, and credential harvesting** now leverage dynamic, runtime manipulations that are invisible to traditional security tools.

-   **Dynamic UI & DOM Manipulation:** Attacks that only appear during user interaction.
-   **Hidden Overlays & Event Hijacking:** Invisible UI elements that steal clicks and data.
-   **Deceptive User Flows:** Legitimate-looking forms and flows designed to deceive.
-   **Network-Level Exfiltration:** Data悄悄 sent to malicious servers.

Static scanners and URL reputation systems are blind to these threats because the danger is only revealed **at runtime**.

---

##  Our Solution: SecureAgent

SecureAgent is an AI-powered, runtime-aware browser security system built to counter these advanced threats. Instead of asking, "Is this source code malicious?", SecureAgent asks:

> **“Is it safe for an autonomous agent to interact with this page *right now*?”**

It does this by:
1.  **Opening** web pages in a real, instrumented browser.
2.  **Observing** the page's actual behavior as a user would see it.
3.  **Analyzing** runtime data using a multi-layered intelligence engine.
4.  **Assigning** an explainable risk score and recommending an action.

---

##  Key Features

-   **Runtime-First Analysis:** Prioritizes live browser behavior over static source code.
-   **Multi-Layered Intelligence:** Combines rule-based detectors, a machine learning model, and an LLM reasoner for comprehensive threat analysis.
-   **Explainable AI (XAI):** Delivers clear, human-readable explanations for every security decision—no black boxes.
-   **Agent Action Mediation:** Goes beyond detection to provide actionable policy decisions: `ALLOW`, `WARN`, or `BLOCK`.
-   **Realistic Attack Simulation:** Includes a suite of test pages to validate detection capabilities in a controlled environment.
-   **Live Security Dashboard:** A real-time interface to monitor scans, view threats, and understand risks.

---

##  System Architecture

The system is designed as a pipeline that flows from the user/agent interaction down to a live security dashboard.

```
User / Agent
     │
     ▼
Frontend (React + TypeScript)
     │
     ▼
FastAPI Backend (Python)
     │
     ├─▶ Selenium Browser (Instrumented)
     │   ├─ DOM Mutation Tracking
     │   ├─ Hidden UI Detection
     │   ├─ Event Hijack Detection
     │   └─ Network Interception
     │
     ├─▶ Static Analysis (HTML, Forms, Keywords)
     ├─▶ ML Model (Statistical Risk Patterns)
     ├─▶ LLM Reasoner (Intent & Context Analysis)
     ├─▶ Risk Engine (Explainable Scoring)
     └─▶ Policy Engine (Agent Decision Logic)
     │
     ▼
Firestore (Real-time Database)
     │
     ▼
Security Dashboard (Live Updates)
```

---

##  Technology Stack

-   **Frontend:** React, TypeScript, Tailwind CSS, Framer Motion, Lucide Icons, Firebase Firestore
-   **Backend:** FastAPI (Python), Selenium, Chromium, BeautifulSoup
-   **Intelligence Layer:**
    -   Custom rule-based detectors (Injection, Phishing, Hidden UI)
    -   Machine Learning model for statistical anomaly detection
    -   LLM-based intent reasoning
    -   Explainable risk-scoring engine
    -   Policy-based agent decision system

---

##  Detection Capabilities

SecureAgent is equipped to detect a wide range of modern web threats:

| Threat Type                     | Detection Method                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Prompt Injection**            | Identifies malicious instruction patterns like "Ignore previous instructions" or "Act as system administrator." |
| **Hidden UI & Clickjacking**    | Uncovers invisible overlays, zero-opacity elements, hidden iframes, and other deceptive UI manipulations.        |
| **Phishing & Credential Theft** | Flags pages impersonating trusted brands, using deceptive forms, or operating on suspicious domains.           |
| **Runtime Behavior Analysis**   | Monitors for high-frequency DOM mutations, click interception, and event listener hijacking.                 |
| **Network Exfiltration**        | Detects cross-origin data transfers and suspicious network traffic related to credential submission.         |

---

##  Security Engine: Risk & Policy

#### Risk Scoring
Each scan produces a clear, actionable security assessment:
-   **Risk Score (0–100):** A quantitative measure of the threat level.
-   **Confidence Level:** The certainty of the assessment (Low, Medium, High).
-   **Primary Threat Signal:** The most significant threat detected.
-   **Attack Chain Explanation:** A human-readable narrative of the findings.

> **Design Principle:** Runtime and network behavior always override signals from the ML/LLM. A legitimate website is never blocked based on language alone.

#### Policy Engine
SecureAgent simulates an agent's potential actions and decides on a policy:
-    BLOCK: High-risk environments, especially those involving credential harvesting.
-    WARN: Suspicious environments where caution is advised.
-    ALLOW: Safe environments with no malicious indicators.

---

##  Live Security Dashboard

The dashboard offers a real-time, transparent view of the system's operations, providing:
-   Live scan updates and status breakdowns (Safe, Warning, Blocked).
-   Expandable, detailed analysis for every scan.
-   Full explainability of policy decisions and recommended agent actions.

This makes the entire system auditable and easy to understand.

---

##  Attack Simulations

The project includes local, realistic test websites to demonstrate and validate detection of:
-   Prompt injection attacks
-   Hidden UI and clickjacking
-   Phishing login portals

These simulations prove the system's effectiveness in a hands-on, verifiable way.

---

##  Why SecureAgent Stands Out

-   **Runtime-Aware:** It sees what users and agents see, not just what static analysis reveals.
-   **Multi-Layered Intelligence:** Fuses rules, ML, and LLM insights for robust detection.
-   **Truly Explainable:** Provides clear justifications for its decisions.
-   **Agent-Centric Security:** Designed for the new era of autonomous web interaction.
-   **End-to-End Solution:** From the browser to the dashboard, it's a complete, integrated system.

---

##  Disclaimer

This project is intended strictly for educational and defensive security research purposes. All malicious pages are simulated and run locally in a controlled environment.
