# SecureAgent Demo Flow

## 5 to 10 Minute Script

1. Start with the dashboard and open the benchmark readiness panel.
   Show the precision, recall, F1 score, benign task success rate, malicious task stop rate, and latency numbers.

2. Demonstrate a benign workflow.
   Scan `/benchmark-fixtures/pages/benign_invoice_portal.html` or `/benchmark-fixtures/pages/benign_profile_settings.html` and show that normal navigation and safe actions are allowed.

3. Demonstrate phishing and deceptive UI defense.
   Open `/benchmark-fixtures/pages/malicious_fake_oauth.html` or `/malicious-simulator-lab/pages/attack3_phishing.html`, attempt a sensitive action, and show SecureAgent blocking or escalating the action.

4. Demonstrate prompt-injection resistance.
   Open `/benchmark-fixtures/pages/malicious_export_prompt.html` and show how the system detects instruction conflict against the user goal.

5. Demonstrate the autonomous protected executor.
   Call `POST /agent/execute` with a benign page first and then with a malicious page to show step-by-step mediation and blocked execution.

6. Close with evidence.
   Run `python3 scripts/competition_mode.py` and open `benchmark-results/latest/SUMMARY.md` plus `benchmark-results/latest/COMPETITION_MODE.md`.

## Suggested Talking Points

- SecureAgent protects both humans and browser agents.
- The scan pipeline combines static analysis, runtime analysis, and policy-aware mediation.
- The benchmark corpus covers benign flows, phishing, prompt injection, obfuscation, and clickjacking.
- The exported artifacts make the evaluation reproducible for judges.
