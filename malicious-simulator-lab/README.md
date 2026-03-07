# SecureAgent Threat Simulation Lab (Safe)

This folder contains realistic but **non-malicious** web pages for testing URL/content threat scanners.

## Safety Model
- No credential exfiltration
- No remote payload execution
- No malware delivery
- No persistence or system changes
- All "threat" behavior is simulated/inert

## Run Locally
From this folder:

```bash
cd malicious-simulator-lab
python3 -m http.server 8099
```

Open:
- http://localhost:8099

## Included Scenarios
- `pages/phishing-login.html`: realistic phishing-style login UI (submission blocked)
- `pages/prompt-injection.html`: hidden/prompt-injection text patterns for scanner detection
- `pages/obfuscated-payload.html`: encoded blobs + suspicious JS patterns (inert)
- `pages/combined-threat.html`: multi-signal page combining several indicators

Use only in isolated local test environments.
