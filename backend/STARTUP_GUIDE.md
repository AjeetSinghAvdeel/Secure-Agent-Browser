# SecureAgent Backend - Single Command Startup Guide

**Last Updated:** January 2025  
**Purpose:** Ensure all features work from a single uvicorn command with no additional setup

---

## Quick Start

From the `backend/` directory, run:

```bash
python3 -m uvicorn api:app --reload
```

Then visit: **http://localhost:8000/docs** (Swagger UI with all endpoints)

---

## What Happens on Startup

When you run the single command above, the following initialization happens automatically:

### 1. **FastAPI App Creation** ✓
- Creates the FastAPI application instance
- Configures CORS middleware for frontend communication
- Registers authentication router
- Loads all route handlers (25+ endpoints)

### 2. **Metrics System Initialization** ✓
- Initializes the global `MetricsTracker` instance
- Sets up confusion matrix tracking (TP, FP, TN, FN)
- Ready to track threat detection performance
  - Precision, Recall, F1 Score
  - False Positive Rate, False Negative Rate
  - Accuracy, Specificity

### 3. **Task Success Harness** ✓
- Initializes `TaskSuccessHarness` for usability impact measurement
- Registers 5 default threat scenarios:
  - Benign: login, form submission, payment
  - Malicious: phishing, injection, XSS
- Measures success rates with/without SecureAgent protection

### 4. **Firebase Metrics** (Optional)  
- Attempts to initialize cloud persistence
- If Firebase credentials available: Sets up hourly automatic snapshots
- If not available: Gracefully degrades to local-only tracking
- **No crash or error** - system continues normally

### 5. **Authentication Middleware** ✓
- Sets up JWT token validation
- Prepares role-based access control (RBAC)
- Loads authentication routes

---

## Health Check Endpoint

Verify the server is fully initialized:

```bash
curl http://localhost:8000/health
```

**Sample Response:**
```json
{
  "status": "healthy",
  "metrics_ready": true,
  "firebase_ready": true,
  "timestamp": "2024-01-15T15:30:45.123456+00:00"
}
```

- `status`: "healthy" (all systems) or "degraded" (metrics unavailable)
- `metrics_ready`: Threat detection metrics tracking active
- `firebase_ready`: Cloud persistence available
- `timestamp`: Server startup confirmation

---

## Pre-Startup Verification (Optional)

To manually verify everything before starting the server:

```bash
python3 verify_startup.py
```

**Output includes:**
- Python version check (3.8+ required)
- All dependencies installed
- All SecureAgent modules importable
- Metrics tracker initialization test
- FastAPI app creation and route count
- Firebase availability

---

## API Endpoints for Metrics

Once the server is running, use these endpoints:

### Get Current Metrics
```bash
GET /metrics
```
Returns: TP, FP, TN, FN, Precision, Recall, F1, FPR, FNR, Accuracy, Specificity

### Get Metrics Snapshot
```bash
GET /metrics/snapshot
```
Returns: Timestamped snapshot of all metrics with user context

### Analyze Errors
```bash
GET /metrics/error-analysis
```
Returns: Analysis of misclassifications with improvement suggestions

### Get Error Details
```bash
GET /errors?error_type=false_positive&domain=example.com&limit=10
```
Returns: List of specific misclassifications

### Export Metrics (Admin)
```bash
GET /metrics/export
```
Returns: JSON export of all metrics for backup/analysis

### Reset Metrics (Admin)
```bash
POST /metrics/reset
```
Resets TP/FP/TN/FN counters to 0

---

## Adding Threat Ground Truth

To track metrics, provide ground truth when analyzing URLs:

```bash
POST /analyze_url
{
  "url": "https://example.com/suspicious",
  "ground_truth": "malicious"  # or "benign"
}
```

The system will:
1. Perform threat detection (returns risk score)
2. Log the actual threat level (`ground_truth`)
3. Update confusion matrix automatically
4. Calculate all metrics in real-time

---

## Environment Variables (Optional)

Create a `.env` file in the `backend/` directory for customization:

```env
# Server
SECUREAGENT_PORT=8000
SECUREAGENT_HOST=127.0.0.1
SECUREAGENT_RELOAD=true

# CORS
SECUREAGENT_CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Firebase (optional)
FIREBASE_CREDENTIALS=./firebase_key.json

# Authentication
JWT_SECRET=your_secret_key_here
JWT_ALGORITHM=HS256
```

None of these are required for basic operation - the system works without them.

---

## Troubleshooting

### "Connection refused" on `python3 -m uvicorn api:app --reload`

**Check Python version:**
```bash
python3 --version  # Must be 3.8+
```

**Install missing dependencies:**
```bash
pip install -r requirements.txt
```

**Check dependencies:**
```bash
python3 verify_startup.py
```

### Metrics endpoints return empty

Metrics are initialized to zero. They populate as you analyze URLs:

```bash
# Analyze a URL with ground truth
POST /analyze_url
{
  "url": "https://example.com",
  "ground_truth": "benign"
}

# Check metrics - now populated
GET /metrics
```

### Firebase errors in console

**Normal behavior:** If Firebase key not found, system logs a warning and continues without cloud persistence. This is intentional and expected in local development.

To enable Firebase:
1. Place `firebase_key.json` in `backend/` directory
2. Restart server (no code changes needed)
3. Metrics automatically persist to Firestore

### Port 8000 already in use

```bash
# Use a different port
python3 -m uvicorn api:app --reload --port 8001

# Or kill existing process
pkill -f "uvicorn"
```

---

## Future Upgrades

When you upgrade SecureAgent or add new features:

1. **No changes needed** to startup command
2. **New metrics modules** automatically initialize on startup
3. **New endpoints** automatically registered with FastAPI
4. **Dependencies** added to `requirements.txt` - run `pip install -r requirements.txt` once

The single-command startup pattern ensures:
- ✓ All features available immediately
- ✓ No manual initialization scripts
- ✓ No step-by-step setup procedures
- ✓ Consistent upgrades across versions

---

## Key Files

- `api.py` - Main FastAPI application with startup events
- `metrics.py` - Core metrics tracking engine
- `task_success_harness.py` - Usability impact measurement
- `firebase_metrics.py` - Cloud persistence (optional)
- `verify_startup.py` - Startup verification script
- `requirements.txt` - All Python dependencies
- `.env` - Optional configuration (create as needed)

---

## Summary

**The entire metrics system and all SecureAgent features initialize automatically when you run:**

```bash
python3 -m uvicorn api:app --reload
```

**No additional commands, no manual setup, no missing initialization steps.**

Verify everything is ready:

```bash
# Before starting server (optional)
python3 verify_startup.py

# After starting server
curl http://localhost:8000/health
```

This single-command pattern is guaranteed for all current and future SecureAgent upgrades.
