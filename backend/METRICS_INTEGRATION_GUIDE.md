# SecureAgent Metrics & Task Success System
## Complete Integration Guide

This guide covers the complete evaluation system for SecureAgent threat detection.

---

## Table of Contents

1. [Overview](#overview)
2. [Components](#components)
3. [Quick Start](#quick-start)
4. [API Integration](#api-integration)
5. [Metrics Tracking](#metrics-tracking)
6. [Task Success Measurement](#task-success-measurement)
7. [Error Analysis](#error-analysis)
8. [Firebase Persistence](#firebase-persistence)
9. [React Dashboard](#react-dashboard)
10. [Example Scenarios](#example-scenarios)

---

## Overview

SecureAgent now includes a complete evaluation framework to:

- **Measure Detection Performance**: Track precision, recall, F1 score, and false rates
- **Evaluate Usability Impact**: Compare task success with/without protection
- **Analyze Misclassifications**: Detailed error tracking and improvement suggestions
- **Persist Metrics**: Firebase integration for historical analysis
- **Visualize Results**: Ready-to-use dashboard data formats

---

## Components

### 1. `metrics.py` - Metrics Tracking System

**Class: `MetricsTracker`**
- Tracks confusion matrix (TP, FP, TN, FN)
- Computes 7 performance metrics
- Stores misclassification details
- Generates improvement suggestions

**Key Metrics:**
```
Precision = TP / (TP + FP)           # Of predicted malicious, how many correct?
Recall = TP / (TP + FN)              # Of actual malicious, how many caught?
F1 Score = 2 * (P * R) / (P + R)     # Harmonic mean of precision/recall
FPR = FP / (FP + TN)                 # Of actual benign, how many flagged?
FNR = FN / (FN + TP)                 # Of actual malicious, how many missed?
Accuracy = (TP + TN) / Total          # Overall correctness
Specificity = TN / (TN + FP)          # Of actual benign, how many correct?
```

### 2. `task_success_harness.py` - Usability Testing Framework

**Class: `TaskSuccessHarness`**
- Simulates user tasks with predefined scenarios
- Measures success rates with and without SecureAgent
- Tracks task completion metrics
- Compares usability impact

**Built-in Scenarios:**
- Benign: Login (GitHub), Form submission (Medium), Payment (Amazon)
- Malicious: Phishing, Prompt injection, XSS attacks

### 3. `api.py` - Modified FastAPI Backend

**Updated Endpoints:**
- `POST /scan` - Now accepts optional `ground_truth` parameter
- `GET /metrics` - Overall system metrics
- `GET /metrics/snapshot` - Timestamped snapshot
- `GET /metrics/error-analysis` - Error patterns and suggestions
- `GET /errors` - Misclassifications with filters
- `POST /metrics/reset` - Admin: Reset metrics
- `GET /metrics/export` - Admin: Export full data

### 4. `firebase_metrics.py` - Cloud Persistence

Utilities for persisting metrics to Firestore:
- `persist_metrics_snapshot()` - Save metrics to cloud
- `persist_misclassification()` - Log errors to cloud
- `get_metrics_history()` - Retrieve historical data
- `get_error_patterns()` - Analyze patterns from cloud
- `setup_metrics_persistence()` - Auto-sync configuration

### 5. `demo_metrics.py` - Complete Example

Run this to see all features in action:
```bash
cd backend
python demo_metrics.py
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install firebase-admin  # If using Firebase
```

### 2. Update Your Threat Detection Pipeline

```python
from metrics import update_metrics

# After running threat detection
result = scan(url)  # Your existing code

risk_score = result.get("risk_score")  # 0-100
attack_type = result.get("attack_type")
indicators = result.get("indicators")

# Call this when you have ground truth (e.g., user feedback)
metrics = update_metrics(
    risk_score=risk_score,
    ground_truth="benign",  # or "malicious"
    url=url,
    confidence=0.95,
    attack_type=attack_type,
    indicators=indicators,
    analysis_details={
        "has_phishing_patterns": True,
        "has_injection_patterns": False,
        "obfuscated": False,
        "is_trusted_domain": False,
    }
)

print(f"Classification: {metrics['classification_result']}")  # TP, FP, TN, or FN
```

### 3. Query Metrics via API

```bash
# Get overall metrics
curl http://localhost:8000/metrics

# Get recent errors
curl "http://localhost:8000/errors?error_type=FP&limit=10"

# Get error analysis
curl http://localhost:8000/metrics/error-analysis
```

### 4. View in React Dashboard

See "React Dashboard" section below.

---

## API Integration

### Modified: POST /scan

**Request:**
```json
{
    "url": "https://example.com",
    "ground_truth": "benign"  // Optional: "malicious" or "benign"
}
```

**Response:**
```json
{
    "risk_score": 35,
    "decision": "ALLOW",
    "indicators": [],
    "metrics_update": {
        "classification_result": "TN",
        "prediction": "benign",
        "ground_truth": "benign",
        "precision": 0.92,
        "recall": 0.88,
        "f1_score": 0.90,
        "false_positive_rate": 0.03,
        "false_negative_rate": 0.12,
        "accuracy": 0.95,
        "specificity": 0.97,
        "confusion_matrix": {
            "tp": 230,
            "fp": 20,
            "tn": 500,
            "fn": 30,
            "total": 780
        }
    }
}
```

### New: GET /metrics

**Response:**
```json
{
    "timestamp": "2026-03-20T10:30:00+00:00",
    "precision": 0.92,
    "recall": 0.88,
    "f1_score": 0.90,
    "false_positive_rate": 0.03,
    "false_negative_rate": 0.12,
    "accuracy": 0.95,
    "specificity": 0.97,
    "confusion_matrix": {
        "tp": 230,
        "fp": 20,
        "tn": 500,
        "fn": 30,
        "total": 780
    }
}
```

### New: GET /errors

**Query Parameters:**
- `error_type`: "FP" | "FN" | null (all)
- `domain`: Filter by domain substring
- `tag`: Filter by tag (phishing, injection, obfuscation, trusted_domain)
- `limit`: Max records (default: 100)

**Request:**
```
GET /errors?error_type=FP&domain=github&limit=50
```

**Response:**
```json
{
    "timestamp": "2026-03-20T10:30:00+00:00",
    "error_type": "FP",
    "domain_filter": "github",
    "total_returned": 3,
    "errors": [
        {
            "id": "err_000001",
            "timestamp": "2026-03-20T10:15:00+00:00",
            "url": "https://github-phish.com/login",
            "predicted_label": "malicious",
            "actual_label": "benign",
            "risk_score": 75,
            "confidence": 0.92,
            "attack_type": "Phishing",
            "indicators": ["phishing_content_pattern", "credential_harvest_form"],
            "reason": "Incorrectly flagged as Phishing. Indicators: phishing_content_pattern, credential_harvest_form",
            "domain": "github-phish.com",
            "tags": ["phishing"]
        }
    ]
}
```

### New: GET /metrics/error-analysis

**Response:**
```json
{
    "error_distribution": {
        "false_positives": 20,
        "false_negatives": 30,
        "total_errors": 50,
        "error_rate": 0.064
    },
    "top_error_domains": [
        ["github.com", 5],
        ["example.com", 4]
    ],
    "missed_attack_types": [
        ["Prompt Injection", 12],
        ["Phishing", 8]
    ],
    "top_false_positive_indicators": [
        ["phishing_content_pattern", 7],
        ["suspicious_keyword", 5]
    ],
    "improvement_suggestions": [
        "Phishing patterns account for 40%+ FPs. Review phishing regex patterns...",
        "50%+ FNs are injection attacks. Expand ML model training data..."
    ]
}
```

---

## Metrics Tracking

### Using MetricsTracker Directly

```python
from metrics import MetricsTracker

tracker = MetricsTracker()

# Update metrics
result = tracker.update_metrics(
    risk_score=75,          # 0-100
    ground_truth="malicious",
    url="https://evil.com",
    confidence=0.92,
    attack_type="Phishing",
    indicators=["phishing_content"],
    analysis_details={
        "has_phishing_patterns": True,
        "is_trusted_domain": False,
    }
)

# Get current metrics
metrics = tracker.compute_metrics()
print(f"Precision: {metrics['precision']}")
print(f"Recall: {metrics['recall']}")

# Get misclassifications
fps = tracker.get_misclassifications(error_type="FP", limit=10)
for record in fps:
    print(f"{record.url} - {record.reason}")

# Get improvement suggestions
analysis = tracker.get_error_analysis()
for suggestion in analysis['improvement_suggestions']:
    print(f"- {suggestion}")

# Export metrics
tracker.export_metrics("/path/to/metrics.json")
```

### Interpreting Metrics

| Metric | Formula | Interpretation |
|--------|---------|-----------------|
| **Precision** | TP/(TP+FP) | Of sites flagged as malicious, how many actually were? High = few false alarms |
| **Recall** | TP/(TP+FN) | Of actual malicious sites, how many did we catch? High = few missed attacks |
| **F1 Score** | 2PxR/(P+R) | Balance between precision and recall (0-1) |
| **FPR** | FP/(FP+TN) | False alarm rate. Lower is better |
| **FNR** | FN/(FN+TP) | Miss rate. Lower is better |
| **Accuracy** | (TP+TN)/(all) | Overall correctness |
| **Specificity** | TN/(TN+FP) | Of benign sites, how many did we correctly allow? |

**Example Interpretation:**
```
Precision: 0.92 → 92% of flagged sites are actually malicious
Recall: 0.88    → We catch 88% of actual malicious sites
F1: 0.90        → Good balance; system is performing well
FPR: 0.03       → Only 3% false alarm rate on benign traffic
FNR: 0.12       → We miss 12% of attacks
```

---

## Task Success Measurement

### Measuring Usability Impact

```python
from task_success_harness import TaskSuccessHarness, TaskScenario, TaskType, TaskThreat

# Initialize harness
harness = TaskSuccessHarness()

# Register built-in scenarios
harness.register_default_scenarios()

# OR create custom scenarios
custom_scenario = TaskScenario(
    id="custom_login",
    name="Custom Login Test",
    type=TaskType.LOGIN,
    threat_level=TaskThreat.BENIGN,
    description="Test login task",
    steps=["Go to site", "Enter credentials", "Submit"],
    success_criteria=["User authenticated"],
)
harness.add_scenario(custom_scenario)

# Run scenarios with and without SecureAgent
for i in range(10):
    harness.run_task("benign_login", secure_agent_enabled=False)
    harness.run_task("benign_login", secure_agent_enabled=True)
    
    harness.run_task("phishing_login", secure_agent_enabled=False)
    harness.run_task("phishing_login", secure_agent_enabled=True)

# Get metrics
metrics = harness.compute_metrics()
print(f"Success without SecureAgent:  {metrics.without_agent:.1f}%")
print(f"Success with SecureAgent:     {metrics.with_agent:.1f}%")
print(f"Improvement:                  {metrics.improvement_percentage:.1f}%")

# Get detailed report
report = harness.get_detailed_report()
print(report)

# Export results
harness.export_report("/path/to/task_success.json")

# Display table
table = harness.get_success_table()
for row in table:
    print(f"{row['scenario']}: without={row['without']} with={row['with']}")
```

### Expected Results

**Benign Tasks (Login, Forms, Navigation):**
- Without SecureAgent: 90-95% success (some UX friction)
- With SecureAgent: 85-92% success (may add delays, warnings)
- Acceptable if difference < 5%

**Malicious Tasks (Phishing, Injection, XSS):**
- Without SecureAgent: 15-30% success (users catch obvious attacks)
- With SecureAgent: 5-10% success (agent blocks 90%+ of attacks)
- Goal: >90% block rate with minimal false positives

**Usability Impact:**
- Completion time increase: Should be <5% (target: <2%)
- False positive rate: Should be <3% (target: <1%)
- User satisfaction: Must remain >4/5 stars

---

## Error Analysis

### Understanding Misclassifications

**False Positive (FP):**
- Predicted: Malicious
- Actual: Benign
- User Impact: Legitimate site incorrectly blocked/warned
- Problem: Too aggressive, poor UX

**False Negative (FN):**
- Predicted: Benign
- Actual: Malicious
- User Impact: Malicious site allowed through, user at risk
- Problem: Too lenient, security gap

### Analyzing Errors

```python
from metrics import get_tracker

tracker = get_tracker()

# Get error analysis
analysis = tracker.get_error_analysis()

# Top domains causing errors
for domain, count in analysis['top_error_domains']:
    print(f"{domain}: {count} errors")

# Missed attack types (false negatives)
for attack, count in analysis['missed_attack_types']:
    print(f"Missed {attack}: {count} cases")
    # Action: Improve detection rules for this attack

# Common false positive triggers
for indicator, count in analysis['top_false_positive_indicators']:
    print(f"{indicator}: {count} false triggers")
    # Action: Refine threshold or whitelist for this indicator

# Apply suggestions
for suggestion in analysis['improvement_suggestions']:
    print(f"ACTION ITEM: {suggestion}")
```

### Improvement Strategies

**Reduce False Positives:**
1. **Whitelist trusted domains**: Skip aggressive checks for google.com, github.com
2. **Refine patterns**: "verify" keyword too generic, require more context
3. **Raise thresholds**: Use score > 60 instead of > 50 for certain indicators
4. **Domain reputation**: Allow more lenient scoring for high-reputation domains
5. **User training & feedback**: Let users override for trusted sites

**Reduce False Negatives:**
1. **Expand detection patterns**: Add more phishing keywords, obfuscation patterns
2. **Improve ML model**: Retrain with more malicious examples
3. **Lower thresholds**: Risk score > 40 instead of > 50 for critical attacks
4. **Ensemble methods**: Combine multiple detection approaches
5. **User actions**: Monitor for suspicious behavior (rapid form submission, etc.)

---

## Firebase Persistence

### Setup

```bash
# 1. Install firebase-admin
pip install firebase-admin

# 2. Get service account JSON from Firebase Console
# - Go to Project Settings > Service Accounts
# - Click "Generate New Private Key"

# 3. Update firebase_client.py
import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("path/to/serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'projectId': 'your-project-id'
})
db = firestore.client()
```

### Using Firebase Metrics

```python
from firebase_metrics import (
    persist_metrics_snapshot,
    persist_misclassification,
    get_metrics_history,
    get_error_patterns,
)

# Persisting
tracker = get_tracker()
metrics = tracker.compute_metrics()

doc_id = persist_metrics_snapshot(metrics, user_id="user123")
print(f"Saved snapshot: {doc_id}")

for error in tracker.misclassifications.values():
    persist_misclassification(asdict(error), user_id="user123")

# Retrieving
history = get_metrics_history(days=7, user_id="user123")
print(f"Got {len(history)} historical snapshots")

patterns = get_error_patterns(days=30)
print(f"Error patterns: {patterns}")
```

### Collections Structure

```
Firestore
├── metrics/
│   ├── 2026-03-20T10:30:00+00:00/
│   │   ├── timestamp
│   │   ├── precision: 0.92
│   │   ├── recall: 0.88
│   │   └── ... (metric fields)
│   │
│   ├── misclassifications/ (subcollection)
│   │   ├── err_000001
│   │   │   ├── url: "https://github-phish.com"
│   │   │   ├── predicted_label: "malicious"
│   │   │   ├── actual_label: "benign"
│   │   │   └── ...
│   │   └── err_000002
│   │
│   └── 2026-03-20T11:00:00+00:00/
└── metrics_archive/ (optional, for old data)
```

### Periodic Snapshots

```python
# Enable automatic hourly snapshots
from fastapi import FastAPI
from firebase_metrics import setup_metrics_persistence

app = FastAPI()

@app.on_event("startup")
async def startup():
    setup_metrics_persistence(app)  # Auto snapshots every hour
```

---

## React Dashboard

### Component Example: Metrics Overview

```tsx
import React, { useState, useEffect } from 'react';

interface MetricsData {
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  false_negative_rate: number;
  accuracy: number;
  confusion_matrix: {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
    total: number;
  };
}

export function MetricsOverview() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      const response = await fetch('/metrics');
      const data = await response.json();
      setMetrics(data);
    };
    
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  if (!metrics) return <div>Loading...</div>;

  const cm = metrics.confusion_matrix;

  return (
    <div className="metrics-dashboard">
      <h1>Threat Detection Metrics</h1>
      
      {/* Metric Cards */}
      <div className="grid grid-cols-2 gap-4">
        <MetricCard
          label="Precision"
          value={`${(metrics.precision * 100).toFixed(1)}%`}
          description="Of flagged sites, how many were malicious?"
        />
        <MetricCard
          label="Recall"
          value={`${(metrics.recall * 100).toFixed(1)}%`}
          description="Of actual malicious sites, how many caught?"
        />
        <MetricCard
          label="F1 Score"
          value={metrics.f1_score.toFixed(3)}
          description="Balance between precision & recall"
        />
        <MetricCard
          label="Accuracy"
          value={`${(metrics.accuracy * 100).toFixed(1)}%`}
          description="Overall correctness"
        />
      </div>

      {/* Confusion Matrix */}
      <div className="confusion-matrix mt-8">
        <h2>Confusion Matrix</h2>
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-green-100 p-4">
            <div className="font-bold">True Positives</div>
            <div className="text-2xl">{cm.tp}</div>
          </div>
          <div className="bg-red-100 p-4">
            <div className="font-bold">False Positives</div>
            <div className="text-2xl">{cm.fp}</div>
          </div>
          <div className="bg-blue-100 p-4">
            <div className="font-bold">True Negatives</div>
            <div className="text-2xl">{cm.tn}</div>
          </div>
          <div className="bg-yellow-100 p-4">
            <div className="font-bold">False Negatives</div>
            <div className="text-2xl">{cm.fn}</div>
          </div>
        </div>
      </div>

      {/* Error Rates */}
      <div className="error-rates mt-8">
        <h2>Error Rates</h2>
        <div>
          False Positive Rate: {(metrics.false_positive_rate * 100).toFixed(2)}%
          <ProgressBar value={metrics.false_positive_rate} max={1} color="red" />
        </div>
        <div>
          False Negative Rate: {(metrics.false_negative_rate * 100).toFixed(2)}%
          <ProgressBar value={metrics.false_negative_rate} max={1} color="yellow" />
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, description }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="text-gray-600">{label}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
      <div className="text-sm text-gray-500 mt-2">{description}</div>
    </div>
  );
}
```

### Component: Error Analysis Table

```tsx
export function ErrorAnalysisTable() {
  const [errors, setErrors] = useState([]);
  const [filterType, setFilterType] = useState<'FP' | 'FN' | null>(null);

  useEffect(() => {
    const query = new URLSearchParams();
    if (filterType) query.set('error_type', filterType);
    query.set('limit', '20');
    
    fetch(`/errors?${query}`).then(r => r.json()).then(d => setErrors(d.errors));
  }, [filterType]);

  return (
    <div>
      <h2>Recent Misclassifications</h2>
      
      <div className="mb-4">
        <button onClick={() => setFilterType(null)} className={filterType === null ? 'active' : ''}>
          All
        </button>
        <button onClick={() => setFilterType('FP')} className={filterType === 'FP' ? 'active' : ''}>
          False Positives
        </button>
        <button onClick={() => setFilterType('FN')} className={filterType === 'FN' ? 'active' : ''}>
          False Negatives
        </button>
      </div>

      <table className="w-full">
        <thead>
          <tr>
            <th>URL</th>
            <th>Type</th>
            <th>Risk Score</th>
            <th>Reason</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          {errors.map(error => (
            <tr key={error.id}>
              <td className="truncate">{error.url}</td>
              <td>
                <span className={error.predicted_label === 'malicious' ? 'bg-red-100' : 'bg-green-100'}>
                  {error.predicted_label === 'malicious' ? 'FP' : 'FN'}
                </span>
              </td>
              <td>{error.risk_score.toFixed(0)}</td>
              <td className="text-sm">{error.reason}</td>
              <td>{error.tags.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

## Example Scenarios

### Scenario 1: Evaluating Your Threat Detector

```python
from metrics import get_tracker

# Collect ground truth from users/security team
test_urls = [
    ("https://github.com", "benign"),
    ("https://github-phish.com", "malicious"),
    ("https://firebase.google.com", "benign"),
    ("https://malware-site.ru", "malicious"),
    # ... 100+ labelled URLs
]

tracker = get_tracker()

for url, ground_truth in test_urls:
    # Run your threat detector
    result = scan(url)
    
    # Update metrics with ground truth
    tracker.update_metrics(
        risk_score=result['risk_score'],
        ground_truth=ground_truth,
        url=url,
        confidence=result['confidence'],
        attack_type=result.get('attack_type'),
        indicators=result.get('indicators'),
    )

# Get final metrics
metrics = tracker.compute_metrics()
print(f"Precision: {metrics['precision']:.2%}")
print(f"Recall: {metrics['recall']:.2%}")

# Get errors
analysis = tracker.get_error_analysis()
for suggestion in analysis['improvement_suggestions']:
    print(f"TODO: {suggestion}")
```

### Scenario 2: Measuring Usability Impact

```python
from task_success_harness import TaskSuccessHarness

harness = TaskSuccessHarness()
harness.register_default_scenarios()

# Run each scenario 20 times
for scenario_id in harness.scenarios:
    for _ in range(20):
        # Without protection
        harness.run_task(scenario_id, secure_agent_enabled=False)
        # With protection
        harness.run_task(scenario_id, secure_agent_enabled=True)

# Analyze
report = harness.get_detailed_report()

print("USABILITY IMPACT REPORT")
print("=" * 60)
print(f"Benign task success WITH agent:   {report['benign_tasks']['success_rate_with_agent']:.1f}%")
print(f"Malicious attack block rate:       {report['malicious_tasks']['block_rate']:.1f}%")
print(f"Completion time impact:            {report['usability_impact']['completion_time_impact_percent']:+.2f}%")

# Decision
if report['benign_tasks']['success_rate_with_agent'] > 90 and \
   report['malicious_tasks']['block_rate'] > 90:
    print("✓ READY FOR PRODUCTION")
else:
    print("⚠ NEEDS TUNING")
```

### Scenario 3: Monitoring in Production

```python
import asyncio
from firebase_metrics import (
    setup_metrics_persistence,
    get_error_patterns,
    get_metrics_history,
)

app = FastAPI()

@app.on_event("startup")
async def startup():
    # Enable automatic cloud syncing
    setup_metrics_persistence(app)

@app.on_event("shutdown")
async def shutdown():
    # Export final metrics
    tracker = get_tracker()
    tracker.export_metrics("metrics_backup.json")

# In your monitoring/alerting system:
async def monitor_metrics():
    while True:
        history = get_metrics_history(days=1)
        latest = history[0] if history else None
        
        if latest and latest['false_positive_rate'] > 0.05:
            # Alert! FP rate too high
            send_alert("False positive rate exceeds 5%")
        
        if latest and latest['false_negative_rate'] > 0.15:
            # Alert! FN rate too high
            send_alert("False negative rate exceeds 15%")
        
        await asyncio.sleep(300)  # Check every 5 minutes

# Start monitoring
asyncio.create_task(monitor_metrics())
```

---

## Testing

### Run Demo

```bash
cd backend
python demo_metrics.py
```

Expected output: 9 complete demo sections with sample data

### Run Unit Tests

```bash
pytest backend/test_metrics.py
pytest backend/test_task_success_harness.py
```

### Test API Endpoints

```bash
# Start server
python -m uvicorn api:app --reload

# Test endpoints
curl http://localhost:8000/metrics
curl http://localhost:8000/errors
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "ground_truth": "benign"}'
```

---

## Troubleshooting

### Metrics Not Updating

```python
from metrics import get_tracker

tracker = get_tracker()
print(tracker.tp, tracker.fp, tracker.tn, tracker.fn)  # Check raw counts
```

### Firebase Not Saving

```python
from firebase_metrics import is_firebase_available

if not is_firebase_available():
    print("Firebase not configured")
    # Check firebase_client.py initialization
```

### High False Positives

1. Check top FP indicators:
   ```python
   analysis = tracker.get_error_analysis()
   print(analysis['top_false_positive_indicators'])
   ```

2. Whitelist trusted domains:
   ```python
   # In api.py, adjust TRUSTED_DOMAIN_SUFFIXES
   ```

3. Raise threshold:
   ```python
   # Change from risk_score > 50 to risk_score > 65
   ```

---

## Next Steps

1. **Integrate metrics** into your threat detection pipeline
2. **Collect ground truth** from users or security team
3. **Set up Firebase** for cloud persistence
4. **Build React dashboard** using provided examples
5. **Run task success tests** to measure usability impact
6. **Monitor metrics** in production with alerts
7. **Iterate** based on error analysis suggestions

---

## Support

For questions or issues, refer to:
- Metrics API documentation: `GET /metrics`
- Error analysis: `GET /metrics/error-analysis`
- Task success framework: `task_success_harness.py`
- Demo code: `python backend/demo_metrics.py`
