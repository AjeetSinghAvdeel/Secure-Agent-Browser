# SecureAgent Metrics System - Quick Reference

## 📊 Metrics Definitions

```
CONFUSION MATRIX:
├─ TP (True Positive):      Malicious detected correctly ✓
├─ FP (False Positive):     Benign flagged as malicious ✗  (UX problem)
├─ TN (True Negative):      Benign allowed correctly ✓
└─ FN (False Negative):     Malicious allowed through ✗  (Security risk)

PERFORMANCE METRICS:
├─ Precision = TP/(TP+FP)                    Goal: > 0.90 (few false alarms)
├─ Recall    = TP/(TP+FN)                    Goal: > 0.85 (catch most attacks)
├─ F1 Score  = 2×(P×R)/(P+R)                 Goal: > 0.87 (balanced)
├─ FPR       = FP/(FP+TN)                    Goal: < 0.03 (< 3% false alarms)
├─ FNR       = FN/(FN+TP)                    Goal: < 0.15 (< 15% missed attacks)
├─ Accuracy  = (TP+TN)/Total                 Goal: > 0.94
└─ Specificity = TN/(TN+FP)                  Goal: > 0.97
```

## 🚀 API Endpoints Cheat Sheet

### Get Overall Metrics
```bash
curl GET /metrics
# Returns: precision, recall, F1, error rates, confusion matrix
```

### Get Misclassifications
```bash
curl GET "/errors?error_type=FP&limit=20"
# Parameters: error_type (FP/FN), domain, tag, limit
# Returns: List of misclassified URLs with reasons
```

### Get Error Analysis
```bash
curl GET /metrics/error-analysis
# Returns: Error patterns, suggestions, domain breakdown
```

### Scan with Ground Truth
```bash
curl POST /scan \
  -d '{"url": "https://example.com", "ground_truth": "benign"}'
# Response includes: metrics_update with classification result
```

## 💻 Code Snippets

### Update Metrics in Your Pipeline
```python
from metrics import update_metrics

result = update_metrics(
    risk_score=75,           # 0-100
    ground_truth="benign",   # or "malicious"
    url="https://site.com",
    confidence=0.92,
    attack_type="Phishing",
    indicators=["phishing_pattern"],
)

# result['classification_result'] = "TP", "FP", "TN", or "FN"
```

### Get Improvement Suggestions
```python
from metrics import get_tracker

tracker = get_tracker()
analysis = tracker.get_error_analysis()

for suggestion in analysis['improvement_suggestions']:
    print(f"ACTION: {suggestion}")
```

### Measure Task Success
```python
from task_success_harness import TaskSuccessHarness

harness = TaskSuccessHarness()
harness.register_default_scenarios()

for scenario in harness.scenarios:
    harness.run_task(scenario, secure_agent_enabled=False)
    harness.run_task(scenario, secure_agent_enabled=True)

metrics = harness.compute_metrics()
# metrics.without_agent, metrics.with_agent, metrics.improvement_percentage
```

### Export Metrics
```python
from metrics import get_tracker

tracker = get_tracker()
tracker.export_metrics("/path/to/metrics.json")
```

### Persist to Firebase
```python
from firebase_metrics import persist_metrics_snapshot, get_tracker

tracker = get_tracker()
metrics = tracker.compute_metrics()
persist_metrics_snapshot(metrics, user_id="user123")
```

## 📈 React Dashboard

### Use the Component
```tsx
import MetricsDashboard from './components/MetricsDashboard';

<MetricsDashboard userId="current_user_id" />
```

### What It Shows
- Precision, Recall, F1, Accuracy cards
- Confusion matrix visualization
- Error analysis charts
- Misclassification table
- Task success comparison
- Real-time updates (every 30 seconds)

## 🎯 Interpretation Guide

### Good System
```
Precision: 0.92  → 92% of flagged sites are actually malicious
Recall: 0.88     → We catch 88% of actual attacks
F1: 0.90         → Excellent balance
FPR: 0.03        → Only 3% false alarm rate
FNR: 0.12        → We miss 12% of attacks
```

### Problem Detection
```
High FPR (>0.05)?        → Too many false alarms, poor UX
                           → Reduce thresholds, refine patterns
                           
High FNR (>0.15)?        → Missing attacks, security risk
                           → Expand patterns, improve ML model
                           
Low Recall (<0.85)?      → Not catching enough attacks
                           → Lower detection threshold
                           
Low Precision (<0.90)?   → Too many false positives
                           → Add filtering, whitelist trusted domains
```

## 🔄 Workflow

```
1. Scan URL
   └─> POST /scan {"url": "...", "ground_truth": "benign"}

2. Update Metrics
   └─> update_metrics(...) called with ground truth

3. Query Results
   └─> GET /metrics → See current performance

4. Analyze Errors
   └─> GET /metrics/error-analysis → See suggestions

5. View Details
   └─> GET /errors?error_type=FP → See specific misclassifications

6. Monitor Dashboard
   └─> React Dashboard → Real-time visualization

7. Iterate
   └─> Apply suggestions → Repeat from step 1
```

## 📁 Files Reference

| File | Purpose | Lines |
|------|---------|-------|
| `metrics.py` | Core metrics tracking | 520 |
| `task_success_harness.py` | Usability measurement | 570 |
| `firebase_metrics.py` | Cloud persistence | 400 |
| `demo_metrics.py` | Working examples | 600 |
| `METRICS_INTEGRATION_GUIDE.md` | Full documentation | 1000+ |
| `MetricsDashboard.tsx` | React component | 400+ |
| `api.py` | API endpoints (modified) | 7 new |

## ⚡ Common Tasks

### Get confusion matrix
```python
tracker = get_tracker()
cm = tracker.compute_metrics()['confusion_matrix']
print(f"TP={cm['tp']}, FP={cm['fp']}, TN={cm['tn']}, FN={cm['fn']}")
```

### Find false positives on github.com
```python
fps = tracker.get_misclassifications(error_type="FP", domain="github")
for fp in fps:
    print(f"{fp.url}: {fp.reason}")
```

### Reset metrics
```python
from metrics import get_tracker
get_tracker().reset_metrics()
```

### Measure usability impact
```python
report = harness.get_detailed_report()
time_impact = report['usability_impact']['completion_time_impact_percent']
block_rate = report['malicious_tasks']['block_rate']
```

### Get improvement suggestions
```python
analysis = tracker.get_error_analysis()
for i, s in enumerate(analysis['improvement_suggestions'], 1):
    print(f"{i}. {s}")
```

## 🚨 Alert Thresholds

### Recommended Monitoring

```
PRECISION:
├─ OK:     > 0.85
├─ WARN:   0.80-0.85
└─ ALERT:  < 0.80

RECALL:
├─ OK:     > 0.80
├─ WARN:   0.75-0.80
└─ ALERT:  < 0.75

FALSE POSITIVE RATE:
├─ OK:     < 0.03
├─ WARN:   0.03-0.05
└─ ALERT:  > 0.05

FALSE NEGATIVE RATE:
├─ OK:     < 0.12
├─ WARN:   0.12-0.15
└─ ALERT:  > 0.15

TASK SUCCESS IMPACT:
├─ OK:     BENIGN success > 90% WITH agent
├─ WARN:   BENIGN success 85-90%
└─ ALERT:  BENIGN success < 85%
```

## 📡 Data Flow

```
Threat Detector Result
         ↓
   scan(url) → risk_score=75, indicators=[...]
         ↓
 update_metrics(ground_truth="benign")  ← Ground truth from user/team
         ↓
 Update: TP/FP/TN/FN counters
         ↓
 Compute: precision, recall, F1, etc.
         ↓
 GET /metrics → API returns current metrics
 GET /errors → API returns misclassifications
 Dashboard → Visualizes metrics
 Firebase → Persists snapshot (hourly)
```

## 🧪 Quick Test

```bash
# Start your API
cd backend && python -m uvicorn api:app --reload

# Run demo (in another terminal)
cd backend && python demo_metrics.py

# Query metrics
curl http://localhost:8000/metrics

# View dashboard
# Open React app with MetricsDashboard component
```

## 🔗 Documentation Links

- **Full Guide**: `backend/METRICS_INTEGRATION_GUIDE.md`
- **Overview**: `METRICS_SYSTEM_OVERVIEW.md`
- **API Docs**: In `api.py` docstrings
- **Source Code**: Each `.py` file has detailed docstrings

## ⚙️ Configuration

### Enable Firebase
```python
# In firebase_client.py
import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
```

### Auto Snapshots
```python
# In main app startup
from firebase_metrics import setup_metrics_persistence

setup_metrics_persistence(app)  # Hourly snapshots
```

## 💡 Pro Tips

1. **Collect Ground Truth** - Get security team to label URLs
2. **Monitor FPR & FNR** - Most important metrics for production
3. **Review Suggestions** - Auto-generated improvement ideas
4. **Use Task Success** - Measure usability impact
5. **Export Regularly** - Keep JSON backups of metrics
6. **Check Dashboard** - Visual trends matter

---

**Quick Start**: Run `python backend/demo_metrics.py` to see everything in action!
