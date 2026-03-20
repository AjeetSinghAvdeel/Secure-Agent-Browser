"""
Comprehensive Demo: Metrics, Task Success, and Error Analysis
==============================================================

This script demonstrates:
1. Metrics tracking for threat detection system
2. Task success measurement (with/without SecureAgent)
3. Error analysis and improvement suggestions
4. Firebase persistence examples
5. Dashboard data generation

Run this to generate sample data and test all features.
"""

import json
from datetime import datetime, timezone
from metrics import MetricsTracker, update_metrics, get_tracker
from task_success_harness import TaskSuccessHarness, TaskScenario, TaskType, TaskThreat
import os


def print_section(title: str):
    """Print formatted section header."""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def demo_metrics_tracking():
    """Demo 1: Basic metrics tracking"""
    print_section("DEMO 1: Metrics Tracking")
    
    tracker = get_tracker()
    tracker.reset_metrics()  # Start fresh
    
    # Simulate 100 threat detection evaluations
    test_data = [
        # (risk_score, ground_truth, attack_type, indicators)
        (75, "malicious", "Phishing", ["phishing_content_pattern", "credential_harvest_form"]),
        (25, "benign", None, []),
        (85, "malicious", "Injection", ["prompt_injection_pattern"]),
        (15, "benign", None, []),
        (60, "benign", None, []),  # False Positive
        (30, "malicious", "Obfuscation", ["obfuscation_script"]),  # False Negative
        (90, "malicious", "Phishing", ["phishing_content"]),
        (10, "benign", None, []),
    ]
    
    print("Processing 8 threat evaluations...\n")
    
    for risk_score, ground_truth, attack_type, indicators in test_data * 12:  # 96 total
        result = update_metrics(
            risk_score=risk_score,
            ground_truth=ground_truth,
            url=f"https://example{risk_score}.com",
            confidence=0.9 if ground_truth == "malicious" else 0.85,
            attack_type=attack_type,
            indicators=indicators,
        )
    
    # Print confusion matrix
    metrics = tracker.compute_metrics()
    cm = metrics["confusion_matrix"]
    
    print("Confusion Matrix:")
    print(f"  True Positives (TP):  {cm['tp']}")
    print(f"  False Positives (FP): {cm['fp']}")
    print(f"  True Negatives (TN):  {cm['tn']}")
    print(f"  False Negatives (FN): {cm['fn']}")
    print(f"  Total: {cm['total']}\n")
    
    # Print computed metrics
    print("Performance Metrics:")
    print(f"  Precision:              {metrics['precision']:.4f} (TP / (TP+FP))")
    print(f"  Recall (Sensitivity):   {metrics['recall']:.4f} (TP / (TP+FN))")
    print(f"  F1 Score:               {metrics['f1_score']:.4f}")
    print(f"  False Positive Rate:    {metrics['false_positive_rate']:.4f}")
    print(f"  False Negative Rate:    {metrics['false_negative_rate']:.4f}")
    print(f"  Accuracy:               {metrics['accuracy']:.4f}")
    print(f"  Specificity:            {metrics['specificity']:.4f}")
    
    return tracker


def demo_error_analysis(tracker: MetricsTracker):
    """Demo 2: Error analysis and improvement suggestions"""
    print_section("DEMO 2: Error Analysis & Improvement Suggestions")
    
    analysis = tracker.get_error_analysis()
    
    print("Error Distribution:")
    print(f"  False Positives: {analysis['error_distribution']['false_positives']}")
    print(f"  False Negatives: {analysis['error_distribution']['false_negatives']}")
    print(f"  Total Errors:    {analysis['error_distribution']['total_errors']}")
    print(f"  Error Rate:      {analysis['error_distribution']['error_rate']:.4f}\n")
    
    print("Top Error Domains:")
    for domain, count in analysis['top_error_domains'][:5]:
        print(f"  - {domain}: {count} errors")
    print()
    
    print("Missed Attack Types (False Negatives):")
    for attack, count in analysis['missed_attack_types'][:5]:
        print(f"  - {attack}: {count} missed cases")
    print()
    
    print("Top False Positive Indicators:")
    for indicator, count in analysis['top_false_positive_indicators'][:5]:
        print(f"  - {indicator}: triggered {count} times")
    print()
    
    print("Improvement Suggestions:")
    for i, suggestion in enumerate(analysis['improvement_suggestions'], 1):
        print(f"  {i}. {suggestion}\n")


def demo_misclassifications(tracker: MetricsTracker):
    """Demo 3: Retrieve and analyze misclassifications"""
    print_section("DEMO 3: Misclassification Analysis")
    
    # Get all False Positives
    fps = tracker.get_misclassifications(error_type="FP", limit=5)
    print(f"Recent False Positives (showing 5 of {len(tracker.misclassifications)}):\n")
    
    for i, fp in enumerate(fps[:5], 1):
        print(f"  [{i}] {fp.id}")
        print(f"      URL: {fp.url}")
        print(f"      Predicted: {fp.predicted_label} | Actual: {fp.actual_label}")
        print(f"      Risk Score: {fp.risk_score:.0f}, Confidence: {fp.confidence:.2f}")
        print(f"      Attack Type: {fp.attack_type or 'N/A'}")
        print(f"      Reason: {fp.reason}")
        print(f"      Tags: {', '.join(fp.tags) if fp.tags else 'None'}")
        print()


def demo_metrics_snapshot(tracker: MetricsTracker):
    """Demo 4: Metrics history and snapshots"""
    print_section("DEMO 4: Metrics Snapshots & History")
    
    # Take multiple snapshots over time
    for i in range(3):
        snapshot = tracker.get_metrics_snapshot()
        print(f"Snapshot {i+1}: {snapshot.timestamp}")
        print(f"  TP={snapshot.tp}, FP={snapshot.fp}, TN={snapshot.tn}, FN={snapshot.fn}")
        print(f"  F1 Score: {snapshot.f1_score:.4f}, Precision: {snapshot.precision:.4f}\n")
    
    # Show history
    print(f"\nTotal snapshots in history: {len(tracker.history)}")


def demo_export(tracker: MetricsTracker):
    """Demo 5: Export metrics to JSON"""
    print_section("DEMO 5: Export Metrics")
    
    # Export to JSON file
    export_file = "/tmp/metrics_export.json"
    json_str = tracker.export_metrics(export_file)
    
    data = json.loads(json_str)
    print(f"Exported to: {export_file}")
    print(f"File size: {len(json_str)} bytes\n")
    
    print("Export Structure:")
    print(f"  - metrics: {list(data['metrics'].keys())}")
    print(f"  - snapshot: {list(data['snapshot'].keys())}")
    print(f"  - error_analysis: {list(data['error_analysis'].keys())}")
    print(f"  - history: {len(data['history'])} snapshots")
    print(f"  - misclassifications: {len(data['misclassifications'])} records\n")
    
    # Show sample JSON
    print("Sample JSON structure:")
    print(json.dumps({
        "metrics": data["metrics"],
        "snapshot": data["snapshot"],
    }, indent=2)[:500] + "...\n")


def demo_task_success():
    """Demo 6: Task success rate measurement"""
    print_section("DEMO 6: Task Success Rate Measurement (with/without SecureAgent)")
    
    harness = TaskSuccessHarness()
    harness.register_default_scenarios()
    
    print(f"Registered {len(harness.scenarios)} test scenarios:\n")
    for id, scenario in harness.scenarios.items():
        print(f"  - {scenario.name} ({scenario.threat_level.value})")
    print()
    
    print("Running 10 iterations of each scenario...")
    print("(Benign = high success rate expected)")
    print("(Malicious without agent = user may miss attack)")
    print("(Malicious with agent = SecureAgent blocks)\n")
    
    # Run each scenario 10 times
    for scenario_id in harness.scenarios.keys():
        for _ in range(10):
            harness.run_task(scenario_id, secure_agent_enabled=False)
            harness.run_task(scenario_id, secure_agent_enabled=True)
    
    # Compute metrics
    metrics = harness.compute_metrics()
    
    print("\nTask Success Summary:")
    print("=" * 60)
    print(f"{'Scenario':<30} {'Without':<12} {'With':<12}")
    print("=" * 60)
    
    for row in harness.get_success_table():
        print(f"{row['scenario']:<30} {row['without']:<12} {row['with']:<12}")
    
    print("=" * 60)
    print(f"\nOverall Task Success Rates:")
    print(f"  Without SecureAgent:  {metrics.without_agent:.1f}% ({metrics.successful_without}/{metrics.total_without})")
    print(f"  With SecureAgent:     {metrics.with_agent:.1f}% ({metrics.successful_with}/{metrics.total_with})")
    print(f"  Improvement:          {metrics.improvement_percentage:.1f}%")
    print(f"  Blocked Attacks:      {metrics.blocked_attempts} attempts")
    
    # Get detailed report
    report = harness.get_detailed_report()
    
    print("\n\nDetailed Analysis:")
    print(f"  Benign Tasks:")
    print(f"    - Total: {report['benign_tasks']['total']}")
    print(f"    - Success Rate with Agent: {report['benign_tasks']['success_rate_with_agent']:.1f}%")
    print(f"    - {report['benign_tasks']['note']}")
    
    print(f"\n  Malicious Tasks:")
    print(f"    - Total: {report['malicious_tasks']['total']}")
    print(f"    - Blocked by Agent: {report['malicious_tasks']['block_rate']:.1f}%")
    print(f"    - {report['malicious_tasks']['note']}")
    
    print(f"\n  Usability Impact:")
    print(f"    - Time Impact: {report['usability_impact']['completion_time_impact_percent']:+.2f}%")
    print(f"    - {report['usability_impact']['note']}")
    
    return harness


def demo_react_dashboard_data():
    """Demo 7: Generate data suitable for React dashboard"""
    print_section("DEMO 7: Data Format for React Dashboard")
    
    tracker = get_tracker()
    
    # Metrics card data
    metrics = tracker.compute_metrics()
    cm = metrics["confusion_matrix"]
    
    dashboard_data = {
        "metrics_cards": {
            "precision": {
                "value": f"{metrics['precision']:.1%}",
                "label": "Precision",
                "description": "Of predicted malicious, how many were correct?",
                "trend": "up"
            },
            "recall": {
                "value": f"{metrics['recall']:.1%}",
                "label": "Recall",
                "description": "Of actual malicious, how many did we catch?",
                "trend": "down"
            },
            "f1_score": {
                "value": f"{metrics['f1_score']:.1%}",
                "label": "F1 Score",
                "description": "Harmonic mean of precision and recall",
                "trend": "up"
            },
        },
        "confusion_matrix_chart": {
            "labels": ["True Positive", "False Positive", "True Negative", "False Negative"],
            "values": [cm["tp"], cm["fp"], cm["tn"], cm["fn"]],
            "colors": ["#10b981", "#ef4444", "#3b82f6", "#f59e0b"],
        },
        "error_breakdown": {
            "false_positives": cm["fp"],
            "false_negatives": cm["fn"],
            "total_errors": cm["fp"] + cm["fn"],
        },
        "top_error_domains": tracker.get_error_analysis()["top_error_domains"][:5],
        "recent_errors": [
            {
                "id": e.id,
                "url": e.url,
                "type": "FP" if (e.predicted_label == "malicious" and e.actual_label == "benign") else "FN",
                "reason": e.reason,
                "tags": e.tags,
                "timestamp": e.timestamp,
            }
            for e in tracker.get_misclassifications(limit=5)
        ]
    }
    
    print("Dashboard Data Structure:\n")
    print(json.dumps(dashboard_data["metrics_cards"], indent=2))
    
    print("\n\nChart Data for Confusion Matrix:")
    print(json.dumps(dashboard_data["confusion_matrix_chart"], indent=2))
    
    print("\n\nRecent Errors for Table:")
    print(json.dumps(dashboard_data["recent_errors"], indent=2)[:500] + "...")
    
    return dashboard_data


def demo_firebase_integration():
    """Demo 8: Firebase integration examples"""
    print_section("DEMO 8: Firebase Integration (if configured)")
    
    try:
        from firebase_metrics import (
            is_firebase_available,
            persist_metrics_snapshot,
            get_metrics_history,
            get_error_patterns,
            export_metrics_to_json,
        )
        
        if not is_firebase_available():
            print("Firebase not configured in this environment.")
            print("To enable, set up firebase-admin and configure your service account.\n")
            print("Example setup:")
            print("  1. pip install firebase-admin")
            print("  2. Set GOOGLE_APPLICATION_CREDENTIALS to your service account JSON")
            print("  3. Update firebase_client.py with your project ID\n")
            return
        
        print("Firebase is available!\n")
        
        tracker = get_tracker()
        metrics = tracker.compute_metrics()
        
        # Persist snapshot
        doc_id = persist_metrics_snapshot(metrics, user_id="demo_user")
        print(f"Persisted metrics snapshot: {doc_id}\n")
        
        # Get history
        history = get_metrics_history(days=7)
        print(f"Retrieved {len(history)} historical snapshots\n")
        
        # Get patterns
        patterns = get_error_patterns(days=7)
        print(f"Error pattern analysis: {patterns}\n")
        
        # Export JSON
        export_json = export_metrics_to_json(user_id="demo_user", days=7)
        print(f"Exported metrics to JSON: {len(export_json)} characters\n")
        
    except ImportError as e:
        print(f"Firebase module not available: {e}")
        print("Install with: pip install firebase-admin\n")


def demo_api_examples():
    """Demo 9: API endpoint examples"""
    print_section("DEMO 9: API Endpoint Examples")
    
    print("Here are the new endpoints added to your FastAPI backend:\n")
    
    print("1. POST /scan (Modified)")
    print("   - Now accepts optional 'ground_truth' parameter")
    print("   - Returns metrics_update with classification result")
    print("""
   Request:
   {
       "url": "https://example.com",
       "ground_truth": "benign"
   }
   
   Response includes:
   {
       "risk_score": 35,
       "decision": "ALLOW",
       "metrics_update": {
           "classification_result": "TN",
           "precision": 0.92,
           "recall": 0.88,
           ...
       }
   }
   """)
    
    print("\n2. GET /metrics")
    print("   - Returns overall system metrics")
    print("""
   Response:
   {
       "precision": 0.92,
       "recall": 0.88,
       "f1_score": 0.90,
       "false_positive_rate": 0.03,
       ...
       "confusion_matrix": {
           "tp": 230, "fp": 20, "tn": 500, "fn": 30
       }
   }
   """)
    
    print("\n3. GET /metrics/snapshot")
    print("   - Returns timestamped snapshot and adds to history")
    
    print("\n4. GET /metrics/error-analysis")
    print("   - Returns error distribution and improvement suggestions")
    
    print("\n5. GET /errors")
    print("   - Returns misclassifications with optional filters")
    print("   - Query params: error_type (FP/FN), domain, tag, limit")
    print("""
   Example: GET /errors?error_type=FP&domain=github&limit=50
   """)
    
    print("\n6. POST /metrics/reset (Admin)")
    print("   - Reset all metrics to zero")
    
    print("\n7. GET /metrics/export (Admin)")
    print("   - Export full metrics with history and misclassifications")


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "═"*78 + "╗")
    print("║" + " "*78 + "║")
    print("║" + "  SecureAgent Metrics, Task Success & Error Analysis - Complete Demo".center(78) + "║")
    print("║" + " "*78 + "║")
    print("╚" + "═"*78 + "╝")
    
    # Run demos
    tracker = demo_metrics_tracking()
    demo_error_analysis(tracker)
    demo_misclassifications(tracker)
    demo_metrics_snapshot(tracker)
    demo_export(tracker)
    
    harness = demo_task_success()
    
    dashboard_data = demo_react_dashboard_data()
    
    demo_firebase_integration()
    
    demo_api_examples()
    
    print_section("SUMMARY")
    print("""
✓ Metrics Tracking:        Complete confusion matrix + 7 performance metrics
✓ Error Analysis:          Tracks FP/FN with reasons and improvement suggestions
✓ Task Success Measurement: Compares usability with/without SecureAgent
✓ API Endpoints:           7 new endpoints for metrics and error retrieval
✓ Firebase Persistence:    Full integration for cloud metric storage
✓ React Dashboard:         Data format and examples provided
✓ Export Capabilities:     JSON export for analysis and reporting

Next Steps:
1. Review metrics.py for metric definitions
2. Review task_success_harness.py for success measurement
3. Review modified api.py for endpoint integration
4. Set up Firebase if not already configured
5. Create React dashboard using dashboard data format
6. Integrate metrics updates into your threat detection pipeline
7. Run periodic exports for historical analysis
    """)


if __name__ == "__main__":
    main()
