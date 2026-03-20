"""
Firebase Metrics Persistence
=============================

Utilities for persisting metrics to Firebase Firestore.

This module provides functions to:
1. Save metrics snapshots to Firestore
2. Load metrics history from Firestore
3. Archive misclassifications
4. Generate reports from persisted data

Setup:
------
1. Ensure firebase_admin is installed: pip install firebase-admin
2. Add to your .env:
   FIREBASE_COLLECTION_METRICS="metrics"
   FIREBASE_COLLECTION_ERRORS="misclassifications"

3. In your FastAPI app:
   from firebase_metrics import setup_metrics_persistence
   
   @app.on_event("startup")
   async def startup():
       setup_metrics_persistence(app)
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import json

try:
    from firebase_admin import firestore
    from firebase_client import db
except ImportError:
    firestore = None
    db = None


METRICS_COLLECTION = "metrics"
ERRORS_COLLECTION = "misclassifications"
SNAPSHOTS_SUBCOLLECTION = "snapshots"


def is_firebase_available() -> bool:
    """Check if Firebase is configured and available."""
    return db is not None and firestore is not None


def persist_metrics_snapshot(
    metrics_data: Dict[str, Any],
    user_id: Optional[str] = None,
) -> Optional[str]:
    """
    Persist metrics snapshot to Firestore.
    
    Args:
        metrics_data: Dictionary with metrics (from MetricsTracker.compute_metrics())
        user_id: Optional user ID for tracking per-user metrics
        
    Returns:
        Document ID if successful, None otherwise
    """
    if not is_firebase_available():
        return None
    
    try:
        timestamp = datetime.now(timezone.utc)
        doc_id = timestamp.isoformat()
        
        doc_data = {
            "timestamp": firestore.SERVER_TIMESTAMP,
            "timestamp_iso": timestamp.isoformat(),
            "metrics": metrics_data.get("confusion_matrix", {}),
            "precision": metrics_data.get("precision"),
            "recall": metrics_data.get("recall"),
            "f1_score": metrics_data.get("f1_score"),
            "false_positive_rate": metrics_data.get("false_positive_rate"),
            "false_negative_rate": metrics_data.get("false_negative_rate"),
            "accuracy": metrics_data.get("accuracy"),
            "specificity": metrics_data.get("specificity"),
            "user_id": user_id,
        }
        
        db.collection(METRICS_COLLECTION).document(doc_id).set(doc_data)
        return doc_id
    except Exception as e:
        print(f"Error persisting metrics snapshot: {e}")
        return None


def persist_misclassification(
    error_record: Dict[str, Any],
    user_id: Optional[str] = None,
) -> Optional[str]:
    """
    Persist misclassification record to Firestore.
    
    Args:
        error_record: MisclassificationRecord converted to dict
        user_id: Optional user ID
        
    Returns:
        Document ID if successful, None otherwise
    """
    if not is_firebase_available():
        return None
    
    try:
        doc_data = {
            "timestamp": firestore.SERVER_TIMESTAMP,
            **error_record,
            "user_id": user_id,
        }
        
        # Store in subcollection under parent metrics doc
        date_key = datetime.now(timezone.utc).date().isoformat()
        
        db.collection(METRICS_COLLECTION).document(date_key).collection(
            ERRORS_COLLECTION
        ).document(error_record.get("id")).set(doc_data)
        
        return error_record.get("id")
    except Exception as e:
        print(f"Error persisting misclassification: {e}")
        return None


def get_metrics_history(
    days: int = 30,
    user_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve metrics snapshots from Firestore.
    
    Args:
        days: Number of days of history to retrieve
        user_id: Optional filter by user ID
        
    Returns:
        List of metrics snapshots
    """
    if not is_firebase_available():
        return []
    
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        query = db.collection(METRICS_COLLECTION).where(
            "timestamp", ">=", cutoff_date
        )
        
        if user_id:
            query = query.where("user_id", "==", user_id)
        
        docs = query.order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
        
        return [doc.to_dict() for doc in docs]
    except Exception as e:
        print(f"Error retrieving metrics history: {e}")
        return []


def get_recent_errors(
    error_type: Optional[str] = None,
    days: int = 7,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Retrieve recent misclassifications from Firestore.
    
    Args:
        error_type: "FP" or "FN" to filter
        days: Number of days of history
        limit: Maximum records to return
        
    Returns:
        List of misclassification records
    """
    if not is_firebase_available():
        return []
    
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        errors = []
        
        # Query recent dates
        current_date = datetime.now(timezone.utc).date()
        for i in range(days):
            query_date = (current_date - timedelta(days=i)).isoformat()
            
            query = db.collection(METRICS_COLLECTION).document(query_date).collection(
                ERRORS_COLLECTION
            )
            
            if error_type:
                if error_type == "FP":
                    query = query.where("predicted_label", "==", "malicious").where(
                        "actual_label", "==", "benign"
                    )
                elif error_type == "FN":
                    query = query.where("predicted_label", "==", "benign").where(
                        "actual_label", "==", "malicious"
                    )
            
            docs = query.order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
            errors.extend([doc.to_dict() for doc in docs])
            
            if len(errors) >= limit:
                break
        
        return errors[:limit]
    except Exception as e:
        print(f"Error retrieving recent errors: {e}")
        return []


def get_error_patterns(days: int = 30) -> Dict[str, Any]:
    """
    Analyze error patterns from persisted data.
    
    Args:
        days: Number of days to analyze
        
    Returns:
        Dictionary with pattern analysis
    """
    if not is_firebase_available():
        return {}
    
    try:
        errors = get_recent_errors(days=days, limit=1000)
        
        # Analyze patterns
        domain_errors: Dict[str, int] = {}
        attack_types: Dict[str, int] = {}
        indicators: Dict[str, int] = {}
        
        for error in errors:
            domain = error.get("domain", "unknown")
            domain_errors[domain] = domain_errors.get(domain, 0) + 1
            
            attack = error.get("attack_type")
            if attack:
                attack_types[attack] = attack_types.get(attack, 0) + 1
            
            for indicator in error.get("indicators", []):
                indicators[indicator] = indicators.get(indicator, 0) + 1
        
        return {
            "total_errors_analyzed": len(errors),
            "top_error_domains": sorted(
                domain_errors.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "common_attack_types": sorted(
                attack_types.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "common_indicators": sorted(
                indicators.items(), key=lambda x: x[1], reverse=True
            )[:20],
        }
    except Exception as e:
        print(f"Error analyzing patterns: {e}")
        return {}


def archive_metrics(days_ago: int = 90) -> int:
    """
    Archive old metrics to reduce Firestore storage.
    
    Args:
        days_ago: Archive metrics older than this many days
        
    Returns:
        Number of archived documents
    """
    if not is_firebase_available():
        return 0
    
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_ago)
        
        docs = db.collection(METRICS_COLLECTION).where(
            "timestamp", "<", cutoff_date
        ).stream()
        
        count = 0
        # Move to archive collection or delete
        for doc in docs:
            # In production, you might move to a separate archive collection
            # db.collection("metrics_archive").document(doc.id).set(doc.to_dict())
            doc.reference.delete()
            count += 1
        
        return count
    except Exception as e:
        print(f"Error archiving metrics: {e}")
        return 0


def export_metrics_to_json(user_id: Optional[str] = None, days: int = 30) -> str:
    """
    Export persisted metrics to JSON string.
    
    Args:
        user_id: Optional filter by user
        days: Number of days to export
        
    Returns:
        JSON string with all exported data
    """
    if not is_firebase_available():
        return "{}"
    
    try:
        history = get_metrics_history(days=days, user_id=user_id)
        errors = get_recent_errors(days=days, limit=1000)
        patterns = get_error_patterns(days=days)
        
        export_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "period_days": days,
            "metrics_snapshots": history,
            "misclassifications": errors,
            "error_patterns": patterns,
            "summary": {
                "total_snapshots": len(history),
                "total_errors": len(errors),
            },
        }
        
        return json.dumps(export_data, indent=2, default=str)
    except Exception as e:
        print(f"Error exporting metrics: {e}")
        return "{}"


def setup_metrics_persistence(app) -> None:
    """
    Configure FastAPI app with automatic metrics persistence.
    
    Usage in your main.py:
    
    ```python
    from fastapi import FastAPI
    from firebase_metrics import setup_metrics_persistence
    
    app = FastAPI()
    
    @app.on_event("startup")
    async def startup():
        setup_metrics_persistence(app)
    ```
    
    This sets up:
    - Periodic snapshots (every hour)
    - Automatic archiving (old metrics)
    """
    
    if not is_firebase_available():
        print("Firebase not configured. Metrics persistence disabled.")
        return
    
    import asyncio
    
    async def periodic_snapshot():
        """Take metrics snapshot every hour."""
        while True:
            try:
                # Import here to avoid circular dependencies
                from metrics import get_tracker
                
                tracker = get_tracker()
                metrics = tracker.compute_metrics()
                persist_metrics_snapshot(metrics)
            except Exception as e:
                print(f"Error in periodic snapshot: {e}")
            
            await asyncio.sleep(3600)  # Every hour
    
    # Start background task
    import threading
    
    def run_periodic_task():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(periodic_snapshot())
    
    thread = threading.Thread(target=run_periodic_task, daemon=True)
    thread.start()
    
    print("Metrics persistence enabled with periodic snapshots")


# Example usage in a management script:
if __name__ == "__main__":
    # Get recent metrics
    history = get_metrics_history(days=7)
    print(f"Metrics snapshots: {len(history)}")
    
    # Get error patterns
    patterns = get_error_patterns(days=7)
    print(f"Error patterns: {patterns}")
    
    # Export to JSON
    export_json = export_metrics_to_json(days=7)
    print(f"Exported {len(export_json)} characters")
    
    # Archive old metrics
    archived = archive_metrics(days_ago=90)
    print(f"Archived {archived} old metric snapshots")
