"""
Metrics Tracker for Threat Detection System
===========================================

Comprehensive evaluation system for measuring:
- Precision, Recall, F1 Score
- False Positive/Negative Rates
- Misclassification tracking and analysis
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Literal
from dataclasses import dataclass, asdict, field
import json
import os


@dataclass
class MetricsSnapshot:
    """Point-in-time metrics snapshot"""
    timestamp: str
    tp: int  # True Positives
    fp: int  # False Positives
    tn: int  # True Negatives
    fn: int  # False Negatives
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    accuracy: float
    specificity: float


@dataclass
class MisclassificationRecord:
    """Detailed record of a misclassification (FP or FN)"""
    id: str
    timestamp: str
    url: str
    predicted_label: Literal["malicious", "benign"]
    actual_label: Literal["malicious", "benign"]
    risk_score: float
    confidence: float
    attack_type: Optional[str]
    indicators: List[str]
    reason: str  # Generated explanation for the error
    domain: str
    tags: List[str] = field(default_factory=list)


class MetricsTracker:
    """
    Thread-safe metrics tracker for threat detection evaluation.
    
    Tracks:
    - True Positives (TP): Correctly identified malicious sites
    - False Positives (FP): Benign sites incorrectly flagged as malicious
    - True Negatives (TN): Correctly identified benign sites
    - False Negatives (FN): Malicious sites incorrectly marked as benign
    """

    def __init__(self):
        self.tp: int = 0
        self.fp: int = 0
        self.tn: int = 0
        self.fn: int = 0
        self.misclassifications: Dict[str, MisclassificationRecord] = {}
        self.history: List[MetricsSnapshot] = []
        self._record_id_counter: int = 0

    def update_metrics(
        self,
        risk_score: float,
        ground_truth: Literal["malicious", "benign"],
        url: str,
        confidence: float = 1.0,
        attack_type: Optional[str] = None,
        indicators: Optional[List[str]] = None,
        analysis_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update metrics based on prediction vs ground truth.
        
        Args:
            risk_score: Model's risk score (0-100)
            ground_truth: Actual label ("malicious" or "benign")
            url: The URL that was scanned
            confidence: Model's confidence (0-1)
            attack_type: Type of attack detected (if any)
            indicators: List of detected indicators/flags
            analysis_details: Additional analysis metadata
            
        Returns:
            Dictionary with updated metrics and error details (if applicable)
        """
        # Convert risk_score to prediction
        prediction = "malicious" if risk_score > 50 else "benign"
        
        # Update confusion matrix
        if prediction == "malicious" and ground_truth == "malicious":
            self.tp += 1
            result = "TP"
        elif prediction == "malicious" and ground_truth == "benign":
            self.fp += 1
            result = "FP"
            self._record_misclassification(
                url=url,
                predicted_label=prediction,
                actual_label=ground_truth,
                risk_score=risk_score,
                confidence=confidence,
                attack_type=attack_type,
                indicators=indicators or [],
                analysis_details=analysis_details or {},
            )
        elif prediction == "benign" and ground_truth == "malicious":
            self.fn += 1
            result = "FN"
            self._record_misclassification(
                url=url,
                predicted_label=prediction,
                actual_label=ground_truth,
                risk_score=risk_score,
                confidence=confidence,
                attack_type=attack_type,
                indicators=indicators or [],
                analysis_details=analysis_details or {},
            )
        else:  # prediction == "benign" and ground_truth == "benign"
            self.tn += 1
            result = "TN"

        metrics = self.compute_metrics()
        metrics["classification_result"] = result
        metrics["prediction"] = prediction
        metrics["ground_truth"] = ground_truth
        
        return metrics

    def _record_misclassification(
        self,
        url: str,
        predicted_label: str,
        actual_label: str,
        risk_score: float,
        confidence: float,
        attack_type: Optional[str],
        indicators: List[str],
        analysis_details: Dict[str, Any],
    ) -> None:
        """Record a misclassification for analysis."""
        self._record_id_counter += 1
        record_id = f"err_{self._record_id_counter:06d}"
        
        # Generate reason for the misclassification
        reason = self._generate_error_reason(
            predicted_label, actual_label, attack_type, indicators
        )
        
        from urllib.parse import urlparse
        domain = urlparse(url).hostname or "unknown"
        
        record = MisclassificationRecord(
            id=record_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            url=url,
            predicted_label=predicted_label,  # type: ignore
            actual_label=actual_label,  # type: ignore
            risk_score=risk_score,
            confidence=confidence,
            attack_type=attack_type,
            indicators=indicators,
            reason=reason,
            domain=domain,
            tags=self._extract_tags(analysis_details),
        )
        
        self.misclassifications[record_id] = record

    def _generate_error_reason(
        self,
        predicted_label: str,
        actual_label: str,
        attack_type: Optional[str],
        indicators: List[str],
    ) -> str:
        """Generate a human-readable reason for the misclassification."""
        if predicted_label == "malicious" and actual_label == "benign":
            # False Positive
            if attack_type:
                return f"Incorrectly flagged as {attack_type}. Indicators: {', '.join(indicators[:3])}"
            return f"False alarm. Triggered by: {', '.join(indicators[:3]) if indicators else 'generic rules'}"
        else:
            # False Negative
            if attack_type:
                return f"Missed {attack_type} attack. Insufficient indicators detected."
            return f"Failed to detect malicious content. Insufficient pattern matches."

    def _extract_tags(self, analysis_details: Dict[str, Any]) -> List[str]:
        """Extract tags from analysis details for categorization."""
        tags = []
        if analysis_details.get("has_phishing_patterns"):
            tags.append("phishing")
        if analysis_details.get("has_injection_patterns"):
            tags.append("injection")
        if analysis_details.get("obfuscated"):
            tags.append("obfuscation")
        if analysis_details.get("is_trusted_domain"):
            tags.append("trusted_domain")
        return tags

    def compute_metrics(self) -> Dict[str, float]:
        """
        Compute all performance metrics.
        
        Returns:
            Dictionary with:
            - precision: TP / (TP + FP)
            - recall: TP / (TP + FN)
            - f1_score: 2 * (precision * recall) / (precision + recall)
            - false_positive_rate: FP / (FP + TN)
            - false_negative_rate: FN / (FN + TP)
            - accuracy: (TP + TN) / (TP + TN + FP + FN)
            - specificity: TN / (TN + FP)
            - confusion_matrix: {tp, fp, fn, tn}
        """
        total = self.tp + self.fp + self.tn + self.fn
        
        # Precision: of predicted positives, how many were correct?
        precision = round(
            self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0, 4
        )
        
        # Recall (Sensitivity): of actual positives, how many did we catch?
        recall = round(
            self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0, 4
        )
        
        # F1 Score: harmonic mean of precision and recall
        f1_score = round(
            2 * (precision * recall) / (precision + recall) 
            if (precision + recall) > 0 else 0.0, 4
        )
        
        # False Positive Rate: of actual negatives, how many did we incorrectly flag?
        false_positive_rate = round(
            self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0, 4
        )
        
        # False Negative Rate: of actual positives, how many did we miss?
        false_negative_rate = round(
            self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0, 4
        )
        
        # Accuracy: overall correctness
        accuracy = round(
            (self.tp + self.tn) / total if total > 0 else 0.0, 4
        )
        
        # Specificity: of actual negatives, how many did we correctly identify?
        specificity = round(
            self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0.0, 4
        )
        
        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "accuracy": accuracy,
            "specificity": specificity,
            "confusion_matrix": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
                "total": total,
            },
        }

    def get_metrics_snapshot(self) -> MetricsSnapshot:
        """Get a timestamped snapshot of current metrics."""
        metrics = self.compute_metrics()
        cm = metrics["confusion_matrix"]
        
        snapshot = MetricsSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tp=cm["tp"],
            fp=cm["fp"],
            tn=cm["tn"],
            fn=cm["fn"],
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1_score=metrics["f1_score"],
            false_positive_rate=metrics["false_positive_rate"],
            false_negative_rate=metrics["false_negative_rate"],
            accuracy=metrics["accuracy"],
            specificity=metrics["specificity"],
        )
        self.history.append(snapshot)
        return snapshot

    def get_misclassifications(
        self, 
        error_type: Optional[str] = None,
        domain: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
    ) -> List[MisclassificationRecord]:
        """
        Retrieve misclassifications with optional filtering.
        
        Args:
            error_type: "FP" for false positives, "FN" for false negatives, or None for all
            domain: Filter by domain
            tag: Filter by tag (phishing, injection, obfuscation, trusted_domain)
            limit: Maximum number of records to return
            
        Returns:
            List of MisclassificationRecord objects
        """
        results = list(self.misclassifications.values())
        
        if error_type == "FP":
            results = [r for r in results if r.predicted_label == "malicious" and r.actual_label == "benign"]
        elif error_type == "FN":
            results = [r for r in results if r.predicted_label == "benign" and r.actual_label == "malicious"]
        
        if domain:
            results = [r for r in results if domain.lower() in r.domain.lower()]
        
        if tag:
            results = [r for r in results if tag in r.tags]
        
        # Sort by timestamp descending (most recent first)
        results.sort(key=lambda r: r.timestamp, reverse=True)
        
        return results[:limit]

    def get_error_analysis(self) -> Dict[str, Any]:
        """
        Generate comprehensive error analysis report.
        
        Returns:
            Dictionary with:
            - error_distribution: FP and FN counts
            - top_error_domains: Domains with most errors
            - error_types: Attack types causing errors
            - common_indicators: Most common false-trigger indicators
            - improvement_suggestions: Recommendations to reduce errors
        """
        misclass = list(self.misclassifications.values())
        fps = [r for r in misclass if r.predicted_label == "malicious" and r.actual_label == "benign"]
        fns = [r for r in misclass if r.predicted_label == "benign" and r.actual_label == "malicious"]
        
        # Count errors by domain
        domain_errors: Dict[str, int] = {}
        for record in misclass:
            domain_errors[record.domain] = domain_errors.get(record.domain, 0) + 1
        
        # Count attacks in FNs
        fn_attacks: Dict[str, int] = {}
        for record in fns:
            if record.attack_type:
                fn_attacks[record.attack_type] = fn_attacks.get(record.attack_type, 0) + 1
        
        # Most common indicators in FPs
        fp_indicators: Dict[str, int] = {}
        for record in fps:
            for indicator in record.indicators[:5]:  # Top 5 per record
                fp_indicators[indicator] = fp_indicators.get(indicator, 0) + 1
        
        return {
            "error_distribution": {
                "false_positives": len(fps),
                "false_negatives": len(fns),
                "total_errors": len(misclass),
                "error_rate": round(len(misclass) / (self.tp + self.fp + self.tn + self.fn) 
                                   if (self.tp + self.fp + self.tn + self.fn) > 0 else 0, 4),
            },
            "top_error_domains": sorted(
                domain_errors.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "missed_attack_types": sorted(
                fn_attacks.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "top_false_positive_indicators": sorted(
                fp_indicators.items(), key=lambda x: x[1], reverse=True
            )[:15],
            "improvement_suggestions": self._generate_improvement_suggestions(fps, fns),
        }

    def _generate_improvement_suggestions(
        self,
        fps: List[MisclassificationRecord],
        fns: List[MisclassificationRecord],
    ) -> List[str]:
        """Generate actionable suggestions to reduce errors."""
        suggestions = []
        
        # False Positive reduction
        if fps:
            trusted_fps = [r for r in fps if "trusted_domain" in r.tags]
            if len(trusted_fps) / len(fps) > 0.3:
                suggestions.append(
                    "30%+ FPs are from trusted domains. Consider raising thresholds for "
                    "whitelisted domains (google.com, github.com, etc.)."
                )
            
            phishing_fps = [r for r in fps if "phishing" in r.tags]
            if len(phishing_fps) / len(fps) > 0.4:
                suggestions.append(
                    "Phishing patterns account for 40%+ FPs. Review phishing regex patterns "
                    "to reduce false triggers (e.g., 'verify' word may be too generic)."
                )
        
        # False Negative reduction
        if fns:
            injection_fns = [r for r in fns if "injection" in r.tags]
            if len(injection_fns) / len(fns) > 0.5:
                suggestions.append(
                    "50%+ FNs are injection attacks. Expand ML model training data for "
                    "prompt injection, XSS, and SQL injection patterns."
                )
            
            low_confidence_fns = [r for r in fns if r.confidence < 0.5]
            if low_confidence_fns:
                suggestions.append(
                    f"{len(low_confidence_fns)} FNs had low confidence (<0.5). "
                    "Consider lowering detection thresholds or retraining ML model."
                )
        
        if not suggestions:
            suggestions.append(
                "System performing well. Continue monitoring for emerging patterns."
            )
        
        return suggestions

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.misclassifications = {}
        self.history = []
        self._record_id_counter = 0

    def export_metrics(self, filepath: Optional[str] = None) -> str:
        """
        Export metrics to JSON.
        
        Args:
            filepath: Optional file path to save to. If None, returns JSON string.
            
        Returns:
            JSON string representation of metrics
        """
        metrics = self.compute_metrics()
        snapshot = self.get_metrics_snapshot()
        
        export_data = {
            "metrics": metrics,
            "snapshot": asdict(snapshot),
            "misclassifications": [
                asdict(r) for r in self.misclassifications.values()
            ],
            "error_analysis": self.get_error_analysis(),
            "history": [asdict(s) for s in self.history],
        }
        
        json_str = json.dumps(export_data, indent=2, default=str)
        
        if filepath:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            with open(filepath, "w") as f:
                f.write(json_str)
        
        return json_str

    def import_metrics(self, filepath: str) -> None:
        """
        Import metrics from JSON file.
        
        Args:
            filepath: Path to JSON file to import
        """
        with open(filepath, "r") as f:
            data = json.load(f)
        
        if "metrics" in data:
            cm = data["metrics"].get("confusion_matrix", {})
            self.tp = cm.get("tp", 0)
            self.fp = cm.get("fp", 0)
            self.tn = cm.get("tn", 0)
            self.fn = cm.get("fn", 0)


# Global tracker instance
_tracker = MetricsTracker()


def get_tracker() -> MetricsTracker:
    """Get the global metrics tracker instance."""
    return _tracker


def update_metrics(
    risk_score: float,
    ground_truth: str,
    url: str,
    confidence: float = 1.0,
    attack_type: Optional[str] = None,
    indicators: Optional[List[str]] = None,
    analysis_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience function to update global tracker."""
    return _tracker.update_metrics(
        risk_score=risk_score,
        ground_truth=ground_truth,  # type: ignore
        url=url,
        confidence=confidence,
        attack_type=attack_type,
        indicators=indicators,
        analysis_details=analysis_details,
    )
