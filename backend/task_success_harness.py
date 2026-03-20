"""
Task Success Rate Measurement Framework
========================================

Evaluate SecureAgent impact on user task completion rates.

Measures:
- Success rate WITHOUT protection
- Success rate WITH protection
- Task success definition and verification
- Benign and malicious task scenarios
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import json
import time


class TaskType(str, Enum):
    """Types of tasks to measure"""
    LOGIN = "login"
    FORM_SUBMISSION = "form_submission"
    NAVIGATION = "navigation"
    DATA_ENTRY = "data_entry"
    PAYMENT = "payment"
    SEARCH = "search"


class TaskThreat(str, Enum):
    """Task threat level"""
    BENIGN = "benign"
    MALICIOUS = "malicious"


class OutcomeStatus(str, Enum):
    """Task outcome status"""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"  # Blocked by SecureAgent (beneficial)
    INTERRUPTED = "interrupted"  # User stopped before completion


@dataclass
class TaskScenario:
    """Definition of a task scenario"""
    id: str
    name: str
    type: TaskType
    threat_level: TaskThreat
    description: str
    steps: List[str]
    success_criteria: List[str]
    malicious_indicators: Optional[List[str]] = None


@dataclass
class TaskExecution:
    """Record of a single task execution"""
    id: str
    scenario_id: str
    timestamp: str
    secure_agent_enabled: bool
    outcome: OutcomeStatus
    duration_seconds: float
    success: bool  # Whether task objective was met
    user_blocked: int = 0  # Number of times user was warned/blocked
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskSuccessMetrics:
    """Aggregated success metrics"""
    timestamp: str
    without_agent: float  # Success rate % without SecureAgent
    with_agent: float  # Success rate % with SecureAgent
    total_without: int  # Total tasks run without agent
    total_with: int  # Total tasks run with agent
    successful_without: int
    successful_with: int
    completion_time_without_avg: float  # Average time in seconds
    completion_time_with_avg: float
    blocked_attempts: int  # Malicious attempts blocked
    improvement_percentage: float  # (with - without) / without * 100


class TaskSuccessHarness:
    """
    Framework for measuring task success rates with/without SecureAgent.
    
    Usage:
        harness = TaskSuccessHarness()
        harness.add_scenario("login_benign", TaskScenario(...))
        harness.run_task("login_benign", secure_agent_enabled=False)
        harness.run_task("login_benign", secure_agent_enabled=True)
        metrics = harness.compute_metrics()
    """

    def __init__(self):
        self.scenarios: Dict[str, TaskScenario] = {}
        self.executions: List[TaskExecution] = []
        self._execution_id_counter: int = 0

    def add_scenario(self, scenario: TaskScenario) -> None:
        """Register a task scenario."""
        self.scenarios[scenario.id] = scenario

    def register_default_scenarios(self) -> None:
        """Register common test scenarios."""
        scenarios = [
            # BENIGN SCENARIOS
            TaskScenario(
                id="benign_login",
                name="Normal Login - GitHub",
                type=TaskType.LOGIN,
                threat_level=TaskThreat.BENIGN,
                description="User logs into GitHub via official website",
                steps=[
                    "Navigate to github.com",
                    "Click 'Sign In' button",
                    "Enter credentials",
                    "Pass 2FA if enabled",
                    "Reach dashboard",
                ],
                success_criteria=[
                    "User authenticated",
                    "Dashboard accessible",
                    "No errors",
                ],
            ),
            TaskScenario(
                id="benign_form",
                name="Newsletter Signup - Medium",
                type=TaskType.FORM_SUBMISSION,
                threat_level=TaskThreat.BENIGN,
                description="User signs up for newsletter on Medium.com",
                steps=[
                    "Navigate to medium.com",
                    "Scroll to footer",
                    "Enter email in signup form",
                    "Click subscribe",
                    "Confirm subscription",
                ],
                success_criteria=[
                    "Form submitted successfully",
                    "Confirmation email received",
                    "No blocking warnings",
                ],
            ),
            TaskScenario(
                id="benign_payment",
                name="Legitimate Purchase - Amazon",
                type=TaskType.PAYMENT,
                threat_level=TaskThreat.BENIGN,
                description="User completes purchase on Amazon",
                steps=[
                    "Add item to cart",
                    "Proceed to checkout",
                    "Enter shipping address",
                    "Enter payment details",
                    "Complete purchase",
                ],
                success_criteria=[
                    "Order placed",
                    "Confirmation email received",
                    "Order tracking available",
                ],
            ),
            # MALICIOUS SCENARIOS
            TaskScenario(
                id="phishing_login",
                name="Phishing Attack - GitHub Clone",
                type=TaskType.LOGIN,
                threat_level=TaskThreat.MALICIOUS,
                description="Attacker phishing for GitHub credentials",
                steps=[
                    "User receives suspicious email link",
                    "Click link to fake github.com site",
                    "Site requests credentials",
                    "User unknowingly enters real credentials",
                ],
                success_criteria=["Attacker captures credentials"],
                malicious_indicators=[
                    "phishing_content_pattern",
                    "credential_harvest_form",
                    "suspicious_tld",
                ],
            ),
            TaskScenario(
                id="injection_attack",
                name="Prompt Injection Attack",
                type=TaskType.DATA_ENTRY,
                threat_level=TaskThreat.MALICIOUS,
                description="Attacker injects prompt injection code",
                steps=[
                    "Navigate to AI form field",
                    "Inject: 'ignore all previous instructions'",
                    "AI system compromised",
                ],
                success_criteria=["AI system jailbroken"],
                malicious_indicators=[
                    "prompt_injection_pattern",
                    "hidden_dom_element",
                ],
            ),
            TaskScenario(
                id="xss_attack",
                name="Cross-Site Scripting Attack",
                type=TaskType.FORM_SUBMISSION,
                threat_level=TaskThreat.MALICIOUS,
                description="Attacker submits XSS payload",
                steps=[
                    "Form with script tag injection",
                    "Payload executes on user machine",
                ],
                success_criteria=["Script executed"],
                malicious_indicators=[
                    "obfuscated_script_pattern",
                    "base64_blob",
                ],
            ),
        ]
        
        for scenario in scenarios:
            self.add_scenario(scenario)

    def run_task(
        self,
        scenario_id: str,
        secure_agent_enabled: bool,
        executor: Optional[Callable[..., bool]] = None,
        duration: Optional[float] = None,
    ) -> TaskExecution:
        """
        Execute a task scenario and record outcome.
        
        Args:
            scenario_id: ID of registered scenario
            secure_agent_enabled: Whether SecureAgent is running
            executor: Optional callable that runs the task and returns success boolean
            duration: Optional task duration in seconds (auto-measured if not provided)
            
        Returns:
            TaskExecution record
        """
        if scenario_id not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_id}")
        
        scenario = self.scenarios[scenario_id]
        self._execution_id_counter += 1
        exec_id = f"task_{self._execution_id_counter:06d}"
        
        # Execute task
        start_time = time.time()
        success = False
        outcome = OutcomeStatus.FAILURE
        reason = None
        
        if executor:
            try:
                success = executor(scenario, secure_agent_enabled)
                outcome = OutcomeStatus.SUCCESS if success else OutcomeStatus.FAILURE
            except Exception as e:
                reason = f"Exception: {str(e)}"
                success = False
                outcome = OutcomeStatus.FAILURE
        else:
            # Simulate task execution
            success, outcome, reason = self._simulate_task(
                scenario, secure_agent_enabled
            )
        
        if duration is None:
            duration = time.time() - start_time
        
        execution = TaskExecution(
            id=exec_id,
            scenario_id=scenario_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            secure_agent_enabled=secure_agent_enabled,
            outcome=outcome,
            duration_seconds=duration,
            success=success,
            reason=reason,
            details={
                "scenario_name": scenario.name,
                "task_type": scenario.type.value,
                "threat_level": scenario.threat_level.value,
            },
        )
        
        self.executions.append(execution)
        return execution

    def _simulate_task(
        self,
        scenario: TaskScenario,
        secure_agent_enabled: bool,
    ) -> tuple[bool, OutcomeStatus, Optional[str]]:
        """
        Simulate task execution based on scenario type and threat level.
        
        Benign tasks: High success rate (85-95%)
        Malicious without agent: Success depends on type, user fails to detect
        Malicious with agent: Agent blocks or warns, task fails (beneficial)
        """
        import random
        
        # Benign tasks
        if scenario.threat_level == TaskThreat.BENIGN:
            # Small chance of unrelated failure (network, UX issue)
            failure_chance = 0.05
            if random.random() < failure_chance:
                return False, OutcomeStatus.FAILURE, "Network timeout"
            return True, OutcomeStatus.SUCCESS, None
        
        # Malicious tasks
        if not secure_agent_enabled:
            # Without protection, user may fall for attack
            detection_chance = 0.25  # Users catch ~25% of obvious attacks
            if random.random() < detection_chance:
                return False, OutcomeStatus.FAILURE, "User noticed suspicious URL"
            return True, OutcomeStatus.SUCCESS, "User credentials compromised"
        
        # With SecureAgent protection
        block_chance = 0.95  # SecureAgent catches 95% of malicious attempts
        if random.random() < block_chance:
            return False, OutcomeStatus.BLOCKED, "Blocked by SecureAgent"
        
        # 5% get through (system gaps)
        return True, OutcomeStatus.SUCCESS, "Attack bypassed security"

    def compute_metrics(self) -> TaskSuccessMetrics:
        """
        Compute aggregated success metrics.
        
        Returns:
            TaskSuccessMetrics with success rates and comparison
        """
        without_agent = [e for e in self.executions if not e.secure_agent_enabled]
        with_agent = [e for e in self.executions if e.secure_agent_enabled]
        
        # Success rate calculation
        without_success = sum(1 for e in without_agent if e.success)
        with_success = sum(1 for e in with_agent if e.success)
        
        without_rate = (
            (without_success / len(without_agent) * 100)
            if without_agent else 0.0
        )
        with_rate = (
            (with_success / len(with_agent) * 100)
            if with_agent else 0.0
        )
        
        # Average completion time
        without_time = (
            sum(e.duration_seconds for e in without_agent) / len(without_agent)
            if without_agent else 0.0
        )
        with_time = (
            sum(e.duration_seconds for e in with_agent) / len(with_agent)
            if with_agent else 0.0
        )
        
        # Count blocked attempts
        blocked = sum(1 for e in with_agent if e.outcome == OutcomeStatus.BLOCKED)
        
        # Improvement percentage
        improvement = (
            (with_rate - without_rate) / without_rate * 100
            if without_rate > 0 else 0.0
        )
        
        return TaskSuccessMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            without_agent=round(without_rate, 2),
            with_agent=round(with_rate, 2),
            total_without=len(without_agent),
            total_with=len(with_agent),
            successful_without=without_success,
            successful_with=with_success,
            completion_time_without_avg=round(without_time, 2),
            completion_time_with_avg=round(with_time, 2),
            blocked_attempts=blocked,
            improvement_percentage=round(improvement, 2),
        )

    def get_detailed_report(self) -> Dict[str, Any]:
        """
        Generate detailed report with breakdown by scenario and threat level.
        
        Returns:
            Dictionary with comprehensive analysis
        """
        metrics = self.compute_metrics()
        
        # Breakdown by scenario
        scenario_stats: Dict[str, Dict[str, Any]] = {}
        for scenario_id, scenario in self.scenarios.items():
            execs = [e for e in self.executions if e.scenario_id == scenario_id]
            
            without = [e for e in execs if not e.secure_agent_enabled]
            with_agent = [e for e in execs if e.secure_agent_enabled]
            
            without_rate = (
                (sum(1 for e in without if e.success) / len(without) * 100)
                if without else 0.0
            )
            with_rate = (
                (sum(1 for e in with_agent if e.success) / len(with_agent) * 100)
                if with_agent else 0.0
            )
            
            scenario_stats[scenario_id] = {
                "name": scenario.name,
                "type": scenario.type.value,
                "threat": scenario.threat_level.value,
                "executions": len(execs),
                "without_agent_success_rate": round(without_rate, 2),
                "with_agent_success_rate": round(with_rate, 2),
                "improvement_percentage": round(
                    (with_rate - without_rate) / without_rate * 100 if without_rate > 0 else 0, 2
                ),
            }
        
        # Threat level analysis
        benign_execs = [e for e in self.executions 
                       if self.scenarios[e.scenario_id].threat_level == TaskThreat.BENIGN]
        malicious_execs = [e for e in self.executions 
                          if self.scenarios[e.scenario_id].threat_level == TaskThreat.MALICIOUS]
        
        benign_with_agent = [e for e in benign_execs if e.secure_agent_enabled]
        malicious_with_agent = [e for e in malicious_execs if e.secure_agent_enabled]
        
        return {
            "summary": asdict(metrics),
            "by_scenario": scenario_stats,
            "benign_tasks": {
                "total": len(benign_execs),
                "success_rate_with_agent": round(
                    (sum(1 for e in benign_with_agent if e.success) / len(benign_with_agent) * 100)
                    if benign_with_agent else 0, 2
                ),
                "note": "Should be ~95%+. Drop indicates poor UX or false positives.",
            },
            "malicious_tasks": {
                "total": len(malicious_execs),
                "blocked_count": sum(1 for e in malicious_with_agent if e.outcome == OutcomeStatus.BLOCKED),
                "block_rate": round(
                    (sum(1 for e in malicious_with_agent if e.outcome == OutcomeStatus.BLOCKED) 
                     / len(malicious_with_agent) * 100)
                    if malicious_with_agent else 0, 2
                ),
                "note": "Should be 90%+. Track gaps where attacks slip through.",
            },
            "usability_impact": {
                "completion_time_impact_percent": round(
                    (metrics.completion_time_with_avg - metrics.completion_time_without_avg) 
                    / metrics.completion_time_without_avg * 100
                    if metrics.completion_time_without_avg > 0 else 0, 2
                ),
                "note": "Should be <5%. Larger values indicate performance issues.",
            },
        }

    def export_report(self, filepath: Optional[str] = None) -> str:
        """
        Export detailed report to JSON.
        
        Args:
            filepath: Optional file path to save to
            
        Returns:
            JSON string
        """
        report = self.get_detailed_report()
        executions = [asdict(e) for e in self.executions]
        
        export_data = {
            "report": report,
            "executions": executions,
            "scenarios": {
                id: {
                    "name": s.name,
                    "type": s.type.value,
                    "threat_level": s.threat_level.value,
                    "description": s.description,
                    "steps": s.steps,
                    "success_criteria": s.success_criteria,
                }
                for id, s in self.scenarios.items()
            },
        }
        
        json_str = json.dumps(export_data, indent=2, default=str)
        
        if filepath:
            import os
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            with open(filepath, "w") as f:
                f.write(json_str)
        
        return json_str

    def get_success_table(self) -> List[Dict[str, Any]]:
        """
        Get success metrics in table format.
        
        Returns:
            List of dicts suitable for rendering as table
        """
        rows = []
        for scenario_id, scenario in self.scenarios.items():
            execs = [e for e in self.executions if e.scenario_id == scenario_id]
            
            without = [e for e in execs if not e.secure_agent_enabled]
            with_agent = [e for e in execs if e.secure_agent_enabled]
            
            without_rate = (
                (sum(1 for e in without if e.success) / len(without) * 100)
                if without else "N/A"
            )
            with_rate = (
                (sum(1 for e in with_agent if e.success) / len(with_agent) * 100)
                if with_agent else "N/A"
            )
            
            rows.append({
                "scenario": scenario.name,
                "threat": scenario.threat_level.value.upper(),
                "without": f"{without_rate:.1f}%" if isinstance(without_rate, float) else without_rate,
                "with": f"{with_rate:.1f}%" if isinstance(with_rate, float) else with_rate,
                "count": f"{len(without)} / {len(with_agent)}",
            })
        
        return rows
