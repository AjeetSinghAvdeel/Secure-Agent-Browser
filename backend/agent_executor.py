from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

try:
    import agent_runtime
except Exception:  # pragma: no cover - package import fallback
    from . import agent_runtime  # type: ignore


@dataclass
class AgentStep:
    step: int
    current_url: str
    page_title: str
    proposed_action: Dict[str, Any]
    mediation: Dict[str, Any]
    executed: bool
    completion_reason: str = ""
    observations: Dict[str, Any] = field(default_factory=dict)


class ProtectedAutonomousAgent:
    def __init__(
        self,
        *,
        scan_callback: Callable[[str, Dict[str, Any] | None], Dict[str, Any]],
        mediate_callback: Callable[[str, Dict[str, Any], Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        self._scan_callback = scan_callback
        self._mediate_callback = mediate_callback

    def _create_driver(self) -> webdriver.Chrome:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1200")
        options.add_argument("--disable-blink-features=AutomationControlled")
        return webdriver.Chrome(options=options)

    def _visible_text(self, driver: webdriver.Chrome) -> str:
        try:
            body = driver.find_element(By.TAG_NAME, "body")
            return " ".join((body.text or "").split())[:8000]
        except Exception:
            return ""

    def _extract_actionables(self, driver: webdriver.Chrome) -> Dict[str, Any]:
        buttons: List[Dict[str, str]] = []
        inputs: List[Dict[str, str]] = []
        links: List[Dict[str, str]] = []

        try:
            for element in driver.find_elements(By.CSS_SELECTOR, "button, [role='button'], input[type='submit']")[:12]:
                label = (element.text or element.get_attribute("value") or element.get_attribute("aria-label") or "").strip()
                if label:
                    buttons.append({"label": label[:80], "tag": element.tag_name})
        except Exception:
            pass

        try:
            for element in driver.find_elements(By.CSS_SELECTOR, "input, textarea")[:12]:
                label = (
                    element.get_attribute("aria-label")
                    or element.get_attribute("placeholder")
                    or element.get_attribute("name")
                    or element.get_attribute("id")
                    or ""
                ).strip()
                input_type = (element.get_attribute("type") or "text").strip().lower()
                inputs.append({"label": label[:80], "type": input_type})
        except Exception:
            pass

        try:
            for element in driver.find_elements(By.CSS_SELECTOR, "a[href]")[:12]:
                label = (element.text or element.get_attribute("aria-label") or "").strip()
                href = (element.get_attribute("href") or "").strip()
                if label or href:
                    links.append({"label": label[:80], "href": href[:160]})
        except Exception:
            pass

        return {"buttons": buttons, "inputs": inputs, "links": links}

    def _page_context(self, driver: webdriver.Chrome) -> Dict[str, Any]:
        actionables = self._extract_actionables(driver)
        detected_patterns: List[str] = []
        if any(item["type"] == "password" for item in actionables["inputs"]):
            detected_patterns.append("misleading_forms")
        return {
            "detected_patterns": detected_patterns,
            "page_text_excerpt": self._visible_text(driver),
            "actionables": actionables,
        }

    def _is_goal_complete(self, goal_summary: Dict[str, Any], actionables: Dict[str, Any]) -> bool:
        if goal_summary.get("read_only"):
            return True
        if goal_summary.get("authenticate"):
            return any(item["type"] == "password" for item in actionables["inputs"])
        if goal_summary.get("download"):
            return any("download" in (item.get("label", "").lower()) for item in actionables["buttons"] + actionables["links"])
        return False

    def _choose_action(
        self,
        *,
        user_goal: str,
        page_text: str,
        current_url: str,
        page_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        plan = agent_runtime.MockWebAgent().plan(
            user_goal=user_goal,
            page_text=page_text,
            page_url=current_url,
            page_context=page_context,
        )
        proposed = dict(plan.get("proposed_action") or {})
        actionables = page_context.get("actionables", {})

        if proposed.get("type") == "click":
            for candidate in actionables.get("buttons", []) + actionables.get("links", []):
                if candidate.get("label"):
                    proposed["target_text"] = candidate["label"]
                    break

        if proposed.get("type") == "type":
            sensitive_input = next(
                (item for item in actionables.get("inputs", []) if item.get("type") in {"password", "email"}),
                None,
            )
            if sensitive_input:
                proposed["target_text"] = sensitive_input.get("label") or sensitive_input.get("type")
                proposed["input_type"] = sensitive_input.get("type")
            else:
                first_input = next(iter(actionables.get("inputs", [])), None)
                if first_input:
                    proposed["target_text"] = first_input.get("label") or "input"
                    proposed["input_type"] = first_input.get("type")

        proposed["planner"] = plan
        return proposed

    def _execute_action(self, driver: webdriver.Chrome, action: Dict[str, Any]) -> bool:
        action_type = str(action.get("type") or "").lower()
        target_text = str(action.get("target_text") or "").strip().lower()

        if action_type == "navigate":
            return True

        if action_type == "click":
            elements = driver.find_elements(By.CSS_SELECTOR, "button, [role='button'], a[href], input[type='submit']")
            for element in elements:
                label = (
                    element.text
                    or element.get_attribute("value")
                    or element.get_attribute("aria-label")
                    or ""
                ).strip().lower()
                if target_text and target_text not in label:
                    continue
                try:
                    element.click()
                    return True
                except Exception:
                    continue
            return False

        if action_type == "type":
            fields = driver.find_elements(By.CSS_SELECTOR, "input, textarea")
            for field in fields:
                field_type = (field.get_attribute("type") or "text").lower()
                label = (
                    field.get_attribute("aria-label")
                    or field.get_attribute("placeholder")
                    or field.get_attribute("name")
                    or field.get_attribute("id")
                    or ""
                ).strip().lower()
                if target_text and target_text not in label and target_text not in field_type:
                    continue
                try:
                    field.clear()
                    field.send_keys(str(action.get("value") or "demo-input"))
                    return True
                except Exception:
                    continue
            return False

        return False

    def execute(
        self,
        *,
        user_goal: str,
        start_url: str,
        max_steps: int = 5,
    ) -> Dict[str, Any]:
        driver = None
        trajectory: List[AgentStep] = []
        try:
            driver = self._create_driver()
            driver.set_page_load_timeout(float(os.getenv("SECUREAGENT_AGENT_TIMEOUT_SECONDS", "12")))
            driver.get(start_url)

            for step_number in range(1, max_steps + 1):
                current_url = driver.current_url or start_url
                page_title = driver.title or ""
                page_context = self._page_context(driver)
                page_text = page_context.get("page_text_excerpt", "")
                goal_summary = agent_runtime.summarize_goal(user_goal)

                if self._is_goal_complete(goal_summary, page_context.get("actionables", {})):
                    trajectory.append(
                        AgentStep(
                            step=step_number,
                            current_url=current_url,
                            page_title=page_title,
                            proposed_action={"type": "complete"},
                            mediation={"decision": "ALLOW", "reason": "Goal conditions satisfied"},
                            executed=False,
                            completion_reason="goal_reached",
                            observations=page_context,
                        )
                    )
                    break

                proposed_action = self._choose_action(
                    user_goal=user_goal,
                    page_text=page_text,
                    current_url=current_url,
                    page_context=page_context,
                )
                scan_result = self._scan_callback(current_url, page_context)
                mediation = self._mediate_callback(user_goal, scan_result, proposed_action)
                decision = str(mediation.get("decision", "WARN")).upper()

                if decision not in {"ALLOW", "REQUIRE_CONFIRMATION"}:
                    trajectory.append(
                        AgentStep(
                            step=step_number,
                            current_url=current_url,
                            page_title=page_title,
                            proposed_action=proposed_action,
                            mediation=mediation,
                            executed=False,
                            completion_reason="blocked_by_secureagent",
                            observations=page_context,
                        )
                    )
                    break

                executed = self._execute_action(driver, proposed_action)
                trajectory.append(
                    AgentStep(
                        step=step_number,
                        current_url=current_url,
                        page_title=page_title,
                        proposed_action=proposed_action,
                        mediation=mediation,
                        executed=executed,
                        completion_reason="" if executed else "execution_failed",
                        observations=page_context,
                    )
                )
                if not executed:
                    break
        except WebDriverException as exc:
            return {
                "status": "error",
                "error": f"Agent browser runtime unavailable: {exc}",
                "trajectory": [step.__dict__ for step in trajectory],
            }
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception:
                    pass

        final_status = "completed"
        if trajectory and trajectory[-1].completion_reason in {"blocked_by_secureagent", "execution_failed"}:
            final_status = trajectory[-1].completion_reason

        return {
            "status": final_status,
            "final_url": trajectory[-1].current_url if trajectory else start_url,
            "steps_executed": len(trajectory),
            "trajectory": [step.__dict__ for step in trajectory],
        }
