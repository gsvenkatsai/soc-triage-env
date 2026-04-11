"""
SOC Triage Environment — core environment logic.

Implements the OpenEnv-compatible interface:
  - reset(task_id, seed) → initial observation
  - step(action_str)     → (observation, reward, done, info)
  - state_dict()         → full internal state for grading
"""

from uuid import uuid4
from environment.models import (
    SOCState, SOCObservation, ActionRecord, AlertSummary, Severity,
    AVAILABLE_ACTIONS,
)
from environment.simulator import Simulator
from environment.reward import compute_reward


class SOCEnvironment:
    """
    SOC Alert Triage environment.

    The agent investigates security alerts by taking investigative actions,
    gathering evidence, and submitting a verdict (escalate / close).
    """

    def __init__(self):
        self.state: SOCState = None
        self.ground_truth: dict = None
        self.done: bool = False
        self.simulator: Simulator = None
        self._episode_id: str = ""

    def reset(self, task_id: int = 1, seed: int = 42) -> SOCObservation:
        """
        Reset the environment to a fresh episode.

        Args:
            task_id: Which task to load (1, 2, or 3)
            seed: Random seed for reproducibility

        Returns:
            Initial observation
        """
        self.simulator = Simulator(seed=seed)
        self.done = False
        self._episode_id = str(uuid4())

        from tasks.task1_ssh_bruteforce import get_task as task1
        from tasks.task2_lateral_movement import get_task as task2
        from tasks.task3_apt_killchain import get_task as task3

        task_map = {1: task1, 2: task2, 3: task3}
        task_fn = task_map.get(task_id)
        if not task_fn:
            raise ValueError(f"Unknown task_id: {task_id}. Must be 1, 2, or 3.")

        task_data = task_fn(seed=seed)
        self.state = task_data["scenario"]
        self.state.episode_id = self._episode_id
        self.ground_truth = task_data["ground_truth"]

        return self._make_observation("Episode started. Investigate the alert and submit a verdict.")

    def step(self, action_str: str):
        """
        Execute one action in the environment.

        Args:
            action_str: Action string (e.g., "pull_logs auth.log")

        Returns:
            (observation, reward, done, info) tuple
        """
        if self.done:
            raise RuntimeError("Episode is done. Call reset() first.")

        if not action_str or not action_str.strip():
            # Invalid empty action
            obs = self._make_observation("Error: Empty action. Provide a valid action string.")
            return obs, -0.05, False, {"error": "empty_action"}

        action_type, parameters, result = self._execute_action(action_str.strip())

        action_record = ActionRecord(
            action_type=action_type,
            parameters=parameters,
            result=result,
            step=self.state.step_count,
        )

        # Compute reward BEFORE appending action (state reflects pre-action)
        reward, reward_components = compute_reward(self.state, action_record, self.ground_truth)

        # Now update state
        self.state.actions_taken.append(action_record)
        self.state.step_count += 1

        # Check terminal conditions
        if action_type in ("escalate", "escalate_critical", "close_false_positive"):
            self.state.verdict = action_type
            self.state.done = True
            self.done = True
        elif self.state.step_count >= self.state.max_steps:
            self.state.done = True
            self.done = True

        obs = self._make_observation(result)
        info = {
            "action_type": action_type,
            "parameters": parameters,
            "reward_components": reward_components,
        }
        return obs, round(reward, 4), self.done, info

    def state_dict(self) -> SOCState:
        """Return the full internal state for grading."""
        return self.state

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _execute_action(self, action_str: str):
        """Parse and execute an action string."""
        parts = action_str.strip().split(" ", 1)
        action_type = parts[0]
        arg = parts[1] if len(parts) > 1 else ""

        # Build context from ground truth for the simulator
        context = self.ground_truth.get("context", {})

        if action_type == "pull_logs":
            logs = self.simulator.pull_logs(arg, context)
            result = "\n".join(logs)
            return action_type, {"source": arg}, result

        elif action_type == "query_ip_reputation":
            rep = self.simulator.query_ip_reputation(arg)
            parts_list = [
                f"IP: {arg}",
                f"Reputation Score: {rep['score']}/100",
                f"Malicious: {rep['malicious']}",
                f"Tags: {', '.join(rep.get('tags', []))}",
                f"Country: {rep.get('country', 'unknown')}",
                f"Threat Type: {rep.get('threat_type', 'none')}",
                f"Reports: {rep.get('reports', 0)}",
            ]
            result = " | ".join(parts_list)
            return action_type, {"ip": arg}, result

        elif action_type == "check_asset_criticality":
            info = self.simulator.check_asset_criticality(arg)
            if "error" in info:
                result = info["error"]
            else:
                result = (
                    f"Asset: {info['hostname']} ({info['asset_id']}) | "
                    f"IP: {info['ip']} | Criticality: {info['criticality']} | "
                    f"Owner: {info['owner']} | Department: {info['department']} | "
                    f"OS: {info['os']}"
                )
            return action_type, {"asset_id": arg}, result

        elif action_type == "correlate_alerts":
            window = int(arg) if arg.isdigit() else 60
            alerts = self.simulator.correlate_alerts(window, {
                **context,
                "kill_chain": self.ground_truth.get("kill_chain", []),
            })
            result = "\n".join(alerts)
            return action_type, {"window_minutes": str(window)}, result

        elif action_type == "lookup_user":
            user = self.simulator.lookup_user(arg)
            if "error" in user:
                result = user["error"]
            else:
                parts_list = [f"{k}: {v}" for k, v in user.items()]
                result = " | ".join(parts_list)
            return action_type, {"username": arg}, result

        elif action_type == "isolate_host":
            info = self.simulator.isolate_host(arg)
            result = f"[CONTAINMENT] {info.get('status', 'unknown')}: {info.get('warning', info.get('reason', ''))}"
            return action_type, {"hostname": arg}, result

        elif action_type == "block_ip":
            info = self.simulator.block_ip(arg)
            result = f"[CONTAINMENT] {info.get('status', 'unknown')}: {info.get('message', '')}"
            return action_type, {"ip": arg}, result

        elif action_type in ("escalate", "escalate_critical", "close_false_positive"):
            result = f"Verdict submitted: {action_type} — {arg}"
            return action_type, {"reason": arg}, result

        else:
            result = (
                f"Unknown action: '{action_type}'. "
                f"Valid actions: pull_logs, query_ip_reputation, check_asset_criticality, "
                f"correlate_alerts, lookup_user, isolate_host, block_ip, "
                f"escalate, escalate_critical, close_false_positive"
            )
            return action_type, {"raw": arg}, result

    def _make_observation(self, last_result: str) -> SOCObservation:
        """Construct an observation from current state."""
        return SOCObservation(
            alert=self.state.alert_summary,
            last_action_result=last_result,
            available_actions=list(AVAILABLE_ACTIONS),
            step_count=self.state.step_count,
            max_steps=self.state.max_steps,
            context_gathered=[a.result for a in self.state.actions_taken],
            done=self.done,
        )