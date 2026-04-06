from environment.models import SOCState, SOCObservation, Action, AlertSummary, Severity
from environment.simulator import Simulator
from environment.reward import compute_reward
from datetime import datetime


AVAILABLE_ACTIONS = [
    "pull_logs <source>",
    "query_ip_reputation <ip>",
    "check_asset_criticality <asset_id>",
    "correlate_alerts <window_minutes>",
    "lookup_user <username>",
    "escalate <reason>",
    "escalate_critical <reason>",
    "close_false_positive <reason>",
]


class SOCEnvironment:
    def __init__(self):
        self.state: SOCState = None
        self.ground_truth: dict = None
        self.done: bool = False
        self.simulator: Simulator = None

    def reset(self, task_id: int, seed: int = 42) -> SOCObservation:
        self.simulator = Simulator(seed=seed)
        self.done = False

        from tasks.task1_ssh_bruteforce import get_task as task1
        from tasks.task2_lateral_movement import get_task as task2
        from tasks.task3_apt_killchain import get_task as task3

        task_map = {1: task1, 2: task2, 3: task3}
        task_fn = task_map.get(task_id)
        if not task_fn:
            raise ValueError(f"Unknown task_id: {task_id}")

        task_data = task_fn(seed=seed)
        self.state = task_data["scenario"]
        self.ground_truth = task_data["ground_truth"]

        return self._make_observation("Episode started. Investigate the alert.")

    def step(self, action_str: str):
        if self.done:
            raise RuntimeError("Episode is done. Call reset() first.")

        action_type, parameters, result = self._execute_action(action_str)

        action = Action(
            action_type=action_type,
            parameters=parameters,
            result=result,
            step=self.state.step_count,
        )

        reward = compute_reward(self.state, action, self.ground_truth)

        # Append action AFTER reward computation (state reflects pre-action)
        self.state.actions_taken.append(action)
        self.state.step_count += 1

        # Check terminal conditions
        if action_type in ("escalate", "escalate_critical", "close_false_positive"):
            self.state.verdict = action_type
            self.done = True
        elif self.state.step_count >= self.state.max_steps:
            self.done = True

        obs = self._make_observation(result)
        info = {"action_type": action_type, "parameters": parameters}
        return obs, reward, self.done, info

    def state_dict(self) -> SOCState:
        return self.state

    def _execute_action(self, action_str: str):
        parts = action_str.strip().split(" ", 1)
        action_type = parts[0]
        arg = parts[1] if len(parts) > 1 else ""

        context = {
            "timestamp": self.state.timestamp.isoformat(),
            "correlated_alerts": self.ground_truth.get("kill_chain", []),
        }

        if action_type == "pull_logs":
            logs = self.simulator.pull_logs(arg, context)
            result = "\n".join(logs)
            return action_type, {"source": arg}, result

        elif action_type == "query_ip_reputation":
            rep = self.simulator.query_ip_reputation(arg)
            result = f"IP {arg} — score: {rep['score']}, tags: {rep['tags']}, malicious: {rep['malicious']}"
            return action_type, {"ip": arg}, result

        elif action_type == "check_asset_criticality":
            info = self.simulator.check_asset_criticality(arg)
            result = str(info)
            return action_type, {"asset_id": arg}, result

        elif action_type == "correlate_alerts":
            alerts = self.simulator.correlate_alerts(int(arg) if arg.isdigit() else 60, context)
            result = "\n".join(alerts)
            return action_type, {"window_minutes": arg}, result

        elif action_type == "lookup_user":
            user = self.simulator.lookup_user(arg)
            result = str(user)
            return action_type, {"username": arg}, result

        elif action_type in ("escalate", "escalate_critical", "close_false_positive"):
            result = f"Verdict submitted: {action_type} — {arg}"
            return action_type, {"reason": arg}, result

        else:
            result = f"Unknown action: {action_type}"
            return action_type, {}, result

    def _make_observation(self, last_result: str) -> SOCObservation:
        return SOCObservation(
            alert=self.state.alert_summary,
            last_action_result=last_result,
            available_actions=AVAILABLE_ACTIONS,
            step_count=self.state.step_count,
            context_gathered=[a.result for a in self.state.actions_taken],
        )