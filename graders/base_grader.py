"""
Base grader with shared helper methods for all task graders.

Graders produce deterministic scores in [0.0, 1.0] based on the
final episode state and ground truth.
"""

from environment.models import SOCState
from typing import Dict, List, Any


class BaseGrader:
    """Base class for task graders."""

    def score(self, state: SOCState, ground_truth: dict) -> float:
        """Compute a score in [0.0, 1.0]. Override in subclasses."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _verdict_correct(self, state: SOCState, ground_truth: dict) -> bool:
        """Check if the agent submitted the correct verdict."""
        return state.verdict == ground_truth.get("correct_verdict")

    def _evidence_gathered_count(self, state: SOCState, ground_truth: dict) -> int:
        """Count how many required evidence items were gathered (parameter-aware)."""
        required = ground_truth.get("required_evidence", [])
        count = 0
        for req in required:
            req_type = req.get("action_type", "") if isinstance(req, dict) else req
            req_params = req.get("parameters", {}) if isinstance(req, dict) else {}
            for taken in state.actions_taken:
                if taken.action_type == req_type:
                    if not req_params:
                        count += 1
                        break
                    if all(taken.parameters.get(k) == v for k, v in req_params.items()):
                        count += 1
                        break
        return count

    def _evidence_quality(self, state: SOCState, ground_truth: dict) -> float:
        """Ratio of required evidence gathered (0.0–1.0)."""
        required = ground_truth.get("required_evidence", [])
        if not required:
            return 0.0
        gathered = self._evidence_gathered_count(state, ground_truth)
        return round(min(1.0, gathered / len(required)), 4)

    def _response_quality(self, state: SOCState, ground_truth: dict) -> float:
        """
        Score the quality of the escalation reason (0.0–1.0).
        Checks if the reason mentions relevant keywords.
        """
        keywords = ground_truth.get("escalation_keywords", [])
        if not keywords or not state.verdict:
            return 0.0

        # Find the verdict action
        reason = ""
        for action in state.actions_taken:
            if action.action_type in ("escalate", "escalate_critical", "close_false_positive"):
                reason = action.parameters.get("reason", "")
                break

        if not reason:
            return 0.0

        reason_lower = reason.lower()
        matched = sum(1 for kw in keywords if kw.lower() in reason_lower)
        # Require at least 2 keyword matches for full score
        return round(min(1.0, matched / min(3, len(keywords))), 4)

    def _efficiency_score(self, state: SOCState) -> float:
        """
        Score based on step efficiency (0.0–1.0).
        Fewer steps = higher score. Using all max_steps = 0.0.
        """
        used = state.step_count
        max_s = state.max_steps
        if max_s <= 0:
            return 0.0
        return round(max(0.0, 1.0 - (used / max_s)), 4)

    def _action_type_taken(self, state: SOCState, action_type: str) -> bool:
        """Check if a specific action type was taken during the episode."""
        return any(a.action_type == action_type for a in state.actions_taken)

    def _action_with_param(self, state: SOCState, action_type: str, param_key: str, param_values: list) -> bool:
        """Check if an action with specific parameter value was taken."""
        for action in state.actions_taken:
            if action.action_type == action_type:
                val = action.parameters.get(param_key, "")
                if val in param_values:
                    return True
        return False