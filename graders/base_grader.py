from environment.models import SOCState


class BaseGrader:
    def score(self, state: SOCState, ground_truth: dict) -> float:
        raise NotImplementedError

    def _verdict_correct(self, state: SOCState, ground_truth: dict) -> bool:
        return state.verdict == ground_truth.get("correct_verdict")

    def _evidence_gathered(self, state: SOCState, ground_truth: dict) -> list:
        required = ground_truth.get("required_evidence", [])
        taken = [a.action_type for a in state.actions_taken]
        return [e for e in required if e in taken]

    def _efficiency_score(self, state: SOCState) -> float:
        # Fewer steps = higher bonus. Max steps = 0.0, 3 steps = 1.0
        used = state.step_count
        max_s = state.max_steps
        return round(max(0.0, 1.0 - (used / max_s)), 4)