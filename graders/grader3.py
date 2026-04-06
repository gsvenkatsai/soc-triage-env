from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader3(BaseGrader):
    """
    Task 3 — APT Kill Chain
    0.4 × correct_verdict + 0.4 × correlation_step_taken + 0.2 × kill_chain_identified
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0

        actions_taken = [a.action_type for a in state.actions_taken]
        correlation_taken = 1.0 if "correlate_alerts" in actions_taken else 0.0

        kill_chain = ground_truth.get("kill_chain") or []
        if kill_chain and "correlate_alerts" in actions_taken:
            kill_chain_identified = 1.0
        else:
            kill_chain_identified = 0.0

        final = round(
            0.4 * verdict_score +
            0.4 * correlation_taken +
            0.2 * kill_chain_identified,
            4
        )
        return final