from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader1(BaseGrader):
    """
    Task 1 — SSH Brute Force
    0.6 × correct_verdict + 0.4 × efficiency_score
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0
        efficiency = self._efficiency_score(state)
        final = round(0.6 * verdict_score + 0.4 * efficiency, 4)
        return final