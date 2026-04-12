"""
Grader for Task 1 — SSH Brute Force Detection (Easy).

Scoring formula:
  0.35 × verdict_correct
  0.30 × evidence_quality
  0.20 × response_quality
  0.15 × efficiency

Evidence quality checks:
 - Pulled auth.log (the key log source)
 - Queried IP reputation for the attacker IP
"""

from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader1(BaseGrader):
    """
    Task 1 — SSH Brute Force
    0.35 × verdict + 0.30 × evidence + 0.20 × response + 0.15 × efficiency
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        # Verdict correctness (0 or 1)
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0

        # Evidence quality (0.0–1.0)
        evidence = self._evidence_quality(state, ground_truth)

        # Response quality — reason mentions brute force / SSH keywords
        response = self._response_quality(state, ground_truth)

        # Efficiency
        efficiency = self._efficiency_score(state)

        final = round(
            0.35 * verdict_score +
            0.30 * evidence +
            0.20 * response +
            0.15 * efficiency,
            4
        )
        return max(0.001, min(0.999, final))