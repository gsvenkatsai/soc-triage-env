"""
Grader for Task 2 — Lateral Movement Investigation (Medium).

Scoring formula:
  0.30 × verdict_correct
  0.25 × evidence_quality
  0.25 × red_herring_handling
  0.20 × efficiency

Red herring handling:
 - Agent checked asset criticality (to identify scanner)
 - Agent did NOT blindly escalate without investigation
"""

from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader2(BaseGrader):
    """
    Task 2 — Lateral Movement
    0.30 × verdict + 0.25 × evidence + 0.25 × red_herring + 0.20 × efficiency
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        # Verdict correctness
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0

        # Evidence quality
        evidence = self._evidence_quality(state, ground_truth)

        # Red herring handling — did agent investigate before escalating?
        red_herring_score = self._compute_red_herring_score(state, ground_truth)

        # Efficiency
        efficiency = self._efficiency_score(state)

        final = round(
            0.30 * verdict_score +
            0.25 * evidence +
            0.25 * red_herring_score +
            0.20 * efficiency,
            4
        )
        return max(0.001, min(0.999, final))

    def _compute_red_herring_score(self, state: SOCState, ground_truth: dict) -> float:
        """
        Score how well the agent handled the red herring.

        Full score if:
        - Checked asset criticality for the scanner (vuln-scanner-01 / A005)
        - Pulled network logs to see scanner traffic
        - Did NOT just immediately escalate
        """
        score = 0.0
        red_herring_assets = ground_truth.get("red_herring_assets", [])

        # Did agent check any asset criticality?
        checked_any_asset = self._action_type_taken(state, "check_asset_criticality")
        if checked_any_asset:
            score += 0.4

        # Did agent specifically check the red herring asset?
        if red_herring_assets:
            checked_red_herring = self._action_with_param(
                state, "check_asset_criticality", "asset_id", red_herring_assets
            )
            if checked_red_herring:
                score += 0.3

        # Did agent pull network logs?
        pulled_network = self._action_with_param(
            state, "pull_logs", "source", ["network.log"]
        )
        if pulled_network:
            score += 0.3

        return min(1.0, score)