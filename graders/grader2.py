from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader2(BaseGrader):
    """
    Task 2 — Lateral Movement
    0.5 × correct_verdict + 0.3 × evidence_quality + 0.2 × avoided_red_herring
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0

        required = ground_truth.get("required_evidence", [])
        gathered = self._evidence_gathered(state, ground_truth)
        evidence_quality = round(len(gathered) / len(required), 4) if required else 0.0

        # Avoided red herring = agent did NOT blindly escalate without checking asset
        red_herring_ip = ground_truth.get("red_herring_ip", "")
        actions_taken = [a.action_type for a in state.actions_taken]
        checked_asset = "check_asset_criticality" in actions_taken
        avoided_red_herring = 1.0 if checked_asset else 0.0

        final = round(
            0.5 * verdict_score +
            0.3 * evidence_quality +
            0.2 * avoided_red_herring,
            4
        )
        return final