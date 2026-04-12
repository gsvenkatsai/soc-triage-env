"""
Grader for Task 3 — APT Kill Chain (Hard).

Scoring formula:
  0.30 × verdict_correct (must be escalate_critical, not just escalate)
  0.30 × kill_chain_coverage
  0.25 × correlation_quality
  0.15 × response_quality

Kill chain coverage: fraction of kill chain stages evidenced:
  - Pulled email.log (initial access / phishing)
  - Pulled endpoint.log (credential theft / execution)
  - Queried C2 IP reputation (exfiltration)
  - Looked up compromised user (attribution)

Correlation quality: performed alert correlation with adequate window.
"""

from graders.base_grader import BaseGrader
from environment.models import SOCState


class Grader3(BaseGrader):
    """
    Task 3 — APT Kill Chain
    0.30 × verdict + 0.30 × kill_chain + 0.25 × correlation + 0.15 × response
    """

    def score(self, state: SOCState, ground_truth: dict) -> float:
        # Verdict — must be escalate_critical (not just escalate)
        verdict_score = 1.0 if self._verdict_correct(state, ground_truth) else 0.0

        # Kill chain coverage — multiple evidence sources checked
        kill_chain = self._compute_kill_chain_coverage(state, ground_truth)

        # Correlation quality
        correlation = self._compute_correlation_quality(state, ground_truth)

        # Response quality — escalation reason mentions APT / kill chain keywords
        response = self._response_quality(state, ground_truth)

        final = round(
            0.30 * verdict_score +
            0.30 * kill_chain +
            0.25 * correlation +
            0.15 * response,
            4
        )
        return max(0.001, min(0.999, final))

    def _compute_kill_chain_coverage(self, state: SOCState, ground_truth: dict) -> float:
        """
        Score how many kill chain stages the agent investigated.

        Checks (each worth 0.25):
        1. Pulled email.log (initial access — phishing)
        2. Pulled endpoint.log (execution — mimikatz)
        3. Queried C2 IP reputation
        4. Looked up compromised user OR pulled network.log
        """
        stages_found = 0
        total_stages = 4

        # Stage 1: email.log (phishing evidence)
        has_email_log = self._action_with_param(
            state, "pull_logs", "source", ["email.log"]
        )
        if has_email_log:
            stages_found += 1

        # Stage 2: endpoint.log (credential theft / execution)
        has_endpoint_log = self._action_with_param(
            state, "pull_logs", "source", ["endpoint.log"]
        )
        if has_endpoint_log:
            stages_found += 1

        # Stage 3: C2 IP reputation
        attacker_ip = ground_truth.get("attacker_ip", "")
        relevant_ips = ground_truth.get("relevant_parameters", {}).get("query_ip_reputation", [])
        has_ip_check = self._action_with_param(
            state, "query_ip_reputation", "ip", relevant_ips or [attacker_ip]
        )
        if has_ip_check:
            stages_found += 1

        # Stage 4: user lookup or network.log
        relevant_users = ground_truth.get("relevant_parameters", {}).get("lookup_user", [])
        has_user_lookup = self._action_with_param(
            state, "lookup_user", "username", relevant_users
        ) if relevant_users else self._action_type_taken(state, "lookup_user")

        has_network_log = self._action_with_param(
            state, "pull_logs", "source", ["network.log"]
        )

        if has_user_lookup or has_network_log:
            stages_found += 1

        return round(stages_found / total_stages, 4)

    def _compute_correlation_quality(self, state: SOCState, ground_truth: dict) -> float:
        """
        Score the quality of alert correlation.

        - 0.0 if no correlation was attempted
        - 0.5 if correlation was done with small window (< 60 min)
        - 0.8 if correlation was done with medium window (60–119 min)
        - 1.0 if correlation was done with large window (≥ 120 min)
        """
        for action in state.actions_taken:
            if action.action_type == "correlate_alerts":
                window_str = action.parameters.get("window_minutes", "0")
                try:
                    window = int(window_str)
                except (ValueError, TypeError):
                    window = 0

                if window >= 120:
                    return 1.0
                elif window >= 60:
                    return 0.8
                elif window > 0:
                    return 0.5

        return 0.0