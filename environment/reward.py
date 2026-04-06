from environment.models import SOCState, Action


def compute_reward(state: SOCState, action: Action, ground_truth: dict) -> float:
    reward = 0.0
    action_type = action.action_type
    actions_taken = [a.action_type for a in state.actions_taken]

    # --- Verdict actions ---
    if action_type in ("escalate", "escalate_critical", "close_false_positive"):
        correct_verdict = ground_truth.get("correct_verdict")
        required_evidence = ground_truth.get("required_evidence", [])
        evidence_gathered = [a for a in actions_taken if a in required_evidence]

        # Correct verdict
        if action_type == correct_verdict:
            reward += 0.30
        else:
            # Wrong verdict on a CRITICAL alert
            if state.severity.value == "CRITICAL":
                reward -= 0.30
            else:
                reward -= 0.10

        # Gathered required evidence before verdict
        if len(evidence_gathered) >= len(required_evidence) and len(required_evidence) > 0:
            reward += 0.20

        # Verdict with zero evidence
        if len(actions_taken) == 0:
            reward -= 0.20

        return round(reward, 4)

    # --- Investigative actions ---
    relevant_actions = ground_truth.get("relevant_actions", [])

    # Repeated action penalty
    if action_type in actions_taken:
        reward -= 0.10
        return round(reward, 4)

    # Relevant action bonus
    if action_type in relevant_actions:
        reward += 0.10
    else:
        # Irrelevant action penalty
        reward -= 0.05

    return round(reward, 4)