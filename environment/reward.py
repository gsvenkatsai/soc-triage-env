"""
Reward computation for the SOC Triage Environment.

Provides meaningful per-step reward signals with:
- Parameter-aware relevance scoring (not just action type)
- Progressive evidence-gathering rewards
- Step cost to encourage efficiency
- Escalation quality bonus based on keyword matching
- Containment action scoring
- Penalties for repeated and irrelevant actions
"""

from environment.models import SOCState, ActionRecord
from typing import Dict, Any, Tuple


def compute_reward(
    state: SOCState,
    action: ActionRecord,
    ground_truth: dict,
) -> Tuple[float, Dict[str, float]]:
    """
    Compute the reward for a single action.

    Returns:
        (total_reward, components_dict) where components_dict breaks down
        the reward into named components for debugging.
    """
    components: Dict[str, float] = {}
    action_type = action.action_type
    params = action.parameters or {}
    actions_taken_types = [a.action_type for a in state.actions_taken]

    # ---- Step cost: small penalty per step to encourage efficiency ----
    components["step_cost"] = -0.02

    # ---- Terminal actions (verdicts) ----
    if action_type in ("escalate", "escalate_critical", "close_false_positive"):
        return _compute_verdict_reward(state, action, ground_truth, components)

    # ---- Containment actions ----
    if action_type in ("isolate_host", "block_ip"):
        return _compute_containment_reward(state, action, ground_truth, components)

    # ---- Investigative actions ----
    return _compute_investigation_reward(state, action, ground_truth, components)


def _compute_verdict_reward(
    state: SOCState,
    action: ActionRecord,
    ground_truth: dict,
    components: Dict[str, float],
) -> Tuple[float, Dict[str, float]]:
    """Reward for verdict (terminal) actions."""
    correct_verdict = ground_truth.get("correct_verdict")
    action_type = action.action_type
    reason = action.parameters.get("reason", "")

    # --- Correct/incorrect verdict ---
    if action_type == correct_verdict:
        components["verdict_correct"] = 0.30
    else:
        # Severity-scaled penalty
        if state.severity.value == "CRITICAL":
            components["verdict_wrong"] = -0.30
        elif state.severity.value == "HIGH":
            components["verdict_wrong"] = -0.20
        else:
            components["verdict_wrong"] = -0.10

    # --- Evidence gathering quality ---
    required = ground_truth.get("required_evidence", [])
    gathered_count = _count_evidence_gathered(state, required)
    if required:
        evidence_ratio = gathered_count / len(required)
        components["evidence_quality"] = round(0.20 * evidence_ratio, 4)

    # --- Verdict with zero evidence penalty ---
    if len(state.actions_taken) == 0:
        components["no_investigation"] = -0.20

    # --- Escalation reason quality ---
    keywords = ground_truth.get("escalation_keywords", [])
    if keywords and reason:
        reason_lower = reason.lower()
        matched = sum(1 for kw in keywords if kw.lower() in reason_lower)
        keyword_ratio = min(1.0, matched / max(1, min(3, len(keywords))))
        components["response_quality"] = round(0.10 * keyword_ratio, 4)

    total = round(sum(components.values()), 4)
    return total, components


def _compute_containment_reward(
    state: SOCState,
    action: ActionRecord,
    ground_truth: dict,
    components: Dict[str, float],
) -> Tuple[float, Dict[str, float]]:
    """Reward for containment actions (isolate_host, block_ip)."""
    containment_targets = ground_truth.get("containment_targets", {})
    action_type = action.action_type
    params = action.parameters

    if action_type == "block_ip":
        target_ips = containment_targets.get("block_ip", [])
        ip = params.get("ip", "")
        if ip in target_ips:
            components["correct_containment"] = 0.10
        else:
            components["wrong_containment"] = -0.10
    elif action_type == "isolate_host":
        target_hosts = containment_targets.get("isolate_host", [])
        hostname = params.get("hostname", "")
        if hostname in target_hosts:
            components["correct_containment"] = 0.10
        else:
            components["wrong_containment"] = -0.15  # Isolating wrong host is dangerous

    total = round(sum(components.values()), 4)
    return total, components


def _compute_investigation_reward(
    state: SOCState,
    action: ActionRecord,
    ground_truth: dict,
    components: Dict[str, float],
) -> Tuple[float, Dict[str, float]]:
    """Reward for investigative (non-terminal) actions."""
    action_type = action.action_type
    params = action.parameters or {}
    actions_taken = state.actions_taken

    # --- Repeated action penalty ---
    # Check for exact same action+parameters
    for prev in actions_taken:
        if prev.action_type == action_type and prev.parameters == params:
            components["repeated_action"] = -0.10
            total = round(sum(components.values()), 4)
            return total, components

    # --- Relevance check (action type level) ---
    relevant_actions = ground_truth.get("relevant_actions", [])
    relevant_params = ground_truth.get("relevant_parameters", {})

    if action_type in relevant_actions:
        # Base relevance bonus
        components["relevant_action"] = 0.05

        # Parameter-specific bonus
        target_params = relevant_params.get(action_type, [])
        if target_params:
            # Check if any parameter value matches
            param_values = list(params.values())
            matched = any(str(v) in target_params for v in param_values)
            if matched:
                components["relevant_parameter"] = 0.05
            else:
                components["irrelevant_parameter"] = -0.02
    else:
        components["irrelevant_action"] = -0.05

    # --- Progressive evidence bonus ---
    # Award extra for completing required evidence items
    required = ground_truth.get("required_evidence", [])
    if required:
        prev_gathered = _count_evidence_gathered(state, required)
        # Check if this action satisfies any required evidence
        new_evidence = _check_evidence_match(action, required, state)
        if new_evidence:
            components["evidence_progress"] = 0.05

    total = round(sum(components.values()), 4)
    return total, components


def _count_evidence_gathered(state: SOCState, required: list) -> int:
    """Count how many required evidence items have been gathered."""
    count = 0
    for req in required:
        req_type = req.get("action_type", "")
        req_params = req.get("parameters", {})
        for taken in state.actions_taken:
            if taken.action_type == req_type:
                if not req_params:
                    count += 1
                    break
                # Check if parameters match
                if all(taken.parameters.get(k) == v for k, v in req_params.items()):
                    count += 1
                    break
    return count


def _check_evidence_match(action: ActionRecord, required: list, state: SOCState) -> bool:
    """Check if the current action satisfies any unsatisfied required evidence."""
    for req in required:
        req_type = req.get("action_type", "")
        req_params = req.get("parameters", {})

        if action.action_type != req_type:
            continue

        # Check parameters match
        if req_params:
            if not all(action.parameters.get(k) == v for k, v in req_params.items()):
                continue

        # Check this wasn't already satisfied
        already_satisfied = False
        for taken in state.actions_taken:
            if taken.action_type == req_type:
                if not req_params or all(taken.parameters.get(k) == v for k, v in req_params.items()):
                    already_satisfied = True
                    break

        if not already_satisfied:
            return True

    return False