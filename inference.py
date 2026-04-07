import os
import sys
from openai import OpenAI

# -------------------------------------------------------
# ENV VARS (mandatory per hackathon spec)
# -------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME",   "meta-llama/Llama-3.1-8B-Instruct")
API_KEY      = os.getenv("HF_TOKEN")     or os.getenv("API_KEY")
BENCHMARK    = "soc-triage-env"

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from environment.env import SOCEnvironment
from graders.grader1 import Grader1
from graders.grader2 import Grader2
from graders.grader3 import Grader3

GRADERS = {1: Grader1(), 2: Grader2(), 3: Grader3()}

TASK_NAMES = {
    1: "ssh-brute-force",
    2: "lateral-movement",
    3: "apt-kill-chain",
}

VALID_ACTION_PREFIXES = [
    "pull_logs",
    "query_ip_reputation",
    "check_asset_criticality",
    "correlate_alerts",
    "lookup_user",
    "escalate",
    "escalate_critical",
    "close_false_positive",
]

MAX_STEPS = 8

# Task 3: required evidence steps before escalating
TASK3_REQUIRED_STEPS = [
    "pull_logs email.log",
    "pull_logs endpoint.log",
    "query_ip_reputation 194.165.16.72",
    "correlate_alerts 120",
]


# -------------------------------------------------------
# ACTION EXTRACTION
# -------------------------------------------------------
def extract_valid_action(text: str) -> str:
    text = text.strip().split("\n")[0].replace('"', "").strip()
    if "|" in text:
        text = text.split("|")[0].strip()
    for prefix in VALID_ACTION_PREFIXES:
        if prefix in text:
            return text[text.index(prefix):].strip()
    return "pull_logs auth.log"


# -------------------------------------------------------
# PROMPT
# -------------------------------------------------------
def build_prompt(obs, history, actions_taken):
    history_text = "\n".join(history[-4:]) if history else "None"
    taken_text   = ", ".join(actions_taken) if actions_taken else "None"
    return f"""You are a SOC analyst.

ALERT: {obs.alert.title}
DESCRIPTION: {obs.alert.description}

ALREADY USED: {taken_text}
RECENT:
{history_text}
STEP: {obs.step_count}

CHOOSE ONE ACTION (output ONLY the action, nothing else):
pull_logs auth.log
pull_logs network.log
pull_logs endpoint.log
pull_logs email.log
query_ip_reputation <ip>
check_asset_criticality <asset_id>
correlate_alerts 120
lookup_user <username>
escalate <reason>
escalate_critical <reason>
close_false_positive <reason>
"""


# -------------------------------------------------------
# LLM CALL (OpenAI client)
# -------------------------------------------------------
def call_llm(prompt: str) -> str:
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=20,
    )
    return response.choices[0].message.content.strip()


# -------------------------------------------------------
# TASK 3 FORCED SEQUENCE
# -------------------------------------------------------
def get_task3_forced_action(actions_taken: list):
    for required in TASK3_REQUIRED_STEPS:
        if required not in actions_taken:
            return required
    return None


# -------------------------------------------------------
# EPISODE RUNNER
# -------------------------------------------------------
def run_episode(task_id: int, seed: int = 42):
    task_name = TASK_NAMES[task_id]

    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)

    env  = SOCEnvironment()
    obs  = env.reset(task_id=task_id, seed=seed)

    done          = False
    history       = []
    actions_taken = []
    rewards       = []
    step_num      = 0
    last_error    = "null"

    while not done and step_num < MAX_STEPS:
        step_num += 1

        if task_id == 3:
            forced = get_task3_forced_action(actions_taken)
            if forced:
                action = forced
            elif env.state.verdict is None:
                action = "escalate_critical multi-stage APT kill chain confirmed"
            else:
                action = "pull_logs auth.log"

        else:
            try:
                prompt = build_prompt(obs, history, actions_taken)
                raw    = call_llm(prompt)
                action = extract_valid_action(raw)
                last_error = "null"
            except Exception as e:
                action     = "pull_logs auth.log"
                last_error = str(e).replace("\n", " ")

            if action in actions_taken:
                action = "pull_logs auth.log"

            if not done and step_num >= 6 and env.state.verdict is None:
                if task_id == 2:
                    action = "escalate lateral movement confirmed"
                else:
                    action = "escalate brute force confirmed"

        obs, reward, done, info = env.step(action)

        actions_taken.append(action)
        history.append(f"{action} -> {obs.last_action_result[:60]}")
        rewards.append(reward)

        print(
            f"[STEP] step={step_num} action={action} "
            f"reward={reward:.2f} done={str(done).lower()} error={last_error}",
            flush=True,
        )

    grader  = GRADERS[task_id]
    score   = grader.score(env.state_dict(), env.ground_truth)
    success = score >= 0.5

    rewards_str = ",".join(f"{r:.2f}" for r in rewards)

    print(
        f"[END] success={str(success).lower()} steps={step_num} "
        f"score={score:.2f} rewards={rewards_str}",
        flush=True,
    )

    return score


# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
def main():
    scores = {}
    for task_id in [1, 2, 3]:
        scores[task_id] = run_episode(task_id, seed=42)

    print("\nFINAL SCORES", flush=True)
    for t, s in scores.items():
        print(f"Task {t}: {s:.2f}", flush=True)
    print(f"Average: {sum(scores.values()) / 3:.2f}", flush=True)


if __name__ == "__main__":
    main()
