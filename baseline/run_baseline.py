import os
import sys
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from environment.env import SOCEnvironment
from graders.grader1 import Grader1
from graders.grader2 import Grader2
from graders.grader3 import Grader3

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

GRADERS = {1: Grader1(), 2: Grader2(), 3: Grader3()}


def build_prompt(obs, history: list[str], actions_taken: list[str]) -> str:
    history_text = "\n".join(history[-6:]) if history else "None yet."
    taken_text = ", ".join(actions_taken) if actions_taken else "None"

    steps_left = obs.available_actions  # just for reference
    urgent = ""
    if obs.step_count >= 4:
        urgent = "\n WARNING: You have gathered enough evidence. You MUST submit a verdict now: escalate, escalate_critical, or close_false_positive <reason>"

    return f"""You are a SOC analyst. Investigate the alert and submit a verdict.

ALERT: {obs.alert.title}
SEVERITY: {obs.alert.severity}
DESCRIPTION: {obs.alert.description}

ACTIONS YOU HAVE ALREADY TAKEN (do NOT repeat these):
{taken_text}

RECENT FINDINGS:
{history_text}

STEP: {obs.step_count}
{urgent}

VALID ACTIONS (pick exactly one, use exact format):
pull_logs auth.log
pull_logs network.log
pull_logs endpoint.log
pull_logs email.log
query_ip_reputation <ip_address>
check_asset_criticality <asset_id>
correlate_alerts 120
lookup_user <username>
escalate <reason>
escalate_critical <reason>
close_false_positive <reason>

RULES:
- Do NOT repeat any action already taken
- After 3-4 investigative actions, submit a verdict
- Respond with ONLY the action string, nothing else
- No explanation, no markdown, just the raw action
"""


def call_groq(prompt: str) -> str:
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=30,
    )
    return response.choices[0].message.content.strip().split("\n")[0].strip()


def run_episode(task_id: int, seed: int = 42) -> float:
    env = SOCEnvironment()
    obs = env.reset(task_id=task_id, seed=seed)
    done = False
    history = []
    actions_taken = []
    total_reward = 0.0

    print(f"\n{'='*60}")
    print(f"TASK {task_id}: {obs.alert.title}")
    print(f"{'='*60}")

    while not done:
        prompt = build_prompt(obs, history, actions_taken)
        action_str = call_groq(prompt)

        # Force verdict if running out of steps
        if obs.step_count >= env.state.max_steps - 2 and env.state.verdict is None:
            action_str = "escalate timeout forced verdict"

        print(f"  Step {obs.step_count}: {action_str}")

        obs, reward, done, info = env.step(action_str)
        total_reward += reward
        actions_taken.append(info.get("action_type", action_str))
        history.append(f"Action: {action_str} | Result: {obs.last_action_result[:80]}")

    grader = GRADERS[task_id]
    final_score = grader.score(env.state, env.ground_truth)

    print(f"  Verdict: {env.state.verdict}")
    print(f"  Total reward: {round(total_reward, 4)}")
    print(f"  Grader score: {final_score}")
    return final_score


def main():
    print("SOC Triage Baseline — Groq llama-3.1-8b-instant | seed=42")
    scores = {}
    for task_id in [1, 2, 3]:
        scores[task_id] = run_episode(task_id, seed=42)

    print(f"\n{'='*60}")
    print("FINAL SCORES")
    print(f"{'='*60}")
    for task_id, score in scores.items():
        print(f"  Task {task_id}: {score:.2f}")
    print(f"  Average: {sum(scores.values()) / len(scores):.2f}")


if __name__ == "__main__":
    main()