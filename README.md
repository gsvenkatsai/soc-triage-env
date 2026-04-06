# SOC Alert Triage — OpenEnv Environment

A simulated Security Operations Center (SOC) environment where an AI agent investigates alerts, gathers evidence, and makes security decisions.

## Overview

This environment models real-world SOC alert triage as a sequential decision problem.  
Each action reveals new information and influences future decisions.

Agent flow:

1. Observe alert
2. Take investigative actions
3. Gather evidence
4. Submit verdict
5. Receive score (0.0 – 1.0)

---

## Observation Space

| Field              | Description                                  |
| ------------------ | -------------------------------------------- |
| alert              | Alert summary (title, severity, description) |
| last_action_result | Output of last action                        |
| available_actions  | List of valid actions                        |
| step_count         | Current step                                 |
| context_gathered   | Collected evidence                           |

---

## Action Space

Discrete actions:

- `pull_logs <source>`
- `query_ip_reputation <ip>`
- `check_asset_criticality <asset_id>`
- `correlate_alerts <window>`
- `lookup_user <username>`
- `escalate <reason>`
- `escalate_critical <reason>`
- `close_false_positive <reason>`

---

## Tasks

### Task 1 — SSH Brute Force (Easy)

- Single IP attacking SSH
- Goal: detect brute-force and escalate

### Task 2 — Lateral Movement (Medium)

- Multiple assets
- Includes red-herring (internal scanner)
- Requires asset analysis

### Task 3 — APT Kill Chain (Hard)

- Multi-stage attack:
  - phishing → credential theft → exfiltration
- Requires alert correlation

---

## Reward & Evaluation

Reward shaping:

- +0.30 correct verdict
- +0.20 sufficient evidence
- +0.10 relevant action
- penalties for noise / repetition

Final evaluation:

- Deterministic graders (0.0–1.0)
- Reproducible with `seed=42`

---

## Baseline Agent

Hybrid agent:

- LLM (Groq llama-3.1-8b-instant)
- Rule-based constraints for reliability

### Baseline Scores

| Task        | Score    |
| ----------- | -------- |
| Task 1      | 0.72     |
| Task 2      | 0.65     |
| Task 3      | 1.00     |
| **Average** | **0.79** |

---

## Setup

```bash
git clone <your-repo>
cd soc-triage-env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
