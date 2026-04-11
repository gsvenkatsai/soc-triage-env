---
title: SOC Triage Env
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
tags:
  - openenv
---

# 🛡️ SOC Alert Triage — OpenEnv Environment

A simulated **Security Operations Center (SOC)** environment where an AI agent investigates security alerts, gathers evidence through log analysis and threat intelligence, and submits triage verdicts.

> This environment models real-world SOC alert triage as a sequential decision problem. Each action reveals new information, and the agent must balance thoroughness against efficiency to reach the correct verdict.

## 🎯 Motivation

SOC analysts handle hundreds of alerts daily, deciding which are genuine threats and which are false positives. This environment trains and evaluates AI agents on three progressively harder triage scenarios — from simple brute-force detection to multi-stage APT kill chain analysis.

Key real-world skills tested:
- **Log analysis** — parsing auth, network, endpoint, email, DNS, and proxy logs
- **Threat intelligence** — IP reputation queries, IOC correlation
- **Asset context** — understanding criticality and business impact
- **Alert correlation** — connecting related events across time windows
- **Decision quality** — correct verdicts with justified reasoning
- **Containment** — isolating hosts and blocking malicious IPs

---

## 🔄 Agent Flow

```
Observe Alert → Investigate (pull logs, query IPs, check assets)
             → Gather Evidence (correlate alerts, lookup users)
             → [Optional] Contain (isolate host, block IP)
             → Submit Verdict (escalate / escalate_critical / close_false_positive)
             → Receive Score (0.0 – 1.0)
```

---

## 📊 Observation Space

| Field              | Type       | Description                                           |
| ------------------ | ---------- | ----------------------------------------------------- |
| `alert`            | object     | Alert summary: id, title, severity, timestamp, source_ip, target_asset, description |
| `last_action_result` | string   | Output of the most recently executed action           |
| `available_actions`| string[]   | List of valid action templates                        |
| `step_count`       | int        | Current step number                                   |
| `max_steps`        | int        | Maximum steps allowed for this task                   |
| `context_gathered` | string[]   | Accumulated results from all prior actions            |
| `done`             | bool       | Whether the episode has ended                         |

---

## 🎮 Action Space

| Action | Description |
|--------|-------------|
| `pull_logs <source>` | Pull logs from: `auth.log`, `network.log`, `endpoint.log`, `email.log`, `dns.log`, `proxy.log` |
| `query_ip_reputation <ip>` | Check threat intelligence for an IP address |
| `check_asset_criticality <id>` | Look up asset details (by hostname or asset ID) |
| `correlate_alerts <window_min>` | Find related alerts within a time window |
| `lookup_user <username>` | Look up user account details and risk score |
| `isolate_host <hostname>` | **Containment**: isolate a compromised host |
| `block_ip <ip>` | **Containment**: block a malicious IP at firewall |
| `escalate <reason>` | **Verdict**: escalate to Tier 2 analyst |
| `escalate_critical <reason>` | **Verdict**: critical escalation to IR team |
| `close_false_positive <reason>` | **Verdict**: close as false positive |

---

## 📋 Tasks

### Task 1 — SSH Brute Force Detection (Easy)
- **Scenario**: External IP hammering SSH on a critical server. 5 failed logins followed by 1 success.
- **Goal**: Pull auth logs, check IP reputation, escalate with reason.
- **Max Steps**: 10
- **Key Challenge**: Straightforward indicators — tests basic triage workflow.

### Task 2 — Lateral Movement Investigation (Medium)
- **Scenario**: Suspicious internal traffic from dev workstation to critical database server. Scan traffic from authorized vulnerability scanner creates a **red herring**.
- **Goal**: Distinguish real lateral movement from benign scanning, check asset criticality, escalate.
- **Max Steps**: 12
- **Key Challenge**: Must investigate the scanner (vuln-scanner-01) and recognize it as authorized before deciding.

### Task 3 — APT Kill Chain (Hard)
- **Scenario**: Multi-stage attack: phishing → credential theft (mimikatz) → persistence → data exfiltration (450MB to C2).
- **Goal**: Correlate alerts across 2-hour window, inspect 4+ log sources, identify all kill chain stages, escalate as **critical**.
- **Max Steps**: 15
- **Key Challenge**: Must use `escalate_critical` (not just `escalate`), correlate with ≥120 minute window, evidence all kill chain stages.

---

## 🏆 Reward & Evaluation

### Per-Step Reward Shaping

| Component | Value | Description |
|-----------|-------|-------------|
| Relevant action + parameter | +0.05 to +0.10 | Right action type with correct parameters |
| Evidence progress | +0.05 | Satisfying a required evidence item |
| Correct verdict | +0.30 | Submitting the right verdict type |
| Evidence at verdict | +0.00 to +0.20 | Based on evidence gathered before verdict |
| Response quality | +0.00 to +0.10 | Keywords in escalation reason |
| Correct containment | +0.10 | Blocking the right IP / isolating right host |
| Step cost | -0.02 | Per-step efficiency pressure |
| Repeated action | -0.10 | Same action+parameters repeated |
| Wrong verdict (CRITICAL) | -0.30 | Wrong verdict on critical alert |
| Wrong containment | -0.10 to -0.15 | Isolating wrong host is heavily penalized |

### Final Grader Scores (0.0 – 1.0)

**Task 1**: `0.35 × verdict + 0.30 × evidence + 0.20 × response_quality + 0.15 × efficiency`

**Task 2**: `0.30 × verdict + 0.25 × evidence + 0.25 × red_herring_handling + 0.20 × efficiency`

**Task 3**: `0.30 × verdict + 0.30 × kill_chain_coverage + 0.25 × correlation_quality + 0.15 × response_quality`

---

## 📈 Baseline Scores

Using **meta-llama/Llama-3.1-8B-Instruct** via HuggingFace Router:

| Task | Difficulty | Score | Notes |
|------|-----------|-------|-------|
| Task 1 — SSH Brute Force | Easy | ~0.72 | Correct verdict with evidence |
| Task 2 — Lateral Movement | Medium | ~0.65 | Depends on red herring investigation |
| Task 3 — APT Kill Chain | Hard | ~0.60 | Requires critical escalation + wide correlation |
| **Average** | | **~0.66** | |

*Scores are approximate and may vary with API routing. Run `python inference.py` to reproduce.*

---

## 🚀 Setup

### Local Development

```bash
git clone https://github.com/gsvenkatsai/soc-triage-env
cd soc-triage-env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v

# Start server
uvicorn server.app:app --host 0.0.0.0 --port 7860

# Run baseline (set OPENAI_API_KEY or HF_TOKEN)
export OPENAI_API_KEY=sk-xxx  # or: export HF_TOKEN=hf_xxx
python inference.py
```

### Docker

```bash
docker build -t soc-triage-env .
docker run -p 7860:7860 soc-triage-env
```

### API Usage

```bash
# Reset environment (task 1, seed 42)
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": 1, "seed": 42}'

# Take an action
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action": "pull_logs auth.log"}'

# Grade the current episode
curl -X POST http://localhost:7860/score

# Check state
curl http://localhost:7860/state

# Health check
curl http://localhost:7860/health

# Interactive API docs
open http://localhost:7860/docs
```

### Python Client

```python
from client import SOCTriageClient

with SOCTriageClient("http://localhost:7860") as env:
    obs = env.reset(task_id=1, seed=42)
    print(obs["alert"]["title"])

    obs, reward, done, info = env.step("pull_logs auth.log")
    print(f"Reward: {reward}, Done: {done}")

    obs, reward, done, info = env.step("escalate brute force confirmed")
    print(f"Final: {done}")
```

---

## 🏗️ Architecture

```
soc-triage-env/
├── environment/
│   ├── models.py        # Pydantic data models
│   ├── env.py           # Core environment (reset/step/state)
│   ├── simulator.py     # Log generation, IP reputation, user directory
│   └── reward.py        # Per-step reward computation
├── tasks/
│   ├── task1_ssh_bruteforce.py    # Easy
│   ├── task2_lateral_movement.py  # Medium
│   └── task3_apt_killchain.py     # Hard
├── graders/
│   ├── base_grader.py   # Shared grading utilities
│   ├── grader1.py       # Task 1 scoring
│   ├── grader2.py       # Task 2 scoring
│   └── grader3.py       # Task 3 scoring
├── server/
│   └── app.py           # FastAPI server
├── data/
│   ├── assets.json      # Asset registry
│   └── ip_reputation.json # IP threat intel
├── tests/               # pytest test suite
├── client.py            # HTTP client
├── inference.py         # Baseline agent (OpenAI API)
├── openenv.yaml         # OpenEnv manifest
├── Dockerfile           # Container definition
└── README.md            # This file
```

---

## 📜 License

MIT
