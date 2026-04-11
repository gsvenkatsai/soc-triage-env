"""
Task 1 — SSH Brute Force Detection (Easy)

Scenario: A single external IP is hammering SSH on a critical server.
The agent must pull logs, query IP reputation, and escalate appropriately.

Difficulty: Easy — clear indicators, single attack vector, straightforward verdict.
"""

from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)

    # Seed-parameterized variation
    attacker_ips = ["185.220.101.45", "45.33.32.156", "103.75.201.4"]
    target_hosts = ["web-server-01", "jump-server-01"]
    attacker_ip = rng.choice(attacker_ips)
    target_host = rng.choice(target_hosts)

    timestamp = "2024-06-01T10:00:00"

    alert_summary = AlertSummary(
        alert_id="ALERT-001",
        title="SSH Brute Force Detected",
        severity=Severity.HIGH,
        timestamp=timestamp,
        source_ip=attacker_ip,
        target_asset=target_host,
        description=(
            f"Multiple failed SSH login attempts from external IP {attacker_ip} "
            f"targeting {target_host}. 5 failures followed by 1 successful login "
            f"within 5 minutes. Possible credential compromise."
        ),
    )

    target_asset_map = {
        "web-server-01": Asset(
            asset_id="A001", hostname="web-server-01", ip="192.168.1.10",
            criticality="high", owner="infra-team", department="infrastructure"),
        "jump-server-01": Asset(
            asset_id="A007", hostname="jump-server-01", ip="192.168.1.5",
            criticality="critical", owner="infra-team", department="infrastructure"),
    }

    assets = [target_asset_map[target_host]]

    logs = [
        LogSource(source_id="L001", source_type="auth",
                  hostname=target_host, available=True),
        LogSource(source_id="L002", source_type="network",
                  hostname="firewall-01", available=True),
    ]

    scenario = SOCState(
        task_id="task1_ssh_bruteforce",
        alert_id="ALERT-001",
        alert_summary=alert_summary,
        severity=Severity.HIGH,
        timestamp=timestamp,
        assets_involved=assets,
        logs_available=logs,
        actions_taken=[],
        step_count=0,
        max_steps=10,
        verdict=None,
        done=False,
    )

    ground_truth = {
        "correct_verdict": "escalate",
        "required_evidence": [
            {"action_type": "pull_logs", "parameters": {"source": "auth.log"}},
            {"action_type": "query_ip_reputation", "parameters": {"ip": attacker_ip}},
        ],
        "relevant_actions": [
            "pull_logs",
            "query_ip_reputation",
            "check_asset_criticality",
            "lookup_user",
        ],
        "relevant_parameters": {
            "pull_logs": ["auth.log", "network.log"],
            "query_ip_reputation": [attacker_ip],
            "check_asset_criticality": [target_host, target_asset_map[target_host].asset_id],
        },
        "escalation_keywords": ["brute", "force", "ssh", "credential", "compromise", "attack"],
        "attacker_ip": attacker_ip,
        "target_host": target_host,
        "kill_chain": None,
        "containment_targets": {
            "block_ip": [attacker_ip],
            "isolate_host": [],  # Not needed for this task
        },
        "context": {
            "timestamp": timestamp,
            "attacker_ip": attacker_ip,
        },
    }

    return {"scenario": scenario, "ground_truth": ground_truth}