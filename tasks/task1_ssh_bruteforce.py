from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
from datetime import datetime
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)
    timestamp = datetime(2024, 6, 1, 10, 0, 0)

    alert_summary = AlertSummary(
        alert_id="ALERT-001",
        title="SSH Brute Force Detected",
        severity=Severity.HIGH,
        timestamp=timestamp,
        source_ip="185.220.101.45",
        target_asset="web-server-01",
        description="Multiple failed SSH login attempts from external IP 185.220.101.45 targeting web-server-01. 4 failures followed by 1 success in 5 minutes.",
    )

    assets = [
        Asset(
            asset_id="A001",
            hostname="web-server-01",
            ip="192.168.1.10",
            criticality="high",
            owner="infra-team",
        )
    ]

    logs = [
        LogSource(source_id="L001", source_type="auth", hostname="web-server-01", available=True),
    ]

    scenario = SOCState(
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
    )

    ground_truth = {
        "correct_verdict": "escalate",
        "required_evidence": ["query_ip_reputation", "pull_logs"],
        "relevant_actions": [
            "query_ip_reputation",
            "pull_logs",
            "check_asset_criticality",
            "lookup_user",
        ],
        "kill_chain": None,
    }

    return {"scenario": scenario, "ground_truth": ground_truth}