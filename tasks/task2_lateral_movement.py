from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
from datetime import datetime
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)
    timestamp = datetime(2024, 6, 2, 14, 30, 0)

    alert_summary = AlertSummary(
        alert_id="ALERT-002",
        title="Lateral Movement Detected",
        severity=Severity.HIGH,
        timestamp=timestamp,
        source_ip="192.168.1.55",
        target_asset="db-server-01",
        description=(
            "Suspicious internal traffic from dev-workstation-05 (192.168.1.55) "
            "to db-server-01 (192.168.1.20) on port 5432. "
            "Same host also scanned web-server-01 on port 22."
        ),
    )

    assets = [
        Asset(asset_id="A002", hostname="db-server-01",
              ip="192.168.1.20", criticality="critical", owner="dba-team"),
        Asset(asset_id="A003", hostname="dev-workstation-05",
              ip="192.168.1.55", criticality="low", owner="dev-team"),
        Asset(asset_id="A005", hostname="vuln-scanner-01",
              ip="192.168.1.99", criticality="low", owner="security-team"),
    ]

    logs = [
        LogSource(source_id="L002", source_type="network",
                  hostname="firewall-01", available=True),
        LogSource(source_id="L003", source_type="endpoint",
                  hostname="db-server-01", available=True),
    ]

    scenario = SOCState(
        alert_id="ALERT-002",
        alert_summary=alert_summary,
        severity=Severity.HIGH,
        timestamp=timestamp,
        assets_involved=assets,
        logs_available=logs,
        actions_taken=[],
        step_count=0,
        max_steps=12,
        verdict=None,
    )

    ground_truth = {
        "correct_verdict": "escalate",
        "required_evidence": ["pull_logs", "check_asset_criticality"],
        "relevant_actions": [
            "pull_logs",
            "check_asset_criticality",
            "query_ip_reputation",
            "lookup_user",
        ],
        # Red herring: 192.168.1.99 is internal vuln scanner, NOT malicious
        "red_herring_ip": "192.168.1.99",
        "kill_chain": None,
    }

    return {"scenario": scenario, "ground_truth": ground_truth}