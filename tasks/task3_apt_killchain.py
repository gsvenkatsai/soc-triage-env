from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
from datetime import datetime
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)
    timestamp = datetime(2024, 6, 3, 9, 0, 0)

    alert_summary = AlertSummary(
        alert_id="ALERT-003",
        title="Multi-Stage APT Kill Chain Suspected",
        severity=Severity.CRITICAL,
        timestamp=timestamp,
        source_ip="194.165.16.72",
        target_asset="db-server-01",
        description=(
            "Large outbound data transfer (450MB) from db-server-01 to known C2 server "
            "194.165.16.72. Preceded by phishing email to hr@company.com 2 hours earlier "
            "and mimikatz.exe execution on db-server-01. Full kill chain suspected."
        ),
    )

    assets = [
        Asset(asset_id="A002", hostname="db-server-01",
              ip="192.168.1.20", criticality="critical", owner="dba-team"),
        Asset(asset_id="A004", hostname="hr-laptop-12",
              ip="192.168.1.88", criticality="medium", owner="hr-team"),
        Asset(asset_id="A001", hostname="web-server-01",
              ip="192.168.1.10", criticality="high", owner="infra-team"),
    ]

    logs = [
        LogSource(source_id="L003", source_type="endpoint",
                  hostname="db-server-01", available=True),
        LogSource(source_id="L004", source_type="email",
                  hostname="mail-gateway-01", available=True),
        LogSource(source_id="L002", source_type="network",
                  hostname="firewall-01", available=True),
    ]

    scenario = SOCState(
        alert_id="ALERT-003",
        alert_summary=alert_summary,
        severity=Severity.CRITICAL,
        timestamp=timestamp,
        assets_involved=assets,
        logs_available=logs,
        actions_taken=[],
        step_count=0,
        max_steps=15,
        verdict=None,
    )

    ground_truth = {
        "correct_verdict": "escalate_critical",
        "required_evidence": [
            "pull_logs",
            "query_ip_reputation",
            "correlate_alerts",
        ],
        "relevant_actions": [
            "pull_logs",
            "query_ip_reputation",
            "correlate_alerts",
            "check_asset_criticality",
            "lookup_user",
        ],
        "kill_chain": [
            "phishing_email_received",
            "credential_theft_mimikatz",
            "exfiltration_to_c2",
        ],
    }

    return {"scenario": scenario, "ground_truth": ground_truth}