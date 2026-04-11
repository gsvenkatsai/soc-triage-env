"""
Task 2 — Lateral Movement Investigation (Medium)

Scenario: Multiple assets show suspicious internal traffic. An internal
vulnerability scanner creates a red herring. The agent must check asset
criticality to distinguish real lateral movement from benign scanning
before escalating.

Difficulty: Medium — requires distinguishing attacker from scanner,
checking multiple assets, analysing network logs carefully.
"""

from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)
    timestamp = "2024-06-02T14:30:00"

    alert_summary = AlertSummary(
        alert_id="ALERT-002",
        title="Suspicious Internal Lateral Movement",
        severity=Severity.HIGH,
        timestamp=timestamp,
        source_ip="192.168.1.55",
        target_asset="db-server-01",
        description=(
            "Suspicious internal traffic detected from dev-workstation-05 (192.168.1.55) "
            "to db-server-01 (192.168.1.20) on port 5432 (PostgreSQL). "
            "Same source also connected to web-server-01 on port 22 (SSH) and "
            "file-server-01 on port 445 (SMB) within a 10-minute window. "
            "Additionally, vuln-scanner-01 (192.168.1.99) triggered firewall blocks "
            "scanning db-server-01 on port 3306. Investigate whether this is lateral "
            "movement or authorized activity."
        ),
    )

    assets = [
        Asset(asset_id="A002", hostname="db-server-01",
              ip="192.168.1.20", criticality="critical", owner="dba-team",
              department="database"),
        Asset(asset_id="A003", hostname="dev-workstation-05",
              ip="192.168.1.55", criticality="low", owner="dev-team",
              department="engineering"),
        Asset(asset_id="A005", hostname="vuln-scanner-01",
              ip="192.168.1.99", criticality="low", owner="security-team",
              department="security"),
        Asset(asset_id="A001", hostname="web-server-01",
              ip="192.168.1.10", criticality="high", owner="infra-team",
              department="infrastructure"),
        Asset(asset_id="A008", hostname="file-server-01",
              ip="192.168.1.40", criticality="high", owner="infra-team",
              department="infrastructure"),
    ]

    logs = [
        LogSource(source_id="L002", source_type="network",
                  hostname="firewall-01", available=True),
        LogSource(source_id="L003", source_type="endpoint",
                  hostname="db-server-01", available=True),
        LogSource(source_id="L001", source_type="auth",
                  hostname="web-server-01", available=True),
    ]

    scenario = SOCState(
        task_id="task2_lateral_movement",
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
        done=False,
    )

    ground_truth = {
        "correct_verdict": "escalate",
        "required_evidence": [
            {"action_type": "pull_logs", "parameters": {"source": "network.log"}},
            {"action_type": "check_asset_criticality", "parameters": {}},  # any asset check counts
        ],
        "relevant_actions": [
            "pull_logs",
            "check_asset_criticality",
            "query_ip_reputation",
            "lookup_user",
        ],
        "relevant_parameters": {
            "pull_logs": ["network.log", "endpoint.log", "auth.log"],
            "check_asset_criticality": [
                "A002", "db-server-01",
                "A003", "dev-workstation-05",
                "A005", "vuln-scanner-01",
                "A001", "web-server-01",
                "A008", "file-server-01",
            ],
            "query_ip_reputation": ["192.168.1.55", "192.168.1.99"],
        },
        "escalation_keywords": ["lateral", "movement", "internal", "compromise", "suspicious", "unauthorized"],
        # Red herring: vuln-scanner-01 is authorized scanner, NOT malicious
        "red_herring_ip": "192.168.1.99",
        "red_herring_assets": ["A005", "vuln-scanner-01"],
        "target_host": "db-server-01",
        "kill_chain": None,
        "containment_targets": {
            "block_ip": [],
            "isolate_host": ["dev-workstation-05"],
        },
        "context": {
            "timestamp": timestamp,
            "attacker_ip": "192.168.1.55",
        },
    }

    return {"scenario": scenario, "ground_truth": ground_truth}