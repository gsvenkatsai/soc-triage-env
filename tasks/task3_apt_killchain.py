"""
Task 3 — APT Kill Chain (Hard)

Scenario: A multi-stage Advanced Persistent Threat attack spanning:
  1. Initial Access   — phishing email to hr@company.com
  2. Credential Theft — mimikatz.exe on db-server-01
  3. Persistence      — registry modification for startup
  4. Exfiltration     — 450MB outbound to C2 server

The agent must correlate alerts across a time window, inspect multiple
log sources, look up the compromised user, and escalate as CRITICAL.

Difficulty: Hard — requires analysing 4+ log sources, correlating events
across a 2-hour window, identifying kill chain stages, and issuing a
critical (not standard) escalation.
"""

from environment.models import SOCState, AlertSummary, Severity, Asset, LogSource
import random


def get_task(seed: int = 42) -> dict:
    rng = random.Random(seed)
    timestamp = "2024-06-03T09:00:00"
    c2_ip = "194.165.16.72"

    alert_summary = AlertSummary(
        alert_id="ALERT-003",
        title="Multi-Stage APT Kill Chain Suspected",
        severity=Severity.CRITICAL,
        timestamp=timestamp,
        source_ip=c2_ip,
        target_asset="db-server-01",
        description=(
            f"CRITICAL: Large outbound data transfer (450MB) detected from db-server-01 "
            f"to known C2 server {c2_ip}. This was preceded by a phishing email to "
            f"hr@company.com ~2 hours earlier and credential harvesting tool (mimikatz.exe) "
            f"execution on db-server-01. Registry persistence mechanism also detected. "
            f"Full APT kill chain suspected: initial access → credential theft → "
            f"persistence → exfiltration. Immediate investigation required."
        ),
    )

    assets = [
        Asset(asset_id="A002", hostname="db-server-01",
              ip="192.168.1.20", criticality="critical", owner="dba-team",
              department="database"),
        Asset(asset_id="A004", hostname="hr-laptop-12",
              ip="192.168.1.88", criticality="medium", owner="hr-team",
              department="human-resources"),
        Asset(asset_id="A001", hostname="web-server-01",
              ip="192.168.1.10", criticality="high", owner="infra-team",
              department="infrastructure"),
        Asset(asset_id="A006", hostname="mail-gateway-01",
              ip="192.168.1.30", criticality="high", owner="infra-team",
              department="infrastructure"),
    ]

    logs = [
        LogSource(source_id="L003", source_type="endpoint",
                  hostname="db-server-01", available=True),
        LogSource(source_id="L004", source_type="email",
                  hostname="mail-gateway-01", available=True),
        LogSource(source_id="L002", source_type="network",
                  hostname="firewall-01", available=True),
        LogSource(source_id="L006", source_type="dns",
                  hostname="dns-resolver-01", available=True),
        LogSource(source_id="L007", source_type="proxy",
                  hostname="proxy-server-01", available=True),
    ]

    scenario = SOCState(
        task_id="task3_apt_killchain",
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
        done=False,
    )

    ground_truth = {
        "correct_verdict": "escalate_critical",
        "required_evidence": [
            {"action_type": "pull_logs", "parameters": {"source": "email.log"}},
            {"action_type": "pull_logs", "parameters": {"source": "endpoint.log"}},
            {"action_type": "query_ip_reputation", "parameters": {"ip": c2_ip}},
            {"action_type": "correlate_alerts", "parameters": {}},  # any correlation counts
        ],
        "relevant_actions": [
            "pull_logs",
            "query_ip_reputation",
            "correlate_alerts",
            "check_asset_criticality",
            "lookup_user",
        ],
        "relevant_parameters": {
            "pull_logs": ["email.log", "endpoint.log", "network.log", "dns.log", "proxy.log"],
            "query_ip_reputation": [c2_ip, "91.240.118.172"],
            "correlate_alerts": ["60", "120", "180"],
            "check_asset_criticality": ["A002", "db-server-01", "A004", "hr-laptop-12"],
            "lookup_user": ["hr_alice", "ubuntu"],
        },
        "escalation_keywords": [
            "apt", "kill chain", "killchain", "kill-chain",
            "exfiltration", "c2", "command and control",
            "multi-stage", "multi stage", "critical",
            "phishing", "mimikatz", "credential",
        ],
        "kill_chain": [
            "CORRELATED: Alert ALERT-PHISH-001 — Phishing email received by hr@company.com (2h before current alert)",
            "CORRELATED: Alert ALERT-CRED-002 — Credential access detected on db-server-01 (mimikatz.exe, 10m before current alert)",
            "CORRELATED: Alert ALERT-MOVE-003 — Unusual internal traffic from dev-workstation-05 to db-server-01 (15m before current alert)",
            "CORRELATED: Alert ALERT-EXFIL-004 — Large outbound transfer db-server-01 -> 194.165.16.72 (450MB, at time of current alert)",
            "CORRELATED: Alert ALERT-PERSIST-005 — Registry modification for persistence on db-server-01 (3m after current alert)",
        ],
        "kill_chain_stages": [
            "initial_access_phishing",
            "credential_theft_mimikatz",
            "persistence_registry",
            "exfiltration_to_c2",
        ],
        "attacker_ip": c2_ip,
        "target_host": "db-server-01",
        "compromised_user": "hr_alice",
        "containment_targets": {
            "block_ip": [c2_ip],
            "isolate_host": ["db-server-01", "hr-laptop-12"],
        },
        "context": {
            "timestamp": timestamp,
            "c2_ip": c2_ip,
            "attacker_ip": c2_ip,
            "compromised_user": "ubuntu",
        },
    }

    return {"scenario": scenario, "ground_truth": ground_truth}