import random
from datetime import datetime, timedelta
from environment.models import Asset, LogSource


class Simulator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def get_asset_registry(self) -> list[Asset]:
        return [
            Asset(asset_id="A001", hostname="web-server-01", ip="192.168.1.10",
                  criticality="high", owner="infra-team"),
            Asset(asset_id="A002", hostname="db-server-01", ip="192.168.1.20",
                  criticality="critical", owner="dba-team"),
            Asset(asset_id="A003", hostname="dev-workstation-05", ip="192.168.1.55",
                  criticality="low", owner="dev-team"),
            Asset(asset_id="A004", hostname="hr-laptop-12", ip="192.168.1.88",
                  criticality="medium", owner="hr-team"),
            Asset(asset_id="A005", hostname="vuln-scanner-01", ip="192.168.1.99",
                  criticality="low", owner="security-team"),
        ]

    def get_log_sources(self) -> list[LogSource]:
        return [
            LogSource(source_id="L001", source_type="auth",
                      hostname="web-server-01", available=True),
            LogSource(source_id="L002", source_type="network",
                      hostname="firewall-01", available=True),
            LogSource(source_id="L003", source_type="endpoint",
                      hostname="db-server-01", available=True),
            LogSource(source_id="L004", source_type="email",
                      hostname="mail-gateway-01", available=True),
            LogSource(source_id="L005", source_type="auth",
                      hostname="hr-laptop-12", available=True),
        ]

    def query_ip_reputation(self, ip: str) -> dict:
        known_malicious = {
            "185.220.101.45": {"score": 95, "tags": ["tor-exit", "brute-force"], "malicious": True},
            "194.165.16.72":  {"score": 88, "tags": ["apt", "c2-server"],        "malicious": True},
            "45.33.32.156":   {"score": 72, "tags": ["scanner", "recon"],        "malicious": True},
        }
        known_clean = {
            "192.168.1.99":   {"score": 0,  "tags": ["internal", "vuln-scanner"], "malicious": False},
            "8.8.8.8":        {"score": 0,  "tags": ["google-dns"],               "malicious": False},
        }
        if ip in known_malicious:
            return known_malicious[ip]
        if ip in known_clean:
            return known_clean[ip]
        # Unknown IP — generate a low-ish random score
        score = self.rng.randint(10, 40)
        return {"score": score, "tags": ["unknown"], "malicious": False}

    def pull_logs(self, source: str, context: dict = {}) -> list[str]:
        base_time = datetime.fromisoformat(
            context.get("timestamp", "2024-06-01T10:00:00")
        )
        logs = {
            "auth.log": [
                f"[{base_time - timedelta(minutes=5)}] Failed password for root from 185.220.101.45 port 42315",
                f"[{base_time - timedelta(minutes=4)}] Failed password for root from 185.220.101.45 port 42316",
                f"[{base_time - timedelta(minutes=3)}] Failed password for admin from 185.220.101.45 port 42317",
                f"[{base_time - timedelta(minutes=2)}] Failed password for ubuntu from 185.220.101.45 port 42318",
                f"[{base_time - timedelta(minutes=1)}] Accepted password for ubuntu from 185.220.101.45 port 42319",
            ],
            "network.log": [
                f"[{base_time}] ALLOW TCP 192.168.1.55 -> 192.168.1.20 port 5432",
                f"[{base_time + timedelta(minutes=2)}] ALLOW TCP 192.168.1.55 -> 192.168.1.10 port 22",
                f"[{base_time + timedelta(minutes=4)}] BLOCK TCP 192.168.1.99 -> 192.168.1.20 port 3306",
            ],
            "email.log": [
                f"[{base_time - timedelta(hours=2)}] Message from phish@evil.com to hr@company.com — subject: 'Urgent: Update your credentials'",
                f"[{base_time - timedelta(hours=1, minutes=50)}] hr@company.com clicked link in email from phish@evil.com",
            ],
            "endpoint.log": [
                f"[{base_time}] Process mimikatz.exe started on db-server-01 by user ubuntu",
                f"[{base_time + timedelta(minutes=1)}] Large outbound transfer: db-server-01 -> 194.165.16.72 (450MB)",
            ],
        }
        return logs.get(source, [f"No logs found for source: {source}"])

    def check_asset_criticality(self, asset_id: str) -> dict:
        registry = {a.asset_id: a for a in self.get_asset_registry()}
        hostname_map = {a.hostname: a for a in self.get_asset_registry()}
        asset = registry.get(asset_id) or hostname_map.get(asset_id)
        if not asset:
            return {"error": f"Asset {asset_id} not found"}
        return {
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "criticality": asset.criticality,
            "owner": asset.owner,
        }

    def correlate_alerts(self, window_minutes: int, context: dict = {}) -> list[str]:
        return context.get("correlated_alerts", [
            "No correlated alerts found in window."
        ])

    def lookup_user(self, username: str) -> dict:
        users = {
            "ubuntu":    {"department": "infra",    "role": "sysadmin",  "active": True},
            "root":      {"department": "system",   "role": "superuser", "active": True},
            "hr_alice":  {"department": "hr",       "role": "analyst",   "active": True},
            "dev_bob":   {"department": "dev",      "role": "engineer",  "active": True},
        }
        return users.get(username, {"error": f"User {username} not found"})