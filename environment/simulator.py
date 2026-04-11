"""
SOC Simulator — generates realistic log entries, IP reputation data,
asset registries, and user directories.

All randomizable elements are parameterized via a seeded RNG so that
identical seeds produce identical scenarios.
"""

import random
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from environment.models import Asset, LogSource


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_json(filename: str) -> dict:
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            data = f.read().strip()
            if data:
                return json.loads(data)
    return {}


class Simulator:
    """Stateless simulator that generates SOC investigation data."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.seed = seed
        self._ip_db = _load_json("ip_reputation.json")
        self._asset_db = _load_json("assets.json")

    # ------------------------------------------------------------------
    # Asset registry
    # ------------------------------------------------------------------
    def get_asset_registry(self) -> List[Asset]:
        """Return the full list of network assets."""
        return [
            Asset(asset_id="A001", hostname="web-server-01", ip="192.168.1.10",
                  criticality="high", owner="infra-team", department="infrastructure",
                  os="ubuntu-22.04"),
            Asset(asset_id="A002", hostname="db-server-01", ip="192.168.1.20",
                  criticality="critical", owner="dba-team", department="database",
                  os="rhel-9"),
            Asset(asset_id="A003", hostname="dev-workstation-05", ip="192.168.1.55",
                  criticality="low", owner="dev-team", department="engineering",
                  os="ubuntu-22.04"),
            Asset(asset_id="A004", hostname="hr-laptop-12", ip="192.168.1.88",
                  criticality="medium", owner="hr-team", department="human-resources",
                  os="windows-11"),
            Asset(asset_id="A005", hostname="vuln-scanner-01", ip="192.168.1.99",
                  criticality="low", owner="security-team", department="security",
                  os="kali-linux"),
            Asset(asset_id="A006", hostname="mail-gateway-01", ip="192.168.1.30",
                  criticality="high", owner="infra-team", department="infrastructure",
                  os="rhel-9"),
            Asset(asset_id="A007", hostname="jump-server-01", ip="192.168.1.5",
                  criticality="critical", owner="infra-team", department="infrastructure",
                  os="ubuntu-22.04"),
            Asset(asset_id="A008", hostname="file-server-01", ip="192.168.1.40",
                  criticality="high", owner="infra-team", department="infrastructure",
                  os="windows-server-2022"),
            Asset(asset_id="A009", hostname="ci-runner-03", ip="192.168.1.60",
                  criticality="low", owner="dev-team", department="engineering",
                  os="ubuntu-22.04"),
            Asset(asset_id="A010", hostname="vpn-gateway-01", ip="192.168.1.2",
                  criticality="critical", owner="infra-team", department="infrastructure",
                  os="pfsense"),
        ]

    def get_log_sources(self) -> List[LogSource]:
        """Return available log sources."""
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
            LogSource(source_id="L006", source_type="dns",
                      hostname="dns-resolver-01", available=True),
            LogSource(source_id="L007", source_type="proxy",
                      hostname="proxy-server-01", available=True),
        ]

    # ------------------------------------------------------------------
    # IP reputation
    # ------------------------------------------------------------------
    def query_ip_reputation(self, ip: str) -> dict:
        """Look up threat intelligence for an IP address."""
        known_malicious = {
            "185.220.101.45": {
                "score": 95, "tags": ["tor-exit", "brute-force", "ssh-scanner"],
                "malicious": True, "country": "DE",
                "first_seen": "2023-11-15", "reports": 1247,
                "threat_type": "brute-force-attacker"
            },
            "194.165.16.72": {
                "score": 92, "tags": ["apt", "c2-server", "cobalt-strike"],
                "malicious": True, "country": "RU",
                "first_seen": "2024-01-20", "reports": 856,
                "threat_type": "command-and-control"
            },
            "45.33.32.156": {
                "score": 72, "tags": ["scanner", "recon", "shodan"],
                "malicious": True, "country": "US",
                "first_seen": "2022-06-01", "reports": 3420,
                "threat_type": "reconnaissance"
            },
            "91.240.118.172": {
                "score": 88, "tags": ["phishing", "credential-harvester"],
                "malicious": True, "country": "UA",
                "first_seen": "2024-02-10", "reports": 512,
                "threat_type": "phishing-infrastructure"
            },
            "103.75.201.4": {
                "score": 85, "tags": ["malware-distribution", "dropper"],
                "malicious": True, "country": "VN",
                "first_seen": "2024-03-05", "reports": 234,
                "threat_type": "malware-distributor"
            },
        }
        known_clean = {
            "192.168.1.99": {
                "score": 0, "tags": ["internal", "vuln-scanner", "authorized"],
                "malicious": False, "country": "internal",
                "first_seen": "N/A", "reports": 0,
                "threat_type": "none"
            },
            "8.8.8.8": {
                "score": 0, "tags": ["google-dns", "trusted"],
                "malicious": False, "country": "US",
                "first_seen": "N/A", "reports": 0,
                "threat_type": "none"
            },
            "192.168.1.55": {
                "score": 5, "tags": ["internal", "dev-workstation"],
                "malicious": False, "country": "internal",
                "first_seen": "N/A", "reports": 0,
                "threat_type": "none"
            },
        }

        # Check known databases
        if ip in known_malicious:
            result = dict(known_malicious[ip])
            # Add slight seed-based variation to score
            result["score"] = min(100, max(0, result["score"] + self.rng.randint(-3, 3)))
            return result
        if ip in known_clean:
            return dict(known_clean[ip])

        # Also check loaded IP reputation DB
        if self._ip_db and ip in self._ip_db:
            return dict(self._ip_db[ip])

        # Unknown IP — generate reputation
        score = self.rng.randint(10, 40)
        return {
            "score": score, "tags": ["unknown"], "malicious": False,
            "country": "unknown", "first_seen": "unknown", "reports": 0,
            "threat_type": "none"
        }

    # ------------------------------------------------------------------
    # Log retrieval
    # ------------------------------------------------------------------
    def pull_logs(self, source: str, context: Optional[dict] = None) -> List[str]:
        """Pull logs from a specific source. Context provides task-specific data."""
        context = context or {}
        base_time = datetime.fromisoformat(
            context.get("timestamp", "2024-06-01T10:00:00")
        )
        attacker_ip = context.get("attacker_ip", "185.220.101.45")
        c2_ip = context.get("c2_ip", "194.165.16.72")
        compromised_user = context.get("compromised_user", "ubuntu")

        logs = {
            "auth.log": [
                f"[{(base_time - timedelta(minutes=5)).isoformat()}] sshd: Failed password for root from {attacker_ip} port {42315 + self.rng.randint(0, 100)} ssh2",
                f"[{(base_time - timedelta(minutes=4)).isoformat()}] sshd: Failed password for root from {attacker_ip} port {42316 + self.rng.randint(0, 100)} ssh2",
                f"[{(base_time - timedelta(minutes=3, seconds=30)).isoformat()}] sshd: Failed password for admin from {attacker_ip} port {42317 + self.rng.randint(0, 100)} ssh2",
                f"[{(base_time - timedelta(minutes=3)).isoformat()}] sshd: Failed password for {compromised_user} from {attacker_ip} port {42318 + self.rng.randint(0, 100)} ssh2",
                f"[{(base_time - timedelta(minutes=2)).isoformat()}] sshd: Failed password for {compromised_user} from {attacker_ip} port {42319 + self.rng.randint(0, 100)} ssh2",
                f"[{(base_time - timedelta(minutes=1)).isoformat()}] sshd: Accepted password for {compromised_user} from {attacker_ip} port {42320 + self.rng.randint(0, 100)} ssh2",
                f"[{base_time.isoformat()}] sshd: pam_unix(sshd:session): session opened for user {compromised_user} by (uid=0)",
                f"[{(base_time + timedelta(seconds=30)).isoformat()}] sudo: {compromised_user} : TTY=pts/0 ; PWD=/home/{compromised_user} ; COMMAND=/bin/bash",
            ],
            "network.log": [
                f"[{(base_time - timedelta(minutes=1)).isoformat()}] ALLOW TCP {attacker_ip} -> 192.168.1.10 port 22 (SSH)",
                f"[{base_time.isoformat()}] ALLOW TCP 192.168.1.55 -> 192.168.1.20 port 5432 (PostgreSQL)",
                f"[{(base_time + timedelta(minutes=2)).isoformat()}] ALLOW TCP 192.168.1.55 -> 192.168.1.10 port 22 (SSH)",
                f"[{(base_time + timedelta(minutes=3)).isoformat()}] ALLOW TCP 192.168.1.55 -> 192.168.1.40 port 445 (SMB)",
                f"[{(base_time + timedelta(minutes=4)).isoformat()}] BLOCK TCP 192.168.1.99 -> 192.168.1.20 port 3306 (MySQL scan)",
                f"[{(base_time + timedelta(minutes=5)).isoformat()}] BLOCK TCP 192.168.1.99 -> 192.168.1.10 port 8080 (HTTP scan)",
                f"[{(base_time + timedelta(minutes=6)).isoformat()}] ALLOW TCP 192.168.1.20 -> {c2_ip} port 443 (HTTPS outbound)",
            ],
            "email.log": [
                f"[{(base_time - timedelta(hours=2)).isoformat()}] RECV from=phish@evil-domain.com to=hr@company.com subject='Urgent: Update your credentials immediately' attachment=update_credentials.html",
                f"[{(base_time - timedelta(hours=1, minutes=50)).isoformat()}] CLICK user=hr@company.com clicked link in email id=MSG-4821 from=phish@evil-domain.com url=https://evil-domain.com/login",
                f"[{(base_time - timedelta(hours=1, minutes=45)).isoformat()}] SUBMIT user=hr@company.com submitted form on https://evil-domain.com/login (credentials captured)",
                f"[{(base_time - timedelta(hours=1, minutes=30)).isoformat()}] RECV from=noreply@evil-domain.com to=hr@company.com subject='Password Reset Confirmation' (automated phishing follow-up)",
            ],
            "endpoint.log": [
                f"[{(base_time - timedelta(minutes=10)).isoformat()}] PROCESS_CREATE host=db-server-01 user={compromised_user} process=cmd.exe parent=explorer.exe pid=4521",
                f"[{base_time.isoformat()}] PROCESS_CREATE host=db-server-01 user={compromised_user} process=mimikatz.exe parent=cmd.exe pid=4522 hash=a1b2c3d4...suspicious",
                f"[{(base_time + timedelta(seconds=15)).isoformat()}] CREDENTIAL_ACCESS host=db-server-01 process=mimikatz.exe target=lsass.exe technique=T1003.001",
                f"[{(base_time + timedelta(minutes=1)).isoformat()}] NETWORK host=db-server-01 process=powershell.exe dst={c2_ip}:443 bytes_out=471859200 (450MB) protocol=HTTPS",
                f"[{(base_time + timedelta(minutes=2)).isoformat()}] FILE_CREATE host=db-server-01 user={compromised_user} path=C:\\Users\\{compromised_user}\\AppData\\Local\\Temp\\exfil.zip size=450MB",
                f"[{(base_time + timedelta(minutes=3)).isoformat()}] REGISTRY_MODIFY host=db-server-01 key=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run value=svchost_update.exe (persistence)",
            ],
            "dns.log": [
                f"[{(base_time - timedelta(hours=2, minutes=5)).isoformat()}] QUERY client=192.168.1.88 type=A name=evil-domain.com -> 91.240.118.172",
                f"[{(base_time - timedelta(hours=2)).isoformat()}] QUERY client=192.168.1.88 type=A name=evil-domain.com -> 91.240.118.172",
                f"[{(base_time - timedelta(minutes=5)).isoformat()}] QUERY client=192.168.1.20 type=A name=cdn-update.evil-domain.com -> {c2_ip} (suspicious subdomain)",
                f"[{base_time.isoformat()}] QUERY client=192.168.1.20 type=TXT name=exfil.evil-domain.com -> base64_encoded_data (possible DNS exfiltration)",
                f"[{(base_time + timedelta(minutes=1)).isoformat()}] QUERY client=192.168.1.55 type=A name=github.com -> 140.82.121.4 (benign)",
            ],
            "proxy.log": [
                f"[{(base_time - timedelta(hours=1, minutes=50)).isoformat()}] ALLOW user=hr_alice src=192.168.1.88 dst=evil-domain.com:443 method=GET url=/login category=UNCATEGORIZED",
                f"[{(base_time - timedelta(hours=1, minutes=49)).isoformat()}] ALLOW user=hr_alice src=192.168.1.88 dst=evil-domain.com:443 method=POST url=/login category=UNCATEGORIZED bytes=2048",
                f"[{base_time.isoformat()}] ALLOW user=system src=192.168.1.20 dst={c2_ip}:443 method=POST url=/api/upload category=UNCATEGORIZED bytes=471859200",
                f"[{(base_time + timedelta(minutes=5)).isoformat()}] BLOCK user=system src=192.168.1.20 dst={c2_ip}:8443 method=POST url=/beacon category=MALWARE",
            ],
        }
        return logs.get(source, [f"No logs found for source: {source}. Available: auth.log, network.log, endpoint.log, email.log, dns.log, proxy.log"])

    # ------------------------------------------------------------------
    # Asset lookup
    # ------------------------------------------------------------------
    def check_asset_criticality(self, asset_id: str) -> dict:
        """Look up asset information by ID or hostname."""
        registry = {a.asset_id: a for a in self.get_asset_registry()}
        hostname_map = {a.hostname: a for a in self.get_asset_registry()}
        asset = registry.get(asset_id) or hostname_map.get(asset_id)
        if not asset:
            return {"error": f"Asset '{asset_id}' not found in registry. Use asset IDs (A001-A010) or hostnames."}
        return {
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "ip": asset.ip,
            "criticality": asset.criticality,
            "owner": asset.owner,
            "department": asset.department,
            "os": asset.os,
        }

    # ------------------------------------------------------------------
    # Alert correlation
    # ------------------------------------------------------------------
    def correlate_alerts(self, window_minutes: int, context: Optional[dict] = None) -> List[str]:
        """Find correlated alerts within a time window."""
        context = context or {}
        kill_chain = context.get("kill_chain", [])

        if kill_chain:
            # Task has related alerts — return them based on window size
            base_alerts = []
            if window_minutes >= 30:
                base_alerts.append("CORRELATED: Alert ALERT-PHISH-001 — Phishing email received by hr@company.com (2h before current alert)")
            if window_minutes >= 60:
                base_alerts.append("CORRELATED: Alert ALERT-CRED-002 — Credential access detected on db-server-01 (mimikatz.exe, 10m before current alert)")
                base_alerts.append("CORRELATED: Alert ALERT-MOVE-003 — Unusual internal traffic from dev-workstation-05 to db-server-01 (15m before current alert)")
            if window_minutes >= 120:
                base_alerts.append("CORRELATED: Alert ALERT-EXFIL-004 — Large outbound transfer db-server-01 -> 194.165.16.72 (450MB, at time of current alert)")
                base_alerts.append("CORRELATED: Alert ALERT-PERSIST-005 — Registry modification for persistence on db-server-01 (3m after current alert)")
            if not base_alerts:
                base_alerts.append(f"No correlated alerts found in {window_minutes}-minute window. Try a larger window (60, 120).")
            base_alerts.append(f"--- Correlation window: {window_minutes} minutes, {len(base_alerts)} related alerts found ---")
            return base_alerts

        # No kill chain data — return minimal correlation
        return [
            f"No correlated alerts found in {window_minutes}-minute window.",
            "Only the current alert matches the criteria."
        ]

    # ------------------------------------------------------------------
    # User directory
    # ------------------------------------------------------------------
    def lookup_user(self, username: str) -> dict:
        """Look up user information from the directory."""
        users = {
            "ubuntu": {
                "username": "ubuntu", "department": "infrastructure",
                "role": "system-administrator", "active": True,
                "last_login": "2024-06-01T09:30:00", "mfa_enabled": True,
                "recent_password_change": False, "risk_score": 15,
                "groups": ["sudo", "docker", "infra-admins"],
            },
            "root": {
                "username": "root", "department": "system",
                "role": "superuser", "active": True,
                "last_login": "2024-05-28T14:00:00", "mfa_enabled": False,
                "recent_password_change": False, "risk_score": 5,
                "groups": ["root"],
            },
            "hr_alice": {
                "username": "hr_alice", "department": "human-resources",
                "role": "hr-analyst", "active": True,
                "last_login": "2024-06-01T08:00:00", "mfa_enabled": True,
                "recent_password_change": True, "risk_score": 65,
                "groups": ["hr-staff", "benefits-admin"],
                "note": "Password changed 2 hours ago — coincides with phishing campaign timing",
            },
            "dev_bob": {
                "username": "dev_bob", "department": "engineering",
                "role": "software-engineer", "active": True,
                "last_login": "2024-06-01T09:00:00", "mfa_enabled": True,
                "recent_password_change": False, "risk_score": 10,
                "groups": ["developers", "ci-users"],
            },
            "dba_charlie": {
                "username": "dba_charlie", "department": "database",
                "role": "database-administrator", "active": True,
                "last_login": "2024-05-31T17:00:00", "mfa_enabled": True,
                "recent_password_change": False, "risk_score": 20,
                "groups": ["dba-team", "sudo"],
            },
            "sec_diana": {
                "username": "sec_diana", "department": "security",
                "role": "security-engineer", "active": True,
                "last_login": "2024-06-01T07:45:00", "mfa_enabled": True,
                "recent_password_change": False, "risk_score": 5,
                "groups": ["security-team", "vuln-scanner-ops"],
            },
        }
        result = users.get(username)
        if result:
            return dict(result)
        return {"error": f"User '{username}' not found. Known users: {', '.join(users.keys())}"}

    # ------------------------------------------------------------------
    # Containment actions
    # ------------------------------------------------------------------
    def isolate_host(self, hostname: str) -> dict:
        """Simulate host isolation (containment action)."""
        registry = {a.hostname: a for a in self.get_asset_registry()}
        asset = registry.get(hostname)
        if not asset:
            return {
                "status": "failed",
                "reason": f"Host '{hostname}' not found in asset registry.",
            }
        return {
            "status": "success",
            "action": "host_isolated",
            "hostname": hostname,
            "ip": asset.ip,
            "criticality": asset.criticality,
            "warning": f"Host {hostname} ({asset.criticality} criticality) has been isolated from the network.",
        }

    def block_ip(self, ip: str) -> dict:
        """Simulate IP blocking at the firewall (containment action)."""
        rep = self.query_ip_reputation(ip)
        return {
            "status": "success",
            "action": "ip_blocked",
            "ip": ip,
            "was_malicious": rep.get("malicious", False),
            "reputation_score": rep.get("score", 0),
            "message": f"IP {ip} has been blocked at the perimeter firewall.",
        }