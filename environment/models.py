"""
Typed Pydantic models for the SOC Triage Environment.

Defines the data structures used across the environment, including:
- Alert and asset models used internally by the simulator
- Observation, Action, and State models exposed via the API
- Severity and VerdictType enumerations
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerdictType(str, Enum):
    ESCALATE = "escalate"
    ESCALATE_CRITICAL = "escalate_critical"
    CLOSE_FALSE_POSITIVE = "close_false_positive"


# ---------------------------------------------------------------------------
# Internal domain models (used by simulator / tasks)
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    """A network asset in the SOC environment."""
    asset_id: str
    hostname: str
    ip: str
    criticality: str  # low | medium | high | critical
    owner: str
    department: str = ""
    os: str = "linux"


class LogSource(BaseModel):
    """A log source available for investigation."""
    source_id: str
    source_type: str  # auth, network, endpoint, email, dns, proxy
    hostname: str
    available: bool = True


class AlertSummary(BaseModel):
    """Summary of a security alert presented to the agent."""
    alert_id: str
    title: str
    severity: Severity
    timestamp: str  # ISO format string for JSON safety
    source_ip: Optional[str] = None
    target_asset: Optional[str] = None
    description: str


class ActionRecord(BaseModel):
    """Record of an action taken during an episode."""
    action_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    result: str = ""
    step: int = 0


# ---------------------------------------------------------------------------
# Environment state (internal, full state for grading)
# ---------------------------------------------------------------------------

class SOCState(BaseModel):
    """Full internal state of the environment for a single episode."""
    episode_id: str = ""
    task_id: str = ""
    alert_id: str = ""
    alert_summary: AlertSummary
    severity: Severity
    timestamp: str  # ISO format string
    assets_involved: List[Asset] = Field(default_factory=list)
    logs_available: List[LogSource] = Field(default_factory=list)
    actions_taken: List[ActionRecord] = Field(default_factory=list)
    step_count: int = 0
    max_steps: int = 10
    verdict: Optional[str] = None
    done: bool = False


# ---------------------------------------------------------------------------
# API-facing models (what the agent sees / sends)
# ---------------------------------------------------------------------------

AVAILABLE_ACTIONS = [
    "pull_logs <source>          — sources: auth.log, network.log, endpoint.log, email.log, dns.log, proxy.log",
    "query_ip_reputation <ip>    — check threat intel for an IP address",
    "check_asset_criticality <asset_id_or_hostname> — look up asset details",
    "correlate_alerts <window_minutes> — find related alerts in time window",
    "lookup_user <username>      — look up user account details",
    "isolate_host <hostname>     — containment: isolate a compromised host",
    "block_ip <ip>               — containment: block a malicious IP at firewall",
    "escalate <reason>           — submit verdict: escalate to Tier 2",
    "escalate_critical <reason>  — submit verdict: critical escalation to IR team",
    "close_false_positive <reason> — submit verdict: close as false positive",
]


class SOCObservation(BaseModel):
    """Observation returned to the agent after each step."""
    alert: AlertSummary
    last_action_result: str = ""
    available_actions: List[str] = Field(default_factory=lambda: list(AVAILABLE_ACTIONS))
    step_count: int = 0
    max_steps: int = 10
    context_gathered: List[str] = Field(default_factory=list)
    done: bool = False


class SOCReward(BaseModel):
    """Reward breakdown returned with each step."""
    total: float = 0.0
    components: Dict[str, float] = Field(default_factory=dict)