from pydantic import BaseModel
from typing import List, Optional
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    LOW = "LOW"
    MED = "MED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Asset(BaseModel):
    asset_id: str
    hostname: str
    ip: str
    criticality: str  # "low" | "medium" | "high" | "critical"
    owner: str


class LogSource(BaseModel):
    source_id: str
    source_type: str  # "auth", "network", "endpoint", "email"
    hostname: str
    available: bool


class Action(BaseModel):
    action_type: str
    parameters: dict
    result: str
    step: int


class AlertSummary(BaseModel):
    alert_id: str
    title: str
    severity: Severity
    timestamp: datetime
    source_ip: Optional[str] = None
    target_asset: Optional[str] = None
    description: str


class SOCState(BaseModel):
    alert_id: str
    alert_summary: AlertSummary
    severity: Severity
    timestamp: datetime
    assets_involved: List[Asset]
    logs_available: List[LogSource]
    actions_taken: List[Action]
    step_count: int
    max_steps: int
    verdict: Optional[str] = None
    ground_truth: Optional[dict] = None


class SOCObservation(BaseModel):
    alert: AlertSummary
    last_action_result: str
    available_actions: List[str]
    step_count: int
    context_gathered: List[str] 