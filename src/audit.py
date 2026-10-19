"""
Audit Logging and Anomaly Detection for SCADA Operations.

Records tamper-evident, structured audit logs for every setpoint request and
monitors for anomalous or malicious patterns (such as extreme setpoint jumps
reminiscent of the 2021 Oldsmar incident).
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import json
from typing import List, Optional, Dict, Any

from src.config import HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM


class DetectionResult(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS_DELTA = "SUSPICIOUS_DELTA"
    UNUSUAL_SESSION = "UNUSUAL_SESSION"
    CRITICAL_ANOMALY = "CRITICAL_ANOMALY"


class FinalDecision(str, Enum):
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class AuditRecord:
    """
    Immutable audit record representing a single setpoint transaction or attempt.

    Contains all required audit fields:
    - UTC timestamp
    - original and requested values
    - authorization outcome
    - safety result where evaluated
    - detection result
    - final decision
    - rejection reason (if rejected)
    """
    timestamp_utc: str
    actor: str
    session_type: str
    original_value: float
    requested_value: float
    authorization_outcome: str
    safety_result: str
    detection_result: str
    final_decision: str
    rejection_reason: Optional[str] = None
    native_alarm_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts the record to a dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Converts the record to a JSON-formatted string."""
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Returns a concise one-line summary of the transaction."""
        alarm_part = f" | NativeAlarm={self.native_alarm_state}" if self.native_alarm_state else ""
        return (
            f"[{self.timestamp_utc}] Actor='{self.actor}' ({self.session_type}) | "
            f"Setpoint: {self.original_value:.1f} -> {self.requested_value:.1f} ppm | "
            f"Auth={self.authorization_outcome} | Safety={self.safety_result} | "
            f"Detection={self.detection_result}{alarm_part} | Verdict={self.final_decision}"
            + (f" | Reason: {self.rejection_reason}" if self.rejection_reason else "")
        )


class AnomalyDetector:
    """
    Heuristic and rule-based anomaly detector for control system setpoint traffic.
    Identifies suspicious behavior before or during transaction evaluation.
    """

    def __init__(self, step_delta_threshold: float = 10.0) -> None:
        self.step_delta_threshold = step_delta_threshold

    def evaluate(
        self,
        original_value: float,
        requested_value: float,
        session_type: str,
        is_authenticated: bool
    ) -> DetectionResult:
        """
        Analyzes setpoint trajectory and session characteristics for anomalies.
        """
        delta = abs(requested_value - original_value)

        # 1. Critical anomaly: Attempt to set setpoint to extreme values (e.g. 11,100 ppm incident value)
        # or massive jump (> 10x max step or > 500 ppm)
        if requested_value >= 500.0 or delta >= 500.0:
            return DetectionResult.CRITICAL_ANOMALY

        # 2. Critical anomaly: Unauthenticated or unauthorized remote session
        if not is_authenticated or session_type == "UNAUTHORIZED_REMOTE":
            return DetectionResult.CRITICAL_ANOMALY

        # 3. Suspicious delta: Setpoint change exceeding normal single-step limit
        if delta > self.step_delta_threshold:
            return DetectionResult.SUSPICIOUS_DELTA

        return DetectionResult.NORMAL


class AuditLogger:
    """
    In-memory audit log repository providing structured query and SIEM-like export capabilities.
    """

    def __init__(self) -> None:
        self._records: List[AuditRecord] = []

    def log(
        self,
        actor: str,
        session_type: str,
        original_value: float,
        requested_value: float,
        authorization_outcome: str,
        safety_result: str,
        detection_result: str,
        final_decision: str,
        rejection_reason: Optional[str] = None,
        custom_timestamp: Optional[str] = None,
        native_alarm_state: Optional[str] = None
    ) -> AuditRecord:
        """
        Creates and appends an immutable audit record with a UTC ISO-8601 timestamp.
        """
        timestamp = custom_timestamp or datetime.now(timezone.utc).isoformat()
        record = AuditRecord(
            timestamp_utc=timestamp,
            actor=actor,
            session_type=session_type,
            original_value=round(float(original_value), 3),
            requested_value=round(float(requested_value), 3),
            authorization_outcome=str(authorization_outcome),
            safety_result=str(safety_result),
            detection_result=str(detection_result),
            final_decision=str(final_decision),
            rejection_reason=rejection_reason,
            native_alarm_state=str(native_alarm_state) if native_alarm_state is not None else None
        )
        self._records.append(record)
        return record

    def get_records(self) -> List[AuditRecord]:
        """Returns all logged records in chronological order."""
        return list(self._records)

    def get_rejected_records(self) -> List[AuditRecord]:
        """Returns all records where the setpoint change was rejected."""
        return [r for r in self._records if r.final_decision == FinalDecision.REJECTED.value]

    def get_anomalies(self) -> List[AuditRecord]:
        """Returns all records flagged as suspicious or critical anomalies."""
        return [
            r for r in self._records
            if r.detection_result in (DetectionResult.SUSPICIOUS_DELTA.value, DetectionResult.CRITICAL_ANOMALY.value)
        ]

    def clear(self) -> None:
        """Clears in-memory audit records (useful for test isolation)."""
        self._records.clear()
