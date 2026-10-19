"""
Tests for Audit Logging and Security Monitoring.

Verifies:
- Every setpoint request (approved, rejected by authorization, or rejected by safety interlock)
  is logged with an ISO-8601 UTC timestamp.
- Audit records faithfully capture:
  - original_value
  - requested_value
  - authorization_outcome
  - safety_result
  - detection_result
  - final_decision
  - rejection_reason
- Record serialization to dictionary and JSON.
- Filtering methods for audit inspection (all records, rejected records, anomalies).
"""

import unittest
from datetime import datetime
import json

from src.config import HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM, HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
from src.safety import Role, SessionType, OperatorContext, AuthorizationStatus, SafetyValidationStatus
from src.audit import AuditLogger, AuditRecord, DetectionResult, FinalDecision
from src.scada_system import ScadaSystem


class TestAuditLogging(unittest.TestCase):
    """Verifies audit trail integrity and structured logging requirements."""

    def setUp(self) -> None:
        self.scada = ScadaSystem()
        self.authorized_operator = OperatorContext(
            user_id="operator_carol",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )
        self.unauthorized_remote = OperatorContext(
            user_id="unauthorized_actor",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )

    def test_utc_timestamp_format(self) -> None:
        """Audit record timestamp must be a valid ISO-8601 UTC string."""
        _, record = self.scada.request_setpoint_change(self.authorized_operator, 104.0)

        self.assertIsNotNone(record.timestamp_utc)
        # Parse ISO format to ensure valid timestamp
        parsed_dt = datetime.fromisoformat(record.timestamp_utc)
        self.assertIsNotNone(parsed_dt.tzinfo)

    def test_complete_audit_record_schema_approved_request(self) -> None:
        """Approved requests must populate all schema fields with COMMITTED verdict and no error reason."""
        _, record = self.scada.request_setpoint_change(self.authorized_operator, 102.0)

        self.assertEqual(record.actor, "operator_carol")
        self.assertEqual(record.session_type, SessionType.LOCAL_HMI_CONSOLE.value)
        self.assertEqual(record.original_value, 100.0)
        self.assertEqual(record.requested_value, 102.0)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(record.detection_result, DetectionResult.NORMAL.value)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)
        self.assertIsNone(record.rejection_reason)

    def test_complete_audit_record_schema_unauthorized_rejection(self) -> None:
        """Unauthorized requests must log authorization denial, safety not evaluated, and rejection reason."""
        _, record = self.scada.request_setpoint_change(self.unauthorized_remote, 102.0)

        self.assertEqual(record.actor, "unauthorized_actor")
        self.assertEqual(record.session_type, SessionType.UNAUTHORIZED_REMOTE.value)
        self.assertEqual(record.original_value, 100.0)
        self.assertEqual(record.requested_value, 102.0)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.NOT_EVALUATED.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertIsNotNone(record.rejection_reason)
        self.assertIn("Authorization Denied", record.rejection_reason)

    def test_complete_audit_record_schema_safety_interlock_rejection(self) -> None:
        """Safety interlock rejections must log authorization approval, safety status, and specific cutoff reason."""
        _, record = self.scada.request_setpoint_change(
            self.authorized_operator,
            HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        self.assertEqual(record.original_value, 100.0)
        self.assertEqual(record.requested_value, 11100.0)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)

    def test_record_json_serialization(self) -> None:
        """Audit records must serialize faithfully to JSON."""
        _, record = self.scada.request_setpoint_change(self.authorized_operator, 103.0)
        json_str = record.to_json()

        data = json.loads(json_str)
        self.assertEqual(data["actor"], "operator_carol")
        self.assertEqual(data["requested_value"], 103.0)
        self.assertEqual(data["final_decision"], FinalDecision.COMMITTED.value)

    def test_query_filter_methods(self) -> None:
        """Audit logger query methods accurately categorize records."""
        # 1. Benign approved
        self.scada.request_setpoint_change(self.authorized_operator, 102.0)
        # 2. Rejected by authorization
        self.scada.request_setpoint_change(self.unauthorized_remote, 102.0)
        # 3. Rejected by safety interlock
        self.scada.request_setpoint_change(self.authorized_operator, 11100.0)

        all_records = self.scada.audit_logger.get_records()
        rejected_records = self.scada.audit_logger.get_rejected_records()
        anomalies = self.scada.audit_logger.get_anomalies()

        self.assertEqual(len(all_records), 3)
        self.assertEqual(len(rejected_records), 2)
        # Both unauthorized remote access and 11,100 ppm jump are anomalies
        self.assertEqual(len(anomalies), 2)


if __name__ == "__main__":
    unittest.main()
