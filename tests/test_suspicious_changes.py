"""
Tests for Suspicious and Anomalous Setpoint Change Detection.

Verifies:
- Anomaly detector identifies rapid setpoint deltas exceeding normal step thresholds.
- Detection engine raises critical alerts on extreme values (e.g. 11,100 ppm) and unauthorized sessions.
- Safety interlock trips on sudden excessive deltas (e.g. 15 ppm delta against 10 ppm illustrative step limit).
- System preserves original setpoint and logs full diagnostic telemetry.
"""

import unittest
from src.config import HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM, HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
from src.safety import Role, SessionType, OperatorContext, SafetyValidationStatus, AuthorizationStatus
from src.audit import AnomalyDetector, DetectionResult, FinalDecision
from src.scada_system import ScadaSystem


class TestSuspiciousChanges(unittest.TestCase):
    """Verifies behavioral detection rules and alerting for suspicious requests."""

    def setUp(self) -> None:
        self.scada = ScadaSystem()
        self.detector = AnomalyDetector(step_delta_threshold=10.0)
        self.authorized_operator = OperatorContext(
            user_id="operator_bob",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

    def test_detector_identifies_suspicious_step_delta(self) -> None:
        """Delta of 15.0 ppm (100 -> 115 ppm) flags SUSPICIOUS_DELTA."""
        result = self.detector.evaluate(
            original_value=100.0,
            requested_value=115.0,
            session_type=SessionType.LOCAL_HMI_CONSOLE.value,
            is_authenticated=True
        )
        self.assertEqual(result, DetectionResult.SUSPICIOUS_DELTA)

    def test_detector_identifies_critical_incident_value(self) -> None:
        """Target setpoint of 11,100.0 ppm triggers CRITICAL_ANOMALY."""
        result = self.detector.evaluate(
            original_value=100.0,
            requested_value=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
            session_type=SessionType.LOCAL_HMI_CONSOLE.value,
            is_authenticated=True
        )
        self.assertEqual(result, DetectionResult.CRITICAL_ANOMALY)

    def test_detector_identifies_unauthorized_remote_session(self) -> None:
        """Unauthorized remote session triggers CRITICAL_ANOMALY even for small setpoint change."""
        result = self.detector.evaluate(
            original_value=100.0,
            requested_value=102.0,
            session_type=SessionType.UNAUTHORIZED_REMOTE.value,
            is_authenticated=False
        )
        self.assertEqual(result, DetectionResult.CRITICAL_ANOMALY)

    def test_suspicious_delta_rejected_by_safety_interlock(self) -> None:
        """
        Even when requested by an authorized operator, a jump from 100.0 to 115.0 ppm
        (exceeding the illustrative 10.0 ppm single-step limit) must be rejected,
        preserving the original 100.0 ppm setpoint.
        """
        success, record = self.scada.request_setpoint_change(
            context=self.authorized_operator,
            requested_setpoint_ppm=115.0
        )

        self.assertFalse(success)
        self.assertEqual(self.scada.process.current_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.EXCEEDS_STEP_DELTA.value)
        self.assertEqual(record.detection_result, DetectionResult.SUSPICIOUS_DELTA.value)
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)

    def test_audit_logger_tracks_anomalies(self) -> None:
        """Audit logger correctly indexes and retrieves flagged anomalies."""
        self.scada.request_setpoint_change(self.authorized_operator, 115.0)  # Suspicious delta
        self.scada.request_setpoint_change(self.authorized_operator, 102.0)  # Normal benign change

        anomalies = self.scada.audit_logger.get_anomalies()
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].requested_value, 115.0)

    def test_defensive_layer_timely_alerting_and_rejection_for_unauthorized_suspicious_request(self) -> None:
        """
        Integration test addressing the research question's timely-alerting requirement:
        'Can an additional defensive layer detect and prevent unauthorized process-setpoint
        changes even when the original SCADA system does not generate a timely alarm?'

        Verifies that:
        1. A suspicious setpoint change (115.0 ppm) requested by an unauthorized remote session
           is immediately intercepted and classified by the defensive anomaly detection layer.
        2. The defensive layer records the expected alert (CRITICAL_ANOMALY) in the returned audit
           record with an immutable ISO-8601 UTC timestamp and indexes it in the anomaly log.
        3. The request is rejected without committing changes, preserving all process telemetry.

        Modeling Scope Note:
        The native legacy SCADA alarm subsystem is explicitly modeled as an independent component
        (ScadaAlarmState.CLEAR at request time), validating that the defensive layer intercepts
        and alerts even when the native SCADA system does not generate a timely alarm.
        """
        unauthorized_remote = OperatorContext(
            user_id="unauthorized_remote_actor",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )
        pre_state = self.scada.get_process_state()

        # 1. Submit simulated suspicious setpoint-change request via public API
        success, record = self.scada.request_setpoint_change(
            context=unauthorized_remote,
            requested_setpoint_ppm=115.0
        )

        # 2. Defensive layer records expected anomaly classification and timely UTC timestamp
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.native_alarm_state, "CLEAR")
        self.assertIsNotNone(record.timestamp_utc)
        self.assertIn(record, self.scada.audit_logger.get_anomalies())

        # 3. Request is rejected and process state remains completely unchanged
        self.assertFalse(success)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(self.scada.process.current_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)

        post_state = self.scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)
        self.assertEqual(post_state.measured_concentration_ppm, pre_state.measured_concentration_ppm)
        self.assertEqual(post_state.simulated_ph, pre_state.simulated_ph)
        self.assertEqual(post_state.pump_active, pre_state.pump_active)


if __name__ == "__main__":
    unittest.main()
