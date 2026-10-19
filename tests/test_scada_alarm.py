"""
Tests for Native SCADA Alarm Subsystem and Decoupled Defensive Layer.

Directly investigates and validates the central research question:
"Can an additional defensive layer detect and prevent unauthorized process-setpoint
changes even when the original SCADA system does not generate a timely alarm?"

Educational Notice:
These tests use illustrative laboratory rules and assumptions (e.g., 300s debounce delay,
unconfigured setpoint registers, 130 ppm PV alarm threshold). They do NOT claim to model
the proprietary alarm configuration of the historical Oldsmar municipal facility.
"""

import unittest
from src.config import (
    HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
    HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
    LAB_ILLUSTRATIVE_SCADA_ALARM_DELAY_SECONDS,
    LAB_ILLUSTRATIVE_SCADA_ALARM_PV_THRESHOLD_PPM,
)
from src.process import ProcessState
from src.safety import Role, SessionType, OperatorContext, AuthorizationStatus, SafetyValidationStatus
from src.audit import DetectionResult, FinalDecision
from src.scada_alarm import (
    NativeScadaAlarmSubsystem,
    ScadaAlarmConfig,
    ScadaAlarmMode,
    ScadaAlarmState,
)
from src.scada_system import ScadaSystem


class TestNativeScadaAlarmSubsystem(unittest.TestCase):
    """Verifies independent behavior of the native SCADA alarm subsystem."""

    def test_native_alarm_silent_when_setpoint_unconfigured(self) -> None:
        """
        When supervisory setpoint registers have no alarm configured (common legacy gap),
        any setpoint change request leaves the native alarm in CLEAR state.
        """
        config = ScadaAlarmConfig(mode=ScadaAlarmMode.UNCONFIGURED_SETPOINT_ALARM)
        alarm_sys = NativeScadaAlarmSubsystem(config)
        process_state = ProcessState(
            active_setpoint_ppm=100.0,
            measured_concentration_ppm=100.0,
            simulated_ph=7.50,
            pump_active=False
        )

        state = alarm_sys.evaluate_request(HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM, process_state)
        self.assertEqual(state, ScadaAlarmState.CLEAR)
        self.assertEqual(alarm_sys.state, ScadaAlarmState.CLEAR)

    def test_native_alarm_delayed_on_process_variable(self) -> None:
        """
        In DELAYED_PV_ALARM mode, alarms monitor downstream sensor telemetry (PV)
        rather than setpoints. At t = 0, physical chemistry has not deviated, so
        the native alarm remains CLEAR (no timely alarm at moment of request).
        """
        config = ScadaAlarmConfig(
            mode=ScadaAlarmMode.DELAYED_PV_ALARM,
            alarm_delay_seconds=300.0,
            pv_alarm_threshold_ppm=130.0
        )
        alarm_sys = NativeScadaAlarmSubsystem(config)
        normal_process_state = ProcessState(
            active_setpoint_ppm=100.0,
            measured_concentration_ppm=100.0,
            simulated_ph=7.50,
            pump_active=False
        )

        state = alarm_sys.evaluate_request(HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM, normal_process_state)
        self.assertEqual(state, ScadaAlarmState.CLEAR)

    def test_native_alarm_pv_delay_timer_progression(self) -> None:
        """
        Verifies that physical sensor alarms transition from PENDING_DELAY to ACTIVE
        only after the illustrative debounce/delay timer expires.
        """
        config = ScadaAlarmConfig(
            mode=ScadaAlarmMode.DELAYED_PV_ALARM,
            alarm_delay_seconds=300.0,
            pv_alarm_threshold_ppm=130.0
        )
        alarm_sys = NativeScadaAlarmSubsystem(config)
        high_pv_state = ProcessState(
            active_setpoint_ppm=140.0,
            measured_concentration_ppm=140.0,  # Exceeds 130.0 ppm threshold
            simulated_ph=8.20,
            pump_active=True
        )

        # At t = 0s of out-of-spec condition: PENDING_DELAY
        state_t0 = alarm_sys.update_telemetry(high_pv_state, elapsed_seconds=0.0)
        self.assertEqual(state_t0, ScadaAlarmState.PENDING_DELAY)

        # After 150s (< 300s delay): still PENDING_DELAY (untimely alarm)
        state_t150 = alarm_sys.update_telemetry(high_pv_state, elapsed_seconds=150.0)
        self.assertEqual(state_t150, ScadaAlarmState.PENDING_DELAY)

        # After additional 150s (total 300s): transitions to ACTIVE
        state_t300 = alarm_sys.update_telemetry(high_pv_state, elapsed_seconds=150.0)
        self.assertEqual(state_t300, ScadaAlarmState.ACTIVE)


class TestUntimelyAlarmEducationalScenario(unittest.TestCase):
    """
    Directly tests the central research question:
    "Can an additional defensive layer detect and prevent unauthorized process-setpoint
    changes even when the original SCADA system does not generate a timely alarm?"
    """

    def setUp(self) -> None:
        self.unauthorized_remote = OperatorContext(
            user_id="remote_exploit_actor",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )
        self.compromised_operator = OperatorContext(
            user_id="operator_insider_or_hijacked",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

    def test_defensive_layer_intercepts_unauthorized_attack_when_native_alarm_silent(self) -> None:
        """
        EDUCATIONAL SCENARIO 1:
        Adversary injects 11,100.0 ppm via unauthorized remote access.
        The native SCADA alarm is unconfigured on setpoint tags (SILENT / CLEAR).

        Asserts:
        - Native SCADA alarm remains CLEAR (no alarm generated).
        - Defensive anomaly detector immediately triggers CRITICAL_ANOMALY.
        - Authorization policy rejects request (Gate 1).
        - Process state (active setpoint, measured concentration, pH) is preserved completely.
        - Audit trail captures both detection alert and native alarm state.
        """
        scada = ScadaSystem(
            alarm_config=ScadaAlarmConfig(mode=ScadaAlarmMode.UNCONFIGURED_SETPOINT_ALARM)
        )
        pre_state = scada.get_process_state()

        # Submit unauthorized setpoint change to incident target (11,100 ppm)
        success, record = scada.request_setpoint_change(
            context=self.unauthorized_remote,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        # 1. Verification of Native Alarm state: Untimely / Silent
        self.assertEqual(scada.get_native_alarm_state(), ScadaAlarmState.CLEAR)
        self.assertEqual(record.native_alarm_state, ScadaAlarmState.CLEAR.value)

        # 2. Verification of Defensive Layer: Immediate Alert & Hard Rejection
        self.assertFalse(success)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertIn("Authorization Denied", record.rejection_reason)

        # 3. Verification of Physical Process State Preservation
        post_state = scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)
        self.assertEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)
        self.assertEqual(post_state.measured_concentration_ppm, pre_state.measured_concentration_ppm)
        self.assertEqual(post_state.simulated_ph, pre_state.simulated_ph)
        self.assertEqual(post_state.pump_active, pre_state.pump_active)

    def test_defensive_layer_intercepts_unauthorized_attack_when_native_alarm_delayed_pv(self) -> None:
        """
        EDUCATIONAL SCENARIO 2:
        Adversary injects 11,100.0 ppm via unauthorized remote access.
        The native SCADA alarm only monitors process variables with a 300s debounce delay.

        Asserts:
        - At t = 0, native alarm is CLEAR (no timely alarm generated at moment of attack).
        - Defensive anomaly detector immediately triggers CRITICAL_ANOMALY.
        - Request rejected and process state preserved.
        """
        scada = ScadaSystem(
            alarm_config=ScadaAlarmConfig(
                mode=ScadaAlarmMode.DELAYED_PV_ALARM,
                alarm_delay_seconds=300.0,
                pv_alarm_threshold_ppm=130.0
            )
        )
        pre_state = scada.get_process_state()

        success, record = scada.request_setpoint_change(
            context=self.unauthorized_remote,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        self.assertFalse(success)
        # At request time, native alarm did not fire
        self.assertEqual(scada.get_native_alarm_state(), ScadaAlarmState.CLEAR)
        self.assertEqual(record.native_alarm_state, ScadaAlarmState.CLEAR.value)
        # Defensive layer flagged anomaly
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        # Process state preserved
        self.assertEqual(scada.get_process_state().active_setpoint_ppm, pre_state.active_setpoint_ppm)

    def test_defense_in_depth_insider_jump_rejected_by_safety_interlock_when_native_alarm_silent(self) -> None:
        """
        EDUCATIONAL SCENARIO 3 (Defense-in-Depth):
        Authorized operator credentials are used to submit 11,100.0 ppm.
        Native SCADA alarm is silent (unconfigured).

        Asserts:
        - Native alarm remains CLEAR.
        - Authorization gate passes (valid credential).
        - Independent Safety Interlock hard-rejects the request (EXCEEDS_HARD_LIMIT).
        - Process state preserved at 100.0 ppm.
        - Audit trail records: Auth=AUTHORIZED, Safety=EXCEEDS_HARD_LIMIT, NativeAlarm=CLEAR.
        """
        scada = ScadaSystem(
            alarm_config=ScadaAlarmConfig(mode=ScadaAlarmMode.UNCONFIGURED_SETPOINT_ALARM)
        )

        success, record = scada.request_setpoint_change(
            context=self.compromised_operator,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        self.assertFalse(success)
        self.assertEqual(scada.get_native_alarm_state(), ScadaAlarmState.CLEAR)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.native_alarm_state, ScadaAlarmState.CLEAR.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(scada.get_process_state().active_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)

    def test_audit_record_records_both_defensive_alert_and_native_alarm_state(self) -> None:
        """
        Verifies that every audit record independently documents both the defensive alert
        classification and the native SCADA alarm state.
        """
        scada = ScadaSystem(
            alarm_config=ScadaAlarmConfig(mode=ScadaAlarmMode.DELAYED_PV_ALARM)
        )
        _, record = scada.request_setpoint_change(
            context=self.unauthorized_remote,
            requested_setpoint_ppm=115.0
        )

        record_dict = record.to_dict()
        self.assertIn("native_alarm_state", record_dict)
        self.assertIn("detection_result", record_dict)
        self.assertEqual(record_dict["native_alarm_state"], ScadaAlarmState.CLEAR.value)
        self.assertEqual(record_dict["detection_result"], DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record_dict["final_decision"], FinalDecision.REJECTED.value)


if __name__ == "__main__":
    unittest.main()
