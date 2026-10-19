"""
Tests for Normal, Authorized Operations within Illustrative Operational Limits.

Verifies:
- Authorized operator on local console can modify setpoint within illustrative normal range.
- Process state updates accurately upon approved setpoint change.
- Audit records reflect authorized and committed status with complete schema.
- Physical plant model simulates chemical concentration progression towards new setpoint.
"""

import unittest
from src.config import HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM
from src.safety import Role, SessionType, OperatorContext, AuthorizationStatus, SafetyValidationStatus
from src.audit import DetectionResult, FinalDecision
from src.scada_system import ScadaSystem


class TestNormalOperation(unittest.TestCase):
    """Verifies baseline legitimate operations under normal plant conditions."""

    def setUp(self) -> None:
        self.scada = ScadaSystem()
        self.operator_context = OperatorContext(
            user_id="operator_jane",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

    def test_initial_reference_state(self) -> None:
        """Process must initialize at the historical reference setpoint of 100.0 ppm."""
        state = self.scada.get_process_state()
        self.assertEqual(state.active_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)
        self.assertEqual(state.measured_concentration_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)
        self.assertTrue(state.pump_active)

    def test_benign_setpoint_change_success(self) -> None:
        """Authorized operator slightly adjusting setpoint (100.0 -> 105.0 ppm) succeeds."""
        success, record = self.scada.request_setpoint_change(
            context=self.operator_context,
            requested_setpoint_ppm=105.0
        )

        self.assertTrue(success)
        self.assertEqual(self.scada.process.current_setpoint_ppm, 105.0)

        # Validate audit logging schema
        self.assertEqual(record.actor, "operator_jane")
        self.assertEqual(record.session_type, SessionType.LOCAL_HMI_CONSOLE.value)
        self.assertEqual(record.original_value, 100.0)
        self.assertEqual(record.requested_value, 105.0)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(record.detection_result, DetectionResult.NORMAL.value)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)
        self.assertIsNone(record.rejection_reason)

    def test_plant_engineer_authorized_role(self) -> None:
        """Plant engineer over authenticated VPN is authorized for benign adjustments."""
        engineer_context = OperatorContext(
            user_id="eng_marcus",
            role=Role.PLANT_ENGINEER,
            session_type=SessionType.AUTHENTICATED_REMOTE_VPN,
            is_authenticated=True
        )
        success, record = self.scada.request_setpoint_change(
            context=engineer_context,
            requested_setpoint_ppm=95.0
        )
        self.assertTrue(success)
        self.assertEqual(self.scada.process.current_setpoint_ppm, 95.0)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)

    def test_process_physical_dynamics_simulation(self) -> None:
        """Plant dynamics simulate gradual chemical concentration adjustment towards new setpoint."""
        self.scada.request_setpoint_change(self.operator_context, 105.0)
        initial_measured = self.scada.get_process_state().measured_concentration_ppm

        # Advance simulation by 2 seconds
        self.scada.simulate_process_step(elapsed_seconds=2.0)
        updated_state = self.scada.get_process_state()

        # Chemical concentration should move towards 105.0 ppm
        self.assertGreater(updated_state.measured_concentration_ppm, initial_measured)
        self.assertLessEqual(updated_state.measured_concentration_ppm, 105.0)


if __name__ == "__main__":
    unittest.main()
