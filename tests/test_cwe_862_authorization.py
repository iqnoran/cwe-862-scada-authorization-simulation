"""
Tests for CWE-862: Missing Authorization in SCADA Supervisory Control.

Educational Scope & Threat Modeling:
Demonstrates the contrast between:
1. Protected Mode: Gate 1 strictly validates actor identity, role permissions,
   and session type before evaluating physical safety or applying setpoints.
2. Vulnerable Mode (CWE-862): Gate 1 authorization check is deliberately omitted.
   An unauthorized user can modify physical process setpoints if the requested
   value does not violate physical safety interlocks.

EDUCATIONAL DISCLAIMERS:
- CWE-862 is an educational software vulnerability modeled strictly for local study.
- It is NOT claimed to be the cause of the historical 2021 Oldsmar incident.
- All threshold values and setpoint bounds are illustrative laboratory assumptions.
"""

import unittest
from src.config import (
    HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
    HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
    LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM,
    LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM,
)
from src.safety import (
    Role,
    SessionType,
    OperatorContext,
    AuthorizationMode,
    AuthorizationStatus,
    SafetyValidationStatus,
)
from src.audit import FinalDecision
from src.scada_system import ScadaSystem


class TestCWE862MissingAuthorization(unittest.TestCase):
    """
    Validates comparative behavior between Protected Mode and Vulnerable Mode (CWE-862).
    Uses a fresh ScadaSystem instance for each test to guarantee no state contamination.
    """

    def setUp(self) -> None:
        # Standard authorized municipal operator
        self.authorized_operator = OperatorContext(
            user_id="operator_alice",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )
        # Unauthorized actor (simulating unauthorized remote desktop session or guest role)
        self.unauthorized_remote_actor = OperatorContext(
            user_id="unauthorized_remote_intruder",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )
        # Unauthorized local guest (authenticated identity, but lacking setpoint role permissions)
        self.unauthorized_guest = OperatorContext(
            user_id="guest_visitor",
            role=Role.GUEST,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

    def test_1_authorized_normal_change_succeeds_in_protected_mode(self) -> None:
        """
        Scenario 1A: An authorized operator submits a normal, permitted setpoint change (100 -> 104 ppm)
        in Protected Mode.
        Expected: Gate 1 authorizes, Gate 2 passes, setpoint is COMMITTED to physical process.
        """
        scada = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
        pre_state = scada.get_process_state()

        success, record = scada.request_setpoint_change(
            context=self.authorized_operator,
            requested_setpoint_ppm=104.0
        )

        self.assertTrue(success)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)
        self.assertIsNone(record.rejection_reason)

        post_state = scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, 104.0)
        self.assertNotEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)

    def test_2_authorized_normal_change_succeeds_in_vulnerable_mode(self) -> None:
        """
        Scenario 1B: An authorized operator submits the same normal, permitted setpoint change (100 -> 104 ppm)
        in Vulnerable Mode.
        Expected: Authorization is NOT checked (omitted), Gate 2 passes, change is COMMITTED.
        """
        scada = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        self.assertTrue(scada.is_vulnerable_mode)

        success, record = scada.request_setpoint_change(
            context=self.authorized_operator,
            requested_setpoint_ppm=104.0
        )

        self.assertTrue(success)
        # Authorization was omitted per CWE-862
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)
        self.assertIsNone(record.rejection_reason)
        self.assertEqual(scada.get_process_state().active_setpoint_ppm, 104.0)

    def test_3_unauthorized_permitted_change_accepted_in_vulnerable_mode_cwe_862(self) -> None:
        """
        Scenario 2A (CWE-862 Core Demonstration):
        An unauthorized caller submits an otherwise permitted setpoint change (100 -> 104 ppm).
        In Vulnerable Mode, authorization is missing, so the operation is INCORRECTLY ACCEPTED.
        Process state is modified by an unauthorized user.
        """
        scada = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        pre_state = scada.get_process_state()
        self.assertEqual(pre_state.active_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)

        # 1. Unauthorized remote intruder submits change
        success, record = scada.request_setpoint_change(
            context=self.unauthorized_remote_actor,
            requested_setpoint_ppm=104.0
        )

        # VULNERABILITY REALIZED:
        self.assertTrue(success, "Vulnerable mode must accept request when authorization check is missing")
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(record.final_decision, FinalDecision.COMMITTED.value)
        self.assertIsNone(record.rejection_reason)

        # Process state was changed by unauthorized actor!
        post_state = scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, 104.0)

        # 2. Test with unauthorized role (GUEST)
        scada_guest = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        success_guest, record_guest = scada_guest.request_setpoint_change(
            context=self.unauthorized_guest,
            requested_setpoint_ppm=103.0
        )
        self.assertTrue(success_guest)
        self.assertEqual(record_guest.final_decision, FinalDecision.COMMITTED.value)
        self.assertEqual(scada_guest.get_process_state().active_setpoint_ppm, 103.0)

    def test_4_unauthorized_permitted_change_rejected_in_protected_mode(self) -> None:
        """
        Scenario 2B (Protected Mode Baseline):
        The same unauthorized caller submits the permitted setpoint change (100 -> 104 ppm).
        In Protected Mode, Gate 1 strictly rejects the request, preserving process state intact.
        """
        scada = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
        pre_state = scada.get_process_state()

        success, record = scada.request_setpoint_change(
            context=self.unauthorized_remote_actor,
            requested_setpoint_ppm=104.0
        )

        # MUST BE REJECTED:
        self.assertFalse(success)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.NOT_EVALUATED.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertIn("Authorization Denied", record.rejection_reason)

        # Physical process state strictly preserved:
        post_state = scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)
        self.assertEqual(post_state.measured_concentration_ppm, pre_state.measured_concentration_ppm)
        self.assertEqual(post_state.simulated_ph, pre_state.simulated_ph)

    def test_5_unauthorized_out_of_bounds_rejected_by_safety_in_vulnerable_mode(self) -> None:
        """
        Scenario 3: An unauthorized user submits a dangerous setpoint outside safety limits (11,100 ppm)
        in Vulnerable Mode.
        Expected: Authorization check is missing (NOT_CHECKED_VULNERABLE), but the independent
        safety interlock trips on EXCEEDS_HARD_LIMIT and REJECTS the command.
        Crucially: The rejection is NOT falsely attributed to authorization; it is attributed
        specifically to the safety interlock tripping!
        """
        scada = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        pre_state = scada.get_process_state()

        success, record = scada.request_setpoint_change(
            context=self.unauthorized_remote_actor,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        self.assertFalse(success)
        # Authorization was NOT checked
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        # Safety interlock tripped on hard limit
        self.assertEqual(record.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        # Rejection reason attributed to safety, NOT authorization
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)
        self.assertNotIn("Authorization Denied", record.rejection_reason)

        # Process state preserved:
        post_state = scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)

    def test_6_authorized_out_of_bounds_rejected_by_safety_interlock(self) -> None:
        """
        Scenario 4: An authorized operator submits an out-of-bounds setpoint (11,100 ppm)
        in both Protected Mode and Vulnerable Mode.
        Expected: Rejected by safety interlock in both modes, demonstrating that authorized users
        are independently constrained by physical safety bounds.
        """
        # Protected Mode
        scada_prot = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
        success_prot, record_prot = scada_prot.request_setpoint_change(
            context=self.authorized_operator,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )
        self.assertFalse(success_prot)
        self.assertEqual(record_prot.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record_prot.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertIn("Safety Interlock Tripped", record_prot.rejection_reason)
        self.assertEqual(scada_prot.get_process_state().active_setpoint_ppm, 100.0)

        # Vulnerable Mode
        scada_vuln = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        success_vuln, record_vuln = scada_vuln.request_setpoint_change(
            context=self.authorized_operator,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )
        self.assertFalse(success_vuln)
        self.assertEqual(record_vuln.authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        self.assertEqual(record_vuln.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertIn("Safety Interlock Tripped", record_vuln.rejection_reason)
        self.assertEqual(scada_vuln.get_process_state().active_setpoint_ppm, 100.0)

    def test_7_audit_records_accurately_reflect_modes_and_attributions(self) -> None:
        """
        Scenario 5: Audit records accurately document authorization status, safety status,
        final decision, and rejection reason for both modes.
        """
        # Test Protected Audit Log
        scada_prot = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
        scada_prot.request_setpoint_change(self.authorized_operator, 102.0)     # Approved
        scada_prot.request_setpoint_change(self.unauthorized_remote_actor, 102.0) # Rejected by auth
        scada_prot.request_setpoint_change(self.authorized_operator, 11100.0)    # Rejected by safety

        records_prot = scada_prot.audit_logger.get_records()
        self.assertEqual(len(records_prot), 3)
        self.assertEqual(records_prot[0].authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(records_prot[0].safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(records_prot[1].authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(records_prot[1].safety_result, SafetyValidationStatus.NOT_EVALUATED.value)
        self.assertEqual(records_prot[2].authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(records_prot[2].safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)

        # Test Vulnerable Audit Log
        scada_vuln = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
        scada_vuln.request_setpoint_change(self.unauthorized_remote_actor, 102.0) # Committed due to missing auth!
        scada_vuln.request_setpoint_change(self.unauthorized_remote_actor, 11100.0) # Rejected by safety

        records_vuln = scada_vuln.audit_logger.get_records()
        self.assertEqual(len(records_vuln), 2)
        # Record 1: Missing auth led to commit
        self.assertEqual(records_vuln[0].authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        self.assertEqual(records_vuln[0].safety_result, SafetyValidationStatus.PASSED.value)
        self.assertEqual(records_vuln[0].final_decision, FinalDecision.COMMITTED.value)
        # Record 2: Missing auth, but safety interlock caught it
        self.assertEqual(records_vuln[1].authorization_outcome, AuthorizationStatus.NOT_CHECKED_VULNERABLE.value)
        self.assertEqual(records_vuln[1].safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertEqual(records_vuln[1].final_decision, FinalDecision.REJECTED.value)
        self.assertIn("Safety Interlock Tripped", records_vuln[1].rejection_reason)

    def test_8_default_mode_is_protected(self) -> None:
        """
        Verifies that default instantiation of ScadaSystem without parameters
        is strictly Protected Mode (fails safe / secure by default).
        """
        scada_default = ScadaSystem()
        self.assertEqual(scada_default.authorization_mode, AuthorizationMode.PROTECTED)
        self.assertFalse(scada_default.is_vulnerable_mode)

        # Unauthorized request must be rejected in default mode
        success, record = scada_default.request_setpoint_change(self.unauthorized_remote_actor, 102.0)
        self.assertFalse(success)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)


if __name__ == "__main__":
    unittest.main()
