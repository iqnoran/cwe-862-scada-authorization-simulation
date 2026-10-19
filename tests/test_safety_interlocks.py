"""
Tests for Safety Interlocks, Authorization Policies, and Incident Mitigation.

================================================================================
EDUCATIONAL DISCLAIMER & NOTICE:
The setpoint figures tested below (100.0 ppm initial reference and 11,100.0 ppm
simulated unauthorized target) represent historical incident-reported values cited
in public advisories regarding the February 2021 Oldsmar, Florida event.

These values are evaluated here strictly for educational cyber-physical simulation
and training in control systems defense. They do NOT represent verified safe operating
limits or direct measurements of actual drinking-water chemical concentrations.

The laboratory limits (80–120 ppm normal range, 150 ppm cutoff, and 10 ppm step
limit) are configurable illustrative laboratory rules, not verified real-world safety limits.
================================================================================
"""

import unittest
from src.config import (
    HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
    HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
    SafetyLimitsConfig
)
from src.safety import (
    SafetyInterlock,
    AuthorizationPolicy,
    Role,
    SessionType,
    OperatorContext,
    AuthorizationStatus,
    SafetyValidationStatus
)
from src.audit import FinalDecision, DetectionResult
from src.scada_system import ScadaSystem


class TestIndependentSafetyInterlock(unittest.TestCase):
    """
    Independently tests the SafetyInterlock without dependencies on authorization
    or network contexts, demonstrating decoupled safety gate verification.
    """

    def setUp(self) -> None:
        self.interlock = SafetyInterlock()

    def test_benign_setpoint_passes_safety_interlock(self) -> None:
        """A normal illustrative setpoint adjustment (100.0 -> 105.0 ppm) passes safety checks."""
        result = self.interlock.evaluate(
            current_setpoint_ppm=HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
            requested_setpoint_ppm=105.0
        )
        self.assertTrue(result.is_safe)
        self.assertEqual(result.status, SafetyValidationStatus.PASSED)

    def test_historical_incident_target_rejected_by_hard_cutoff(self) -> None:
        """
        Historical 11,100.0 ppm target is hard-rejected by the safety interlock
        against the illustrative 150.0 ppm cutoff.
        """
        result = self.interlock.evaluate(
            current_setpoint_ppm=HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )
        self.assertFalse(result.is_safe)
        self.assertEqual(result.status, SafetyValidationStatus.EXCEEDS_HARD_LIMIT)
        self.assertIn("Safety interlock tripped", result.reason)
        self.assertIn("150.0 ppm", result.reason)

    def test_negative_setpoint_rejected(self) -> None:
        """Physically impossible negative setpoint is rejected."""
        result = self.interlock.evaluate(
            current_setpoint_ppm=100.0,
            requested_setpoint_ppm=-5.0
        )
        self.assertFalse(result.is_safe)
        self.assertEqual(result.status, SafetyValidationStatus.NEGATIVE_VALUE)

    def test_configurable_safety_limits(self) -> None:
        """Safety limits are fully configurable for laboratory experimentation."""
        custom_limits = SafetyLimitsConfig(
            normal_min_ppm=90.0,
            normal_max_ppm=110.0,
            hard_safety_cutoff_ppm=125.0,
            max_step_delta_ppm=5.0
        )
        custom_interlock = SafetyInterlock(limits=custom_limits)

        # 6.0 ppm step delta should fail custom 5.0 ppm limit
        result = custom_interlock.evaluate(current_setpoint_ppm=100.0, requested_setpoint_ppm=106.0)
        self.assertFalse(result.is_safe)
        self.assertEqual(result.status, SafetyValidationStatus.EXCEEDS_STEP_DELTA)


class TestIndependentAuthorizationPolicy(unittest.TestCase):
    """
    Independently tests the AuthorizationPolicy without dependencies on setpoint values.
    """

    def setUp(self) -> None:
        self.policy = AuthorizationPolicy()

    def test_local_operator_authorized(self) -> None:
        context = OperatorContext(
            user_id="operator_alice",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )
        result = self.policy.evaluate(context)
        self.assertTrue(result.is_authorized)
        self.assertEqual(result.status, AuthorizationStatus.AUTHORIZED)

    def test_unauthorized_remote_session_denied(self) -> None:
        """Simulated unauthorized remote desktop access is rejected."""
        context = OperatorContext(
            user_id="unknown_remote_user",
            role=Role.OPERATOR,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )
        result = self.policy.evaluate(context)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status, AuthorizationStatus.UNAUTHORIZED)

    def test_guest_role_insufficient_privileges(self) -> None:
        context = OperatorContext(
            user_id="viewer_bob",
            role=Role.GUEST,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )
        result = self.policy.evaluate(context)
        self.assertFalse(result.is_authorized)
        self.assertEqual(result.status, AuthorizationStatus.INSUFFICIENT_PRIVILEGES)


class TestOldsmarIncidentMitigation(unittest.TestCase):
    """
    End-to-end simulation of the 2021 Oldsmar incident attack vector and defense-in-depth mitigations.
    """

    def setUp(self) -> None:
        self.scada = ScadaSystem()

    def test_simulated_oldsmar_unauthorized_attack_rejected(self) -> None:
        """
        Simulates an unauthorized remote intrusion attempting to elevate setpoint from 100.0 to 11,100.0 ppm.
        Must be rejected, preserving the initial 100.0 ppm setpoint with zero state modification.
        """
        attacker_context = OperatorContext(
            user_id="unauthorized_remote_actor",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )

        success, record = self.scada.request_setpoint_change(
            context=attacker_context,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        # 1. Action must fail
        self.assertFalse(success)

        # 2. Original setpoint must be strictly preserved
        self.assertEqual(self.scada.process.current_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)
        self.assertEqual(
            self.scada.get_process_state().measured_concentration_ppm,
            HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM
        )

        # 3. Audit record verification
        self.assertEqual(record.original_value, 100.0)
        self.assertEqual(record.requested_value, 11100.0)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.NOT_EVALUATED.value)
        self.assertEqual(record.detection_result, DetectionResult.CRITICAL_ANOMALY.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertIn("Authorization Denied", record.rejection_reason)

    def test_defense_in_depth_authorized_compromise_rejected_by_safety_interlock(self) -> None:
        """
        Defense-in-Depth Scenario: Even if an adversary compromises a valid operator credential
        or an authorized operator enters 11,100.0 ppm erroneously, the independent Safety Interlock
        must trip and preserve the original 100.0 ppm setpoint.
        """
        compromised_operator = OperatorContext(
            user_id="compromised_operator_account",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

        success, record = self.scada.request_setpoint_change(
            context=compromised_operator,
            requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM
        )

        # 1. Action must fail at the safety interlock gate
        self.assertFalse(success)

        # 2. Original setpoint strictly preserved
        self.assertEqual(self.scada.process.current_setpoint_ppm, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM)

        # 3. Audit verification: Authorization passed, but Safety Interlock tripped
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.EXCEEDS_HARD_LIMIT.value)
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)

    def test_unauthorized_benign_setpoint_rejected_and_state_preserved(self) -> None:
        """
        1. An unauthorized session requests a benign setpoint of 102.0 ppm.
        Must be rejected by authorization policy (Gate 1), preserving the initial
        setpoint and all process-state telemetry unchanged.
        """
        unauthorized_context = OperatorContext(
            user_id="unauthorized_remote_actor",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        )
        pre_setpoint = self.scada.process.current_setpoint_ppm
        pre_state = self.scada.get_process_state()

        success, record = self.scada.request_setpoint_change(
            context=unauthorized_context,
            requested_setpoint_ppm=102.0
        )

        # 1. Action must be rejected
        self.assertFalse(success)

        # 2. Process current setpoint remains at pre-request value
        self.assertEqual(self.scada.process.current_setpoint_ppm, pre_setpoint)

        # 3. All relevant process-state fields remain unchanged
        post_state = self.scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)
        self.assertEqual(post_state.measured_concentration_ppm, pre_state.measured_concentration_ppm)
        self.assertEqual(post_state.simulated_ph, pre_state.simulated_ph)
        self.assertEqual(post_state.pump_active, pre_state.pump_active)

        # 4. Audit record reflects rejection decision and reason
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.UNAUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.NOT_EVALUATED.value)
        self.assertEqual(record.original_value, pre_setpoint)
        self.assertEqual(record.requested_value, 102.0)
        self.assertIn("Authorization Denied", record.rejection_reason)

    def test_authorized_negative_setpoint_rejected_and_state_preserved(self) -> None:
        """
        2. An authorized operator requests a physically impossible negative setpoint of -5.0 ppm.
        Must be rejected by safety interlock non-negative check (Gate 2), preserving
        the initial setpoint and all process-state telemetry unchanged.
        """
        authorized_operator = OperatorContext(
            user_id="operator_alice",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )
        pre_setpoint = self.scada.process.current_setpoint_ppm
        pre_state = self.scada.get_process_state()

        success, record = self.scada.request_setpoint_change(
            context=authorized_operator,
            requested_setpoint_ppm=-5.0
        )

        # 1. Action must be rejected
        self.assertFalse(success)

        # 2. Process current setpoint remains at pre-request value
        self.assertEqual(self.scada.process.current_setpoint_ppm, pre_setpoint)

        # 3. All relevant process-state fields remain unchanged
        post_state = self.scada.get_process_state()
        self.assertEqual(post_state.active_setpoint_ppm, pre_state.active_setpoint_ppm)
        self.assertEqual(post_state.measured_concentration_ppm, pre_state.measured_concentration_ppm)
        self.assertEqual(post_state.simulated_ph, pre_state.simulated_ph)
        self.assertEqual(post_state.pump_active, pre_state.pump_active)

        # 4. Audit record reflects rejection decision and reason
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.NEGATIVE_VALUE.value)
        self.assertEqual(record.original_value, pre_setpoint)
        self.assertEqual(record.requested_value, -5.0)
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)
        self.assertIn("Physical invalidity", record.rejection_reason)

    def test_authorized_setpoint_outside_normal_range_rejected_and_state_preserved(self) -> None:
        """
        3. An authorized operator requests 130.0 ppm, which is outside the illustrative
        normal envelope [80.0, 120.0] ppm and below the illustrative hard cutoff (150.0 ppm).
        From a baseline of 120.0 ppm (delta = 10.0 ppm <= 10.0 ppm step limit), the safety
        interlock rejects the change for OUTSIDE_NORMAL_RANGE and preserves process state.
        Additionally verifies that requesting 130.0 ppm from 100.0 ppm trips EXCEEDS_STEP_DELTA
        (due to evaluation pipeline order) while also preserving process state.
        """
        authorized_operator = OperatorContext(
            user_id="operator_alice",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        )

        # Primary case: baseline at 120.0 ppm (within normal envelope, delta = 10.0 ppm)
        # Isolates the normal range check below the 150.0 ppm hard cutoff.
        scada_120 = ScadaSystem(initial_setpoint_ppm=120.0)
        pre_setpoint_120 = scada_120.process.current_setpoint_ppm
        pre_state_120 = scada_120.get_process_state()

        success, record = scada_120.request_setpoint_change(
            context=authorized_operator,
            requested_setpoint_ppm=130.0
        )

        # 1. Action must be rejected
        self.assertFalse(success)

        # 2. Process current setpoint remains at pre-request value (120.0 ppm)
        self.assertEqual(scada_120.process.current_setpoint_ppm, pre_setpoint_120)

        # 3. All relevant process-state fields remain unchanged
        post_state_120 = scada_120.get_process_state()
        self.assertEqual(post_state_120.active_setpoint_ppm, pre_state_120.active_setpoint_ppm)
        self.assertEqual(post_state_120.measured_concentration_ppm, pre_state_120.measured_concentration_ppm)
        self.assertEqual(post_state_120.simulated_ph, pre_state_120.simulated_ph)
        self.assertEqual(post_state_120.pump_active, pre_state_120.pump_active)

        # 4. Audit record reflects rejection decision and reason
        self.assertEqual(record.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record.authorization_outcome, AuthorizationStatus.AUTHORIZED.value)
        self.assertEqual(record.safety_result, SafetyValidationStatus.OUTSIDE_NORMAL_RANGE.value)
        self.assertEqual(record.original_value, pre_setpoint_120)
        self.assertEqual(record.requested_value, 130.0)
        self.assertIn("Safety Interlock Tripped", record.rejection_reason)
        self.assertIn("outside illustrative normal range", record.rejection_reason)

        # Pipeline order verification: from default 100.0 ppm baseline, delta of 30.0 ppm
        # trips EXCEEDS_STEP_DELTA before normal range evaluation, also preserving state.
        pre_setpoint_default = self.scada.process.current_setpoint_ppm
        pre_state_default = self.scada.get_process_state()

        success_default, record_default = self.scada.request_setpoint_change(
            context=authorized_operator,
            requested_setpoint_ppm=130.0
        )

        self.assertFalse(success_default)
        self.assertEqual(self.scada.process.current_setpoint_ppm, pre_setpoint_default)
        post_state_default = self.scada.get_process_state()
        self.assertEqual(post_state_default.active_setpoint_ppm, pre_state_default.active_setpoint_ppm)
        self.assertEqual(post_state_default.measured_concentration_ppm, pre_state_default.measured_concentration_ppm)
        self.assertEqual(post_state_default.simulated_ph, pre_state_default.simulated_ph)
        self.assertEqual(post_state_default.pump_active, pre_state_default.pump_active)
        self.assertEqual(record_default.final_decision, FinalDecision.REJECTED.value)
        self.assertEqual(record_default.safety_result, SafetyValidationStatus.EXCEEDS_STEP_DELTA.value)
        self.assertIn("Safety Interlock Tripped", record_default.rejection_reason)
        self.assertIn("single-step limit", record_default.rejection_reason)


if __name__ == "__main__":
    unittest.main()
