"""
SCADA Controller Integration Module.

Acts as the supervisory control and data acquisition (SCADA) core, coordinating
operator inputs, authorization enforcement, safety interlocks, security anomaly
detection, and physical process state updates.

EDUCATIONAL NOTICE:
This module represents a defense-in-depth architecture where authorization and
safety interlocks are decoupled. Even if an attacker bypasses authorization,
the physical safety interlock halts dangerous commands (such as 11,100 ppm).
"""

from typing import Tuple, Optional
from src.config import SafetyLimitsConfig, HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM
from src.process import WaterTreatmentProcess, ProcessState
from src.scada_alarm import (
    NativeScadaAlarmSubsystem,
    ScadaAlarmConfig,
    ScadaAlarmState,
)
from src.safety import (
    AuthorizationMode,
    AuthorizationPolicy,
    SafetyInterlock,
    OperatorContext,
    AuthorizationStatus,
    SafetyValidationStatus,
)
from src.audit import (
    AuditLogger,
    AuditRecord,
    AnomalyDetector,
    DetectionResult,
    FinalDecision,
)


class ScadaSystem:
    """
    Supervisory Control and Data Acquisition (SCADA) Coordinator.

    Orchestrates:
    1. Anomaly detection monitoring (Additional Defensive Layer)
    2. Native SCADA alarm subsystem monitoring (Decoupled original control system alarm)
    3. Authorization policy evaluation (Gate 1 - bypassed in educational CWE-862 vulnerable mode)
    4. Safety interlock validation (Gate 2 - always evaluated before process commit)
    5. Process setpoint commit (strictly gated)
    6. Immutable audit logging (captures both defensive alert and native alarm states)
    """

    def __init__(
        self,
        initial_setpoint_ppm: float = HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
        limits_config: Optional[SafetyLimitsConfig] = None,
        alarm_config: Optional[ScadaAlarmConfig] = None,
        authorization_mode: AuthorizationMode = AuthorizationMode.PROTECTED
    ) -> None:
        self.process = WaterTreatmentProcess(initial_setpoint_ppm=initial_setpoint_ppm)
        self.auth_policy = AuthorizationPolicy()
        self.safety_interlock = SafetyInterlock(limits=limits_config)
        self.anomaly_detector = AnomalyDetector(
            step_delta_threshold=(limits_config or SafetyLimitsConfig()).max_step_delta_ppm
        )
        self.native_alarm = NativeScadaAlarmSubsystem(config=alarm_config)
        self.authorization_mode = authorization_mode
        self.audit_logger = AuditLogger()

    def request_setpoint_change(
        self,
        context: OperatorContext,
        requested_setpoint_ppm: float
    ) -> Tuple[bool, AuditRecord]:
        """
        Processes an operator or remote session setpoint change request.

        Enforces:
        - Rejection of unauthorized requests without modifying process state.
        - Verification that authorized requests pass safety limits before committing.
        - Logging every request (approved or rejected) with full audit telemetry.

        Returns:
            Tuple[bool, AuditRecord]: (was_committed, generated_audit_record)
        """
        original_value = self.process.current_setpoint_ppm

        # 1. Run detection engine for anomalies (Additional Defensive Layer)
        detection_result = self.anomaly_detector.evaluate(
            original_value=original_value,
            requested_value=requested_setpoint_ppm,
            session_type=context.session_type.value,
            is_authenticated=context.is_authenticated
        )

        # 2. Evaluate native SCADA alarm annunciator state (Independent Original SCADA System)
        native_alarm_state = self.native_alarm.evaluate_request(
            requested_setpoint_ppm=requested_setpoint_ppm,
            current_process_state=self.process.get_state()
        )

        # 3. Gate 1: Authorization Policy Check
        if self.authorization_mode == AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION:
            # EDUCATIONAL NOTICE - CWE-862 (Missing Authorization):
            # In this deliberately vulnerable educational mode, the authorization check
            # is completely omitted. The system fails to verify whether the actor
            # is authenticated, holds the necessary role, or originates from a permitted session.
            # It proceeds directly to Gate 2 (Safety Interlock).
            auth_outcome = AuthorizationStatus.NOT_CHECKED_VULNERABLE.value
        else:
            # PROTECTED MODE (Default):
            # Strictly verify identity, role authority, and permitted session origin.
            auth_result = self.auth_policy.evaluate(context, action="SETPOINT_CHANGE")
            auth_outcome = auth_result.status.value

            if not auth_result.is_authorized:
                # Unauthorized request: Immediately reject, do not commit any process change
                final_decision = FinalDecision.REJECTED.value
                safety_status = SafetyValidationStatus.NOT_EVALUATED.value
                rejection_reason = f"Authorization Denied: {auth_result.reason}"

                # Log the rejected transaction
                record = self.audit_logger.log(
                    actor=context.user_id,
                    session_type=context.session_type.value,
                    original_value=original_value,
                    requested_value=requested_setpoint_ppm,
                    authorization_outcome=auth_outcome,
                    safety_result=safety_status,
                    detection_result=detection_result.value,
                    final_decision=final_decision,
                    rejection_reason=rejection_reason,
                    native_alarm_state=native_alarm_state.value
                )
                return False, record

        # 4. Gate 2: Safety Interlock Check
        # (Reached only if authorized in Protected Mode, or directly in Vulnerable Mode)
        safety_result = self.safety_interlock.evaluate(
            current_setpoint_ppm=original_value,
            requested_setpoint_ppm=requested_setpoint_ppm
        )

        if not safety_result.is_safe:
            # Safety violation: Reject change, keep original setpoint intact
            final_decision = FinalDecision.REJECTED.value
            rejection_reason = f"Safety Interlock Tripped: {safety_result.reason}"

            record = self.audit_logger.log(
                actor=context.user_id,
                session_type=context.session_type.value,
                original_value=original_value,
                requested_value=requested_setpoint_ppm,
                authorization_outcome=auth_outcome,
                safety_result=safety_result.status.value,
                detection_result=detection_result.value,
                final_decision=final_decision,
                rejection_reason=rejection_reason,
                native_alarm_state=native_alarm_state.value
            )
            return False, record

        # 5. Applicable gates passed: Commit setpoint change to physical process
        # NOTE: In Vulnerable Mode, an unauthorized actor reaches this line if their
        # request did not trip the physical safety interlock, demonstrating CWE-862!
        self.process.apply_setpoint(requested_setpoint_ppm)
        final_decision = FinalDecision.COMMITTED.value
        rejection_reason = None

        record = self.audit_logger.log(
            actor=context.user_id,
            session_type=context.session_type.value,
            original_value=original_value,
            requested_value=requested_setpoint_ppm,
            authorization_outcome=auth_outcome,
            safety_result=safety_result.status.value,
            detection_result=detection_result.value,
            final_decision=final_decision,
            rejection_reason=rejection_reason,
            native_alarm_state=native_alarm_state.value
        )
        return True, record

    @property
    def is_vulnerable_mode(self) -> bool:
        """Returns True if the system is operating in the educational CWE-862 vulnerable mode."""
        return self.authorization_mode == AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION

    def get_process_state(self) -> ProcessState:
        """Returns current process telemetry."""
        return self.process.get_state()

    def get_native_alarm_state(self) -> ScadaAlarmState:
        """Returns the current state of the native SCADA alarm annunciator."""
        return self.native_alarm.state

    def simulate_process_step(self, elapsed_seconds: float = 1.0) -> None:
        """Simulates physical plant dynamics progression over elapsed time."""
        self.process.simulate_time_step(elapsed_seconds=elapsed_seconds)
        self.native_alarm.update_telemetry(self.process.get_state(), elapsed_seconds=elapsed_seconds)

    def reset(self) -> None:
        """Resets the process to initial reference baseline."""
        self.process.reset()
        self.native_alarm.reset()

