"""
Authorization Policy and Safety Interlock Validation.

EDUCATIONAL NOTICE & DISCLAIMERS:
1. Authorization policies and Safety Interlocks are logically separated into
   distinct, independently testable components, reflecting defense-in-depth in
   Industrial Control Systems (ICS).
2. The safety thresholds (80–120 ppm normal range, 150 ppm cutoff, and 10 ppm step
   limit) are configurable illustrative laboratory rules for demonstration only,
   and do NOT represent verified real-world water treatment engineering specifications.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
from src.config import (
    SafetyLimitsConfig,
    LAB_ILLUSTRATIVE_NORMAL_MIN_PPM,
    LAB_ILLUSTRATIVE_NORMAL_MAX_PPM,
    LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM,
    LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM,
)


class AuthorizationMode(str, Enum):
    """
    Operational mode for educational authorization demonstration (CWE-862).

    PROTECTED:
        Default and production-safe mode. The Gate 1 authorization policy is
        strictly verified before any state-changing operation. Unauthorized
        callers are immediately rejected, and the physical process state is preserved.

    VULNERABLE_MISSING_AUTHORIZATION:
        Explicit, isolated educational mode demonstrating CWE-862 (Missing Authorization).
        The Gate 1 authorization check is deliberately omitted, modeling software that fails
        to verify caller authority before executing control logic. Requests proceed directly
        to physical safety interlocks. Strictly for local educational simulation.
    """
    PROTECTED = "PROTECTED"
    VULNERABLE_MISSING_AUTHORIZATION = "VULNERABLE_MISSING_AUTHORIZATION"


class Role(str, Enum):
    OPERATOR = "OPERATOR"
    PLANT_ENGINEER = "PLANT_ENGINEER"
    SUPERVISOR = "SUPERVISOR"
    GUEST = "GUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"


class SessionType(str, Enum):
    LOCAL_HMI_CONSOLE = "LOCAL_HMI_CONSOLE"
    AUTHENTICATED_REMOTE_VPN = "AUTHENTICATED_REMOTE_VPN"
    UNAUTHORIZED_REMOTE = "UNAUTHORIZED_REMOTE"


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    INVALID_SESSION = "INVALID_SESSION"
    INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"
    NOT_CHECKED_VULNERABLE = "NOT_CHECKED_VULNERABLE"



class SafetyValidationStatus(str, Enum):
    PASSED = "PASSED"
    NOT_EVALUATED = "NOT_EVALUATED"
    EXCEEDS_HARD_LIMIT = "EXCEEDS_HARD_LIMIT"
    EXCEEDS_STEP_DELTA = "EXCEEDS_STEP_DELTA"
    OUTSIDE_NORMAL_RANGE = "OUTSIDE_NORMAL_RANGE"
    NEGATIVE_VALUE = "NEGATIVE_VALUE"


@dataclass(frozen=True)
class OperatorContext:
    """Contextual metadata about the requesting actor and session origin."""
    user_id: str
    role: Role
    session_type: SessionType
    is_authenticated: bool = True


@dataclass(frozen=True)
class AuthorizationResult:
    """Result of independent authorization policy check."""
    is_authorized: bool
    status: AuthorizationStatus
    reason: str


@dataclass(frozen=True)
class SafetyResult:
    """Result of independent safety interlock check."""
    is_safe: bool
    status: SafetyValidationStatus
    reason: str


class AuthorizationPolicy:
    """
    Independent Authorization Policy Checker.

    Verifies identity, role privileges, and session authenticity.
    Does NOT evaluate physical safety limits.
    """

    ALLOWED_ROLES_FOR_SETPOINT = {Role.OPERATOR, Role.PLANT_ENGINEER, Role.SUPERVISOR}
    PERMITTED_SESSION_TYPES = {SessionType.LOCAL_HMI_CONSOLE, SessionType.AUTHENTICATED_REMOTE_VPN}

    def evaluate(self, context: OperatorContext, action: str = "SETPOINT_CHANGE") -> AuthorizationResult:
        """
        Evaluates whether the given context is authorized to perform the action.
        """
        if not context.is_authenticated or context.role == Role.UNAUTHENTICATED:
            return AuthorizationResult(
                is_authorized=False,
                status=AuthorizationStatus.UNAUTHORIZED,
                reason="Unauthenticated request rejected."
            )

        if context.session_type == SessionType.UNAUTHORIZED_REMOTE:
            return AuthorizationResult(
                is_authorized=False,
                status=AuthorizationStatus.UNAUTHORIZED,
                reason="Unauthorized remote desktop session rejected (simulated unauthorized access)."
            )

        if context.session_type not in self.PERMITTED_SESSION_TYPES:
            return AuthorizationResult(
                is_authorized=False,
                status=AuthorizationStatus.INVALID_SESSION,
                reason=f"Session type '{context.session_type.value}' is not permitted for setpoint modifications."
            )

        if context.role not in self.ALLOWED_ROLES_FOR_SETPOINT:
            return AuthorizationResult(
                is_authorized=False,
                status=AuthorizationStatus.INSUFFICIENT_PRIVILEGES,
                reason=f"Role '{context.role.value}' does not possess setpoint modification authority."
            )

        return AuthorizationResult(
            is_authorized=True,
            status=AuthorizationStatus.AUTHORIZED,
            reason="Operator identity, role privileges, and session authentication verified."
        )


class SafetyInterlock:
    """
    Independent Safety Instrumented System (SIS) / Safety Interlock.

    Simulates an independent, programmable safety gate that enforces physical
    and operational boundaries regardless of who initiates the command.
    Does NOT check user authorization.
    """

    def __init__(self, limits: Optional[SafetyLimitsConfig] = None) -> None:
        self.limits = limits or SafetyLimitsConfig()

    def evaluate(self, current_setpoint_ppm: float, requested_setpoint_ppm: float) -> SafetyResult:
        """
        Validates proposed setpoint against physical hard limits and step limits.
        """
        # 1. Non-negative check
        if requested_setpoint_ppm < 0.0:
            return SafetyResult(
                is_safe=False,
                status=SafetyValidationStatus.NEGATIVE_VALUE,
                reason=f"Physical invalidity: Requested setpoint {requested_setpoint_ppm:.1f} ppm cannot be negative."
            )

        # 2. Hard physical safety cutoff (e.g. 150.0 ppm illustrative laboratory limit)
        if requested_setpoint_ppm > self.limits.hard_safety_cutoff_ppm:
            return SafetyResult(
                is_safe=False,
                status=SafetyValidationStatus.EXCEEDS_HARD_LIMIT,
                reason=(
                    f"Safety interlock tripped: Requested setpoint {requested_setpoint_ppm:.1f} ppm exceeds "
                    f"hard safety cutoff of {self.limits.hard_safety_cutoff_ppm:.1f} ppm "
                    f"(Illustrative laboratory safety rule)."
                )
            )

        # 3. Maximum single-step delta limit (e.g. 10.0 ppm illustrative laboratory limit)
        delta = abs(requested_setpoint_ppm - current_setpoint_ppm)
        if delta > self.limits.max_step_delta_ppm:
            return SafetyResult(
                is_safe=False,
                status=SafetyValidationStatus.EXCEEDS_STEP_DELTA,
                reason=(
                    f"Safety interlock tripped: Delta of {delta:.1f} ppm exceeds maximum allowed "
                    f"single-step limit of {self.limits.max_step_delta_ppm:.1f} ppm "
                    f"(Illustrative laboratory safety rule)."
                )
            )

        # 4. Normal operating envelope check (80.0–120.0 ppm illustrative laboratory rule)
        if (requested_setpoint_ppm < self.limits.normal_min_ppm or
                requested_setpoint_ppm > self.limits.normal_max_ppm):
            return SafetyResult(
                is_safe=False,
                status=SafetyValidationStatus.OUTSIDE_NORMAL_RANGE,
                reason=(
                    f"Operational violation: Requested setpoint {requested_setpoint_ppm:.1f} ppm is outside "
                    f"illustrative normal range [{self.limits.normal_min_ppm:.1f} - {self.limits.normal_max_ppm:.1f}] ppm."
                )
            )

        return SafetyResult(
            is_safe=True,
            status=SafetyValidationStatus.PASSED,
            reason="Setpoint is within illustrative normal operational bounds and step limits."
        )
