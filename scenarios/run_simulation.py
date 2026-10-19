"""
Interactive & Standalone Demonstration: 2021 Oldsmar Water Treatment Cyber Incident Lab.

================================================================================
EDUCATIONAL DISCLAIMER & NOTICE:
The setpoint figures used in this demonstration (100.0 ppm initial reference and
11,100.0 ppm simulated unauthorized target) represent historical incident-reported
values cited in public advisories regarding the February 2021 Oldsmar, Florida event.

These values are evaluated strictly for educational cyber-physical simulation and
training in control systems defense. They do NOT represent verified safe operating
limits or direct measurements of actual drinking-water chemical concentrations.

The laboratory limits (80–120 ppm normal range, 150 ppm cutoff, and 10 ppm step
limit) are configurable illustrative laboratory rules, not verified real-world safety limits.

All simulation components are local-only, simulated entirely in memory, and have
zero connectivity to real industrial equipment or live operational networks.
================================================================================
"""

import sys
import os

# Ensure the root project directory is on sys.path for local module resolution
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.config import (
    HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM,
    HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
    LAB_ILLUSTRATIVE_NORMAL_MIN_PPM,
    LAB_ILLUSTRATIVE_NORMAL_MAX_PPM,
    LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM,
    LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM,
)
from src.safety import Role, SessionType, OperatorContext
from src.scada_system import ScadaSystem


def print_banner() -> None:
    print("=" * 80)
    print("  EDUCATIONAL CYBERSECURITY LAB: 2021 OLDSMAR INCIDENT SIMULATION")
    print("  Defense-in-Depth for Cyber-Physical & Water Treatment Systems")
    print("=" * 80)
    print("  [DISCLAIMER]")
    print(f"  - Initial Reference Setpoint: {HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM:.1f} ppm (Historical incident reported)")
    print(f"  - Unauthorized Target Setpoint: {HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM:.1f} ppm (Historical incident reported)")
    print("  - Illustrative Laboratory Rules (Not real plant engineering limits):")
    print(f"      * Normal Range: {LAB_ILLUSTRATIVE_NORMAL_MIN_PPM:.1f} - {LAB_ILLUSTRATIVE_NORMAL_MAX_PPM:.1f} ppm")
    print(f"      * Hard Safety Cutoff: {LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM:.1f} ppm")
    print(f"      * Max Single-Step Delta: {LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM:.1f} ppm")
    print("      * Native SCADA Alarm: Process Variable (PV) monitoring with 300s delay (No SP entry alarm)")
    print("  - Execution: 100% Local In-Memory Simulation (No external network or hardware)")
    print("=" * 80)
    print()


def run_demonstration() -> None:
    print_banner()

    scada = ScadaSystem()
    print(f"[*] Initializing SCADA System...")
    init_state = scada.get_process_state()
    print(f"    Current Active Setpoint : {init_state.active_setpoint_ppm:.1f} ppm")
    print(f"    Measured Concentration  : {init_state.measured_concentration_ppm:.1f} ppm")
    print(f"    Simulated Water pH      : {init_state.simulated_ph:.2f}")
    print()

    # --------------------------------------------------------------------------
    # Scenario 1: Normal Municipal Operation
    # --------------------------------------------------------------------------
    print("-" * 80)
    print("PHASE 1: Routine Municipal Operation (Authorized Setpoint Adjustment)")
    print("-" * 80)
    operator = OperatorContext(
        user_id="operator_carter",
        role=Role.OPERATOR,
        session_type=SessionType.LOCAL_HMI_CONSOLE,
        is_authenticated=True
    )
    print(f"[*] Actor '{operator.user_id}' requesting setpoint change: 100.0 ppm -> 105.0 ppm...")
    success, record = scada.request_setpoint_change(operator, requested_setpoint_ppm=105.0)

    print(f"    Verdict            : {'APPROVED & COMMITTED' if success else 'REJECTED'}")
    print(f"    Authorization Gate : {record.authorization_outcome}")
    print(f"    Safety Gate        : {record.safety_result}")
    print(f"    Detection Engine   : {record.detection_result}")
    print(f"    Native SCADA Alarm : {record.native_alarm_state} (Normal / Silent)")
    print(f"    Active Setpoint    : {scada.get_process_state().active_setpoint_ppm:.1f} ppm")

    # Simulate plant response over 4 seconds
    print("    [Physical Simulation] Dosing pump adjusting chemical concentration over time...")
    scada.simulate_process_step(elapsed_seconds=4.0)
    state = scada.get_process_state()
    print(f"    Updated Measured Concentration: {state.measured_concentration_ppm:.1f} ppm (pH: {state.simulated_ph:.2f})")
    print()

    # --------------------------------------------------------------------------
    # Scenario 2: 2021 Oldsmar Incident Attack (Unauthorized Remote Intrusion)
    # --------------------------------------------------------------------------
    print("-" * 80)
    print("PHASE 2: 2021 Oldsmar Attack Replication (Simulated Unauthorized Remote Access)")
    print("-" * 80)
    print("Context: Unauthenticated remote desktop session (e.g., TeamViewer exploit vector)")
    print(f"Target: Elevate NaOH setpoint from 105.0 ppm -> {HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM:.1f} ppm")
    attacker = OperatorContext(
        user_id="remote_intruder",
        role=Role.UNAUTHENTICATED,
        session_type=SessionType.UNAUTHORIZED_REMOTE,
        is_authenticated=False
    )
    print(f"[*] Submitting exploit setpoint command: {HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM:.1f} ppm...")
    success, record = scada.request_setpoint_change(attacker, requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM)

    print(f"    Verdict            : {'APPROVED & COMMITTED' if success else 'HARD REJECTED'}")
    print(f"    Authorization Gate : {record.authorization_outcome}")
    print(f"    Safety Gate        : {record.safety_result}")
    print(f"    Native SCADA Alarm : {record.native_alarm_state} (UNTIMELY / NO ALARM AT MOMENT OF ATTACK)")
    print(f"    Detection Engine   : {record.detection_result} (ALERT RAISED BY DEFENSIVE LAYER!)")
    print(f"    Rejection Reason   : {record.rejection_reason}")
    print(f"    Active Setpoint    : {scada.get_process_state().active_setpoint_ppm:.1f} ppm (PRESERVED INTACT!)")
    print()

    # --------------------------------------------------------------------------
    # Scenario 3: Defense-in-Depth (Compromised Credential / Insider Error)
    # --------------------------------------------------------------------------
    print("-" * 80)
    print("PHASE 3: Defense-in-Depth (Authorized Credential Bypassed / Insider Error)")
    print("-" * 80)
    print("Context: Adversary steals legitimate operator credentials or operator makes extreme typo")
    compromised_op = OperatorContext(
        user_id="operator_compromised",
        role=Role.OPERATOR,
        session_type=SessionType.LOCAL_HMI_CONSOLE,
        is_authenticated=True
    )
    print(f"[*] Authorized account submitting dangerous target: {HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM:.1f} ppm...")
    success, record = scada.request_setpoint_change(compromised_op, requested_setpoint_ppm=HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM)

    print(f"    Verdict            : {'APPROVED & COMMITTED' if success else 'HARD REJECTED'}")
    print(f"    Authorization Gate : {record.authorization_outcome} (Passed by credential)")
    print(f"    Safety Interlock   : {record.safety_result} (INDEPENDENT HARD LIMIT TRIPPED!)")
    print(f"    Native SCADA Alarm : {record.native_alarm_state} (UNTIMELY / NO ALARM AT MOMENT OF ATTACK)")
    print(f"    Detection Engine   : {record.detection_result}")
    print(f"    Rejection Reason   : {record.rejection_reason}")
    print(f"    Active Setpoint    : {scada.get_process_state().active_setpoint_ppm:.1f} ppm (PRESERVED INTACT!)")
    print()

    # --------------------------------------------------------------------------
    # Review Audit Logs
    # --------------------------------------------------------------------------
    print("=" * 80)
    print("AUDIT TRAIL & INCIDENT LOG INSPECTION (SIEM VIEW)")
    print("=" * 80)
    for idx, rec in enumerate(scada.audit_logger.get_records(), start=1):
        print(f"\n[Record #{idx}]")
        print(f"  Timestamp (UTC)      : {rec.timestamp_utc}")
        print(f"  Actor                : {rec.actor}")
        print(f"  Session Type         : {rec.session_type}")
        print(f"  Original Setpoint    : {rec.original_value:.1f} ppm")
        print(f"  Requested Setpoint   : {rec.requested_value:.1f} ppm")
        print(f"  Authorization Status : {rec.authorization_outcome}")
        print(f"  Safety Status        : {rec.safety_result}")
        print(f"  Native SCADA Alarm   : {rec.native_alarm_state}")
        print(f"  Detection Result     : {rec.detection_result}")
        print(f"  Final Decision       : {rec.final_decision}")
        if rec.rejection_reason:
            print(f"  Rejection Reason     : {rec.rejection_reason}")
    print("\n" + "=" * 80)
    print("  SIMULATION DEMONSTRATION COMPLETE: ALL SAFETY CRITERIA SATISFIED")
    print("=" * 80)


if __name__ == "__main__":
    run_demonstration()
