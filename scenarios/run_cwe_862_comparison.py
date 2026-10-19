"""
Interactive Terminal Demonstration: CWE-862 (Missing Authorization) SCADA Lab.

Compares:
1. Protected Mode: Gate 1 strictly verifies caller identity, role, and session type.
2. Vulnerable Mode: Gate 1 authorization check is omitted (CWE-862), directly exposing
   the physical process to callers if the request passes physical safety interlocks.

================================================================================
EDUCATIONAL DISCLAIMER & NOTICE:
- CWE-862 is an educational software vulnerability modeled for local research and training.
- It is NOT claimed to be the root cause of the historical 2021 Oldsmar incident.
- All threshold values (80–120 ppm normal, 150 ppm cutoff, 10 ppm step) are illustrative
  laboratory rules and do NOT represent real-world plant engineering specifications.
- Execution is 100% in-memory with zero connection to live SCADA equipment or networks.
================================================================================
"""

import os
import sys

# Ensure project root is on sys.path
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
from src.safety import (
    Role,
    SessionType,
    OperatorContext,
    AuthorizationMode,
    AuthorizationStatus,
)
from src.scada_system import ScadaSystem


def print_banner() -> None:
    print("=" * 80)
    print("  EDUCATIONAL SCADA LAB: CWE-862 (MISSING AUTHORIZATION) DEMONSTRATION")
    print("  Comparing Protected Mode vs. Vulnerable Mode in Supervisory Control")
    print("=" * 80)
    print("  [DISCLAIMER]")
    print("  - CWE-862 is an educational vulnerability model; NOT the cause of the 2021 incident.")
    print("  - Setpoints & Thresholds are illustrative laboratory rules for demonstration:")
    print(f"      * Normal Range: {LAB_ILLUSTRATIVE_NORMAL_MIN_PPM:.1f} - {LAB_ILLUSTRATIVE_NORMAL_MAX_PPM:.1f} ppm")
    print(f"      * Hard Safety Cutoff: {LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM:.1f} ppm")
    print(f"      * Max Single-Step Delta: {LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM:.1f} ppm")
    print("  - 100% Local In-Memory Simulation (No external network or hardware connectivity)")
    print("=" * 80)
    print()


def execute_and_display_request(
    scada: ScadaSystem,
    context: OperatorContext,
    requested_setpoint: float,
    scenario_title: str = ""
) -> None:
    """Executes a single setpoint change and displays complete diagnostic telemetry."""
    if scenario_title:
        print("-" * 80)
        print(f"  {scenario_title}")
        print("-" * 80)

    pre_state = scada.get_process_state()

    print(f"[*] Submitting Setpoint Change Request:")
    print(f"    - Mode                 : {scada.authorization_mode.value}")
    print(f"    - Requesting Actor     : '{context.user_id}' (Role: {context.role.value}, Authenticated: {context.is_authenticated})")
    print(f"    - Session Origin       : {context.session_type.value}")
    print(f"    - Requested Setpoint   : {requested_setpoint:.1f} ppm (Current: {pre_state.active_setpoint_ppm:.1f} ppm)")
    print()
    print(f"[*] Process State (BEFORE Request):")
    print(f"    - Active Setpoint      : {pre_state.active_setpoint_ppm:.1f} ppm")
    print(f"    - Measured Conc.       : {pre_state.measured_concentration_ppm:.1f} ppm")
    print(f"    - Simulated Water pH   : {pre_state.simulated_ph:.2f}")
    print(f"    - Dosing Pump Active   : {pre_state.pump_active}")
    print()

    # Execute request
    success, record = scada.request_setpoint_change(context, requested_setpoint)
    post_state = scada.get_process_state()

    print(f"[*] Transaction Evaluation Results:")
    print(f"    - Authorization Gate   : {record.authorization_outcome}")
    print(f"    - Safety Interlock     : {record.safety_result}")
    print(f"    - Detection Engine     : {record.detection_result}")
    print(f"    - Native SCADA Alarm   : {record.native_alarm_state}")
    print(f"    - FINAL VERDICT        : {'APPROVED & COMMITTED' if success else 'HARD REJECTED'}")
    if record.rejection_reason:
        print(f"    - Rejection Reason     : {record.rejection_reason}")
    print()

    print(f"[*] Process State (AFTER Request):")
    print(f"    - Active Setpoint      : {post_state.active_setpoint_ppm:.1f} ppm "
          + ("(CHANGED!)" if post_state.active_setpoint_ppm != pre_state.active_setpoint_ppm else "(PRESERVED INTACT)"))
    print(f"    - Measured Conc.       : {post_state.measured_concentration_ppm:.1f} ppm")
    print(f"    - Simulated Water pH   : {post_state.simulated_ph:.2f}")
    print()

    print(f"[*] Immutable Audit Record:")
    print(f"    {record.to_json(indent=6)}")
    print()


def run_automated_comparison() -> None:
    """Executes the standard comparative matrix of all 4 key scenarios."""
    print("=" * 80)
    print("  RUNNING AUTOMATED COMPARATIVE DEMONSTRATION MATRIX")
    print("=" * 80)
    print()

    authorized_op = OperatorContext(
        user_id="operator_alice",
        role=Role.OPERATOR,
        session_type=SessionType.LOCAL_HMI_CONSOLE,
        is_authenticated=True
    )
    unauthorized_remote = OperatorContext(
        user_id="unauthorized_remote_intruder",
        role=Role.UNAUTHENTICATED,
        session_type=SessionType.UNAUTHORIZED_REMOTE,
        is_authenticated=False
    )

    # --------------------------------------------------------------------------
    # Scenario 1: Authorized User - Benign Setpoint Change (100 -> 104 ppm)
    # --------------------------------------------------------------------------
    scada_prot_1 = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
    execute_and_display_request(
        scada_prot_1, authorized_op, 104.0,
        "SCENARIO 1A: Authorized User submits permitted change (PROTECTED MODE)"
    )

    scada_vuln_1 = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
    execute_and_display_request(
        scada_vuln_1, authorized_op, 104.0,
        "SCENARIO 1B: Authorized User submits permitted change (VULNERABLE MODE)"
    )

    # --------------------------------------------------------------------------
    # Scenario 2: Unauthorized User - Benign Setpoint Change (100 -> 104 ppm)
    # (The Core CWE-862 Demonstration)
    # --------------------------------------------------------------------------
    scada_prot_2 = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
    execute_and_display_request(
        scada_prot_2, unauthorized_remote, 104.0,
        "SCENARIO 2A: Unauthorized Remote User submits permitted change (PROTECTED MODE)"
    )

    scada_vuln_2 = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
    execute_and_display_request(
        scada_vuln_2, unauthorized_remote, 104.0,
        "SCENARIO 2B: Unauthorized Remote User submits permitted change (VULNERABLE MODE - CWE-862 REALIZED!)"
    )

    # --------------------------------------------------------------------------
    # Scenario 3: Unauthorized User - Extreme Out-of-Bounds Request (11,100 ppm)
    # --------------------------------------------------------------------------
    scada_prot_3 = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
    execute_and_display_request(
        scada_prot_3, unauthorized_remote, HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
        "SCENARIO 3A: Unauthorized User submits dangerous 11,100 ppm target (PROTECTED MODE)"
    )

    scada_vuln_3 = ScadaSystem(authorization_mode=AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION)
    execute_and_display_request(
        scada_vuln_3, unauthorized_remote, HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
        "SCENARIO 3B: Unauthorized User submits dangerous 11,100 ppm target (VULNERABLE MODE - SAFETY INTERLOCK CATCHES IT)"
    )

    # --------------------------------------------------------------------------
    # Scenario 4: Authorized User - Extreme Out-of-Bounds Request (11,100 ppm)
    # --------------------------------------------------------------------------
    scada_prot_4 = ScadaSystem(authorization_mode=AuthorizationMode.PROTECTED)
    execute_and_display_request(
        scada_prot_4, authorized_op, HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM,
        "SCENARIO 4: Authorized Operator submits dangerous 11,100 ppm target (PROTECTED MODE)"
    )

    print("=" * 80)
    print("  SUMMARY COMPARISON TABLE: CWE-862 (MISSING AUTHORIZATION)")
    print("=" * 80)
    print(f"  {'Scenario':<30} | {'Mode':<12} | {'Caller':<15} | {'Auth Status':<22} | {'Safety Status':<18} | {'Verdict':<10} | {'Setpoint':<10}")
    print("-" * 135)
    print(f"  {'1A. Benign Authorized':<30} | {'PROTECTED':<12} | {'Operator':<15} | {'AUTHORIZED':<22} | {'PASSED':<18} | {'COMMITTED':<10} | {'104.0 ppm':<10}")
    print(f"  {'1B. Benign Authorized':<30} | {'VULNERABLE':<12} | {'Operator':<15} | {'NOT_CHECKED_VULN':<22} | {'PASSED':<18} | {'COMMITTED':<10} | {'104.0 ppm':<10}")
    print(f"  {'2A. Benign Unauthorized':<30} | {'PROTECTED':<12} | {'RemoteIntruder':<15} | {'UNAUTHORIZED':<22} | {'NOT_EVALUATED':<18} | {'REJECTED':<10} | {'100.0 ppm':<10}")
    print(f"  {'2B. Benign Unauthorized (CWE)':<30} | {'VULNERABLE':<12} | {'RemoteIntruder':<15} | {'NOT_CHECKED_VULN':<22} | {'PASSED':<18} | {'COMMITTED':<10} | {'104.0 ppm':<10} *VULNERABLE*")
    print(f"  {'3A. Dangerous Unauthorized':<30} | {'PROTECTED':<12} | {'RemoteIntruder':<15} | {'UNAUTHORIZED':<22} | {'NOT_EVALUATED':<18} | {'REJECTED':<10} | {'100.0 ppm':<10}")
    print(f"  {'3B. Dangerous Unauthorized':<30} | {'VULNERABLE':<12} | {'RemoteIntruder':<15} | {'NOT_CHECKED_VULN':<22} | {'EXCEEDS_HARD_LIMIT':<18} | {'REJECTED':<10} | {'100.0 ppm':<10} *SAFETY CATCH*")
    print(f"  {'4.  Dangerous Authorized':<30} | {'PROTECTED':<12} | {'Operator':<15} | {'AUTHORIZED':<22} | {'EXCEEDS_HARD_LIMIT':<18} | {'REJECTED':<10} | {'100.0 ppm':<10}")
    print("=" * 135)
    print()


def run_interactive_cli() -> None:
    """Interactive console prompt allowing custom experimentation."""
    print_banner()

    users = {
        "1": OperatorContext(
            user_id="operator_alice",
            role=Role.OPERATOR,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        ),
        "2": OperatorContext(
            user_id="plant_engineer_dan",
            role=Role.PLANT_ENGINEER,
            session_type=SessionType.AUTHENTICATED_REMOTE_VPN,
            is_authenticated=True
        ),
        "3": OperatorContext(
            user_id="remote_intruder",
            role=Role.UNAUTHENTICATED,
            session_type=SessionType.UNAUTHORIZED_REMOTE,
            is_authenticated=False
        ),
        "4": OperatorContext(
            user_id="guest_visitor",
            role=Role.GUEST,
            session_type=SessionType.LOCAL_HMI_CONSOLE,
            is_authenticated=True
        ),
    }

    modes = {
        "1": AuthorizationMode.PROTECTED,
        "2": AuthorizationMode.VULNERABLE_MISSING_AUTHORIZATION,
    }

    while True:
        print("-" * 80)
        print("  INTERACTIVE SCADA AUTHORIZATION EXPERIMENTATION MENU")
        print("-" * 80)
        print("  [1] Run Interactive Custom Test")
        print("  [2] Run Automated Comparative Demonstration (All Scenarios)")
        print("  [3] Exit Demonstration")
        print("-" * 80)

        try:
            choice = input("Enter choice [1-3] (default: 2): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting demonstration.")
            break

        if not choice or choice == "2":
            run_automated_comparison()
            continue
        elif choice == "3":
            print("\nExiting demonstration. Goodbye.")
            break
        elif choice != "1":
            print("[!] Invalid option. Please select 1, 2, or 3.\n")
            continue

        # 1. Mode Selection
        print("\nSelect Operating Mode:")
        print("  [1] Protected Mode (Default: Gate 1 Authorization strictly verified)")
        print("  [2] Vulnerable Mode (CWE-862: Gate 1 Authorization check omitted)")
        mode_choice = input("Enter mode [1-2] (default: 1): ").strip() or "1"
        selected_mode = modes.get(mode_choice, AuthorizationMode.PROTECTED)

        # 2. User Selection
        print("\nSelect Simulated Actor Context:")
        print("  [1] Authorized Operator ('operator_alice', Role=OPERATOR, Local Console)")
        print("  [2] Authorized Engineer ('plant_engineer_dan', Role=PLANT_ENGINEER, VPN)")
        print("  [3] Unauthorized Remote Intruder ('remote_intruder', Role=UNAUTHENTICATED, Remote)")
        print("  [4] Unauthorized Guest ('guest_visitor', Role=GUEST, Local Console)")
        user_choice = input("Enter actor [1-4] (default: 3): ").strip() or "3"
        selected_context = users.get(user_choice, users["3"])

        # 3. Setpoint Input with Safe Numeric Validation
        while True:
            raw_sp = input(f"\nEnter requested setpoint in ppm [e.g. 104.0, 115.0, {HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM:.1f}]: ").strip()
            if not raw_sp:
                print("[!] Input cannot be empty. Please enter a numerical setpoint value.")
                continue
            try:
                requested_setpoint = float(raw_sp)
                break
            except ValueError:
                print(f"[!] Invalid numeric input '{raw_sp}'. Please enter a valid floating-point number.")

        # Fresh instance for clean testing
        scada = ScadaSystem(authorization_mode=selected_mode)
        print()
        execute_and_display_request(
            scada=scada,
            context=selected_context,
            requested_setpoint=requested_setpoint,
            scenario_title=f"CUSTOM INTERACTIVE RUN ({selected_mode.value})"
        )


def main() -> None:
    if "--demo" in sys.argv or "--batch" in sys.argv or "--all" in sys.argv or not sys.stdin.isatty():
        print_banner()
        run_automated_comparison()
    else:
        run_interactive_cli()


if __name__ == "__main__":
    main()
