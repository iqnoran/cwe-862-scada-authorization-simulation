"""
Configuration and Educational Constants for the Oldsmar Incident Simulation.

================================================================================
EDUCATIONAL DISCLAIMER & NOTICE:
The setpoint figures below (100.0 ppm and 11,100.0 ppm) represent historical
incident-reported values cited in public cybersecurity advisories regarding the
February 2021 Oldsmar, Florida water treatment facility incident.

These numbers are utilized strictly for educational cyber-physical simulation
and training in control system defensive architecture. They do NOT represent
verified safe operating limits, real plant engineering specifications, or direct
measurements of finished drinking-water chemical concentrations.

Similarly, the laboratory thresholds (80.0–120.0 ppm normal range, 150.0 ppm
cutoff, and 10.0 ppm step limit) are illustrative laboratory rules designed for
this educational software simulation and must not be used as engineering guidance
for real-world water treatment facilities.

All simulation components are local-only, simulated entirely in memory, and have
zero connectivity to real industrial equipment or live operational networks.
================================================================================
"""

from dataclasses import dataclass

# Historical incident-reported setpoint values cited in public advisories
# (Used strictly for educational simulation)
HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM: float = 100.0
HISTORICAL_INCIDENT_TARGET_SETPOINT_PPM: float = 11100.0

# Illustrative laboratory rules (Configurable demonstration bounds, NOT real-world engineering limits)
LAB_ILLUSTRATIVE_NORMAL_MIN_PPM: float = 80.0
LAB_ILLUSTRATIVE_NORMAL_MAX_PPM: float = 120.0
LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM: float = 150.0
LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM: float = 10.0

# Illustrative native SCADA alarm modeling assumptions (Laboratory rules; does NOT represent actual Oldsmar plant configuration)
LAB_ILLUSTRATIVE_SCADA_ALARM_DELAY_SECONDS: float = 300.0  # 5-minute debounce/hydraulic transport delay
LAB_ILLUSTRATIVE_SCADA_ALARM_PV_THRESHOLD_PPM: float = 130.0  # High alarm on measured Process Variable (PV)
LAB_ILLUSTRATIVE_SCADA_ALARM_SETPOINT_THRESHOLD_PPM: float = 130.0  # Static alarm threshold if SP monitoring enabled


@dataclass(frozen=True)
class SafetyLimitsConfig:
    """
    Configurable safety limits for the simulated Safety Instrumented System (SIS).

    NOTE: The default values here are illustrative laboratory rules for educational
    purposes and do not represent verified real-world engineering specifications.
    """
    normal_min_ppm: float = LAB_ILLUSTRATIVE_NORMAL_MIN_PPM
    normal_max_ppm: float = LAB_ILLUSTRATIVE_NORMAL_MAX_PPM
    hard_safety_cutoff_ppm: float = LAB_ILLUSTRATIVE_HARD_SAFETY_CUTOFF_PPM
    max_step_delta_ppm: float = LAB_ILLUSTRATIVE_MAX_STEP_DELTA_PPM

