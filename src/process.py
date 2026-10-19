"""
Physical Process Model for Simulated Water Treatment Chemical Dosing.

Simulates the physical behavior of a water treatment chemical dosing stage
(specifically Sodium Hydroxide / NaOH dosing for pH elevation).

EDUCATIONAL NOTICE:
This is a local mathematical model for educational cybersecurity demonstration.
It does not connect to real physical equipment or represent real plant dynamics.
"""

from dataclasses import dataclass
from typing import Dict, Any
from src.config import HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM


@dataclass
class ProcessState:
    """Snapshot of the physical water treatment stage."""
    active_setpoint_ppm: float
    measured_concentration_ppm: float
    simulated_ph: float
    pump_active: bool


class WaterTreatmentProcess:
    """
    Simulated water treatment process stage.

    Maintains active chemical dosing setpoints and models physical
    chemical concentration lag (illustrating why physical water systems
    have inertia, allowing time for detection before contaminated water
    reaches consumers).
    """

    def __init__(self, initial_setpoint_ppm: float = HISTORICAL_INITIAL_REFERENCE_SETPOINT_PPM) -> None:
        self._initial_setpoint_ppm = float(initial_setpoint_ppm)
        self._active_setpoint_ppm = float(initial_setpoint_ppm)
        self._measured_concentration_ppm = float(initial_setpoint_ppm)
        self._pump_active = True
        # Typical water pH baseline modeling for educational demonstration:
        # 100 ppm NaOH corresponds illustrative ~7.5 pH
        self._simulated_ph = self._calculate_ph(self._measured_concentration_ppm)

    @property
    def current_setpoint_ppm(self) -> float:
        """Returns the active setpoint stored in the simulated PLC/controller."""
        return self._active_setpoint_ppm

    @property
    def measured_concentration_ppm(self) -> float:
        """Returns the current measured chemical concentration in the tank."""
        return self._measured_concentration_ppm

    @property
    def simulated_ph(self) -> float:
        """Returns the simulated pH of the process water."""
        return self._simulated_ph

    def apply_setpoint(self, new_setpoint_ppm: float) -> None:
        """
        Commits an approved setpoint change to the simulated controller.
        This must only be called after authorization and safety interlocks pass.
        """
        self._active_setpoint_ppm = float(new_setpoint_ppm)

    def simulate_time_step(self, elapsed_seconds: float = 1.0, dosing_rate_ppm_per_sec: float = 0.5) -> None:
        """
        Simulates physical dosing pump action moving concentration toward the setpoint.
        """
        if not self._pump_active:
            return

        delta = self._active_setpoint_ppm - self._measured_concentration_ppm
        max_change = dosing_rate_ppm_per_sec * max(0.0, elapsed_seconds)

        if abs(delta) <= max_change:
            self._measured_concentration_ppm = self._active_setpoint_ppm
        elif delta > 0:
            self._measured_concentration_ppm += max_change
        else:
            self._measured_concentration_ppm -= max_change

        self._simulated_ph = self._calculate_ph(self._measured_concentration_ppm)

    def get_state(self) -> ProcessState:
        """Returns current process telemetry."""
        return ProcessState(
            active_setpoint_ppm=self._active_setpoint_ppm,
            measured_concentration_ppm=round(self._measured_concentration_ppm, 3),
            simulated_ph=round(self._simulated_ph, 2),
            pump_active=self._pump_active
        )

    def reset(self) -> None:
        """Resets the process back to historical reference baseline."""
        self._active_setpoint_ppm = self._initial_setpoint_ppm
        self._measured_concentration_ppm = self._initial_setpoint_ppm
        self._simulated_ph = self._calculate_ph(self._measured_concentration_ppm)
        self._pump_active = True

    @staticmethod
    def _calculate_ph(concentration_ppm: float) -> float:
        """
        Illustrative non-linear pH curve for educational visualization.
        Not intended for precise chemical engineering.
        """
        if concentration_ppm <= 0:
            return 7.0
        # Baseline ~7.5 at 100 ppm, rising smoothly for higher concentrations
        ratio = concentration_ppm / 100.0
        # Educational logarithmic approximation
        import math
        ph = 7.5 + (math.log10(ratio) if ratio > 0 else 0) * 1.5
        return min(14.0, max(0.0, ph))
