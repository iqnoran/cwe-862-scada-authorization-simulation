"""
Native SCADA Alarm Subsystem (Educational Model).

Models the legacy supervisory control and data acquisition (SCADA) alarm subsystem
independently from the additional defensive security/anomaly detection layer.

================================================================================
EDUCATIONAL DISCLAIMER & NOTICE:
This module represents an illustrative laboratory model of legacy SCADA alarming behavior
(such as alarms monitoring Process Variables rather than supervisory setpoint tags,
or delays introduced by debounce timers and hydraulic retention).

It does NOT claim to reproduce or reverse-engineer the proprietary software, vendor
alarm configuration, or PLC ladder logic of the historical Oldsmar municipal facility.

All threshold values, debounce timers, and alarm modes are illustrative laboratory
assumptions for educational cyber-physical defense simulation.
================================================================================
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.config import (
    LAB_ILLUSTRATIVE_SCADA_ALARM_DELAY_SECONDS,
    LAB_ILLUSTRATIVE_SCADA_ALARM_PV_THRESHOLD_PPM,
    LAB_ILLUSTRATIVE_SCADA_ALARM_SETPOINT_THRESHOLD_PPM,
)
from src.process import ProcessState


class ScadaAlarmState(str, Enum):
    """
    State of the native SCADA alarm annunciator.
    """
    CLEAR = "CLEAR"                    # No alarm annunciated; normal or silent state
    PENDING_DELAY = "PENDING_DELAY"    # Condition met, but debounce/delay timer has not elapsed
    ACTIVE = "ACTIVE"                  # Alarm is actively annunciating on the operator console


class ScadaAlarmMode(str, Enum):
    """
    Operational mode of the legacy SCADA alarm subsystem.

    - DELAYED_PV_ALARM: Alarms monitor the downstream physical Process Variable (PV)
      subject to debounce/hydraulic delays, rather than the supervisory setpoint (SP).
    - UNCONFIGURED_SETPOINT_ALARM: Supervisory setpoint registers have no boundary
      or rate-of-change alarms configured (common legacy supervisory gap).
    - STATIC_THRESHOLD_ALARM: Conventional setpoint threshold alarm (for baseline comparison).
    """
    DELAYED_PV_ALARM = "DELAYED_PV_ALARM"
    UNCONFIGURED_SETPOINT_ALARM = "UNCONFIGURED_SETPOINT_ALARM"
    STATIC_THRESHOLD_ALARM = "STATIC_THRESHOLD_ALARM"


@dataclass(frozen=True)
class ScadaAlarmConfig:
    """
    Configuration parameters for the native SCADA alarm subsystem.

    NOTE: All thresholds and delay intervals are illustrative laboratory assumptions.
    """
    mode: ScadaAlarmMode = ScadaAlarmMode.DELAYED_PV_ALARM
    alarm_delay_seconds: float = LAB_ILLUSTRATIVE_SCADA_ALARM_DELAY_SECONDS
    pv_alarm_threshold_ppm: float = LAB_ILLUSTRATIVE_SCADA_ALARM_PV_THRESHOLD_PPM
    setpoint_alarm_threshold_ppm: float = LAB_ILLUSTRATIVE_SCADA_ALARM_SETPOINT_THRESHOLD_PPM


class NativeScadaAlarmSubsystem:
    """
    Simulated Native SCADA Alarm Subsystem.

    Operates independently from the defensive anomaly detector and safety interlock.
    Models whether the native control system alerts an operator at the instant of a
    setpoint change request or after physical process progression.
    """

    def __init__(self, config: Optional[ScadaAlarmConfig] = None) -> None:
        self.config = config or ScadaAlarmConfig()
        self.state: ScadaAlarmState = ScadaAlarmState.CLEAR
        self.time_in_alarm_condition: float = 0.0

    def evaluate_request(
        self,
        requested_setpoint_ppm: float,
        current_process_state: ProcessState
    ) -> ScadaAlarmState:
        """
        Evaluates whether the native SCADA system generates an alarm at the instant
        the setpoint change request is submitted (t = 0).

        Returns:
            ScadaAlarmState: The alarm state at the time of the request.
        """
        if self.config.mode == ScadaAlarmMode.UNCONFIGURED_SETPOINT_ALARM:
            # Setpoint tags are unmonitored; supervisory input generates no native alarm
            self.state = ScadaAlarmState.CLEAR
            return self.state

        if self.config.mode == ScadaAlarmMode.DELAYED_PV_ALARM:
            # Alarms monitor downstream physical Process Variable (PV), not setpoint entry.
            # At t = 0, physical chemical concentration has not yet deviated.
            if current_process_state.measured_concentration_ppm >= self.config.pv_alarm_threshold_ppm:
                if self.time_in_alarm_condition >= self.config.alarm_delay_seconds:
                    self.state = ScadaAlarmState.ACTIVE
                else:
                    self.state = ScadaAlarmState.PENDING_DELAY
            else:
                self.state = ScadaAlarmState.CLEAR
            return self.state

        if self.config.mode == ScadaAlarmMode.STATIC_THRESHOLD_ALARM:
            # Static setpoint alarm configuration
            if requested_setpoint_ppm >= self.config.setpoint_alarm_threshold_ppm:
                if self.config.alarm_delay_seconds > 0.0:
                    self.state = ScadaAlarmState.PENDING_DELAY
                else:
                    self.state = ScadaAlarmState.ACTIVE
            else:
                self.state = ScadaAlarmState.CLEAR
            return self.state

        self.state = ScadaAlarmState.CLEAR
        return self.state

    def update_telemetry(
        self,
        process_state: ProcessState,
        elapsed_seconds: float = 1.0
    ) -> ScadaAlarmState:
        """
        Updates alarm state based on physical process variable evolution over time.

        Args:
            process_state: Current physical telemetry from the treatment process.
            elapsed_seconds: Simulated seconds elapsed during step.

        Returns:
            ScadaAlarmState: Updated alarm state after elapsed time.
        """
        if self.config.mode == ScadaAlarmMode.UNCONFIGURED_SETPOINT_ALARM:
            self.state = ScadaAlarmState.CLEAR
            return self.state

        is_pv_exceeded = process_state.measured_concentration_ppm >= self.config.pv_alarm_threshold_ppm

        if is_pv_exceeded:
            self.time_in_alarm_condition += elapsed_seconds
            if self.time_in_alarm_condition >= self.config.alarm_delay_seconds:
                self.state = ScadaAlarmState.ACTIVE
            else:
                self.state = ScadaAlarmState.PENDING_DELAY
        else:
            self.time_in_alarm_condition = 0.0
            self.state = ScadaAlarmState.CLEAR

        return self.state

    def reset(self) -> None:
        """Resets the alarm annunciator and condition timer."""
        self.state = ScadaAlarmState.CLEAR
        self.time_in_alarm_condition = 0.0
