"""Model capabilities (ADR-0054 section 8; AI-INFERENCE-CONTRACTS section 3).

A neutral module: the configuration (what a model is declared to support) and
the adapters (what a protocol can carry) both use it, and neither imports the
other.
"""

from __future__ import annotations

import enum


class Capability(enum.StrEnum):
    TEXT_INPUT = "text_input"
    TEXT_OUTPUT = "text_output"
    SYSTEM_INSTRUCTIONS = "system_instructions"
    TEMPERATURE = "temperature"
    STOP_SEQUENCES = "stop_sequences"
