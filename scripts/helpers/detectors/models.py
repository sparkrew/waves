"""Shared label model and weakness-type constants."""

from __future__ import annotations

from dataclasses import asdict, dataclass


IW = "Injection Weakness (IW)"
PTW = "Privileged Trigger Weakness (PTW)"
SEW = "Secrets Exposure Weakness (SEW)"
KVCW = "Known Vulnerable Component Weakness (KVCW)"
AIW = "Artifact Integrity Weakness (AIW)"
CFW = "Control Flow Weakness (CFW)"
EPW = "Excessive Permission Weakness (EPW)"
UDW = "Unpinned Dependency Weakness (UDW)"
GRCW = "GitHub Runner Compatibility Weakness (GRCW)"
HGW = "Hardening Gap Weakness (HGW)"

ALL_TYPES = (IW, PTW, SEW, KVCW, AIW, CFW, EPW, UDW, GRCW, HGW)


@dataclass
class Label:
    workflow_blob_url: str
    line_number: int
    weakness_type: str
    evidence: str
    explanation: str

    def to_row(self) -> dict:
        return asdict(self)


@dataclass
class WorkflowContext:
    """Parsed workflow ready for detectors."""

    url: str
    text: str
    data: dict
    lines: list[str]
    purpose: str = ""
