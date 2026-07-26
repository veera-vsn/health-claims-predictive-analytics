"""Finding and severity primitives shared by every rule module.

The scoring model is deliberately simple and inspectable: each axis starts at
100 and every finding subtracts its severity's penalty. No finding can push an
axis below zero, and a clean agent scores 100. Nothing is probabilistic, so the
same input always produces the same score -- which matters when someone pastes
the card into a PR and a reviewer wants to reproduce it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


#: Points deducted from an axis for a single finding of each severity.
PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 22,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

#: Ordering helper -- lower sorts first, so the worst findings lead the report.
RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Axis(str, Enum):
    INJECTION = "injection_resistance"
    SCOPING = "tool_scoping"
    EXFILTRATION = "exfiltration_surface"
    SECRETS = "secret_handling"
    OUTPUT = "output_validation"


AXIS_LABELS = {
    Axis.INJECTION: "Injection Resistance",
    Axis.SCOPING: "Tool Scoping",
    Axis.EXFILTRATION: "Exfil Surface",
    Axis.SECRETS: "Secret Handling",
    Axis.OUTPUT: "Output Validation",
}

#: Axis weights for the composite score. They sum to 1.0.
AXIS_WEIGHTS = {
    Axis.INJECTION: 0.25,
    Axis.SCOPING: 0.25,
    Axis.EXFILTRATION: 0.20,
    Axis.SECRETS: 0.15,
    Axis.OUTPUT: 0.15,
}


@dataclass
class Finding:
    """One concrete weakness, tied to an axis and (where possible) a tool."""

    id: str
    axis: Axis
    severity: Severity
    title: str
    detail: str
    fix: str
    tool: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def penalty(self) -> int:
        return PENALTY[self.severity]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "axis": self.axis.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "tool": self.tool,
            "evidence": self.evidence,
            "penalty": self.penalty,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Worst first, then alphabetically by id so output is stable."""
    return sorted(findings, key=lambda f: (RANK[f.severity], f.id, f.tool or ""))
