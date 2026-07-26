"""Compose the rule modules into a single 0-100 audit result.

Scoring is intentionally boring: each axis starts at 100, findings subtract
their severity's penalty, axes clamp at 0, and the composite is a weighted sum.
Same input, same score, forever -- which is what makes it usable as a CI gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .context import AuditContext
from .findings import AXIS_LABELS, AXIS_WEIGHTS, Axis, Finding, Severity, sort_findings
from .normalize import Tool, parse_tools
from .rules import MODULES

#: score floor -> (grade, headline verdict)
GRADE_BANDS: tuple[tuple[int, str, str], ...] = (
    (90, "A", "Hardened"),
    (80, "B", "Solid, with gaps"),
    (70, "C", "Exploitable"),
    (60, "D", "Weak"),
    (0, "F", "Critically exposed"),
)

BAR_SEGMENTS = 5


@dataclass
class AxisScore:
    axis: Axis
    score: int
    weight: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def label(self) -> str:
        return AXIS_LABELS[self.axis]

    @property
    def bar(self) -> str:
        filled = round(self.score / 100 * BAR_SEGMENTS)
        return "▓" * filled + "░" * (BAR_SEGMENTS - filled)

    def to_dict(self) -> dict:
        return {
            "axis": self.axis.value,
            "label": self.label,
            "score": self.score,
            "weight": self.weight,
            "bar": self.bar,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditResult:
    score: int
    grade: str
    verdict: str
    axes: list[AxisScore]
    findings: list[Finding]
    probes: list[dict]
    tools: list[Tool]
    scan_id: str
    #: Counts are stored rather than derived so a result reloaded from a share
    #: link (which keeps only the top finding) still reports the real totals.
    tool_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=lambda: {s.value: 0 for s in Severity})

    @property
    def top_risk(self) -> Finding | None:
        return self.findings[0] if self.findings else None

    @property
    def unmitigated_probe_count(self) -> int:
        return sum(1 for p in self.probes if p["unmitigated"])

    @property
    def tool_count_label(self) -> str:
        if self.tool_count == 0:
            return "no tools declared"
        return f"{self.tool_count} tool{'s' if self.tool_count != 1 else ''} analysed"

    def headline(self) -> str:
        """The one-line summary used on the card and in the API."""
        n = self.unmitigated_probe_count
        if n == 0:
            return f"{self.verdict} — no unmitigated injection classes."
        plural = "class" if n == 1 else "classes"
        return f"{self.verdict} — {n} unmitigated injection {plural}."

    def to_dict(self) -> dict:
        top = self.top_risk
        return {
            "scan_id": self.scan_id,
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "headline": self.headline(),
            "axes": [a.to_dict() for a in self.axes],
            "findings": [f.to_dict() for f in self.findings],
            "probes": self.probes,
            "unmitigated_probes": self.unmitigated_probe_count,
            "severity_counts": self.severity_counts,
            "top_risk": top.to_dict() if top else None,
            "tools_analysed": [t.to_dict() for t in self.tools],
            "tool_count": self.tool_count,
        }


def _grade(score: int) -> tuple[str, str]:
    for floor, grade, verdict in GRADE_BANDS:
        if score >= floor:
            return grade, verdict
    return "F", "Critically exposed"


def _scan_id(prompt: str, tools_raw: str, config: dict) -> str:
    """Stable short id for an input, so a re-scan of the same agent matches."""
    digest = hashlib.sha256()
    digest.update(prompt.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(tools_raw.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(repr(sorted(config.items())).encode("utf-8"))
    return digest.hexdigest()[:12]


def audit(
    system_prompt: str = "",
    tools: object = None,
    config: dict | None = None,
) -> AuditResult:
    """Run the full audit. `tools` may be a JSON string, list, or mapping."""
    prompt = system_prompt or ""
    config = dict(config or {})
    parsed_tools = parse_tools(tools)

    ctx = AuditContext.build(prompt=prompt, tools=parsed_tools, config=config)

    all_findings: list[Finding] = []
    for module in MODULES:
        all_findings.extend(module.evaluate(ctx))
    all_findings = sort_findings(all_findings)

    axes: list[AxisScore] = []
    for axis, weight in AXIS_WEIGHTS.items():
        axis_findings = [f for f in all_findings if f.axis == axis]
        penalty = sum(f.penalty for f in axis_findings)
        axes.append(
            AxisScore(
                axis=axis,
                score=max(0, 100 - penalty),
                weight=weight,
                findings=axis_findings,
            )
        )

    composite = round(sum(a.score * a.weight for a in axes))
    grade, verdict = _grade(composite)

    counts = {s.value: 0 for s in Severity}
    for finding in all_findings:
        counts[finding.severity.value] += 1

    tools_raw = tools if isinstance(tools, str) else repr(tools)
    return AuditResult(
        score=composite,
        grade=grade,
        verdict=verdict,
        axes=axes,
        findings=all_findings,
        probes=[r.to_dict() for r in ctx.probe_results],
        tools=parsed_tools,
        scan_id=_scan_id(prompt, tools_raw, config),
        tool_count=len(parsed_tools),
        severity_counts=counts,
    )
