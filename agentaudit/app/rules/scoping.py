"""Axis 2 -- tool and permission scoping (least privilege).

The question this axis answers: if the model is fully compromised, how much can
it actually do? Capability-based access control says a tool should carry the
narrowest authority that still lets it do its job. A `run_shell(command: str)`
carries every authority the process has; a `restart_service(name: enum[...])`
carries one. We penalise the gap between the two.
"""

from __future__ import annotations

from .. import capabilities as cap
from ..context import AuditContext
from ..findings import RANK, Axis, Finding, Severity
from ..normalize import Tool

#: More tools than this, with privileged ones in the mix, is sprawl.
TOOL_SPRAWL_THRESHOLD = 15

#: Capability -> severity when the capability is exposed with no constraint.
_UNCONSTRAINED_SEVERITY = {
    cap.SHELL: Severity.CRITICAL,
    cap.DEPLOY: Severity.CRITICAL,
    cap.PAYMENT: Severity.CRITICAL,
    cap.CREDENTIAL: Severity.HIGH,
    cap.FILE_WRITE: Severity.HIGH,
    cap.DB_WRITE: Severity.HIGH,
    cap.NETWORK_SEND: Severity.HIGH,
    cap.NETWORK_FETCH: Severity.MEDIUM,
    cap.FILE_READ: Severity.MEDIUM,
    cap.DB_READ: Severity.MEDIUM,
}


def evaluate(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []

    if not ctx.tools:
        # No tools is not a weakness -- it is the safest possible configuration.
        return findings

    for tool in ctx.tools:
        findings.extend(_evaluate_tool(ctx, tool))

    privileged = ctx.tools_with(cap.DANGEROUS_SINKS | cap.EGRESS_SINKS)
    if len(ctx.tools) > TOOL_SPRAWL_THRESHOLD and privileged:
        findings.append(
            Finding(
                id="SCP200",
                axis=Axis.SCOPING,
                severity=Severity.MEDIUM,
                title=f"Tool sprawl: {len(ctx.tools)} tools, {len(privileged)} privileged",
                detail=(
                    "Every tool in the schema is reachable on every turn, so the attack surface is "
                    "the union of all of them. Large tool sets also degrade selection accuracy, "
                    "which makes accidental privileged calls more likely."
                ),
                fix="Split the agent by role, or gate tool availability by task phase so only the relevant subset is exposed.",
            )
        )

    return findings


def _evaluate_tool(ctx: AuditContext, tool: Tool) -> list[Finding]:
    findings: list[Finding] = []
    caps = tool.capabilities

    if not caps:
        return findings

    # --- unconstrained free-form parameters on a privileged tool ----------
    freeform = [
        p
        for p in tool.params
        if cap.FREEFORM_PARAM_NAMES.match(p.name) and p.type in ("string", "unknown") and not p.is_constrained
    ]
    if freeform:
        worst = _worst_capability(caps)
        if worst:
            severity = _UNCONSTRAINED_SEVERITY.get(worst, Severity.MEDIUM)
            names = ", ".join(f"`{p.name}`" for p in freeform)
            findings.append(
                Finding(
                    id="SCP201",
                    axis=Axis.SCOPING,
                    severity=severity,
                    title=f"`{tool.name}` takes unconstrained input for a privileged action",
                    detail=(
                        f"This tool provides {cap.describe({worst})}, and {names} accepts any string — "
                        f"no enum, no pattern, no length bound. Whatever the model can be persuaded "
                        f"to write, this tool will execute."
                    ),
                    fix=_constraint_fix(worst, freeform[0].name),
                    tool=tool.name,
                    evidence=[f"{p.name}: {p.type} (unconstrained)" for p in freeform],
                )
            )

    # --- destructive capability with no human checkpoint ------------------
    needs_confirmation = caps & cap.REQUIRES_CONFIRMATION
    if needs_confirmation and not ctx.asks_confirmation:
        severity = Severity.HIGH if caps & cap.DANGEROUS_SINKS else Severity.MEDIUM
        findings.append(
            Finding(
                id="SCP202",
                axis=Axis.SCOPING,
                severity=severity,
                title=f"`{tool.name}` can act irreversibly with no confirmation step",
                detail=(
                    f"This tool provides {cap.describe(needs_confirmation)}, but neither the prompt "
                    f"nor the config declares a human-in-the-loop checkpoint. There is nothing "
                    f"between a hallucinated or injected call and the real-world effect."
                ),
                fix="Require explicit user approval before this tool runs, or move it behind a queue a human drains.",
                tool=tool.name,
            )
        )

    # --- open schema ------------------------------------------------------
    if tool.additional_properties_open and tool.params and caps & (cap.DANGEROUS_SINKS | cap.EGRESS_SINKS):
        findings.append(
            Finding(
                id="SCP203",
                axis=Axis.SCOPING,
                severity=Severity.LOW,
                title=f"`{tool.name}` accepts undeclared parameters",
                detail=(
                    "`additionalProperties` is not set to false, so arguments outside the declared "
                    "schema pass validation and reach your handler unchecked."
                ),
                fix='Set `"additionalProperties": false` on the tool schema and reject unknown keys server-side.',
                tool=tool.name,
            )
        )

    # --- undocumented privileged tool -------------------------------------
    if not tool.description.strip() and caps & cap.DANGEROUS_SINKS:
        findings.append(
            Finding(
                id="SCP204",
                axis=Axis.SCOPING,
                severity=Severity.LOW,
                title=f"`{tool.name}` is privileged but undocumented",
                detail=(
                    "The model infers this tool's purpose and limits from its name alone. Ambiguity "
                    "here shows up as calls you did not intend."
                ),
                fix="Write a description that states what the tool does, when to use it, and explicitly when not to.",
                tool=tool.name,
            )
        )

    # --- shell access at all ----------------------------------------------
    if cap.SHELL in caps:
        findings.append(
            Finding(
                id="SCP205",
                axis=Axis.SCOPING,
                severity=Severity.HIGH,
                title=f"`{tool.name}` grants general command execution",
                detail=(
                    "A shell tool collapses every other control: file access, network egress, and "
                    "credential theft all become reachable through one call. Capability scoping is "
                    "meaningless while it is present."
                ),
                fix="Replace the shell with narrow tools for the specific operations you actually need, or sandbox it with no network and no credentials.",
                tool=tool.name,
            )
        )

    return findings


def _worst_capability(caps: set[str]) -> str | None:
    """The capability with the harshest penalty, used to rate a shared finding."""
    ranked = [c for c in caps if c in _UNCONSTRAINED_SEVERITY]
    if not ranked:
        return None
    return min(ranked, key=lambda c: RANK[_UNCONSTRAINED_SEVERITY[c]])


_CONSTRAINT_FIXES = {
    cap.SHELL: "Drop the free-form command. Expose an enum of the specific operations you support and build the command server-side.",
    cap.DEPLOY: "Constrain to an enum of known services/environments and require a signed approval for anything else.",
    cap.PAYMENT: "Bound the amount, pin the currency, allowlist recipients, and require confirmation over a threshold.",
    cap.CREDENTIAL: "Never let the model name the credential. Resolve secrets server-side from a fixed identifier.",
    cap.FILE_WRITE: "Constrain the path with a pattern rooted at an allowed directory and reject traversal server-side.",
    cap.DB_WRITE: "Replace free-form SQL with named, parameterised operations the model can only fill in.",
    cap.NETWORK_SEND: "Allowlist recipients with an enum or a pattern; never accept an arbitrary destination.",
    cap.NETWORK_FETCH: "Allowlist hosts with a pattern and resolve/verify the host server-side before the request.",
    cap.FILE_READ: "Root the path in an allowed directory with a pattern, and canonicalise before opening.",
    cap.DB_READ: "Expose parameterised queries instead of arbitrary SQL.",
}


def _constraint_fix(capability: str, param_name: str) -> str:
    base = _CONSTRAINT_FIXES.get(capability)
    if base:
        return base
    return f"Add an `enum`, `pattern`, or `maxLength` to `{param_name}` so the schema itself bounds what can be passed."
