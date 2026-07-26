"""Axis 3 -- data-exfiltration surface.

Injection is the vector; exfiltration is usually the payoff. This axis asks
whether a successful injection has a route for data to leave, and how wide that
route is. The headline check is the lethal trifecta: private data access,
untrusted content ingestion, and an outbound channel in a single agent.
"""

from __future__ import annotations

from .. import capabilities as cap
from ..context import AuditContext
from ..findings import Axis, Finding, Severity
from ..probes import has_signal


def evaluate(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []

    if ctx.has_lethal_trifecta:
        data_tools = ", ".join(t.name for t in ctx.private_data_tools[:3]) or "declared private data access"
        source_tools = ", ".join(t.name for t in ctx.untrusted_sources[:3]) or "declared untrusted input"
        sink_tools = ", ".join(t.name for t in ctx.open_egress_sinks[:3])
        findings.append(
            Finding(
                id="EXF300",
                axis=Axis.EXFILTRATION,
                severity=Severity.CRITICAL,
                title="Lethal trifecta: private data + untrusted content + outbound channel",
                detail=(
                    f"This agent reads private data ({data_tools}), ingests attacker-controllable "
                    f"content ({source_tools}), and can send data out ({sink_tools}). Any one "
                    f"poisoned document is enough to read your data and forward it. No prompt "
                    f"wording reliably fixes this combination — the architecture has to change."
                ),
                fix=(
                    "Break one leg of the trifecta: split into two agents that do not share a context, "
                    "drop the egress tool from the agent that reads private data, or route all outbound "
                    "calls through a human-approved allowlist."
                ),
            )
        )

    # --- free-form destinations on egress tools ---------------------------
    for tool in ctx.egress_sinks:
        open_destinations = [
            p
            for p in tool.params
            if cap.DESTINATION_PARAM_NAMES.match(p.name) and not p.is_constrained
        ]
        if open_destinations:
            names = ", ".join(f"`{p.name}`" for p in open_destinations)
            findings.append(
                Finding(
                    id="EXF301",
                    axis=Axis.EXFILTRATION,
                    severity=Severity.HIGH,
                    title=f"`{tool.name}` accepts an arbitrary destination",
                    detail=(
                        f"{names} is unconstrained, so the model can be induced to name any host or "
                        f"recipient. This is the standard exfiltration primitive — the attacker does "
                        f"not need to breach anything, only to supply an address."
                    ),
                    fix="Pin destinations to an enum, or validate against a server-side allowlist before the call — never trust the model's chosen address.",
                    tool=tool.name,
                    evidence=[f"{p.name}: {p.type} (unconstrained)" for p in open_destinations],
                )
            )

    # --- no stated egress policy ------------------------------------------
    if ctx.can_egress and not has_signal(ctx.prompt, "egress_allowlist"):
        findings.append(
            Finding(
                id="EXF302",
                axis=Axis.EXFILTRATION,
                severity=Severity.MEDIUM,
                title="No egress allowlist stated in the prompt",
                detail=(
                    "The agent can reach the network but the prompt never bounds where to. Even as a "
                    "defence-in-depth layer behind server-side validation, an explicit allowlist "
                    "gives the model a reason to refuse an injected destination."
                ),
                fix="Name the approved domains or recipients in the prompt and instruct the agent to refuse anything else.",
            )
        )

    # --- markdown rendering exfil -----------------------------------------
    renders = bool(ctx.config.get("renders_markdown"))
    if (renders or ctx.can_egress) and not has_signal(ctx.prompt, "render_safety"):
        severity = Severity.HIGH if renders and ctx.touches_private_data else Severity.MEDIUM
        findings.append(
            Finding(
                id="EXF303",
                axis=Axis.EXFILTRATION,
                severity=severity,
                title="Data can leak through rendered links and images",
                detail=(
                    "If the agent's output is rendered as markdown or HTML, an image URL containing "
                    "stolen data fires on render — no click, no visible trace. The prompt does not "
                    "forbid interpolating data into URLs."
                ),
                fix="Forbid the agent from placing any retrieved or user data into URLs, and strip or proxy remote images in your renderer.",
            )
        )

    # --- memory poisoning as a persistence mechanism ----------------------
    if cap.MEMORY_WRITE in ctx.capabilities and ctx.reads_untrusted_content:
        if not has_signal(ctx.prompt, "memory_safety"):
            findings.append(
                Finding(
                    id="EXF304",
                    axis=Axis.EXFILTRATION,
                    severity=Severity.HIGH,
                    title="Persistent memory is writable from untrusted content",
                    detail=(
                        "The agent both ingests external content and writes to persistent memory, "
                        "with no rule about what may be stored. An injected instruction written to "
                        "memory survives the session and re-fires on every future run."
                    ),
                    fix="Restrict memory writes to a typed schema of facts and preferences, and never persist free text that came from a tool.",
                )
            )

    # --- private data with no handling policy -----------------------------
    if ctx.touches_private_data and not ctx.has_confidentiality_clause:
        findings.append(
            Finding(
                id="EXF305",
                axis=Axis.EXFILTRATION,
                severity=Severity.LOW,
                title="No confidentiality clause for the data the agent can reach",
                detail=(
                    "The agent can read private records but the prompt never states that this data "
                    "must not be disclosed or repeated back into untrusted channels."
                ),
                fix="State explicitly which data classes the agent may surface, to whom, and that everything else stays internal.",
            )
        )

    return findings
