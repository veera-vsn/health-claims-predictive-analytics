"""Axis 5 -- output validation.

Model output is untrusted input to whatever consumes it. This axis asks what
happens downstream: does generated text reach a shell, a SQL engine, or a
browser without a validation step, and does the prompt commit to a shape you
can actually check?
"""

from __future__ import annotations

import re

from .. import capabilities as cap
from ..context import AuditContext
from ..findings import Axis, Finding, Severity

#: Parameters whose contents are executed or interpreted by the receiver.
_EXECUTED_PARAMS = re.compile(r"^(command|cmd|code|script|sql|query|statement|expression|eval|program)s?$", re.IGNORECASE)


def evaluate(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []

    # --- model output flowing into an interpreter -------------------------
    executing = []
    for tool in ctx.tools:
        if tool.capabilities & {cap.SHELL, cap.DB_WRITE, cap.DB_READ, cap.DEPLOY}:
            hits = [p for p in tool.params if _EXECUTED_PARAMS.match(p.name)]
            if hits:
                executing.append((tool, hits))

    if executing or ctx.config.get("executes_model_output"):
        names = ", ".join(f"`{t.name}`" for t, _ in executing[:3]) or "a declared execution sink"
        findings.append(
            Finding(
                id="OUT500",
                axis=Axis.OUTPUT,
                severity=Severity.HIGH,
                title="Generated text is executed without a validation layer",
                detail=(
                    f"{names} interprets whatever the model writes. Prompt injection becomes remote "
                    f"code execution at this boundary — there is no separate exploit step."
                ),
                fix="Parse and validate generated commands or queries against an allowlisted grammar before execution, and run them with the least privilege that still works.",
                tool=executing[0][0].name if executing else None,
            )
        )

    # --- no committed output shape ----------------------------------------
    if not ctx.requires_structured_output:
        severity = Severity.MEDIUM if ctx.tools else Severity.LOW
        findings.append(
            Finding(
                id="OUT501",
                axis=Axis.OUTPUT,
                severity=severity,
                title="No structured output contract",
                detail=(
                    "The prompt does not commit the agent to JSON, a schema, or a fixed format. "
                    "Free-form output cannot be validated, so downstream code either trusts it or "
                    "parses it heuristically — both fail silently under injection."
                ),
                fix="Specify an exact output schema and validate every response against it, rejecting anything that does not parse.",
            )
        )

    # --- nothing said about checking tool results -------------------------
    if ctx.tools and not ctx.validates_output:
        findings.append(
            Finding(
                id="OUT502",
                axis=Axis.OUTPUT,
                severity=Severity.MEDIUM,
                title="No instruction to validate or sanitise tool results",
                detail=(
                    "The prompt never asks the agent to check that tool output is well-formed or "
                    "plausible before acting on it. Malformed or hostile results propagate straight "
                    "into the next tool call."
                ),
                fix="Instruct the agent to verify tool results against expectations and to stop and report rather than improvise when they do not match.",
            )
        )

    # --- HTML/script in rendered output -----------------------------------
    if ctx.config.get("renders_markdown"):
        forbids_html = re.search(r"(do not (output|emit|include|generate) .{0,40}(html|script|iframe|javascript)|no raw html|escape html)", ctx.prompt, re.IGNORECASE)
        if not forbids_html:
            findings.append(
                Finding(
                    id="OUT503",
                    axis=Axis.OUTPUT,
                    severity=Severity.MEDIUM,
                    title="Rendered output is not constrained against active content",
                    detail=(
                        "Output is rendered as markdown or HTML and the prompt does not forbid raw "
                        "HTML, script tags, or iframes. An injection that shapes the response becomes "
                        "stored XSS in your UI."
                    ),
                    fix="Forbid raw HTML in the prompt and — the part that actually matters — sanitise on the render side with an allowlist.",
                )
            )

    # --- retrieval without attribution ------------------------------------
    if cap.RETRIEVAL in ctx.capabilities and not ctx.requires_citations:
        findings.append(
            Finding(
                id="OUT504",
                axis=Axis.OUTPUT,
                severity=Severity.LOW,
                title="Retrieved claims are not attributed to a source",
                detail=(
                    "The agent retrieves documents but is not required to cite them. Without "
                    "attribution, neither the user nor a reviewer can tell which claim came from a "
                    "poisoned document."
                ),
                fix="Require a source identifier alongside every retrieved claim, and surface it in the UI.",
            )
        )

    # --- unbounded responses ----------------------------------------------
    if not ctx.bounds_response and ctx.tools:
        findings.append(
            Finding(
                id="OUT505",
                axis=Axis.OUTPUT,
                severity=Severity.LOW,
                title="No length or scope bound on responses",
                detail=(
                    "Nothing caps how much the agent emits or how many tool calls it chains. This "
                    "is a cost and loop-safety issue as much as a security one."
                ),
                fix="State an explicit bound on response length and tool-call depth, and enforce a hard iteration cap in your runner.",
            )
        )

    return findings
