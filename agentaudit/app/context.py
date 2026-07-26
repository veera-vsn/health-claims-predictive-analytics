"""The analysed view of one agent, built once and shared by every rule module."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import capabilities as cap
from .normalize import Tool
from .probes import ProbeResult, run_probes

#: Optional declarations a user can supply to sharpen the audit. Everything here
#: is *also* inferred from the tools where possible, so the fields are a way to
#: correct us, not a form to fill in.
CONFIG_FLAGS = (
    "human_in_the_loop",
    "renders_markdown",
    "has_memory",
    "handles_private_data",
    "executes_model_output",
)

#: Phrases that mean the agent asks a human before acting. These read as
#: controls only when they are *not* negated -- "do not ask for confirmation"
#: contains "ask for confirmation" and means the exact opposite, so every match
#: here goes through `_affirmative`.
_CONFIRMATION = re.compile(
    r"(ask (the user )?(for )?(confirmation|permission|approval)|confirm (with the user )?before|"
    r"require (explicit )?(user )?(confirmation|approval|sign[- ]?off)|"
    r"human[- ]in[- ]the[- ]loop|check with the user (first|before)|get approval|seek approval)",
    re.IGNORECASE,
)

#: Confirmation controls that are phrased as prohibitions and so are *already*
#: negative on the surface. "Do not delete anything without asking" is a real
#: control, so these bypass the negation guard.
_CONFIRMATION_PROHIBITIVE = re.compile(
    r"((do not|don'?t|never|must not|should not) [^.\n]{0,60}without (asking|confirming|confirmation|approval|permission|checking))",
    re.IGNORECASE,
)

#: Negations that flip the meaning of a control phrase that follows them.
_NEGATION = re.compile(
    r"(do not|don'?t|never|no need to|without|avoid|refrain from|must not|should not|"
    r"you needn'?t|skip|bypass|omit|rather than|instead of)\s*$",
    re.IGNORECASE,
)

#: How far back to look for a negation before a matched control phrase.
_NEGATION_WINDOW = 24


def _affirmative(pattern: re.Pattern[str], text: str) -> bool:
    """True when `pattern` matches somewhere it is not negated.

    A prompt can both grant and withhold a control in different sentences; we
    credit it if any single occurrence stands unnegated.
    """
    for match in pattern.finditer(text):
        window = text[max(0, match.start() - _NEGATION_WINDOW) : match.start()]
        if not _NEGATION.search(window):
            return True
    return False

#: Phrases that hand the agent a blank cheque.
_UNBOUNDED_AUTONOMY = re.compile(
    r"(without (asking|confirmation|approval|checking|permission)|do not ask (for )?(permission|confirmation|the user)|"
    r"never ask|act autonomously|full autonomy|no confirmation (is )?(needed|required)|proceed automatically|"
    r"take any action (necessary|required)|do whatever (it takes|is necessary))",
    re.IGNORECASE,
)

#: Phrases that invite the model to abandon its guardrails.
_OVERRIDE_INVITATION = re.compile(
    r"(you (can|may|should) ignore .{0,40}(instruction|rule|restriction|guideline)|always comply|comply with (all|any) (request|instruction)|"
    r"never refuse|do not refuse|you must obey|obey (all|any)|no restrictions|without limitation|"
    r"you have no (restrictions|limits|guardrails)|bypass .{0,20}(safety|filter|policy)|unrestricted)",
    re.IGNORECASE,
)

#: Phrases that keep the prompt and credentials confidential.
_CONFIDENTIALITY = re.compile(
    r"(never (reveal|disclose|share|print|repeat|output|expose) .{0,60}(system prompt|instructions|these rules|credential|api key|secret|token)|"
    r"do not (reveal|disclose|share|print|repeat|output|expose) .{0,60}(system prompt|instructions|these rules|credential|api key|secret|token)|"
    r"(prompt|instructions) (is|are) confidential|keep .{0,30}(confidential|private|secret))",
    re.IGNORECASE,
)

#: Phrases requiring a machine-checkable output shape.
_STRUCTURED_OUTPUT = re.compile(
    r"(respond (only )?(in|with) (valid )?json|return (valid )?json|output (must be|as) (valid )?json|"
    r"conform to the .{0,20}schema|match the (following )?schema|json schema|"
    r"respond in the (following|exact) format|use this format exactly|xml tags?)",
    re.IGNORECASE,
)

#: Phrases requiring the agent to validate what a tool handed back.
_VALIDATES_OUTPUT = re.compile(
    r"(validate .{0,40}(output|result|response|data|input)|verify .{0,40}(output|result|before|against)|"
    r"check that .{0,40}(matches|conforms|is valid)|sanitis|saniti[sz]e|escape .{0,20}(html|output|input|special)|"
    r"reject .{0,40}(malformed|invalid|unexpected))",
    re.IGNORECASE,
)

#: Phrases requiring sources to be cited (a weak but real grounding control).
_CITATION = re.compile(
    r"(cite (your )?(sources?|references?)|include (the )?(source|citation|reference)|link to the source|"
    r"attribute .{0,20}(to|the source)|state where .{0,20}(came from|you found))",
    re.IGNORECASE,
)

#: Phrases bounding response length or scope.
_BOUNDED = re.compile(
    r"(no more than \d+|at most \d+|maximum of \d+|limit .{0,30}to \d+|under \d+ (words|characters|tokens|items)|"
    r"keep .{0,30}(brief|short|concise)|\d+ (words|sentences|characters|items) or (fewer|less))",
    re.IGNORECASE,
)


@dataclass
class AuditContext:
    """Everything the rules need, computed once."""

    prompt: str
    tools: list[Tool]
    config: dict = field(default_factory=dict)
    probe_results: list[ProbeResult] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)

    # -- construction ------------------------------------------------------

    @classmethod
    def build(cls, prompt: str, tools: list[Tool], config: dict | None = None) -> "AuditContext":
        config = dict(config or {})
        cap.annotate(tools)
        capabilities: set[str] = set()
        for tool in tools:
            capabilities |= tool.capabilities

        # Config can declare capabilities the tool names don't reveal.
        if config.get("has_memory"):
            capabilities.add(cap.MEMORY_WRITE)
        if config.get("handles_private_data"):
            capabilities.add(cap.USER_DATA)

        ctx = cls(prompt=prompt, tools=tools, config=config, capabilities=capabilities)
        ctx.probe_results = run_probes(prompt, capabilities)
        return ctx

    # -- prompt predicates -------------------------------------------------

    @property
    def has_prompt(self) -> bool:
        return bool(self.prompt.strip())

    @property
    def asks_confirmation(self) -> bool:
        if self.config.get("human_in_the_loop"):
            return True
        if _CONFIRMATION_PROHIBITIVE.search(self.prompt):
            return True
        return _affirmative(_CONFIRMATION, self.prompt)

    @property
    def grants_unbounded_autonomy(self) -> bool:
        return bool(_UNBOUNDED_AUTONOMY.search(self.prompt))

    @property
    def invites_override(self) -> bool:
        return bool(_OVERRIDE_INVITATION.search(self.prompt))

    @property
    def has_confidentiality_clause(self) -> bool:
        return bool(_CONFIDENTIALITY.search(self.prompt))

    @property
    def requires_structured_output(self) -> bool:
        return _affirmative(_STRUCTURED_OUTPUT, self.prompt)

    @property
    def validates_output(self) -> bool:
        return _affirmative(_VALIDATES_OUTPUT, self.prompt)

    @property
    def requires_citations(self) -> bool:
        return _affirmative(_CITATION, self.prompt)

    @property
    def bounds_response(self) -> bool:
        return _affirmative(_BOUNDED, self.prompt)

    # -- capability predicates ---------------------------------------------

    def tools_with(self, caps: set[str]) -> list[Tool]:
        return cap.tools_with(self.tools, caps)

    @property
    def untrusted_sources(self) -> list[Tool]:
        return self.tools_with(cap.UNTRUSTED_SOURCES)

    @property
    def egress_sinks(self) -> list[Tool]:
        return self.tools_with(cap.EGRESS_SINKS)

    @property
    def dangerous_sinks(self) -> list[Tool]:
        return self.tools_with(cap.DANGEROUS_SINKS)

    @property
    def private_data_tools(self) -> list[Tool]:
        return self.tools_with(cap.PRIVATE_DATA)

    def _declared(self, key: str) -> bool | None:
        """An explicit config boolean, or None when the user said nothing.

        An explicit `false` is a real signal -- "my RAG corpus is public docs"
        -- and has to beat inference, otherwise the flag is unusable.
        """
        if key not in self.config:
            return None
        value = self.config[key]
        return bool(value) if isinstance(value, bool) else None

    @property
    def reads_untrusted_content(self) -> bool:
        declared = self._declared("reads_untrusted_content")
        if declared is not None:
            return declared
        return bool(self.untrusted_sources)

    @property
    def can_egress(self) -> bool:
        return bool(self.egress_sinks)

    @property
    def open_egress_sinks(self) -> list[Tool]:
        """Egress tools whose destination the model can actually choose.

        A tool whose only destination parameter is pinned by an enum or a host
        pattern is a bounded channel, not an exfiltration primitive.
        """
        out: list[Tool] = []
        for tool in self.egress_sinks:
            destinations = [p for p in tool.params if cap.DESTINATION_PARAM_NAMES.match(p.name)]
            if not destinations or any(not p.is_constrained for p in destinations):
                out.append(tool)
        return out

    @property
    def touches_private_data(self) -> bool:
        declared = self._declared("handles_private_data")
        if declared is not None:
            return declared
        return bool(self.private_data_tools)

    @property
    def has_lethal_trifecta(self) -> bool:
        """Private data + untrusted content + an *open* egress path, in one agent.

        Simon Willison's framing: any two of these is manageable, all three
        means a single poisoned document can walk your data out the door. We
        require the egress leg to be unbounded -- an allowlisted fetcher does
        not complete the trifecta.
        """
        return bool(self.touches_private_data and self.reads_untrusted_content and self.open_egress_sinks)

    @property
    def unmitigated_probes(self) -> list[ProbeResult]:
        return [r for r in self.probe_results if r.unmitigated]
