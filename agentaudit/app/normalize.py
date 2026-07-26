"""Parse whatever tool-schema dialect the user pasted into one internal shape.

Agent frameworks all describe tools slightly differently. We accept the four
formats people actually paste -- OpenAI function-calling (current and legacy),
Anthropic `input_schema`, and MCP `inputSchema` -- plus a bare name->spec map,
because making someone reformat their tools before they can get a score kills
the whole "paste and go" moment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: Keys that hold the JSON Schema for a tool's arguments, in priority order.
SCHEMA_KEYS = ("parameters", "input_schema", "inputSchema", "schema", "args_schema")


class ToolParseError(ValueError):
    """Raised when the pasted tool blob cannot be understood at all."""


@dataclass
class Param:
    name: str
    type: str = "unknown"
    description: str = ""
    required: bool = False
    enum: list[Any] | None = None
    pattern: str | None = None
    max_length: int | None = None
    fmt: str | None = None

    @property
    def is_constrained(self) -> bool:
        """True when the schema meaningfully narrows what can be passed."""
        if self.enum:
            return True
        if self.pattern:
            return True
        if self.type in ("boolean", "integer", "number"):
            return True
        if self.max_length is not None and self.max_length <= 256:
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "constrained": self.is_constrained,
        }


@dataclass
class Tool:
    name: str
    description: str = ""
    schema: dict = field(default_factory=dict)
    params: list[Param] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)

    @property
    def text(self) -> str:
        """Name plus description, lowercased -- what capability rules match on."""
        return f"{self.name} {self.description}".lower()

    @property
    def additional_properties_open(self) -> bool:
        return self.schema.get("additionalProperties", True) is not False

    def param(self, name: str) -> Param | None:
        for p in self.params:
            if p.name == name:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "capabilities": sorted(self.capabilities),
            "params": [p.to_dict() for p in self.params],
        }


def _extract_schema(spec: dict) -> dict:
    for key in SCHEMA_KEYS:
        value = spec.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _parse_params(schema: dict) -> list[Param]:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    required = schema.get("required")
    required_names = set(required) if isinstance(required, list) else set()

    params: list[Param] = []
    for name, spec in properties.items():
        if not isinstance(spec, dict):
            params.append(Param(name=str(name), required=str(name) in required_names))
            continue
        declared = spec.get("type", "unknown")
        # JSON Schema allows a list of types (e.g. ["string", "null"]).
        if isinstance(declared, list):
            declared = next((t for t in declared if t != "null"), "unknown")
        params.append(
            Param(
                name=str(name),
                type=str(declared),
                description=str(spec.get("description", "")),
                required=str(name) in required_names,
                enum=spec.get("enum") if isinstance(spec.get("enum"), list) else None,
                pattern=spec.get("pattern") if isinstance(spec.get("pattern"), str) else None,
                max_length=spec.get("maxLength") if isinstance(spec.get("maxLength"), int) else None,
                fmt=spec.get("format") if isinstance(spec.get("format"), str) else None,
            )
        )
    return params


def _tool_from_spec(spec: dict, fallback_name: str | None = None) -> Tool | None:
    # OpenAI current format nests everything under "function".
    if isinstance(spec.get("function"), dict):
        spec = spec["function"]

    name = spec.get("name") or spec.get("tool_name") or fallback_name
    if not name:
        return None

    schema = _extract_schema(spec)
    return Tool(
        name=str(name),
        description=str(spec.get("description") or spec.get("desc") or ""),
        schema=schema,
        params=_parse_params(schema),
    )


def parse_tools(raw: Any) -> list[Tool]:
    """Turn a pasted tool definition into `Tool` objects.

    Accepts a JSON string, a list of tool specs, or a name->spec mapping. Blank
    input is legitimate -- plenty of agents are prompt-only -- and yields [].
    """
    if raw is None:
        return []

    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolParseError(f"Tools must be valid JSON: {exc.msg} (line {exc.lineno})") from exc

    # Some frameworks wrap the list in an envelope.
    if isinstance(raw, dict):
        for key in ("tools", "functions", "tool_definitions"):
            if isinstance(raw.get(key), (list, dict)):
                raw = raw[key]
                break

    tools: list[Tool] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                tool = _tool_from_spec(item)
                if tool:
                    tools.append(tool)
    elif isinstance(raw, dict):
        # A name -> spec mapping, e.g. {"read_file": {"description": ...}}.
        for name, spec in raw.items():
            if isinstance(spec, dict):
                tool = _tool_from_spec(spec, fallback_name=str(name))
                if tool:
                    tools.append(tool)
    else:
        raise ToolParseError("Tools must be a JSON array or object of tool definitions.")

    return tools
