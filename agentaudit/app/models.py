"""Request and response models for the public API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

#: Generous enough for a real agent, small enough that nobody can post a novel.
MAX_PROMPT_CHARS = 200_000
MAX_TOOLS_CHARS = 500_000


class ScanRequest(BaseModel):
    system_prompt: str = Field(default="", description="The agent's system prompt.")
    tools: Any = Field(default=None, description="Tool schema: JSON string, array, or object.")
    config: dict[str, Any] = Field(default_factory=dict, description="Optional declarations.")

    @field_validator("system_prompt")
    @classmethod
    def _prompt_length(cls, value: str) -> str:
        if len(value) > MAX_PROMPT_CHARS:
            raise ValueError(f"system_prompt exceeds {MAX_PROMPT_CHARS} characters")
        return value

    @field_validator("tools")
    @classmethod
    def _tools_length(cls, value: Any) -> Any:
        if isinstance(value, str) and len(value) > MAX_TOOLS_CHARS:
            raise ValueError(f"tools exceeds {MAX_TOOLS_CHARS} characters")
        return value

    @field_validator("config")
    @classmethod
    def _config_size(cls, value: dict) -> dict:
        if len(value) > 32:
            raise ValueError("config has too many keys")
        return value

    @property
    def is_empty(self) -> bool:
        if self.system_prompt.strip():
            return False
        if isinstance(self.tools, str):
            return not self.tools.strip()
        return not self.tools
