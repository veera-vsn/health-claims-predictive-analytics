"""Rule modules, one per scoring axis.

Every module exposes `evaluate(ctx: AuditContext) -> list[Finding]` and holds no
state, so the whole audit is a pure function of the pasted input.
"""

from . import exfiltration, injection, output_validation, scoping, secrets

#: Evaluation order. Only affects tie-breaking in the report, not the score.
MODULES = (injection, scoping, exfiltration, secrets, output_validation)

__all__ = ["MODULES", "injection", "scoping", "exfiltration", "secrets", "output_validation"]
