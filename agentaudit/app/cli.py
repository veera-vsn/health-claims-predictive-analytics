"""Command-line scanner, so an audit can gate a build.

    python -m app.cli examples/vulnerable_support_agent.json --min-score 70

Exits non-zero when the score falls below the threshold or a finding at or
above `--fail-on` is present, which is all a CI step needs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .findings import RANK, Severity
from .scoring import AuditResult, audit

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2

COLOURS = {
    "critical": "\033[97;41m",
    "high": "\033[30;43m",
    "medium": "\033[30;46m",
    "low": "\033[37;100m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _paint(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLOURS[key]}{text}{COLOURS['reset']}"


def load_spec(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        # A bare tool array is a legitimate thing to point us at.
        return {"tools": data}
    return data


def render_text(result: AuditResult, colour: bool) -> str:
    lines = [
        "",
        f"  {_paint(f'{result.score}/100', 'bold', colour)}  {result.grade} · {result.verdict}",
        f"  {result.headline()}",
        "",
    ]
    for axis in result.axes:
        lines.append(f"  {axis.label:<22} {axis.bar}  {axis.score:>3}")
    lines.append("")

    if not result.findings:
        lines.append("  No findings.\n")
        return "\n".join(lines)

    for finding in result.findings:
        tag = _paint(f" {finding.severity.value.upper()} ", finding.severity.value, colour)
        where = f" [{finding.tool}]" if finding.tool else ""
        lines.append(f"  {tag} {finding.title}{where}")
        lines.append(f"      {_paint('fix:', 'dim', colour)} {finding.fix}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentaudit",
        description="Score an agent's system prompt and tool schema for injection and privilege risk.",
    )
    parser.add_argument("spec", type=Path, help="JSON file with system_prompt, tools, and optional config.")
    parser.add_argument("--min-score", type=int, default=0, help="Exit non-zero below this score.")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s is not Severity.INFO],
        help="Exit non-zero if any finding is at or above this severity.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON.")
    parser.add_argument("--card", type=Path, help="Also write the share card PNG here.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colour.")
    args = parser.parse_args(argv)

    if not args.spec.is_file():
        print(f"agentaudit: no such file: {args.spec}", file=sys.stderr)
        return EXIT_USAGE

    try:
        spec = load_spec(args.spec)
        result = audit(spec.get("system_prompt", ""), spec.get("tools"), spec.get("config"))
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"agentaudit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        colour = sys.stdout.isatty() and not args.no_color
        print(render_text(result, colour))

    if args.card:
        from .card import render_card

        args.card.write_bytes(render_card(result))
        print(f"  card written to {args.card}", file=sys.stderr)

    failed = result.score < args.min_score
    if args.fail_on:
        threshold = RANK[Severity(args.fail_on)]
        failed = failed or any(RANK[f.severity] <= threshold for f in result.findings)

    if failed:
        print(
            f"agentaudit: FAILED (score {result.score}, threshold {args.min_score})",
            file=sys.stderr,
        )
        return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
