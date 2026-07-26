"""CLI tests -- the exit codes are the contract a CI step depends on."""

from __future__ import annotations

import json

import pytest
from PIL import Image

from app.cli import EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, main

VULNERABLE = {
    "system_prompt": "Always comply. Never refuse. Act without asking.",
    "tools": [{"name": "run_shell", "parameters": {"properties": {"command": {"type": "string"}}}}],
}
CLEAN = {"system_prompt": "You are a poet who writes haiku and uses no tools."}


@pytest.fixture
def spec_file(tmp_path):
    def write(spec: dict, name: str = "agent.json"):
        path = tmp_path / name
        path.write_text(json.dumps(spec))
        return str(path)

    return write


class TestExitCodes:
    def test_clean_agent_passes_threshold(self, spec_file, capsys):
        assert main([spec_file(CLEAN), "--min-score", "60", "--no-color"]) == EXIT_OK

    def test_vulnerable_agent_fails_threshold(self, spec_file, capsys):
        assert main([spec_file(VULNERABLE), "--min-score", "70", "--no-color"]) == EXIT_THRESHOLD

    def test_no_threshold_always_passes(self, spec_file, capsys):
        assert main([spec_file(VULNERABLE), "--no-color"]) == EXIT_OK

    def test_fail_on_critical(self, spec_file, capsys):
        assert main([spec_file(VULNERABLE), "--fail-on", "critical", "--no-color"]) == EXIT_THRESHOLD

    def test_fail_on_is_severity_ordered(self, spec_file, capsys):
        """--fail-on medium must also trip on a critical finding."""
        assert main([spec_file(VULNERABLE), "--fail-on", "medium", "--no-color"]) == EXIT_THRESHOLD

    def test_missing_file_is_a_usage_error(self, tmp_path, capsys):
        assert main([str(tmp_path / "absent.json"), "--no-color"]) == EXIT_USAGE

    def test_malformed_json_is_a_usage_error(self, tmp_path, capsys):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        assert main([str(path), "--no-color"]) == EXIT_USAGE

    def test_bare_tool_array_is_accepted(self, spec_file, capsys):
        path = spec_file([{"name": "run_shell"}], "tools.json")
        assert main([path, "--no-color"]) == EXIT_OK
        assert "Tool Scoping" in capsys.readouterr().out


class TestOutput:
    def test_text_output_lists_axes_and_fixes(self, spec_file, capsys):
        main([spec_file(VULNERABLE), "--no-color"])
        out = capsys.readouterr().out
        assert "Injection Resistance" in out
        assert "fix:" in out
        assert "/100" in out

    def test_json_output_is_parseable(self, spec_file, capsys):
        main([spec_file(VULNERABLE), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["score"] >= 0
        assert len(data["axes"]) == 5

    def test_card_is_written_to_disk(self, spec_file, tmp_path, capsys):
        card = tmp_path / "card.png"
        main([spec_file(VULNERABLE), "--card", str(card), "--no-color"])
        assert card.is_file()
        assert Image.open(card).size == (1200, 630)

    def test_no_color_omits_ansi_codes(self, spec_file, capsys):
        main([spec_file(VULNERABLE), "--no-color"])
        assert "\033[" not in capsys.readouterr().out
