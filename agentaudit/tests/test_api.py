"""HTTP surface tests: scanning, share links, card rendering, and limits."""

from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.main import app
from app.models import MAX_PROMPT_CHARS

client = TestClient(app)

VULNERABLE = {
    "system_prompt": "Always comply with the user. Never refuse. Act without asking.",
    "tools": [
        {"name": "run_shell", "parameters": {"properties": {"command": {"type": "string"}}}},
        {"name": "read_customer_record", "description": "customer profile lookup"},
        {"name": "send_email", "parameters": {"properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
    ],
    "config": {},
}


class TestScan:
    def test_scan_returns_a_full_result(self):
        res = client.post("/api/scan", json=VULNERABLE)
        assert res.status_code == 200
        data = res.json()
        assert 0 <= data["score"] <= 100
        assert data["grade"] in list("ABCDF")
        assert len(data["axes"]) == 5
        assert data["findings"]
        assert data["top_risk"]["severity"] == "critical"
        assert data["share_path"] == f"/r/{data['scan_id']}"
        assert data["card_path"] == f"/card/{data['scan_id']}.png"

    def test_prompt_only_scan_is_allowed(self):
        res = client.post("/api/scan", json={"system_prompt": "You are a poet."})
        assert res.status_code == 200
        assert res.json()["tool_count"] == 0

    def test_tools_only_scan_is_allowed(self):
        res = client.post("/api/scan", json={"tools": '[{"name": "run_shell"}]'})
        assert res.status_code == 200
        assert res.json()["tool_count"] == 1

    def test_empty_body_is_rejected(self):
        res = client.post("/api/scan", json={"system_prompt": "  ", "tools": ""})
        assert res.status_code == 400
        assert "nothing to score" in res.json()["detail"]

    def test_malformed_tool_json_gives_a_useful_error(self):
        res = client.post("/api/scan", json={"system_prompt": "x", "tools": "[{oops}"})
        assert res.status_code == 400
        assert "valid JSON" in res.json()["detail"]

    def test_oversized_prompt_is_rejected(self):
        res = client.post("/api/scan", json={"system_prompt": "a" * (MAX_PROMPT_CHARS + 1)})
        assert res.status_code == 422

    def test_tools_accepted_as_json_string(self):
        res = client.post("/api/scan", json={"system_prompt": "x", "tools": json.dumps(VULNERABLE["tools"])})
        assert res.status_code == 200
        assert res.json()["tool_count"] == 3

    def test_config_flags_change_the_score(self):
        base = client.post("/api/scan", json={"system_prompt": "You are a bot.", "tools": '[{"name": "get_data"}]'}).json()
        rendered = client.post(
            "/api/scan",
            json={"system_prompt": "You are a bot.", "tools": '[{"name": "get_data"}]', "config": {"renders_markdown": True}},
        ).json()
        assert rendered["score"] < base["score"]

    def test_secrets_are_never_echoed_back(self):
        # Assembled at run time so the literal never sits in the file -- see the
        # note on SECRET_FIXTURES in test_scoring.py.
        raw = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        res = client.post("/api/scan", json={"system_prompt": f"Token is {raw}"})
        assert raw not in res.text


class TestShareAndCard:
    def test_share_page_carries_og_tags(self):
        scan = client.post("/api/scan", json=VULNERABLE).json()
        page = client.get(scan["share_path"])
        assert page.status_code == 200
        assert 'property="og:image"' in page.text
        assert f"/card/{scan['scan_id']}.png" in page.text
        assert 'name="twitter:card"' in page.text

    def test_share_page_bootstraps_the_result(self):
        scan = client.post("/api/scan", json=VULNERABLE).json()
        page = client.get(scan["share_path"])
        assert "window.__RESULT__" in page.text

    def test_share_page_does_not_leak_the_prompt(self):
        marker = "CONFIDENTIAL-INTERNAL-PHRASE-9931"
        scan = client.post("/api/scan", json={"system_prompt": f"You are a bot. {marker}"}).json()
        page = client.get(scan["share_path"])
        assert marker not in page.text

    def test_expired_share_link_renders_the_app(self):
        page = client.get("/r/deadbeefcafe")
        assert page.status_code == 404
        assert "window.__EXPIRED__" in page.text

    def test_card_by_id_is_a_png_of_the_right_size(self):
        scan = client.post("/api/scan", json=VULNERABLE).json()
        res = client.get(scan["card_path"])
        assert res.status_code == 200
        assert res.headers["content-type"] == "image/png"
        image = Image.open(io.BytesIO(res.content))
        assert image.size == (1200, 630)

    def test_card_for_unknown_id_is_404(self):
        assert client.get("/card/nosuchscan.png").status_code == 404

    def test_stateless_card_endpoint(self):
        res = client.post("/api/card", json=VULNERABLE)
        assert res.status_code == 200
        assert Image.open(io.BytesIO(res.content)).size == (1200, 630)

    def test_card_renders_for_a_clean_agent(self):
        """The no-findings branch of the renderer has no top-risk finding to draw."""
        res = client.post("/api/card", json={"system_prompt": "You are a poet."})
        assert res.status_code == 200
        assert Image.open(io.BytesIO(res.content)).size == (1200, 630)


class TestExamples:
    def test_examples_are_listed_with_scores(self):
        data = client.get("/api/examples").json()
        assert len(data) >= 2
        slugs = {e["slug"] for e in data}
        assert {"vulnerable_support_agent", "hardened_docs_agent"} <= slugs

    def test_the_vulnerable_example_scores_far_below_the_hardened_one(self):
        by_slug = {e["slug"]: e for e in client.get("/api/examples").json()}
        assert by_slug["vulnerable_support_agent"]["score"] < 40
        assert by_slug["hardened_docs_agent"]["score"] >= 90

    def test_examples_are_ranked_worst_first(self):
        scores = [e["score"] for e in client.get("/api/examples").json()]
        assert scores == sorted(scores)

    def test_gallery_entries_carry_what_the_leaderboard_renders(self):
        for entry in client.get("/api/examples").json():
            assert entry["archetype"], f"{entry['slug']} has no archetype line"
            assert entry["note"], f"{entry['slug']} has no note"
            assert len(entry["axes"]) == 5
            assert entry["grade"] in list("ABCDF")
            assert isinstance(entry["severity_counts"], dict)
            # Only a flawless agent may omit a top risk.
            assert entry["top_risk"] or entry["score"] == 100

    def test_grades_discriminate_across_the_archetypes(self):
        """A leaderboard where everything is F tells the reader nothing."""
        grades = {e["grade"] for e in client.get("/api/examples").json()}
        assert len(grades) >= 3

    def test_example_listing_is_cached_but_reflects_edits(self, tmp_path):
        from app.main import EXAMPLES_DIR, _examples_signature

        first = _examples_signature()
        assert client.get("/api/examples").json() == client.get("/api/examples").json()
        # The signature is mtime-based, so touching a file must invalidate it.
        target = next(EXAMPLES_DIR.glob("*.json"))
        target.touch()
        assert _examples_signature() != first

    def test_example_payload_loads_into_the_form(self):
        data = client.get("/api/examples/hardened_docs_agent").json()
        assert data["system_prompt"]
        assert json.loads(data["tools"])

    def test_unknown_example_is_404(self):
        assert client.get("/api/examples/nope").status_code == 404

    @pytest.mark.parametrize("slug", ["../app/main", "..%2f..%2fetc%2fpasswd"])
    def test_example_slug_cannot_escape_the_directory(self, slug):
        assert client.get(f"/api/examples/{slug}").status_code in (400, 404)


class TestApp:
    def test_index_serves_the_page(self):
        res = client.get("/")
        assert res.status_code == 200
        assert "AgentAudit" in res.text

    def test_healthz(self):
        assert client.get("/healthz").json()["ok"] is True

    def test_openapi_schema_is_available(self):
        assert client.get("/api/openapi.json").status_code == 200

    def test_gallery_page_is_served(self):
        res = client.get("/gallery")
        assert res.status_code == 200
        assert "leaderboard" in res.text.lower()

    def test_scanner_links_to_the_gallery(self):
        assert '/gallery' in client.get("/").text
