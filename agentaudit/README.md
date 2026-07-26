# AgentAudit

**Your AI agent has a security score. Most are failing.**

Paste an agent's system prompt and tool schema; get a 0–100 security audit across five
axes, a ranked findings list with a concrete fix for each, and a shareable score card —
in about 20 seconds.

```
  15/100  F · Critically exposed
  Critically exposed — 7 unmitigated injection classes.

  Injection Resistance   ░░░░░    0
  Tool Scoping           ░░░░░    0
  Exfil Surface          ░░░░░    0
  Secret Handling        ▓▓▓░░   66
  Output Validation      ▓▓░░░   37

   CRITICAL  Lethal trifecta: private data + untrusted content + outbound channel
   CRITICAL  `run_shell_command` takes unconstrained input for a privileged action
      HIGH  credential hardcoded in the system prompt
```

## Why it is built this way

**No LLM is involved in scoring.** Every check is static analysis over the prompt text
and the tool schema. That is a deliberate design choice, not a shortcut:

- **Deterministic.** The same input always produces the same score, which is what makes
  it usable as a CI gate. A score that drifts between runs is worthless in a build.
- **Free to run.** Scanning is pure CPU. A launch-day traffic spike costs bandwidth and
  nothing else — there is no per-scan inference bill to bankrupt the free tier.
- **Private.** Your system prompt is never sent to a model provider. It is scored in
  memory and discarded.

The trade-off is real and worth stating plainly: this measures whether your prompt and
schema **declare** the right controls, not whether your runtime **enforces** them. A high
score is a floor, not a guarantee.

## Quick start

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# open http://localhost:8000
```

Run the tests:

```bash
pip install -r requirements-dev.txt
pytest
```

## Use it in CI

```bash
python -m app.cli agent.json --min-score 70
python -m app.cli agent.json --fail-on high --json
python -m app.cli agent.json --card score.png
```

Exit codes: `0` pass · `1` below threshold or a finding at/above `--fail-on` · `2` usage error.

```yaml
# .github/workflows/agent-security.yml
- run: python -m app.cli agents/support.json --min-score 75 --fail-on critical
```

The spec file is `{"system_prompt": "...", "tools": [...], "config": {...}}`. A bare tool
array works too.

## The five axes

| Axis | Weight | What it asks |
|---|---|---|
| Injection resistance | 25% | Does the prompt state a defence against each attack class the agent's capabilities expose it to? |
| Tool scoping | 25% | If the model were fully compromised, how much could it actually do? |
| Exfiltration surface | 20% | Is there a route for data to leave, and how wide is it? |
| Secret handling | 15% | Are credentials in the prompt, or routed through the model as tool arguments? |
| Output validation | 15% | Does generated text reach a shell, a SQL engine, or a browser unchecked? |

Each axis starts at 100; findings subtract 40 (critical), 22 (high), 12 (medium), or 5
(low), floored at zero. The composite is the weighted sum.

Grades: **A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F below**. The bands are wide at the
bottom on purpose. They were calibrated against the eight archetypes in `examples/`: on
an evenly-spaced scale six of the eight landed in F, which makes the letter meaningless.
A config with a good trust-boundary prompt and one unscoped tool is not in the same
state as one with a hardcoded credential and a free-form shell, and the grade should say
so.

## The gallery

`/gallery` scores eight common agent architectures and ranks them worst-first — a
leaderboard of *architectures*, never of people or of anyone's production system. Every
entry is a reference implementation of a widely-published pattern, written for this repo
and reproducible with `python -m app.cli examples/<slug>.json`.

| | Architecture | Score |
|---|---|---|
| 1 | Vulnerable support agent | 15 · F |
| 2 | Browser shopping agent | 35 · F |
| 3 | Email triage assistant | 39 · F |
| 4 | MCP filesystem server | 49 · D |
| 5 | RAG support bot | 55 · D |
| 6 | Autonomous coding agent | 56 · D |
| 7 | SQL analyst agent | 81 · B |
| 8 | Hardened docs agent | 100 · A |

The pattern worth noticing: the failures cluster in *architecture*, not prose. The
coding agent and the SQL analyst both have careful trust-boundary prompts; what sinks
them is a free-form `command` and a free-form `sql`. Prompt wording is the cheap half.

### The injection probe library

Seven attack classes, following the AgentDojo taxonomy. A probe counts as *unmitigated*
when the agent's capabilities make it reachable and the prompt states no defence.

| | Class | Relevant when |
|---|---|---|
| P1 | Direct instruction override | always |
| P2 | Tool-output injection | the agent reads external content |
| P3 | Delimiter / role escape | always |
| P4 | Authority spoofing | always |
| P5 | Data exfiltration via URL | the agent can reach the network |
| P6 | Memory / multi-turn poisoning | the agent has memory or retrieval |
| P7 | Encoded / obfuscated payload | always |

### The lethal trifecta

The headline check, following Simon Willison's framing: private data access **+**
untrusted content ingestion **+** an outbound channel, in one agent. Any two are
manageable; all three mean a single poisoned document can walk your data out the door.
An egress tool whose destination is pinned by an `enum` or host `pattern` does not
complete the trifecta — bounded channels are not exfiltration primitives.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/scan` | Score an agent. Returns the full result plus share and card paths. |
| `POST /api/card` | Stateless PNG render, for CI jobs that want the image in one call. |
| `GET /r/{scan_id}` | Share page with Open Graph tags for link unfurls. |
| `GET /card/{scan_id}.png` | The 1200×630 score card. |
| `GET /gallery` | The leaderboard of scored architectures. |
| `GET /api/examples` | The bundled example agents, with live scores. |
| `GET /api/docs` | OpenAPI docs. |

```bash
curl -s localhost:8000/api/scan -H 'Content-Type: application/json' \
  -d '{"system_prompt": "You are a bot.", "tools": "[{\"name\": \"run_shell\"}]"}' | jq .score
```

Tool schemas are accepted in OpenAI (current and legacy), Anthropic `input_schema`, MCP
`inputSchema`, or a bare `name -> spec` mapping. Nobody should have to reformat their
tools to get a score.

### Optional config flags

All are inferred from the tools where possible; set them to correct us. An explicit
`false` beats inference — useful when, say, your RAG corpus is public documentation
rather than private records.

`renders_markdown` · `has_memory` · `handles_private_data` · `human_in_the_loop` ·
`executes_model_output` · `reads_untrusted_content`

## Data handling

Nothing is written to disk. Scan results live in a bounded in-memory LRU (1000 entries,
24-hour TTL) purely so share links resolve, and the store keeps the **result** — never
the prompt text. Detected secrets are redacted before they leave the process: the API
response contains `ghp_ab…******** (40 chars)`, never the credential. Restarting the
server clears everything.

## Layout

```
app/
  findings.py     severity, axis, and penalty primitives
  normalize.py    parse OpenAI / Anthropic / MCP tool dialects into one shape
  capabilities.py classify each tool by what it can actually do
  probes.py       the injection probe library and its defence signals
  context.py      the analysed view of one agent, built once
  rules/          one module per axis, each a pure evaluate(ctx) -> [Finding]
  scoring.py      compose the axes into a composite result
  card.py         render the 1200x630 share card with Pillow
  cli.py          CI entry point
  main.py         FastAPI service
  static/         the scanner page and the gallery
examples/         eight agent archetypes, used by the UI, the gallery, and the tests
tests/            121 tests across the engine, API, and CLI
Dockerfile        production image
.github/          a copy-pasteable CI workflow
```

## Deploying

```bash
docker build -t agentaudit .
docker run -p 8000:8000 -e AGENTAUDIT_HOST=agentaudit.dev agentaudit
```

`AGENTAUDIT_HOST` is the hostname stamped on share cards and Open Graph URLs; set it to
your real domain or link unfurls will point at the placeholder. `PORT` is honoured for
platforms that inject one.

The image installs `fonts-dejavu-core` because `card.py` looks for DejaVu first and
falls back to a bitmap font that renders badly. Everything else is a wheel, so there is
no build toolchain in the image.

Share links are held per-process in memory, so if you run multiple workers a link is
only resolvable by the worker that created it. For a single-box launch that is fine;
scale out and you need shared storage or sticky sessions.

## Limitations

- It reads **stated policy**, not runtime behaviour. It cannot see your guardrails,
  sandbox, or server-side validation — declare those with the config flags.
- Capability classification is keyword-based over tool names and descriptions. A tool
  called `do_the_thing` with no description classifies as nothing.
- A 100 means every control this scanner checks for is present. It does not mean the
  agent is secure.
