# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
pip install -r requirements.txt
python app.py
# Server starts at http://localhost:5000
```

Configure via `.env`:
- `LLM_PROVIDER`: `anthropic`, `openai`, or `gemini` (auto-detected from API keys)
- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY`
- `ANTHROPIC_MODEL` / `OPENAI_MODEL` / `GEMINI_MODEL`
- `FLASK_PORT` (default 5000), `FLASK_DEBUG`

When no valid API key is set, the app returns a 503 error — there is no fallback. At least one API key must be configured.

## Architecture

Single-process Flask app. No database — all state is held in-memory in `app.py` (`active_models` dict keyed by session).

**Request flow:**
```
Browser (7-step wizard)
  → Flask routes (app.py)
    → STRIDEAnalyzer (engine/stride.py)       # builds prompts, calls LLM
    → LLMClient (engine/llm_client.py)        # wraps Anthropic / OpenAI / Gemini SDKs
    → DREADScorer (engine/dread.py)           # scores & aggregates risk
    → ReportGenerator (engine/report.py)      # produces Markdown / HTML output
```

**Key modules:**
- `engine/threat_model.py` — core dataclasses: `Threat`, `DREADScore`, `SystemInfo`, `ThreatModel`, plus `STRIDE_CATEGORIES` and `ARCHITECTURE_TEMPLATES`
- `engine/llm_client.py` — `generate()`, `generate_stream()`, `generate_json()` with provider auto-detection
- `engine/stride.py` — `analyze_threats_with_llm()` (raises `RuntimeError` if LLM unavailable or parse fails)
- `prompts/templates.py` — `DOMAIN_EXPERTISE` dict (11+ domains), `SYSTEM_PROMPT`, `ANALYZE_THREATS_PROMPT`

**API endpoints (app.py):**
- `GET /api/status` — LLM readiness
- `GET /api/templates` — architecture templates
- `POST /api/analyze` — run STRIDE (blocking)
- `POST /api/analyze/stream` — run STRIDE (SSE streaming)
- `POST /api/score` — update DREAD scores
- `POST /api/threat/remove` — remove a threat
- `POST /api/report/markdown|html|preview` — export reports

**Frontend:** Single-page dark-mode wizard in `templates/index.html` + `static/js/app.js`. No build step required.

## No Test Suite

There are no automated tests. `walkthrough.md` describes manual verification steps.
