# AI Threat Modeling Assistant — Walkthrough

## What Was Built

A full-stack **AI-powered Threat Modeling Assistant** following the OWASP Threat Modeling Process with STRIDE threat identification and DREAD risk scoring. The app is in `f:\AntiGravity\telnet\Threat Model\`.

---

## Architecture

| Layer | Technology | Files |
|-------|-----------|-------|
| **Web Server** | Python Flask | [app.py](file:///f:/AntiGravity/telnet/Threat%20Model/app.py) |
| **LLM Client** | OpenAI / Anthropic | [llm_client.py](file:///f:/AntiGravity/telnet/Threat%20Model/engine/llm_client.py) |
| **STRIDE Engine** | Python + LLM prompts | [stride.py](file:///f:/AntiGravity/telnet/Threat%20Model/engine/stride.py) |
| **DREAD Scoring** | Python | [dread.py](file:///f:/AntiGravity/telnet/Threat%20Model/engine/dread.py) |
| **Report Generator** | Markdown + HTML | [report.py](file:///f:/AntiGravity/telnet/Threat%20Model/engine/report.py) |
| **Frontend** | HTML/CSS/JS | [index.html](file:///f:/AntiGravity/telnet/Threat%20Model/templates/index.html), [style.css](file:///f:/AntiGravity/telnet/Threat%20Model/static/css/style.css), [app.js](file:///f:/AntiGravity/telnet/Threat%20Model/static/js/app.js) |

---

## Verified Workflow

### Step 1: System Info — Dark-mode wizard with architecture templates

![Step 1 - System Input](C:/Users/mahen/.gemini/antigravity/brain/9b6b44e0-2d38-4cdb-9853-e1f57847c570/step1_initial_ui_1773572467592.png)

### Step 5: Threat Review — 10 STRIDE threats with DREAD risk dashboard

![Step 5 - Threat Review](C:/Users/mahen/.gemini/antigravity/brain/9b6b44e0-2d38-4cdb-9853-e1f57847c570/step4_threat_review_1773572537256.png)

### Step 6: Report Generation — Executive summary with risk metrics

![Step 6 - Report](C:/Users/mahen/.gemini/antigravity/brain/9b6b44e0-2d38-4cdb-9853-e1f57847c570/final_report_preview_1773572563470.png)

### Full Workflow Recording

![Threat Model Test Flow](C:/Users/mahen/.gemini/antigravity/brain/9b6b44e0-2d38-4cdb-9853-e1f57847c570/threat_model_test_1773572453660.webp)

---

## How to Run

```bash
cd "f:\AntiGravity\telnet\Threat Model"
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

### To Enable AI-Powered Analysis

Set an API key in environment variables or create a `.env` file:

```env
# Option A: OpenAI
OPENAI_API_KEY=sk-your-key-here

# Option B: Anthropic
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Without an API key, the app uses curated **template-based threat generation** (still produces real, actionable threats).

---

## Verification Results

| Test | Result |
|------|--------|
| Flask server starts | ✅ Runs on `http://localhost:5000` |
| UI loads with dark theme | ✅ Premium dark-mode wizard |
| Template pre-fills data | ✅ REST API template fills components, flows, boundaries |
| STRIDE analysis runs | ✅ 10 threats across all 6 categories |
| DREAD sliders work | ✅ Real-time score recalculation |
| Risk dashboard updates | ✅ Critical/High/Medium/Low counts |
| Report generation | ✅ Professional Markdown + styled HTML |
| Report export buttons | ✅ [.md](file:///f:/AntiGravity/telnet/graphiti_setup_guide.md) and [.html](file:///f:/AntiGravity/telnet/Threat%20Model/templates/index.html) downloads |
