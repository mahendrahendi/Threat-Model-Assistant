# AI Threat Modeling Assistant

An AI-powered threat modeling tool that uses **STRIDE** threat categorization and **DREAD** risk scoring to generate professional, context-aware security assessments. Powered by your choice of **Anthropic Claude**, **OpenAI GPT**, or **Google Gemini**.

## Table of Contents

- [Quick Start](#quick-start)
- [Supported LLM Providers](#supported-llm-providers)
- [The 7-Step Wizard](#the-7-step-wizard)
- [How to Get the Best Results](#how-to-get-the-best-results)
- [Understanding the Output](#understanding-the-output)
- [Domain Expertise Modes](#domain-expertise-modes)
- [Architecture Templates](#architecture-templates)
- [Exporting Reports](#exporting-reports)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Clone and enter the project
git clone <repo-url>
cd Threat-Model-Assistant

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your API key
cp .env.example .env            # or create .env manually
# Edit .env and set at least one API key (see Configuration below)

# 5. Run
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Supported LLM Providers

| Provider | API Key Variable | Default Model | Notes |
|----------|-----------------|---------------|-------|
| **Google Gemini** | `GEMINI_API_KEY` | `gemini-2.5-flash` | Fast, cost-effective, good results |
| **Anthropic Claude** | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` | Excellent reasoning, detailed threats |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o` | Strong general-purpose analysis |

You only need **one** API key. If multiple are set, use `LLM_PROVIDER` in `.env` to pick which one:

```env
LLM_PROVIDER=gemini          # or: anthropic, openai
GEMINI_API_KEY=your-key-here
```

If `LLM_PROVIDER` is not set, the app auto-detects in order: Gemini > OpenAI > Anthropic.

---

## The 7-Step Wizard

The app guides you through a 7-step wizard to build a threat model:

### Step 1: Describe Your System
- **Application Name** (required): A clear, descriptive name.
- **System Description** (required): What the system does, who uses it, what data it handles.
- **System Domain**: Choose a specialized security domain for domain-specific threat expertise (see [Domain Expertise](#domain-expertise-modes)).
- **Architecture Template**: Pick a pre-built template (Web App, REST API, Microservices, Mobile, Cloud) to auto-populate components, data flows, and trust boundaries.

### Step 2: Deep Context (Crown Jewels, Workflows, Roles)
This is the **most important step** for quality results. See [How to Get the Best Results](#how-to-get-the-best-results).

- **Crown Jewels**: Your most critical assets — what would cause maximum damage if compromised.
- **Business Workflows**: Step-by-step descriptions of critical processes.
- **User Roles & Permissions**: Who interacts with the system and what they can do.

### Step 3: Architecture Details
- **Technology Stack**: Add specific technologies (languages, databases, frameworks, cloud providers).
- **Authentication Mechanisms**: Select what auth methods the system uses.
- **Existing Security Controls**: Check what's already in place (WAF, encryption, RBAC, etc.).
- **Data Sensitivity**: Public, Internal, Confidential, or Restricted.
- **Network Exposure**: Internal Only, VPN, or Internet-Facing.

### Step 4: Data Flows & Trust Boundaries
- **Components**: System components (auto-filled from templates, or add custom ones).
- **Data Flows**: How data moves between components (source, destination, data type, protocol).
- **Trust Boundaries**: Where trust levels change (e.g., Internet ↔ DMZ ↔ Internal Network).

### Step 5: AI Analysis
The LLM analyzes your system in real-time with streaming output. You'll see a live terminal showing the analysis progress.

### Step 6: Threat Review & DREAD Scoring
Review all identified threats. Each threat shows:
- STRIDE category with color coding
- Detailed attack scenario
- DREAD risk scores (adjustable)
- Recommended mitigations with security standard references

You can **adjust DREAD scores** if you disagree with the AI's assessment, and **remove irrelevant threats**.

### Step 7: Report Export
Download your completed threat model as:
- **Markdown** (.md) — great for version control and wikis
- **HTML** — styled dark-mode report, print-friendly

---

## How to Get the Best Results

The quality of your threat model depends directly on the quality of input you provide. Here's how to maximize the value:

### 1. Write a Detailed System Description

**Bad:**
> "An e-commerce website"

**Good:**
> "A B2C e-commerce platform that processes 50K orders/month. Customers browse products, add to cart, and pay with credit cards via Stripe integration. Admins manage inventory, pricing, and customer support tickets through a separate admin panel. The system stores PII (names, addresses, emails) and delegates payment processing to Stripe (no card data stored locally). Backend runs on AWS ECS with PostgreSQL RDS."

The description should answer: **What does it do? Who uses it? What sensitive data does it handle? Where is it deployed?**

### 2. Always Define Crown Jewels

Crown Jewels are the critical assets that attackers want most. The AI prioritizes threats against these.

| Asset | Why Critical | Location |
|-------|-------------|----------|
| Customer PII database | Contains 500K customer records, GDPR regulated | PostgreSQL RDS in private subnet |
| Stripe API secret key | Allows arbitrary charges and refunds | AWS Secrets Manager |
| Admin session tokens | Full access to inventory and customer data | Redis cache |
| Order transaction records | Financial audit trail, SOX compliance | PostgreSQL + S3 archives |

### 3. Describe Business Workflows Step-by-Step

Don't just say "checkout process." Break it down:

> **Checkout Workflow:**
> Actors: Customer, Payment Service, Inventory Service, Email Service
> Steps: Customer adds items to cart → Enters shipping address → Selects payment method → Frontend sends order to backend API → Backend validates inventory availability → Backend creates payment intent with Stripe → Stripe processes card → On success, backend decrements inventory → Backend creates order record → Email service sends confirmation

The AI will analyze **each step** for abuse potential (e.g., can inventory be decremented without payment? Can the payment amount be modified client-side?).

### 4. Define User Roles with Permissions

> **Customer** (Trust: Low) — Browse products, manage own profile, place orders, view own order history
>
> **Support Agent** (Trust: Medium) — View customer profiles, process refunds up to $100, access support tickets
>
> **Admin** (Trust: High) — Full inventory management, pricing changes, user management, view all orders
>
> **Service Account: Payment Worker** (Trust: Internal) — Process payment callbacks, update order status

### 5. Add All Real Data Flows

Template data flows are generic. Customize them to reflect your actual system:

| Source | Destination | Data | Protocol |
|--------|-------------|------|----------|
| Browser | API Gateway | Auth tokens + user requests | HTTPS |
| API Gateway | Auth Service | JWT validation | gRPC |
| Order Service | Stripe API | Payment intents + amounts | HTTPS |
| Order Service | PostgreSQL | Order records + customer data | TLS/TCP |
| PostgreSQL | S3 | Nightly backup dumps | HTTPS |

### 6. Mark Trust Boundaries Accurately

Trust boundaries are where the security context changes. Every boundary is a potential attack surface:

- **Internet ↔ CDN/Load Balancer**: External users hit your perimeter
- **DMZ ↔ Application Tier**: Public-facing services access internal services
- **Application ↔ Database**: App layer accesses sensitive data stores
- **Your Infrastructure ↔ Third-party APIs**: Data leaves your control

### 7. Select the Right Domain

If your system falls into a specialized domain, selecting it gives the AI expert knowledge about domain-specific threats that generic analysis would miss:

- **PKI/CA** — Knows about key ceremony attacks, unauthorized certificate issuance, HSM bypass
- **Payment/PCI** — Knows about cardholder data leaks, BIN attacks, PCI DSS scoping issues
- **Healthcare/HIPAA** — Knows about PHI exposure, break-glass access abuse, audit log tampering
- **IAM/Identity** — Knows about SAML assertion forgery, token replay, consent phishing
- **Cloud/SaaS** — Knows about tenant escape, SSRF to metadata services, CI/CD poisoning
- **IoT/Embedded** — Knows about firmware extraction, debug port access, replay attacks

---

## Understanding the Output

### STRIDE Categories

Each threat is classified into one of six categories:

| Category | Security Property | What It Means |
|----------|-------------------|---------------|
| **Spoofing** | Authentication | Impersonating a user or component |
| **Tampering** | Integrity | Unauthorized modification of data or code |
| **Repudiation** | Non-repudiation | Denying actions without proof |
| **Information Disclosure** | Confidentiality | Data exposed to unauthorized parties |
| **Denial of Service** | Availability | Making systems unavailable |
| **Elevation of Privilege** | Authorization | Gaining access beyond intended permissions |

### DREAD Risk Scores

Each threat gets a 1-10 score on five factors:

| Factor | Question |
|--------|----------|
| **D**amage | How severe would the impact be? |
| **R**eproducibility | How consistently can this be exploited? |
| **E**xploitability | How much skill/tooling is needed? |
| **A**ffected Users | How many users/systems impacted? |
| **D**iscoverability | How easy is it to find this vulnerability? |

The **overall score** is the average of all five factors.

| Score Range | Risk Level |
|-------------|------------|
| 9.0 - 10.0 | Critical |
| 7.0 - 8.9 | High |
| 4.0 - 6.9 | Medium |
| 1.0 - 3.9 | Low |

You can manually adjust any DREAD score in Step 6 if the AI's assessment doesn't match your judgment.

---

## Domain Expertise Modes

| Domain | Key | Best For |
|--------|-----|----------|
| General | `general` | Any system without a specialized domain |
| PKI / CA | `pki_ca` | Certificate authorities, key management, HSM systems |
| Payment / PCI | `payment` | Payment gateways, card processing, PCI DSS scoped systems |
| IAM / Identity | `iam_identity` | SSO, federation, directory services, access management |
| Healthcare / HIPAA | `healthcare` | EHR/EMR, patient portals, clinical systems, PHI handling |
| Cloud / SaaS | `cloud_saas` | Multi-tenant platforms, cloud-native infrastructure |
| IoT / Embedded | `iot_embedded` | Connected devices, firmware, industrial control systems |

---

## Architecture Templates

Pre-built templates to jumpstart your analysis:

| Template | Components | Use When |
|----------|-----------|----------|
| **Web Application** | Browser, Load Balancer, Web Server, App Server, Database, Cache | Traditional web apps |
| **REST API Service** | API Client, Gateway, Auth Service, Business Logic, DB, Message Queue | API-first backends |
| **Microservices** | Client, Gateway, Services A/B/C, Event Bus, Databases, Registry | Distributed systems |
| **Mobile Application** | Mobile App, CDN, API Server, Auth Provider, DB, Push Service | iOS/Android apps |
| **Cloud Infrastructure** | Users, IdP, VPN, VPC, Compute, Storage, Database, Logging | Cloud environments |

Templates pre-fill components, data flows, and trust boundaries. You should **customize them** to match your actual system — the defaults are starting points.

---

## Exporting Reports

### Markdown Report
Best for: Git repos, wikis, Confluence, documentation systems. Contains:
- Executive summary with risk statistics
- Full system description
- All threats organized by STRIDE category
- DREAD score tables with reasoning
- Mitigation recommendations with standard references
- Risk matrix sorted by severity

### HTML Report
Best for: Sharing with stakeholders, printing, presentations. Same content as Markdown but with:
- Professional dark-mode styling
- Print-friendly CSS (switches to light theme when printing)
- Risk level color coding

---

## Configuration Reference

### `.env` File

```env
# LLM Provider (optional — auto-detects if not set)
LLM_PROVIDER=gemini              # gemini | anthropic | openai

# API Keys (set at least one)
GEMINI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key
OPENAI_API_KEY=your-key

# Model Override (optional — uses sensible defaults)
GEMINI_MODEL=gemini-2.5-flash
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_MODEL=gpt-4o

# Server (optional)
FLASK_PORT=5000
FLASK_DEBUG=true
```

### Model Recommendations

| Use Case | Recommended Model |
|----------|-------------------|
| Fast iteration / testing | `gemini-2.5-flash` |
| Production threat models | `claude-sonnet-4-6` or `gpt-4o` |
| Maximum depth | `claude-opus-4-6` |
| Budget-conscious | `gemini-2.5-flash` or `claude-haiku-4-5` |

---

## Troubleshooting

### "No LLM configured"
At least one API key must be set in `.env`. Verify:
1. The `.env` file exists in the project root
2. The key is **not** commented out (no `#` prefix)
3. The key is valid (test it with `curl` or the provider's playground)

### "LLM response could not be parsed as JSON"
The LLM returned text that wasn't valid JSON. This can happen when:
- The response was too long and got truncated — the app attempts to repair truncated JSON, but it doesn't always work
- The model returned markdown-wrapped JSON — the app strips code fences, but unusual formatting may fail
- Try running the analysis again — LLM outputs are non-deterministic

### Streaming errors / "Stream closed before completion"
- Check your internet connection
- Some models take longer — the request may have timed out
- Try a faster model (`gemini-2.5-flash`)

### Provider is stuck on the wrong model
If you set `LLM_PROVIDER=gemini` but the log still shows Anthropic:
1. Make sure you saved the `.env` file
2. **Restart the Flask server** — env vars are loaded at startup
3. Check that `LLM_PROVIDER` is not set to a different value elsewhere

### "ModuleNotFoundError" on startup
```bash
pip install -r requirements.txt
```
If using a specific provider, ensure its SDK is installed:
- Gemini: `pip install google-genai`
- Anthropic: `pip install anthropic`
- OpenAI: `pip install openai`

---

## Project Structure

```
Threat-Model-Assistant/
├── app.py                    # Flask app, API routes, session management
├── engine/
│   ├── threat_model.py       # Core data models (Threat, DREADScore, SystemInfo)
│   ├── llm_client.py         # Multi-provider LLM client (Anthropic/OpenAI/Gemini)
│   ├── stride.py             # STRIDE analysis engine, prompt builder
│   ├── dread.py              # DREAD scoring and risk aggregation
│   └── report.py             # Markdown and HTML report generator
├── prompts/
│   └── templates.py          # System prompts, analysis prompts, domain expertise
├── templates/
│   └── index.html            # Single-page wizard UI
├── static/
│   ├── js/app.js             # Frontend logic
│   └── css/style.css         # Dark-mode styling
├── requirements.txt
└── .env                      # Your API keys (not committed)
```

---

## Methodology

This tool implements the **OWASP Threat Modeling Process**:

1. **Decompose** — Break down the system into components, data flows, and trust boundaries
2. **Identify Threats** — Use STRIDE to systematically find threats per component
3. **Score Risks** — Use DREAD to quantify and prioritize each threat
4. **Mitigate** — Recommend countermeasures based on industry standards (OWASP ASVS, NIST 800-53, CIS Controls)

The AI performs a **3-phase analysis**:
- **Phase 1**: Threats to crown jewels (critical assets)
- **Phase 2**: Business logic abuse (workflow manipulation)
- **Phase 3**: Architectural threats (trust boundary violations, protocol attacks)

---

## License

MIT
