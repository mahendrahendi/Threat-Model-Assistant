"""
Report Generator — Creates professional threat model reports in Markdown and HTML.
Produces stakeholder-ready output with executive summary, risk matrix, and full analysis.
"""

from datetime import datetime
from engine.threat_model import STRIDE_CATEGORIES
from engine.dread import aggregate_risk_summary


def generate_markdown_report(threat_model):
    """Generate a full threat model report in Markdown format."""
    sys = threat_model.system_info
    threats = threat_model.threats
    summary = aggregate_risk_summary(threats)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = []

    # Header
    lines.append(f"# Threat Model Report: {sys.name}")
    lines.append(f"")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Methodology:** OWASP Threat Modeling Process + STRIDE + DREAD")
    lines.append(f"**Tool:** AI Threat Modeling Assistant v1.0")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Executive Summary
    lines.append(f"## Executive Summary")
    lines.append(f"")
    lines.append(f"This threat model analyzes **{sys.name}** — {sys.description}")
    lines.append(f"")
    lines.append(f"### Risk Overview")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Threats Identified | **{summary['total_threats']}** |")
    lines.append(f"| Average Risk Score | **{summary['average_score']}/10** |")
    lines.append(f"| Critical Threats | **{summary['by_risk_level']['Critical']}** 🔴 |")
    lines.append(f"| High Threats | **{summary['by_risk_level']['High']}** 🟠 |")
    lines.append(f"| Medium Threats | **{summary['by_risk_level']['Medium']}** 🟡 |")
    lines.append(f"| Low Threats | **{summary['by_risk_level']['Low']}** 🟢 |")
    lines.append(f"")

    if summary.get("highest_risk"):
        hr = summary["highest_risk"]
        lines.append(f"**Highest Risk:** {hr['title']} (Score: {hr['dread_score']['overall']}/10 — {hr['dread_score']['risk_level']})")
        lines.append(f"")

    # System Description
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## System Under Analysis")
    lines.append(f"")
    lines.append(f"| Property | Details |")
    lines.append(f"|----------|---------|")
    lines.append(f"| **Name** | {sys.name} |")
    lines.append(f"| **Architecture** | {sys.architecture_type} |")
    lines.append(f"| **Tech Stack** | {', '.join(sys.tech_stack) if sys.tech_stack else 'Not specified'} |")
    lines.append(f"| **Authentication** | {', '.join(sys.authentication) if sys.authentication else 'Not specified'} |")
    lines.append(f"| **Data Sensitivity** | {sys.data_sensitivity} |")
    lines.append(f"| **Network Exposure** | {sys.network_exposure} |")
    lines.append(f"| **Existing Controls** | {', '.join(sys.existing_controls) if sys.existing_controls else 'None specified'} |")
    lines.append(f"")

    # Components
    if sys.components:
        lines.append(f"### Components")
        lines.append(f"")
        for comp in sys.components:
            lines.append(f"- {comp}")
        lines.append(f"")

    # Data Flows
    if sys.data_flows:
        lines.append(f"### Data Flows")
        lines.append(f"")
        lines.append(f"| # | Source | Destination | Data | Protocol |")
        lines.append(f"|---|--------|-------------|------|----------|")
        for i, flow in enumerate(sys.data_flows, 1):
            lines.append(f"| {i} | {flow.get('source', '')} | {flow.get('destination', '')} | {flow.get('data', '')} | {flow.get('protocol', '')} |")
        lines.append(f"")

    # Trust Boundaries
    if sys.trust_boundaries:
        lines.append(f"### Trust Boundaries")
        lines.append(f"")
        for tb in sys.trust_boundaries:
            lines.append(f"- **{tb.get('name', '')}**: Outside [{', '.join(tb.get('outside', []))}] → Inside [{', '.join(tb.get('inside', []))}]")
        lines.append(f"")

    # STRIDE Analysis
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## STRIDE Threat Analysis")
    lines.append(f"")

    categorized = threat_model.get_threats_by_category()
    for category, cat_info in STRIDE_CATEGORIES.items():
        cat_threats = categorized.get(category, [])
        lines.append(f"### {cat_info['icon']} {category} — {cat_info['property']}")
        lines.append(f"*{cat_info['description']}*")
        lines.append(f"")

        if not cat_threats:
            lines.append(f"No threats identified in this category.")
            lines.append(f"")
            continue

        for t in cat_threats:
            dread = t.dread_score
            lines.append(f"#### {t.title}")
            lines.append(f"")
            lines.append(f"- **Risk Level:** {dread.risk_level} ({dread.overall}/10)")
            lines.append(f"- **Affected Component:** {t.affected_component}")
            lines.append(f"- **Description:** {t.description}")
            lines.append(f"")
            lines.append(f"**Attack Scenario:**")
            lines.append(f"> {t.attack_scenario}")
            lines.append(f"")

            if t.prerequisites:
                lines.append(f"**Prerequisites:**")
                for p in t.prerequisites:
                    lines.append(f"- {p}")
                lines.append(f"")

            lines.append(f"**DREAD Score:**")
            lines.append(f"")
            lines.append(f"| Factor | Score | Description |")
            lines.append(f"|--------|-------|-------------|")
            reasoning = dread.reasoning if dread.reasoning else {}
            lines.append(f"| Damage | {dread.damage}/10 | {reasoning.get('damage', '')} |")
            lines.append(f"| Reproducibility | {dread.reproducibility}/10 | {reasoning.get('reproducibility', '')} |")
            lines.append(f"| Exploitability | {dread.exploitability}/10 | {reasoning.get('exploitability', '')} |")
            lines.append(f"| Affected Users | {dread.affected_users}/10 | {reasoning.get('affected_users', '')} |")
            lines.append(f"| Discoverability | {dread.discoverability}/10 | {reasoning.get('discoverability', '')} |")
            lines.append(f"| **Overall** | **{dread.overall}/10** | **{dread.risk_level}** |")
            lines.append(f"")

            if t.mitigations:
                lines.append(f"**Recommended Mitigations:**")
                for m in t.mitigations:
                    lines.append(f"1. {m}")
                lines.append(f"")

            if t.references:
                lines.append(f"**References:** {', '.join(t.references)}")
                lines.append(f"")

            lines.append(f"---")
            lines.append(f"")

    # Risk Matrix
    lines.append(f"## Risk Matrix Summary")
    lines.append(f"")
    lines.append(f"| # | Threat | Category | Risk Level | DREAD Score | Affected Component |")
    lines.append(f"|---|--------|----------|------------|-------------|--------------------|")

    sorted_threats = sorted(threats, key=lambda t: t.dread_score.overall, reverse=True)
    for i, t in enumerate(sorted_threats, 1):
        lines.append(f"| {i} | {t.title} | {t.category} | {t.dread_score.risk_level} | {t.dread_score.overall}/10 | {t.affected_component} |")
    lines.append(f"")

    # Methodology Appendix
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Appendix: Methodology")
    lines.append(f"")
    lines.append(f"### OWASP Threat Modeling Process")
    lines.append(f"This analysis follows the four-step OWASP threat modeling process:")
    lines.append(f"1. **Decompose** — Understand the system architecture, data flows, and trust boundaries")
    lines.append(f"2. **Identify Threats** — Use STRIDE to systematically identify threats per component")
    lines.append(f"3. **Score Risks** — Use DREAD to quantify and prioritize each threat")
    lines.append(f"4. **Mitigate** — Recommend countermeasures based on industry standards")
    lines.append(f"")
    lines.append(f"### STRIDE Categories")
    lines.append(f"| Category | Security Property | Description |")
    lines.append(f"|----------|-------------------|-------------|")
    for cat, info in STRIDE_CATEGORIES.items():
        lines.append(f"| {info['icon']} {cat} | {info['property']} | {info['description']} |")
    lines.append(f"")
    lines.append(f"### DREAD Scoring")
    lines.append(f"Each threat is scored on five factors (1-10 scale):")
    lines.append(f"- **D**amage — How severe is the impact?")
    lines.append(f"- **R**eproducibility — How easy to replicate?")
    lines.append(f"- **E**xploitability — How easy to exploit?")
    lines.append(f"- **A**ffected Users — How many impacted?")
    lines.append(f"- **D**iscoverability — How easy to find?")
    lines.append(f"")
    lines.append(f"**Risk Levels:** Critical (≥9) | High (≥7) | Medium (≥4) | Low (<4)")

    return "\n".join(lines)


def generate_html_report(threat_model):
    """Generate a styled HTML threat model report."""
    md_content = generate_markdown_report(threat_model)

    # Convert key markdown elements to HTML
    html_body = _md_to_html(md_content)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Model Report — {threat_model.system_info.name}</title>
    <style>
        :root {{
            --bg-primary: #0a0e27;
            --bg-secondary: #151937;
            --bg-card: #1a1f3d;
            --text-primary: #e8e8f0;
            --text-secondary: #8b8fa3;
            --accent: #00d4ff;
            --critical: #ff0040;
            --high: #ff4757;
            --medium: #ffa502;
            --low: #2ed573;
            --border: #2a2f52;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Inter, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.7;
            padding: 2rem;
            max-width: 1100px;
            margin: 0 auto;
        }}
        h1 {{ 
            color: var(--accent); 
            font-size: 2rem; 
            margin: 1.5rem 0 0.5rem; 
            border-bottom: 2px solid var(--accent);
            padding-bottom: 0.5rem;
        }}
        h2 {{ 
            color: var(--accent); 
            font-size: 1.5rem; 
            margin: 2rem 0 0.8rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem;
        }}
        h3 {{ color: #c8cadc; font-size: 1.2rem; margin: 1.5rem 0 0.5rem; }}
        h4 {{ color: #a8aabf; font-size: 1.1rem; margin: 1.2rem 0 0.4rem; }}
        p {{ margin: 0.5rem 0; color: var(--text-secondary); }}
        strong {{ color: var(--text-primary); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: var(--bg-secondary);
            color: var(--accent);
            text-align: left;
            padding: 0.7rem 1rem;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.6rem 1rem;
            border-top: 1px solid var(--border);
            font-size: 0.9rem;
        }}
        tr:hover td {{ background: rgba(0, 212, 255, 0.03); }}
        blockquote {{
            border-left: 3px solid var(--accent);
            padding: 0.8rem 1.2rem;
            margin: 0.8rem 0;
            background: var(--bg-secondary);
            border-radius: 0 6px 6px 0;
            color: var(--text-secondary);
            font-style: italic;
        }}
        ul, ol {{ padding-left: 1.5rem; margin: 0.5rem 0; }}
        li {{ margin: 0.3rem 0; color: var(--text-secondary); }}
        hr {{
            border: none;
            border-top: 1px solid var(--border);
            margin: 2rem 0;
        }}
        code {{ 
            background: var(--bg-secondary); 
            padding: 0.15rem 0.4rem; 
            border-radius: 4px; 
            font-size: 0.85rem;
            color: var(--accent);
        }}
        .risk-critical {{ color: var(--critical); font-weight: 700; }}
        .risk-high {{ color: var(--high); font-weight: 700; }}
        .risk-medium {{ color: var(--medium); font-weight: 700; }}
        .risk-low {{ color: var(--low); font-weight: 700; }}
        @media print {{
            body {{ background: white; color: #333; padding: 1rem; }}
            table {{ background: #f8f9fa; }}
            th {{ background: #e9ecef; color: #333; }}
            td {{ border-color: #dee2e6; }}
            h1, h2 {{ color: #0066cc; }}
            blockquote {{ background: #f8f9fa; border-color: #0066cc; }}
        }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""
    return html


def _md_to_html(md):
    """Simple markdown to HTML converter for report output."""
    import re

    lines = md.split('\n')
    html_lines = []
    in_table = False
    in_list = False
    in_blockquote = False

    for line in lines:
        stripped = line.strip()

        # Horizontal rule
        if stripped == '---':
            if in_table:
                html_lines.append('</table>')
                in_table = False
            if in_list:
                html_lines.append('</ul>')
                in_list = False
            html_lines.append('<hr>')
            continue

        # Headers
        if stripped.startswith('#### '):
            html_lines.append(f'<h4>{_inline_md(stripped[5:])}</h4>')
            continue
        if stripped.startswith('### '):
            html_lines.append(f'<h3>{_inline_md(stripped[4:])}</h3>')
            continue
        if stripped.startswith('## '):
            html_lines.append(f'<h2>{_inline_md(stripped[3:])}</h2>')
            continue
        if stripped.startswith('# '):
            html_lines.append(f'<h1>{_inline_md(stripped[2:])}</h1>')
            continue

        # Table
        if '|' in stripped and stripped.startswith('|'):
            cells = [c.strip() for c in stripped.split('|')[1:-1]]
            if all(c.replace('-', '').replace(':', '') == '' for c in cells):
                continue  # separator row
            if not in_table:
                html_lines.append('<table>')
                tag = 'th'
                in_table = True
            else:
                tag = 'td'
            row = ''.join(f'<{tag}>{_inline_md(c)}</{tag}>' for c in cells)
            html_lines.append(f'<tr>{row}</tr>')
            continue
        elif in_table:
            html_lines.append('</table>')
            in_table = False

        # Blockquote
        if stripped.startswith('> '):
            if not in_blockquote:
                html_lines.append('<blockquote>')
                in_blockquote = True
            html_lines.append(f'<p>{_inline_md(stripped[2:])}</p>')
            continue
        elif in_blockquote:
            html_lines.append('</blockquote>')
            in_blockquote = False

        # List items
        if stripped.startswith('- ') or stripped.startswith('* '):
            if not in_list:
                html_lines.append('<ul>')
                in_list = True
            html_lines.append(f'<li>{_inline_md(stripped[2:])}</li>')
            continue
        if re.match(r'^\d+\.\s', stripped):
            if not in_list:
                html_lines.append('<ol>')
                in_list = True
            content = re.sub(r'^\d+\.\s', '', stripped)
            html_lines.append(f'<li>{_inline_md(content)}</li>')
            continue
        elif in_list:
            if html_lines and '<ol>' in ''.join(html_lines[-5:]):
                html_lines.append('</ol>')
            else:
                html_lines.append('</ul>')
            in_list = False

        # Paragraph
        if stripped:
            html_lines.append(f'<p>{_inline_md(stripped)}</p>')
        else:
            html_lines.append('')

    # Close any open tags
    if in_table:
        html_lines.append('</table>')
    if in_list:
        html_lines.append('</ul>')
    if in_blockquote:
        html_lines.append('</blockquote>')

    return '\n'.join(html_lines)


def _inline_md(text):
    """Convert inline markdown (bold, italic, code, links)."""
    import re
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    # Code
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    # Risk level highlighting
    text = text.replace('🔴', '<span class="risk-critical">🔴</span>')
    text = text.replace('🟠', '<span class="risk-high">🟠</span>')
    text = text.replace('🟡', '<span class="risk-medium">🟡</span>')
    text = text.replace('🟢', '<span class="risk-low">🟢</span>')
    return text
