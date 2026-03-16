"""
STRIDE Threat Analysis Engine.
Generates contextual threats per component/data flow using LLM.
"""

from engine.threat_model import Threat, DREADScore, STRIDE_CATEGORIES
from engine.llm_client import LLMClient
from prompts.templates import SYSTEM_PROMPT, ANALYZE_THREATS_PROMPT


def _format_data_flows(data_flows):
    if not data_flows:
        return "No data flows defined"
    lines = []
    for i, flow in enumerate(data_flows, 1):
        src = flow.get("source", "Unknown")
        dst = flow.get("destination", "Unknown")
        data = flow.get("data", "Unknown data")
        proto = flow.get("protocol", "Unknown")
        lines.append(f"  {i}. {src} → {dst} | Data: {data} | Protocol: {proto}")
    return "\n".join(lines)


def _format_trust_boundaries(boundaries):
    if not boundaries:
        return "No trust boundaries defined"
    lines = []
    for i, tb in enumerate(boundaries, 1):
        name = tb.get("name", "Unknown")
        outside = ", ".join(tb.get("outside", []))
        inside = ", ".join(tb.get("inside", []))
        lines.append(f"  {i}. [{name}] Outside: {outside} | Inside: {inside}")
    return "\n".join(lines)


def _format_components(components):
    if not components:
        return "No components defined"
    return ", ".join(components)


def _format_crown_jewels(crown_jewels):
    if not crown_jewels:
        return "No critical assets explicitly identified"
    lines = []
    for i, cj in enumerate(crown_jewels, 1):
        name = cj.get("name", "Unknown")
        why = cj.get("why_critical", "")
        location = cj.get("location", "")
        lines.append(f"  {i}. {name} — Why critical: {why} | Located in: {location}")
    return "\n".join(lines)


def _format_business_workflows(workflows):
    if not workflows:
        return "No business workflows described"
    lines = []
    for i, wf in enumerate(workflows, 1):
        name = wf.get("name", "Unknown workflow")
        steps = wf.get("steps", "")
        actors = wf.get("actors", "")
        lines.append(f"  {i}. [{name}]\n     Actors: {actors}\n     Steps: {steps}")
    return "\n".join(lines)


def _format_user_roles(roles):
    if not roles:
        return "No user roles described"
    lines = []
    for i, role in enumerate(roles, 1):
        name = role.get("name", "Unknown")
        permissions = role.get("permissions", "")
        trust_level = role.get("trust_level", "")
        lines.append(f"  {i}. {name} (Trust: {trust_level}) — Permissions: {permissions}")
    return "\n".join(lines)


def _build_prompts(system_info):
    from prompts.templates import DOMAIN_EXPERTISE
    domain = getattr(system_info, 'domain', 'general') or 'general'
    domain_info = DOMAIN_EXPERTISE.get(domain, DOMAIN_EXPERTISE["general"])
    domain_context = domain_info.get("context", "")

    # Build domain-aware system prompt
    system_prompt = SYSTEM_PROMPT.format(domain_expertise=domain_context)

    # Build the prompt with system details + deep context
    prompt = ANALYZE_THREATS_PROMPT.format(
        name=system_info.name,
        description=system_info.description,
        architecture_type=system_info.architecture_type,
        tech_stack=", ".join(system_info.tech_stack) if system_info.tech_stack else "Not specified",
        authentication=", ".join(system_info.authentication) if system_info.authentication else "Not specified",
        data_sensitivity=system_info.data_sensitivity,
        network_exposure=system_info.network_exposure,
        existing_controls=", ".join(system_info.existing_controls) if system_info.existing_controls else "None specified",
        components=_format_components(system_info.components),
        data_flows=_format_data_flows(system_info.data_flows),
        trust_boundaries=_format_trust_boundaries(system_info.trust_boundaries),
        crown_jewels=_format_crown_jewels(getattr(system_info, 'crown_jewels', [])),
        business_workflows=_format_business_workflows(getattr(system_info, 'business_workflows', [])),
        user_roles=_format_user_roles(getattr(system_info, 'user_roles', []))
    )
    return system_prompt, prompt


def analyze_threats_with_llm(system_info, llm_client):
    """
    Use LLM to generate STRIDE threats for the given system.
    Raises RuntimeError if LLM is unavailable or response cannot be parsed.
    """
    if not llm_client or not llm_client.is_available:
        raise RuntimeError("LLM not connected. Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.")

    system_prompt, prompt = _build_prompts(system_info)

    result, raw_response = llm_client.generate_json(system_prompt, prompt, temperature=0.3, max_tokens=16384)

    if result and "threats" in result:
        threats = []
        for t_data in result["threats"]:
            # Validate STRIDE category
            category = t_data.get("category", "")
            if category not in STRIDE_CATEGORIES:
                for valid_cat in STRIDE_CATEGORIES:
                    if valid_cat.lower() in category.lower():
                        category = valid_cat
                        break
                else:
                    category = "Information Disclosure"  # default

            dread_data = t_data.get("dread_score", {})
            dread = DREADScore(
                damage=dread_data.get("damage", 5),
                reproducibility=dread_data.get("reproducibility", 5),
                exploitability=dread_data.get("exploitability", 5),
                affected_users=dread_data.get("affected_users", 5),
                discoverability=dread_data.get("discoverability", 5),
                reasoning=dread_data.get("reasoning", {})
            )

            threat = Threat(
                title=t_data.get("title", "Unnamed Threat"),
                category=category,
                description=t_data.get("description", ""),
                attack_scenario=t_data.get("attack_scenario", ""),
                affected_component=t_data.get("affected_component", ""),
                prerequisites=t_data.get("prerequisites", []),
                mitigations=t_data.get("mitigations", []),
                references=t_data.get("references", []),
                dread_score=dread
            )
            threats.append(threat)
        return threats, f"{system_prompt}\n\n---\n\n{prompt}", raw_response

    raise RuntimeError("LLM returned a response that could not be parsed. Please try again.")
