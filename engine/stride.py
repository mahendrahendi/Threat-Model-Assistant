"""
STRIDE Threat Analysis Engine.
Generates contextual threats per component/data flow using LLM + fallback templates.
"""

from engine.threat_model import Threat, DREADScore, STRIDE_CATEGORIES
from engine.llm_client import LLMClient
from prompts.templates import SYSTEM_PROMPT, ANALYZE_THREATS_PROMPT


# Fallback threat templates when LLM is unavailable
FALLBACK_THREATS = {
    "Spoofing": [
        {
            "title": "Authentication Bypass via Credential Stuffing",
            "description": "Attacker uses leaked credentials from other breaches to gain unauthorized access to user accounts.",
            "attack_scenario": "1. Attacker obtains credential dump from dark web. 2. Uses automated tools to test credentials against login endpoint. 3. Successfully authenticates as legitimate user due to password reuse.",
            "prerequisites": ["Access to leaked credential databases", "No rate limiting on login endpoint"],
            "mitigations": [
                "Implement rate limiting on authentication endpoints (OWASP ASVS V2.2.1)",
                "Enforce multi-factor authentication (NIST 800-63B)",
                "Deploy credential breach detection (e.g., HaveIBeenPwned API integration)",
                "Implement account lockout after failed attempts"
            ],
            "references": ["OWASP ASVS V2.2.1", "NIST 800-63B", "CWE-307"],
            "dread": {"damage": 8, "reproducibility": 7, "exploitability": 7, "affected_users": 6, "discoverability": 5}
        },
        {
            "title": "Session Token Hijacking",
            "description": "Attacker steals or forges session tokens to impersonate authenticated users.",
            "attack_scenario": "1. Attacker intercepts session token via XSS or network sniffing. 2. Replays token to gain authenticated access. 3. Performs actions as the victim user.",
            "prerequisites": ["XSS vulnerability or network access", "Predictable or long-lived session tokens"],
            "mitigations": [
                "Set Secure, HttpOnly, SameSite flags on session cookies (OWASP ASVS V3.4)",
                "Implement session timeout and rotation",
                "Bind sessions to client fingerprint (IP, User-Agent)",
                "Use short-lived tokens with refresh mechanism"
            ],
            "references": ["OWASP ASVS V3.4", "CWE-384", "CWE-614"],
            "dread": {"damage": 8, "reproducibility": 6, "exploitability": 5, "affected_users": 7, "discoverability": 4}
        }
    ],
    "Tampering": [
        {
            "title": "API Parameter Manipulation",
            "description": "Attacker modifies API request parameters to alter business logic or access unauthorized data.",
            "attack_scenario": "1. Attacker intercepts API request using proxy (e.g., Burp Suite). 2. Modifies parameters like user_id, price, or role. 3. Server processes tampered request without proper validation.",
            "prerequisites": ["Knowledge of API structure", "Ability to intercept/modify HTTP requests"],
            "mitigations": [
                "Implement server-side input validation for all parameters (OWASP ASVS V5.1)",
                "Use HMAC signatures for critical API parameters",
                "Implement proper authorization checks — never trust client-side data",
                "Log and alert on parameter tampering attempts"
            ],
            "references": ["OWASP ASVS V5.1", "CWE-20", "CWE-639"],
            "dread": {"damage": 7, "reproducibility": 8, "exploitability": 7, "affected_users": 5, "discoverability": 6}
        },
        {
            "title": "Database Injection via Unsanitized Input",
            "description": "Attacker injects malicious SQL/NoSQL queries through application inputs to modify or extract data.",
            "attack_scenario": "1. Attacker identifies input field connected to database query. 2. Crafts injection payload (e.g., SQL UNION, NoSQL $gt operator). 3. Application executes injected query, exposing or modifying data.",
            "prerequisites": ["Input fields that interact with database", "Insufficient input sanitization"],
            "mitigations": [
                "Use parameterized queries / prepared statements exclusively (OWASP ASVS V5.3.4)",
                "Implement ORM with proper escaping",
                "Apply least-privilege database accounts",
                "Deploy WAF rules for injection patterns"
            ],
            "references": ["OWASP ASVS V5.3.4", "CWE-89", "CWE-943"],
            "dread": {"damage": 9, "reproducibility": 7, "exploitability": 6, "affected_users": 9, "discoverability": 6}
        }
    ],
    "Repudiation": [
        {
            "title": "Insufficient Audit Logging for Critical Actions",
            "description": "System lacks comprehensive audit trails, allowing users or attackers to deny performing critical actions.",
            "attack_scenario": "1. Insider or attacker performs unauthorized data modification. 2. No immutable audit log captures the action with user identity and timestamp. 3. Investigation cannot attribute the action to any individual.",
            "prerequisites": ["Access to perform critical actions", "Weak or absent logging"],
            "mitigations": [
                "Implement comprehensive audit logging for all state-changing operations (OWASP ASVS V7.1)",
                "Store logs in append-only, tamper-evident storage (e.g., WORM storage)",
                "Include user identity, timestamp, source IP, action details in every log entry",
                "Set up log monitoring and alerting for suspicious patterns"
            ],
            "references": ["OWASP ASVS V7.1", "NIST 800-53 AU-2", "CWE-778"],
            "dread": {"damage": 6, "reproducibility": 8, "exploitability": 3, "affected_users": 8, "discoverability": 3}
        }
    ],
    "Information Disclosure": [
        {
            "title": "Sensitive Data Exposure in API Responses",
            "description": "API returns more data than necessary, exposing sensitive fields like internal IDs, emails, or configuration details.",
            "attack_scenario": "1. Attacker inspects API responses using browser dev tools or proxy. 2. Discovers sensitive data in response payloads (e.g., user PII, internal system info). 3. Uses exposed data for further attacks or data harvesting.",
            "prerequisites": ["Access to API endpoints", "API returns verbose responses"],
            "mitigations": [
                "Implement response filtering — only return required fields (OWASP ASVS V8.3)",
                "Use DTOs/serializers to control response shape",
                "Remove debug information, stack traces, and internal IDs from production responses",
                "Implement field-level access control for sensitive attributes"
            ],
            "references": ["OWASP ASVS V8.3", "CWE-200", "CWE-532"],
            "dread": {"damage": 6, "reproducibility": 9, "exploitability": 8, "affected_users": 7, "discoverability": 8}
        },
        {
            "title": "Cryptographic Key/Secret Exposure",
            "description": "Application secrets, API keys, or cryptographic keys are exposed through code repositories, configuration files, or error messages.",
            "attack_scenario": "1. Attacker scans public repositories or accesses configuration files. 2. Finds hardcoded API keys, database credentials, or encryption keys. 3. Uses credentials to access backend systems or decrypt sensitive data.",
            "prerequisites": ["Access to source code, config files, or error output"],
            "mitigations": [
                "Use secrets management solutions (HashiCorp Vault, AWS Secrets Manager)",
                "Never commit secrets to version control — use .gitignore and pre-commit hooks",
                "Rotate secrets regularly and implement secret scanning in CI/CD",
                "Use environment variables for runtime configuration"
            ],
            "references": ["OWASP ASVS V6.4", "CWE-798", "CWE-312"],
            "dread": {"damage": 9, "reproducibility": 6, "exploitability": 8, "affected_users": 9, "discoverability": 5}
        }
    ],
    "Denial of Service": [
        {
            "title": "Resource Exhaustion via Unthrottled API",
            "description": "Attacker floods API endpoints with requests, exhausting server resources and causing service unavailability.",
            "attack_scenario": "1. Attacker identifies resource-intensive API endpoints. 2. Sends high volume of requests using botnets or scripting tools. 3. Server resources (CPU, memory, connections) become exhausted, denying service to legitimate users.",
            "prerequisites": ["Internet-accessible endpoints", "No rate limiting"],
            "mitigations": [
                "Implement rate limiting per user/IP (OWASP ASVS V11.1)",
                "Deploy DDoS protection (CloudFlare, AWS Shield)",
                "Use auto-scaling for critical services",
                "Implement request size limits and timeout configurations"
            ],
            "references": ["OWASP ASVS V11.1", "CWE-400", "NIST 800-53 SC-5"],
            "dread": {"damage": 7, "reproducibility": 9, "exploitability": 8, "affected_users": 9, "discoverability": 7}
        }
    ],
    "Elevation of Privilege": [
        {
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "Attacker manipulates object references (IDs) to access resources belonging to other users or roles.",
            "attack_scenario": "1. Attacker authenticates as regular user. 2. Modifies resource ID in API request (e.g., /api/users/123 → /api/users/456). 3. Gains access to another user's data or admin-level resources due to missing authorization check.",
            "prerequisites": ["Authenticated access", "Predictable resource identifiers"],
            "mitigations": [
                "Implement proper authorization checks on every resource access (OWASP ASVS V4.1)",
                "Use UUIDs instead of sequential IDs",
                "Verify resource ownership at the service layer, not just at the controller",
                "Implement row-level security at the database level"
            ],
            "references": ["OWASP ASVS V4.1", "CWE-639", "CWE-285"],
            "dread": {"damage": 8, "reproducibility": 8, "exploitability": 7, "affected_users": 6, "discoverability": 6}
        },
        {
            "title": "Privilege Escalation via Role Manipulation",
            "description": "Attacker modifies their own role or permissions through API manipulation or configuration bypass.",
            "attack_scenario": "1. Attacker discovers role field in JWT token or API request. 2. Modifies role from 'user' to 'admin' in the token or request body. 3. Server accepts the modified role and grants elevated privileges.",
            "prerequisites": ["Knowledge of role structure", "Client-side role storage or weak server validation"],
            "mitigations": [
                "Never trust client-supplied role/permission data",
                "Implement server-side role resolution from authenticated identity",
                "Sign and validate JWT tokens with strong keys (OWASP ASVS V3.5)",
                "Implement RBAC with principle of least privilege"
            ],
            "references": ["OWASP ASVS V4.2", "CWE-269", "CWE-266"],
            "dread": {"damage": 9, "reproducibility": 5, "exploitability": 5, "affected_users": 8, "discoverability": 4}
        }
    ]
}


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
    Falls back to template-based threats if LLM is unavailable.
    Passes deep context: crown jewels, business workflows, user roles, domain expertise.
    """
    if not llm_client or not llm_client.is_available:
        return generate_fallback_threats(system_info), None, None

    system_prompt, prompt = _build_prompts(system_info)

    result, raw_response = llm_client.generate_json(system_prompt, prompt, temperature=0.3, max_tokens=8000)

    if result and "threats" in result:
        threats = []
        for t_data in result["threats"]:
            # Validate STRIDE category
            category = t_data.get("category", "")
            if category not in STRIDE_CATEGORIES:
                # Try to match partial
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

    # Fallback if LLM response parsing failed
    return generate_fallback_threats(system_info), f"{system_prompt}\n\n---\n\n{prompt}", raw_response


def generate_fallback_threats(system_info):
    """
    Generate threats from curated templates when LLM is unavailable.
    Selects and contextualizes threats based on system architecture.
    """
    threats = []
    for category, threat_templates in FALLBACK_THREATS.items():
        for t_data in threat_templates:
            dread_data = t_data.get("dread", {})
            component = system_info.components[0] if system_info.components else "System"

            threat = Threat(
                title=t_data["title"],
                category=category,
                description=t_data["description"],
                attack_scenario=t_data["attack_scenario"],
                affected_component=component,
                prerequisites=t_data.get("prerequisites", []),
                mitigations=t_data.get("mitigations", []),
                references=t_data.get("references", []),
                dread_score=DREADScore(
                    damage=dread_data.get("damage", 5),
                    reproducibility=dread_data.get("reproducibility", 5),
                    exploitability=dread_data.get("exploitability", 5),
                    affected_users=dread_data.get("affected_users", 5),
                    discoverability=dread_data.get("discoverability", 5)
                )
            )
            threats.append(threat)
    return threats
