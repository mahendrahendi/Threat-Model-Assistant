"""
AI Threat Modeling Assistant — Flask Application
Main entry point for the web application.
"""

import os
import sys
import json
import time
from flask import Flask, render_template, request, jsonify, Response

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from engine.threat_model import ThreatModel, SystemInfo, Threat, DREADScore, ARCHITECTURE_TEMPLATES, STRIDE_CATEGORIES
from engine.llm_client import LLMClient
from engine.stride import analyze_threats_with_llm
from engine.dread import update_threat_score, aggregate_risk_summary, get_dread_factors_info
from engine.report import generate_markdown_report, generate_html_report

app = Flask(__name__)

# Initialize LLM client
llm_client = LLMClient()

# In-memory session storage for active threat models
active_models = {}


@app.route('/')
def index():
    """Serve the main wizard UI."""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Return LLM connection status and available configuration."""
    return jsonify({
        "llm": llm_client.get_status(),
        "stride_categories": STRIDE_CATEGORIES,
        "dread_factors": get_dread_factors_info()
    })


@app.route('/api/templates', methods=['GET'])
def get_templates():
    """Return available architecture templates."""
    templates = {}
    for key, tmpl in ARCHITECTURE_TEMPLATES.items():
        templates[key] = {
            "name": tmpl["name"],
            "description": tmpl["description"],
            "components": tmpl["components"],
            "data_flows": tmpl["data_flows"],
            "trust_boundaries": tmpl["trust_boundaries"]
        }
    return jsonify(templates)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Run STRIDE threat analysis on the provided system info.
    Returns identified threats with DREAD scores.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Build SystemInfo from request — including deep context fields
    system_info = SystemInfo(
        name=data.get("name", "Unnamed System"),
        description=data.get("description", ""),
        architecture_type=data.get("architecture_type", "web_application"),
        tech_stack=data.get("tech_stack", []),
        authentication=data.get("authentication", []),
        data_sensitivity=data.get("data_sensitivity", "Internal"),
        network_exposure=data.get("network_exposure", "Internet-Facing"),
        data_flows=data.get("data_flows", []),
        trust_boundaries=data.get("trust_boundaries", []),
        components=data.get("components", []),
        existing_controls=data.get("existing_controls", []),
        crown_jewels=data.get("crown_jewels", []),
        business_workflows=data.get("business_workflows", []),
        user_roles=data.get("user_roles", []),
        domain=data.get("domain", "general")
    )

    # Create threat model
    model = ThreatModel(system_info=system_info)

    if not llm_client or not llm_client.is_available:
        return jsonify({"error": "LLM not connected. Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY."}), 503

    # Run STRIDE analysis with timing
    start_time = time.time()
    try:
        threats, raw_prompt, raw_response = analyze_threats_with_llm(system_info, llm_client)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 502
    elapsed = round(time.time() - start_time, 2)
    for threat in threats:
        model.add_threat(threat)

    # Store in session
    active_models[model.id] = model

    return jsonify({
        "model_id": model.id,
        "threats": [t.to_dict() for t in model.threats],
        "risk_summary": aggregate_risk_summary(model.threats),
        "llm_used": llm_client.is_available,
        "llm_meta": {
            "provider": llm_client.provider if llm_client.is_available else None,
            "model": llm_client.model if llm_client.is_available else None,
            "elapsed_seconds": elapsed,
            "threat_count": len(threats),
            "domain": data.get("domain", "general"),
            "crown_jewels_count": len(data.get("crown_jewels", [])),
            "workflows_count": len(data.get("business_workflows", [])),
            "user_roles_count": len(data.get("user_roles", [])),
            "raw_prompt": raw_prompt,
            "raw_response": raw_response
        }
    })

@app.route('/api/analyze/stream', methods=['POST'])
def analyze_stream():
    """Server-Sent Events endpoint for real-time LLM streaming."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    system_info = SystemInfo(
        name=data.get("name", "Unnamed System"),
        description=data.get("description", ""),
        architecture_type=data.get("architecture_type", "web_application"),
        tech_stack=data.get("tech_stack", []),
        authentication=data.get("authentication", []),
        data_sensitivity=data.get("data_sensitivity", "Internal"),
        network_exposure=data.get("network_exposure", "Internet-Facing"),
        data_flows=data.get("data_flows", []),
        trust_boundaries=data.get("trust_boundaries", []),
        components=data.get("components", []),
        existing_controls=data.get("existing_controls", []),
        crown_jewels=data.get("crown_jewels", []),
        business_workflows=data.get("business_workflows", []),
        user_roles=data.get("user_roles", []),
        domain=data.get("domain", "general")
    )
    if not llm_client or not llm_client.is_available:
        return jsonify({"error": "LLM not connected. Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY."}), 503

    model = ThreatModel(system_info=system_info)

    def generate():
        start_time = time.time()
        from engine.stride import _build_prompts

        system_prompt, prompt = _build_prompts(system_info)
        
        # Stream prompt info first
        yield f"data: {json.dumps({'type': 'prompts', 'system': system_prompt, 'user': prompt})}\n\n"

        full_response = ""
        for chunk in llm_client.generate_stream(system_prompt, prompt, temperature=0.3, max_tokens=16384):
            if chunk:
                full_response += chunk
                # SSE data must be single line, so we json serialize the chunk object
                yield f"data: {json.dumps({'type': 'chunk', 'text': chunk})}\n\n"
                
        # Finish stream and parse JSON
        parsed = llm_client._parse_json_response(full_response)
        threats = []
        if parsed and "threats" in parsed:
            from engine.stride import STRIDE_CATEGORIES
            for t_data in parsed["threats"]:
                category = t_data.get("category", "")
                if category not in STRIDE_CATEGORIES:
                    for valid_cat in STRIDE_CATEGORIES:
                        if valid_cat.lower() in category.lower():
                            category = valid_cat
                            break
                    else: category = "Information Disclosure"

                dread_data = t_data.get("dread_score", {})
                dread = DREADScore(
                    damage=dread_data.get("damage", 5),
                    reproducibility=dread_data.get("reproducibility", 5),
                    exploitability=dread_data.get("exploitability", 5),
                    affected_users=dread_data.get("affected_users", 5),
                    discoverability=dread_data.get("discoverability", 5),
                    reasoning=dread_data.get("reasoning", {})
                )
                threats.append(Threat(
                    title=t_data.get("title", "Unnamed Threat"),
                    category=category,
                    description=t_data.get("description", ""),
                    attack_scenario=t_data.get("attack_scenario", ""),
                    affected_component=t_data.get("affected_component", ""),
                    prerequisites=t_data.get("prerequisites", []),
                    mitigations=t_data.get("mitigations", []),
                    references=t_data.get("references", []),
                    dread_score=dread
                ))
        else:
            print(f"\n[CRITICAL PARSE ERROR] LLM succeeded but parsing failed!", flush=True)
            print(f"[CRITICAL PARSE ERROR] Raw response: {full_response[:200]}...", flush=True)
            yield f"data: {json.dumps({'type': 'complete', 'result': {'error': 'LLM response could not be parsed as JSON. Please try again.'}})}\n\n"
            return

        elapsed = round(time.time() - start_time, 2)
        for t in threats: model.add_threat(t)
        active_models[model.id] = model

        final_payload = {
            "model_id": model.id,
            "threats": [t.to_dict() for t in model.threats],
            "risk_summary": aggregate_risk_summary(model.threats),
            "llm_used": True,
            "llm_meta": {
                "provider": llm_client.provider,
                "model": llm_client.model,
                "elapsed_seconds": elapsed,
                "threat_count": len(threats),
                "domain": system_info.domain,
                "raw_response": full_response
            }
        }
        
        yield f"data: {json.dumps({'type': 'complete', 'result': final_payload})}\n\n"

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/score', methods=['POST'])
def update_score():
    """Update DREAD scores for a specific threat."""
    data = request.get_json()
    model_id = data.get("model_id")
    threat_id = data.get("threat_id")
    scores = data.get("scores", {})

    if not model_id or model_id not in active_models:
        return jsonify({"error": "Invalid model ID"}), 400

    model = active_models[model_id]
    for threat in model.threats:
        if threat.id == threat_id:
            update_threat_score(threat, scores)
            return jsonify({
                "threat": threat.to_dict(),
                "risk_summary": aggregate_risk_summary(model.threats)
            })

    return jsonify({"error": "Threat not found"}), 404


@app.route('/api/threat/remove', methods=['POST'])
def remove_threat():
    """Remove a threat from the model."""
    data = request.get_json()
    model_id = data.get("model_id")
    threat_id = data.get("threat_id")

    if not model_id or model_id not in active_models:
        return jsonify({"error": "Invalid model ID"}), 400

    model = active_models[model_id]
    model.threats = [t for t in model.threats if t.id != threat_id]

    return jsonify({
        "success": True,
        "risk_summary": aggregate_risk_summary(model.threats)
    })


@app.route('/api/report/markdown', methods=['POST'])
def report_markdown():
    """Generate and return Markdown report."""
    data = request.get_json()
    model_id = data.get("model_id")

    if not model_id or model_id not in active_models:
        return jsonify({"error": "Invalid model ID"}), 400

    model = active_models[model_id]
    md = generate_markdown_report(model)

    return Response(
        md,
        mimetype='text/markdown',
        headers={'Content-Disposition': f'attachment; filename=threat_model_{model.system_info.name.replace(" ", "_")}.md'}
    )


@app.route('/api/report/html', methods=['POST'])
def report_html():
    """Generate and return styled HTML report."""
    data = request.get_json()
    model_id = data.get("model_id")

    if not model_id or model_id not in active_models:
        return jsonify({"error": "Invalid model ID"}), 400

    model = active_models[model_id]
    html = generate_html_report(model)

    return Response(
        html,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=threat_model_{model.system_info.name.replace(" ", "_")}.html'}
    )


@app.route('/api/report/preview', methods=['POST'])
def report_preview():
    """Generate and return report data for in-app preview."""
    data = request.get_json()
    model_id = data.get("model_id")

    if not model_id or model_id not in active_models:
        return jsonify({"error": "Invalid model ID"}), 400

    model = active_models[model_id]
    md = generate_markdown_report(model)
    html = generate_html_report(model)

    return jsonify({
        "markdown": md,
        "html": html,
        "model": model.to_dict()
    })


if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'

    llm_status = (f"[OK] {llm_client.provider} ({llm_client.model})"
                  if llm_client.is_available
                  else "[X] No API key configured -- set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY")
    print(f"\n"
          f"  ==================================================\n"
          f"  |  AI Threat Modeling Assistant v1.0              |\n"
          f"  |  OWASP + STRIDE + DREAD                        |\n"
          f"  ==================================================\n"
          f"  LLM Status: {llm_status}\n"
          f"  Server:     http://localhost:{port}\n"
          f"  ==================================================\n")

    app.run(host='0.0.0.0', port=port, debug=debug)
