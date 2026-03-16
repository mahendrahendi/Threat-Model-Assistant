/**
 * AI Threat Modeling Assistant — Frontend Application
 * Manages wizard navigation, API calls, threat cards, DREAD scoring, and report export.
 */

// ==================== STATE ====================
const state = {
    currentStep: 1,
    totalSteps: 7,
    modelId: null,
    threats: [],
    riskSummary: null,
    templates: {},
    selectedTemplate: null,
    selectedDomain: 'general',
    tags: {
        tech: [],
        component: []
    },
    reportData: null,
    llmAvailable: false
};

const TEMPLATE_ICONS = {
    web_application: '🌐',
    rest_api: '⚡',
    microservices: '🔗',
    mobile_app: '📱',
    cloud_infrastructure: '☁️'
};

const STRIDE_COLORS = {
    'Spoofing': '#ff4757',
    'Tampering': '#ff6348',
    'Repudiation': '#ffa502',
    'Information Disclosure': '#a55eea',
    'Denial of Service': '#3742fa',
    'Elevation of Privilege': '#e84393'
};

// ==================== INIT ====================
document.addEventListener('DOMContentLoaded', () => {
    checkLLMStatus();
    loadTemplates();
});

async function checkLLMStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const statusEl = document.getElementById('llm-status');
        const dot = statusEl.querySelector('.status-dot');
        const text = statusEl.querySelector('.status-text');

        if (data.llm.available) {
            dot.className = 'status-dot online';
            text.textContent = `${data.llm.provider} (${data.llm.model})`;
            state.llmAvailable = true;
        } else {
            dot.className = 'status-dot offline';
            text.textContent = 'No LLM — Using Templates';
            state.llmAvailable = false;
        }
    } catch (e) {
        console.error('Status check failed:', e);
    }
}

async function loadTemplates() {
    try {
        const res = await fetch('/api/templates');
        state.templates = await res.json();
        renderTemplateGrid();
    } catch (e) {
        console.error('Failed to load templates:', e);
    }
}

// ==================== WIZARD NAV ====================
function nextStep() {
    if (state.currentStep === 1 && !validateStep1()) return;
    if (state.currentStep < state.totalSteps) {
        goToStep(state.currentStep + 1);
    }
}

function prevStep() {
    if (state.currentStep > 1) {
        goToStep(state.currentStep - 1);
    }
}

function goToStep(step) {
    // Hide current
    document.getElementById(`step-${state.currentStep}`).classList.remove('active');

    // Update nav
    const navItems = document.querySelectorAll('.step-item');
    const connectors = document.querySelectorAll('.step-connector');

    navItems.forEach((item, i) => {
        const s = i + 1;
        item.classList.remove('active');
        if (s < step) item.classList.add('completed');
        if (s === step) item.classList.add('active');
    });

    connectors.forEach((conn, i) => {
        conn.classList.toggle('active', i < step - 1);
    });

    state.currentStep = step;

    // Show new step
    document.getElementById(`step-${step}`).classList.add('active');

    // Trigger step-specific actions
    if (step === 7) {
        loadReportPreview();
    }
}

function validateStep1() {
    const name = document.getElementById('sys-name').value.trim();
    const desc = document.getElementById('sys-desc').value.trim();
    if (!name) {
        highlightField('sys-name');
        return false;
    }
    if (!desc) {
        highlightField('sys-desc');
        return false;
    }
    return true;
}

function highlightField(id) {
    const el = document.getElementById(id);
    el.style.borderColor = 'var(--critical)';
    el.style.boxShadow = '0 0 0 3px rgba(255, 0, 64, 0.15)';
    el.focus();
    setTimeout(() => {
        el.style.borderColor = '';
        el.style.boxShadow = '';
    }, 2000);
}

// ==================== TEMPLATES ====================
function renderTemplateGrid() {
    const grid = document.getElementById('template-grid');
    grid.innerHTML = '';

    // Add "Custom" option
    const customCard = document.createElement('div');
    customCard.className = 'template-card';
    customCard.innerHTML = `
        <div class="template-icon">🛠️</div>
        <div class="template-name">Custom</div>
        <div class="template-desc">Define from scratch</div>
    `;
    customCard.onclick = () => selectTemplate(null, customCard);
    grid.appendChild(customCard);

    for (const [key, tmpl] of Object.entries(state.templates)) {
        const card = document.createElement('div');
        card.className = 'template-card';
        card.innerHTML = `
            <div class="template-icon">${TEMPLATE_ICONS[key] || '📦'}</div>
            <div class="template-name">${tmpl.name}</div>
            <div class="template-desc">${tmpl.description.substring(0, 60)}...</div>
        `;
        card.onclick = () => selectTemplate(key, card);
        grid.appendChild(card);
    }
}

function selectTemplate(key, cardEl) {
    // Clear selection in template grid only
    document.querySelectorAll('#template-grid .template-card').forEach(c => c.classList.remove('selected'));
    cardEl.classList.add('selected');
    state.selectedTemplate = key;

    if (key && state.templates[key]) {
        const tmpl = state.templates[key];
        // Pre-fill components
        state.tags.component = [...tmpl.components];
        renderTags('component');

        // Pre-fill data flows
        renderDataFlows(tmpl.data_flows);

        // Pre-fill trust boundaries
        renderTrustBoundaries(tmpl.trust_boundaries);
    }
}

// ==================== DOMAIN SELECTOR ====================
function selectDomain(domain, cardEl) {
    document.querySelectorAll('#domain-grid .template-card').forEach(c => c.classList.remove('selected'));
    cardEl.classList.add('selected');
    state.selectedDomain = domain;
}

// ==================== CROWN JEWELS ====================
function addCrownJewel() {
    const list = document.getElementById('crown-jewels-list');
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.style.flexWrap = 'wrap';
    div.innerHTML = `
        <input type="text" placeholder="Asset name (e.g., Root CA Private Key)" class="cj-name" style="flex:1;min-width:200px">
        <input type="text" placeholder="Why critical? (e.g., Signs all intermediate CAs)" class="cj-why" style="flex:2;min-width:250px">
        <input type="text" placeholder="Where stored? (e.g., HSM Partition 1)" class="cj-location" style="flex:1;min-width:150px">
        <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
    `;
    list.appendChild(div);
}

function getCrownJewels() {
    const jewels = [];
    document.querySelectorAll('#crown-jewels-list .flow-item').forEach(item => {
        jewels.push({
            name: item.querySelector('.cj-name').value.trim(),
            why_critical: item.querySelector('.cj-why').value.trim(),
            location: item.querySelector('.cj-location').value.trim()
        });
    });
    return jewels.filter(j => j.name);
}

// ==================== BUSINESS WORKFLOWS ====================
function addWorkflow() {
    const list = document.getElementById('workflows-list');
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.style.flexWrap = 'wrap';
    div.innerHTML = `
        <input type="text" placeholder="Workflow name (e.g., Certificate Issuance)" class="wf-name" style="flex:1;min-width:200px">
        <input type="text" placeholder="Actors involved (e.g., External User, RA, CA)" class="wf-actors" style="flex:1;min-width:200px">
        <textarea placeholder="Steps: e.g., 1. User submits CSR → 2. RA validates identity → 3. CA selects signing key → 4. CA signs certificate" class="wf-steps input-field" rows="2" style="flex:100%;margin-top:0.4rem"></textarea>
        <button class="btn-remove" onclick="this.parentElement.remove()" style="align-self:flex-start;margin-top:0.4rem">✕</button>
    `;
    list.appendChild(div);
}

function getWorkflows() {
    const workflows = [];
    document.querySelectorAll('#workflows-list .flow-item').forEach(item => {
        workflows.push({
            name: item.querySelector('.wf-name').value.trim(),
            actors: item.querySelector('.wf-actors').value.trim(),
            steps: item.querySelector('.wf-steps').value.trim()
        });
    });
    return workflows.filter(w => w.name);
}

// ==================== USER ROLES ====================
function addUserRole() {
    const list = document.getElementById('user-roles-list');
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.style.flexWrap = 'wrap';
    div.innerHTML = `
        <input type="text" placeholder="Role name (e.g., External User)" class="role-name" style="flex:1;min-width:150px">
        <input type="text" placeholder="Permissions (e.g., Request certificates, view own certs)" class="role-permissions" style="flex:2;min-width:250px">
        <select class="role-trust input-field" style="flex:0 0 120px;padding:0.4rem">
            <option value="Untrusted">Untrusted</option>
            <option value="Low">Low Trust</option>
            <option value="Medium" selected>Medium Trust</option>
            <option value="High">High Trust</option>
            <option value="Privileged">Privileged</option>
        </select>
        <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
    `;
    list.appendChild(div);
}

function getUserRoles() {
    const roles = [];
    document.querySelectorAll('#user-roles-list .flow-item').forEach(item => {
        roles.push({
            name: item.querySelector('.role-name').value.trim(),
            permissions: item.querySelector('.role-permissions').value.trim(),
            trust_level: item.querySelector('.role-trust').value
        });
    });
    return roles.filter(r => r.name);
}

// ==================== TAG INPUT ====================
function handleTagInput(event, type) {
    if (event.key === 'Enter') {
        event.preventDefault();
        const input = document.getElementById(`${type}-input`);
        const value = input.value.trim();
        if (value && !state.tags[type].includes(value)) {
            addTag(type, value);
        }
        input.value = '';
    }
}

function addTag(type, value) {
    if (!state.tags[type].includes(value)) {
        state.tags[type].push(value);
        renderTags(type);
    }
}

function removeTag(type, value) {
    state.tags[type] = state.tags[type].filter(t => t !== value);
    renderTags(type);
}

function renderTags(type) {
    const container = document.getElementById(`${type}-tags`);
    container.innerHTML = state.tags[type].map(tag =>
        `<span class="tag">${tag}<span class="remove-tag" onclick="removeTag('${type}', '${tag.replace(/'/g, "\\'")}')">&times;</span></span>`
    ).join('');
}

// ==================== DATA FLOWS ====================
function addDataFlow() {
    const list = document.getElementById('data-flows-list');
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.innerHTML = `
        <input type="text" placeholder="Source" class="flow-source">
        <span class="flow-arrow">→</span>
        <input type="text" placeholder="Destination" class="flow-dest">
        <input type="text" placeholder="Data Type" class="flow-data">
        <input type="text" placeholder="Protocol" class="flow-protocol" style="max-width:100px">
        <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
    `;
    list.appendChild(div);
}

function renderDataFlows(flows) {
    const list = document.getElementById('data-flows-list');
    list.innerHTML = '';
    flows.forEach(flow => {
        const div = document.createElement('div');
        div.className = 'flow-item';
        div.innerHTML = `
            <input type="text" placeholder="Source" class="flow-source" value="${flow.source || ''}">
            <span class="flow-arrow">→</span>
            <input type="text" placeholder="Destination" class="flow-dest" value="${flow.destination || ''}">
            <input type="text" placeholder="Data Type" class="flow-data" value="${flow.data || ''}">
            <input type="text" placeholder="Protocol" class="flow-protocol" style="max-width:100px" value="${flow.protocol || ''}">
            <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
        `;
        list.appendChild(div);
    });
}

function getDataFlows() {
    const flows = [];
    document.querySelectorAll('#data-flows-list .flow-item').forEach(item => {
        flows.push({
            source: item.querySelector('.flow-source').value.trim(),
            destination: item.querySelector('.flow-dest').value.trim(),
            data: item.querySelector('.flow-data').value.trim(),
            protocol: item.querySelector('.flow-protocol').value.trim()
        });
    });
    return flows.filter(f => f.source && f.destination);
}

// ==================== TRUST BOUNDARIES ====================
function addTrustBoundary() {
    const list = document.getElementById('trust-boundaries-list');
    const div = document.createElement('div');
    div.className = 'boundary-item';
    div.innerHTML = `
        <input type="text" placeholder="Boundary Name" class="boundary-name">
        <input type="text" placeholder="Outside components (comma-separated)" class="boundary-outside">
        <span class="flow-arrow">⇢</span>
        <input type="text" placeholder="Inside components (comma-separated)" class="boundary-inside">
        <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
    `;
    list.appendChild(div);
}

function renderTrustBoundaries(boundaries) {
    const list = document.getElementById('trust-boundaries-list');
    list.innerHTML = '';
    boundaries.forEach(tb => {
        const div = document.createElement('div');
        div.className = 'boundary-item';
        div.innerHTML = `
            <input type="text" placeholder="Boundary Name" class="boundary-name" value="${tb.name || ''}">
            <input type="text" placeholder="Outside" class="boundary-outside" value="${(tb.outside || []).join(', ')}">
            <span class="flow-arrow">⇢</span>
            <input type="text" placeholder="Inside" class="boundary-inside" value="${(tb.inside || []).join(', ')}">
            <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>
        `;
        list.appendChild(div);
    });
}

function getTrustBoundaries() {
    const boundaries = [];
    document.querySelectorAll('.boundary-item').forEach(item => {
        boundaries.push({
            name: item.querySelector('.boundary-name').value.trim(),
            outside: item.querySelector('.boundary-outside').value.split(',').map(s => s.trim()).filter(Boolean),
            inside: item.querySelector('.boundary-inside').value.split(',').map(s => s.trim()).filter(Boolean)
        });
    });
    return boundaries.filter(b => b.name);
}

// ==================== ANALYSIS ====================

// Terminal helper: add a line to the AI terminal
function terminalLog(type, label, text) {
    const body = document.getElementById('ai-terminal-body');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.innerHTML = `<span class="terminal-prompt">${label}</span><span class="terminal-text">${text}</span>`;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
}

// Remove the blinking cursor from previous "thinking" lines
function clearThinking() {
    document.querySelectorAll('.terminal-line.thinking').forEach(el => {
        el.classList.remove('thinking');
        el.classList.add('llm');
    });
}

// Toggle raw API logs view
function toggleRawLogs() {
    const logsEl = document.getElementById('raw-api-logs');
    const btn = document.getElementById('toggle-raw-logs');
    if (logsEl.classList.contains('visible')) {
        logsEl.classList.remove('visible');
        btn.textContent = 'View Raw API Logs';
    } else {
        logsEl.classList.add('visible');
        btn.textContent = 'Hide Raw API Logs';
        
        // Scroll to the logs
        setTimeout(() => {
            const terminalBody = document.getElementById('ai-terminal-body');
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }, 50);
    }
}

// Domain names for display
const DOMAIN_NAMES = {
    general: 'General Security',
    pki_ca: 'PKI / Certificate Authority',
    payment: 'Payment Processing / PCI DSS',
    iam_identity: 'IAM / Identity Management',
    healthcare: 'Healthcare / HIPAA',
    cloud_saas: 'Cloud / SaaS Platform',
    iot_embedded: 'IoT / Embedded Systems'
};

async function runAnalysis() {
    // Collect all data including deep context
    const payload = {
        name: document.getElementById('sys-name').value.trim(),
        description: document.getElementById('sys-desc').value.trim(),
        architecture_type: state.selectedTemplate || 'custom',
        domain: state.selectedDomain || 'general',
        tech_stack: state.tags.tech,
        authentication: getCheckedValues('auth'),
        data_sensitivity: getRadioValue('sensitivity'),
        network_exposure: getRadioValue('exposure'),
        data_flows: getDataFlows(),
        trust_boundaries: getTrustBoundaries(),
        components: state.tags.component,
        existing_controls: getCheckedValues('controls'),
        crown_jewels: getCrownJewels(),
        business_workflows: getWorkflows(),
        user_roles: getUserRoles()
    };

    // Switch to analysis step
    goToStep(5);

    // Get UI elements
    const progressBar = document.getElementById('analysis-progress-bar');
    const substatus = document.getElementById('analysis-substatus');
    const checks = document.querySelectorAll('.stride-check');
    const terminalBody = document.getElementById('ai-terminal-body');

    // Reset everything
    progressBar.style.width = '0%';
    terminalBody.querySelectorAll('.terminal-line').forEach(el => el.remove());
    
    // Reset raw logs UI
    document.getElementById('toggle-raw-logs').style.display = 'none';
    document.getElementById('raw-api-logs').classList.remove('visible');
    document.getElementById('toggle-raw-logs').textContent = 'View Raw API Logs';
    
    checks.forEach(c => {
        c.classList.remove('checking', 'done');
        c.querySelector('.check-icon').textContent = '⏳';
    });

    const delay = (ms) => new Promise(r => setTimeout(r, ms));

    // ═══ FIRE THE REAL API CALL IMMEDIATELY    // Set up the API call but DON'T await it yet
    const apiStartTime = performance.now();
    let apiResponse = null;
    let apiReader = null;
    
    // We will initiate the request, but read the stream inside the terminal animation loop

    // ═══ ANIMATION: Show what's happening ═══
    // Phase 0: System init
    terminalLog('system', 'system', '▸ ThreatModelAI Engine v1.0 initialized');
    await delay(400);

    terminalLog('system', 'system', `▸ Analysis target: "${payload.name}"`);
    substatus.textContent = 'Initializing threat analysis engine...';
    progressBar.style.width = '3%';
    await delay(400);

    // Show LLM connection
    const isLLM = state.llmAvailable;
    if (isLLM) {
        const statusEl = document.querySelector('.status-text');
        const providerInfo = statusEl ? statusEl.textContent : 'LLM';
        terminalLog('success', 'llm', `✓ Connected to ${providerInfo}`);
    } else {
        terminalLog('warning', 'llm', '⚠ No LLM API key — using curated threat templates');
    }
    progressBar.style.width = '5%';
    await delay(350);

    // Phase 1: Domain expertise
    const domainName = DOMAIN_NAMES[payload.domain] || 'General Security';
    terminalLog('phase', 'phase', `━━━ LOADING DOMAIN EXPERTISE: ${domainName} ━━━`);
    progressBar.style.width = '8%';
    await delay(350);

    if (payload.domain !== 'general') {
        const domainLines = {
            pki_ca: [
                'Loading PKI attack patterns: unauthorized cert issuance, key compromise, CA impersonation...',
                'Loading standards: WebTrust, RFC 5280, CAB Forum Baseline Requirements...',
                'Loading critical checks: root key access, certificate profile abuse, HSM bypass vectors...'
            ],
            payment: [
                'Loading PCI DSS threat patterns: cardholder data flows, tokenization bypass...',
                'Loading standards: PCI DSS v4.0, PA-DSS, ISO 8583...',
                'Loading critical checks: CDE boundary leaks, PAN masking, key extraction...'
            ],
            iam_identity: [
                'Loading IAM attack patterns: credential stuffing, token replay, consent phishing...',
                'Loading standards: NIST 800-63, OAuth 2.0 Security BCP...',
                'Loading critical checks: role escalation, SAML assertion forgery, session fixation...'
            ],
            healthcare: [
                'Loading HIPAA threat patterns: PHI exfiltration, record tampering...',
                'Loading standards: HIPAA Security Rule, HITECH, HL7 FHIR Security...',
                'Loading critical checks: break-glass audit, minimum necessary, BAA compliance...'
            ],
            cloud_saas: [
                'Loading cloud threat patterns: tenant escape, SSRF, supply chain...',
                'Loading standards: CIS Benchmarks, CSA CCM, SOC 2...',
                'Loading critical checks: tenant isolation, metadata service access, IAM misconfiguration...'
            ],
            iot_embedded: [
                'Loading IoT threat patterns: firmware extraction, debug port access...',
                'Loading standards: OWASP IoT Top 10, ETSI EN 303 645...',
                'Loading critical checks: secure boot chain, OTA update signing, key storage...'
            ]
        };
        const lines = domainLines[payload.domain] || [];
        for (const line of lines) {
            terminalLog('data', 'domain', line);
            await delay(300);
        }
    } else {
        terminalLog('data', 'domain', 'Using broad security analysis — no domain-specific patterns loaded');
    }
    progressBar.style.width = '12%';
    await delay(300);

    // Phase 2: Show what prompt is being built
    terminalLog('phase', 'phase', '━━━ CONSTRUCTING ANALYSIS PROMPT ━━━');
    substatus.textContent = 'Building deep-context prompt for LLM...';
    progressBar.style.width = '15%';
    await delay(300);

    terminalLog('prompt', 'prompt', `System prompt: "You are a Senior Application Security Architect with 20+ years of experience..."`);
    await delay(250);

    terminalLog('prompt', 'prompt', `Target: ${payload.name} | Arch: ${payload.architecture_type} | Sensitivity: ${payload.data_sensitivity} | Exposure: ${payload.network_exposure}`);
    await delay(250);

    if (payload.tech_stack.length > 0) {
        terminalLog('prompt', 'prompt', `Tech stack: ${payload.tech_stack.join(', ')}`);
        await delay(200);
    }

    if (payload.crown_jewels.length > 0) {
        terminalLog('prompt', 'assets', `👑 Crown jewels: ${payload.crown_jewels.map(c => c.name).join(', ')}`);
        for (const cj of payload.crown_jewels) {
            terminalLog('data', 'assets', `  ▸ ${cj.name}: ${cj.why_critical} [${cj.location}]`);
            await delay(150);
        }
    } else {
        terminalLog('warning', 'assets', '⚠ No crown jewels specified — analysis will be less targeted');
    }
    await delay(200);

    if (payload.business_workflows.length > 0) {
        terminalLog('prompt', 'workflow', `⚙ Business workflows: ${payload.business_workflows.length} workflow(s)`);
        for (const wf of payload.business_workflows) {
            terminalLog('data', 'workflow', `  ▸ ${wf.name} (Actors: ${wf.actors})`);
            await delay(150);
        }
    }

    if (payload.user_roles.length > 0) {
        terminalLog('prompt', 'roles', `👤 User roles: ${payload.user_roles.map(r => `${r.name} [${r.trust_level}]`).join(', ')}`);
        await delay(200);
    }

    terminalLog('prompt', 'prompt', `Data flows: ${payload.data_flows.length} | Trust boundaries: ${payload.trust_boundaries.length} | Controls: ${payload.existing_controls.length}`);
    progressBar.style.width = '20%';
    await delay(300);

    // Phase 3: Now show that we're waiting for the REAL LLM response
    terminalLog('phase', 'phase', '━━━ SENDING TO LLM — WAITING FOR RESPONSE ━━━');
    substatus.textContent = isLLM ? 'Waiting for LLM response... (this takes 10-30 seconds for real AI analysis)' : 'Processing with threat templates...';
    progressBar.style.width = '25%';
    await delay(200);

    terminalLog('system', 'api', `POST /api/analyze → ${payload.name} (${JSON.stringify(payload).length} bytes)`);
    await delay(200);

    // Start "waiting for LLM" animation — this continues until API responds
    checks[0].classList.add('checking');
    checks[0].querySelector('.check-icon').textContent = '🔄';
    terminalLog('thinking', 'llm', isLLM ? 'LLM is analyzing threat surface — processing' : 'Generating threats from curated templates');

    // Keep STRIDE checklist cycling while waiting for real response
    let waitPhase = 0;
    const waitMessages = [
        'Analyzing spoofing and identity threats',
        'Evaluating data tampering vectors',
        'Checking repudiation controls',
        'Scanning for information disclosure paths',
        'Assessing denial of service risks',
        'Mapping privilege escalation chains'
    ];
    const waitInterval = setInterval(() => {
        // Cycle through STRIDE checks to show activity
        checks.forEach((c, i) => {
            c.classList.remove('checking');
            if (i < waitPhase) {
                c.classList.add('done');
                c.querySelector('.check-icon').textContent = '✅';
            }
        });
        if (waitPhase < 6) {
            checks[waitPhase].classList.add('checking');
            checks[waitPhase].querySelector('.check-icon').textContent = '🔄';
            substatus.textContent = waitMessages[waitPhase];
        }
        waitPhase = Math.min(waitPhase + 1, 5);

        // Slowly advance progress
        const currentWidth = parseFloat(progressBar.style.width) || 25;
        progressBar.style.width = Math.min(currentWidth + 3, 85) + '%';
    }, isLLM ? 4000 : 300);

    // ═══ WAIT FOR THE REAL API RESPONSE STREAM ═══
    try {
        apiResponse = await fetch('/api/analyze/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!apiResponse.ok) {
            const errData = await apiResponse.json();
            throw new Error(errData.error || 'Server error');
        }

        // Stop waiting animation immediately because stream has started
        clearInterval(waitInterval);
        clearThinking();
        terminalLog('success', 'api', 'Established real-time streaming connection to engine.');
        
        // Expose raw logs to show the stream in real-time
        if (isLLM) {
            const logsEl = document.getElementById('raw-api-logs');
            const btn = document.getElementById('toggle-raw-logs');
            logsEl.classList.add('visible');
            btn.style.display = 'block';
            btn.textContent = 'Hide Raw API Logs';
            terminalLog('system', 'action', 'Streaming tokens perfectly from API to terminal below ▼');
            
            // Auto-scroll once to reveal the box
            setTimeout(() => {
                const terminalBody = document.getElementById('ai-terminal-body');
                terminalBody.scrollTop = terminalBody.scrollHeight;
            }, 100);
        }

        apiReader = apiResponse.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let finalData = null;
        let streamedText = '';
        const rawResponseBox = document.getElementById('raw-response-content');
        const rawPromptBox = document.getElementById('raw-prompt-content');
        
        // Loop continuously to read chunks
        while (true) {
            const { done, value } = await apiReader.read();
            if (done) break;
            
            buffer += decoder.decode(value, {stream: true});
            let lines = buffer.split('\n');
            buffer = lines.pop(); // Keep incomplete line in buffer
            
            for (let line of lines) {
                if (line.startsWith('data: ')) {
                    try {
                        const eventData = JSON.parse(line.substring(6));
                        
                        // Handle server sent events
                        if (eventData.type === 'prompts') {
                            rawPromptBox.textContent = `--- SYSTEM PROMPT ---\n${eventData.system}\n\n--- USER PROMPT ---\n${eventData.user}`;
                        } else if (eventData.type === 'chunk') {
                            streamedText += eventData.text;
                            rawResponseBox.textContent = streamedText;
                            rawResponseBox.scrollTop = rawResponseBox.scrollHeight;
                        } else if (eventData.type === 'complete') {
                            finalData = eventData.result;
                        }
                    } catch (e) {
                        // Ignore mid-chunk json parse errors safely
                    }
                }
            }
        }
        
        if (!finalData) throw new Error("Stream closed before completion event");

        const data = finalData;
        const elapsed = ((performance.now() - apiStartTime) / 1000).toFixed(1);

        if (data.error) {
            terminalLog('warning', 'error', `✗ Analysis failed: ${data.error}`);
            substatus.textContent = `Error: ${data.error}`;
            return;
        }

        // Complete all STRIDE checks
        checks.forEach(c => {
            c.classList.remove('checking');
            c.classList.add('done');
            c.querySelector('.check-icon').textContent = '✅';
        });
        progressBar.style.width = '100%';

        // ═══ SHOW REAL PROOF FROM LLM ═══
        terminalLog('phase', 'phase', '━━━ RESPONSE RECEIVED ━━━');

        // Show real metadata from the backend
        const meta = data.llm_meta || {};
        if (data.llm_used && meta.provider) {
            terminalLog('success', 'llm', `✓ Provider: ${meta.provider} | Model: ${meta.model}`);
            terminalLog('success', 'llm', `✓ Response time: ${meta.elapsed_seconds}s (server) | ${elapsed}s (total)`);
            terminalLog('success', 'llm', `✓ Context sent: ${meta.crown_jewels_count} crown jewels, ${meta.workflows_count} workflows, ${meta.user_roles_count} roles`);
        } else {
            terminalLog('warning', 'result', `⚠ Template mode — no LLM was called (${elapsed}s)`);
            terminalLog('warning', 'result', '  Configure ANTHROPIC_API_KEY, GEMINI_API_KEY, or OPENAI_API_KEY for AI analysis');
        }

        terminalLog('success', 'result', `✓ ${data.threats.length} threats identified across STRIDE categories`);

        // Update raw logs with accurate meta properties if they weren't fully caught by the stream
        if (meta.raw_prompt) document.getElementById('raw-prompt-content').textContent = meta.raw_prompt;
        if (meta.raw_response) document.getElementById('raw-response-content').textContent = meta.raw_response;

        // Show risk breakdown
        const rs = data.risk_summary?.by_risk_level || {};
        const riskLine = [
            rs.Critical ? `🔴 ${rs.Critical} Critical` : null,
            rs.High ? `🟠 ${rs.High} High` : null,
            rs.Medium ? `🟡 ${rs.Medium} Medium` : null,
            rs.Low ? `🟢 ${rs.Low} Low` : null
        ].filter(Boolean).join(' | ');

        if (riskLine) {
            terminalLog('success', 'result', riskLine);
        }

        substatus.textContent = data.llm_used
            ? `${data.threats.length} threats found via ${meta.provider}/${meta.model} in ${meta.elapsed_seconds}s`
            : `${data.threats.length} threats from templates (no LLM). Add API key for AI analysis.`;

        // Store results
        state.modelId = data.model_id;
        state.threats = data.threats;
        state.riskSummary = data.risk_summary;

        // Auto-advance after pause
        setTimeout(() => {
            goToStep(6);
            renderRiskDashboard();
            renderThreatCards();
        }, 2500);

    } catch (e) {
        clearInterval(waitInterval);
        clearThinking();
        terminalLog('warning', 'error', `✗ Network error: ${e.message}`);
        substatus.textContent = `Analysis failed: ${e.message}`;
        console.error('Analysis error:', e);
    }
}

function getCheckedValues(name) {
    return Array.from(document.querySelectorAll(`input[name="${name}"]:checked`))
        .map(cb => cb.value);
}

function getRadioValue(name) {
    const checked = document.querySelector(`input[name="${name}"]:checked`);
    return checked ? checked.value : '';
}

// ==================== RISK DASHBOARD ====================
function renderRiskDashboard() {
    const dashboard = document.getElementById('risk-dashboard');
    const s = state.riskSummary;
    if (!s) return;

    dashboard.innerHTML = `
        <div class="risk-stat stat-critical">
            <div class="stat-value">${s.by_risk_level.Critical || 0}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="risk-stat stat-high">
            <div class="stat-value">${s.by_risk_level.High || 0}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="risk-stat stat-medium">
            <div class="stat-value">${s.by_risk_level.Medium || 0}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="risk-stat stat-low">
            <div class="stat-value">${s.by_risk_level.Low || 0}</div>
            <div class="stat-label">Low</div>
        </div>
    `;
}

// ==================== THREAT CARDS ====================
function renderThreatCards(filter = 'all') {
    const container = document.getElementById('threat-cards');
    container.innerHTML = '';

    const filtered = filter === 'all'
        ? state.threats
        : state.threats.filter(t => t.category === filter);

    // Sort by risk score descending
    filtered.sort((a, b) => b.dread_score.overall - a.dread_score.overall);

    filtered.forEach(threat => {
        container.appendChild(createThreatCard(threat));
    });
}

function createThreatCard(threat) {
    const card = document.createElement('div');
    card.className = 'threat-card';
    card.id = `threat-${threat.id}`;
    card.dataset.category = threat.category;

    const catColor = STRIDE_COLORS[threat.category] || '#747d8c';
    const riskColor = threat.dread_score.risk_color;
    const dread = threat.dread_score;

    card.innerHTML = `
        <div class="threat-card-header" onclick="toggleThreatCard('${threat.id}')">
            <span class="threat-category-badge" style="background:${catColor}20; color:${catColor}; border: 1px solid ${catColor}40">
                ${threat.category_icon} ${threat.category}
            </span>
            <span class="threat-title">${threat.title}</span>
            <span class="threat-risk-badge" style="background:${riskColor}20; color:${riskColor}; border: 1px solid ${riskColor}40">
                ${dread.overall}/10 ${dread.risk_level}
            </span>
            <span class="threat-expand-icon">▼</span>
        </div>
        <div class="threat-card-body">
            <div class="threat-section">
                <div class="threat-section-title">Description</div>
                <p class="threat-text">${threat.description}</p>
            </div>

            <div class="threat-section">
                <div class="threat-section-title">Attack Scenario</div>
                <div class="threat-attack-scenario">${threat.attack_scenario}</div>
            </div>

            <div class="threat-section">
                <div class="threat-section-title">Affected Component</div>
                <p class="threat-text">${threat.affected_component}</p>
            </div>

            ${threat.prerequisites && threat.prerequisites.length ? `
            <div class="threat-section">
                <div class="threat-section-title">Prerequisites</div>
                <ul class="threat-list">
                    ${threat.prerequisites.map(p => `<li>${p}</li>`).join('')}
                </ul>
            </div>` : ''}

            <div class="threat-section">
                <div class="threat-section-title">DREAD Risk Score</div>
                <div class="dread-sliders">
                    ${createDreadSlider(threat.id, 'damage', 'Damage', dread.damage)}
                    ${createDreadSlider(threat.id, 'reproducibility', 'Reproducibility', dread.reproducibility)}
                    ${createDreadSlider(threat.id, 'exploitability', 'Exploitability', dread.exploitability)}
                    ${createDreadSlider(threat.id, 'affected_users', 'Affected Users', dread.affected_users)}
                    ${createDreadSlider(threat.id, 'discoverability', 'Discoverability', dread.discoverability)}
                </div>
                <div class="dread-overall">
                    <span class="dread-overall-label">Overall Risk Score</span>
                    <span class="dread-overall-score" id="dread-overall-${threat.id}" style="color:${riskColor}">${dread.overall}/10 — ${dread.risk_level}</span>
                </div>
            </div>

            ${threat.mitigations && threat.mitigations.length ? `
            <div class="threat-section">
                <div class="threat-section-title">Recommended Mitigations</div>
                <ul class="threat-list mitigation-list">
                    ${threat.mitigations.map(m => `<li>${m}</li>`).join('')}
                </ul>
            </div>` : ''}

            ${threat.references && threat.references.length ? `
            <div class="threat-section">
                <div class="threat-section-title">References</div>
                <div class="reference-tags">
                    ${threat.references.map(r => `<span class="ref-tag">${r}</span>`).join('')}
                </div>
            </div>` : ''}

            <div class="threat-card-actions">
                <button class="btn-delete-threat" onclick="deleteThreat('${threat.id}')">🗑 Remove Threat</button>
            </div>
        </div>
    `;

    return card;
}

function createDreadSlider(threatId, factor, label, value) {
    const color = getDreadColor(value);
    return `
        <div class="dread-slider-group">
            <div class="dread-slider-label">
                <span class="dread-slider-name">${label}</span>
                <span class="dread-slider-value" id="dread-val-${threatId}-${factor}" style="color:${color}">${value}</span>
            </div>
            <input type="range" class="dread-slider" min="1" max="10" value="${value}"
                oninput="updateDreadSlider('${threatId}', '${factor}', this.value)">
        </div>
    `;
}

function getDreadColor(value) {
    if (value >= 9) return 'var(--critical)';
    if (value >= 7) return 'var(--high)';
    if (value >= 4) return 'var(--medium)';
    return 'var(--low)';
}

function toggleThreatCard(threatId) {
    const card = document.getElementById(`threat-${threatId}`);
    card.classList.toggle('expanded');
}

// ==================== DREAD SCORE UPDATE ====================
async function updateDreadSlider(threatId, factor, value) {
    value = parseInt(value);

    // Update UI immediately
    const valEl = document.getElementById(`dread-val-${threatId}-${factor}`);
    valEl.textContent = value;
    valEl.style.color = getDreadColor(value);

    // Find threat and update locally
    const threat = state.threats.find(t => t.id === threatId);
    if (threat) {
        threat.dread_score[factor] = value;
        // Recalculate overall
        const d = threat.dread_score;
        const overall = ((d.damage + d.reproducibility + d.exploitability + d.affected_users + d.discoverability) / 5).toFixed(1);
        d.overall = parseFloat(overall);
        d.risk_level = overall >= 9 ? 'Critical' : overall >= 7 ? 'High' : overall >= 4 ? 'Medium' : 'Low';
        d.risk_color = getDreadColorHex(d.risk_level);

        // Update overall display
        const overallEl = document.getElementById(`dread-overall-${threatId}`);
        overallEl.textContent = `${overall}/10 — ${d.risk_level}`;
        overallEl.style.color = d.risk_color;

        // Update header badge
        const card = document.getElementById(`threat-${threatId}`);
        const badge = card.querySelector('.threat-risk-badge');
        badge.textContent = `${overall}/10 ${d.risk_level}`;
        badge.style.color = d.risk_color;
        badge.style.background = `${d.risk_color}20`;
        badge.style.borderColor = `${d.risk_color}40`;
    }

    // Save to backend
    try {
        const res = await fetch('/api/score', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model_id: state.modelId,
                threat_id: threatId,
                scores: { [factor]: value }
            })
        });
        const data = await res.json();
        if (data.risk_summary) {
            state.riskSummary = data.risk_summary;
            renderRiskDashboard();
        }
    } catch (e) {
        console.error('Score update failed:', e);
    }
}

function getDreadColorHex(level) {
    return {
        'Critical': '#ff0040',
        'High': '#ff4757',
        'Medium': '#ffa502',
        'Low': '#2ed573'
    }[level] || '#747d8c';
}

// ==================== THREAT MANAGEMENT ====================
async function deleteThreat(threatId) {
    try {
        const res = await fetch('/api/threat/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model_id: state.modelId,
                threat_id: threatId
            })
        });
        const data = await res.json();

        if (data.success) {
            state.threats = state.threats.filter(t => t.id !== threatId);
            state.riskSummary = data.risk_summary;

            const card = document.getElementById(`threat-${threatId}`);
            card.style.opacity = '0';
            card.style.transform = 'translateX(20px)';
            setTimeout(() => card.remove(), 300);

            renderRiskDashboard();
        }
    } catch (e) {
        console.error('Delete threat failed:', e);
    }
}

function filterThreats(filter) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.filter-btn[data-filter="${filter}"]`).classList.add('active');
    renderThreatCards(filter);
}

// ==================== REPORT ====================
async function loadReportPreview() {
    const preview = document.getElementById('report-preview');
    const mdContent = document.getElementById('report-md-content');

    preview.innerHTML = '<div class="report-loading">Generating report...</div>';

    try {
        const res = await fetch('/api/report/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model_id: state.modelId })
        });
        const data = await res.json();
        state.reportData = data;

        // Render HTML preview in iframe
        const iframe = document.createElement('iframe');
        iframe.style.width = '100%';
        iframe.style.minHeight = '500px';
        iframe.style.border = 'none';
        iframe.style.borderRadius = '8px';
        iframe.style.background = '#0a0e27';
        preview.innerHTML = '';
        preview.appendChild(iframe);

        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
        iframeDoc.open();
        iframeDoc.write(data.html);
        iframeDoc.close();

        // Auto-resize iframe
        setTimeout(() => {
            iframe.style.height = (iframeDoc.body.scrollHeight + 40) + 'px';
        }, 200);

        // Populate markdown tab
        mdContent.textContent = data.markdown;

    } catch (e) {
        preview.innerHTML = `<div class="report-loading">Failed to generate report: ${e.message}</div>`;
    }
}

function switchReportTab(tab) {
    document.querySelectorAll('.report-tab').forEach(t => t.classList.remove('active'));

    if (tab === 'preview') {
        document.getElementById('report-preview').style.display = 'block';
        document.getElementById('report-markdown').style.display = 'none';
        document.querySelector('.report-tab:first-child').classList.add('active');
    } else {
        document.getElementById('report-preview').style.display = 'none';
        document.getElementById('report-markdown').style.display = 'block';
        document.querySelector('.report-tab:last-child').classList.add('active');
    }
}

async function downloadReport(format) {
    if (!state.modelId) return;

    try {
        const res = await fetch(`/api/report/${format}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model_id: state.modelId })
        });

        const blob = await res.blob();
        const ext = format === 'markdown' ? 'md' : 'html';
        const filename = `threat_model_${document.getElementById('sys-name').value.replace(/\s+/g, '_')}.${ext}`;

        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.click();
        URL.revokeObjectURL(link.href);
    } catch (e) {
        console.error('Download failed:', e);
    }
}

// ==================== UTILITIES ====================
function startOver() {
    state.modelId = null;
    state.threats = [];
    state.riskSummary = null;
    state.selectedTemplate = null;
    state.selectedDomain = 'general';
    state.tags = { tech: [], component: [] };
    state.reportData = null;

    // Reset form fields
    document.getElementById('sys-name').value = '';
    document.getElementById('sys-desc').value = '';
    document.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
    document.querySelectorAll('input[name="sensitivity"]').forEach(r => r.checked = r.value === 'Internal');
    document.querySelectorAll('input[name="exposure"]').forEach(r => r.checked = r.value === 'Internet-Facing');
    document.getElementById('data-flows-list').innerHTML = '';
    document.getElementById('trust-boundaries-list').innerHTML = '';
    document.getElementById('crown-jewels-list').innerHTML = '';
    document.getElementById('workflows-list').innerHTML = '';
    document.getElementById('user-roles-list').innerHTML = '';

    // Reset domain selection
    document.querySelectorAll('#domain-grid .template-card').forEach(c => c.classList.remove('selected'));
    document.querySelector('#domain-grid .template-card[data-domain="general"]').classList.add('selected');

    renderTags('tech');
    renderTags('component');

    // Reset nav
    document.querySelectorAll('.step-item').forEach(item => {
        item.classList.remove('active', 'completed');
    });
    document.querySelectorAll('.step-connector').forEach(c => c.classList.remove('active'));

    goToStep(1);
    document.querySelector('.step-item[data-step="1"]').classList.add('active');
}
