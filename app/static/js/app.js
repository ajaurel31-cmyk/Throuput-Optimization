/**
 * Network Throughput Bottleneck Analyzer — Frontend
 */

// ========================================
// State
// ========================================
const state = {
    devices: [],
    report: null,
    claudeAnalysis: null,
    settings: {
        linkSpeedGbps: 10,
        siteA: 'ATL',
        siteB: 'PHX',
    },
};

// Device role definitions — the actual traffic path
// Servers connect to core switches, not edge switches
const DEVICE_ROLES = [
    { id: 'source_server',       label: 'Source Server',       icon: '&#x1F5A5;', site: 'local' },
    { id: 'core_switch_local',   label: 'Core Switch (Local)', icon: '&#x1F501;', site: 'local' },
    { id: 'firewall_local',      label: 'Firewall (Local)',    icon: '&#x1F6E1;', site: 'local' },
    { id: 'edge_switch_local',   label: 'Edge Switch (Local)', icon: '&#x1F310;', site: 'local' },
    { id: 'edge_switch_remote',  label: 'Edge Switch (Remote)',icon: '&#x1F310;', site: 'remote' },
    { id: 'firewall_remote',     label: 'Firewall (Remote)',   icon: '&#x1F6E1;', site: 'remote' },
    { id: 'core_switch_remote',  label: 'Core Switch (Remote)',icon: '&#x1F501;', site: 'remote' },
    { id: 'target_server',       label: 'Target Server',       icon: '&#x1F5A5;', site: 'remote' },
];

// ========================================
// Tab Navigation
// ========================================
function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabId}"]`).classList.add('active');
    document.getElementById(`tab-${tabId}`).classList.add('active');
}

// ========================================
// Network Path Visualization
// ========================================
function renderNetworkPath() {
    const container = document.getElementById('network-path');
    container.innerHTML = '';

    DEVICE_ROLES.forEach((role, index) => {
        // Add WAN link indicator between local edge and remote edge
        if (index === 4) {
            const wan = document.createElement('div');
            wan.className = 'path-link wan';
            wan.innerHTML = `<span class="path-link-label">${state.settings.linkSpeedGbps}G WAN</span>`;
            container.appendChild(wan);
        }

        // Create the node
        const node = document.createElement('div');
        node.className = 'path-node';

        // Check if device is uploaded for this role
        const device = state.devices.find(d => d.device_role === role.id);
        let iconClass = '';
        let deviceLabel = '';

        if (device) {
            iconClass = 'populated';
            deviceLabel = device.device_name;

            // Check if this device has issues in the report
            if (state.report) {
                const findings = state.report.findings.filter(f => f.device === device.device_name);
                const hasCritical = findings.some(f => f.severity === 'critical');
                const hasWarning = findings.some(f => f.severity === 'warning');
                if (hasCritical) iconClass = 'has-critical';
                else if (hasWarning) iconClass = 'has-issues';
            }
        }

        const siteLabel = role.site === 'local' ? state.settings.siteA : state.settings.siteB;

        node.innerHTML = `
            <div class="path-node-icon ${iconClass}">${role.icon}</div>
            <div class="path-node-label">${role.label.replace('Local', siteLabel).replace('Remote', state.settings.siteB)}</div>
            <div class="path-node-device">${deviceLabel}</div>
        `;
        container.appendChild(node);

        // Add link between nodes (except after last and before WAN)
        if (index < DEVICE_ROLES.length - 1 && index !== 3) {
            const link = document.createElement('div');
            link.className = 'path-link';
            container.appendChild(link);
        }
    });
}

// ========================================
// Device Upload
// ========================================
function renderDeviceRoleOptions() {
    const selects = document.querySelectorAll('.device-role-select');
    selects.forEach(select => {
        select.innerHTML = '<option value="">-- Select device role --</option>';
        DEVICE_ROLES.forEach(role => {
            const siteLabel = role.site === 'local' ? state.settings.siteA : state.settings.siteB;
            const label = role.label.replace('Local', siteLabel).replace('Remote', state.settings.siteB);
            select.innerHTML += `<option value="${role.id}">${label}</option>`;
        });
    });
}

function toggleConfigView() {
    const textEl = document.getElementById('ssh-preview-text');
    const preEl = document.getElementById('ssh-preview-pre');
    const btn = document.getElementById('ssh-preview-toggle');
    state._sshConfigExpanded = !state._sshConfigExpanded;
    if (state._sshConfigExpanded) {
        textEl.textContent = state._sshConfigFull;
        preEl.style.maxHeight = '80vh';
        preEl.tabIndex = 0;
        preEl.focus();
        btn.textContent = 'Collapse';
    } else {
        textEl.textContent = state._sshConfigPreview;
        preEl.style.maxHeight = '200px';
        btn.textContent = 'View Full Config';
    }
}

async function sshFetchConfig() {
    const host = document.getElementById('ssh-host').value.trim();
    const port = parseInt(document.getElementById('ssh-port').value) || 22;
    const username = document.getElementById('ssh-username').value.trim();
    const password = document.getElementById('ssh-password').value;
    const deviceType = document.getElementById('ssh-device-type').value;
    const deviceRole = document.getElementById('ssh-device-role').value;
    const deviceName = document.getElementById('ssh-device-name').value.trim();
    const statusEl = document.getElementById('ssh-status');
    const previewEl = document.getElementById('ssh-preview');

    if (!host) { alert('Enter the device IP address or hostname'); return; }
    if (!username) { alert('Enter the SSH username'); return; }
    if (!password) { alert('Enter the SSH password'); return; }
    if (!deviceRole) { alert('Select the device role in the network path'); return; }

    showLoading(`Connecting to ${host} via SSH...`);
    statusEl.textContent = 'Connecting...';
    previewEl.style.display = 'none';

    try {
        const resp = await fetch('/api/ssh-fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host, port, username, password,
                device_type: deviceType,
                device_role: deviceRole,
                device_name: deviceName,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Failed: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            alert(`SSH Error: ${data.error}`);
            return;
        }

        // Success
        statusEl.textContent = `Connected! Detected: ${data.device.detected_type} | Vendor: ${data.device.vendor} | ${data.device.interface_count} interfaces`;
        statusEl.style.color = 'var(--success)';

        // Show config preview
        if (data.config_preview) {
            state._sshConfigPreview = data.config_preview;
            state._sshConfigFull = data.config_full || data.config_preview;
            state._sshConfigExpanded = false;
            document.getElementById('ssh-preview-text').textContent = data.config_preview;
            document.getElementById('ssh-preview-toggle').textContent = 'View Full Config';
            previewEl.style.display = 'block';
        }

        // Add to device list
        state.devices.push(data.device);
        renderDeviceList();
        renderNetworkPath();

        // Clear password for security
        document.getElementById('ssh-password').value = '';

        if (data.device.warnings && data.device.warnings.length > 0) {
            showAlert(`Parser warnings for ${data.device.device_name}: ${data.device.warnings.join('; ')}`, 'warning');
        }

        showAlert(`Config fetched from ${host} (${data.device.vendor})`, 'success');
    } catch (e) {
        statusEl.textContent = `Connection failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
        alert(`SSH fetch failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('file-input');
    const deviceName = document.getElementById('file-device-name').value.trim();
    const deviceRole = document.getElementById('file-device-role').value;

    if (!fileInput.files.length) {
        alert('Please select a config file');
        return;
    }
    if (!deviceRole) {
        alert('Please select the device role in the network path');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('device_name', deviceName || fileInput.files[0].name);
    formData.append('device_role', deviceRole);

    showLoading('Parsing configuration...');

    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            alert(`Error: ${data.error}`);
            return;
        }

        state.devices.push(data.device);
        renderDeviceList();
        renderNetworkPath();
        fileInput.value = '';
        document.getElementById('file-device-name').value = '';

        if (data.device.warnings && data.device.warnings.length > 0) {
            showAlert(`Parser warnings for ${data.device.device_name}: ${data.device.warnings.join('; ')}`, 'warning');
        }
    } catch (e) {
        alert(`Upload failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function uploadText() {
    const configText = document.getElementById('paste-config').value.trim();
    const deviceName = document.getElementById('paste-device-name').value.trim();
    const deviceRole = document.getElementById('paste-device-role').value;

    if (!configText) {
        alert('Please paste the device configuration');
        return;
    }
    if (!deviceRole) {
        alert('Please select the device role in the network path');
        return;
    }

    showLoading('Parsing configuration...');

    try {
        const resp = await fetch('/api/upload-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                config_text: configText,
                device_name: deviceName || 'Pasted Config',
                device_role: deviceRole,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Error: ${data.error}`);
            return;
        }

        state.devices.push(data.device);
        renderDeviceList();
        renderNetworkPath();
        document.getElementById('paste-config').value = '';
        document.getElementById('paste-device-name').value = '';
    } catch (e) {
        alert(`Upload failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function deleteDevice(fileId) {
    try {
        await fetch(`/api/devices/${fileId}`, { method: 'DELETE' });
        state.devices = state.devices.filter(d => d.file_id !== fileId);
        renderDeviceList();
        renderNetworkPath();
    } catch (e) {
        alert(`Delete failed: ${e.message}`);
    }
}

async function clearAllDevices() {
    if (!confirm('Remove all uploaded configs?')) return;
    try {
        await fetch('/api/clear', { method: 'POST' });
        state.devices = [];
        state.report = null;
        state.claudeAnalysis = null;
        renderDeviceList();
        renderNetworkPath();
        renderResults();
    } catch (e) {
        alert(`Clear failed: ${e.message}`);
    }
}

function renderDeviceList() {
    const list = document.getElementById('device-list');
    const count = document.getElementById('device-count');
    count.textContent = state.devices.length;

    if (state.devices.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">&#x1F4E4;</div>
                <div class="empty-state-text">
                    No configs uploaded yet. Upload your switch, firewall, and server
                    configs to start the analysis.
                </div>
            </div>`;
        return;
    }

    list.innerHTML = state.devices.map(d => {
        const role = DEVICE_ROLES.find(r => r.id === d.device_role);
        const roleLabel = role ? role.label : d.device_role;
        const vendorClass = `vendor-${d.vendor || 'unknown'}`;

        return `
            <div class="device-item">
                <div class="device-info">
                    <span class="device-vendor-badge ${vendorClass}">${d.vendor || '?'}</span>
                    <div>
                        <div class="device-name">${escapeHtml(d.device_name)}</div>
                        <div class="device-role">${roleLabel} &middot; ${d.interface_count || 0} interfaces</div>
                    </div>
                </div>
                <button class="device-delete" onclick="deleteDevice('${d.file_id}')" title="Remove">&#x2715;</button>
            </div>`;
    }).join('');
}

// ========================================
// Analysis
// ========================================
async function runAnalysis() {
    if (state.devices.length === 0) {
        alert('Upload at least one device config first');
        return;
    }

    showLoading('Running bottleneck analysis...');

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                link_speed_gbps: state.settings.linkSpeedGbps,
                site_a: state.settings.siteA,
                site_b: state.settings.siteB,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Analysis error: ${data.error}`);
            return;
        }

        state.report = data.report;
        renderResults();
        renderNetworkPath();
        switchTab('results');
    } catch (e) {
        alert(`Analysis failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function runClaudeAnalysis() {
    if (state.devices.length === 0) {
        alert('Upload at least one device config first');
        return;
    }

    showLoading('Sending configs to Claude for deep analysis... This may take 30-60 seconds.');

    try {
        const resp = await fetch('/api/analyze-claude', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                link_speed_gbps: state.settings.linkSpeedGbps,
                site_a: state.settings.siteA,
                site_b: state.settings.siteB,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Analysis error: ${data.error}`);
            return;
        }

        state.report = data.report;
        state.claudeAnalysis = data.claude_analysis;
        renderResults();
        renderNetworkPath();
        switchTab('results');
    } catch (e) {
        alert(`Claude analysis failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

// ========================================
// Results Rendering
// ========================================
function renderResults() {
    const container = document.getElementById('results-container');

    if (!state.report) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">&#x1F50D;</div>
                <div class="empty-state-text">
                    Upload your device configs and click "Run Analysis" to find
                    throughput bottlenecks.
                </div>
            </div>`;
        return;
    }

    const r = state.report;
    const pct = r.max_theoretical_mbps > 0
        ? Math.round((r.estimated_bottleneck_mbps / r.max_theoretical_mbps) * 100)
        : 0;
    const barClass = pct < 30 ? 'low' : pct < 70 ? 'medium' : 'high';
    const riskClass = `risk-${r.overall_risk}`;

    let html = `
        <!-- Stats -->
        <div class="stats-bar">
            <div class="stat-card">
                <div class="stat-value critical">${r.stats.critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value warning">${r.stats.warning}</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value info">${r.stats.info}</div>
                <div class="stat-label">Info</div>
            </div>
            <div class="stat-card">
                <div class="stat-value success">${r.estimated_bottleneck_mbps}</div>
                <div class="stat-label">Est. Throughput (Mbps)</div>
            </div>
        </div>

        <!-- Throughput Gauge -->
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">Estimated Effective Throughput</div>
                    <div class="card-subtitle">Based on config analysis — actual throughput may vary</div>
                </div>
                <span class="risk-badge ${riskClass}">${r.overall_risk} risk</span>
            </div>
            <div class="throughput-gauge">
                <div class="throughput-bar ${barClass}" style="width: ${Math.max(pct, 5)}%">
                    ${r.estimated_bottleneck_mbps} Mbps
                </div>
            </div>
            <div class="throughput-labels">
                <span>0 Mbps</span>
                <span>Current: ~400 Mbps (50 MB/s)</span>
                <span>${r.max_theoretical_mbps} Mbps (${state.settings.linkSpeedGbps}G max)</span>
            </div>
        </div>

        <!-- Summary -->
        <div class="card">
            <div class="card-title">Analysis Summary</div>
            <div class="summary-box">${escapeHtml(r.summary)}</div>
        </div>

        <!-- Findings -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">Findings (${r.findings.length})</div>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-secondary" onclick="filterFindings('all')">All</button>
                    <button class="btn btn-secondary" onclick="filterFindings('critical')">Critical</button>
                    <button class="btn btn-secondary" onclick="filterFindings('warning')">Warning</button>
                </div>
            </div>
            <div id="findings-list">
                ${renderFindings(r.findings)}
            </div>
        </div>
    `;

    // Claude Analysis section
    if (state.claudeAnalysis) {
        if (state.claudeAnalysis.status === 'success') {
            html += `
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">Claude Deep Analysis</div>
                            <div class="card-subtitle">
                                Model: ${state.claudeAnalysis.model || 'claude'} &middot;
                                Tokens: ${state.claudeAnalysis.usage?.input_tokens || '?'} in / ${state.claudeAnalysis.usage?.output_tokens || '?'} out
                            </div>
                        </div>
                    </div>
                    <div class="claude-analysis">${formatClaudeResponse(state.claudeAnalysis.analysis)}</div>
                </div>`;
        } else {
            html += `
                <div class="alert alert-warning">
                    Claude Analysis: ${state.claudeAnalysis.message || 'Not available'}
                </div>`;
        }
    }

    container.innerHTML = html;

    // Show the interactive chat section
    showChatSection();
}

function renderFindings(findings) {
    if (findings.length === 0) {
        return '<div class="empty-state"><div class="empty-state-text">No issues found. Your config looks clean.</div></div>';
    }

    // Sort: critical first, then warning, then info
    const order = { critical: 0, warning: 1, info: 2 };
    const sorted = [...findings].sort((a, b) => (order[a.severity] || 3) - (order[b.severity] || 3));

    return sorted.map(f => `
        <div class="finding ${f.severity}" data-severity="${f.severity}">
            <div class="finding-header">
                <span class="finding-severity severity-${f.severity}">${f.severity}</span>
                <span class="finding-category">${f.category}</span>
                <span class="finding-device">${escapeHtml(f.device)}</span>
            </div>
            <div class="finding-title">${escapeHtml(f.title)}</div>
            <div class="finding-detail">${escapeHtml(f.detail)}</div>
            <div class="finding-recommendation">${escapeHtml(f.recommendation)}</div>
        </div>
    `).join('');
}

function filterFindings(severity) {
    const findings = document.querySelectorAll('.finding');
    findings.forEach(f => {
        if (severity === 'all' || f.dataset.severity === severity) {
            f.style.display = '';
        } else {
            f.style.display = 'none';
        }
    });
}

function formatClaudeResponse(text) {
    if (!text) return '';
    // Basic markdown-like formatting
    let html = escapeHtml(text);
    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Headers
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    // Code blocks
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    // List items
    html = html.replace(/^- (.+)$/gm, '&bull; $1');
    return html;
}

// ========================================
// Interactive Chat
// ========================================
state.chatHistory = [];  // {role, content} pairs for Claude API
state.chatVisible = false;

function showChatSection() {
    const section = document.getElementById('chat-section');
    if (section) {
        section.style.display = '';
        state.chatVisible = true;
    }
}

function clearChat() {
    state.chatHistory = [];
    const container = document.getElementById('chat-messages');
    if (container) container.innerHTML = '';
    // Re-show suggestions
    const suggestions = document.querySelector('.chat-suggestions');
    if (suggestions) suggestions.style.display = '';
}

function askSuggestion(btn) {
    const text = btn.textContent.trim();
    document.getElementById('chat-input').value = text;
    sendChatMessage();
}

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message) return;

    input.value = '';
    input.disabled = true;
    document.getElementById('chat-send-btn').disabled = true;

    // Hide suggestions after first message
    const suggestions = document.querySelector('.chat-suggestions');
    if (suggestions) suggestions.style.display = 'none';

    // Add user message to UI
    appendChatBubble('user', message);

    // Add typing indicator
    const typingId = appendChatBubble('assistant', '', true);

    try {
        const resp = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: message,
                history: state.chatHistory,
                link_speed_gbps: state.settings.linkSpeedGbps,
                site_a: state.settings.siteA,
                site_b: state.settings.siteB,
            }),
        });
        const data = await resp.json();

        // Remove typing indicator
        removeChatBubble(typingId);

        if (data.status === 'success') {
            // Update conversation history for context continuity
            state.chatHistory.push({ role: 'user', content: message });
            state.chatHistory.push({ role: 'assistant', content: data.reply });

            appendChatBubble('assistant', data.reply);
        } else {
            appendChatBubble('assistant',
                'Error: ' + (data.message || 'Failed to get a response. Check your API key.'));
        }
    } catch (e) {
        removeChatBubble(typingId);
        appendChatBubble('assistant', 'Connection error: ' + e.message);
    } finally {
        input.disabled = false;
        document.getElementById('chat-send-btn').disabled = false;
        input.focus();
    }
}

function appendChatBubble(role, content, isTyping) {
    const container = document.getElementById('chat-messages');
    const bubble = document.createElement('div');
    const id = 'chat-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
    bubble.id = id;
    bubble.className = 'chat-bubble chat-' + role;

    if (isTyping) {
        bubble.innerHTML = '<div class="chat-typing"><span></span><span></span><span></span></div>';
    } else if (role === 'assistant') {
        bubble.innerHTML = formatClaudeResponse(content);
    } else {
        bubble.textContent = content;
    }

    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
    return id;
}

function removeChatBubble(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
}

// Send on Enter (Shift+Enter for newline)
document.addEventListener('keydown', function(e) {
    if (e.target.id === 'chat-input' && e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
    }
});

// ========================================
// Diagnostics
// ========================================
function getDiagTarget() {
    return document.getElementById('diag-target').value.trim();
}

function getDiagLinkSpeed() {
    return parseFloat(document.getElementById('diag-link-speed').value) || 10;
}

function getSelectedTests() {
    const checkboxes = document.querySelectorAll('.diag-test-chips input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

async function runDiagnostics() {
    const target = getDiagTarget();
    if (!target) {
        alert('Enter a target host (IP address or hostname)');
        return;
    }

    const tests = getSelectedTests();
    if (tests.length === 0) {
        alert('Select at least one diagnostic test');
        return;
    }

    showLoading('Running network diagnostics... This may take up to 2 minutes.');

    try {
        const resp = await fetch('/api/diagnostics/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                link_speed_gbps: getDiagLinkSpeed(),
                tests: tests,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Diagnostic error: ${data.error}`);
            return;
        }

        renderDiagResults(data.report);
    } catch (e) {
        alert(`Diagnostics failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function runQuickPing() {
    const target = getDiagTarget();
    if (!target) {
        alert('Enter a target host');
        return;
    }

    showLoading('Pinging ' + target + '...');

    try {
        const resp = await fetch('/api/diagnostics/ping', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, count: 5 }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Ping error: ${data.error}`);
            return;
        }

        renderDiagResults({
            target: target,
            results: [data.result],
            overall_health: data.result.status === 'pass' ? 'healthy' : data.result.status === 'warning' ? 'degraded' : 'critical',
            health_score: data.result.status === 'pass' ? 100 : data.result.status === 'warning' ? 60 : 0,
            summary: data.result.summary,
            timestamp: new Date().toISOString(),
        });
    } catch (e) {
        alert(`Ping failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function runQuickTrace() {
    const target = getDiagTarget();
    if (!target) {
        alert('Enter a target host');
        return;
    }

    showLoading('Running traceroute to ' + target + '... This may take up to a minute.');

    try {
        const resp = await fetch('/api/diagnostics/traceroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, max_hops: 20 }),
        });
        const data = await resp.json();

        if (data.error) {
            alert(`Traceroute error: ${data.error}`);
            return;
        }

        renderDiagResults({
            target: target,
            results: [data.result],
            overall_health: data.result.status === 'pass' ? 'healthy' : 'degraded',
            health_score: data.result.status === 'pass' ? 100 : 50,
            summary: data.result.summary,
            timestamp: new Date().toISOString(),
        });
    } catch (e) {
        alert(`Traceroute failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

function renderDiagResults(report) {
    const container = document.getElementById('diag-results');
    if (!report || !report.results || report.results.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">&#x1F50C;</div>
                <div class="empty-state-text">No diagnostic results yet.</div>
            </div>`;
        return;
    }

    const healthClass = {
        healthy: 'health-healthy',
        degraded: 'health-degraded',
        impaired: 'health-impaired',
        critical: 'health-critical',
    }[report.overall_health] || 'health-unknown';

    const scoreBarClass = report.health_score >= 80 ? 'high' : report.health_score >= 50 ? 'medium' : 'low';

    let html = `
        <!-- Health Overview -->
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">Diagnostic Report: ${escapeHtml(report.target)}</div>
                    <div class="card-subtitle">${report.timestamp || ''}</div>
                </div>
                <span class="health-badge ${healthClass}">${report.overall_health}</span>
            </div>
            <div class="diag-health-bar-container">
                <div class="diag-health-label">Health Score</div>
                <div class="throughput-gauge">
                    <div class="throughput-bar ${scoreBarClass}" style="width: ${Math.max(report.health_score, 5)}%">
                        ${report.health_score}/100
                    </div>
                </div>
            </div>
            <div class="summary-box">${escapeHtml(report.summary)}</div>
        </div>

        <!-- Individual Test Results -->
    `;

    for (const result of report.results) {
        const statusIcon = {
            pass: '&#x2705;',
            warning: '&#x26A0;',
            fail: '&#x274C;',
            error: '&#x26D4;',
        }[result.status] || '&#x2753;';

        html += `
        <div class="card diag-result-card diag-status-${result.status}">
            <div class="card-header" onclick="toggleDiagDetail(this)">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <span class="diag-status-icon">${statusIcon}</span>
                    <div>
                        <div class="card-title">${escapeHtml(result.test_name)}</div>
                        <div class="card-subtitle">${escapeHtml(result.summary)}</div>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <span class="diag-duration">${result.duration_ms > 0 ? result.duration_ms.toFixed(0) + 'ms' : ''}</span>
                    <span class="diag-expand-icon">&#x25BC;</span>
                </div>
            </div>
            <div class="diag-detail" style="display: none;">
        `;

        // Render test-specific details
        html += renderTestDetails(result);

        // Recommendations
        if (result.recommendations && result.recommendations.length > 0) {
            html += `<div class="diag-recommendations">
                <div class="diag-rec-title">Recommendations</div>`;
            for (const rec of result.recommendations) {
                html += `<div class="diag-rec-item">${escapeHtml(rec)}</div>`;
            }
            html += `</div>`;
        }

        html += `</div></div>`;
    }

    container.innerHTML = html;
}

function renderTestDetails(result) {
    const d = result.details || {};
    let html = '';

    switch (result.test_name) {
        case 'DNS Resolution':
            if (d.ipv4_addresses) {
                html += `<div class="diag-detail-grid">
                    <div class="diag-detail-item"><span class="diag-detail-label">IPv4</span><span class="diag-detail-value">${d.ipv4_addresses.join(', ') || 'None'}</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">IPv6</span><span class="diag-detail-value">${(d.ipv6_addresses || []).join(', ') || 'None'}</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Resolution Time</span><span class="diag-detail-value">${d.resolution_time_ms}ms</span></div>
                </div>`;
            }
            break;

        case 'ICMP Ping':
            if (d.avg_rtt !== undefined) {
                html += `<div class="diag-detail-grid">
                    <div class="diag-detail-item"><span class="diag-detail-label">Min RTT</span><span class="diag-detail-value">${d.min_rtt}ms</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Avg RTT</span><span class="diag-detail-value">${d.avg_rtt}ms</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Max RTT</span><span class="diag-detail-value">${d.max_rtt}ms</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Jitter</span><span class="diag-detail-value">${d.jitter}ms</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Packet Loss</span><span class="diag-detail-value">${d.packet_loss}%</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Transmitted</span><span class="diag-detail-value">${d.transmitted}</span></div>
                </div>`;
            }
            break;

        case 'Traceroute':
            if (d.hops && d.hops.length > 0) {
                html += `<div class="diag-traceroute-table"><table>
                    <thead><tr><th>Hop</th><th>IP</th><th>RTT (ms)</th><th>Visual</th></tr></thead><tbody>`;
                let maxRtt = 1;
                for (const h of d.hops) {
                    if (h.avg_rtt > maxRtt) maxRtt = h.avg_rtt;
                }
                for (const h of d.hops) {
                    const barWidth = h.avg_rtt > 0 ? Math.max((h.avg_rtt / maxRtt) * 100, 3) : 0;
                    const barClass = h.avg_rtt > 100 ? 'rtt-high' : h.avg_rtt > 30 ? 'rtt-medium' : 'rtt-low';
                    html += `<tr>
                        <td>${h.hop}</td>
                        <td class="mono">${h.ip}</td>
                        <td class="mono">${h.avg_rtt > 0 ? h.avg_rtt.toFixed(1) : '*'}</td>
                        <td><div class="rtt-bar-container"><div class="rtt-bar ${barClass}" style="width:${barWidth}%"></div></div></td>
                    </tr>`;
                }
                html += `</tbody></table></div>`;
            }
            break;

        case 'MTU Path Discovery':
            if (d.probes) {
                html += `<div class="diag-detail-grid">
                    <div class="diag-detail-item"><span class="diag-detail-label">Path MTU</span><span class="diag-detail-value">${d.path_mtu} bytes</span></div>
                </div>`;
                html += `<div class="diag-mtu-probes"><div class="diag-rec-title">Probes</div>`;
                for (const p of d.probes) {
                    const icon = p.success ? '&#x2705;' : '&#x274C;';
                    html += `<span class="diag-mtu-probe ${p.success ? 'probe-pass' : 'probe-fail'}">${icon} ${p.mtu}</span>`;
                }
                html += `</div>`;
            }
            break;

        case 'TCP Port Scan':
            if (d.ports) {
                html += `<div class="diag-ports-grid">`;
                for (const p of d.ports) {
                    const portClass = p.state === 'open' ? 'port-open' : p.state === 'closed' ? 'port-closed' : 'port-filtered';
                    html += `<div class="diag-port-item ${portClass}">
                        <div class="diag-port-num">${p.port}</div>
                        <div class="diag-port-service">${p.service}</div>
                        <div class="diag-port-state">${p.state}</div>
                    </div>`;
                }
                html += `</div>`;
            }
            break;

        case 'Bandwidth-Delay Product':
            if (d.bdp_mb !== undefined) {
                html += `<div class="diag-detail-grid">
                    <div class="diag-detail-item"><span class="diag-detail-label">RTT</span><span class="diag-detail-value">${d.rtt_ms}ms</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Link Speed</span><span class="diag-detail-value">${d.link_speed_gbps} Gbps</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">BDP</span><span class="diag-detail-value">${d.bdp_mb} MB</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">TCP Buffer (recommended)</span><span class="diag-detail-value">${(d.recommended_tcp_buffer / 1048576).toFixed(1)} MB</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Max (default window)</span><span class="diag-detail-value">${d.max_single_stream_default_mbps} Mbps</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Max (tuned window)</span><span class="diag-detail-value">${d.max_single_stream_tuned_mbps} Mbps</span></div>
                </div>`;
            }
            break;

        case 'Path Analysis':
            if (d.hops && d.hops.length > 0) {
                html += `<div class="diag-detail-grid">
                    <div class="diag-detail-item"><span class="diag-detail-label">Total Hops</span><span class="diag-detail-value">${d.total_hops}</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Responding</span><span class="diag-detail-value">${d.responding_hops}</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Path Health</span><span class="diag-detail-value">${d.path_health}</span></div>
                    <div class="diag-detail-item"><span class="diag-detail-label">Probes/Hop</span><span class="diag-detail-value">${d.rounds}</span></div>
                </div>`;
                if (d.worst_hop) {
                    html += `<div class="alert alert-warning" style="margin: 0.75rem 0;">
                        <strong>Worst hop:</strong> Hop ${d.worst_hop.hop} (${escapeHtml(d.worst_hop.ip)}) &mdash; ${d.worst_hop.loss_percent}% loss
                    </div>`;
                }
                html += `<div class="pa-table-container"><table class="pa-table">
                    <thead><tr><th>Hop</th><th>IP</th><th>Loss</th><th>Avg RTT</th><th>Visual</th></tr></thead><tbody>`;
                for (const h of d.hops) {
                    const lossBarWidth = Math.max(h.loss_percent, 0);
                    const lossBarClass = h.loss_percent > 20 ? 'pa-loss-high' : h.loss_percent > 0 ? 'pa-loss-medium' : 'pa-loss-none';
                    html += `<tr class="${h.loss_percent > 20 ? 'pa-row-critical' : h.loss_percent > 0 ? 'pa-row-warning' : ''}">
                        <td>${h.hop}</td>
                        <td class="mono">${escapeHtml(h.ip)}</td>
                        <td class="mono">${h.ip === '*' ? '*' : h.loss_percent.toFixed(1) + '%'}</td>
                        <td class="mono">${h.avg_rtt > 0 ? h.avg_rtt.toFixed(1) : '*'}</td>
                        <td><div class="pa-loss-bar-container"><div class="pa-loss-bar ${lossBarClass}" style="width:${h.ip === '*' ? 100 : lossBarWidth}%"></div></div></td>
                    </tr>`;
                }
                html += `</tbody></table></div>`;
            }
            break;
    }

    return html;
}

// ========================================
// Path Analysis (MTR-style)
// ========================================
async function runPathAnalysis() {
    const target = document.getElementById('pa-target').value.trim();
    if (!target) {
        alert('Enter a target host (IP address or hostname)');
        return;
    }

    const sourceIp = document.getElementById('pa-source').value.trim();
    const rounds = parseInt(document.getElementById('pa-rounds').value) || 10;
    const maxHops = parseInt(document.getElementById('pa-max-hops').value) || 20;
    const statusEl = document.getElementById('pa-status');

    const estimatedTime = Math.round((rounds * maxHops * 0.5) + 15);
    statusEl.textContent = 'Probing path...';
    statusEl.style.color = 'var(--text-secondary)';
    showLoading(`Running path analysis to ${target}... This may take up to ${estimatedTime} seconds.`);

    try {
        const resp = await fetch('/api/diagnostics/path-analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                source_ip: sourceIp || undefined,
                rounds: rounds,
                max_hops: maxHops,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Error: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            alert(`Path Analysis Error: ${data.error}`);
            return;
        }

        statusEl.textContent = 'Analysis complete!';
        statusEl.style.color = 'var(--success)';
        renderPathAnalysis(data.result);
    } catch (e) {
        statusEl.textContent = `Failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
        alert(`Path analysis failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

function renderPathAnalysis(result) {
    const container = document.getElementById('pa-results');
    if (!result) {
        container.innerHTML = '';
        return;
    }

    const d = result.details || {};
    const hops = d.hops || [];
    const problemHops = d.problem_hops || [];
    const worstHop = d.worst_hop;
    const pathHealth = d.path_health || 'unknown';

    const healthClass = {
        healthy: 'health-healthy',
        degraded: 'health-degraded',
        impaired: 'health-impaired',
        critical: 'health-critical',
    }[pathHealth] || 'health-unknown';

    const statusIcon = {
        pass: '&#x2705;',
        warning: '&#x26A0;',
        fail: '&#x274C;',
        error: '&#x26D4;',
    }[result.status] || '&#x2753;';

    let html = '';

    // Header card with summary
    html += `
    <div class="card">
        <div class="card-header">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <span style="font-size: 1.25rem;">${statusIcon}</span>
                <div>
                    <div class="card-title">Path Analysis: ${escapeHtml(d.target || '')}</div>
                    <div class="card-subtitle">
                        ${d.total_hops || 0} hops discovered, ${d.responding_hops || 0} responding
                        ${d.source_ip ? ' | Source: ' + escapeHtml(d.source_ip) : ''}
                        ${d.tool ? ' | Tool: ' + d.tool : ''}
                        | ${d.rounds || 0} probes/hop
                    </div>
                </div>
            </div>
            <span class="health-badge ${healthClass}">${pathHealth}</span>
        </div>
        <div class="summary-box">${escapeHtml(result.summary)}</div>
    </div>`;

    // Worst hop callout
    if (worstHop) {
        html += `
        <div class="alert alert-warning">
            <strong>Worst hop:</strong> Hop ${worstHop.hop} (${escapeHtml(worstHop.ip)}) &mdash; ${worstHop.loss_percent}% packet loss
        </div>`;
    }

    // Per-hop table
    if (hops.length > 0) {
        html += `
        <div class="card">
            <div class="card-title">Per-Hop Results</div>
            <div class="pa-table-container">
                <table class="pa-table">
                    <thead>
                        <tr>
                            <th>Hop</th>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Loss</th>
                            <th>Sent</th>
                            <th>Recv</th>
                            <th>Avg (ms)</th>
                            <th>Min (ms)</th>
                            <th>Max (ms)</th>
                            <th>StDev</th>
                            <th>Delta</th>
                            <th>Loss Visual</th>
                        </tr>
                    </thead>
                    <tbody>`;

        for (const h of hops) {
            const isProblem = problemHops.some(p => p.hop === h.hop);
            const rowClass = h.status === 'timeout' ? 'pa-row-timeout' :
                             h.loss_percent > 20 ? 'pa-row-critical' :
                             h.loss_percent > 0 ? 'pa-row-warning' :
                             isProblem ? 'pa-row-warning' : '';

            const lossBarWidth = Math.max(h.loss_percent, 0);
            const lossBarClass = h.loss_percent > 20 ? 'pa-loss-high' :
                                 h.loss_percent > 0 ? 'pa-loss-medium' : 'pa-loss-none';

            const delta = h.latency_delta !== undefined ? h.latency_delta : '';
            const deltaClass = delta > 50 ? 'pa-delta-high' : delta > 20 ? 'pa-delta-medium' : '';

            html += `
                <tr class="${rowClass}">
                    <td class="mono">${h.hop}</td>
                    <td class="mono">${escapeHtml(h.ip)}</td>
                    <td class="pa-hostname">${h.hostname && h.hostname !== h.ip ? escapeHtml(h.hostname) : ''}</td>
                    <td class="mono ${h.loss_percent > 0 ? 'pa-loss-text' : ''}">${h.ip === '*' ? '*' : h.loss_percent.toFixed(1) + '%'}</td>
                    <td class="mono">${h.ip === '*' ? '' : h.sent}</td>
                    <td class="mono">${h.ip === '*' ? '' : h.received}</td>
                    <td class="mono">${h.avg_rtt > 0 ? h.avg_rtt.toFixed(1) : '*'}</td>
                    <td class="mono">${h.min_rtt > 0 ? h.min_rtt.toFixed(1) : '*'}</td>
                    <td class="mono">${h.max_rtt > 0 ? h.max_rtt.toFixed(1) : '*'}</td>
                    <td class="mono">${h.stdev > 0 ? h.stdev.toFixed(1) : '*'}</td>
                    <td class="mono ${deltaClass}">${delta !== '' && delta > 0 ? '+' + delta.toFixed(0) : delta === 0 ? '0' : ''}</td>
                    <td>
                        <div class="pa-loss-bar-container">
                            <div class="pa-loss-bar ${lossBarClass}" style="width: ${Math.max(lossBarWidth, h.ip === '*' ? 100 : 0)}%"></div>
                        </div>
                    </td>
                </tr>`;
        }

        html += `</tbody></table></div></div>`;
    }

    // Latency progression chart (text-based visualization)
    const respondingHops = hops.filter(h => h.ip !== '*' && h.avg_rtt > 0);
    if (respondingHops.length > 0) {
        const maxRtt = Math.max(...respondingHops.map(h => h.avg_rtt), 1);

        html += `
        <div class="card">
            <div class="card-title">Latency Progression</div>
            <div class="card-subtitle" style="margin-bottom: 1rem;">RTT (ms) per hop — look for sharp jumps indicating WAN segments or congestion</div>
            <div class="pa-latency-chart">`;

        for (const h of hops) {
            if (h.ip === '*') {
                html += `
                <div class="pa-latency-row">
                    <span class="pa-latency-hop">Hop ${h.hop}</span>
                    <span class="pa-latency-ip">* * *</span>
                    <div class="pa-latency-bar-outer">
                        <div class="pa-latency-bar pa-latency-timeout" style="width: 100%"></div>
                    </div>
                    <span class="pa-latency-value">timeout</span>
                </div>`;
                continue;
            }
            const barWidth = h.avg_rtt > 0 ? Math.max((h.avg_rtt / maxRtt) * 100, 2) : 0;
            const barClass = h.avg_rtt > 150 ? 'pa-latency-high' :
                             h.avg_rtt > 50 ? 'pa-latency-medium' : 'pa-latency-low';
            const lossIndicator = h.loss_percent > 0 ? ` | ${h.loss_percent}% loss` : '';

            html += `
            <div class="pa-latency-row">
                <span class="pa-latency-hop">Hop ${h.hop}</span>
                <span class="pa-latency-ip">${escapeHtml(h.ip)}</span>
                <div class="pa-latency-bar-outer">
                    <div class="pa-latency-bar ${barClass}" style="width: ${barWidth}%"></div>
                </div>
                <span class="pa-latency-value">${h.avg_rtt.toFixed(1)}ms${lossIndicator}</span>
            </div>`;
        }

        html += `</div></div>`;
    }

    // Problem hops detail
    if (problemHops.length > 0) {
        html += `
        <div class="card">
            <div class="card-title">Problem Hops Identified</div>`;

        for (const ph of problemHops) {
            html += `
            <div class="finding warning">
                <div class="finding-header">
                    <span class="finding-severity severity-warning">HOP ${ph.hop}</span>
                    <span class="finding-category">${escapeHtml(ph.ip)}</span>
                </div>
                <div class="finding-detail">${ph.issues.map(i => escapeHtml(i)).join('<br>')}</div>
            </div>`;
        }

        html += `</div>`;
    }

    // Recommendations
    if (result.recommendations && result.recommendations.length > 0) {
        html += `
        <div class="card">
            <div class="card-title">Recommendations</div>
            <div class="diag-recommendations" style="border: none; padding: 0;">`;
        for (const rec of result.recommendations) {
            html += `<div class="diag-rec-item">${escapeHtml(rec)}</div>`;
        }
        html += `</div></div>`;
    }

    container.innerHTML = html;
}

// Also add Path Analysis rendering to the generic diagnostic results renderer
function toggleDiagDetail(header) {
    const detail = header.nextElementSibling;
    const icon = header.querySelector('.diag-expand-icon');
    if (detail.style.display === 'none') {
        detail.style.display = 'block';
        icon.innerHTML = '&#x25B2;';
    } else {
        detail.style.display = 'none';
        icon.innerHTML = '&#x25BC;';
    }
}

// ========================================
// iPerf3 Bandwidth Test
// ========================================
function toggleUdpOptions() {
    const proto = document.getElementById('iperf-protocol').value;
    document.getElementById('iperf-udp-bw-group').style.display = proto === 'udp' ? '' : 'none';
}

async function runIperfTest() {
    const target = document.getElementById('iperf-target').value.trim();
    if (!target) {
        alert('Enter the target server IP address (the server running iperf3 -s)');
        return;
    }

    const port = parseInt(document.getElementById('iperf-port').value) || 5201;
    const duration = parseInt(document.getElementById('iperf-duration').value) || 10;
    const parallel = parseInt(document.getElementById('iperf-parallel').value) || 1;
    const direction = document.getElementById('iperf-direction').value;
    const protocol = document.getElementById('iperf-protocol').value;
    const udpBandwidth = document.getElementById('iperf-udp-bandwidth').value.trim() || '1G';
    const windowSize = document.getElementById('iperf-window').value.trim();
    const linkSpeed = parseFloat(document.getElementById('iperf-link-speed').value) || 10;

    const statusEl = document.getElementById('iperf-status');
    statusEl.textContent = 'Starting bandwidth test...';
    statusEl.style.color = 'var(--text-secondary)';

    showLoading(`Running iPerf3 bandwidth test to ${target}... This will take ~${duration + 5} seconds.`);

    try {
        const resp = await fetch('/api/iperf/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                port: port,
                duration: duration,
                parallel: parallel,
                reverse: direction === 'receive',
                udp: protocol === 'udp',
                udp_bandwidth: udpBandwidth,
                window_size: windowSize,
                link_speed_gbps: linkSpeed,
                source_label: state.settings.siteA,
                target_label: state.settings.siteB,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Error: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            alert(`iPerf3 Error: ${data.error}`);
            return;
        }

        statusEl.textContent = 'Test complete!';
        statusEl.style.color = 'var(--success)';
        renderIperfResults(data.report);
    } catch (e) {
        statusEl.textContent = `Failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
        alert(`iPerf3 test failed: ${e.message}`);
    } finally {
        hideLoading();
    }
}

function renderIperfResults(report) {
    const container = document.getElementById('iperf-results');
    if (!report || !report.test_result) {
        container.innerHTML = '';
        return;
    }

    const r = report.test_result;
    const pct = report.efficiency_percent;
    const barClass = pct < 30 ? 'low' : pct < 70 ? 'medium' : 'high';

    const healthClass = {
        healthy: 'health-healthy',
        degraded: 'health-degraded',
        impaired: 'health-impaired',
        critical: 'health-critical',
    }[report.health] || 'health-unknown';

    let html = '';

    // Error state
    if (r.status === 'error') {
        html += `
        <div class="card">
            <div class="card-header">
                <div class="card-title">Bandwidth Test Failed</div>
                <span class="health-badge health-critical">ERROR</span>
            </div>
            <div class="alert alert-warning">${escapeHtml(r.error_message)}</div>
            <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.8; margin-top: 1rem;">
                <strong>Troubleshooting:</strong><br>
                1. Verify iPerf3 is installed: <code>iperf3 --version</code><br>
                2. Verify the remote server is running: <code>iperf3 -s</code><br>
                3. Check firewall allows port 5201 (TCP + UDP) between the servers<br>
                4. Test connectivity: <code>Test-NetConnection -ComputerName ${escapeHtml(report.target)} -Port 5201</code>
            </div>
        </div>`;
        container.innerHTML = html;
        return;
    }

    // Throughput gauge
    html += `
    <div class="card">
        <div class="card-header">
            <div>
                <div class="card-title">Bandwidth Test Results: ${escapeHtml(report.source)} &rarr; ${escapeHtml(report.target)}</div>
                <div class="card-subtitle">${report.timestamp}</div>
            </div>
            <span class="health-badge ${healthClass}">${report.health}</span>
        </div>

        <!-- Throughput Stats -->
        <div class="iperf-stats-row">
            <div class="iperf-stat">
                <div class="iperf-stat-value ${pct >= 80 ? 'success' : pct >= 50 ? 'warning' : 'critical'}">${r.throughput_mbps.toFixed(1)}</div>
                <div class="iperf-stat-label">Mbps</div>
            </div>
            <div class="iperf-stat">
                <div class="iperf-stat-value">${r.throughput_gbps.toFixed(3)}</div>
                <div class="iperf-stat-label">Gbps</div>
            </div>
            <div class="iperf-stat">
                <div class="iperf-stat-value">${pct.toFixed(1)}%</div>
                <div class="iperf-stat-label">Efficiency</div>
            </div>`;

    if (r.protocol === 'tcp') {
        html += `
            <div class="iperf-stat">
                <div class="iperf-stat-value ${r.retransmits > 100 ? 'critical' : r.retransmits > 0 ? 'warning' : 'success'}">${r.retransmits}</div>
                <div class="iperf-stat-label">Retransmits</div>
            </div>`;
    } else {
        html += `
            <div class="iperf-stat">
                <div class="iperf-stat-value ${r.loss_percent > 5 ? 'critical' : r.loss_percent > 1 ? 'warning' : 'success'}">${r.loss_percent.toFixed(1)}%</div>
                <div class="iperf-stat-label">Packet Loss</div>
            </div>`;
    }

    html += `
        </div>

        <!-- Throughput gauge bar -->
        <div class="throughput-gauge">
            <div class="throughput-bar ${barClass}" style="width: ${Math.max(pct, 5)}%">
                ${r.throughput_mbps.toFixed(0)} Mbps
            </div>
        </div>
        <div class="throughput-labels">
            <span>0 Mbps</span>
            <span>${pct.toFixed(1)}% of link capacity</span>
            <span>${report.link_speed_gbps * 1000} Mbps (${report.link_speed_gbps}G max)</span>
        </div>
    </div>`;

    // Detailed metrics
    html += `<div class="card">
        <div class="card-title">Test Details</div>
        <div class="diag-detail-grid" style="margin-top: 1rem;">`;

    if (r.protocol === 'tcp') {
        html += `
            <div class="diag-detail-item"><span class="diag-detail-label">Protocol</span><span class="diag-detail-value">TCP</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Streams</span><span class="diag-detail-value">${r.parallel_streams}</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Duration</span><span class="diag-detail-value">${r.duration_sec.toFixed(0)}s</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Transferred</span><span class="diag-detail-value">${formatBytes(r.bytes_transferred)}</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Retransmits</span><span class="diag-detail-value">${r.retransmits}</span></div>`;

        if (r.mean_rtt_us > 0) {
            html += `
            <div class="diag-detail-item"><span class="diag-detail-label">Avg RTT</span><span class="diag-detail-value">${(r.mean_rtt_us / 1000).toFixed(1)}ms</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Min RTT</span><span class="diag-detail-value">${(r.min_rtt_us / 1000).toFixed(1)}ms</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Max RTT</span><span class="diag-detail-value">${(r.max_rtt_us / 1000).toFixed(1)}ms</span></div>`;
        }
        if (r.max_snd_cwnd > 0) {
            html += `
            <div class="diag-detail-item"><span class="diag-detail-label">Max TCP Window</span><span class="diag-detail-value">${(r.max_snd_cwnd / 1024).toFixed(0)} KB</span></div>`;
        }
    } else {
        html += `
            <div class="diag-detail-item"><span class="diag-detail-label">Protocol</span><span class="diag-detail-value">UDP</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Duration</span><span class="diag-detail-value">${r.duration_sec.toFixed(0)}s</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Jitter</span><span class="diag-detail-value">${r.jitter_ms.toFixed(3)}ms</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Packet Loss</span><span class="diag-detail-value">${r.lost_packets} / ${r.total_packets} (${r.loss_percent.toFixed(1)}%)</span></div>`;
    }

    if (r.host_cpu_total > 0) {
        html += `
            <div class="diag-detail-item"><span class="diag-detail-label">Local CPU</span><span class="diag-detail-value">${r.host_cpu_total.toFixed(0)}%</span></div>
            <div class="diag-detail-item"><span class="diag-detail-label">Remote CPU</span><span class="diag-detail-value">${r.remote_cpu_total.toFixed(0)}%</span></div>`;
    }

    html += `</div>`;

    // Per-stream breakdown (multi-stream)
    if (r.streams && r.streams.length > 1) {
        html += `
        <div style="margin-top: 1rem;">
            <div class="form-label">Per-Stream Breakdown</div>
            <div class="iperf-stream-table">
                <table>
                    <thead><tr><th>Stream</th><th>Throughput</th><th>Retransmits</th><th>RTT (avg)</th><th>Window</th></tr></thead>
                    <tbody>`;
        for (const s of r.streams) {
            html += `<tr>
                <td>#${s.stream_id}</td>
                <td class="mono">${s.throughput_mbps.toFixed(1)} Mbps</td>
                <td class="mono">${s.retransmits || 0}</td>
                <td class="mono">${s.mean_rtt ? (s.mean_rtt / 1000).toFixed(1) + 'ms' : '-'}</td>
                <td class="mono">${s.max_snd_cwnd ? (s.max_snd_cwnd / 1024).toFixed(0) + ' KB' : '-'}</td>
            </tr>`;
        }
        html += `</tbody></table></div></div>`;
    }

    html += `</div>`;

    // Bottleneck Diagnosis
    if (report.diagnoses && report.diagnoses.length > 0) {
        html += `<div class="card">
            <div class="card-header">
                <div class="card-title">Bottleneck Diagnosis</div>
            </div>`;

        for (const d of report.diagnoses) {
            const severityClass = d.severity === 'critical' ? 'critical' : d.severity === 'warning' ? 'warning' : 'info';
            html += `
            <div class="finding ${severityClass}">
                <div class="finding-header">
                    <span class="finding-severity severity-${severityClass}">${d.severity}</span>
                    <span class="finding-category">${escapeHtml(d.bottleneck_location)}</span>
                    <span class="finding-device">confidence: ${d.confidence}</span>
                </div>
                <div class="finding-title">${escapeHtml(d.title)}</div>
                <div class="finding-detail">${escapeHtml(d.detail)}</div>
                <div class="finding-recommendation">${escapeHtml(d.recommendation)}</div>
            </div>`;
        }

        html += `</div>`;
    }

    // Overall Verdict
    if (report.overall_verdict) {
        html += `
        <div class="card">
            <div class="card-title">Test Summary</div>
            <div class="summary-box">${escapeHtml(report.overall_verdict)}</div>
        </div>`;
    }

    container.innerHTML = html;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

// ========================================
// Settings
// ========================================
function updateSettings() {
    state.settings.linkSpeedGbps = parseFloat(document.getElementById('link-speed').value) || 10;
    state.settings.siteA = document.getElementById('site-a').value.trim() || 'ATL';
    state.settings.siteB = document.getElementById('site-b').value.trim() || 'PHX';
    renderNetworkPath();
    renderDeviceRoleOptions();
    showAlert('Settings updated', 'success');
}

// ========================================
// Drag & Drop
// ========================================
function setupDragDrop() {
    const zone = document.getElementById('drop-zone');
    if (!zone) return;

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            document.getElementById('file-input').files = files;
            document.getElementById('file-device-name').value = files[0].name.replace(/\.[^.]+$/, '');
        }
    });

    zone.addEventListener('click', () => {
        document.getElementById('file-input').click();
    });
}

// ========================================
// Utilities
// ========================================
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showLoading(message) {
    const overlay = document.getElementById('loading-overlay');
    overlay.querySelector('.loading-text').textContent = message || 'Working...';
    overlay.classList.add('active');
}

function hideLoading() {
    document.getElementById('loading-overlay').classList.remove('active');
}

function showAlert(message, type) {
    const container = document.getElementById('alerts');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    container.appendChild(alert);
    setTimeout(() => alert.remove(), 5000);
}

// ========================================
// Check API status
// ========================================
async function checkStatus() {
    try {
        const resp = await fetch('/api/status');
        const data = await resp.json();

        const dot = document.getElementById('claude-status-dot');
        const text = document.getElementById('claude-status-text');

        if (data.claude_available) {
            dot.className = 'status-dot active';
            text.textContent = 'Claude API Connected';
        } else {
            dot.className = 'status-dot inactive';
            text.textContent = 'Claude API Not Configured';
        }

        // Update Claude button state
        const btn = document.getElementById('btn-claude-analyze');
        if (btn) {
            btn.disabled = !data.claude_available;
            if (!data.claude_available) {
                btn.title = 'Set ANTHROPIC_API_KEY in .env to enable';
            }
        }

        // Reload device list from server
        if (data.devices_loaded > 0) {
            const devResp = await fetch('/api/devices');
            const devData = await devResp.json();
            if (devData.devices && devData.devices.length > 0) {
                state.devices = devData.devices;
                renderDeviceList();
                renderNetworkPath();
            }
        }
    } catch (e) {
        console.error('Status check failed:', e);
    }
}

// ========================================
// Packet Capture & Analysis
// ========================================
state.activeCapture = null;  // {capture_id, ...}
state.capturePolling = null; // interval ID

function switchPcapTab(tab) {
    document.querySelectorAll('.pcap-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.pcap-tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector(`.pcap-tab[onclick*="${tab}"]`).classList.add('active');
    document.getElementById(`pcap-tab-${tab}`).classList.add('active');
}

async function checkPcapTools() {
    try {
        const resp = await fetch('/api/capture/tools');
        const data = await resp.json();
        const statusEl = document.getElementById('pcap-tools-status');
        if (data.tools) {
            const parts = [];
            if (data.tools.platform === 'windows') {
                // Windows: show dumpcap/tshark/pktmon
                if (data.tools.dumpcap !== undefined) parts.push(data.tools.dumpcap ? 'dumpcap \u2705' : 'dumpcap \u274C');
                if (data.tools.tshark !== undefined) parts.push(data.tools.tshark ? 'tshark \u2705' : 'tshark \u274C');
                if (data.tools.pktmon !== undefined) parts.push(data.tools.pktmon ? 'pktmon \u2705' : 'pktmon \u274C');
            } else {
                // Linux: show tcpdump/tshark
                if (data.tools.tcpdump !== undefined) parts.push(data.tools.tcpdump ? 'tcpdump \u2705' : 'tcpdump \u274C');
                if (data.tools.tshark !== undefined) parts.push(data.tools.tshark ? 'tshark \u2705' : 'tshark \u274C');
            }
            if (data.tools.capture_method) {
                parts.push('via ' + data.tools.capture_method);
            }
            statusEl.textContent = parts.join(' | ');
            if (data.tools.capture_method === 'none') {
                statusEl.style.color = 'var(--critical)';
            } else if (!data.tools.tshark) {
                statusEl.style.color = 'var(--warning)';
            }
        }
        // Populate interface dropdown
        if (data.interfaces) {
            const sel = document.getElementById('pcap-interface');
            sel.innerHTML = '';
            for (const iface of data.interfaces) {
                const opt = document.createElement('option');
                opt.value = iface.name;
                opt.textContent = iface.display;
                sel.appendChild(opt);
            }
        }
    } catch (e) {
        console.error('Failed to check pcap tools:', e);
    }
}

async function startCapture() {
    const targetIp = document.getElementById('pcap-target-ip').value.trim();
    if (!targetIp) {
        alert('Enter the target (remote) IP address');
        return;
    }

    const sourceIp = document.getElementById('pcap-source-ip').value.trim();
    const iface = document.getElementById('pcap-interface').value;
    const duration = parseInt(document.getElementById('pcap-duration').value) || 30;
    const maxPackets = parseInt(document.getElementById('pcap-max-packets').value) || 100000;
    const portFilter = document.getElementById('pcap-port-filter').value.trim();
    const statusEl = document.getElementById('pcap-capture-status');

    statusEl.textContent = 'Starting capture...';
    statusEl.style.color = 'var(--text-secondary)';

    try {
        const resp = await fetch('/api/capture/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_ip: targetIp,
                source_ip: sourceIp,
                interface: iface,
                duration: duration,
                max_packets: maxPackets,
                port_filter: portFilter,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Error: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            return;
        }

        state.activeCapture = data.capture;
        const capTool = data.capture.capture_tool || 'capture';
        const ifaceDisplay = iface || 'default interface';
        statusEl.textContent = `${capTool}: capturing on ${ifaceDisplay}... (${duration}s max, ${maxPackets.toLocaleString()} pkt limit)`;
        statusEl.style.color = 'var(--accent)';

        // Toggle buttons
        document.getElementById('btn-start-capture').style.display = 'none';
        document.getElementById('btn-stop-capture').style.display = '';

        // Poll for status
        state.capturePolling = setInterval(() => pollCaptureStatus(), 2000);

    } catch (e) {
        statusEl.textContent = `Failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
    }
}

async function stopCapture() {
    if (!state.activeCapture) return;

    // Snapshot the capture info before any async operations
    const captureId = state.activeCapture.capture_id;
    const statusEl = document.getElementById('pcap-capture-status');
    statusEl.textContent = 'Stopping capture...';

    if (state.capturePolling) {
        clearInterval(state.capturePolling);
        state.capturePolling = null;
    }

    try {
        const resp = await fetch('/api/capture/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ capture_id: captureId }),
        });
        const data = await resp.json();

        if (data.error) {
            // Capture may have already completed via polling — treat as success
            if (data.error.includes('not found') || data.error.includes('already completed') || data.error.includes('No active capture')) {
                statusEl.textContent = 'Capture already completed.';
                statusEl.style.color = 'var(--success)';
                await refreshCaptureList();
            } else {
                statusEl.textContent = `Error: ${data.error}`;
                statusEl.style.color = 'var(--critical)';
            }
        } else if (data.capture) {
            const cap = data.capture;
            statusEl.textContent = `Capture complete: ${cap.filename} (${cap.packet_count} packets, ${formatBytes(cap.file_size_bytes)})`;
            statusEl.style.color = 'var(--success)';
            // Auto-select in analyze dropdown
            await refreshCaptureList();
            const sel = document.getElementById('pcap-analyze-file');
            if (sel && cap.filename) {
                for (const opt of sel.options) {
                    if (opt.value === cap.filename) {
                        sel.value = cap.filename;
                        break;
                    }
                }
            }
            // Pre-fill source/target IPs
            if (cap.source_ip) document.getElementById('pcap-analyze-src').value = cap.source_ip;
            if (cap.target_ip) document.getElementById('pcap-analyze-dst').value = cap.target_ip;
        } else {
            statusEl.textContent = 'Capture stopped.';
            statusEl.style.color = 'var(--success)';
            await refreshCaptureList();
        }
    } catch (e) {
        statusEl.textContent = `Stop failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
    }

    state.activeCapture = null;
    document.getElementById('btn-start-capture').style.display = '';
    document.getElementById('btn-stop-capture').style.display = 'none';
}

async function pollCaptureStatus() {
    if (!state.activeCapture) return;

    // Snapshot capture_id before async operations
    const captureId = state.activeCapture.capture_id;

    try {
        const resp = await fetch('/api/capture/status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ capture_id: captureId }),
        });
        const data = await resp.json();

        // Bail if capture was stopped while we were waiting for the response
        if (!state.activeCapture || state.activeCapture.capture_id !== captureId) return;

        if (data.error || (data.capture && data.capture.status === 'complete')) {
            // Capture ended
            if (state.capturePolling) {
                clearInterval(state.capturePolling);
                state.capturePolling = null;
            }
            const statusEl = document.getElementById('pcap-capture-status');
            if (data.capture && data.capture.filename) {
                const cap = data.capture;
                statusEl.textContent = `Capture complete: ${cap.filename} (${cap.packet_count} packets, ${formatBytes(cap.file_size_bytes)})`;
                statusEl.style.color = 'var(--success)';
                await refreshCaptureList();
                // Auto-select
                const sel = document.getElementById('pcap-analyze-file');
                if (sel) {
                    for (const opt of sel.options) {
                        if (opt.value === cap.filename) { sel.value = cap.filename; break; }
                    }
                }
                if (cap.source_ip) document.getElementById('pcap-analyze-src').value = cap.source_ip;
                if (cap.target_ip) document.getElementById('pcap-analyze-dst').value = cap.target_ip;
            } else {
                statusEl.textContent = 'Capture ended.';
                statusEl.style.color = 'var(--success)';
                await refreshCaptureList();
            }
            state.activeCapture = null;
            document.getElementById('btn-start-capture').style.display = '';
            document.getElementById('btn-stop-capture').style.display = 'none';
        } else if (data.capture) {
            const cap = data.capture;
            const statusEl = document.getElementById('pcap-capture-status');
            statusEl.textContent = `Capturing... ${formatBytes(cap.file_size_bytes)} written`;
        }
    } catch (e) {
        // Polling error, ignore
    }
}

async function refreshCaptureList() {
    try {
        const resp = await fetch('/api/capture/list');
        const data = await resp.json();

        // Update the analyze dropdown
        const sel = document.getElementById('pcap-analyze-file');
        const currentVal = sel.value;
        sel.innerHTML = '<option value="">-- Select a capture file --</option>';
        if (data.captures) {
            for (const cap of data.captures) {
                const opt = document.createElement('option');
                opt.value = cap.filename;
                opt.textContent = `${cap.filename} (${cap.file_size_display}, ${cap.packet_count >= 0 ? cap.packet_count + ' pkts' : '? pkts'})`;
                sel.appendChild(opt);
            }
        }
        // Restore selection
        if (currentVal) sel.value = currentVal;

        // Render file list card
        renderCaptureFileList(data.captures || []);
    } catch (e) {
        console.error('Failed to refresh capture list:', e);
    }
}

function renderCaptureFileList(captures) {
    const container = document.getElementById('pcap-file-list');
    if (!captures || captures.length === 0) {
        container.innerHTML = '';
        return;
    }

    let html = `<div class="card" style="margin-top: 1rem;">
        <div class="card-header">
            <div class="card-title">Saved Captures (${captures.length})</div>
        </div>`;

    for (const cap of captures) {
        html += `
        <div class="device-item">
            <div class="device-info">
                <span class="device-vendor-badge vendor-linux" style="font-size: 0.7rem;">PCAP</span>
                <div>
                    <div class="device-name">${escapeHtml(cap.filename)}</div>
                    <div class="device-role">${cap.file_size_display} &middot; ${cap.packet_count >= 0 ? cap.packet_count + ' packets' : '?'} &middot; ${cap.modified}</div>
                </div>
            </div>
            <button class="device-delete" onclick="deleteCaptureFile('${escapeHtml(cap.filename)}')" title="Delete">&#x2715;</button>
        </div>`;
    }

    html += '</div>';
    container.innerHTML = html;
}

async function deleteCaptureFile(filename) {
    if (!confirm(`Delete capture file ${filename}?`)) return;
    try {
        await fetch('/api/capture/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: filename }),
        });
        refreshCaptureList();
    } catch (e) {
        alert(`Delete failed: ${e.message}`);
    }
}

// Pcap upload via drag-drop
function setupPcapDragDrop() {
    const zone = document.getElementById('pcap-drop-zone');
    if (!zone) return;

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            document.getElementById('pcap-file-input').files = e.dataTransfer.files;
            uploadPcapFile(e.dataTransfer.files[0]);
        }
    });
    zone.addEventListener('click', () => document.getElementById('pcap-file-input').click());

    document.getElementById('pcap-file-input').addEventListener('change', (e) => {
        if (e.target.files.length > 0) uploadPcapFile(e.target.files[0]);
    });
}

async function uploadPcapFile(file) {
    const statusEl = document.getElementById('pcap-upload-status');
    statusEl.textContent = `Uploading ${file.name}...`;
    statusEl.style.color = 'var(--text-secondary)';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await fetch('/api/capture/upload', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Error: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            return;
        }

        statusEl.textContent = `Uploaded: ${data.filename} (${formatBytes(data.file_size_bytes)})`;
        statusEl.style.color = 'var(--success)';

        // Refresh list and auto-select
        await refreshCaptureList();
        const sel = document.getElementById('pcap-analyze-file');
        sel.value = data.filename;
    } catch (e) {
        statusEl.textContent = `Upload failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
    }
}

async function analyzePcap() {
    const filename = document.getElementById('pcap-analyze-file').value;
    const sourceIp = document.getElementById('pcap-analyze-src').value.trim();
    const targetIp = document.getElementById('pcap-analyze-dst').value.trim();
    const sourceLabel = document.getElementById('pcap-analyze-src-label').value.trim() || 'Source';
    const targetLabel = document.getElementById('pcap-analyze-dst-label').value.trim() || 'Target';
    const statusEl = document.getElementById('pcap-analyze-status');

    if (!filename) { alert('Select a capture file to analyze'); return; }
    if (!sourceIp) { alert('Enter the source IP (slow direction sender)'); return; }
    if (!targetIp) { alert('Enter the target IP (slow direction receiver)'); return; }

    statusEl.textContent = 'Analyzing packets... This may take a minute for large captures.';
    statusEl.style.color = 'var(--text-secondary)';
    showLoading('Analyzing packet capture...');

    try {
        const resp = await fetch('/api/capture/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: filename,
                source_ip: sourceIp,
                target_ip: targetIp,
                source_label: sourceLabel,
                target_label: targetLabel,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            statusEl.textContent = `Error: ${data.error}`;
            statusEl.style.color = 'var(--critical)';
            return;
        }

        statusEl.textContent = 'Analysis complete!';
        statusEl.style.color = 'var(--success)';
        renderPcapResults(data.report);
    } catch (e) {
        statusEl.textContent = `Analysis failed: ${e.message}`;
        statusEl.style.color = 'var(--critical)';
    } finally {
        hideLoading();
    }
}

function renderPcapResults(report) {
    const container = document.getElementById('pcap-results');
    if (!report) { container.innerHTML = ''; return; }

    const fwd = report.forward;
    const rev = report.reverse;

    // Determine which direction is slower
    const fwdSlow = fwd.throughput_mbps < rev.throughput_mbps;
    const ratio = (fwd.throughput_mbps > 0 && rev.throughput_mbps > 0)
        ? (Math.max(fwd.throughput_mbps, rev.throughput_mbps) / Math.min(fwd.throughput_mbps, rev.throughput_mbps)).toFixed(1)
        : '?';

    // Count findings by severity
    const critCount = report.findings.filter(f => f.severity === 'critical').length;
    const warnCount = report.findings.filter(f => f.severity === 'warning').length;
    const infoCount = report.findings.filter(f => f.severity === 'info').length;

    let html = '';

    // Summary stats bar
    html += `
    <div class="card" style="margin-top: 1rem;">
        <div class="card-header">
            <div>
                <div class="card-title">Packet Analysis: ${escapeHtml(report.filename)}</div>
                <div class="card-subtitle">
                    ${report.total_packets.toLocaleString()} packets | ${report.capture_duration_sec.toFixed(1)}s duration | Tool: ${report.analysis_tool}
                </div>
            </div>
        </div>
        <div class="summary-box">${escapeHtml(report.summary)}</div>
    </div>`;

    // Direction comparison cards
    html += `
    <div class="stats-bar" style="margin-top: 1rem;">
        <div class="stat-card">
            <div class="stat-value ${critCount > 0 ? 'critical' : 'success'}">${critCount}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value warning">${warnCount}</div>
            <div class="stat-label">Warnings</div>
        </div>
        <div class="stat-card">
            <div class="stat-value info">${infoCount}</div>
            <div class="stat-label">Info</div>
        </div>
        <div class="stat-card">
            <div class="stat-value critical">${ratio}:1</div>
            <div class="stat-label">Asymmetry Ratio</div>
        </div>
    </div>`;

    // Per-direction throughput comparison
    html += `
    <div class="card" style="margin-top: 1rem;">
        <div class="card-title">Directional Throughput Comparison</div>
        <div class="pcap-direction-grid">
            <div class="pcap-direction-card ${fwdSlow ? 'pcap-slow' : 'pcap-fast'}">
                <div class="pcap-dir-label">${escapeHtml(fwd.label)}</div>
                <div class="pcap-dir-speed">${fwd.throughput_mbps.toFixed(1)} <small>Mbps</small></div>
                <div class="pcap-dir-details">
                    ${fwd.packets.toLocaleString()} packets<br>
                    ${formatBytes(fwd.bytes_total)} transferred<br>
                    ${fwd.retransmissions} retransmissions<br>
                    ${fwd.duplicate_acks} dup ACKs<br>
                    ${fwd.zero_window} zero-window
                </div>
                <div class="pcap-dir-tag">${fwdSlow ? 'SLOW' : 'FAST'}</div>
            </div>
            <div class="pcap-direction-card ${!fwdSlow ? 'pcap-slow' : 'pcap-fast'}">
                <div class="pcap-dir-label">${escapeHtml(rev.label)}</div>
                <div class="pcap-dir-speed">${rev.throughput_mbps.toFixed(1)} <small>Mbps</small></div>
                <div class="pcap-dir-details">
                    ${rev.packets.toLocaleString()} packets<br>
                    ${formatBytes(rev.bytes_total)} transferred<br>
                    ${rev.retransmissions} retransmissions<br>
                    ${rev.duplicate_acks} dup ACKs<br>
                    ${rev.zero_window} zero-window
                </div>
                <div class="pcap-dir-tag">${!fwdSlow ? 'SLOW' : 'FAST'}</div>
            </div>
        </div>
    </div>`;

    // TCP Window Size Comparison
    if (fwd.window_size_max > 0 || rev.window_size_max > 0) {
        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">TCP Window Size Comparison</div>
            <div class="diag-detail-grid" style="margin-top: 0.75rem;">
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} Min</span><span class="diag-detail-value">${fwd.window_size_min.toLocaleString()} bytes</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} Avg</span><span class="diag-detail-value">${fwd.window_size_avg.toLocaleString()} bytes</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} Max</span><span class="diag-detail-value">${fwd.window_size_max.toLocaleString()} bytes</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} Min</span><span class="diag-detail-value">${rev.window_size_min.toLocaleString()} bytes</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} Avg</span><span class="diag-detail-value">${rev.window_size_avg.toLocaleString()} bytes</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} Max</span><span class="diag-detail-value">${rev.window_size_max.toLocaleString()} bytes</span></div>
            </div>
        </div>`;
    }

    // RTT Comparison
    if (fwd.rtt_samples > 0 || rev.rtt_samples > 0) {
        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">RTT Analysis</div>
            <div class="diag-detail-grid" style="margin-top: 0.75rem;">
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} RTT (avg)</span><span class="diag-detail-value">${fwd.rtt_avg_ms.toFixed(1)} ms</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} RTT (min/max)</span><span class="diag-detail-value">${fwd.rtt_min_ms.toFixed(1)} / ${fwd.rtt_max_ms.toFixed(1)} ms</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)} Samples</span><span class="diag-detail-value">${fwd.rtt_samples}</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} RTT (avg)</span><span class="diag-detail-value">${rev.rtt_avg_ms.toFixed(1)} ms</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} RTT (min/max)</span><span class="diag-detail-value">${rev.rtt_min_ms.toFixed(1)} / ${rev.rtt_max_ms.toFixed(1)} ms</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)} Samples</span><span class="diag-detail-value">${rev.rtt_samples}</span></div>
            </div>
        </div>`;
    }

    // TCP Connection Setup (SYN analysis)
    if (report.connections && report.connections.length > 0) {
        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">TCP Connection Setup (SYN Analysis)</div>
            <div class="pa-table-container" style="margin-top: 0.75rem;">
                <table class="pa-table">
                    <thead>
                        <tr><th>Source</th><th>Destination</th><th>Handshake</th><th>Client MSS</th><th>Server MSS</th><th>WScale (C/S)</th><th>SACK</th></tr>
                    </thead>
                    <tbody>`;
        for (const conn of report.connections) {
            const wscaleClient = conn.window_scale_client >= 0 ? conn.window_scale_client : 'NONE';
            const wscaleServer = conn.window_scale_server >= 0 ? conn.window_scale_server : 'NONE';
            const wscaleClass = (conn.window_scale_client < 0 || conn.window_scale_server < 0) ? 'style="color: var(--critical); font-weight: 600;"' : '';
            html += `
                    <tr>
                        <td class="mono">${escapeHtml(conn.src_ip)}:${conn.src_port}</td>
                        <td class="mono">${escapeHtml(conn.dst_ip)}:${conn.dst_port}</td>
                        <td class="mono">${conn.handshake_ms.toFixed(1)} ms</td>
                        <td class="mono">${conn.mss_client || '?'}</td>
                        <td class="mono">${conn.mss_server || '?'}</td>
                        <td class="mono" ${wscaleClass}>${wscaleClient} / ${wscaleServer}</td>
                        <td class="mono">${conn.sack_permitted ? '\u2705' : '\u274C'}</td>
                    </tr>`;
        }
        html += `</tbody></table></div></div>`;
    }

    // Per-second throughput timeline
    if (report.timeline && report.timeline.length > 0) {
        const maxMbps = Math.max(
            ...report.timeline.map(t => Math.max(t.forward_mbps, t.reverse_mbps)),
            1
        );
        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">Per-Second Throughput Timeline</div>
            <div class="card-subtitle" style="margin-bottom: 0.75rem;">Bars show forward (top, blue) and reverse (bottom, green) throughput each second</div>
            <div class="pcap-timeline">`;

        for (const t of report.timeline) {
            const fwdWidth = Math.max((t.forward_mbps / maxMbps) * 100, 0);
            const revWidth = Math.max((t.reverse_mbps / maxMbps) * 100, 0);
            html += `
                <div class="pcap-timeline-row">
                    <span class="pcap-timeline-sec">${t.second}s</span>
                    <div class="pcap-timeline-bars">
                        <div class="pcap-timeline-bar pcap-bar-fwd" style="width: ${fwdWidth}%"
                             title="${fwd.label}: ${t.forward_mbps} Mbps"></div>
                        <div class="pcap-timeline-bar pcap-bar-rev" style="width: ${revWidth}%"
                             title="${rev.label}: ${t.reverse_mbps} Mbps"></div>
                    </div>
                    <span class="pcap-timeline-val">${t.forward_mbps} / ${t.reverse_mbps}</span>
                </div>`;
        }

        html += `
                <div class="pcap-timeline-legend">
                    <span><span class="pcap-legend-dot pcap-bar-fwd"></span> ${escapeHtml(fwd.label)} (Mbps)</span>
                    <span><span class="pcap-legend-dot pcap-bar-rev"></span> ${escapeHtml(rev.label)} (Mbps)</span>
                </div>
            </div>
        </div>`;
    }

    // DSCP Analysis
    if ((fwd.dscp_values && Object.keys(fwd.dscp_values).length > 0) ||
        (rev.dscp_values && Object.keys(rev.dscp_values).length > 0)) {
        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">DSCP / QoS Markings</div>
            <div class="diag-detail-grid" style="margin-top: 0.75rem;">
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(fwd.label)}</span><span class="diag-detail-value">${Object.entries(fwd.dscp_values || {}).map(([k,v]) => `${k}: ${v}`).join(', ') || 'none'}</span></div>
                <div class="diag-detail-item"><span class="diag-detail-label">${escapeHtml(rev.label)}</span><span class="diag-detail-value">${Object.entries(rev.dscp_values || {}).map(([k,v]) => `${k}: ${v}`).join(', ') || 'none'}</span></div>
            </div>
        </div>`;
    }

    // Findings
    if (report.findings && report.findings.length > 0) {
        const order = { critical: 0, warning: 1, info: 2 };
        const sorted = [...report.findings].sort((a, b) => (order[a.severity] || 3) - (order[b.severity] || 3));

        html += `
        <div class="card" style="margin-top: 1rem;">
            <div class="card-title">Findings (${report.findings.length})</div>`;

        for (const f of sorted) {
            html += `
            <div class="finding ${f.severity}">
                <div class="finding-header">
                    <span class="finding-severity severity-${f.severity}">${f.severity}</span>
                    <span class="finding-category">${escapeHtml(f.category)}</span>
                </div>
                <div class="finding-title">${escapeHtml(f.title)}</div>
                <div class="finding-detail">${escapeHtml(f.detail)}</div>
                <div class="finding-recommendation">${escapeHtml(f.recommendation)}</div>
            </div>`;
        }

        html += `</div>`;
    }

    container.innerHTML = html;
}

// ========================================
// Init
// ========================================
document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    renderNetworkPath();
    renderDeviceRoleOptions();
    renderDeviceList();
    renderResults();
    setupDragDrop();
    setupPcapDragDrop();
    checkStatus();
    checkPcapTools();
    refreshCaptureList();
});
