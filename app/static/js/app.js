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
    checkStatus();
});
