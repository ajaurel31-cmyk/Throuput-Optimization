"""
Flask routes for the Network Throughput Bottleneck Analyzer.
"""

import os
import json
import re
import uuid

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    current_app,
    session,
)
from werkzeug.utils import secure_filename

from app.parsers import GenericConfigParser
from app.analyzers.bottleneck_engine import BottleneckAnalyzer
from app.analyzers.claude_analyzer import ClaudeAnalyzer
from app.diagnostics import NetworkDiagnostics
from app.diagnostics.iperf_tester import IperfTester
from app.connectors import SSHConfigFetcher
from app.config_loader import get_preloaded_devices, load_configs

main_bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {"txt", "conf", "cfg", "log", "xml", "set"}

# Valid device roles in the traffic path
VALID_ROLES = {
    "source_server",
    "core_switch_local",
    "firewall_local",
    "edge_switch_local",
    "edge_switch_remote",
    "firewall_remote",
    "core_switch_remote",
    "target_server",
}


def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@main_bp.before_request
def _inject_preloaded_configs():
    """Seed new sessions with auto-loaded configs from configs/ directory."""
    if "_configs_seeded" not in session:
        preloaded = get_preloaded_devices()
        if preloaded:
            session["devices"] = preloaded
            session["_configs_seeded"] = True
            session.modified = True


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/api/upload", methods=["POST"])
def upload_config():
    """Upload a device configuration file."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    device_name = request.form.get("device_name", "unknown")
    device_role = request.form.get("device_role", "unknown")

    if device_role not in VALID_ROLES:
        return jsonify({"error": f"Invalid device role: {device_role}"}), 400

    # Read config text
    try:
        config_text = file.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Failed to read file: {str(e)}"}), 400

    if not config_text.strip():
        return jsonify({"error": "Config file is empty"}), 400

    # Save file for reference
    file_id = str(uuid.uuid4())[:8]
    safe_name = secure_filename(file.filename) if file.filename else "config.txt"
    save_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"], f"{file_id}_{safe_name}"
    )
    with open(save_path, "w") as f:
        f.write(config_text)

    # Parse the config
    parsed = GenericConfigParser.parse(config_text, device_name, device_role)
    parsed["file_id"] = file_id
    parsed["filename"] = safe_name

    # Store in session
    if "devices" not in session:
        session["devices"] = []
    session["devices"].append(parsed)
    session.modified = True

    return jsonify(
        {
            "status": "ok",
            "device": {
                "file_id": file_id,
                "device_name": parsed.get("device_name", device_name),
                "device_role": device_role,
                "vendor": parsed.get("vendor", "unknown"),
                "interface_count": len(parsed.get("interfaces", [])),
                "warnings": parsed.get("warnings", []),
            },
        }
    )


@main_bp.route("/api/upload-text", methods=["POST"])
def upload_config_text():
    """Upload a device configuration as raw text (paste)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    config_text = data.get("config_text", "").strip()
    device_name = data.get("device_name", "unknown")
    device_role = data.get("device_role", "unknown")

    if not config_text:
        return jsonify({"error": "Config text is empty"}), 400

    if device_role not in VALID_ROLES:
        return jsonify({"error": f"Invalid device role: {device_role}"}), 400

    # Save file for reference
    file_id = str(uuid.uuid4())[:8]
    save_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"], f"{file_id}_pasted.txt"
    )
    with open(save_path, "w") as f:
        f.write(config_text)

    # Parse the config
    parsed = GenericConfigParser.parse(config_text, device_name, device_role)
    parsed["file_id"] = file_id
    parsed["filename"] = "pasted.txt"

    # Store in session
    if "devices" not in session:
        session["devices"] = []
    session["devices"].append(parsed)
    session.modified = True

    return jsonify(
        {
            "status": "ok",
            "device": {
                "file_id": file_id,
                "device_name": parsed.get("device_name", device_name),
                "device_role": device_role,
                "vendor": parsed.get("vendor", "unknown"),
                "interface_count": len(parsed.get("interfaces", [])),
                "warnings": parsed.get("warnings", []),
            },
        }
    )


@main_bp.route("/api/devices", methods=["GET"])
def list_devices():
    """List all uploaded devices."""
    devices = session.get("devices", [])
    return jsonify(
        {
            "devices": [
                {
                    "file_id": d.get("file_id"),
                    "device_name": d.get("device_name"),
                    "device_role": d.get("device_role"),
                    "vendor": d.get("vendor"),
                    "interface_count": len(d.get("interfaces", [])),
                }
                for d in devices
            ]
        }
    )


@main_bp.route("/api/devices/<file_id>", methods=["DELETE"])
def delete_device(file_id):
    """Remove a device from the session."""
    devices = session.get("devices", [])
    session["devices"] = [d for d in devices if d.get("file_id") != file_id]
    session.modified = True
    return jsonify({"status": "ok"})


@main_bp.route("/api/clear", methods=["POST"])
def clear_devices():
    """Clear all uploaded devices."""
    session["devices"] = []
    session.modified = True
    return jsonify({"status": "ok"})


@main_bp.route("/api/analyze", methods=["POST"])
def analyze():
    """Run bottleneck analysis on all uploaded device configs."""
    devices = session.get("devices", [])
    if not devices:
        return jsonify({"error": "No device configs uploaded yet"}), 400

    data = request.get_json() or {}
    link_speed = data.get("link_speed_gbps", 10)
    site_a = data.get("site_a", "ATL")
    site_b = data.get("site_b", "PHX")

    # Run local bottleneck analysis
    analyzer = BottleneckAnalyzer(devices, link_speed_gbps=link_speed)
    report = analyzer.analyze()
    report_dict = report.to_dict()

    return jsonify(
        {
            "status": "ok",
            "report": report_dict,
        }
    )


@main_bp.route("/api/analyze-claude", methods=["POST"])
def analyze_with_claude():
    """Run deep analysis using Claude API."""
    devices = session.get("devices", [])
    if not devices:
        return jsonify({"error": "No device configs uploaded yet"}), 400

    data = request.get_json() or {}
    link_speed = data.get("link_speed_gbps", 10)
    site_a = data.get("site_a", "ATL")
    site_b = data.get("site_b", "PHX")

    # First run local analysis
    analyzer = BottleneckAnalyzer(devices, link_speed_gbps=link_speed)
    report = analyzer.analyze()
    report_dict = report.to_dict()

    # Then send to Claude for deeper analysis
    claude = ClaudeAnalyzer()
    claude_result = claude.analyze(
        devices, report_dict, link_speed_gbps=link_speed, site_a=site_a, site_b=site_b
    )

    return jsonify(
        {
            "status": "ok",
            "report": report_dict,
            "claude_analysis": claude_result,
        }
    )


@main_bp.route("/api/chat", methods=["POST"])
def chat_with_claude():
    """Interactive follow-up chat about the analysis."""
    devices = session.get("devices", [])
    data = request.get_json() or {}

    user_message = data.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    conversation_history = data.get("history", [])
    link_speed = data.get("link_speed_gbps", 10)
    site_a = data.get("site_a", "ATL")
    site_b = data.get("site_b", "PHX")

    # Run local analysis for context (if devices are loaded)
    local_report = {}
    if devices:
        analyzer = BottleneckAnalyzer(devices, link_speed_gbps=link_speed)
        report = analyzer.analyze()
        local_report = report.to_dict()

    claude = ClaudeAnalyzer()
    result = claude.chat(
        user_message=user_message,
        conversation_history=conversation_history,
        devices=devices,
        local_report=local_report,
        link_speed_gbps=link_speed,
        site_a=site_a,
        site_b=site_b,
    )

    return jsonify(result)


@main_bp.route("/api/diagnostics/run", methods=["POST"])
def run_diagnostics():
    """Run network diagnostics against a target host."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target host specified"}), 400

    # Basic input validation — prevent command injection
    if not _is_valid_host(target):
        return jsonify({"error": "Invalid target. Use a hostname or IP address."}), 400

    link_speed = data.get("link_speed_gbps", 10)
    tests = data.get("tests", [])  # empty = run all

    diag = NetworkDiagnostics(target, link_speed_gbps=link_speed)

    if tests:
        # Run specific tests
        report = _run_selected_tests(diag, tests)
    else:
        report = diag.run_all()

    return jsonify({"status": "ok", "report": report.to_dict()})


@main_bp.route("/api/diagnostics/ping", methods=["POST"])
def run_ping():
    """Run a quick ping test."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    target = data.get("target", "").strip()
    if not target or not _is_valid_host(target):
        return jsonify({"error": "Invalid target"}), 400

    count = min(int(data.get("count", 5)), 20)
    diag = NetworkDiagnostics(target)
    result = diag.test_ping(count=count)
    return jsonify({"status": "ok", "result": result.to_dict()})


@main_bp.route("/api/diagnostics/traceroute", methods=["POST"])
def run_traceroute():
    """Run traceroute to a target."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    target = data.get("target", "").strip()
    if not target or not _is_valid_host(target):
        return jsonify({"error": "Invalid target"}), 400

    max_hops = min(int(data.get("max_hops", 20)), 30)
    diag = NetworkDiagnostics(target)
    result = diag.test_traceroute(max_hops=max_hops)
    return jsonify({"status": "ok", "result": result.to_dict()})


@main_bp.route("/api/diagnostics/ports", methods=["POST"])
def run_port_scan():
    """Run TCP port connectivity test."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    target = data.get("target", "").strip()
    if not target or not _is_valid_host(target):
        return jsonify({"error": "Invalid target"}), 400

    ports = data.get("ports", [22, 80, 443, 179, 161, 8080, 8443])
    # Validate port numbers
    ports = [int(p) for p in ports if 1 <= int(p) <= 65535][:20]

    diag = NetworkDiagnostics(target)
    result = diag.test_tcp_ports(ports=ports)
    return jsonify({"status": "ok", "result": result.to_dict()})


@main_bp.route("/api/ssh-fetch", methods=["POST"])
def ssh_fetch_config():
    """SSH into a network device and fetch its running config."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    host = data.get("host", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    device_type = data.get("device_type", "auto").strip()
    port = int(data.get("port", 22))
    device_name = data.get("device_name", "").strip()
    device_role = data.get("device_role", "")

    # Validate required fields
    if not host:
        return jsonify({"error": "Host IP or hostname is required"}), 400
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not _is_valid_host(host):
        return jsonify({"error": "Invalid host. Use a hostname or IP address."}), 400
    if device_role and device_role not in VALID_ROLES:
        return jsonify({"error": f"Invalid device role: {device_role}"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"error": "Port must be between 1 and 65535"}), 400

    # Fetch config via SSH
    fetcher = SSHConfigFetcher(
        host=host,
        username=username,
        password=password,
        device_type=device_type,
        port=port,
    )
    result = fetcher.fetch()

    if result["status"] != "success":
        return jsonify({"error": result["message"]}), 400

    config_text = result["config_text"]
    if not config_text.strip():
        return jsonify({"error": "Retrieved config is empty. Check device credentials and permissions."}), 400

    # Use detected hostname as device name if not provided
    if not device_name:
        device_name = result.get("hostname") or host

    # Save the fetched config to file
    file_id = str(uuid.uuid4())[:8]
    safe_name = f"ssh_{host.replace('.', '_')}.conf"
    save_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"], f"{file_id}_{safe_name}"
    )
    with open(save_path, "w") as f:
        f.write(config_text)

    # Parse the config
    parsed = GenericConfigParser.parse(config_text, device_name, device_role or "unknown")
    parsed["file_id"] = file_id
    parsed["filename"] = safe_name
    parsed["source"] = "ssh"
    parsed["source_host"] = host

    # If role was provided, store in session
    if device_role:
        if "devices" not in session:
            session["devices"] = []
        session["devices"].append(parsed)
        session.modified = True

    return jsonify(
        {
            "status": "ok",
            "device": {
                "file_id": file_id,
                "device_name": parsed.get("device_name", device_name),
                "device_role": device_role,
                "vendor": parsed.get("vendor", "unknown"),
                "interface_count": len(parsed.get("interfaces", [])),
                "warnings": parsed.get("warnings", []),
                "detected_type": result.get("device_type", "unknown"),
                "hostname": result.get("hostname"),
                "source": "ssh",
                "source_host": host,
            },
            "config_preview": config_text[:500] + ("..." if len(config_text) > 500 else ""),
            "config_full": config_text,
        }
    )


@main_bp.route("/api/iperf/test", methods=["POST"])
def run_iperf_test():
    """Run an iperf3 bandwidth test and diagnose bottlenecks."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target server IP or hostname is required"}), 400
    if not _is_valid_host(target):
        return jsonify({"error": "Invalid target. Use a hostname or IP address."}), 400

    port = int(data.get("port", 5201))
    if not (1 <= port <= 65535):
        return jsonify({"error": "Port must be between 1 and 65535"}), 400

    duration = min(max(int(data.get("duration", 10)), 5), 60)
    parallel = min(max(int(data.get("parallel", 1)), 1), 16)
    reverse = bool(data.get("reverse", False))
    udp = bool(data.get("udp", False))
    udp_bandwidth = data.get("udp_bandwidth", "1G").strip()
    window_size = data.get("window_size", "").strip() or None
    link_speed = float(data.get("link_speed_gbps", 10))
    source_label = data.get("source_label", "ATL").strip()
    target_label = data.get("target_label", "PHX").strip()

    # Validate udp_bandwidth format
    if udp and not re.match(r"^\d+[KMG]?$", udp_bandwidth, re.IGNORECASE):
        return jsonify({"error": "Invalid UDP bandwidth format. Use e.g. 1G, 500M, 100K"}), 400

    # Validate window_size format if provided
    if window_size and not re.match(r"^\d+[KM]?$", window_size, re.IGNORECASE):
        return jsonify({"error": "Invalid window size format. Use e.g. 4M, 512K"}), 400

    tester = IperfTester(
        target=target,
        port=port,
        link_speed_gbps=link_speed,
        source_label=source_label,
        target_label=target_label,
    )

    report = tester.run_test(
        duration=duration,
        parallel=parallel,
        reverse=reverse,
        udp=udp,
        udp_bandwidth=udp_bandwidth,
        window_size=window_size,
    )

    return jsonify({"status": "ok", "report": report.to_dict()})


def _is_valid_host(host):
    """Validate that the host is a safe hostname or IP address."""
    import re
    # Allow IPs (v4)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return True
    # Allow hostnames (alphanumeric, dots, hyphens)
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$", host):
        return True
    # Allow single-label hostnames
    if re.match(r"^[a-zA-Z0-9]{1,63}$", host):
        return True
    return False


def _run_selected_tests(diag, test_names):
    """Run only the selected diagnostic tests."""
    from app.diagnostics.network_diagnostics import DiagnosticReport
    import time

    report = DiagnosticReport(
        target=diag.target,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )

    test_map = {
        "dns": diag.test_dns,
        "ping": diag.test_ping,
        "traceroute": diag.test_traceroute,
        "mtu": diag.test_mtu_path,
        "ports": diag.test_tcp_ports,
        "bdp": diag.test_bdp,
    }

    for name in test_names:
        fn = test_map.get(name)
        if fn:
            try:
                report.results.append(fn())
            except Exception as e:
                from app.diagnostics.network_diagnostics import DiagnosticResult
                report.results.append(DiagnosticResult(
                    test_name=name,
                    status="error",
                    summary=str(e),
                ))

    diag._calculate_health(report)
    return report


@main_bp.route("/api/configs/reload", methods=["POST"])
def reload_configs():
    """Re-scan configs/ directory and reload into current session."""
    loaded = load_configs()
    # Merge: keep manually-uploaded devices, replace auto-loaded ones
    manual_devices = [
        d for d in session.get("devices", [])
        if d.get("source") != "auto-loaded"
    ]
    session["devices"] = manual_devices + loaded
    session["_configs_seeded"] = True
    session.modified = True
    return jsonify(
        {
            "status": "ok",
            "auto_loaded": len(loaded),
            "manual_kept": len(manual_devices),
            "total_devices": len(session["devices"]),
            "devices": [
                {
                    "device_name": d.get("device_name"),
                    "device_role": d.get("device_role"),
                    "vendor": d.get("vendor"),
                    "source": d.get("source", "upload"),
                }
                for d in session["devices"]
            ],
        }
    )


@main_bp.route("/api/status", methods=["GET"])
def api_status():
    """Check API status including Claude availability."""
    claude = ClaudeAnalyzer()
    return jsonify(
        {
            "status": "ok",
            "claude_available": claude.available,
            "devices_loaded": len(session.get("devices", [])),
        }
    )
