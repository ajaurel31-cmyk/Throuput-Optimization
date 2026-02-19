# Network Throughput Bottleneck Analyzer

A web application for diagnosing network throughput bottlenecks between sites. Built for network engineers troubleshooting sub-optimal WAN performance.

## Problem Statement

Getting only ~50 MB/s on a 5 Gbps pipe between ATL and PHX? This tool helps you find out why by analyzing your switch and firewall configurations for common throughput killers.

## Traffic Path Model

The app models the actual traffic path:

```
Source Server → Core Switch → Firewall → Edge Switch → [WAN] → Edge Switch → Firewall → Core Switch → Target Server
```

At each hop, it checks for:
- **MTU mismatches** — fragmentation, PMTUD black holes, jumbo frame inconsistencies
- **Speed/duplex mismatches** — half-duplex, 1G links in a 10G path, auto-negotiation issues
- **QoS throttling** — traffic shapers, policers capping bandwidth below link rate
- **Firewall overhead** — SSL decryption, IPS/AV inspection, large rule bases
- **TCP settings** — window size, MSS clamping, buffer sizes
- **Routing issues** — asymmetric paths, suboptimal next-hops

## Features

- **Multi-vendor config parsing**: Cisco IOS/NX-OS, Palo Alto, Juniper JunOS
- **Auto-detect vendor**: Just paste or upload — the parser figures out the format
- **Rule-based analysis**: Instant local analysis with no API calls needed
- **Claude AI deep analysis**: Send configs to Claude for expert-level cross-device correlation
- **Visual network path**: See which devices have issues at a glance
- **Throughput estimation**: Estimates effective throughput based on detected issues

## Quick Start

```bash
# 1. Clone and enter the directory
cd Throuput-Optimization

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (optional — for Claude AI analysis)
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 5. Run the app
python run.py
```

Open http://localhost:5000 in your browser.

## Usage

1. **Upload configs**: Upload or paste your switch/firewall/server configs
2. **Assign roles**: Tell the app where each device sits in the traffic path
3. **Run Analysis**: Click "Run Analysis" for instant rule-based checks
4. **Claude Deep Analysis**: Click "Claude Deep Analysis" for AI-powered review (requires API key)
5. **Review findings**: Check critical/warning issues and follow recommendations

## Sample Configs

The `sample_configs/` directory contains example configs with intentional bottleneck issues:
- `atl_core_switch.conf` — Cisco switch with jumbo frames (MTU 9216)
- `atl_firewall.conf` — Palo Alto with SSL decryption + full threat inspection
- `atl_edge_switch.conf` — Cisco switch with standard MTU (mismatch!)
- `phx_core_switch.conf` — Cisco switch with small TCP window size

## What to Upload

For best results, upload configs from every device in the path:

| Device | What to capture |
|--------|----------------|
| Source Server | `ifconfig`, `ethtool <iface>`, `sysctl -a \| grep tcp` |
| Core Switch | `show running-config` |
| Firewall | Full config (Palo Alto: `set cli config-output-format set; show`) |
| Edge Switch | `show running-config` |
| Target Server | Same as source server |

## Supported Vendors

| Vendor | Format | Auto-detected |
|--------|--------|---------------|
| Cisco IOS/IOS-XE | `show running-config` | Yes |
| Cisco NX-OS | `show running-config` | Yes |
| Palo Alto | `set` format or XML | Yes |
| Juniper JunOS | `show configuration \| display set` | Yes |
| Other | Any text format | Partial (generic parser) |

## Architecture

```
app/
├── __init__.py           # Flask app factory
├── routes.py             # API endpoints
├── parsers/
│   ├── cisco_parser.py   # Cisco IOS/NX-OS parser
│   ├── paloalto_parser.py # Palo Alto parser
│   ├── juniper_parser.py # Juniper JunOS parser
│   └── generic_parser.py # Auto-detect + fallback
├── analyzers/
│   ├── bottleneck_engine.py  # Rule-based analysis engine
│   └── claude_analyzer.py    # Claude API integration
├── templates/
│   └── index.html        # Main dashboard
└── static/
    ├── css/style.css     # Dashboard styles
    └── js/app.js         # Frontend logic
```

## Claude API Integration

The app can send parsed configs to Claude for deeper analysis. Claude will:
- Correlate settings across all devices in the path
- Provide vendor-specific CLI commands for fixes
- Recommend server-side TCP/NIC tuning
- Identify issues the rule-based engine might miss

To enable: set `ANTHROPIC_API_KEY` in your `.env` file.
