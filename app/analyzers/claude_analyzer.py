"""
Claude API Integration for Deep Network Config Analysis

Sends parsed device configs and local analysis results to Claude for:
- Cross-device correlation (things the rule-based engine might miss)
- Best-practice recommendations specific to the vendor/model
- TCP tuning recommendations based on the ATL-PHX path characteristics
- Root cause analysis combining all the evidence
- Server-side tuning (NIC offloads, TCP stack, buffer sizes)
"""

import os
import json

try:
    import anthropic
except ImportError:
    anthropic = None


SYSTEM_PROMPT = """You are an expert network engineer specializing in WAN optimization,
throughput troubleshooting, and datacenter networking. You have deep knowledge of:
- Cisco IOS/IOS-XE/NX-OS switches and routers
- Palo Alto Networks firewalls
- Juniper JunOS devices
- TCP/IP performance tuning
- QoS, traffic shaping, and policing
- MTU/MSS optimization
- Server NIC and OS TCP stack tuning

You are analyzing device configurations to find why throughput between two sites
is limited. The traffic path is:

  Source Server → Core Switch → Firewall → Edge Switch → [WAN] → Edge Switch → Firewall → Core Switch → Target Server

Be specific and actionable in your recommendations. Reference actual config lines
when possible. Think like a senior network engineer doing a thorough config review.

IMPORTANT: Focus on throughput-impacting settings. Don't waste time on cosmetic issues.
Prioritize findings by impact on throughput."""


class ClaudeAnalyzer:
    """Send configs and analysis to Claude for deep inspection."""

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.available = bool(self.api_key and anthropic)

    def analyze(self, devices, local_report, link_speed_gbps=10, site_a="ATL", site_b="PHX"):
        """
        Send device configs and local findings to Claude for deeper analysis.

        Args:
            devices: list of parsed device dicts
            local_report: dict from BottleneckReport.to_dict()
            link_speed_gbps: WAN link speed
            site_a: source site name
            site_b: destination site name

        Returns:
            dict with Claude's analysis or error message
        """
        if not self.available:
            return {
                "status": "unavailable",
                "message": (
                    "Claude API is not configured. Set ANTHROPIC_API_KEY in your "
                    ".env file to enable AI-powered deep analysis."
                ),
            }

        # Build the prompt with all the context
        prompt = self._build_prompt(devices, local_report, link_speed_gbps, site_a, site_b)

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            analysis_text = response.content[0].text

            return {
                "status": "success",
                "analysis": analysis_text,
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
            }

        except anthropic.AuthenticationError:
            return {
                "status": "error",
                "message": "Invalid ANTHROPIC_API_KEY. Please check your API key.",
            }
        except anthropic.RateLimitError:
            return {
                "status": "error",
                "message": "Claude API rate limit reached. Please try again in a moment.",
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Claude API error: {str(e)}",
            }

    def _build_prompt(self, devices, local_report, link_speed_gbps, site_a, site_b):
        """Build a detailed prompt for Claude with all config context."""
        sections = []

        sections.append(
            f"## Problem Statement\n"
            f"We are only achieving ~50 MB/s (400 Mbps) throughput on a {link_speed_gbps} Gbps "
            f"WAN link between our {site_a} and {site_b} sites. "
            f"Theoretical max is {link_speed_gbps * 1000} Mbps (~{link_speed_gbps * 125} MB/s). "
            f"We are using only ~{round(400 / (link_speed_gbps * 1000) * 100, 1)}% of the pipe.\n"
        )

        sections.append(
            f"## Network Path\n"
            f"Source Server → Core Switch ({site_a}) → Firewall ({site_a}) → "
            f"Edge Switch ({site_a}) → [{link_speed_gbps}G WAN] → "
            f"Edge Switch ({site_b}) → Firewall ({site_b}) → "
            f"Core Switch ({site_b}) → Target Server\n"
        )

        # Include local analysis results
        sections.append(
            f"## Automated Analysis Results\n"
            f"Our local analysis found the following issues:\n"
        )
        for finding in local_report.get("findings", []):
            sections.append(
                f"- [{finding['severity'].upper()}] [{finding['device']}] "
                f"{finding['title']}: {finding['detail']}"
            )

        # Include raw configs (truncated for token limits)
        sections.append("\n## Device Configurations\n")
        for device in devices:
            device_name = device.get("device_name", "unknown")
            role = device.get("device_role", "unknown")
            vendor = device.get("vendor", "unknown")

            sections.append(f"### {device_name} (Role: {role}, Vendor: {vendor})")

            # Include parsed interface details
            for iface in device.get("interfaces", []):
                iface_info = f"  Interface {iface.get('name', '?')}: "
                details = []
                if iface.get("speed"):
                    details.append(f"speed={iface['speed']}")
                if iface.get("duplex"):
                    details.append(f"duplex={iface['duplex']}")
                if iface.get("mtu"):
                    details.append(f"mtu={iface['mtu']}")
                if iface.get("ip_address"):
                    details.append(f"ip={iface['ip_address']}")
                if iface.get("service_policy_in"):
                    details.append(f"qos_in={iface['service_policy_in']}")
                if iface.get("service_policy_out"):
                    details.append(f"qos_out={iface['service_policy_out']}")
                if details:
                    sections.append(iface_info + ", ".join(details))

            # Include raw config snippet for deeper analysis
            raw = device.get("raw_preview", "")
            if not raw:
                # For Cisco devices, include interface blocks
                for iface in device.get("interfaces", []):
                    if iface.get("raw"):
                        raw += iface["raw"] + "\n\n"

            if raw:
                # Limit to ~3000 chars per device to stay within token budget
                raw_truncated = raw[:3000]
                if len(raw) > 3000:
                    raw_truncated += "\n... [truncated]"
                sections.append(f"```\n{raw_truncated}\n```")

            sections.append("")

        sections.append(
            "## Instructions\n"
            "Based on the configurations and automated analysis above:\n\n"
            "1. **Root Cause Analysis**: What are the most likely causes of the 50 MB/s bottleneck? "
            "Rank by probability.\n\n"
            "2. **Configuration Issues**: What specific config changes would you recommend on each device? "
            "Provide exact CLI commands.\n\n"
            "3. **Missing Information**: What additional 'show' commands or tests should be run "
            "to confirm the diagnosis?\n\n"
            "4. **Server-Side Tuning**: What OS/TCP/NIC settings should be checked on the source "
            "and target servers? Provide specific sysctl or ethtool commands.\n\n"
            "5. **Quick Wins**: What are the fastest changes that could improve throughput right now?\n\n"
            "6. **Anything Else**: Are there any other issues you spot that our automated analysis missed?\n\n"
            "Be specific. Reference device names and interface names. Provide exact commands."
        )

        return "\n".join(sections)
