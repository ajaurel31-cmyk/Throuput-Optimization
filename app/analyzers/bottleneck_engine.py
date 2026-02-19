"""
Bottleneck Analysis Engine

Models the actual network path for ATL-to-PHX (or any site-to-site) traffic:

  Source Server → Core Switch → Firewall → Edge Switch → WAN → Edge Switch → Firewall → Core Switch → Target Server

At each hop, checks for common throughput killers:
  1. MTU mismatches (fragmentation / black-hole)
  2. Speed/duplex mismatches
  3. QoS / traffic shaping / policing
  4. Half-duplex interfaces
  5. Interface errors
  6. Firewall inspection overhead (IPS, AV, SSL decrypt)
  7. TCP window size / MSS clamping
  8. Jumbo frame inconsistencies across path
  9. Suboptimal routing (asymmetric, extra hops)
  10. NIC offload / server-side TCP tuning gaps
"""

from dataclasses import dataclass, field


# Canonical device roles in the traffic path
PATH_ORDER = [
    "source_server",
    "core_switch_local",
    "firewall_local",
    "edge_switch_local",
    # --- WAN ---
    "edge_switch_remote",
    "firewall_remote",
    "core_switch_remote",
    "target_server",
]

ROLE_LABELS = {
    "source_server": "Source Server",
    "core_switch_local": "Core Switch (Local / ATL)",
    "firewall_local": "Firewall (Local / ATL)",
    "edge_switch_local": "Edge Switch (Local / ATL)",
    "edge_switch_remote": "Edge Switch (Remote / PHX)",
    "firewall_remote": "Firewall (Remote / PHX)",
    "core_switch_remote": "Core Switch (Remote / PHX)",
    "target_server": "Target Server",
}

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"


@dataclass
class Finding:
    severity: str  # critical, warning, info
    category: str  # mtu, speed_duplex, qos, firewall, tcp, routing, general
    device: str
    title: str
    detail: str
    recommendation: str


@dataclass
class BottleneckReport:
    findings: list = field(default_factory=list)
    path_devices: list = field(default_factory=list)
    mtu_path: list = field(default_factory=list)
    speed_path: list = field(default_factory=list)
    overall_risk: str = "unknown"
    max_theoretical_mbps: float = 0
    estimated_bottleneck_mbps: float = 0
    summary: str = ""

    def to_dict(self):
        return {
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "device": f.device,
                    "title": f.title,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "path_devices": self.path_devices,
            "mtu_path": self.mtu_path,
            "speed_path": self.speed_path,
            "overall_risk": self.overall_risk,
            "max_theoretical_mbps": self.max_theoretical_mbps,
            "estimated_bottleneck_mbps": self.estimated_bottleneck_mbps,
            "summary": self.summary,
            "stats": {
                "critical": len(
                    [f for f in self.findings if f.severity == SEVERITY_CRITICAL]
                ),
                "warning": len(
                    [f for f in self.findings if f.severity == SEVERITY_WARNING]
                ),
                "info": len(
                    [f for f in self.findings if f.severity == SEVERITY_INFO]
                ),
            },
        }


class BottleneckAnalyzer:
    """
    Analyzes parsed device configs to find throughput bottlenecks across the
    network path.
    """

    def __init__(self, devices=None, link_speed_gbps=10):
        """
        Args:
            devices: list of parsed device dicts (from config parsers)
            link_speed_gbps: WAN link speed in Gbps (default 10)
        """
        self.devices = devices or []
        self.link_speed_gbps = link_speed_gbps
        self.report = BottleneckReport()
        self.report.max_theoretical_mbps = link_speed_gbps * 1000

    def analyze(self):
        """Run full analysis and return report."""
        self._build_path()
        self._check_mtu_consistency()
        self._check_speed_duplex()
        self._check_qos_shaping()
        self._check_firewall_overhead()
        self._check_tcp_settings()
        self._check_device_warnings()
        self._calculate_risk()
        self._generate_summary()
        return self.report

    def _build_path(self):
        """Map uploaded devices to positions in the network path."""
        for device in self.devices:
            role = device.get("device_role", "unknown")
            label = ROLE_LABELS.get(role, role)
            self.report.path_devices.append(
                {
                    "role": role,
                    "label": label,
                    "device_name": device.get("device_name", "unknown"),
                    "vendor": device.get("vendor", "unknown"),
                }
            )

    def _check_mtu_consistency(self):
        """
        Check MTU values across all devices in the path.
        MTU mismatch is one of the most common causes of throughput problems.
        - Standard MTU: 1500
        - Jumbo frames: 9000-9216
        - If any device in the path has a smaller MTU, packets get fragmented
          or dropped (PMTUD black hole if ICMP is blocked by firewall)
        """
        path_mtus = []

        for device in self.devices:
            device_name = device.get("device_name", "unknown")
            role = device.get("device_role", "unknown")

            # Collect per-interface MTUs
            for iface in device.get("interfaces", []):
                mtu = iface.get("mtu") or iface.get("ip_mtu")
                if mtu:
                    path_mtus.append(
                        {
                            "device": device_name,
                            "role": role,
                            "interface": iface.get("name", "?"),
                            "mtu": mtu,
                        }
                    )

            # Check global/system MTU
            global_mtu = device.get("global_settings", {}).get("system_mtu")
            if global_mtu:
                path_mtus.append(
                    {
                        "device": device_name,
                        "role": role,
                        "interface": "system-global",
                        "mtu": global_mtu,
                    }
                )

        self.report.mtu_path = path_mtus

        if not path_mtus:
            self.report.findings.append(
                Finding(
                    severity=SEVERITY_INFO,
                    category="mtu",
                    device="all",
                    title="No explicit MTU values found in configs",
                    detail=(
                        "No MTU settings were found in the uploaded configurations. "
                        "Devices may be using default MTU (typically 1500). "
                        "If jumbo frames are expected, this could be a problem."
                    ),
                    recommendation=(
                        "Verify MTU on each device with 'show interface' commands. "
                        "Run path MTU discovery test: ping -M do -s 8972 <target_ip>"
                    ),
                )
            )
            return

        mtu_values = set(m["mtu"] for m in path_mtus)
        min_mtu = min(m["mtu"] for m in path_mtus)
        max_mtu = max(m["mtu"] for m in path_mtus)

        if len(mtu_values) > 1:
            self.report.findings.append(
                Finding(
                    severity=SEVERITY_CRITICAL,
                    category="mtu",
                    device="path",
                    title=f"MTU MISMATCH across path: {min_mtu} to {max_mtu}",
                    detail=(
                        f"Found {len(mtu_values)} different MTU values across the path: "
                        f"{sorted(mtu_values)}. "
                        f"This causes fragmentation (adds overhead and CPU load) or "
                        f"packet drops if PMTUD fails (ICMP blocked at firewall). "
                        f"Effective path MTU is limited to {min_mtu}."
                    ),
                    recommendation=(
                        f"Standardize MTU to {min_mtu} across all devices, or better yet, "
                        f"set all devices to the same MTU (1500 for standard, 9216 for jumbo). "
                        f"Ensure ICMP 'need to fragment' (type 3 code 4) is allowed through firewalls "
                        f"for PMTUD to work. Devices with mismatched MTU:\n"
                        + "\n".join(
                            f"  - {m['device']} ({m['interface']}): MTU {m['mtu']}"
                            for m in path_mtus
                        )
                    ),
                )
            )

        if max_mtu > 1500 and min_mtu <= 1500:
            self.report.findings.append(
                Finding(
                    severity=SEVERITY_CRITICAL,
                    category="mtu",
                    device="path",
                    title="Jumbo frames enabled on some devices but not all",
                    detail=(
                        f"Some devices have jumbo frame MTU ({max_mtu}) but others are at "
                        f"standard ({min_mtu}). This is a classic throughput killer — "
                        f"jumbo frames will be fragmented or dropped at the non-jumbo hop."
                    ),
                    recommendation=(
                        "Either enable jumbo frames (MTU 9216) on ALL devices in the path "
                        "(including the firewall — verify it supports jumbo), or disable "
                        "jumbo frames everywhere and use standard 1500 MTU."
                    ),
                )
            )

    def _check_speed_duplex(self):
        """
        Check for speed and duplex mismatches.
        A single half-duplex or 100 Mbps link in a 10G path kills throughput.
        Also check for auto-negotiation issues.
        """
        path_speeds = []

        for device in self.devices:
            device_name = device.get("device_name", "unknown")
            role = device.get("device_role", "unknown")

            for iface in device.get("interfaces", []):
                if iface.get("shutdown"):
                    continue

                speed = iface.get("speed")
                duplex = iface.get("duplex")
                negotiation = iface.get("negotiation")

                if speed or duplex:
                    path_speeds.append(
                        {
                            "device": device_name,
                            "role": role,
                            "interface": iface.get("name", "?"),
                            "speed": speed,
                            "duplex": duplex,
                            "negotiation": negotiation,
                        }
                    )

                # Half duplex check
                if duplex and "half" in str(duplex).lower():
                    self.report.findings.append(
                        Finding(
                            severity=SEVERITY_CRITICAL,
                            category="speed_duplex",
                            device=device_name,
                            title=f"HALF-DUPLEX on {iface.get('name', '?')}",
                            detail=(
                                f"Interface {iface.get('name', '?')} on {device_name} is set to "
                                f"half-duplex. This limits throughput to roughly half the link speed "
                                f"and causes collisions, late collisions, and retransmissions."
                            ),
                            recommendation=(
                                f"Set to full-duplex: 'duplex full' on {iface.get('name', '?')}. "
                                f"Verify both ends of the link match."
                            ),
                        )
                    )

                # Sub-10G speed check on uplink/trunk interfaces
                if speed and speed not in ("auto", "10000", "25000", "40000", "100000"):
                    speed_val = speed
                    try:
                        speed_int = int(speed)
                        if speed_int < 5000:
                            self.report.findings.append(
                                Finding(
                                    severity=SEVERITY_CRITICAL,
                                    category="speed_duplex",
                                    device=device_name,
                                    title=f"Speed bottleneck: {speed_int} Mbps on {iface.get('name', '?')}",
                                    detail=(
                                        f"Interface {iface.get('name', '?')} on {device_name} "
                                        f"is set to {speed_int} Mbps. On a 5 Gbps WAN path, "
                                        f"this interface is a hard ceiling for throughput."
                                    ),
                                    recommendation=(
                                        f"Upgrade or reconfigure to 5G+. Check SFP/transceiver type "
                                        f"and cable. Verify the remote end matches."
                                    ),
                                )
                            )
                    except ValueError:
                        pass

                # Auto-negotiation mismatch risk
                if negotiation == "off" and not speed:
                    self.report.findings.append(
                        Finding(
                            severity=SEVERITY_WARNING,
                            category="speed_duplex",
                            device=device_name,
                            title=f"Auto-negotiation disabled without explicit speed on {iface.get('name', '?')}",
                            detail=(
                                f"Auto-negotiation is off on {iface.get('name', '?')} but no "
                                f"speed is explicitly set. The remote end may negotiate to a "
                                f"different speed/duplex causing mismatch."
                            ),
                            recommendation=(
                                "Either enable auto-negotiation on both ends, or explicitly "
                                "set speed and duplex on BOTH ends of the link."
                            ),
                        )
                    )

        self.report.speed_path = path_speeds

    def _check_qos_shaping(self):
        """Check for QoS policies that may be throttling traffic."""
        for device in self.devices:
            device_name = device.get("device_name", "unknown")

            # Check QoS policies (Cisco)
            for policy in device.get("qos_policies", []):
                for cls in policy.get("classes", []):
                    for action in cls.get("actions", []):
                        # Look for shapers and policers
                        if "shape" in action.lower() or "police" in action.lower():
                            self.report.findings.append(
                                Finding(
                                    severity=SEVERITY_WARNING,
                                    category="qos",
                                    device=device_name,
                                    title=f"Traffic shaping/policing in policy '{policy['name']}'",
                                    detail=(
                                        f"QoS policy '{policy['name']}', class '{cls['name']}' "
                                        f"has shaping/policing: {action}. This could be capping "
                                        f"throughput below the physical link rate."
                                    ),
                                    recommendation=(
                                        "Review the configured rate against expected throughput. "
                                        "If the shaper rate is below 5 Gbps and this applies to "
                                        "the data transfer traffic, it's your bottleneck. "
                                        "Check with 'show policy-map interface <iface>'."
                                    ),
                                )
                            )

            # Check policers (Juniper)
            for policer in device.get("policers", []):
                self.report.findings.append(
                    Finding(
                        severity=SEVERITY_WARNING,
                        category="qos",
                        device=device_name,
                        title=f"Policer '{policer['name']}' configured",
                        detail=(
                            f"Policer '{policer['name']}' found on {device_name}. "
                            f"Settings: {policer.get('settings', [])}"
                        ),
                        recommendation=(
                            "Verify the bandwidth-limit and burst-size are appropriate "
                            "for 10G throughput."
                        ),
                    )
                )

    def _check_firewall_overhead(self):
        """Check for firewall features that reduce throughput."""
        for device in self.devices:
            if device.get("vendor") != "paloalto":
                continue

            device_name = device.get("device_name", "unknown")

            # SSL decryption
            if device.get("ssl_decryption"):
                self.report.findings.append(
                    Finding(
                        severity=SEVERITY_CRITICAL,
                        category="firewall",
                        device=device_name,
                        title="SSL Decryption enabled on firewall",
                        detail=(
                            "SSL/TLS decryption is enabled. This is one of the most "
                            "CPU-intensive firewall operations and can reduce throughput "
                            "by 50-80% depending on the hardware platform, cipher suites, "
                            "and session count."
                        ),
                        recommendation=(
                            "Check if the data transfer traffic between ATL and PHX is "
                            "being decrypted. If so, consider adding a decryption exclusion "
                            "rule for the specific server IPs or applications doing the "
                            "bulk transfer. Monitor firewall CPU during transfers."
                        ),
                    )
                )

            # Threat prevention profiles
            if device.get("threat_profiles"):
                profiles = device["threat_profiles"]
                self.report.findings.append(
                    Finding(
                        severity=SEVERITY_WARNING,
                        category="firewall",
                        device=device_name,
                        title=f"{len(profiles)} threat prevention profiles active",
                        detail=(
                            f"Active profiles: "
                            f"{', '.join(p['type'] + ':' + p['name'] for p in profiles[:5])}. "
                            f"Each inspection layer (AV, IPS, spyware, file-blocking, WildFire) "
                            f"adds processing overhead that reduces firewall throughput."
                        ),
                        recommendation=(
                            "Check if bulk data transfer traffic needs full threat inspection. "
                            "Consider creating a security policy rule specifically for the "
                            "server-to-server traffic with reduced or no threat profiles. "
                            "Monitor firewall dataplane CPU: 'show running resource-monitor'."
                        ),
                    )
                )

            # High security rule count
            rule_count = device.get("security_rules_count", 0)
            if rule_count > 500:
                self.report.findings.append(
                    Finding(
                        severity=SEVERITY_WARNING,
                        category="firewall",
                        device=device_name,
                        title=f"{rule_count} security rules — rule lookup overhead",
                        detail=(
                            f"The firewall has {rule_count} security rules. Large rule bases "
                            f"increase per-packet processing time."
                        ),
                        recommendation=(
                            "Ensure the rule matching the ATL-PHX traffic is near the top "
                            "of the rule base. Consider rule optimization and consolidation."
                        ),
                    )
                )

    def _check_tcp_settings(self):
        """Check TCP-related settings that affect throughput."""
        for device in self.devices:
            device_name = device.get("device_name", "unknown")

            # TCP MSS clamping
            for iface in device.get("interfaces", []):
                tcp_mss = iface.get("tcp_mss")
                if tcp_mss and tcp_mss < 1460:
                    self.report.findings.append(
                        Finding(
                            severity=SEVERITY_WARNING,
                            category="tcp",
                            device=device_name,
                            title=f"TCP MSS clamped to {tcp_mss} on {iface.get('name', '?')}",
                            detail=(
                                f"TCP Maximum Segment Size is clamped to {tcp_mss} bytes. "
                                f"Standard is 1460 (1500 MTU - 40 bytes IP+TCP headers). "
                                f"Lower MSS means more packets for the same data volume, "
                                f"increasing overhead."
                            ),
                            recommendation=(
                                f"If MTU is 1500 across the path, set MSS to 1460. "
                                f"If jumbo frames are used, set MSS to MTU - 40."
                            ),
                        )
                    )

            # Global TCP window size
            tcp_window = device.get("global_settings", {}).get("tcp_window_size")
            if tcp_window and tcp_window < 65535:
                self.report.findings.append(
                    Finding(
                        severity=SEVERITY_WARNING,
                        category="tcp",
                        device=device_name,
                        title=f"TCP window size limited to {tcp_window}",
                        detail=(
                            f"Global TCP window size is set to {tcp_window} bytes. "
                            f"For high-bandwidth, high-latency paths (like ATL to PHX, "
                            f"~30-50ms RTT), the bandwidth-delay product requires much "
                            f"larger windows. BDP = 5 Gbps * 40ms = ~25 MB window needed."
                        ),
                        recommendation=(
                            "Enable TCP window scaling (RFC 1323) and increase TCP buffer sizes. "
                            "On Linux servers: sysctl net.ipv4.tcp_window_scaling=1, "
                            "net.core.rmem_max=67108864, net.core.wmem_max=67108864."
                        ),
                    )
                )

    def _check_device_warnings(self):
        """Propagate warnings from individual device parsers."""
        for device in self.devices:
            device_name = device.get("device_name", "unknown")
            for warning in device.get("warnings", []):
                severity = SEVERITY_WARNING
                if "CRITICAL" in warning.upper():
                    severity = SEVERITY_CRITICAL
                self.report.findings.append(
                    Finding(
                        severity=severity,
                        category="general",
                        device=device_name,
                        title=warning[:100],
                        detail=warning,
                        recommendation="Review the device configuration for this issue.",
                    )
                )

    def _calculate_risk(self):
        """Calculate overall risk level based on findings."""
        criticals = len(
            [f for f in self.report.findings if f.severity == SEVERITY_CRITICAL]
        )
        warnings = len(
            [f for f in self.report.findings if f.severity == SEVERITY_WARNING]
        )

        if criticals > 0:
            self.report.overall_risk = "high"
        elif warnings > 2:
            self.report.overall_risk = "medium"
        elif warnings > 0:
            self.report.overall_risk = "low"
        else:
            self.report.overall_risk = "minimal"

        # Estimate bottleneck based on findings
        estimated = self.link_speed_gbps * 1000  # Start at max
        for f in self.report.findings:
            if f.severity == SEVERITY_CRITICAL:
                if "half-duplex" in f.title.lower():
                    estimated = min(estimated, 500)  # ~500 Mbps max with half duplex
                elif "ssl decryption" in f.title.lower():
                    estimated = min(estimated, 2000)  # SSL decrypt tanks throughput
                elif "speed" in f.category and "1000" in f.detail:
                    estimated = min(estimated, 1000)
                elif "speed" in f.category and "100" in f.detail:
                    estimated = min(estimated, 100)
                elif "mtu mismatch" in f.title.lower():
                    estimated = min(estimated, estimated * 0.7)

            elif f.severity == SEVERITY_WARNING:
                if "shaping" in f.title.lower() or "policing" in f.title.lower():
                    estimated = min(estimated, estimated * 0.8)
                elif "threat" in f.title.lower():
                    estimated = min(estimated, estimated * 0.85)

        self.report.estimated_bottleneck_mbps = round(estimated, 1)

    def _generate_summary(self):
        """Generate human-readable summary."""
        stats = {
            "critical": len(
                [f for f in self.report.findings if f.severity == SEVERITY_CRITICAL]
            ),
            "warning": len(
                [f for f in self.report.findings if f.severity == SEVERITY_WARNING]
            ),
            "info": len(
                [f for f in self.report.findings if f.severity == SEVERITY_INFO]
            ),
        }

        lines = [
            f"Analyzed {len(self.devices)} device(s) on the network path.",
            f"Found {stats['critical']} critical, {stats['warning']} warning, "
            f"and {stats['info']} informational issues.",
            f"",
            f"WAN Link: {self.link_speed_gbps} Gbps ({self.report.max_theoretical_mbps} Mbps theoretical max)",
            f"Estimated effective throughput: {self.report.estimated_bottleneck_mbps} Mbps",
            f"Overall risk level: {self.report.overall_risk.upper()}",
        ]

        if stats["critical"] > 0:
            lines.append("")
            lines.append("CRITICAL issues found that are likely causing throughput degradation:")
            for f in self.report.findings:
                if f.severity == SEVERITY_CRITICAL:
                    lines.append(f"  - [{f.device}] {f.title}")

        self.report.summary = "\n".join(lines)
