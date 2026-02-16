"""
Parser for Cisco IOS/IOS-XE/NX-OS switch and router configurations.

Extracts throughput-relevant settings:
- Interface speed/duplex/MTU
- QoS policies and shaping
- Spanning tree, port-channel, and L2 settings
- Routing and ACL information
- Buffer/queue settings
"""

import re


class CiscoConfigParser:
    VENDOR = "cisco"

    def __init__(self, config_text, device_name="unknown"):
        self.raw = config_text
        self.device_name = device_name
        self.hostname = None
        self.interfaces = []
        self.qos_policies = []
        self.acls = []
        self.routing = {}
        self.global_settings = {}
        self.warnings = []
        self._parse()

    def _parse(self):
        self._parse_hostname()
        self._parse_interfaces()
        self._parse_qos()
        self._parse_acls()
        self._parse_global()
        self._parse_routing()

    def _parse_hostname(self):
        m = re.search(r"^hostname\s+(\S+)", self.raw, re.MULTILINE)
        if m:
            self.hostname = m.group(1)
            self.device_name = self.hostname

    def _parse_interfaces(self):
        # Split config into interface blocks
        iface_blocks = re.split(r"^(?=interface\s)", self.raw, flags=re.MULTILINE)
        for block in iface_blocks:
            m = re.match(r"interface\s+(\S+)", block)
            if not m:
                continue
            iface = {
                "name": m.group(1),
                "description": None,
                "speed": None,
                "duplex": None,
                "mtu": None,
                "ip_mtu": None,
                "tcp_mss": None,
                "shutdown": False,
                "switchport_mode": None,
                "vlan": None,
                "channel_group": None,
                "negotiation": None,
                "storm_control": [],
                "service_policy_in": None,
                "service_policy_out": None,
                "ip_address": None,
                "errors": [],
                "raw": block.strip(),
            }

            for line in block.splitlines():
                line = line.strip()

                if re.match(r"description\s+(.+)", line):
                    iface["description"] = re.match(
                        r"description\s+(.+)", line
                    ).group(1)

                elif re.match(r"speed\s+(\S+)", line):
                    iface["speed"] = re.match(r"speed\s+(\S+)", line).group(1)

                elif re.match(r"duplex\s+(\S+)", line):
                    iface["duplex"] = re.match(r"duplex\s+(\S+)", line).group(1)

                elif re.match(r"mtu\s+(\d+)", line):
                    iface["mtu"] = int(re.match(r"mtu\s+(\d+)", line).group(1))

                elif re.match(r"ip\s+mtu\s+(\d+)", line):
                    iface["ip_mtu"] = int(
                        re.match(r"ip\s+mtu\s+(\d+)", line).group(1)
                    )

                elif re.match(r"ip\s+tcp\s+adjust-mss\s+(\d+)", line):
                    iface["tcp_mss"] = int(
                        re.match(r"ip\s+tcp\s+adjust-mss\s+(\d+)", line).group(1)
                    )

                elif line == "shutdown":
                    iface["shutdown"] = True

                elif re.match(r"switchport\s+mode\s+(\S+)", line):
                    iface["switchport_mode"] = re.match(
                        r"switchport\s+mode\s+(\S+)", line
                    ).group(1)

                elif re.match(r"switchport\s+access\s+vlan\s+(\d+)", line):
                    iface["vlan"] = int(
                        re.match(r"switchport\s+access\s+vlan\s+(\d+)", line).group(1)
                    )

                elif re.match(r"channel-group\s+(\d+)", line):
                    iface["channel_group"] = int(
                        re.match(r"channel-group\s+(\d+)", line).group(1)
                    )

                elif re.match(r"no\s+negotiation\s+auto", line):
                    iface["negotiation"] = "off"
                elif re.match(r"negotiation\s+auto", line):
                    iface["negotiation"] = "auto"

                elif re.match(r"service-policy\s+input\s+(\S+)", line):
                    iface["service_policy_in"] = re.match(
                        r"service-policy\s+input\s+(\S+)", line
                    ).group(1)

                elif re.match(r"service-policy\s+output\s+(\S+)", line):
                    iface["service_policy_out"] = re.match(
                        r"service-policy\s+output\s+(\S+)", line
                    ).group(1)

                elif re.match(r"ip\s+address\s+(\S+\s+\S+)", line):
                    iface["ip_address"] = re.match(
                        r"ip\s+address\s+(\S+\s+\S+)", line
                    ).group(1)

                elif re.match(r"storm-control\s+(.+)", line):
                    iface["storm_control"].append(
                        re.match(r"storm-control\s+(.+)", line).group(1)
                    )

            # Flag potential issues
            if iface["duplex"] == "half":
                iface["errors"].append(
                    "CRITICAL: Half-duplex configured — will severely limit throughput"
                )

            if iface["mtu"] and iface["mtu"] < 1500:
                iface["errors"].append(
                    f"WARNING: MTU {iface['mtu']} is below standard 1500 — may cause fragmentation"
                )

            if iface["speed"] and iface["speed"] not in ("auto", "10000", "25000", "40000", "100000"):
                if iface["speed"] in ("10", "100", "1000"):
                    iface["errors"].append(
                        f"WARNING: Interface speed hard-set to {iface['speed']} Mbps — potential bottleneck on 10G path"
                    )

            self.interfaces.append(iface)

    def _parse_qos(self):
        # Extract policy-map blocks
        policy_blocks = re.findall(
            r"^policy-map\s+(\S+)\n((?:\s+.+\n)*)", self.raw, re.MULTILINE
        )
        for name, body in policy_blocks:
            policy = {"name": name, "classes": [], "raw": f"policy-map {name}\n{body}"}

            class_blocks = re.split(r"(?=\s+class\s)", body)
            for cb in class_blocks:
                cm = re.match(r"\s+class\s+(\S+)", cb)
                if not cm:
                    continue
                cls = {"name": cm.group(1), "actions": []}
                for line in cb.splitlines():
                    line = line.strip()
                    if re.match(r"(police|shape|bandwidth|priority|queue-limit)", line):
                        cls["actions"].append(line)
                        # Check for rate limiters that could cap throughput
                        rate_match = re.search(r"(\d+)\s*(bps|kbps|mbps|gbps)", line, re.IGNORECASE)
                        if rate_match:
                            rate_val = int(rate_match.group(1))
                            rate_unit = rate_match.group(2).lower()
                            bps = rate_val
                            if rate_unit == "kbps":
                                bps = rate_val * 1000
                            elif rate_unit == "mbps":
                                bps = rate_val * 1_000_000
                            elif rate_unit == "gbps":
                                bps = rate_val * 1_000_000_000
                            if bps < 1_000_000_000:  # Less than 1 Gbps
                                self.warnings.append(
                                    f"QoS policy '{name}' class '{cm.group(1)}' "
                                    f"has rate limiter at {rate_val} {rate_unit} — "
                                    f"may throttle throughput"
                                )
                cls["actions"] = cls["actions"]
                policy["classes"].append(cls)
            self.qos_policies.append(policy)

    def _parse_acls(self):
        acl_blocks = re.findall(
            r"^(?:ip\s+)?access-list\s+(?:extended\s+)?(\S+)\n((?:\s+.+\n)*)",
            self.raw,
            re.MULTILINE,
        )
        for name, body in acl_blocks:
            self.acls.append({"name": name, "rules": body.strip().splitlines()})

    def _parse_global(self):
        # System MTU
        m = re.search(r"^system\s+mtu\s+(\d+)", self.raw, re.MULTILINE)
        if m:
            self.global_settings["system_mtu"] = int(m.group(1))

        # System MTU jumbo
        m = re.search(r"^system\s+mtu\s+jumbo\s+(\d+)", self.raw, re.MULTILINE)
        if m:
            self.global_settings["system_mtu_jumbo"] = int(m.group(1))

        # Spanning tree mode
        m = re.search(r"^spanning-tree\s+mode\s+(\S+)", self.raw, re.MULTILINE)
        if m:
            self.global_settings["stp_mode"] = m.group(1)

        # TCP window size (global)
        m = re.search(r"^ip\s+tcp\s+window-size\s+(\d+)", self.raw, re.MULTILINE)
        if m:
            self.global_settings["tcp_window_size"] = int(m.group(1))

    def _parse_routing(self):
        # Check for OSPF, BGP, EIGRP, static routes
        if re.search(r"^router\s+ospf", self.raw, re.MULTILINE):
            self.routing["ospf"] = True
        if re.search(r"^router\s+bgp", self.raw, re.MULTILINE):
            self.routing["bgp"] = True
        if re.search(r"^router\s+eigrp", self.raw, re.MULTILINE):
            self.routing["eigrp"] = True

        static_routes = re.findall(r"^ip\s+route\s+(.+)", self.raw, re.MULTILINE)
        if static_routes:
            self.routing["static_routes"] = static_routes

    def to_dict(self):
        return {
            "vendor": self.VENDOR,
            "device_name": self.device_name,
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "qos_policies": self.qos_policies,
            "acls": [{"name": a["name"], "rule_count": len(a["rules"])} for a in self.acls],
            "routing": self.routing,
            "global_settings": self.global_settings,
            "warnings": self.warnings,
        }
