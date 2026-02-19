"""
Parser for Palo Alto Networks firewall configurations (set-format and XML snippets).

Focuses on throughput-impacting settings:
- Interface MTU, speed, link-state
- Security policy (rules that may rate-limit or block)
- NAT rules (can add latency/overhead)
- Zone configuration
- QoS profiles
- Session limits
- Threat prevention profiles (IPS/IDS overhead)
- SSL decryption (major throughput impact)
"""

import re


class PaloAltoConfigParser:
    VENDOR = "paloalto"

    def __init__(self, config_text, device_name="unknown"):
        self.raw = config_text
        self.device_name = device_name
        self.hostname = None
        self.interfaces = []
        self.security_rules = []
        self.nat_rules = []
        self.zones = []
        self.qos_profiles = []
        self.session_settings = {}
        self.threat_profiles = []
        self.ssl_decryption = False
        self.warnings = []
        self._parse()

    def _parse(self):
        self._detect_format()
        self._parse_hostname()
        self._parse_interfaces()
        self._parse_security_rules()
        self._parse_nat()
        self._parse_zones()
        self._parse_qos()
        self._parse_session_settings()
        self._parse_threat_prevention()
        self._parse_ssl_decryption()

    def _detect_format(self):
        # Detect if it's set-format or XML
        self.is_set_format = bool(re.search(r"^set\s+", self.raw, re.MULTILINE))

    def _parse_hostname(self):
        if self.is_set_format:
            m = re.search(
                r"^set\s+deviceconfig\s+system\s+hostname\s+(\S+)",
                self.raw,
                re.MULTILINE,
            )
        else:
            m = re.search(r"<hostname>(\S+)</hostname>", self.raw)
        if m:
            self.hostname = m.group(1)
            self.device_name = self.hostname

    def _parse_interfaces(self):
        if self.is_set_format:
            # Match ethernet interface lines
            iface_lines = re.findall(
                r"^set\s+network\s+interface\s+ethernet\s+(\S+)\s+(.+)",
                self.raw,
                re.MULTILINE,
            )
            ifaces = {}
            for iface_name, rest in iface_lines:
                if iface_name not in ifaces:
                    ifaces[iface_name] = {
                        "name": f"ethernet{iface_name}",
                        "mtu": None,
                        "speed": None,
                        "duplex": None,
                        "link_state": None,
                        "ip_address": None,
                        "zone": None,
                        "errors": [],
                    }
                iface = ifaces[iface_name]

                mtu_match = re.search(r"mtu\s+(\d+)", rest)
                if mtu_match:
                    iface["mtu"] = int(mtu_match.group(1))

                speed_match = re.search(r"link-speed\s+(\S+)", rest)
                if speed_match:
                    iface["speed"] = speed_match.group(1)

                duplex_match = re.search(r"link-duplex\s+(\S+)", rest)
                if duplex_match:
                    iface["duplex"] = duplex_match.group(1)

                ip_match = re.search(r"layer3\s+ip\s+(\S+)", rest)
                if ip_match:
                    iface["ip_address"] = ip_match.group(1)

                state_match = re.search(r"link-state\s+(\S+)", rest)
                if state_match:
                    iface["link_state"] = state_match.group(1)

            for iface in ifaces.values():
                if iface["duplex"] and "half" in iface["duplex"].lower():
                    iface["errors"].append(
                        "CRITICAL: Half-duplex on firewall interface — severe bottleneck"
                    )
                if iface["mtu"] and iface["mtu"] < 1500:
                    iface["errors"].append(
                        f"WARNING: MTU {iface['mtu']} below 1500 — fragmentation risk"
                    )
                self.interfaces.append(iface)
        else:
            # Basic XML parsing
            iface_blocks = re.findall(
                r"<entry\s+name=\"(ethernet\d+/\d+)\">(.*?)</entry>",
                self.raw,
                re.DOTALL,
            )
            for name, body in iface_blocks:
                iface = {
                    "name": name,
                    "mtu": None,
                    "speed": None,
                    "ip_address": None,
                    "errors": [],
                }
                mtu_m = re.search(r"<mtu>(\d+)</mtu>", body)
                if mtu_m:
                    iface["mtu"] = int(mtu_m.group(1))
                self.interfaces.append(iface)

    def _parse_security_rules(self):
        if self.is_set_format:
            rule_names = set(
                re.findall(
                    r"^set\s+rulebase\s+security\s+rules\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
            )
            for name in rule_names:
                rule = {"name": name, "action": None, "profile_group": None}
                action_m = re.search(
                    rf"^set\s+rulebase\s+security\s+rules\s+{re.escape(name)}\s+action\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
                if action_m:
                    rule["action"] = action_m.group(1)

                profile_m = re.search(
                    rf"^set\s+rulebase\s+security\s+rules\s+{re.escape(name)}\s+profile-setting\s+group\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
                if profile_m:
                    rule["profile_group"] = profile_m.group(1)
                self.security_rules.append(rule)

            # Warn about rules with threat profiles (add processing overhead)
            rules_with_profiles = [
                r for r in self.security_rules if r["profile_group"]
            ]
            if len(rules_with_profiles) > 10:
                self.warnings.append(
                    f"{len(rules_with_profiles)} security rules have threat inspection profiles — "
                    "high inspection load can reduce firewall throughput"
                )

    def _parse_nat(self):
        if self.is_set_format:
            nat_names = set(
                re.findall(
                    r"^set\s+rulebase\s+nat\s+rules\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
            )
            for name in nat_names:
                self.nat_rules.append({"name": name})
            if len(self.nat_rules) > 50:
                self.warnings.append(
                    f"{len(self.nat_rules)} NAT rules — large NAT table can add latency"
                )

    def _parse_zones(self):
        if self.is_set_format:
            zone_names = set(
                re.findall(
                    r"^set\s+network\s+zone\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
            )
            self.zones = list(zone_names)

    def _parse_qos(self):
        if self.is_set_format:
            qos_lines = re.findall(
                r"^set\s+network\s+qos\s+(.+)", self.raw, re.MULTILINE
            )
            if qos_lines:
                self.qos_profiles = qos_lines
                self.warnings.append(
                    "QoS profiles configured on firewall — verify shaping rates "
                    "are not capping throughput below 5 Gbps"
                )

    def _parse_session_settings(self):
        if self.is_set_format:
            sess_lines = re.findall(
                r"^set\s+deviceconfig\s+setting\s+session\s+(.+)",
                self.raw,
                re.MULTILINE,
            )
            for line in sess_lines:
                parts = line.split()
                if len(parts) >= 2:
                    self.session_settings[parts[0]] = parts[1]

    def _parse_threat_prevention(self):
        if self.is_set_format:
            profiles = set(
                re.findall(
                    r"^set\s+profiles\s+(vulnerability|spyware|antivirus|file-blocking|wildfire-analysis)\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
            )
            self.threat_profiles = [
                {"type": p[0], "name": p[1]} for p in profiles
            ]
            if self.threat_profiles:
                self.warnings.append(
                    f"{len(self.threat_profiles)} threat prevention profiles active — "
                    "IPS/AV inspection adds latency and reduces firewall throughput capacity"
                )

    def _parse_ssl_decryption(self):
        if self.is_set_format:
            if re.search(r"^set\s+rulebase\s+decryption", self.raw, re.MULTILINE):
                self.ssl_decryption = True
                self.warnings.append(
                    "CRITICAL: SSL decryption is enabled — this can reduce firewall "
                    "throughput by 50-80% depending on hardware model and traffic mix"
                )

    def to_dict(self):
        return {
            "vendor": self.VENDOR,
            "device_name": self.device_name,
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "security_rules_count": len(self.security_rules),
            "nat_rules_count": len(self.nat_rules),
            "zones": self.zones,
            "qos_profiles_count": len(self.qos_profiles),
            "session_settings": self.session_settings,
            "threat_profiles": self.threat_profiles,
            "ssl_decryption": self.ssl_decryption,
            "warnings": self.warnings,
        }
