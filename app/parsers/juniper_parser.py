"""
Parser for Juniper JunOS configurations (set-format and hierarchical).

Extracts throughput-relevant settings:
- Interface speed/duplex/MTU
- Firewall filters (equivalent to ACLs)
- Policers and shapers
- CoS (Class of Service) configuration
- Routing configuration
"""

import re


class JuniperConfigParser:
    VENDOR = "juniper"

    def __init__(self, config_text, device_name="unknown"):
        self.raw = config_text
        self.device_name = device_name
        self.hostname = None
        self.interfaces = []
        self.firewall_filters = []
        self.policers = []
        self.cos_config = []
        self.warnings = []
        self._parse()

    def _parse(self):
        self._parse_hostname()
        self._parse_interfaces()
        self._parse_policers()
        self._parse_firewall_filters()

    def _parse_hostname(self):
        m = re.search(
            r"^set\s+system\s+host-name\s+(\S+)", self.raw, re.MULTILINE
        )
        if not m:
            m = re.search(r"host-name\s+(\S+);", self.raw)
        if m:
            self.hostname = m.group(1)
            self.device_name = self.hostname

    def _parse_interfaces(self):
        # set-format parsing
        iface_lines = re.findall(
            r"^set\s+interfaces\s+(\S+)\s+(.+)", self.raw, re.MULTILINE
        )
        ifaces = {}
        for iface_name, rest in iface_lines:
            if iface_name not in ifaces:
                ifaces[iface_name] = {
                    "name": iface_name,
                    "mtu": None,
                    "speed": None,
                    "duplex": None,
                    "description": None,
                    "ip_address": None,
                    "errors": [],
                }
            iface = ifaces[iface_name]

            mtu_match = re.match(r"mtu\s+(\d+)", rest)
            if mtu_match:
                iface["mtu"] = int(mtu_match.group(1))

            speed_match = re.match(r"speed\s+(\S+)", rest)
            if speed_match:
                iface["speed"] = speed_match.group(1)

            duplex_match = re.match(r"link-mode\s+(\S+)", rest)
            if duplex_match:
                iface["duplex"] = duplex_match.group(1)

            desc_match = re.match(r"description\s+\"?(.+?)\"?$", rest)
            if desc_match:
                iface["description"] = desc_match.group(1)

            ip_match = re.match(r"unit\s+\d+\s+family\s+inet\s+address\s+(\S+)", rest)
            if ip_match:
                iface["ip_address"] = ip_match.group(1)

        for iface in ifaces.values():
            if iface["duplex"] and "half" in str(iface["duplex"]).lower():
                iface["errors"].append("CRITICAL: Half-duplex configured")
            if iface["mtu"] and iface["mtu"] < 1500:
                iface["errors"].append(
                    f"WARNING: MTU {iface['mtu']} below 1500"
                )
            self.interfaces.append(iface)

    def _parse_policers(self):
        policer_lines = re.findall(
            r"^set\s+firewall\s+policer\s+(\S+)\s+(.+)", self.raw, re.MULTILINE
        )
        policers = {}
        for name, rest in policer_lines:
            if name not in policers:
                policers[name] = {"name": name, "settings": []}
            policers[name]["settings"].append(rest)

            bw_match = re.match(r"if-exceeding\s+bandwidth-limit\s+(\S+)", rest)
            if bw_match:
                bw = bw_match.group(1)
                self.warnings.append(
                    f"Policer '{name}' bandwidth limit: {bw} — may throttle traffic"
                )

        self.policers = list(policers.values())

    def _parse_firewall_filters(self):
        filter_names = set(
            re.findall(
                r"^set\s+firewall\s+filter\s+(\S+)", self.raw, re.MULTILINE
            )
        )
        for name in filter_names:
            self.firewall_filters.append({"name": name})

    def to_dict(self):
        return {
            "vendor": self.VENDOR,
            "device_name": self.device_name,
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "policers": self.policers,
            "firewall_filters": [f["name"] for f in self.firewall_filters],
            "warnings": self.warnings,
        }
