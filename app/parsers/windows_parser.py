"""
Parser for Windows Server network configuration (PowerShell / netsh output).

Extracts throughput-relevant settings from common PowerShell commands:
- Get-NetAdapter / Get-NetIPConfiguration
- Get-NetAdapterAdvancedProperty
- Get-NetTCPSetting / netsh interface tcp show global
- Get-NetRoute
"""

import re


class WindowsConfigParser:
    VENDOR = "windows"

    def __init__(self, config_text, device_name="unknown"):
        self.raw = config_text
        self.device_name = device_name
        self.hostname = None
        self.interfaces = []
        self.global_settings = {}
        self.warnings = []
        self._parse()

    def _parse(self):
        self._parse_hostname()
        self._parse_adapters()
        self._parse_advanced_properties()
        self._parse_ip_config()
        self._parse_tcp_settings()
        self._parse_routes()

    # ------------------------------------------------------------------
    # Hostname
    # ------------------------------------------------------------------

    def _parse_hostname(self):
        # Look for output of 'hostname' command in the pasted text
        m = re.search(r"=+\s*HOSTNAME\s*=+\s*\n(\S+)", self.raw,
                      re.IGNORECASE)
        if m:
            self.hostname = m.group(1).strip()
            self.device_name = self.hostname
            return

        # Fallback: ComputerName from Get-NetAdapter output
        m = re.search(r"ComputerName\s*:\s*(\S+)", self.raw, re.IGNORECASE)
        if m:
            self.hostname = m.group(1)
            self.device_name = self.hostname

    # ------------------------------------------------------------------
    # Network adapters (Get-NetAdapter output)
    # ------------------------------------------------------------------

    def _parse_adapters(self):
        """Parse Get-NetAdapter Format-List output into interface dicts."""
        # Split by adapter blocks — each starts with "Name :"
        blocks = re.split(r"(?=^Name\s*:)", self.raw, flags=re.MULTILINE)

        for block in blocks:
            name_m = re.match(r"Name\s*:\s*(.+)", block)
            if not name_m:
                continue

            iface = self._new_iface(name_m.group(1).strip())

            # LinkSpeed: "10 Gbps", "1 Gbps", "100 Mbps"
            speed_m = re.search(r"LinkSpeed\s*:\s*(.+)", block,
                                re.IGNORECASE)
            if speed_m:
                iface["speed"] = self._parse_link_speed(
                    speed_m.group(1).strip()
                )

            # Status: Up / Disconnected / Disabled
            status_m = re.search(r"Status\s*:\s*(\S+)", block, re.IGNORECASE)
            if status_m:
                status = status_m.group(1).strip().lower()
                if status in ("disconnected", "disabled", "notpresent"):
                    iface["shutdown"] = True

            # MTUSize from Get-NetAdapter
            mtu_m = re.search(r"MTUSize\s*:\s*(\d+)", block, re.IGNORECASE)
            if mtu_m:
                iface["mtu"] = int(mtu_m.group(1))

            # InterfaceDescription
            desc_m = re.search(r"InterfaceDescription\s*:\s*(.+)", block,
                               re.IGNORECASE)
            if desc_m:
                iface["description"] = desc_m.group(1).strip()

            # MediaType
            media_m = re.search(r"MediaType\s*:\s*(.+)", block,
                                re.IGNORECASE)
            if media_m:
                iface["media_type"] = media_m.group(1).strip()

            self.interfaces.append(iface)

        # If no Format-List output found, try table format
        if not self.interfaces:
            self._parse_adapters_table()

    def _parse_adapters_table(self):
        """Parse Get-NetAdapter table format output."""
        for m in re.finditer(
            r"^(\S+)\s+.*?(Up|Disconnected|Disabled)\s+"
            r"(\d+\s*(?:Gbps|Mbps|Kbps))",
            self.raw, re.MULTILINE | re.IGNORECASE
        ):
            iface = self._new_iface(m.group(1))
            iface["speed"] = self._parse_link_speed(m.group(3))
            if m.group(2).lower() != "up":
                iface["shutdown"] = True
            self.interfaces.append(iface)

    # ------------------------------------------------------------------
    # Advanced adapter properties (Get-NetAdapterAdvancedProperty)
    # ------------------------------------------------------------------

    def _parse_advanced_properties(self):
        """Parse Get-NetAdapterAdvancedProperty output for offloads, RSS, etc."""
        # Build a lookup of interface names
        iface_map = {iface["name"].lower(): iface
                     for iface in self.interfaces}

        for m in re.finditer(
            r"^(\S+)\s+(.+?)\s{2,}(\S+.*)$",
            self.raw, re.MULTILINE
        ):
            adapter = m.group(1).strip()
            prop_name = m.group(2).strip().lower()
            prop_val = m.group(3).strip()

            iface = iface_map.get(adapter.lower())
            if not iface:
                continue

            if "jumbo" in prop_name or "mtu" in prop_name:
                mtu_val = re.search(r"(\d+)", prop_val)
                if mtu_val:
                    val = int(mtu_val.group(1))
                    if val > 1500:
                        iface["mtu"] = val
                if "disable" in prop_val.lower():
                    pass  # jumbo disabled, MTU stays default

            elif "speed" in prop_name and "duplex" not in prop_name:
                iface["speed"] = self._parse_link_speed(prop_val)

            elif "duplex" in prop_name:
                iface["duplex"] = prop_val.lower().replace(
                    "full duplex", "full"
                ).replace("half duplex", "half").strip()
                if "half" in iface["duplex"]:
                    iface["errors"].append(
                        "CRITICAL: Half-duplex — will severely limit "
                        "throughput"
                    )

            elif "flow control" in prop_name:
                iface["flow_control"] = prop_val

            elif any(kw in prop_name for kw in (
                "offload", "rss", "chimney", "rsc", "lso", "uso"
            )):
                if "offloads" not in iface:
                    iface["offloads"] = {}
                iface["offloads"][prop_name] = prop_val

    # ------------------------------------------------------------------
    # IP configuration (Get-NetIPConfiguration)
    # ------------------------------------------------------------------

    def _parse_ip_config(self):
        """Extract IP addresses from Get-NetIPConfiguration output."""
        iface_map = {iface["name"].lower(): iface
                     for iface in self.interfaces}

        # Get-NetIPConfiguration Format-List blocks
        blocks = re.split(r"(?=^InterfaceAlias\s*:)", self.raw,
                          flags=re.MULTILINE)
        for block in blocks:
            alias_m = re.search(r"InterfaceAlias\s*:\s*(.+)", block)
            if not alias_m:
                continue
            alias = alias_m.group(1).strip().lower()
            iface = iface_map.get(alias)
            if not iface:
                continue

            ip_m = re.search(r"IPv4Address\s*:\s*(\S+)", block)
            if ip_m:
                iface["ip_address"] = ip_m.group(1).strip()

            gw_m = re.search(r"IPv4DefaultGateway\s*:\s*(\S+)", block)
            if gw_m:
                iface["gateway"] = gw_m.group(1).strip()

    # ------------------------------------------------------------------
    # TCP settings (Get-NetTCPSetting + netsh interface tcp show global)
    # ------------------------------------------------------------------

    def _parse_tcp_settings(self):
        """Parse TCP tuning parameters."""
        tcp = {}

        # netsh interface tcp show global
        for m in re.finditer(
            r"^\s*(.+?)\s*:\s*(.+)$", self.raw, re.MULTILINE
        ):
            key = m.group(1).strip().lower()
            val = m.group(2).strip()

            if "receive window" in key or "autotuning" in key:
                tcp["auto_tuning"] = val
                if "disabled" in val.lower():
                    self.warnings.append(
                        "CRITICAL: TCP Receive Window Auto-Tuning is "
                        "disabled — will limit throughput on high-latency "
                        "links"
                    )

            elif "scaling heuristics" in key:
                tcp["scaling_heuristics"] = val
                if "enabled" in val.lower():
                    self.warnings.append(
                        "WARNING: TCP Scaling Heuristics enabled — Windows "
                        "may reduce window size automatically"
                    )

            elif "chimney offload" in key:
                tcp["chimney_offload"] = val

            elif "direct cache access" in key or "dca" in key:
                tcp["dca"] = val

            elif "ecn capability" in key:
                tcp["ecn"] = val

            elif "timestamps" in key:
                tcp["timestamps"] = val

            elif "congestion" in key and "provider" in key:
                tcp["congestion_provider"] = val

            elif "initial rto" in key:
                tcp["initial_rto"] = val

        # Get-NetTCPSetting Format-List
        auto_m = re.search(
            r"AutoTuningLevelLocal\s*:\s*(\S+)", self.raw, re.IGNORECASE
        )
        if auto_m:
            level = auto_m.group(1).strip()
            tcp["auto_tuning_level"] = level
            if level.lower() == "disabled":
                self.warnings.append(
                    "CRITICAL: AutoTuningLevelLocal is Disabled — "
                    "TCP window won't scale for high-bandwidth links"
                )
            elif level.lower() == "highlylimited":
                self.warnings.append(
                    "WARNING: AutoTuningLevelLocal is HighlyLimited — "
                    "TCP window scaling is restricted"
                )

        cong_m = re.search(
            r"CongestionProvider\s*:\s*(\S+)", self.raw, re.IGNORECASE
        )
        if cong_m:
            tcp["congestion_provider"] = cong_m.group(1).strip()

        icw_m = re.search(
            r"InitialCongestionWindow\s*:\s*(\d+)", self.raw, re.IGNORECASE
        )
        if icw_m:
            tcp["initial_congestion_window"] = int(icw_m.group(1))

        if tcp:
            self.global_settings["tcp"] = tcp

    # ------------------------------------------------------------------
    # Route table
    # ------------------------------------------------------------------

    def _parse_routes(self):
        """Extract default route info."""
        default_m = re.search(
            r"0\.0\.0\.0/0\s+(\S+)\s+(\S+)", self.raw
        )
        if default_m:
            self.global_settings["default_gateway"] = default_m.group(1)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _new_iface(name):
        return {
            "name": name,
            "description": None,
            "speed": None,
            "duplex": None,
            "mtu": None,
            "ip_mtu": None,
            "tcp_mss": None,
            "shutdown": False,
            "negotiation": "auto",
            "ip_address": None,
            "errors": [],
        }

    @staticmethod
    def _parse_link_speed(text):
        """Convert Windows speed strings like '10 Gbps' to Mbps string."""
        m = re.search(r"([\d.]+)\s*(Gbps|Mbps|Kbps)", text, re.IGNORECASE)
        if not m:
            return None
        val = float(m.group(1))
        unit = m.group(2).lower()
        if unit == "gbps":
            return str(int(val * 1000))
        elif unit == "kbps":
            return str(int(val / 1000))
        return str(int(val))

    def to_dict(self):
        return {
            "vendor": self.VENDOR,
            "device_name": self.device_name,
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "global_settings": self.global_settings,
            "warnings": self.warnings,
            "raw_preview": self.raw[:2000],
        }
