"""
Parser for Linux server network configuration (Proxmox, Ubuntu, RHEL, etc.).

Extracts throughput-relevant settings from common Linux commands:
- ip link show / ip addr show
- ip route show / ip route get
- ethtool <interface>
- cat /proc/net/bonding/<bond>
- sysctl net.ipv4.tcp_* / net.core.*
"""

import re


class LinuxConfigParser:
    VENDOR = "linux"

    def __init__(self, config_text, device_name="unknown"):
        self.raw = config_text
        self.device_name = device_name
        self.hostname = None
        self.interfaces = []
        self.bonds = []
        self.bridges = []
        self.routes = []
        self.route_lookups = []
        self.global_settings = {}
        self.warnings = []
        self._parse()

    def _parse(self):
        self._parse_hostname()
        self._parse_ip_link()
        self._parse_ethtool()
        self._parse_ip_addr()
        self._parse_bond_status()
        self._parse_routes()
        self._parse_route_lookups()
        self._parse_sysctl_tcp()
        self._detect_routing_bottlenecks()

    # ------------------------------------------------------------------
    # Hostname
    # ------------------------------------------------------------------

    def _parse_hostname(self):
        m = re.search(r"=+\s*HOSTNAME\s*=+\s*\n(\S+)", self.raw, re.IGNORECASE)
        if m:
            self.hostname = m.group(1).strip()
            self.device_name = self.hostname
            return

        m = re.search(r"hostname\s*:\s*(\S+)", self.raw, re.IGNORECASE)
        if m:
            self.hostname = m.group(1).strip()
            self.device_name = self.hostname

    # ------------------------------------------------------------------
    # ip link show
    # ------------------------------------------------------------------

    def _parse_ip_link(self):
        """Parse 'ip link show' output into interface dicts."""
        pattern = re.compile(
            r"^\d+:\s+(\S+?):\s+<([^>]*)>\s+mtu\s+(\d+)\s+.*?"
            r"state\s+(\S+)",
            re.MULTILINE,
        )
        for m in pattern.finditer(self.raw):
            name = m.group(1)
            flags = m.group(2)
            mtu = int(m.group(3))
            state = m.group(4)

            iface = self._new_iface(name)
            iface["mtu"] = mtu
            iface["state"] = state.lower()
            iface["shutdown"] = state.upper() not in ("UP", "UNKNOWN")

            # Detect interface roles from flags
            flag_list = [f.strip() for f in flags.split(",")]
            if "SLAVE" in flag_list:
                iface["bond_slave"] = True
                # Extract master from the raw text
                master_m = re.search(
                    rf"^\d+:\s+{re.escape(name)}:.*?master\s+(\S+)",
                    self.raw,
                    re.MULTILINE,
                )
                if master_m:
                    iface["bond_master"] = master_m.group(1)

            if "MASTER" in flag_list:
                iface["is_bond"] = True

            self.interfaces.append(iface)

    # ------------------------------------------------------------------
    # ethtool output
    # ------------------------------------------------------------------

    def _parse_ethtool(self):
        """Parse ethtool output blocks for speed, duplex, auto-negotiation."""
        blocks = re.split(r"#\s*ethtool\s+", self.raw)

        for block in blocks:
            name_m = re.match(r"(\S+)", block)
            if not name_m:
                continue

            name = name_m.group(1)
            iface = self._find_or_create_iface(name)

            speed_m = re.search(r"Speed:\s*(\d+)Mb/s", block)
            if speed_m:
                iface["speed"] = speed_m.group(1)
                iface["speed_mbps"] = int(speed_m.group(1))

            duplex_m = re.search(r"Duplex:\s*(\S+)", block)
            if duplex_m:
                iface["duplex"] = duplex_m.group(1).lower()
                if "half" in iface["duplex"]:
                    iface["errors"].append(
                        "CRITICAL: Half-duplex — will severely limit throughput"
                    )

            autoneg_m = re.search(r"Auto-negotiation:\s*(\S+)", block)
            if autoneg_m:
                iface["negotiation"] = (
                    "auto" if autoneg_m.group(1).lower() == "on" else "off"
                )

            link_m = re.search(r"Link detected:\s*(\S+)", block)
            if link_m:
                iface["link_detected"] = link_m.group(1).lower() == "yes"

    # ------------------------------------------------------------------
    # ip addr show
    # ------------------------------------------------------------------

    def _parse_ip_addr(self):
        """Parse IP address assignments from ip addr output."""
        for m in re.finditer(
            r"(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+.*?(\S+)\s*$",
            self.raw,
            re.MULTILINE,
        ):
            iface_name = m.group(4) if m.group(4) != "scope" else m.group(1)
            ip_addr = m.group(2)
            prefix = m.group(3)

            # Try to match to an existing interface
            # Handle the format: "7: vmbr0 inet 10.2.25.92/24 scope global vmbr0"
            for token in [m.group(4), m.group(1)]:
                token_clean = token.rstrip(":")
                iface = self._find_iface(token_clean)
                if iface:
                    iface["ip_address"] = ip_addr
                    iface["prefix_length"] = int(prefix)
                    break

    # ------------------------------------------------------------------
    # Bond status (/proc/net/bonding/*)
    # ------------------------------------------------------------------

    def _parse_bond_status(self):
        """Parse Linux bonding driver status."""
        # Look for bond mode
        mode_m = re.search(
            r"Bonding Mode:\s*(.+)", self.raw, re.IGNORECASE
        )
        bond_mode = mode_m.group(1).strip() if mode_m else None

        # Active aggregator
        active_m = re.search(
            r"Active Aggregator:\s*(\S+)", self.raw, re.IGNORECASE
        )

        # Parse slave interfaces
        slave_blocks = re.split(
            r"(?=Slave Interface:)", self.raw, flags=re.IGNORECASE
        )
        slaves = []
        for block in slave_blocks:
            slave_m = re.search(r"Slave Interface:\s*(\S+)", block, re.IGNORECASE)
            if not slave_m:
                continue

            slave_name = slave_m.group(1)
            slave_speed_m = re.search(r"Speed:\s*(\d+)\s*Mbps", block)
            slave_duplex_m = re.search(r"Duplex:\s*(\S+)", block)

            slave_info = {
                "name": slave_name,
                "speed_mbps": int(slave_speed_m.group(1)) if slave_speed_m else None,
                "duplex": slave_duplex_m.group(1).lower() if slave_duplex_m else None,
            }
            slaves.append(slave_info)

            # Update the interface entry too
            iface = self._find_iface(slave_name)
            if iface and slave_speed_m:
                iface["speed"] = slave_speed_m.group(1)
                iface["speed_mbps"] = int(slave_speed_m.group(1))

        if bond_mode or slaves:
            bond_info = {
                "mode": bond_mode,
                "active_aggregator": (
                    active_m.group(1) if active_m else None
                ),
                "slaves": slaves,
            }
            self.bonds.append(bond_info)
            self.global_settings["bond"] = bond_info

            # Check for bond speed limitations
            if slaves:
                max_slave_speed = max(
                    s["speed_mbps"] for s in slaves if s["speed_mbps"]
                )
                if max_slave_speed <= 1000 and bond_mode and "802.3ad" in bond_mode:
                    total_bond_bw = sum(
                        s["speed_mbps"] for s in slaves if s["speed_mbps"]
                    )
                    self.warnings.append(
                        f"WARNING: bond0 is LACP ({bond_mode}) with "
                        f"{len(slaves)}x {max_slave_speed} Mbps slaves = "
                        f"{total_bond_bw} Mbps aggregate, but single-flow "
                        f"throughput is limited to {max_slave_speed} Mbps "
                        f"(LACP hashes per-flow, not per-packet)"
                    )

    # ------------------------------------------------------------------
    # Routes (ip route show)
    # ------------------------------------------------------------------

    def _parse_routes(self):
        """Parse ip route table."""
        for m in re.finditer(
            r"^(default|[\d./]+)\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)",
            self.raw,
            re.MULTILINE,
        ):
            route = {
                "destination": m.group(1),
                "gateway": m.group(2),
                "interface": m.group(3),
            }
            self.routes.append(route)

    def _parse_route_lookups(self):
        """Parse 'ip route get' output for specific destination lookups."""
        for m in re.finditer(
            r"^(\d+\.\d+\.\d+\.\d+)\s+via\s+(\S+)\s+dev\s+(\S+)\s+src\s+(\S+)",
            self.raw,
            re.MULTILINE,
        ):
            lookup = {
                "destination": m.group(1),
                "gateway": m.group(2),
                "interface": m.group(3),
                "source": m.group(4),
            }
            self.route_lookups.append(lookup)

        # Also capture local routes
        for m in re.finditer(
            r"^local\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+src\s+(\S+)",
            self.raw,
            re.MULTILINE,
        ):
            lookup = {
                "destination": m.group(1),
                "gateway": None,
                "interface": m.group(2),
                "source": m.group(3),
                "local": True,
            }
            self.route_lookups.append(lookup)

    # ------------------------------------------------------------------
    # sysctl TCP settings
    # ------------------------------------------------------------------

    def _parse_sysctl_tcp(self):
        """Parse sysctl values for TCP and network buffer tuning."""
        tcp = {}

        sysctl_patterns = {
            "tcp_window_scaling": r"net\.ipv4\.tcp_window_scaling\s*=\s*(\S+)",
            "rmem_max": r"net\.core\.rmem_max\s*=\s*(\d+)",
            "wmem_max": r"net\.core\.wmem_max\s*=\s*(\d+)",
            "rmem_default": r"net\.core\.rmem_default\s*=\s*(\d+)",
            "wmem_default": r"net\.core\.wmem_default\s*=\s*(\d+)",
            "tcp_rmem": r"net\.ipv4\.tcp_rmem\s*=\s*(.+)",
            "tcp_wmem": r"net\.ipv4\.tcp_wmem\s*=\s*(.+)",
            "tcp_mtu_probing": r"net\.ipv4\.tcp_mtu_probing\s*=\s*(\S+)",
            "tcp_congestion_control": r"net\.ipv4\.tcp_congestion_control\s*=\s*(\S+)",
        }

        for key, pattern in sysctl_patterns.items():
            m = re.search(pattern, self.raw)
            if m:
                tcp[key] = m.group(1).strip()

        if tcp:
            self.global_settings["tcp"] = tcp

            # Check for suboptimal TCP buffer sizes
            rmem_max = int(tcp.get("rmem_max", 0))
            wmem_max = int(tcp.get("wmem_max", 0))

            if rmem_max and rmem_max < 4194304:
                self.warnings.append(
                    f"WARNING: net.core.rmem_max = {rmem_max} "
                    f"({rmem_max // 1024} KB) — too small for high-throughput "
                    f"transfers. Recommended: 67108864 (64 MB) for 10G+ links"
                )

            if wmem_max and wmem_max < 4194304:
                self.warnings.append(
                    f"WARNING: net.core.wmem_max = {wmem_max} "
                    f"({wmem_max // 1024} KB) — too small for high-throughput "
                    f"transfers. Recommended: 67108864 (64 MB) for 10G+ links"
                )

            # Check tcp_rmem max value
            tcp_rmem = tcp.get("tcp_rmem", "")
            if tcp_rmem:
                parts = tcp_rmem.split()
                if len(parts) == 3:
                    tcp_rmem_max = int(parts[2])
                    if tcp_rmem_max < 16777216:
                        self.warnings.append(
                            f"WARNING: net.ipv4.tcp_rmem max = {tcp_rmem_max} "
                            f"({tcp_rmem_max // 1024} KB) — limits TCP receive "
                            f"window. Recommended: 67108864 for 10G+ links"
                        )

            # Check MTU probing
            mtu_probing = tcp.get("tcp_mtu_probing", "0")
            if mtu_probing == "0":
                self.warnings.append(
                    "INFO: TCP MTU probing is disabled "
                    "(net.ipv4.tcp_mtu_probing=0). Enable it (set to 1) if "
                    "jumbo frames are used on any segment to avoid black-hole "
                    "PMTUD issues"
                )

    # ------------------------------------------------------------------
    # Routing bottleneck detection
    # ------------------------------------------------------------------

    def _detect_routing_bottlenecks(self):
        """
        Cross-reference routes with interface speeds to detect cases where
        traffic is routed through a slow interface when faster ones exist.
        """
        # Build speed map for all interfaces
        speed_map = {}
        mtu_map = {}
        for iface in self.interfaces:
            if iface.get("speed_mbps") and not iface.get("shutdown"):
                speed_map[iface["name"]] = iface["speed_mbps"]
            if iface.get("mtu"):
                mtu_map[iface["name"]] = iface["mtu"]

        if not speed_map:
            return

        max_speed = max(speed_map.values())
        fastest_ifaces = [
            name for name, spd in speed_map.items() if spd == max_speed
        ]

        # Check each route lookup
        for lookup in self.route_lookups:
            if lookup.get("local"):
                continue

            dest = lookup["destination"]
            route_iface = lookup["interface"]
            route_speed = speed_map.get(route_iface)

            if route_speed is None:
                # Might be a bridge — check if it's backed by a bond
                for iface in self.interfaces:
                    if iface.get("name") == route_iface:
                        # For bridges/bonds, check the underlying slave speed
                        for slave_iface in self.interfaces:
                            if slave_iface.get("bond_master") == "bond0":
                                slave_speed = slave_iface.get("speed_mbps")
                                if slave_speed:
                                    route_speed = slave_speed
                                    break
                        # Also check if bond0 is slave to this bridge
                        for b_iface in self.interfaces:
                            if (
                                b_iface.get("is_bond")
                                and b_iface.get("name") == "bond0"
                            ):
                                for s_iface in self.interfaces:
                                    if s_iface.get("bond_master") == "bond0":
                                        route_speed = s_iface.get("speed_mbps")
                                        break
                                break
                        break

            if route_speed and route_speed < max_speed:
                # Find which faster interface could potentially carry this
                faster_with_jumbo = [
                    f"{name} ({speed_map[name] / 1000:.0f}G, MTU {mtu_map.get(name, '?')})"
                    for name in fastest_ifaces
                    if mtu_map.get(name, 1500) >= 9000
                ]
                faster_list = ", ".join(faster_with_jumbo) if faster_with_jumbo else ", ".join(fastest_ifaces)

                self.warnings.append(
                    f"CRITICAL: Traffic to {dest} routes via {route_iface} "
                    f"at {route_speed} Mbps — but this host has "
                    f"{max_speed / 1000:.0f}G NIC(s) available: {faster_list}. "
                    f"Throughput is hard-capped at "
                    f"~{route_speed * 0.95 / 8:.0f} MB/s"
                )

        # Check for MTU mismatch between bridge and fast NICs
        bridge_mtu = mtu_map.get("vmbr0")
        if bridge_mtu:
            for iface in self.interfaces:
                if (
                    iface.get("mtu")
                    and iface["mtu"] >= 9000
                    and bridge_mtu < 9000
                    and not iface.get("bond_slave")
                ):
                    self.warnings.append(
                        f"INFO: {iface['name']} has jumbo MTU "
                        f"({iface['mtu']}) but vmbr0 bridge is at "
                        f"standard MTU ({bridge_mtu}) — traffic routed "
                        f"through vmbr0 cannot use jumbo frames"
                    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _new_iface(name):
        return {
            "name": name,
            "description": None,
            "speed": None,
            "speed_mbps": None,
            "duplex": None,
            "mtu": None,
            "ip_mtu": None,
            "tcp_mss": None,
            "shutdown": False,
            "negotiation": "auto",
            "ip_address": None,
            "prefix_length": None,
            "state": None,
            "bond_slave": False,
            "bond_master": None,
            "is_bond": False,
            "link_detected": None,
            "errors": [],
        }

    def _find_iface(self, name):
        """Find an existing interface by name."""
        for iface in self.interfaces:
            if iface["name"] == name:
                return iface
        return None

    def _find_or_create_iface(self, name):
        """Find an interface or create a new one."""
        iface = self._find_iface(name)
        if not iface:
            iface = self._new_iface(name)
            self.interfaces.append(iface)
        return iface

    def to_dict(self):
        return {
            "vendor": self.VENDOR,
            "device_name": self.device_name,
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "bonds": self.bonds,
            "routes": self.routes,
            "route_lookups": self.route_lookups,
            "global_settings": self.global_settings,
            "warnings": self.warnings,
            "raw_preview": self.raw[:2000],
        }
