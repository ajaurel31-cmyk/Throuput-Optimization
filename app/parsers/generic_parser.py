"""
Generic config parser — auto-detects vendor and delegates to the appropriate parser.
Also handles unknown/unsupported config formats by extracting common patterns.
"""

import re

from app.parsers.cisco_parser import CiscoConfigParser
from app.parsers.paloalto_parser import PaloAltoConfigParser
from app.parsers.juniper_parser import JuniperConfigParser
from app.parsers.windows_parser import WindowsConfigParser


class GenericConfigParser:

    @staticmethod
    def detect_vendor(config_text):
        """Detect the vendor based on config text patterns."""
        text_lower = config_text.lower()

        # Palo Alto detection
        if any(
            kw in text_lower
            for kw in [
                "set deviceconfig",
                "set rulebase security",
                "set network interface ethernet",
                "set network zone",
                "paloaltonetworks",
            ]
        ):
            return "paloalto"

        # Juniper detection
        if any(
            kw in text_lower
            for kw in [
                "set system host-name",
                "set interfaces",
                "set firewall filter",
                "set routing-options",
                "juniper",
                "junos",
            ]
        ):
            return "juniper"

        # Windows Server detection (PowerShell / netsh output)
        if any(
            kw in text_lower
            for kw in [
                "get-netadapter",
                "get-nettcpsetting",
                "get-netipconfig",
                "netsh interface tcp",
                "autotuninglevellolocal",
                "receive window auto-tuning level",
                "linkspeed",
                "interfacedescription",
                "mtusize",
            ]
        ):
            return "windows"

        # Cisco detection (broadest — check last)
        if any(
            kw in text_lower
            for kw in [
                "hostname ",
                "interface gigabitethernet",
                "interface tengigabitethernet",
                "interface fastethernet",
                "switchport mode",
                "spanning-tree",
                "router ospf",
                "router bgp",
                "cisco",
                "ios",
                "nx-os",
            ]
        ):
            return "cisco"

        return "unknown"

    @staticmethod
    def parse(config_text, device_name="unknown", device_role="unknown"):
        """Auto-detect vendor and parse config. Returns parsed dict."""
        vendor = GenericConfigParser.detect_vendor(config_text)

        if vendor == "cisco":
            parser = CiscoConfigParser(config_text, device_name)
        elif vendor == "windows":
            parser = WindowsConfigParser(config_text, device_name)
        elif vendor == "paloalto":
            parser = PaloAltoConfigParser(config_text, device_name)
        elif vendor == "juniper":
            parser = JuniperConfigParser(config_text, device_name)
        else:
            # Fallback: extract basic info
            return GenericConfigParser._fallback_parse(
                config_text, device_name, device_role
            )

        result = parser.to_dict()
        result["device_role"] = device_role
        return result

    @staticmethod
    def _fallback_parse(config_text, device_name, device_role):
        """Extract basic throughput-relevant info from unknown config format."""
        result = {
            "vendor": "unknown",
            "device_name": device_name,
            "device_role": device_role,
            "interfaces": [],
            "warnings": [
                "Config vendor not auto-detected — using generic parser. "
                "Claude analysis will provide deeper inspection."
            ],
            "raw_preview": config_text[:2000],
        }

        # Try to find MTU values
        mtu_matches = re.findall(r"mtu\s+(\d+)", config_text, re.IGNORECASE)
        if mtu_matches:
            mtus = [int(m) for m in mtu_matches]
            result["detected_mtus"] = list(set(mtus))
            for mtu in set(mtus):
                if mtu < 1500:
                    result["warnings"].append(
                        f"MTU value {mtu} found — below standard 1500"
                    )

        # Try to find speed settings
        speed_matches = re.findall(
            r"speed\s+(auto|10|100|1000|10000|25000|40000|100000)",
            config_text,
            re.IGNORECASE,
        )
        if speed_matches:
            result["detected_speeds"] = list(set(speed_matches))

        # Try to find duplex settings
        duplex_matches = re.findall(
            r"duplex\s+(full|half|auto)", config_text, re.IGNORECASE
        )
        if duplex_matches:
            result["detected_duplex"] = list(set(duplex_matches))
            if "half" in [d.lower() for d in duplex_matches]:
                result["warnings"].append(
                    "CRITICAL: Half-duplex detected — will severely limit throughput"
                )

        return result
