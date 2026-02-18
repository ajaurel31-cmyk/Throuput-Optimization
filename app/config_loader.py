"""
Auto-loader for device configs from the configs/ directory.

On app startup, reads configs/manifest.json to find config files and their
device name/role mappings, parses them, and stores them so every new session
gets the configs pre-loaded without manual re-upload.
"""

import json
import os
import logging

from app.parsers import GenericConfigParser

logger = logging.getLogger(__name__)

# Module-level cache of pre-loaded devices
_preloaded_devices = []


def load_configs(configs_dir=None):
    """
    Read manifest.json from configs_dir, parse each referenced config file,
    and cache the results. Returns the list of parsed device dicts.
    """
    global _preloaded_devices

    if configs_dir is None:
        configs_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "configs"
        )

    manifest_path = os.path.join(configs_dir, "manifest.json")

    if not os.path.isfile(manifest_path):
        logger.info("No configs/manifest.json found — skipping auto-load.")
        _preloaded_devices = []
        return _preloaded_devices

    try:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read manifest.json: %s", e)
        _preloaded_devices = []
        return _preloaded_devices

    devices = []
    for entry in manifest.get("devices", []):
        filename = entry.get("filename")
        device_name = entry.get("device_name", "unknown")
        device_role = entry.get("device_role", "unknown")

        if not filename:
            logger.warning("Skipping manifest entry with no filename.")
            continue

        filepath = os.path.join(configs_dir, filename)
        if not os.path.isfile(filepath):
            logger.warning(
                "Config file '%s' listed in manifest but not found — skipping.",
                filename,
            )
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                config_text = f.read()
        except OSError as e:
            logger.warning("Failed to read '%s': %s", filename, e)
            continue

        if not config_text.strip():
            logger.warning("Config file '%s' is empty — skipping.", filename)
            continue

        parsed = GenericConfigParser.parse(config_text, device_name, device_role)
        parsed["file_id"] = f"auto_{filename.replace('.', '_')}"
        parsed["filename"] = filename
        parsed["source"] = "auto-loaded"
        devices.append(parsed)
        logger.info(
            "Auto-loaded: %s (%s) as %s [%s]",
            device_name,
            filename,
            device_role,
            parsed.get("vendor", "unknown"),
        )

    _preloaded_devices = devices
    logger.info("Auto-loaded %d device config(s) from configs/", len(devices))
    return _preloaded_devices


def get_preloaded_devices():
    """Return a deep copy of the pre-loaded devices list."""
    import copy
    return copy.deepcopy(_preloaded_devices)
