"""
SSH connector for fetching device configurations from network equipment.

Supports:
  - Cisco IOS / IOS-XE / NX-OS
  - Palo Alto PAN-OS
  - Juniper JunOS
"""

import time
import re
import socket

import paramiko


# Commands to run per device type.  Each entry is a list of (setup, config)
# commands.  Setup commands disable paging; config commands fetch the config.
DEVICE_COMMANDS = {
    "cisco": {
        "setup": ["terminal length 0"],
        "config": ["show running-config"],
    },
    "paloalto": {
        "setup": ["set cli pager off"],
        "config": ["show config running"],
    },
    "juniper": {
        "setup": [],
        "config": ["show configuration | display set | no-more"],
    },
}

# Timeout constants (seconds)
SSH_CONNECT_TIMEOUT = 15
SSH_COMMAND_TIMEOUT = 60
SSH_READ_TIMEOUT = 90


class SSHConfigFetcher:
    """Fetch running config from a network device over SSH."""

    def __init__(self, host, username, password, device_type="auto", port=22):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.device_type = device_type.lower()
        self.client = None

    def fetch(self):
        """
        Connect via SSH, detect device type if needed, fetch config.

        Returns dict with:
          - status: "success" | "error"
          - config_text: the raw config output
          - device_type: detected or specified device type
          - hostname: device hostname if detected
          - message: error message if status == "error"
        """
        try:
            self._connect()

            # Auto-detect device type from SSH banner / initial prompt
            if self.device_type == "auto":
                self.device_type = self._detect_device_type()

            if self.device_type not in DEVICE_COMMANDS:
                return {
                    "status": "error",
                    "message": (
                        f"Unsupported device type: {self.device_type}. "
                        "Supported: cisco, paloalto, juniper"
                    ),
                }

            commands = DEVICE_COMMANDS[self.device_type]
            config_text = self._run_commands(commands)
            hostname = self._extract_hostname(config_text)

            return {
                "status": "success",
                "config_text": config_text,
                "device_type": self.device_type,
                "hostname": hostname,
            }

        except paramiko.AuthenticationException:
            return {
                "status": "error",
                "message": "Authentication failed. Check username and password.",
            }
        except paramiko.SSHException as e:
            return {
                "status": "error",
                "message": f"SSH error: {str(e)}",
            }
        except socket.timeout:
            return {
                "status": "error",
                "message": (
                    f"Connection timed out. Verify {self.host}:{self.port} "
                    "is reachable and SSH is enabled."
                ),
            }
        except socket.gaierror:
            return {
                "status": "error",
                "message": f"Could not resolve hostname: {self.host}",
            }
        except ConnectionRefusedError:
            return {
                "status": "error",
                "message": (
                    f"Connection refused by {self.host}:{self.port}. "
                    "Verify SSH is enabled on the device."
                ),
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
            }
        finally:
            self._disconnect()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self):
        """Establish SSH connection."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

    def _disconnect(self):
        """Close SSH connection."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

    def _detect_device_type(self):
        """Detect device type from the SSH banner and initial output."""
        shell = self.client.invoke_shell()
        time.sleep(2)  # let the prompt settle
        output = ""
        if shell.recv_ready():
            output = shell.recv(65535).decode("utf-8", errors="replace")
        shell.close()

        output_lower = output.lower()

        # Palo Alto prompts look like: "admin@PA-5260>"
        if "pa-" in output_lower or "panorama" in output_lower:
            return "paloalto"

        # Juniper prompts look like: "user@router>"
        if "junos" in output_lower or "{master:" in output_lower:
            return "juniper"

        # Cisco is the most common default — IOS prompt: "Router#" or "Switch>"
        return "cisco"

    def _run_commands(self, commands):
        """Execute setup + config commands and return combined output."""
        shell = self.client.invoke_shell(width=512)
        time.sleep(1)
        # Drain initial prompt
        if shell.recv_ready():
            shell.recv(65535)

        # Run setup commands (disable paging, etc.)
        for cmd in commands.get("setup", []):
            shell.send(cmd + "\n")
            time.sleep(1)
            if shell.recv_ready():
                shell.recv(65535)  # discard setup output

        # Run config commands and collect output
        config_output = ""
        for cmd in commands.get("config", []):
            shell.send(cmd + "\n")

            # Read output until we see the prompt return or timeout
            config_output += self._read_until_prompt(shell)

        shell.close()

        # Clean up the output
        config_output = self._clean_output(config_output, commands)
        return config_output

    def _read_until_prompt(self, shell):
        """Read shell output until prompt returns or timeout."""
        output = ""
        start = time.time()
        idle_count = 0

        while time.time() - start < SSH_READ_TIMEOUT:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", errors="replace")
                output += chunk
                idle_count = 0
            else:
                time.sleep(0.5)
                idle_count += 1
                # If idle for 5 seconds after receiving some data, assume done
                if idle_count >= 10 and len(output) > 100:
                    break

        return output

    def _clean_output(self, output, commands):
        """Remove command echoes, prompts, and ANSI escape sequences."""
        # Strip ANSI escape codes
        output = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", output)
        output = re.sub(r"\x1b\].*?\x07", "", output)
        # Strip carriage returns
        output = output.replace("\r", "")

        lines = output.split("\n")
        cleaned = []
        skip_commands = set()
        for cmd_list in commands.values():
            for cmd in cmd_list:
                skip_commands.add(cmd.strip().lower())

        for line in lines:
            stripped = line.strip().lower()
            # Skip lines that are just the command echo
            if stripped in skip_commands:
                continue
            # Skip prompt-only lines (e.g. "Router#", "admin@PA>")
            if re.match(r"^[\w\-@./:()]+[#>$]\s*$", stripped):
                continue
            cleaned.append(line)

        return "\n".join(cleaned).strip()

    def _extract_hostname(self, config_text):
        """Try to extract hostname from config text."""
        # Cisco: "hostname XXXXX"
        match = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
        if match:
            return match.group(1)

        # Palo Alto: "set deviceconfig system hostname XXXXX"
        match = re.search(
            r"set deviceconfig system hostname\s+(\S+)", config_text
        )
        if match:
            return match.group(1)

        # Juniper: "set system host-name XXXXX"
        match = re.search(r"set system host-name\s+(\S+)", config_text)
        if match:
            return match.group(1)

        return None
