"""
SSH connector for fetching device configurations from network equipment.

Supports:
  - Cisco IOS / IOS-XE / NX-OS
  - Palo Alto PAN-OS
  - Juniper JunOS
"""

import logging
import time
import re
import socket

try:
    import paramiko
except ImportError:
    paramiko = None

logger = logging.getLogger(__name__)


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
        if paramiko is None:
            return {
                "status": "error",
                "message": "paramiko is not installed. Run: pip install paramiko",
            }

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

        except paramiko.AuthenticationException as e:
            return {
                "status": "error",
                "message": f"Authentication failed: {str(e)}",
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
        """Establish SSH connection.

        Tries multiple authentication strategies to handle the wide variety
        of SSH implementations found on network devices:
          1. Standard password auth (with legacy algorithm support)
          2. Keyboard-interactive auth via Transport (for switches that
             reject normal password auth, e.g. many Cisco devices)
          3. Direct password auth via Transport
        """
        # Disable rsa-sha2 variants that many older switches don't support,
        # forcing paramiko to fall back to ssh-rsa.
        disabled_algorithms = {
            "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
        }

        errors = []

        # --- Strategy 1: Standard SSHClient.connect() ---
        try:
            logger.info("SSH to %s:%s – trying standard password auth",
                        self.host, self.port)
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=SSH_CONNECT_TIMEOUT,
                banner_timeout=SSH_CONNECT_TIMEOUT,
                auth_timeout=SSH_CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
                disabled_algorithms=disabled_algorithms,
            )
            logger.info("SSH to %s – standard password auth succeeded",
                        self.host)
            return  # success
        except paramiko.AuthenticationException as e:
            errors.append(f"password auth: {e}")
            logger.info("SSH to %s – standard password auth failed: %s",
                        self.host, e)
        except Exception as e:
            errors.append(f"password auth connect: {e}")
            logger.info("SSH to %s – standard connect failed: %s",
                        self.host, e)

        # --- Strategy 2: Keyboard-interactive via Transport ---
        try:
            logger.info("SSH to %s – trying keyboard-interactive auth",
                        self.host)
            sock = socket.create_connection(
                (self.host, self.port), timeout=SSH_CONNECT_TIMEOUT
            )
            transport = paramiko.Transport(sock)
            transport.set_log_channel(__name__)
            transport.start_client(timeout=SSH_CONNECT_TIMEOUT)

            def _kbd_interactive_handler(title, instructions, prompt_list):
                return [self.password for _ in prompt_list]

            transport.auth_interactive(self.username, _kbd_interactive_handler)

            if not transport.is_authenticated():
                transport.close()
                raise paramiko.AuthenticationException(
                    "keyboard-interactive auth completed but not authenticated"
                )

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client._transport = transport
            logger.info("SSH to %s – keyboard-interactive auth succeeded",
                        self.host)
            return  # success
        except paramiko.AuthenticationException as e:
            errors.append(f"keyboard-interactive: {e}")
            logger.info("SSH to %s – keyboard-interactive failed: %s",
                        self.host, e)
        except Exception as e:
            errors.append(f"keyboard-interactive connect: {e}")
            logger.info("SSH to %s – keyboard-interactive connect failed: %s",
                        self.host, e)

        # --- Strategy 3: Password auth via Transport ---
        try:
            logger.info("SSH to %s – trying transport password auth",
                        self.host)
            sock = socket.create_connection(
                (self.host, self.port), timeout=SSH_CONNECT_TIMEOUT
            )
            transport = paramiko.Transport(sock)
            transport.set_log_channel(__name__)
            transport.start_client(timeout=SSH_CONNECT_TIMEOUT)
            transport.auth_password(self.username, self.password)

            if not transport.is_authenticated():
                transport.close()
                raise paramiko.AuthenticationException(
                    "transport password auth completed but not authenticated"
                )

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client._transport = transport
            logger.info("SSH to %s – transport password auth succeeded",
                        self.host)
            return  # success
        except paramiko.AuthenticationException as e:
            errors.append(f"transport password: {e}")
            logger.info("SSH to %s – transport password failed: %s",
                        self.host, e)
        except Exception as e:
            errors.append(f"transport password connect: {e}")
            logger.info("SSH to %s – transport password connect failed: %s",
                        self.host, e)

        # All strategies failed
        detail = "; ".join(errors)
        raise paramiko.AuthenticationException(
            f"All auth methods failed for {self.host}: {detail}"
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
