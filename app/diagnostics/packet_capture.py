"""
Packet Capture Engine

Cross-platform packet capture supporting Windows Server and Linux.

Windows capture tools (in order of preference):
  1. dumpcap (from Wireshark) — outputs pcap directly
  2. tshark (from Wireshark) — outputs pcap directly
  3. pktmon (built-in Windows Server 2019+) — captures to ETL, converts to pcapng

Linux capture tools:
  1. tcpdump

Supports:
  - Start/stop live captures with BPF filters
  - Upload pre-captured pcap files
  - List and manage capture files
  - Interface discovery (platform-aware)
"""

import os
import platform
import re
import subprocess
import time
import threading
from dataclasses import dataclass, field


@dataclass
class CaptureInfo:
    """Metadata for a packet capture."""
    capture_id: str
    filename: str
    filepath: str
    status: str  # running, complete, error
    target_ip: str = ""
    source_ip: str = ""
    interface: str = ""
    duration: int = 0
    max_packets: int = 0
    file_size_bytes: int = 0
    packet_count: int = 0
    start_time: str = ""
    end_time: str = ""
    error: str = ""
    pid: int = 0
    capture_tool: str = ""

    def to_dict(self):
        return {
            "capture_id": self.capture_id,
            "filename": self.filename,
            "filepath": self.filepath,
            "status": self.status,
            "target_ip": self.target_ip,
            "source_ip": self.source_ip,
            "interface": self.interface,
            "duration": self.duration,
            "max_packets": self.max_packets,
            "file_size_bytes": self.file_size_bytes,
            "packet_count": self.packet_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "error": self.error,
            "capture_tool": self.capture_tool,
        }


class PacketCaptureEngine:
    """
    Manages packet captures across Windows and Linux.

    Windows: uses dumpcap/tshark from Wireshark, or pktmon (Server 2019+)
    Linux: uses tcpdump

    Usage:
        engine = PacketCaptureEngine(capture_dir='captures')
        info = engine.start_capture(target_ip='10.15.25.50', duration=30)
        # ... wait ...
        engine.stop_capture(info.capture_id)
    """

    # Common Wireshark install paths on Windows
    _WIRESHARK_PATHS = [
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
    ]

    def __init__(self, capture_dir="captures"):
        self.capture_dir = capture_dir
        os.makedirs(capture_dir, exist_ok=True)
        self._active_captures = {}  # capture_id -> (CaptureInfo, subprocess.Popen, extra_data)
        self._lock = threading.Lock()
        self._is_windows = platform.system() == "Windows"

        # Resolve tool paths once at init
        self._tool_paths = self._discover_tools()

    def _discover_tools(self):
        """Find available capture/analysis tool paths."""
        tools = {}

        if self._is_windows:
            # Check Wireshark tools on Windows
            for ws_dir in self._WIRESHARK_PATHS:
                if os.path.isdir(ws_dir):
                    for tool in ["dumpcap", "tshark", "capinfos"]:
                        exe = os.path.join(ws_dir, f"{tool}.exe")
                        if os.path.isfile(exe):
                            tools.setdefault(tool, exe)

            # Also check if they're on PATH
            for tool in ["dumpcap", "tshark", "capinfos"]:
                if tool not in tools and self._is_on_path(f"{tool}.exe"):
                    tools[tool] = f"{tool}.exe"

            # Check for pktmon (built-in Windows Server 2019+ / Win10 1809+)
            if self._is_on_path("pktmon.exe"):
                tools["pktmon"] = "pktmon.exe"
        else:
            # Linux tools
            for tool in ["tcpdump", "tshark", "dumpcap", "capinfos"]:
                if self._is_on_path(tool):
                    tools[tool] = tool

        return tools

    def _is_on_path(self, executable):
        """Check if an executable is on the system PATH."""
        try:
            # Use 'where' on Windows, 'which' on Linux
            which_cmd = "where" if self._is_windows else "which"
            result = subprocess.run(
                [which_cmd, executable],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def check_tools(self):
        """Check which capture/analysis tools are available."""
        available = {}
        if self._is_windows:
            for tool in ["dumpcap", "tshark", "capinfos", "pktmon"]:
                available[tool] = tool in self._tool_paths
        else:
            for tool in ["tcpdump", "tshark", "dumpcap", "capinfos"]:
                available[tool] = tool in self._tool_paths

        available["platform"] = "windows" if self._is_windows else "linux"

        # Determine the capture method that will be used
        if self._is_windows:
            if "dumpcap" in self._tool_paths:
                available["capture_method"] = "dumpcap (Wireshark)"
            elif "tshark" in self._tool_paths:
                available["capture_method"] = "tshark (Wireshark)"
            elif "pktmon" in self._tool_paths:
                available["capture_method"] = "pktmon (Windows built-in)"
            else:
                available["capture_method"] = "none"
        else:
            if "tcpdump" in self._tool_paths:
                available["capture_method"] = "tcpdump"
            elif "dumpcap" in self._tool_paths:
                available["capture_method"] = "dumpcap"
            else:
                available["capture_method"] = "none"

        return available

    def list_interfaces(self):
        """List available network interfaces for capture."""
        if self._is_windows:
            return self._list_interfaces_windows()
        else:
            return self._list_interfaces_linux()

    def _list_interfaces_windows(self):
        """List network interfaces on Windows."""
        interfaces = []

        # Method 1: Use tshark -D or dumpcap -D (most reliable for capture)
        for tool in ["dumpcap", "tshark"]:
            if tool not in self._tool_paths:
                continue
            try:
                result = subprocess.run(
                    [self._tool_paths[tool], "-D"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        # Format: "1. \Device\NPF_{GUID} (Description)"
                        # or: "1. \Device\NPF_{GUID} (Ethernet)"
                        match = re.match(
                            r"(\d+)\.\s+(.+?)(?:\s+\((.+?)\))?\s*$", line
                        )
                        if match:
                            iface_num = match.group(1)
                            iface_id = match.group(2).strip()
                            description = match.group(3) or iface_id
                            interfaces.append({
                                "name": iface_num,
                                "id": iface_id,
                                "ip": "",
                                "display": f"{iface_num}. {description}",
                            })
                    if interfaces:
                        return interfaces
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # Method 2: Use netsh to list interfaces
        try:
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[3:]:  # Skip header lines
                    parts = line.split()
                    if len(parts) >= 4:
                        idx = parts[0]
                        state = parts[2]
                        name = " ".join(parts[3:])
                        if state.lower() == "connected" and name.lower() != "loopback pseudo-interface 1":
                            # Get IP for this interface
                            ip_addr = self._get_windows_interface_ip(name)
                            interfaces.append({
                                "name": name,
                                "id": name,
                                "ip": ip_addr,
                                "display": f"{name} ({ip_addr})" if ip_addr else name,
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not interfaces:
            interfaces.append({
                "name": "0",
                "id": "default",
                "ip": "",
                "display": "Default interface",
            })

        return interfaces

    def _get_windows_interface_ip(self, iface_name):
        """Get IP address of a Windows interface."""
        try:
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "addresses", iface_name],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                match = re.search(r"IP Address:\s+([\d.]+)", result.stdout)
                if match:
                    return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    def _list_interfaces_linux(self):
        """List network interfaces on Linux."""
        interfaces = []
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    match = re.match(r"\d+:\s+(\S+?)(?:@\S+)?:", line)
                    if match:
                        iface = match.group(1)
                        if iface != "lo":
                            ip_result = subprocess.run(
                                ["ip", "-4", "addr", "show", iface],
                                capture_output=True, text=True, timeout=5,
                            )
                            ip_addr = ""
                            ip_match = re.search(
                                r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_result.stdout
                            )
                            if ip_match:
                                ip_addr = ip_match.group(1)

                            interfaces.append({
                                "name": iface,
                                "id": iface,
                                "ip": ip_addr,
                                "display": f"{iface} ({ip_addr})" if ip_addr else iface,
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Add "any" for Linux
        interfaces.insert(0, {
            "name": "any",
            "id": "any",
            "ip": "",
            "display": "any (all interfaces)",
        })

        return interfaces

    def start_capture(
        self,
        target_ip,
        source_ip="",
        interface="",
        duration=30,
        max_packets=100000,
        snap_len=0,
        port_filter="",
    ):
        """
        Start a packet capture using the best available tool.

        Args:
            target_ip: Remote IP to filter on (required)
            source_ip: Local IP to filter on (optional)
            interface: Network interface to capture on
            duration: Max capture duration in seconds (default 30)
            max_packets: Max packets to capture (default 100000)
            snap_len: Snap length in bytes (0 = full packet)
            port_filter: Optional port filter (e.g., "445" for SMB)

        Returns:
            CaptureInfo with capture details
        """
        # Validate target_ip
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
            return CaptureInfo(
                capture_id="", filename="", filepath="",
                status="error", error="Invalid target IP address",
            )

        # Validate source_ip if provided
        if source_ip and not re.match(
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", source_ip
        ):
            return CaptureInfo(
                capture_id="", filename="", filepath="",
                status="error", error="Invalid source IP address",
            )

        # Clamp duration and packet count
        duration = min(max(duration, 5), 120)
        max_packets = min(max(max_packets, 1000), 500000)

        # Generate capture ID and filename
        capture_id = f"cap_{int(time.time())}_{os.getpid()}"
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp_str}_{target_ip.replace('.', '_')}.pcapng"
        filepath = os.path.join(self.capture_dir, filename)

        # Build BPF filter
        bpf_filter = self._build_bpf_filter(target_ip, source_ip, port_filter)

        # Set default interface
        if not interface:
            interface = "any" if not self._is_windows else ""

        info = CaptureInfo(
            capture_id=capture_id,
            filename=filename,
            filepath=filepath,
            status="running",
            target_ip=target_ip,
            source_ip=source_ip,
            interface=interface,
            duration=duration,
            max_packets=max_packets,
            start_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )

        if self._is_windows:
            self._start_capture_windows(info, bpf_filter, snap_len)
        else:
            self._start_capture_linux(info, bpf_filter, snap_len)

        return info

    def _start_capture_windows(self, info, bpf_filter, snap_len):
        """Start capture on Windows using dumpcap, tshark, or pktmon."""
        if "dumpcap" in self._tool_paths:
            self._start_dumpcap(info, bpf_filter, snap_len)
        elif "tshark" in self._tool_paths:
            self._start_tshark_capture(info, bpf_filter, snap_len)
        elif "pktmon" in self._tool_paths:
            self._start_pktmon(info, bpf_filter)
        else:
            info.status = "error"
            info.error = (
                "No packet capture tool found on this Windows Server. "
                "Install Wireshark from https://www.wireshark.org/download.html "
                "(includes dumpcap and tshark for capture & analysis). "
                "Alternatively, Windows Server 2019+ includes pktmon — "
                "run 'pktmon start' from an admin PowerShell to verify availability."
            )

    def _start_dumpcap(self, info, bpf_filter, snap_len):
        """Start capture using dumpcap (Wireshark's capture engine)."""
        dumpcap = self._tool_paths["dumpcap"]

        cmd = [dumpcap]

        # Interface selection
        if info.interface and info.interface not in ("", "any", "0"):
            cmd.extend(["-i", info.interface])
        # If no interface specified, dumpcap uses the default

        cmd.extend([
            "-w", info.filepath,
            "-c", str(info.max_packets),
            "-a", f"duration:{info.duration}",
        ])

        if snap_len > 0:
            cmd.extend(["-s", str(snap_len)])

        if bpf_filter:
            cmd.extend(["-f", bpf_filter])

        info.capture_tool = "dumpcap"
        self._launch_capture_process(cmd, info)

    def _start_tshark_capture(self, info, bpf_filter, snap_len):
        """Start capture using tshark."""
        tshark = self._tool_paths["tshark"]

        cmd = [tshark]

        if info.interface and info.interface not in ("", "any", "0"):
            cmd.extend(["-i", info.interface])

        cmd.extend([
            "-w", info.filepath,
            "-c", str(info.max_packets),
            "-a", f"duration:{info.duration}",
            "-n",  # Don't resolve names
        ])

        if snap_len > 0:
            cmd.extend(["-s", str(snap_len)])

        if bpf_filter:
            cmd.extend(["-f", bpf_filter])

        info.capture_tool = "tshark"
        self._launch_capture_process(cmd, info)

    def _start_pktmon(self, info, bpf_filter):
        """
        Start capture using pktmon (Windows Server 2019+ built-in).

        pktmon captures to ETL format; we convert to pcapng when stopping.
        """
        pktmon = self._tool_paths["pktmon"]

        # pktmon uses ETL format natively — we'll convert when stopping
        etl_path = info.filepath.replace(".pcapng", ".etl")

        # Build pktmon command
        # pktmon filter add — add IP filter
        # pktmon start — start capture
        try:
            # Reset any existing pktmon state
            subprocess.run(
                [pktmon, "stop"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            subprocess.run(
                [pktmon, "filter", "remove"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Add filter for target IP
            filter_cmd = [pktmon, "filter", "add", "-i", info.target_ip]
            if info.source_ip:
                # pktmon doesn't support complex BPF — add source as second filter
                subprocess.run(
                    [pktmon, "filter", "add", "-i", info.source_ip],
                    capture_output=True, text=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )

            result = subprocess.run(
                filter_cmd,
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            if result.returncode != 0:
                info.status = "error"
                info.error = f"pktmon filter failed: {result.stderr.strip()}"
                return

            # Start capture
            cmd = [
                pktmon, "start",
                "--capture",
                "--file-name", etl_path,
                "--packet-size", "0",  # Full packets
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            info.pid = proc.pid
            info.capture_tool = "pktmon"

            with self._lock:
                self._active_captures[info.capture_id] = (info, proc, {"etl_path": etl_path})

            # Watchdog to stop after duration
            watchdog = threading.Thread(
                target=self._capture_watchdog,
                args=(info.capture_id, info.duration),
                daemon=True,
            )
            watchdog.start()

        except FileNotFoundError:
            info.status = "error"
            info.error = (
                "pktmon not found. This tool requires Windows Server 2019+ or Windows 10 1809+. "
                "Run from an Administrator PowerShell."
            )
        except PermissionError:
            info.status = "error"
            info.error = (
                "Permission denied. pktmon requires Administrator privileges. "
                "Run the application from an elevated (Administrator) PowerShell or Command Prompt."
            )
        except Exception as e:
            info.status = "error"
            info.error = str(e)

    def _start_capture_linux(self, info, bpf_filter, snap_len):
        """Start capture on Linux using tcpdump."""
        if "tcpdump" in self._tool_paths:
            interface = info.interface or "any"

            # Validate interface name
            if not re.match(r"^[a-zA-Z0-9._\-]+$", interface):
                info.status = "error"
                info.error = "Invalid interface name"
                return

            cmd = [
                self._tool_paths["tcpdump"],
                "-i", interface,
                "-w", info.filepath,
                "-c", str(info.max_packets),
                "-nn",
            ]
            if snap_len > 0:
                cmd.extend(["-s", str(snap_len)])
            else:
                cmd.extend(["-s", "0"])

            if bpf_filter:
                cmd.append(bpf_filter)

            info.capture_tool = "tcpdump"
            self._launch_capture_process(cmd, info)

        elif "dumpcap" in self._tool_paths:
            self._start_dumpcap(info, bpf_filter, snap_len)
        else:
            info.status = "error"
            info.error = (
                "No capture tool found. Install tcpdump: apt-get install tcpdump"
            )

    def _launch_capture_process(self, cmd, info):
        """Launch a capture subprocess (shared by dumpcap/tshark/tcpdump)."""
        try:
            kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
            if self._is_windows:
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            proc = subprocess.Popen(cmd, **kwargs)
            info.pid = proc.pid

            with self._lock:
                self._active_captures[info.capture_id] = (info, proc, {})

            # Watchdog to stop capture after duration
            watchdog = threading.Thread(
                target=self._capture_watchdog,
                args=(info.capture_id, info.duration),
                daemon=True,
            )
            watchdog.start()

        except FileNotFoundError:
            info.status = "error"
            tool = info.capture_tool or "capture tool"
            if self._is_windows:
                info.error = (
                    f"{tool} not found. Install Wireshark from "
                    "https://www.wireshark.org/download.html — it includes "
                    "dumpcap and tshark for packet capture."
                )
            else:
                info.error = (
                    f"{tool} not found. Install it with: "
                    "apt-get install tcpdump (Linux)"
                )
        except PermissionError:
            info.status = "error"
            if self._is_windows:
                info.error = (
                    "Permission denied. Run the application as Administrator "
                    "to capture packets, or install Npcap with "
                    "'Allow non-admin users to capture' enabled."
                )
            else:
                info.error = (
                    "Permission denied. tcpdump requires root/sudo privileges. "
                    "Run with: sudo python run.py, or add CAP_NET_RAW capability."
                )
        except Exception as e:
            info.status = "error"
            info.error = str(e)

    def stop_capture(self, capture_id):
        """Stop a running capture and finalize it."""
        with self._lock:
            entry = self._active_captures.get(capture_id)

        if not entry:
            return {"error": f"No active capture with ID {capture_id}"}

        info, proc, extra = entry

        # Handle pktmon specially — stop via pktmon stop command
        if info.capture_tool == "pktmon":
            return self._stop_pktmon(capture_id, info, proc, extra)

        # Stop dumpcap/tshark/tcpdump
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

        # Read stderr for packet count info
        stderr_output = ""
        try:
            stderr_output = proc.stderr.read().decode("utf-8", errors="replace")
        except Exception:
            pass

        # Parse packet count from tool output
        if info.capture_tool == "tcpdump":
            pkt_match = re.search(r"(\d+)\s+packets?\s+captured", stderr_output)
            if pkt_match:
                info.packet_count = int(pkt_match.group(1))
        elif info.capture_tool in ("dumpcap", "tshark"):
            # dumpcap: "Packets captured: 1234"
            # tshark: "1234 packets captured"
            pkt_match = re.search(
                r"(?:Packets captured:\s*|Packets:\s*)(\d+)|(\d+)\s+packets?\s+captured",
                stderr_output,
            )
            if pkt_match:
                info.packet_count = int(pkt_match.group(1) or pkt_match.group(2))

        # Update file size
        if os.path.exists(info.filepath):
            info.file_size_bytes = os.path.getsize(info.filepath)

        info.status = "complete"
        info.end_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        with self._lock:
            self._active_captures.pop(capture_id, None)

        return info.to_dict()

    def _stop_pktmon(self, capture_id, info, proc, extra):
        """Stop a pktmon capture and convert ETL to pcapng."""
        pktmon = self._tool_paths.get("pktmon", "pktmon.exe")
        etl_path = extra.get("etl_path", "")

        try:
            # Stop pktmon
            subprocess.run(
                [pktmon, "stop"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Wait for the process to finish
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

            # Convert ETL to pcapng
            if etl_path and os.path.exists(etl_path):
                convert_result = subprocess.run(
                    [pktmon, "pcapng", etl_path, "-o", info.filepath],
                    capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if convert_result.returncode != 0:
                    # If conversion fails, keep the ETL file
                    info.filepath = etl_path
                    info.filename = os.path.basename(etl_path)
                else:
                    # Clean up ETL file after successful conversion
                    try:
                        os.remove(etl_path)
                    except OSError:
                        pass

            # Clean up filters
            subprocess.run(
                [pktmon, "filter", "remove"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

        except Exception as e:
            info.error = f"Error stopping pktmon: {e}"

        # Update file info
        if os.path.exists(info.filepath):
            info.file_size_bytes = os.path.getsize(info.filepath)

        info.status = "complete"
        info.end_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        with self._lock:
            self._active_captures.pop(capture_id, None)

        return info.to_dict()

    def get_capture_status(self, capture_id):
        """Check the status of a capture."""
        with self._lock:
            entry = self._active_captures.get(capture_id)

        if not entry:
            return {"error": "Capture not found or already completed"}

        info, proc, extra = entry
        poll = proc.poll()

        if poll is not None:
            return self.stop_capture(capture_id)

        # Still running — update file size
        if os.path.exists(info.filepath):
            info.file_size_bytes = os.path.getsize(info.filepath)

        return info.to_dict()

    def list_captures(self):
        """List all pcap files in the capture directory."""
        captures = []
        if not os.path.exists(self.capture_dir):
            return captures

        for fname in sorted(os.listdir(self.capture_dir), reverse=True):
            if not fname.endswith((".pcap", ".pcapng", ".cap", ".etl")):
                continue
            fpath = os.path.join(self.capture_dir, fname)
            fsize = os.path.getsize(fpath)
            mtime = os.path.getmtime(fpath)

            pkt_count = self._get_packet_count(fpath)

            captures.append({
                "filename": fname,
                "filepath": fpath,
                "file_size_bytes": fsize,
                "file_size_display": self._format_bytes(fsize),
                "modified": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(mtime)
                ),
                "packet_count": pkt_count,
            })

        return captures

    def delete_capture(self, filename):
        """Delete a capture file."""
        if not re.match(r"^[\w.\-]+\.(pcap|pcapng|cap|etl)$", filename):
            return {"error": "Invalid filename"}

        fpath = os.path.join(self.capture_dir, filename)
        if not os.path.exists(fpath):
            return {"error": "File not found"}

        os.remove(fpath)
        return {"status": "deleted", "filename": filename}

    def _build_bpf_filter(self, target_ip, source_ip="", port_filter=""):
        """Build a BPF filter string (works with dumpcap/tshark/tcpdump)."""
        parts = []

        if source_ip:
            parts.append(f"(host {target_ip} and host {source_ip})")
        else:
            parts.append(f"host {target_ip}")

        if port_filter:
            port_filter = port_filter.strip()
            if re.match(r"^\d{1,5}$", port_filter):
                port_num = int(port_filter)
                if 1 <= port_num <= 65535:
                    parts.append(f"port {port_num}")

        return " and ".join(parts)

    def _capture_watchdog(self, capture_id, duration):
        """Background thread that stops a capture after the specified duration."""
        time.sleep(duration)
        with self._lock:
            entry = self._active_captures.get(capture_id)
        if entry:
            self.stop_capture(capture_id)

    def _get_packet_count(self, filepath):
        """Get packet count from a pcap file using capinfos or tshark."""
        if "capinfos" in self._tool_paths:
            try:
                result = subprocess.run(
                    [self._tool_paths["capinfos"], "-c", "-M", filepath],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
                )
                if result.returncode == 0:
                    match = re.search(r"Number of packets:\s*(\d+)", result.stdout)
                    if match:
                        return int(match.group(1))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if "tshark" in self._tool_paths:
            try:
                result = subprocess.run(
                    [self._tool_paths["tshark"], "-r", filepath,
                     "-T", "fields", "-e", "frame.number"],
                    capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    return len([l for l in lines if l.strip()])
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return -1  # Unknown

    @staticmethod
    def _format_bytes(nbytes):
        """Human-readable file size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if nbytes < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.1f} TB"
