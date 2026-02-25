"""
Packet Capture Engine

Wraps tcpdump to capture packets for throughput analysis.
Supports:
  - Start/stop live captures with BPF filters
  - Upload pre-captured pcap files
  - List and manage capture files
  - Interface discovery
"""

import os
import re
import signal
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
    interface: str = "any"
    duration: int = 0
    max_packets: int = 0
    file_size_bytes: int = 0
    packet_count: int = 0
    start_time: str = ""
    end_time: str = ""
    error: str = ""
    pid: int = 0

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
        }


class PacketCaptureEngine:
    """
    Manages packet captures using tcpdump.

    Usage:
        engine = PacketCaptureEngine(capture_dir='captures')
        info = engine.start_capture(target_ip='10.15.25.50', duration=30)
        # ... wait ...
        engine.stop_capture(info.capture_id)
        # or let duration expire
    """

    def __init__(self, capture_dir="captures"):
        self.capture_dir = capture_dir
        os.makedirs(capture_dir, exist_ok=True)
        self._active_captures = {}  # capture_id -> (CaptureInfo, subprocess.Popen)
        self._lock = threading.Lock()

    def check_tools(self):
        """Check which capture/analysis tools are available."""
        tools = {}
        for tool in ["tcpdump", "tshark", "capinfos"]:
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                tools[tool] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                tools[tool] = False
        return tools

    def list_interfaces(self):
        """List available network interfaces for capture."""
        interfaces = []
        try:
            # Try ip link first (Linux)
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
                            # Get IP address for this interface
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
                                "ip": ip_addr,
                                "display": f"{iface} ({ip_addr})" if ip_addr else iface,
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Always add "any" as an option
        interfaces.insert(0, {
            "name": "any",
            "ip": "",
            "display": "any (all interfaces)",
        })

        return interfaces

    def start_capture(
        self,
        target_ip,
        source_ip="",
        interface="any",
        duration=30,
        max_packets=100000,
        snap_len=0,
        port_filter="",
    ):
        """
        Start a tcpdump packet capture.

        Args:
            target_ip: Remote IP to filter on (required)
            source_ip: Local IP to filter on (optional, narrows filter)
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

        # Validate interface name (alphanumeric, hyphens, dots)
        if not re.match(r"^[a-zA-Z0-9._\-]+$", interface):
            return CaptureInfo(
                capture_id="", filename="", filepath="",
                status="error", error="Invalid interface name",
            )

        # Clamp duration and packet count
        duration = min(max(duration, 5), 120)
        max_packets = min(max(max_packets, 1000), 500000)

        # Generate capture ID and filename
        capture_id = f"cap_{int(time.time())}_{os.getpid()}"
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp_str}_{target_ip.replace('.', '_')}.pcap"
        filepath = os.path.join(self.capture_dir, filename)

        # Build BPF filter
        bpf_filter = self._build_bpf_filter(target_ip, source_ip, port_filter)

        # Build tcpdump command
        cmd = [
            "tcpdump",
            "-i", interface,
            "-w", filepath,
            "-c", str(max_packets),
            "-nn",  # Don't resolve hostnames or ports
        ]
        if snap_len > 0:
            cmd.extend(["-s", str(snap_len)])
        else:
            cmd.extend(["-s", "0"])  # Full packet capture

        if bpf_filter:
            cmd.append(bpf_filter)

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

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            info.pid = proc.pid

            with self._lock:
                self._active_captures[capture_id] = (info, proc)

            # Start a watchdog thread to stop capture after duration
            watchdog = threading.Thread(
                target=self._capture_watchdog,
                args=(capture_id, duration),
                daemon=True,
            )
            watchdog.start()

        except FileNotFoundError:
            info.status = "error"
            info.error = (
                "tcpdump not found. Install it with: "
                "apt-get install tcpdump (Linux) or brew install tcpdump (macOS)"
            )
        except PermissionError:
            info.status = "error"
            info.error = (
                "Permission denied. tcpdump requires root/sudo privileges. "
                "Run with: sudo python run.py, or add CAP_NET_RAW capability."
            )
        except Exception as e:
            info.status = "error"
            info.error = str(e)

        return info

    def stop_capture(self, capture_id):
        """Stop a running capture and finalize it."""
        with self._lock:
            entry = self._active_captures.get(capture_id)

        if not entry:
            return {"error": f"No active capture with ID {capture_id}"}

        info, proc = entry

        # Send SIGTERM to tcpdump
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

        # Read stderr for packet count
        stderr_output = ""
        try:
            stderr_output = proc.stderr.read().decode("utf-8", errors="replace")
        except Exception:
            pass

        # Parse tcpdump summary (e.g., "42 packets captured")
        pkt_match = re.search(r"(\d+)\s+packets?\s+captured", stderr_output)
        if pkt_match:
            info.packet_count = int(pkt_match.group(1))

        # Update file size
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

        info, proc = entry
        poll = proc.poll()

        if poll is not None:
            # Process has exited
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
            if not fname.endswith((".pcap", ".pcapng", ".cap")):
                continue
            fpath = os.path.join(self.capture_dir, fname)
            fsize = os.path.getsize(fpath)
            mtime = os.path.getmtime(fpath)

            # Try to get packet count via capinfos
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
        # Sanitize filename — only allow pcap files in our directory
        if not re.match(r"^[\w.\-]+\.(pcap|pcapng|cap)$", filename):
            return {"error": "Invalid filename"}

        fpath = os.path.join(self.capture_dir, filename)
        if not os.path.exists(fpath):
            return {"error": "File not found"}

        os.remove(fpath)
        return {"status": "deleted", "filename": filename}

    def _build_bpf_filter(self, target_ip, source_ip="", port_filter=""):
        """Build a BPF filter string for tcpdump."""
        parts = []

        if source_ip:
            # Filter for traffic between specific source and target
            parts.append(
                f"(host {target_ip} and host {source_ip})"
            )
        else:
            # Filter for any traffic to/from target
            parts.append(f"host {target_ip}")

        if port_filter:
            # Validate port
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
        try:
            result = subprocess.run(
                ["capinfos", "-c", "-M", filepath],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                match = re.search(r"Number of packets:\s*(\d+)", result.stdout)
                if match:
                    return int(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: try tshark
        try:
            result = subprocess.run(
                ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=30,
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
