"""
PCAP Analyzer for Asymmetric Throughput Diagnosis

Analyzes packet captures to find the root cause of directional throughput
problems. Designed specifically for diagnosing why ATL->PHX gets 10 Mbps
while PHX->ATL gets 140 Mbps on the same link.

Checks:
  1. Per-direction throughput (bytes, packets, data rate)
  2. TCP retransmissions & duplicate ACKs per direction
  3. TCP window size analysis (min/avg/max, zero-window events)
  4. Window scaling negotiation (SYN options)
  5. RTT estimation per direction
  6. DSCP/QoS marking differences
  7. IP fragmentation
  8. MSS negotiation
  9. TCP connection setup timing (SYN -> SYN-ACK latency)
  10. Per-second throughput timeline

Uses tshark (Wireshark CLI) for deep analysis.
Falls back to tcpdump -r for basic stats if tshark isn't available.
"""

import os
import platform
import re
import subprocess
import time
import json
from dataclasses import dataclass, field


@dataclass
class DirectionStats:
    """Stats for one direction of traffic (e.g., ATL -> PHX)."""
    label: str = ""
    packets: int = 0
    bytes_total: int = 0
    data_bytes: int = 0  # payload only (excluding headers)
    throughput_mbps: float = 0.0
    throughput_MBps: float = 0.0
    retransmissions: int = 0
    duplicate_acks: int = 0
    zero_window: int = 0
    window_size_min: int = 0
    window_size_avg: int = 0
    window_size_max: int = 0
    rtt_samples: int = 0
    rtt_min_ms: float = 0.0
    rtt_avg_ms: float = 0.0
    rtt_max_ms: float = 0.0
    dscp_values: dict = field(default_factory=dict)
    fragments: int = 0
    rst_packets: int = 0
    fin_packets: int = 0

    def to_dict(self):
        return {
            "label": self.label,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "data_bytes": self.data_bytes,
            "throughput_mbps": round(self.throughput_mbps, 2),
            "throughput_MBps": round(self.throughput_MBps, 2),
            "retransmissions": self.retransmissions,
            "duplicate_acks": self.duplicate_acks,
            "zero_window": self.zero_window,
            "window_size_min": self.window_size_min,
            "window_size_avg": self.window_size_avg,
            "window_size_max": self.window_size_max,
            "rtt_samples": self.rtt_samples,
            "rtt_min_ms": round(self.rtt_min_ms, 3),
            "rtt_avg_ms": round(self.rtt_avg_ms, 3),
            "rtt_max_ms": round(self.rtt_max_ms, 3),
            "dscp_values": self.dscp_values,
            "fragments": self.fragments,
            "rst_packets": self.rst_packets,
            "fin_packets": self.fin_packets,
        }


@dataclass
class TcpConnectionInfo:
    """TCP connection setup details from SYN analysis."""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    syn_time: float = 0.0
    synack_time: float = 0.0
    handshake_ms: float = 0.0
    mss_client: int = 0
    mss_server: int = 0
    window_scale_client: int = -1  # -1 = not present
    window_scale_server: int = -1
    sack_permitted: bool = False

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "handshake_ms": round(self.handshake_ms, 3),
            "mss_client": self.mss_client,
            "mss_server": self.mss_server,
            "window_scale_client": self.window_scale_client,
            "window_scale_server": self.window_scale_server,
            "sack_permitted": self.sack_permitted,
        }


@dataclass
class PcapAnalysisReport:
    """Complete pcap analysis report."""
    filename: str = ""
    file_size_bytes: int = 0
    total_packets: int = 0
    capture_duration_sec: float = 0.0
    analysis_tool: str = ""
    source_ip: str = ""
    target_ip: str = ""
    forward: DirectionStats = field(default_factory=DirectionStats)  # source -> target
    reverse: DirectionStats = field(default_factory=DirectionStats)  # target -> source
    connections: list = field(default_factory=list)
    timeline: list = field(default_factory=list)  # per-second throughput
    findings: list = field(default_factory=list)
    summary: str = ""

    def to_dict(self):
        return {
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "total_packets": self.total_packets,
            "capture_duration_sec": round(self.capture_duration_sec, 2),
            "analysis_tool": self.analysis_tool,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "forward": self.forward.to_dict(),
            "reverse": self.reverse.to_dict(),
            "connections": [c.to_dict() for c in self.connections],
            "timeline": self.timeline,
            "findings": self.findings,
            "summary": self.summary,
        }


class PcapAnalyzer:
    """
    Analyzes pcap files for asymmetric throughput diagnosis.

    Usage:
        analyzer = PcapAnalyzer()
        report = analyzer.analyze('capture.pcap', '10.2.25.55', '10.15.25.50')
        print(report.to_dict())
    """

    # Common Wireshark install paths on Windows
    _WIRESHARK_PATHS = [
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
    ]

    def __init__(self):
        self._is_windows = platform.system() == "Windows"
        self._tool_paths = self._discover_tools()
        self._has_tshark = "tshark" in self._tool_paths
        self._has_capinfos = "capinfos" in self._tool_paths
        self._has_tcpdump = "tcpdump" in self._tool_paths

    def _discover_tools(self):
        """Find available analysis tools, checking Windows install paths."""
        tools = {}

        if self._is_windows:
            # Check common Wireshark install directories on Windows
            for ws_dir in self._WIRESHARK_PATHS:
                if os.path.isdir(ws_dir):
                    for tool in ["tshark", "capinfos"]:
                        exe = os.path.join(ws_dir, f"{tool}.exe")
                        if os.path.isfile(exe):
                            tools.setdefault(tool, exe)

            # Also check PATH
            for tool in ["tshark", "capinfos"]:
                if tool not in tools and self._check_tool_on_path(f"{tool}.exe"):
                    tools[tool] = f"{tool}.exe"
        else:
            # Linux — tools are on PATH
            for tool in ["tshark", "capinfos", "tcpdump"]:
                if self._check_tool_on_path(tool):
                    tools[tool] = tool

        return tools

    def _check_tool_on_path(self, executable):
        """Check if a tool is available on the system PATH."""
        try:
            which_cmd = "where" if self._is_windows else "which"
            result = subprocess.run(
                [which_cmd, executable],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(self, pcap_path, source_ip, target_ip, source_label="", target_label=""):
        """
        Analyze a pcap file for directional throughput issues.

        Args:
            pcap_path: Path to the .pcap/.pcapng file
            source_ip: The "slow" direction source IP (e.g., ATL server)
            target_ip: The "slow" direction target IP (e.g., PHX server)
            source_label: Human label for source (e.g., "ATL")
            target_label: Human label for target (e.g., "PHX")

        Returns:
            PcapAnalysisReport
        """
        if not os.path.exists(pcap_path):
            report = PcapAnalysisReport(filename=os.path.basename(pcap_path))
            report.summary = f"File not found: {pcap_path}"
            return report

        src_label = source_label or source_ip
        tgt_label = target_label or target_ip

        report = PcapAnalysisReport(
            filename=os.path.basename(pcap_path),
            file_size_bytes=os.path.getsize(pcap_path),
            source_ip=source_ip,
            target_ip=target_ip,
        )
        report.forward.label = f"{src_label} -> {tgt_label}"
        report.reverse.label = f"{tgt_label} -> {src_label}"

        if self._has_tshark:
            report.analysis_tool = "tshark"
            self._analyze_with_tshark(pcap_path, source_ip, target_ip, report)
        elif self._has_tcpdump:
            report.analysis_tool = "tcpdump"
            self._analyze_with_tcpdump(pcap_path, source_ip, target_ip, report)
        else:
            if self._is_windows:
                report.summary = (
                    "No analysis tools found. Install Wireshark from "
                    "https://www.wireshark.org/download.html — it includes "
                    "tshark and capinfos for pcap analysis."
                )
            else:
                report.summary = (
                    "No analysis tools found. Install tshark (apt-get install tshark) "
                    "or tcpdump (apt-get install tcpdump) to analyze captures."
                )
            return report

        # Generate findings based on the stats
        self._generate_findings(report)
        self._generate_summary(report)

        return report

    # ------------------------------------------------------------------
    # tshark-based analysis (full featured)
    # ------------------------------------------------------------------

    def _analyze_with_tshark(self, pcap_path, source_ip, target_ip, report):
        """Deep analysis using tshark."""
        # Step 1: Get capture overview (duration, packet count)
        self._tshark_capture_info(pcap_path, report)

        # Step 2: Per-direction packet/byte counts
        self._tshark_direction_stats(pcap_path, source_ip, target_ip, report)

        # Step 3: TCP retransmissions per direction
        self._tshark_retransmissions(pcap_path, source_ip, target_ip, report)

        # Step 4: Duplicate ACKs per direction
        self._tshark_duplicate_acks(pcap_path, source_ip, target_ip, report)

        # Step 5: Window size analysis per direction
        self._tshark_window_sizes(pcap_path, source_ip, target_ip, report)

        # Step 6: Zero window events
        self._tshark_zero_windows(pcap_path, source_ip, target_ip, report)

        # Step 7: RTT analysis
        self._tshark_rtt_analysis(pcap_path, source_ip, target_ip, report)

        # Step 8: TCP connection setup (SYN analysis)
        self._tshark_syn_analysis(pcap_path, source_ip, target_ip, report)

        # Step 9: DSCP/QoS markings per direction
        self._tshark_dscp_analysis(pcap_path, source_ip, target_ip, report)

        # Step 10: Fragmentation per direction
        self._tshark_fragmentation(pcap_path, source_ip, target_ip, report)

        # Step 11: RST and FIN counts
        self._tshark_rst_fin(pcap_path, source_ip, target_ip, report)

        # Step 12: Per-second throughput timeline
        self._tshark_timeline(pcap_path, source_ip, target_ip, report)

        # Calculate throughput
        if report.capture_duration_sec > 0:
            dur = report.capture_duration_sec
            report.forward.throughput_mbps = (
                (report.forward.bytes_total * 8) / (dur * 1_000_000)
            )
            report.forward.throughput_MBps = (
                report.forward.bytes_total / (dur * 1_000_000)
            )
            report.reverse.throughput_mbps = (
                (report.reverse.bytes_total * 8) / (dur * 1_000_000)
            )
            report.reverse.throughput_MBps = (
                report.reverse.bytes_total / (dur * 1_000_000)
            )

    def _tshark_capture_info(self, pcap_path, report):
        """Get total packets and duration from capinfos or tshark."""
        if self._has_capinfos:
            try:
                capinfos_path = self._tool_paths.get("capinfos", "capinfos")
                result = subprocess.run(
                    [capinfos_path, "-c", "-u", "-a", "-e", "-M", pcap_path],
                    capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
                )
                if result.returncode == 0:
                    out = result.stdout
                    m = re.search(r"Number of packets:\s*(\d+)", out)
                    if m:
                        report.total_packets = int(m.group(1))

                    # Parse start/end time for duration
                    start_m = re.search(
                        r"First packet time:\s*(.+)", out
                    )
                    end_m = re.search(
                        r"Last packet time:\s*(.+)", out
                    )
                    dur_m = re.search(
                        r"Capture duration:\s*([\d.]+)", out
                    )
                    if dur_m:
                        report.capture_duration_sec = float(dur_m.group(1))
                    return
            except (subprocess.TimeoutExpired, Exception):
                pass

        # Fallback: use tshark to count and get first/last frame time
        try:
            result = self._run_tshark(
                pcap_path,
                ["-T", "fields", "-e", "frame.time_epoch"],
                timeout=60,
            )
            if result:
                lines = [l.strip() for l in result.split("\n") if l.strip()]
                report.total_packets = len(lines)
                if len(lines) >= 2:
                    first = float(lines[0])
                    last = float(lines[-1])
                    report.capture_duration_sec = last - first
        except Exception:
            pass

    def _tshark_direction_stats(self, pcap_path, src_ip, dst_ip, report):
        """Get packet and byte counts per direction."""
        for direction, filter_expr, stats in [
            ("forward", f"ip.src=={src_ip} && ip.dst=={dst_ip}", report.forward),
            ("reverse", f"ip.src=={dst_ip} && ip.dst=={src_ip}", report.reverse),
        ]:
            result = self._run_tshark(
                pcap_path,
                ["-Y", filter_expr, "-T", "fields",
                 "-e", "frame.len", "-e", "tcp.len"],
                timeout=60,
            )
            if result:
                lines = [l for l in result.split("\n") if l.strip()]
                stats.packets = len(lines)
                total_bytes = 0
                data_bytes = 0
                for line in lines:
                    parts = line.split("\t")
                    if parts[0]:
                        total_bytes += int(parts[0])
                    if len(parts) > 1 and parts[1]:
                        data_bytes += int(parts[1])
                stats.bytes_total = total_bytes
                stats.data_bytes = data_bytes

    def _tshark_retransmissions(self, pcap_path, src_ip, dst_ip, report):
        """Count TCP retransmissions per direction."""
        for filter_expr, stats in [
            (f"tcp.analysis.retransmission && ip.src=={src_ip} && ip.dst=={dst_ip}",
             report.forward),
            (f"tcp.analysis.retransmission && ip.src=={dst_ip} && ip.dst=={src_ip}",
             report.reverse),
        ]:
            count = self._tshark_count(pcap_path, filter_expr)
            stats.retransmissions = count

    def _tshark_duplicate_acks(self, pcap_path, src_ip, dst_ip, report):
        """Count duplicate ACKs per direction."""
        for filter_expr, stats in [
            (f"tcp.analysis.duplicate_ack && ip.src=={src_ip} && ip.dst=={dst_ip}",
             report.forward),
            (f"tcp.analysis.duplicate_ack && ip.src=={dst_ip} && ip.dst=={src_ip}",
             report.reverse),
        ]:
            count = self._tshark_count(pcap_path, filter_expr)
            stats.duplicate_acks = count

    def _tshark_window_sizes(self, pcap_path, src_ip, dst_ip, report):
        """Analyze TCP window sizes per direction."""
        for filter_expr, stats in [
            (f"ip.src=={src_ip} && ip.dst=={dst_ip}", report.forward),
            (f"ip.src=={dst_ip} && ip.dst=={src_ip}", report.reverse),
        ]:
            result = self._run_tshark(
                pcap_path,
                ["-Y", f"{filter_expr} && tcp.window_size > 0",
                 "-T", "fields", "-e", "tcp.window_size"],
                timeout=60,
            )
            if result:
                values = []
                for line in result.split("\n"):
                    line = line.strip()
                    if line and line.isdigit():
                        values.append(int(line))
                if values:
                    stats.window_size_min = min(values)
                    stats.window_size_max = max(values)
                    stats.window_size_avg = sum(values) // len(values)

    def _tshark_zero_windows(self, pcap_path, src_ip, dst_ip, report):
        """Count TCP zero-window advertisements per direction."""
        for filter_expr, stats in [
            (f"tcp.analysis.zero_window && ip.src=={src_ip} && ip.dst=={dst_ip}",
             report.forward),
            (f"tcp.analysis.zero_window && ip.src=={dst_ip} && ip.dst=={src_ip}",
             report.reverse),
        ]:
            count = self._tshark_count(pcap_path, filter_expr)
            stats.zero_window = count

    def _tshark_rtt_analysis(self, pcap_path, src_ip, dst_ip, report):
        """Extract RTT estimates from TCP ACK analysis."""
        # tshark's tcp.analysis.ack_rtt gives RTT for ACKs
        for filter_expr, stats in [
            (f"ip.src=={src_ip} && ip.dst=={dst_ip}", report.forward),
            (f"ip.src=={dst_ip} && ip.dst=={src_ip}", report.reverse),
        ]:
            result = self._run_tshark(
                pcap_path,
                ["-Y", f"{filter_expr} && tcp.analysis.ack_rtt",
                 "-T", "fields", "-e", "tcp.analysis.ack_rtt"],
                timeout=60,
            )
            if result:
                rtts = []
                for line in result.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            rtt_sec = float(line)
                            rtts.append(rtt_sec * 1000)  # Convert to ms
                        except ValueError:
                            pass
                if rtts:
                    stats.rtt_samples = len(rtts)
                    stats.rtt_min_ms = min(rtts)
                    stats.rtt_max_ms = max(rtts)
                    stats.rtt_avg_ms = sum(rtts) / len(rtts)

    def _tshark_syn_analysis(self, pcap_path, src_ip, dst_ip, report):
        """Analyze TCP SYN packets for MSS, window scaling, SACK."""
        # Get SYN packets (not SYN-ACK)
        result = self._run_tshark(
            pcap_path,
            ["-Y", "tcp.flags.syn==1",
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "tcp.flags.ack",
             "-e", "frame.time_epoch",
             "-e", "tcp.options.mss_val",
             "-e", "tcp.options.wscale.shift",
             "-e", "tcp.options.sack_perm"],
            timeout=30,
        )
        if not result:
            return

        # Parse SYN and SYN-ACK pairs to build connection info
        syns = {}  # (src, dst, dport) -> (time, mss, wscale, sack)
        connections = []

        for line in result.split("\n"):
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 6:
                continue

            s_ip = parts[0].strip()
            d_ip = parts[1].strip()
            s_port = parts[2].strip()
            d_port = parts[3].strip()
            is_ack = parts[4].strip()
            epoch = parts[5].strip()
            mss = parts[6].strip() if len(parts) > 6 else ""
            wscale = parts[7].strip() if len(parts) > 7 else ""
            sack = parts[8].strip() if len(parts) > 8 else ""

            if is_ack == "0":
                # SYN (client -> server)
                key = (s_ip, d_ip, d_port)
                syns[key] = {
                    "time": float(epoch) if epoch else 0,
                    "mss": int(mss) if mss else 0,
                    "wscale": int(wscale) if wscale else -1,
                    "sack": sack == "1",
                    "src_port": int(s_port) if s_port else 0,
                }
            elif is_ack == "1":
                # SYN-ACK (server -> client)
                key = (d_ip, s_ip, s_port)
                if key in syns:
                    syn_data = syns[key]
                    conn = TcpConnectionInfo(
                        src_ip=key[0],
                        dst_ip=key[1],
                        src_port=syn_data["src_port"],
                        dst_port=int(d_port) if d_port else 0,
                        syn_time=syn_data["time"],
                        synack_time=float(epoch) if epoch else 0,
                        mss_client=syn_data["mss"],
                        mss_server=int(mss) if mss else 0,
                        window_scale_client=syn_data["wscale"],
                        window_scale_server=int(wscale) if wscale else -1,
                        sack_permitted=syn_data["sack"] and sack == "1",
                    )
                    if conn.synack_time > conn.syn_time > 0:
                        conn.handshake_ms = (
                            (conn.synack_time - conn.syn_time) * 1000
                        )
                    connections.append(conn)

        # Keep first 20 connections max
        report.connections = connections[:20]

    def _tshark_dscp_analysis(self, pcap_path, src_ip, dst_ip, report):
        """Check DSCP/TOS markings per direction."""
        for filter_expr, stats in [
            (f"ip.src=={src_ip} && ip.dst=={dst_ip}", report.forward),
            (f"ip.src=={dst_ip} && ip.dst=={src_ip}", report.reverse),
        ]:
            result = self._run_tshark(
                pcap_path,
                ["-Y", filter_expr, "-T", "fields", "-e", "ip.dsfield.dscp"],
                timeout=30,
            )
            if result:
                dscp_counts = {}
                for line in result.split("\n"):
                    val = line.strip()
                    if val:
                        dscp_name = self._dscp_name(val)
                        dscp_counts[dscp_name] = dscp_counts.get(dscp_name, 0) + 1
                stats.dscp_values = dscp_counts

    def _tshark_fragmentation(self, pcap_path, src_ip, dst_ip, report):
        """Count IP fragments per direction."""
        for filter_expr, stats in [
            (f"ip.flags.mf==1 && ip.src=={src_ip} && ip.dst=={dst_ip}",
             report.forward),
            (f"ip.flags.mf==1 && ip.src=={dst_ip} && ip.dst=={src_ip}",
             report.reverse),
        ]:
            count = self._tshark_count(pcap_path, filter_expr)
            stats.fragments = count

    def _tshark_rst_fin(self, pcap_path, src_ip, dst_ip, report):
        """Count RST and FIN packets per direction."""
        for direction_filter, stats in [
            (f"ip.src=={src_ip} && ip.dst=={dst_ip}", report.forward),
            (f"ip.src=={dst_ip} && ip.dst=={src_ip}", report.reverse),
        ]:
            # RST
            rst_count = self._tshark_count(
                pcap_path, f"tcp.flags.reset==1 && {direction_filter}"
            )
            stats.rst_packets = rst_count

            # FIN
            fin_count = self._tshark_count(
                pcap_path, f"tcp.flags.fin==1 && {direction_filter}"
            )
            stats.fin_packets = fin_count

    def _tshark_timeline(self, pcap_path, src_ip, dst_ip, report):
        """Build per-second throughput timeline for both directions."""
        result = self._run_tshark(
            pcap_path,
            ["-qz", f"io,stat,1,ip.src=={src_ip}&&ip.dst=={dst_ip},ip.src=={dst_ip}&&ip.dst=={src_ip}"],
            timeout=60,
        )
        if not result:
            return

        timeline = []
        # Parse tshark io,stat output
        # Format: | Interval | Frames | Bytes | Frames | Bytes |
        in_table = False
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("|") and "<>" in line:
                in_table = True
                continue
            if not in_table:
                continue
            if line.startswith("=") or not line:
                continue
            if not line.startswith("|"):
                continue

            # Parse: | 0.000 <> 1.000 | 1234 | 56789 | 5678 | 12345 |
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) < 5:
                continue

            try:
                interval = parts[0]
                time_match = re.match(r"([\d.]+)\s*<>\s*([\d.]+)", interval)
                if not time_match:
                    continue

                sec_start = float(time_match.group(1))

                # Forward stats (columns 1-2)
                fwd_frames = int(parts[1]) if parts[1].isdigit() else 0
                fwd_bytes = int(parts[2]) if parts[2].isdigit() else 0

                # Reverse stats (columns 3-4)
                rev_frames = int(parts[3]) if parts[3].isdigit() else 0
                rev_bytes = int(parts[4]) if parts[4].isdigit() else 0

                timeline.append({
                    "second": int(sec_start),
                    "forward_bytes": fwd_bytes,
                    "forward_mbps": round((fwd_bytes * 8) / 1_000_000, 2),
                    "reverse_bytes": rev_bytes,
                    "reverse_mbps": round((rev_bytes * 8) / 1_000_000, 2),
                })
            except (ValueError, IndexError):
                continue

        report.timeline = timeline

    # ------------------------------------------------------------------
    # tcpdump-based analysis (fallback, limited)
    # ------------------------------------------------------------------

    def _analyze_with_tcpdump(self, pcap_path, src_ip, dst_ip, report):
        """Basic analysis using tcpdump -r (fallback when tshark unavailable)."""
        tcpdump_path = self._tool_paths.get("tcpdump", "tcpdump")
        try:
            result = subprocess.run(
                [tcpdump_path, "-nn", "-r", pcap_path, "-tt",
                 f"host {src_ip} and host {dst_ip}"],
                capture_output=True, text=True, timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            report.summary = "tcpdump read failed or timed out."
            return

        if result.returncode != 0:
            report.summary = f"tcpdump error: {result.stderr[:200]}"
            return

        lines = result.stdout.strip().split("\n")
        report.total_packets = len(lines)

        first_time = None
        last_time = None
        fwd_packets = 0
        fwd_bytes = 0
        rev_packets = 0
        rev_bytes = 0

        for line in lines:
            if not line.strip():
                continue

            # Parse timestamp
            ts_match = re.match(r"^([\d.]+)\s", line)
            if ts_match:
                ts = float(ts_match.group(1))
                if first_time is None:
                    first_time = ts
                last_time = ts

            # Parse direction and length
            # e.g., "1234567890.123456 IP 10.2.25.55.445 > 10.15.25.50.49152: ..."
            # Look for "length NNNN" or try to extract from the line
            length_match = re.search(r"length\s+(\d+)", line)
            pkt_len = int(length_match.group(1)) if length_match else 0

            if f"{src_ip}." in line and f"> {dst_ip}." in line:
                fwd_packets += 1
                fwd_bytes += pkt_len
            elif f"{dst_ip}." in line and f"> {src_ip}." in line:
                rev_packets += 1
                rev_bytes += pkt_len

        report.forward.packets = fwd_packets
        report.forward.bytes_total = fwd_bytes
        report.reverse.packets = rev_packets
        report.reverse.bytes_total = rev_bytes

        if first_time and last_time:
            report.capture_duration_sec = last_time - first_time
            if report.capture_duration_sec > 0:
                dur = report.capture_duration_sec
                report.forward.throughput_mbps = (fwd_bytes * 8) / (dur * 1_000_000)
                report.forward.throughput_MBps = fwd_bytes / (dur * 1_000_000)
                report.reverse.throughput_mbps = (rev_bytes * 8) / (dur * 1_000_000)
                report.reverse.throughput_MBps = rev_bytes / (dur * 1_000_000)

        # Count retransmissions (limited: look for duplicate seq numbers)
        # tcpdump can't reliably detect retransmissions without -v, so note limitation
        report.findings.append({
            "severity": "info",
            "category": "tool_limitation",
            "title": "Limited analysis (tcpdump fallback)",
            "detail": (
                "tshark is not installed. Using tcpdump for basic packet/byte counts only. "
                "Install tshark for retransmission, window size, RTT, and DSCP analysis."
            ),
            "recommendation": (
                "Install Wireshark from https://www.wireshark.org/download.html "
                "(includes tshark for deep analysis)"
                if self._is_windows else
                "Install Wireshark/tshark: sudo apt-get install tshark"
            ),
        })

    # ------------------------------------------------------------------
    # Finding generation
    # ------------------------------------------------------------------

    def _generate_findings(self, report):
        """Analyze the collected stats and generate actionable findings."""
        fwd = report.forward
        rev = report.reverse

        # 1. Throughput asymmetry
        if fwd.throughput_mbps > 0 and rev.throughput_mbps > 0:
            ratio = max(fwd.throughput_mbps, rev.throughput_mbps) / min(
                fwd.throughput_mbps, rev.throughput_mbps
            )
            if ratio > 3:
                slower = "forward" if fwd.throughput_mbps < rev.throughput_mbps else "reverse"
                slower_stats = fwd if slower == "forward" else rev
                faster_stats = rev if slower == "forward" else fwd
                report.findings.append({
                    "severity": "critical",
                    "category": "asymmetric_throughput",
                    "title": f"Severe throughput asymmetry detected ({ratio:.1f}:1)",
                    "detail": (
                        f"{faster_stats.label}: {faster_stats.throughput_mbps:.1f} Mbps | "
                        f"{slower_stats.label}: {slower_stats.throughput_mbps:.1f} Mbps"
                    ),
                    "recommendation": "Review findings below for root cause of the slow direction.",
                })

        # 2. Retransmissions
        for stats in [fwd, rev]:
            if stats.packets > 0 and stats.retransmissions > 0:
                retx_pct = (stats.retransmissions / stats.packets) * 100
                if retx_pct > 5:
                    report.findings.append({
                        "severity": "critical",
                        "category": "retransmissions",
                        "title": f"High retransmission rate: {stats.label}",
                        "detail": (
                            f"{stats.retransmissions} retransmissions out of "
                            f"{stats.packets} packets ({retx_pct:.1f}%). "
                            "Indicates packet loss in this direction causing TCP to "
                            "back off and resend, destroying throughput."
                        ),
                        "recommendation": (
                            "Check interface error counters (CRC, input errors) on "
                            "every hop in this direction. Run 'show interface' on switches "
                            "and firewalls. Check for QoS policer drops."
                        ),
                    })
                elif retx_pct > 1:
                    report.findings.append({
                        "severity": "warning",
                        "category": "retransmissions",
                        "title": f"Moderate retransmissions: {stats.label}",
                        "detail": (
                            f"{stats.retransmissions} retransmissions out of "
                            f"{stats.packets} packets ({retx_pct:.1f}%)."
                        ),
                        "recommendation": (
                            "Check interface error counters and QoS output drops "
                            "on devices in this traffic path."
                        ),
                    })

        # 3. Duplicate ACKs (indicates reordering or loss)
        for stats in [fwd, rev]:
            if stats.duplicate_acks > 100:
                report.findings.append({
                    "severity": "warning",
                    "category": "duplicate_acks",
                    "title": f"High duplicate ACK count: {stats.label}",
                    "detail": (
                        f"{stats.duplicate_acks} duplicate ACKs. This means the "
                        "receiver is repeatedly asking for missing segments. Caused by "
                        "packet loss or reordering in the network."
                    ),
                    "recommendation": (
                        "Investigate packet loss or out-of-order delivery between hops. "
                        "Check for ECMP load balancing causing reordering."
                    ),
                })

        # 4. Window size issues
        for stats in [fwd, rev]:
            if stats.window_size_max > 0 and stats.window_size_max < 65536:
                report.findings.append({
                    "severity": "critical",
                    "category": "tcp_window",
                    "title": f"TCP window never exceeds 64KB: {stats.label}",
                    "detail": (
                        f"Max window: {stats.window_size_max} bytes. "
                        "Without window scaling, TCP is limited to 64KB in flight. "
                        "On a high-latency link, this caps throughput severely. "
                        "E.g., 64KB / 30ms RTT = ~17 Mbps max."
                    ),
                    "recommendation": (
                        "Enable TCP window scaling on both endpoints. "
                        "Windows: netsh int tcp set global autotuninglevel=normal. "
                        "Linux: sysctl -w net.ipv4.tcp_window_scaling=1"
                    ),
                })
            elif stats.window_size_avg > 0 and stats.window_size_avg < 131072:
                report.findings.append({
                    "severity": "warning",
                    "category": "tcp_window",
                    "title": f"Small average TCP window: {stats.label}",
                    "detail": (
                        f"Avg window: {stats.window_size_avg:,} bytes "
                        f"(min: {stats.window_size_min:,}, max: {stats.window_size_max:,}). "
                        "Small windows throttle throughput on high-BDP links."
                    ),
                    "recommendation": (
                        "Increase TCP receive buffer: "
                        "Linux: sysctl -w net.core.rmem_max=16777216; "
                        "sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'"
                    ),
                })

        # 5. Zero window events
        for stats in [fwd, rev]:
            if stats.zero_window > 0:
                report.findings.append({
                    "severity": "critical" if stats.zero_window > 10 else "warning",
                    "category": "zero_window",
                    "title": f"TCP zero-window events: {stats.label}",
                    "detail": (
                        f"{stats.zero_window} zero-window advertisements. "
                        "The receiver is telling the sender to STOP sending because "
                        "its receive buffer is full. This is the receiver saying "
                        "'I can't process data fast enough.' Common causes: "
                        "slow disk I/O, CPU bottleneck, small socket buffer."
                    ),
                    "recommendation": (
                        "Check disk I/O on the receiving server (is it writing to a slow disk?). "
                        "Increase socket receive buffer size. Check CPU utilization."
                    ),
                })

        # 6. Window scaling not negotiated
        for conn in report.connections:
            if conn.window_scale_client == -1 or conn.window_scale_server == -1:
                report.findings.append({
                    "severity": "critical",
                    "category": "window_scaling",
                    "title": "TCP window scaling NOT negotiated",
                    "detail": (
                        f"Connection {conn.src_ip}:{conn.src_port} -> "
                        f"{conn.dst_ip}:{conn.dst_port}: "
                        f"Client wscale={conn.window_scale_client}, "
                        f"Server wscale={conn.window_scale_server}. "
                        "Without window scaling, max window is 64KB, "
                        "which severely limits throughput on any link with latency."
                    ),
                    "recommendation": (
                        "Enable window scaling on BOTH endpoints. A middlebox (firewall, "
                        "load balancer) may be stripping TCP options from SYN packets. "
                        "Check Palo Alto: set deviceconfig setting tcp strip-tcp-options no"
                    ),
                })
                break  # Only report once

        # 7. MSS issues
        for conn in report.connections:
            if conn.mss_client > 0 and conn.mss_client < 1360:
                report.findings.append({
                    "severity": "warning",
                    "category": "mss",
                    "title": f"Small MSS negotiated: {conn.mss_client} bytes",
                    "detail": (
                        "Standard Ethernet MSS is 1460 bytes (MTU 1500 - 40 byte headers). "
                        f"Client MSS of {conn.mss_client} increases per-packet overhead "
                        "and reduces throughput efficiency."
                    ),
                    "recommendation": (
                        "Check MTU settings on the client interface. If using VPN or tunnels, "
                        "MSS clamping may be too aggressive. Check firewall MSS adjust setting."
                    ),
                })
                break

        # 8. DSCP/QoS mismatch between directions
        fwd_dscp = set(fwd.dscp_values.keys()) if fwd.dscp_values else set()
        rev_dscp = set(rev.dscp_values.keys()) if rev.dscp_values else set()
        if fwd_dscp and rev_dscp and fwd_dscp != rev_dscp:
            report.findings.append({
                "severity": "warning",
                "category": "dscp_mismatch",
                "title": "Different DSCP markings per direction",
                "detail": (
                    f"Forward DSCP: {dict(fwd.dscp_values)} | "
                    f"Reverse DSCP: {dict(rev.dscp_values)}. "
                    "Different QoS markings may cause one direction to be "
                    "prioritized differently at routers with QoS policies."
                ),
                "recommendation": (
                    "Review QoS policies on switches and routers. Ensure both "
                    "directions receive the same QoS treatment."
                ),
            })

        # 9. Fragmentation
        for stats in [fwd, rev]:
            if stats.fragments > 0:
                report.findings.append({
                    "severity": "warning",
                    "category": "fragmentation",
                    "title": f"IP fragmentation detected: {stats.label}",
                    "detail": (
                        f"{stats.fragments} fragmented packets. Fragmentation adds "
                        "overhead and increases the chance of packet loss (if any "
                        "fragment is lost, the entire datagram must be retransmitted)."
                    ),
                    "recommendation": (
                        "Check MTU settings across the path. Set consistent MTU on all "
                        "devices or enable PMTUD. Check for MTU black holes."
                    ),
                })

        # 10. High RST count (connection problems)
        for stats in [fwd, rev]:
            if stats.rst_packets > 10:
                report.findings.append({
                    "severity": "warning",
                    "category": "connection_resets",
                    "title": f"Multiple TCP resets: {stats.label}",
                    "detail": (
                        f"{stats.rst_packets} RST packets. Connections are being "
                        "forcibly closed. May indicate firewall blocking, application "
                        "errors, or port exhaustion."
                    ),
                    "recommendation": (
                        "Check firewall logs for denied connections. Check application "
                        "logs on both servers."
                    ),
                })

        # 11. High RTT
        for stats in [fwd, rev]:
            if stats.rtt_avg_ms > 50:
                report.findings.append({
                    "severity": "info",
                    "category": "latency",
                    "title": f"Elevated RTT: {stats.label}",
                    "detail": (
                        f"Average RTT: {stats.rtt_avg_ms:.1f} ms "
                        f"(min: {stats.rtt_min_ms:.1f}, max: {stats.rtt_max_ms:.1f}). "
                        "High latency combined with small windows severely limits throughput."
                    ),
                    "recommendation": (
                        "Ensure TCP window scaling is enabled and buffers are large enough "
                        "for the bandwidth-delay product."
                    ),
                })

        # 12. Handshake latency
        for conn in report.connections[:5]:
            if conn.handshake_ms > 100:
                report.findings.append({
                    "severity": "info",
                    "category": "handshake",
                    "title": f"Slow TCP handshake: {conn.handshake_ms:.1f} ms",
                    "detail": (
                        f"{conn.src_ip}:{conn.src_port} -> "
                        f"{conn.dst_ip}:{conn.dst_port}: "
                        f"SYN to SYN-ACK took {conn.handshake_ms:.1f} ms. "
                        "This is the base RTT for the connection."
                    ),
                    "recommendation": "This RTT affects all TCP operations on this connection.",
                })
                break  # Only report once

    def _generate_summary(self, report):
        """Generate a human-readable summary of the analysis."""
        fwd = report.forward
        rev = report.reverse
        parts = []

        parts.append(
            f"Analyzed {report.total_packets:,} packets over "
            f"{report.capture_duration_sec:.1f} seconds."
        )

        if fwd.throughput_mbps > 0 or rev.throughput_mbps > 0:
            parts.append(
                f"{fwd.label}: {fwd.throughput_mbps:.1f} Mbps "
                f"({fwd.packets:,} pkts, {fwd.retransmissions} retx). "
                f"{rev.label}: {rev.throughput_mbps:.1f} Mbps "
                f"({rev.packets:,} pkts, {rev.retransmissions} retx)."
            )

        critical = sum(1 for f in report.findings if f["severity"] == "critical")
        warning = sum(1 for f in report.findings if f["severity"] == "warning")

        if critical > 0:
            parts.append(
                f"Found {critical} critical issue(s) and {warning} warning(s)."
            )
        elif warning > 0:
            parts.append(f"Found {warning} warning(s).")
        else:
            parts.append("No significant issues detected in this capture.")

        report.summary = " ".join(parts)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_tshark(self, pcap_path, extra_args, timeout=60):
        """Run tshark with given arguments and return stdout."""
        tshark_path = self._tool_paths.get("tshark", "tshark")
        cmd = [tshark_path, "-r", pcap_path] + extra_args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if self._is_windows else 0,
            )
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return ""

    def _tshark_count(self, pcap_path, display_filter):
        """Count packets matching a display filter."""
        result = self._run_tshark(
            pcap_path,
            ["-Y", display_filter, "-T", "fields", "-e", "frame.number"],
            timeout=30,
        )
        if result:
            return len([l for l in result.split("\n") if l.strip()])
        return 0

    @staticmethod
    def _dscp_name(value):
        """Convert DSCP numeric value to name."""
        dscp_map = {
            "0": "BE (Best Effort)",
            "8": "CS1 (Scavenger)",
            "10": "AF11",
            "12": "AF12",
            "14": "AF13",
            "16": "CS2",
            "18": "AF21",
            "20": "AF22",
            "22": "AF23",
            "24": "CS3",
            "26": "AF31",
            "28": "AF32",
            "30": "AF33",
            "32": "CS4",
            "34": "AF41",
            "36": "AF42",
            "38": "AF43",
            "40": "CS5",
            "46": "EF (Expedited)",
            "48": "CS6",
            "56": "CS7",
        }
        return dscp_map.get(str(value).strip(), f"DSCP {value}")
