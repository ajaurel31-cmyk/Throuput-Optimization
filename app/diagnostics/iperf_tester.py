"""
iPerf3 Bandwidth Tester & Bottleneck Diagnosis Engine

Runs iperf3 bandwidth tests between ATL and PHX (or any two sites) and
diagnoses where the throughput bottleneck is.

Designed for Windows Server environments:
  - Uses iperf3.exe (must be in PATH or specified)
  - Parses JSON output from iperf3 -J
  - Provides Windows-specific tuning recommendations
"""

import json
import subprocess
import time
import re
from dataclasses import dataclass, field


@dataclass
class IperfResult:
    """Structured result from an iperf3 test."""
    status: str  # success, error
    summary: str
    direction: str  # send, receive
    protocol: str  # tcp, udp
    duration_sec: float = 0
    parallel_streams: int = 1

    # TCP metrics
    throughput_mbps: float = 0
    throughput_gbps: float = 0
    bytes_transferred: int = 0
    retransmits: int = 0
    mean_rtt_us: int = 0
    min_rtt_us: int = 0
    max_rtt_us: int = 0
    max_snd_cwnd: int = 0  # congestion window bytes

    # UDP metrics
    jitter_ms: float = 0
    lost_packets: int = 0
    total_packets: int = 0
    loss_percent: float = 0

    # Per-stream data
    streams: list = field(default_factory=list)

    # CPU usage
    host_cpu_total: float = 0
    remote_cpu_total: float = 0

    # Raw data
    raw_json: dict = field(default_factory=dict)
    error_message: str = ""

    def to_dict(self):
        return {
            "status": self.status,
            "summary": self.summary,
            "direction": self.direction,
            "protocol": self.protocol,
            "duration_sec": self.duration_sec,
            "parallel_streams": self.parallel_streams,
            "throughput_mbps": round(self.throughput_mbps, 2),
            "throughput_gbps": round(self.throughput_gbps, 4),
            "bytes_transferred": self.bytes_transferred,
            "retransmits": self.retransmits,
            "mean_rtt_us": self.mean_rtt_us,
            "min_rtt_us": self.min_rtt_us,
            "max_rtt_us": self.max_rtt_us,
            "max_snd_cwnd": self.max_snd_cwnd,
            "jitter_ms": round(self.jitter_ms, 3),
            "lost_packets": self.lost_packets,
            "total_packets": self.total_packets,
            "loss_percent": round(self.loss_percent, 2),
            "streams": self.streams,
            "host_cpu_total": round(self.host_cpu_total, 1),
            "remote_cpu_total": round(self.remote_cpu_total, 1),
            "error_message": self.error_message,
        }


@dataclass
class BottleneckDiagnosis:
    """Bottleneck diagnosis based on iperf3 results."""
    bottleneck_location: str  # network, tcp_config, cpu, server, firewall, unknown
    confidence: str  # high, medium, low
    severity: str  # critical, warning, info
    title: str
    detail: str
    recommendation: str

    def to_dict(self):
        return {
            "bottleneck_location": self.bottleneck_location,
            "confidence": self.confidence,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class IperfReport:
    """Full iperf3 test report with diagnosis."""
    source: str
    target: str
    link_speed_gbps: float
    timestamp: str
    test_result: IperfResult = None
    diagnoses: list = field(default_factory=list)
    overall_verdict: str = ""
    efficiency_percent: float = 0
    health: str = "unknown"  # healthy, degraded, impaired, critical

    def to_dict(self):
        return {
            "source": self.source,
            "target": self.target,
            "link_speed_gbps": self.link_speed_gbps,
            "timestamp": self.timestamp,
            "test_result": self.test_result.to_dict() if self.test_result else None,
            "diagnoses": [d.to_dict() for d in self.diagnoses],
            "overall_verdict": self.overall_verdict,
            "efficiency_percent": round(self.efficiency_percent, 1),
            "health": self.health,
        }


class IperfTester:
    """
    Runs iperf3 bandwidth tests and diagnoses bottlenecks.

    Prerequisites:
      - iperf3 must be installed on this machine (the client)
      - The remote target must be running: iperf3 -s
      - For Windows: iperf3.exe must be in PATH or provide full path
    """

    def __init__(self, target, port=5201, link_speed_gbps=10, source_label="ATL", target_label="PHX"):
        self.target = target
        self.port = port
        self.link_speed_gbps = link_speed_gbps
        self.source_label = source_label
        self.target_label = target_label

    def run_test(self, duration=10, parallel=1, reverse=False, udp=False, udp_bandwidth="1G", window_size=None):
        """
        Run an iperf3 bandwidth test and return a full report with diagnosis.

        Args:
            duration: Test duration in seconds (5-60)
            parallel: Number of parallel streams (1-16)
            reverse: If True, test in reverse (server sends to client)
            udp: If True, use UDP instead of TCP
            udp_bandwidth: Target bandwidth for UDP tests (e.g. "1G", "500M")
            window_size: TCP window size override (e.g. "4M", "512K")
        """
        report = IperfReport(
            source=self.source_label,
            target=f"{self.target_label} ({self.target})",
            link_speed_gbps=self.link_speed_gbps,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )

        # Run the iperf3 test
        result = self._execute_iperf(
            duration=duration,
            parallel=parallel,
            reverse=reverse,
            udp=udp,
            udp_bandwidth=udp_bandwidth,
            window_size=window_size,
        )
        report.test_result = result

        if result.status == "success":
            # Calculate efficiency
            max_mbps = self.link_speed_gbps * 1000
            report.efficiency_percent = (result.throughput_mbps / max_mbps) * 100 if max_mbps > 0 else 0

            # Run diagnosis
            report.diagnoses = self._diagnose(result)

            # Determine overall health
            if report.efficiency_percent >= 80:
                report.health = "healthy"
            elif report.efficiency_percent >= 50:
                report.health = "degraded"
            elif report.efficiency_percent >= 20:
                report.health = "impaired"
            else:
                report.health = "critical"

            # Build verdict
            report.overall_verdict = self._build_verdict(result, report)
        else:
            report.health = "critical"
            report.overall_verdict = f"Test failed: {result.error_message}"

        return report

    def _execute_iperf(self, duration, parallel, reverse, udp, udp_bandwidth, window_size):
        """Execute iperf3 and parse JSON output."""
        cmd = [
            "iperf3",
            "-c", self.target,
            "-p", str(self.port),
            "-t", str(duration),
            "-P", str(parallel),
            "-J",  # JSON output
        ]

        if reverse:
            cmd.append("-R")
        if udp:
            cmd.extend(["-u", "-b", udp_bandwidth])
        if window_size:
            cmd.extend(["-w", window_size])

        direction = "receive" if reverse else "send"
        protocol = "udp" if udp else "tcp"

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 30,
            )

            output = proc.stdout
            stderr = proc.stderr

            # Try to parse JSON even if return code is non-zero
            # (iperf3 sometimes returns non-zero but still has partial results)
            if output.strip():
                try:
                    data = json.loads(output)
                except json.JSONDecodeError:
                    return IperfResult(
                        status="error",
                        summary="Failed to parse iperf3 output",
                        direction=direction,
                        protocol=protocol,
                        error_message=f"Invalid JSON output. stderr: {stderr.strip()}"
                    )
            else:
                return IperfResult(
                    status="error",
                    summary="No output from iperf3",
                    direction=direction,
                    protocol=protocol,
                    error_message=stderr.strip() or "iperf3 produced no output. Is the server running?"
                )

            # Check for iperf3-level errors
            if "error" in data:
                return IperfResult(
                    status="error",
                    summary=f"iperf3 error: {data['error']}",
                    direction=direction,
                    protocol=protocol,
                    error_message=data["error"],
                )

            return self._parse_iperf_json(data, direction, protocol, parallel)

        except subprocess.TimeoutExpired:
            return IperfResult(
                status="error",
                summary="iperf3 test timed out",
                direction=direction,
                protocol=protocol,
                error_message=f"Test exceeded timeout of {duration + 30}s. The iperf3 server may be unresponsive.",
            )
        except FileNotFoundError:
            return IperfResult(
                status="error",
                summary="iperf3 not found",
                direction=direction,
                protocol=protocol,
                error_message=(
                    "iperf3 is not installed or not in PATH. "
                    "Download from https://iperf.fr/iperf-download.php and add to PATH."
                ),
            )

    def _parse_iperf_json(self, data, direction, protocol, parallel):
        """Parse iperf3 JSON output into IperfResult."""
        result = IperfResult(
            status="success",
            summary="",
            direction=direction,
            protocol=protocol,
            parallel_streams=parallel,
            raw_json=data,
        )

        end = data.get("end", {})

        # Duration
        result.duration_sec = end.get("sum_sent", end.get("sum", {})).get("seconds", 0)

        # CPU usage
        cpu = end.get("cpu_utilization_percent", {})
        result.host_cpu_total = cpu.get("host_total", 0)
        result.remote_cpu_total = cpu.get("remote_total", 0)

        if protocol == "tcp":
            # Use sent or received summary depending on direction
            sum_data = end.get("sum_sent", {})
            sum_recv = end.get("sum_received", {})

            # Throughput from sender's perspective
            bits_per_sec = sum_data.get("bits_per_second", 0)
            result.throughput_mbps = bits_per_sec / 1_000_000
            result.throughput_gbps = bits_per_sec / 1_000_000_000
            result.bytes_transferred = sum_data.get("bytes", 0)
            result.retransmits = sum_data.get("retransmits", 0)

            # Per-stream data for multi-stream tests
            streams = end.get("streams", [])
            for i, s in enumerate(streams):
                sender = s.get("sender", {})
                stream_info = {
                    "stream_id": i + 1,
                    "throughput_mbps": round(sender.get("bits_per_second", 0) / 1_000_000, 2),
                    "bytes": sender.get("bytes", 0),
                    "retransmits": sender.get("retransmits", 0),
                    "max_snd_cwnd": sender.get("max_snd_cwnd", 0),
                    "max_rtt": sender.get("max_rtt", 0),
                    "min_rtt": sender.get("min_rtt", 0),
                    "mean_rtt": sender.get("mean_rtt", 0),
                }
                result.streams.append(stream_info)

                # Aggregate RTT and cwnd from streams
                if sender.get("max_snd_cwnd", 0) > result.max_snd_cwnd:
                    result.max_snd_cwnd = sender.get("max_snd_cwnd", 0)
                if sender.get("mean_rtt", 0) > 0:
                    result.mean_rtt_us = max(result.mean_rtt_us, sender.get("mean_rtt", 0))
                if sender.get("min_rtt", 0) > 0:
                    if result.min_rtt_us == 0:
                        result.min_rtt_us = sender.get("min_rtt", 0)
                    else:
                        result.min_rtt_us = min(result.min_rtt_us, sender.get("min_rtt", 0))
                if sender.get("max_rtt", 0) > result.max_rtt_us:
                    result.max_rtt_us = sender.get("max_rtt", 0)

            # Build summary
            recv_mbps = sum_recv.get("bits_per_second", 0) / 1_000_000
            result.summary = (
                f"Sender: {result.throughput_mbps:.1f} Mbps | "
                f"Receiver: {recv_mbps:.1f} Mbps | "
                f"Retransmits: {result.retransmits} | "
                f"Streams: {parallel}"
            )

        elif protocol == "udp":
            sum_data = end.get("sum", {})
            bits_per_sec = sum_data.get("bits_per_second", 0)
            result.throughput_mbps = bits_per_sec / 1_000_000
            result.throughput_gbps = bits_per_sec / 1_000_000_000
            result.bytes_transferred = sum_data.get("bytes", 0)
            result.jitter_ms = sum_data.get("jitter_ms", 0)
            result.lost_packets = sum_data.get("lost_packets", 0)
            result.total_packets = sum_data.get("packets", 0)
            result.loss_percent = sum_data.get("lost_percent", 0)

            result.summary = (
                f"Throughput: {result.throughput_mbps:.1f} Mbps | "
                f"Jitter: {result.jitter_ms:.3f}ms | "
                f"Loss: {result.loss_percent:.1f}% ({result.lost_packets}/{result.total_packets})"
            )

        return result

    def _diagnose(self, result):
        """Analyze iperf3 results and identify bottlenecks."""
        diagnoses = []
        max_mbps = self.link_speed_gbps * 1000
        achieved_pct = (result.throughput_mbps / max_mbps) * 100 if max_mbps > 0 else 0

        if result.protocol == "tcp":
            diagnoses.extend(self._diagnose_tcp(result, max_mbps, achieved_pct))
        else:
            diagnoses.extend(self._diagnose_udp(result, max_mbps, achieved_pct))

        # CPU bottleneck check (applies to both TCP/UDP)
        if result.host_cpu_total > 80:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="cpu",
                confidence="high",
                severity="critical",
                title="Local CPU Saturation",
                detail=(
                    f"Host CPU utilization is {result.host_cpu_total:.0f}% during the test. "
                    f"The local server's CPU is the bottleneck, not the network."
                ),
                recommendation=(
                    "Windows Server tuning:\r\n"
                    "  1. Enable RSS (Receive Side Scaling):\r\n"
                    "     Set-NetAdapterRss -Name \"Ethernet\" -Enabled $true\r\n"
                    "  2. Check NIC offload settings:\r\n"
                    "     Get-NetAdapterChecksumOffload | Format-List\r\n"
                    "  3. Enable TCP offload:\r\n"
                    "     netsh int tcp set global chimney=enabled\r\n"
                    "  4. Consider using a NIC with better multi-queue support"
                ),
            ))
        elif result.host_cpu_total > 50:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="cpu",
                confidence="medium",
                severity="warning",
                title="Elevated Local CPU Usage",
                detail=f"Host CPU at {result.host_cpu_total:.0f}% — approaching saturation with more streams or traffic.",
                recommendation=(
                    "Monitor CPU during production transfers. Enable RSS and NIC offloading:\r\n"
                    "  Set-NetAdapterRss -Name \"Ethernet\" -Enabled $true\r\n"
                    "  Enable-NetAdapterChecksumOffload -Name \"Ethernet\""
                ),
            ))

        if result.remote_cpu_total > 80:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="cpu",
                confidence="high",
                severity="critical",
                title="Remote Server CPU Saturation",
                detail=f"Remote CPU at {result.remote_cpu_total:.0f}% — the remote server is the bottleneck.",
                recommendation=(
                    "The remote server needs TCP/NIC tuning:\r\n"
                    "  1. Enable RSS: Set-NetAdapterRss -Name \"Ethernet\" -Enabled $true\r\n"
                    "  2. Enable TCP offloading\r\n"
                    "  3. Verify NIC drivers are up to date\r\n"
                    "  4. Check if antivirus/security software is consuming CPU"
                ),
            ))

        return diagnoses

    def _diagnose_tcp(self, result, max_mbps, achieved_pct):
        """Diagnose TCP-specific bottlenecks."""
        diagnoses = []

        # 1. Overall throughput assessment
        if achieved_pct < 10:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="network",
                confidence="high",
                severity="critical",
                title=f"Severe Throughput Limitation — {result.throughput_mbps:.0f} Mbps on {self.link_speed_gbps}G link",
                detail=(
                    f"Achieving only {achieved_pct:.1f}% of link capacity. "
                    f"Expected ~{max_mbps:.0f} Mbps but measured {result.throughput_mbps:.0f} Mbps. "
                    f"A major bottleneck exists in the path."
                ),
                recommendation=(
                    "Investigate in this order:\r\n"
                    "  1. Check for QoS policers/shapers on all network devices in the path\r\n"
                    "  2. Verify firewall throughput capacity (SSL inspection, IPS)\r\n"
                    "  3. Check interface speed/duplex on all switches (show interface status)\r\n"
                    "  4. Look for interface errors: show interface counters errors\r\n"
                    "  5. Verify no traffic is being routed through a low-bandwidth path"
                ),
            ))
        elif achieved_pct < 50:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="network",
                confidence="high",
                severity="warning",
                title=f"Below Expected Throughput — {result.throughput_mbps:.0f} Mbps ({achieved_pct:.0f}% of {self.link_speed_gbps}G)",
                detail=(
                    f"Throughput is significantly below link capacity. "
                    f"This is commonly caused by TCP tuning issues, firewall overhead, or QoS policies."
                ),
                recommendation=(
                    "Check these common causes:\r\n"
                    "  1. Windows TCP tuning (see TCP Window recommendation below)\r\n"
                    "  2. Firewall deep inspection throughput limits\r\n"
                    "  3. QoS traffic shaping on switches/routers\r\n"
                    "  4. Try multiple parallel streams to rule out single-stream BDP limits"
                ),
            ))

        # 2. Retransmission analysis
        if result.retransmits > 0:
            retransmit_rate = 0
            total_segments_approx = result.bytes_transferred / 1460 if result.bytes_transferred > 0 else 1
            retransmit_rate = (result.retransmits / total_segments_approx) * 100

            if retransmit_rate > 1:
                diagnoses.append(BottleneckDiagnosis(
                    bottleneck_location="network",
                    confidence="high",
                    severity="critical",
                    title=f"High TCP Retransmissions — {result.retransmits} retransmits ({retransmit_rate:.2f}%)",
                    detail=(
                        f"A retransmit rate of {retransmit_rate:.2f}% indicates significant packet loss or congestion. "
                        f"Even 1% packet loss can reduce TCP throughput by 50% or more."
                    ),
                    recommendation=(
                        "Investigate packet loss:\r\n"
                        "  1. Check switch interface counters for CRC errors, input errors, output drops:\r\n"
                        "     show interface counters errors\r\n"
                        "  2. Check firewall session table utilization\r\n"
                        "  3. Look for QoS queue drops: show policy-map interface\r\n"
                        "  4. Check for MTU mismatches causing fragmentation\r\n"
                        "  5. On Windows: netstat -s | findstr Retransmit"
                    ),
                ))
            elif retransmit_rate > 0.1:
                diagnoses.append(BottleneckDiagnosis(
                    bottleneck_location="network",
                    confidence="medium",
                    severity="warning",
                    title=f"Moderate Retransmissions — {result.retransmits} retransmits ({retransmit_rate:.2f}%)",
                    detail=(
                        f"Some packet loss is occurring. While not severe, this reduces TCP efficiency "
                        f"and may indicate intermittent congestion."
                    ),
                    recommendation=(
                        "Monitor for patterns:\r\n"
                        "  1. Run tests at different times to check for congestion patterns\r\n"
                        "  2. Check interface utilization on transit switches\r\n"
                        "  3. Verify CRC/FCS error counters on all interfaces in the path"
                    ),
                ))
            elif result.retransmits > 0:
                diagnoses.append(BottleneckDiagnosis(
                    bottleneck_location="network",
                    confidence="low",
                    severity="info",
                    title=f"Minor Retransmissions — {result.retransmits} retransmits",
                    detail="A small number of retransmissions is normal and unlikely to affect throughput.",
                    recommendation="No action needed. This is within normal operating parameters.",
                ))

        # 3. TCP Window / BDP analysis
        if result.mean_rtt_us > 0:
            rtt_ms = result.mean_rtt_us / 1000
            rtt_sec = rtt_ms / 1000
            bdp_bytes = (self.link_speed_gbps * 1_000_000_000 / 8) * rtt_sec
            bdp_mb = bdp_bytes / (1024 * 1024)

            # Check if cwnd was limiting
            if result.max_snd_cwnd > 0 and result.max_snd_cwnd < bdp_bytes * 0.8:
                cwnd_limited_mbps = (result.max_snd_cwnd * 8) / (rtt_sec * 1_000_000)
                diagnoses.append(BottleneckDiagnosis(
                    bottleneck_location="tcp_config",
                    confidence="high",
                    severity="critical" if cwnd_limited_mbps < max_mbps * 0.5 else "warning",
                    title=f"TCP Window Size Limiting Throughput",
                    detail=(
                        f"Max congestion window: {result.max_snd_cwnd / 1024:.0f} KB | "
                        f"BDP requires: {bdp_bytes / 1024:.0f} KB | "
                        f"RTT: {rtt_ms:.1f}ms\r\n"
                        f"The TCP window is smaller than the bandwidth-delay product, "
                        f"capping single-stream throughput at ~{cwnd_limited_mbps:.0f} Mbps."
                    ),
                    recommendation=(
                        f"Increase TCP buffers on both servers (Windows):\r\n"
                        f"  1. Set auto-tuning to experimental:\r\n"
                        f"     netsh int tcp set global autotuninglevel=experimental\r\n"
                        f"  2. Or set manually via registry:\r\n"
                        f"     HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\r\n"
                        f"       TcpWindowSize = {int(bdp_bytes * 2)} (DWORD)\r\n"
                        f"       Tcp1323Opts = 3 (enable window scaling + timestamps)\r\n"
                        f"  3. Or use PowerShell:\r\n"
                        f"     Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Experimental\r\n"
                        f"  4. Use parallel streams (iperf3 -P 4) to work around single-stream limit"
                    ),
                ))
            elif result.parallel_streams == 1 and achieved_pct < 50 and rtt_ms > 5:
                # Single stream on high-RTT path
                max_single = (65535 * 8) / (rtt_sec * 1_000_000)
                diagnoses.append(BottleneckDiagnosis(
                    bottleneck_location="tcp_config",
                    confidence="medium",
                    severity="warning",
                    title=f"Single Stream + High RTT = BDP Limited",
                    detail=(
                        f"RTT: {rtt_ms:.1f}ms | BDP: {bdp_mb:.1f} MB | "
                        f"Single TCP stream max (default window): ~{max_single:.0f} Mbps.\r\n"
                        f"A single TCP stream cannot fill a {self.link_speed_gbps}G pipe with {rtt_ms:.0f}ms RTT "
                        f"without TCP window scaling."
                    ),
                    recommendation=(
                        f"Options to improve throughput:\r\n"
                        f"  1. Run with parallel streams: iperf3 -P 4 or -P 8\r\n"
                        f"  2. Enable TCP window scaling (Windows):\r\n"
                        f"     netsh int tcp set global autotuninglevel=experimental\r\n"
                        f"  3. Recommended TCP buffer size: {int(bdp_bytes * 2) // 1024} KB\r\n"
                        f"  4. Use SMB multichannel or parallel copy tools for file transfers"
                    ),
                ))

        # 4. Stream imbalance check (multi-stream)
        if result.parallel_streams > 1 and len(result.streams) > 1:
            throughputs = [s["throughput_mbps"] for s in result.streams]
            if throughputs:
                avg_tp = sum(throughputs) / len(throughputs)
                max_tp = max(throughputs)
                min_tp = min(throughputs)

                if avg_tp > 0 and (max_tp - min_tp) / avg_tp > 0.5:
                    diagnoses.append(BottleneckDiagnosis(
                        bottleneck_location="network",
                        confidence="medium",
                        severity="warning",
                        title="Stream Throughput Imbalance",
                        detail=(
                            f"Streams range from {min_tp:.0f} to {max_tp:.0f} Mbps "
                            f"(avg: {avg_tp:.0f} Mbps). This imbalance suggests uneven "
                            f"load balancing or RSS queue distribution."
                        ),
                        recommendation=(
                            "Check:\r\n"
                            "  1. RSS (Receive Side Scaling) configuration on both servers\r\n"
                            "  2. LACP/port-channel hash algorithm on switches\r\n"
                            "  3. NIC queue distribution:\r\n"
                            "     Get-NetAdapterRss -Name \"Ethernet\""
                        ),
                    ))

        # 5. No issues found — link looks healthy
        if not diagnoses and achieved_pct >= 80:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="none",
                confidence="high",
                severity="info",
                title="Link Performance is Healthy",
                detail=(
                    f"Achieving {achieved_pct:.0f}% of link capacity ({result.throughput_mbps:.0f} Mbps "
                    f"on {self.link_speed_gbps}G). No significant bottlenecks detected."
                ),
                recommendation="No immediate action needed. Performance is within expected range.",
            ))

        return diagnoses

    def _diagnose_udp(self, result, max_mbps, achieved_pct):
        """Diagnose UDP-specific bottlenecks."""
        diagnoses = []

        # Packet loss
        if result.loss_percent > 5:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="network",
                confidence="high",
                severity="critical",
                title=f"High UDP Packet Loss — {result.loss_percent:.1f}%",
                detail=(
                    f"Lost {result.lost_packets} of {result.total_packets} packets. "
                    f"This indicates congestion, QoS drops, or buffer overflow in the path."
                ),
                recommendation=(
                    "Investigate:\r\n"
                    "  1. Check QoS queue drops on all devices\r\n"
                    "  2. Verify interface buffer sizes on switches\r\n"
                    "  3. Check firewall UDP session limits\r\n"
                    "  4. Reduce UDP bandwidth target to find the sustainable rate"
                ),
            ))
        elif result.loss_percent > 1:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="network",
                confidence="medium",
                severity="warning",
                title=f"Moderate UDP Packet Loss — {result.loss_percent:.1f}%",
                detail=f"Lost {result.lost_packets} of {result.total_packets} packets. Some congestion is present.",
                recommendation="Monitor during peak hours. Check QoS policies and interface utilization.",
            ))

        # Jitter
        if result.jitter_ms > 10:
            diagnoses.append(BottleneckDiagnosis(
                bottleneck_location="network",
                confidence="medium",
                severity="warning",
                title=f"High Jitter — {result.jitter_ms:.1f}ms",
                detail="Jitter above 10ms indicates inconsistent queueing or congestion in the path.",
                recommendation=(
                    "Check:\r\n"
                    "  1. QoS queue configuration — ensure traffic is in the correct queue\r\n"
                    "  2. Interface utilization on transit links\r\n"
                    "  3. Firewall processing latency"
                ),
            ))

        return diagnoses

    def _build_verdict(self, result, report):
        """Build a human-readable overall verdict."""
        max_mbps = self.link_speed_gbps * 1000
        pct = report.efficiency_percent
        lines = []

        lines.append(f"Bandwidth Test: {report.source} -> {report.target}")
        lines.append(f"Link: {self.link_speed_gbps} Gbps | Measured: {result.throughput_mbps:.1f} Mbps ({pct:.1f}% efficiency)")
        lines.append(f"Protocol: {result.protocol.upper()} | Streams: {result.parallel_streams} | Duration: {result.duration_sec:.0f}s")

        if result.protocol == "tcp":
            lines.append(f"Retransmissions: {result.retransmits}")
            if result.mean_rtt_us > 0:
                lines.append(f"RTT: {result.mean_rtt_us / 1000:.1f}ms avg ({result.min_rtt_us / 1000:.1f}ms min / {result.max_rtt_us / 1000:.1f}ms max)")
            if result.max_snd_cwnd > 0:
                lines.append(f"Max TCP Window (cwnd): {result.max_snd_cwnd / 1024:.0f} KB")
        else:
            lines.append(f"Jitter: {result.jitter_ms:.3f}ms | Loss: {result.loss_percent:.1f}%")

        if result.host_cpu_total > 0:
            lines.append(f"CPU: Local {result.host_cpu_total:.0f}% | Remote {result.remote_cpu_total:.0f}%")

        lines.append("")
        critical = [d for d in report.diagnoses if d.severity == "critical"]
        warnings = [d for d in report.diagnoses if d.severity == "warning"]

        if critical:
            lines.append(f"BOTTLENECKS FOUND: {len(critical)} critical, {len(warnings)} warnings")
            for d in critical:
                lines.append(f"  [CRITICAL] {d.title}")
        elif warnings:
            lines.append(f"ISSUES FOUND: {len(warnings)} warnings")
            for d in warnings:
                lines.append(f"  [WARNING] {d.title}")
        else:
            lines.append("No significant bottlenecks detected.")

        return "\n".join(lines)
