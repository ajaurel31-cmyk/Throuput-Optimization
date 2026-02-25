"""
Network Diagnostics Engine

Provides live network diagnostic tests to complement the static config analysis:
  1. Ping (ICMP reachability + latency)
  2. Traceroute (hop-by-hop path discovery)
  3. TCP port connectivity (open/filtered/closed)
  4. DNS resolution
  5. Bandwidth-Delay Product calculation
  6. MTU path discovery (iterative probe)
  7. Full diagnostic suite (runs all tests and produces a report)
"""

import socket
import struct
import subprocess
import re
import time
import platform
from dataclasses import dataclass, field


@dataclass
class DiagnosticResult:
    """Single diagnostic test result."""
    test_name: str
    status: str  # pass, fail, warning, error
    summary: str
    details: dict = field(default_factory=dict)
    duration_ms: float = 0
    recommendations: list = field(default_factory=list)

    def to_dict(self):
        return {
            "test_name": self.test_name,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
            "duration_ms": round(self.duration_ms, 2),
            "recommendations": self.recommendations,
        }


@dataclass
class DiagnosticReport:
    """Full diagnostic report combining all test results."""
    target: str
    results: list = field(default_factory=list)
    overall_health: str = "unknown"
    health_score: int = 0
    summary: str = ""
    timestamp: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "results": [r.to_dict() for r in self.results],
            "overall_health": self.overall_health,
            "health_score": self.health_score,
            "summary": self.summary,
            "timestamp": self.timestamp,
        }


class NetworkDiagnostics:
    """
    Runs network diagnostic tests against a target host.
    Designed to complement config-based analysis with live probing.
    """

    def __init__(self, target, link_speed_gbps=10, timeout=5):
        self.target = target
        self.link_speed_gbps = link_speed_gbps
        self.timeout = timeout
        self.is_linux = platform.system().lower() != "windows"

    def run_all(self):
        """Run the full diagnostic suite and return a report."""
        report = DiagnosticReport(
            target=self.target,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )

        # Run each test, catching failures so one bad test doesn't stop the rest
        tests = [
            ("DNS Resolution", self.test_dns),
            ("ICMP Ping", self.test_ping),
            ("Traceroute", self.test_traceroute),
            ("MTU Path Discovery", self.test_mtu_path),
            ("TCP Port Scan", self.test_tcp_ports),
            ("Bandwidth-Delay Product", self.test_bdp),
        ]

        for name, test_fn in tests:
            try:
                result = test_fn()
                report.results.append(result)
            except Exception as e:
                report.results.append(DiagnosticResult(
                    test_name=name,
                    status="error",
                    summary=f"Test failed with error: {str(e)}",
                    details={"error": str(e)},
                ))

        # Calculate health score
        self._calculate_health(report)
        return report

    # ------------------------------------------------------------------
    # Individual tests
    # ------------------------------------------------------------------

    def test_dns(self):
        """Resolve the target hostname and measure resolution time."""
        start = time.time()
        try:
            results = socket.getaddrinfo(self.target, None, socket.AF_UNSPEC)
            elapsed = (time.time() - start) * 1000

            addresses = list(set(
                (r[0], r[4][0]) for r in results
            ))
            ipv4 = [addr for fam, addr in addresses if fam == socket.AF_INET]
            ipv6 = [addr for fam, addr in addresses if fam == socket.AF_INET6]

            status = "pass"
            recs = []
            if elapsed > 500:
                status = "warning"
                recs.append("DNS resolution is slow (>500ms). Check DNS server performance and consider using a local caching resolver.")

            return DiagnosticResult(
                test_name="DNS Resolution",
                status=status,
                summary=f"Resolved to {len(ipv4)} IPv4 and {len(ipv6)} IPv6 address(es) in {elapsed:.0f}ms",
                details={
                    "hostname": self.target,
                    "ipv4_addresses": ipv4,
                    "ipv6_addresses": ipv6,
                    "resolution_time_ms": round(elapsed, 2),
                },
                duration_ms=elapsed,
                recommendations=recs,
            )
        except socket.gaierror as e:
            elapsed = (time.time() - start) * 1000
            return DiagnosticResult(
                test_name="DNS Resolution",
                status="fail",
                summary=f"DNS resolution failed: {e}",
                details={"hostname": self.target, "error": str(e)},
                duration_ms=elapsed,
                recommendations=[
                    "Verify the hostname is correct.",
                    "Check DNS server configuration (resolv.conf or system DNS settings).",
                    "Try using an IP address directly to bypass DNS.",
                ],
            )

    def test_ping(self, count=5):
        """Ping the target and collect latency statistics."""
        start = time.time()
        try:
            if self.is_linux:
                cmd = ["ping", "-c", str(count), "-W", str(self.timeout), self.target]
            else:
                cmd = ["ping", "-n", str(count), "-w", str(self.timeout * 1000), self.target]

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout * count + 10
            )
            elapsed = (time.time() - start) * 1000
            output = proc.stdout + proc.stderr

            # Parse results
            parsed = self._parse_ping_output(output)
            parsed["raw_output"] = output.strip()

            if parsed.get("packet_loss", 100) == 100:
                status = "fail"
                summary = f"All {count} ping packets lost — host unreachable"
                recs = [
                    "Host may be down or ICMP is blocked by a firewall.",
                    "Check firewall rules for ICMP echo-request/echo-reply.",
                    "Verify routing with traceroute to see where packets are dropped.",
                ]
            elif parsed.get("packet_loss", 0) > 0:
                status = "warning"
                summary = f"Packet loss detected: {parsed['packet_loss']}% ({parsed.get('received', '?')}/{parsed.get('transmitted', '?')} received)"
                recs = [
                    f"Packet loss of {parsed['packet_loss']}% will degrade TCP throughput significantly.",
                    "Check interface error counters on all devices in the path.",
                    "Look for CRC errors, input errors, and output drops.",
                ]
            else:
                avg_rtt = parsed.get("avg_rtt", 0)
                status = "pass"
                if avg_rtt > 100:
                    status = "warning"
                summary = f"Ping successful: {parsed.get('avg_rtt', '?')}ms avg, {parsed.get('min_rtt', '?')}ms min, {parsed.get('max_rtt', '?')}ms max, 0% loss"
                recs = []
                if avg_rtt > 100:
                    recs.append(f"RTT of {avg_rtt}ms is high for a WAN link. This limits single-stream TCP throughput via the bandwidth-delay product.")
                if parsed.get("jitter", 0) > 10:
                    recs.append(f"High jitter ({parsed['jitter']}ms) detected. This can cause TCP retransmissions and throughput variability.")

            return DiagnosticResult(
                test_name="ICMP Ping",
                status=status,
                summary=summary,
                details=parsed,
                duration_ms=elapsed,
                recommendations=recs,
            )
        except subprocess.TimeoutExpired:
            elapsed = (time.time() - start) * 1000
            return DiagnosticResult(
                test_name="ICMP Ping",
                status="fail",
                summary="Ping timed out — no response received",
                details={"target": self.target, "timeout": self.timeout},
                duration_ms=elapsed,
                recommendations=[
                    "Host may be down or ICMP is blocked.",
                    "Try increasing the timeout or check firewall rules.",
                ],
            )
        except FileNotFoundError:
            return DiagnosticResult(
                test_name="ICMP Ping",
                status="error",
                summary="ping command not found on this system",
                details={"error": "ping binary not available"},
            )

    def test_traceroute(self, max_hops=20):
        """Run traceroute to discover the network path."""
        start = time.time()
        try:
            if self.is_linux:
                cmd = ["traceroute", "-m", str(max_hops), "-w", str(self.timeout), "-n", self.target]
            else:
                cmd = ["tracert", "-h", str(max_hops), "-w", str(self.timeout * 1000), "-d", self.target]

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=max_hops * self.timeout + 15
            )
            elapsed = (time.time() - start) * 1000
            output = proc.stdout + proc.stderr

            hops = self._parse_traceroute_output(output)
            hop_count = len([h for h in hops if h.get("ip") != "*"])
            timeout_hops = len([h for h in hops if h.get("ip") == "*"])

            status = "pass"
            recs = []

            if hop_count == 0:
                status = "fail"
                summary = "Traceroute failed — no hops responded"
                recs.append("All hops timed out. ICMP/UDP may be completely blocked.")
            elif timeout_hops > hop_count * 0.5:
                status = "warning"
                summary = f"Traceroute completed: {hop_count} hops responded, {timeout_hops} timed out"
                recs.append("Many hops are not responding. Some routers block traceroute probes (this is often normal).")
            else:
                summary = f"Path has {hop_count} hops to target"

            # Check for latency spikes between hops
            prev_rtt = 0
            for h in hops:
                if h.get("avg_rtt") and h["avg_rtt"] > 0:
                    if prev_rtt > 0 and (h["avg_rtt"] - prev_rtt) > 50:
                        recs.append(f"Hop {h['hop']}: latency jump of {h['avg_rtt'] - prev_rtt:.0f}ms (possible WAN segment or congested link)")
                    prev_rtt = h["avg_rtt"]

            return DiagnosticResult(
                test_name="Traceroute",
                status=status,
                summary=summary,
                details={
                    "hops": hops,
                    "hop_count": hop_count,
                    "timeout_hops": timeout_hops,
                    "raw_output": output.strip(),
                },
                duration_ms=elapsed,
                recommendations=recs,
            )
        except subprocess.TimeoutExpired:
            elapsed = (time.time() - start) * 1000
            return DiagnosticResult(
                test_name="Traceroute",
                status="warning",
                summary="Traceroute timed out before completing",
                details={"target": self.target},
                duration_ms=elapsed,
                recommendations=["Target may be too many hops away or probes are being filtered."],
            )
        except FileNotFoundError:
            return DiagnosticResult(
                test_name="Traceroute",
                status="error",
                summary="traceroute command not found on this system",
                details={"error": "traceroute/tracert binary not available"},
                recommendations=["Install traceroute: apt install traceroute (Linux) or use Windows tracert."],
            )

    def test_tcp_ports(self, ports=None):
        """Test TCP connectivity to common network service ports."""
        if ports is None:
            ports = [22, 80, 443, 179, 161, 8080, 8443]

        start = time.time()
        port_results = []
        open_ports = 0
        closed_ports = 0
        filtered_ports = 0

        for port in ports:
            port_start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result_code = sock.connect_ex((self._resolve_target(), port))
                port_elapsed = (time.time() - port_start) * 1000
                sock.close()

                if result_code == 0:
                    port_results.append({
                        "port": port,
                        "state": "open",
                        "service": self._port_service_name(port),
                        "response_ms": round(port_elapsed, 1),
                    })
                    open_ports += 1
                else:
                    port_results.append({
                        "port": port,
                        "state": "closed",
                        "service": self._port_service_name(port),
                        "response_ms": round(port_elapsed, 1),
                    })
                    closed_ports += 1
            except socket.timeout:
                port_elapsed = (time.time() - port_start) * 1000
                port_results.append({
                    "port": port,
                    "state": "filtered",
                    "service": self._port_service_name(port),
                    "response_ms": round(port_elapsed, 1),
                })
                filtered_ports += 1
            except OSError as e:
                port_elapsed = (time.time() - port_start) * 1000
                port_results.append({
                    "port": port,
                    "state": "error",
                    "service": self._port_service_name(port),
                    "error": str(e),
                    "response_ms": round(port_elapsed, 1),
                })

        elapsed = (time.time() - start) * 1000
        recs = []

        if filtered_ports > len(ports) * 0.5:
            status = "warning"
            recs.append("Most ports are filtered — a firewall is blocking probes. This is expected for well-secured networks.")
        elif open_ports > 0:
            status = "pass"
        else:
            status = "warning"
            recs.append("No open TCP ports found. Verify the target is running expected services.")

        return DiagnosticResult(
            test_name="TCP Port Scan",
            status=status,
            summary=f"{open_ports} open, {closed_ports} closed, {filtered_ports} filtered (of {len(ports)} tested)",
            details={
                "ports": port_results,
                "open": open_ports,
                "closed": closed_ports,
                "filtered": filtered_ports,
            },
            duration_ms=elapsed,
            recommendations=recs,
        )

    def test_mtu_path(self):
        """
        Discover the path MTU by sending ICMP packets of decreasing size
        with the Don't Fragment (DF) bit set.
        """
        start = time.time()
        # Test from large to small
        test_sizes = [8972, 4472, 1972, 1472, 1400, 1200, 1000, 576]
        results = []
        path_mtu = 0

        for size in test_sizes:
            try:
                if self.is_linux:
                    cmd = ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(size), self.target]
                else:
                    cmd = ["ping", "-n", "1", "-w", "2000", "-f", "-l", str(size), self.target]

                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5
                )
                success = proc.returncode == 0

                results.append({"size": size, "mtu": size + 28, "success": success})
                if success and size + 28 > path_mtu:
                    path_mtu = size + 28
                    break  # Found the max that works
            except (subprocess.TimeoutExpired, FileNotFoundError):
                results.append({"size": size, "mtu": size + 28, "success": False})

        elapsed = (time.time() - start) * 1000
        recs = []

        if path_mtu == 0:
            # Try to get at least something
            for r in results:
                if r["success"]:
                    path_mtu = r["mtu"]
                    break

        if path_mtu == 0:
            status = "fail"
            summary = "Could not determine path MTU — all probe sizes failed"
            recs.append("ICMP may be blocked or the host is unreachable.")
            recs.append("Check firewall rules for ICMP type 3 code 4 (need to fragment).")
        elif path_mtu >= 9000:
            status = "pass"
            summary = f"Path MTU: {path_mtu} bytes (jumbo frames supported end-to-end)"
        elif path_mtu >= 1500:
            status = "pass"
            summary = f"Path MTU: {path_mtu} bytes (standard MTU)"
            if self.link_speed_gbps >= 10:
                recs.append("Consider enabling jumbo frames (MTU 9216) end-to-end for better throughput on high-speed links.")
        else:
            status = "warning"
            summary = f"Path MTU: {path_mtu} bytes (below standard 1500)"
            recs.append(f"Path MTU of {path_mtu} is below standard 1500. Check for MTU mismatches or tunnel overhead (GRE/IPsec adds 24-58 bytes).")

        return DiagnosticResult(
            test_name="MTU Path Discovery",
            status=status,
            summary=summary,
            details={
                "path_mtu": path_mtu,
                "probes": results,
            },
            duration_ms=elapsed,
            recommendations=recs,
        )

    def test_bdp(self):
        """
        Calculate the Bandwidth-Delay Product and recommend TCP buffer sizes.
        Uses the ping RTT and configured link speed.
        """
        start = time.time()
        # Get RTT via a quick ping
        try:
            if self.is_linux:
                cmd = ["ping", "-c", "3", "-W", str(self.timeout), self.target]
            else:
                cmd = ["ping", "-n", "3", "-w", str(self.timeout * 1000), self.target]

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout * 5
            )
            parsed = self._parse_ping_output(proc.stdout + proc.stderr)
            rtt_ms = parsed.get("avg_rtt", 0)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            rtt_ms = 0

        elapsed = (time.time() - start) * 1000

        if rtt_ms <= 0:
            return DiagnosticResult(
                test_name="Bandwidth-Delay Product",
                status="error",
                summary="Could not measure RTT — unable to calculate BDP",
                details={"rtt_ms": 0},
                duration_ms=elapsed,
                recommendations=["Run a successful ping test first to measure RTT."],
            )

        # BDP = bandwidth (bits/sec) * RTT (seconds)
        bandwidth_bps = self.link_speed_gbps * 1_000_000_000
        rtt_sec = rtt_ms / 1000
        bdp_bits = bandwidth_bps * rtt_sec
        bdp_bytes = bdp_bits / 8
        bdp_kb = bdp_bytes / 1024
        bdp_mb = bdp_bytes / (1024 * 1024)

        # Recommended TCP buffer = 2x BDP for good utilization
        recommended_buffer = int(bdp_bytes * 2)

        # Single-stream max throughput = TCP_window / RTT
        default_window = 65535  # Default TCP window without scaling
        max_single_stream_mbps = (default_window * 8) / (rtt_sec * 1_000_000) if rtt_sec > 0 else 0
        with_scaling_mbps = (recommended_buffer * 8) / (rtt_sec * 1_000_000) if rtt_sec > 0 else 0

        recs = []
        status = "pass"

        if bdp_mb > 1:
            recs.append(
                f"BDP is {bdp_mb:.1f} MB. TCP window scaling (RFC 1323) is REQUIRED "
                f"to fill the pipe."
            )
            recs.append(
                f"Without window scaling, max single-stream throughput is only "
                f"{max_single_stream_mbps:.0f} Mbps ({max_single_stream_mbps/1000:.2f} Gbps)."
            )
            status = "warning"

        recs.append(
            f"Recommended TCP buffer sizes:\n"
            f"  Linux:   sysctl -w net.core.rmem_max={recommended_buffer}\n"
            f"           sysctl -w net.core.wmem_max={recommended_buffer}\n"
            f"           sysctl -w net.ipv4.tcp_rmem='4096 87380 {recommended_buffer}'\n"
            f"           sysctl -w net.ipv4.tcp_wmem='4096 65536 {recommended_buffer}'"
        )

        if self.link_speed_gbps >= 10 and rtt_ms > 5:
            recs.append(
                "For high-bandwidth, high-latency paths, consider using multiple "
                "parallel TCP streams (e.g., iperf3 -P 4) or a WAN acceleration tool."
            )

        return DiagnosticResult(
            test_name="Bandwidth-Delay Product",
            status=status,
            summary=f"BDP: {bdp_mb:.1f} MB (RTT: {rtt_ms:.1f}ms, Link: {self.link_speed_gbps} Gbps)",
            details={
                "rtt_ms": round(rtt_ms, 2),
                "link_speed_gbps": self.link_speed_gbps,
                "bdp_bytes": round(bdp_bytes),
                "bdp_mb": round(bdp_mb, 2),
                "recommended_tcp_buffer": recommended_buffer,
                "max_single_stream_default_mbps": round(max_single_stream_mbps, 1),
                "max_single_stream_tuned_mbps": round(with_scaling_mbps, 1),
            },
            duration_ms=elapsed,
            recommendations=recs,
        )

    # ------------------------------------------------------------------
    # Path Analysis (MTR-style per-hop loss & latency)
    # ------------------------------------------------------------------

    def test_path_analysis(self, rounds=10, max_hops=20, source_ip=None):
        """
        MTR-style path analysis: discover hops via traceroute, then send
        multiple pings to EACH hop to measure per-hop packet loss, latency
        variation, and identify exactly where drops or throttling occur.

        Args:
            rounds:    Number of probes per hop (more = better accuracy)
            max_hops:  Maximum TTL for path discovery
            source_ip: Optional source IP / interface to bind to (e.g. 10.2.25.55)
        """
        start = time.time()

        # -- Step 1: Try mtr first (best tool for this), fall back to manual --
        mtr_result = self._try_mtr(rounds, max_hops, source_ip)
        if mtr_result is not None:
            mtr_result.duration_ms = (time.time() - start) * 1000
            return mtr_result

        # -- Step 2: Manual approach — traceroute then per-hop ping --
        # 2a. Discover the path
        hops = self._discover_hops(max_hops, source_ip)
        if not hops:
            elapsed = (time.time() - start) * 1000
            return DiagnosticResult(
                test_name="Path Analysis",
                status="fail",
                summary="Could not discover any hops to target",
                details={"target": self.target, "source_ip": source_ip},
                duration_ms=elapsed,
                recommendations=[
                    "All traceroute probes timed out. ICMP/UDP may be blocked.",
                    "Try running from a different source interface or without source binding.",
                ],
            )

        # 2b. Probe each discovered hop
        hop_results = []
        for hop in hops:
            hop_ip = hop["ip"]
            if hop_ip == "*":
                hop_results.append({
                    "hop": hop["hop"],
                    "ip": "*",
                    "hostname": "*",
                    "loss_percent": 100.0,
                    "sent": rounds,
                    "received": 0,
                    "avg_rtt": 0,
                    "min_rtt": 0,
                    "max_rtt": 0,
                    "jitter": 0,
                    "stdev": 0,
                    "rtts": [],
                    "status": "timeout",
                })
                continue

            probe = self._probe_hop(hop_ip, count=rounds, source_ip=source_ip)
            probe["hop"] = hop["hop"]
            hop_results.append(probe)

        # -- Step 3: Analyze results --
        analysis = self._analyze_path(hop_results)
        elapsed = (time.time() - start) * 1000

        return DiagnosticResult(
            test_name="Path Analysis",
            status=analysis["status"],
            summary=analysis["summary"],
            details={
                "target": self.target,
                "source_ip": source_ip,
                "rounds": rounds,
                "max_hops": max_hops,
                "total_hops": len(hop_results),
                "responding_hops": len([h for h in hop_results if h["ip"] != "*"]),
                "hops": hop_results,
                "problem_hops": analysis["problem_hops"],
                "worst_hop": analysis.get("worst_hop"),
                "path_health": analysis["path_health"],
            },
            duration_ms=elapsed,
            recommendations=analysis["recommendations"],
        )

    def _try_mtr(self, rounds, max_hops, source_ip):
        """Try to use mtr for path analysis (preferred tool)."""
        try:
            cmd = [
                "mtr", "--report", "--report-cycles", str(rounds),
                "--max-ttl", str(max_hops), "--no-dns", "--json",
                self.target,
            ]
            if source_ip:
                cmd.extend(["--address", source_ip])

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=rounds * max_hops + 30,
            )

            if proc.returncode != 0:
                return None

            import json as _json
            data = _json.loads(proc.stdout)
            report = data.get("report", {})
            mtr_hops = report.get("hubs", [])

            if not mtr_hops:
                return None

            hop_results = []
            for h in mtr_hops:
                hop_results.append({
                    "hop": h.get("count", 0),
                    "ip": h.get("host", "*"),
                    "hostname": h.get("host", "*"),
                    "loss_percent": h.get("Loss%", 100.0),
                    "sent": rounds,
                    "received": round(rounds * (1 - h.get("Loss%", 100) / 100)),
                    "avg_rtt": h.get("Avg", 0),
                    "min_rtt": h.get("Best", 0),
                    "max_rtt": h.get("Wrst", 0),
                    "jitter": h.get("Wrst", 0) - h.get("Best", 0),
                    "stdev": h.get("StDev", 0),
                    "rtts": [],
                    "status": "ok" if h.get("Loss%", 100) == 0 else
                              "loss" if h.get("Loss%", 100) < 100 else "timeout",
                })

            analysis = self._analyze_path(hop_results)

            return DiagnosticResult(
                test_name="Path Analysis",
                status=analysis["status"],
                summary=analysis["summary"],
                details={
                    "target": self.target,
                    "source_ip": source_ip,
                    "tool": "mtr",
                    "rounds": rounds,
                    "max_hops": max_hops,
                    "total_hops": len(hop_results),
                    "responding_hops": len([h for h in hop_results if h["ip"] != "*"]),
                    "hops": hop_results,
                    "problem_hops": analysis["problem_hops"],
                    "worst_hop": analysis.get("worst_hop"),
                    "path_health": analysis["path_health"],
                },
                recommendations=analysis["recommendations"],
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return None

    def _discover_hops(self, max_hops, source_ip):
        """Run traceroute to discover path hops."""
        try:
            if self.is_linux:
                cmd = ["traceroute", "-m", str(max_hops), "-w", "2", "-n",
                       "-q", "1", self.target]
                if source_ip:
                    cmd.extend(["-s", source_ip])
            else:
                cmd = ["tracert", "-h", str(max_hops), "-w", "2000", "-d",
                       self.target]

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=max_hops * 3 + 15,
            )
            return self._parse_traceroute_output(proc.stdout + proc.stderr)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _probe_hop(self, hop_ip, count=10, source_ip=None):
        """Send multiple pings to a single hop and collect statistics."""
        try:
            if self.is_linux:
                cmd = ["ping", "-c", str(count), "-W", "2", "-i", "0.3", hop_ip]
                if source_ip:
                    cmd.extend(["-I", source_ip])
            else:
                cmd = ["ping", "-n", str(count), "-w", str(count * 1000), hop_ip]

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=count * 3 + 10,
            )
            output = proc.stdout + proc.stderr
            parsed = self._parse_ping_output(output)

            # Extract individual RTTs from ping output for detailed analysis
            rtts = [float(m) for m in re.findall(
                r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE
            )]

            loss = parsed.get("packet_loss", 100.0)
            avg_rtt = parsed.get("avg_rtt", 0)
            min_rtt = parsed.get("min_rtt", 0)
            max_rtt = parsed.get("max_rtt", 0)
            jitter = parsed.get("jitter", 0)

            # Compute stdev from individual RTTs
            stdev = 0
            if len(rtts) > 1:
                mean = sum(rtts) / len(rtts)
                stdev = (sum((x - mean) ** 2 for x in rtts) / len(rtts)) ** 0.5

            if loss == 100:
                status = "timeout"
            elif loss > 0:
                status = "loss"
            elif avg_rtt > 150:
                status = "high_latency"
            else:
                status = "ok"

            return {
                "ip": hop_ip,
                "hostname": self._reverse_dns(hop_ip),
                "loss_percent": loss,
                "sent": parsed.get("transmitted", count),
                "received": parsed.get("received", 0),
                "avg_rtt": round(avg_rtt, 2),
                "min_rtt": round(min_rtt, 2),
                "max_rtt": round(max_rtt, 2),
                "jitter": round(jitter, 2),
                "stdev": round(stdev, 2),
                "rtts": [round(r, 2) for r in rtts],
                "status": status,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {
                "ip": hop_ip,
                "hostname": hop_ip,
                "loss_percent": 100.0,
                "sent": count,
                "received": 0,
                "avg_rtt": 0,
                "min_rtt": 0,
                "max_rtt": 0,
                "jitter": 0,
                "stdev": 0,
                "rtts": [],
                "status": "timeout",
            }

    def _reverse_dns(self, ip):
        """Attempt reverse DNS lookup, return IP on failure."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ip

    def _analyze_path(self, hop_results):
        """Analyze per-hop results to identify problem points."""
        problem_hops = []
        recs = []
        worst_hop = None
        worst_loss = 0
        prev_rtt = 0
        status = "pass"

        responding = [h for h in hop_results if h["ip"] != "*"]

        if not responding:
            return {
                "status": "fail",
                "summary": "No hops responded to probes",
                "problem_hops": [],
                "worst_hop": None,
                "path_health": "critical",
                "recommendations": [
                    "All hops timed out. ICMP may be completely blocked.",
                    "Check firewall rules along the entire path.",
                ],
            }

        for h in hop_results:
            if h["ip"] == "*":
                continue

            issues = []

            # Check for packet loss at this hop
            if h["loss_percent"] > 0 and h["loss_percent"] < 100:
                issues.append(f"{h['loss_percent']}% packet loss")
                if h["loss_percent"] > worst_loss:
                    worst_loss = h["loss_percent"]
                    worst_hop = h

            # Check for latency spike from previous hop
            if prev_rtt > 0 and h["avg_rtt"] > 0:
                delta = h["avg_rtt"] - prev_rtt
                h["latency_delta"] = round(delta, 2)
                if delta > 50:
                    issues.append(f"+{delta:.0f}ms latency jump (WAN segment or congestion)")
                elif delta > 20:
                    issues.append(f"+{delta:.0f}ms latency increase")
            else:
                h["latency_delta"] = round(h["avg_rtt"], 2) if h["avg_rtt"] > 0 else 0

            # Check for high jitter
            if h["jitter"] > 20:
                issues.append(f"High jitter: {h['jitter']}ms")

            # Check for high absolute latency
            if h["avg_rtt"] > 200:
                issues.append(f"High latency: {h['avg_rtt']}ms")

            if issues:
                problem_hops.append({
                    "hop": h["hop"],
                    "ip": h["ip"],
                    "issues": issues,
                })

            if h["avg_rtt"] > 0:
                prev_rtt = h["avg_rtt"]

        # Determine overall status and health
        # Check the final hop (target) specifically
        target_hop = None
        for h in reversed(hop_results):
            if h["ip"] != "*":
                target_hop = h
                break

        target_loss = target_hop["loss_percent"] if target_hop else 100

        if target_loss == 100:
            status = "fail"
            path_health = "critical"
            # Find where packets start dropping
            last_ok = None
            for h in hop_results:
                if h["ip"] != "*" and h["loss_percent"] < 100:
                    last_ok = h
            if last_ok:
                recs.append(
                    f"Packets reach hop {last_ok['hop']} ({last_ok['ip']}) "
                    f"but are lost after that. The drop point is between "
                    f"hop {last_ok['hop']} and the target."
                )
                recs.append(
                    "Check routing, firewall rules, and ICMP filtering "
                    "between these hops."
                )
            else:
                recs.append("No hops responded. Check local routing and firewall.")
        elif target_loss > 20:
            status = "fail"
            path_health = "critical"
        elif target_loss > 5:
            status = "warning"
            path_health = "impaired"
        elif target_loss > 0:
            status = "warning"
            path_health = "degraded"
        elif worst_loss > 0:
            # Intermediate hop loss can be ICMP rate limiting (normal)
            status = "warning"
            path_health = "degraded"
            recs.append(
                "Some intermediate hops show packet loss. This is often "
                "caused by ICMP rate-limiting on transit routers (not a real "
                "problem). If the target itself has 0% loss, the path is healthy."
            )
        else:
            path_health = "healthy"

        # Build summary
        total = len(hop_results)
        resp = len(responding)
        if target_loss == 100:
            summary = (
                f"Path has {total} hops ({resp} responding). "
                f"Target is UNREACHABLE — 100% loss at destination."
            )
        elif worst_loss > 0:
            summary = (
                f"Path has {total} hops ({resp} responding). "
                f"Worst loss: {worst_loss}% at hop "
                f"{worst_hop['hop']} ({worst_hop['ip']}). "
                f"Target loss: {target_loss}%."
            )
        else:
            summary = (
                f"Path has {total} hops ({resp} responding). "
                f"No packet loss detected. Path is clean."
            )

        # Add specific recommendations for problem hops
        for ph in problem_hops:
            for issue in ph["issues"]:
                if "packet loss" in issue and ph["ip"] != "*":
                    recs.append(
                        f"Hop {ph['hop']} ({ph['ip']}): {issue}. "
                        f"Check interface error counters and QoS policies on this device."
                    )
                elif "latency jump" in issue:
                    recs.append(
                        f"Hop {ph['hop']} ({ph['ip']}): {issue}. "
                        f"This likely indicates a WAN segment or congested link."
                    )

        if not recs and status == "pass":
            recs.append("Path looks healthy. No packet loss or significant latency issues detected.")

        return {
            "status": status,
            "summary": summary,
            "problem_hops": problem_hops,
            "worst_hop": {
                "hop": worst_hop["hop"],
                "ip": worst_hop["ip"],
                "loss_percent": worst_hop["loss_percent"],
            } if worst_hop else None,
            "path_health": path_health,
            "recommendations": recs,
        }

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_ping_output(self, output):
        """Parse ping output for statistics."""
        result = {}

        # Match packet loss (Linux: "5 packets transmitted, 5 received, 0% packet loss")
        loss_match = re.search(
            r"(\d+)\s+(?:packets?\s+)?transmitted,?\s+(\d+)\s+(?:packets?\s+)?received.*?(\d+(?:\.\d+)?)%\s+(?:packet\s+)?loss",
            output, re.IGNORECASE,
        )
        if loss_match:
            result["transmitted"] = int(loss_match.group(1))
            result["received"] = int(loss_match.group(2))
            result["packet_loss"] = float(loss_match.group(3))

        # Match RTT stats (Linux: "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms")
        rtt_match = re.search(
            r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
            output, re.IGNORECASE,
        )
        if rtt_match:
            result["min_rtt"] = float(rtt_match.group(1))
            result["avg_rtt"] = float(rtt_match.group(2))
            result["max_rtt"] = float(rtt_match.group(3))
            result["jitter"] = float(rtt_match.group(4))

        # Windows format: "Minimum = 1ms, Maximum = 3ms, Average = 2ms"
        win_match = re.search(
            r"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms",
            output, re.IGNORECASE,
        )
        if win_match and "avg_rtt" not in result:
            result["min_rtt"] = float(win_match.group(1))
            result["max_rtt"] = float(win_match.group(2))
            result["avg_rtt"] = float(win_match.group(3))
            result["jitter"] = result["max_rtt"] - result["min_rtt"]

        return result

    def _parse_traceroute_output(self, output):
        """Parse traceroute output into a list of hops."""
        hops = []
        for line in output.strip().split("\n"):
            line = line.strip()
            # Match hop lines like "1  192.168.1.1  1.234 ms  1.345 ms  1.456 ms"
            hop_match = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2)

            # Check for timeout
            if rest.strip() == "* * *":
                hops.append({"hop": hop_num, "ip": "*", "rtts": [], "avg_rtt": 0})
                continue

            # Extract IPs and RTTs
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            rtt_matches = re.findall(r"([\d.]+)\s*ms", rest)

            ip = ip_match.group(1) if ip_match else "*"
            rtts = [float(r) for r in rtt_matches]
            avg_rtt = sum(rtts) / len(rtts) if rtts else 0

            hops.append({
                "hop": hop_num,
                "ip": ip,
                "rtts": rtts,
                "avg_rtt": round(avg_rtt, 2),
            })

        return hops

    def _resolve_target(self):
        """Resolve hostname to IP for socket operations."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return self.target

    def _port_service_name(self, port):
        """Return common service name for a port number."""
        services = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            161: "SNMP",
            179: "BGP",
            443: "HTTPS",
            830: "NETCONF",
            3389: "RDP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }
        return services.get(port, f"port-{port}")

    def _calculate_health(self, report):
        """Calculate overall health score from test results."""
        if not report.results:
            report.overall_health = "unknown"
            report.health_score = 0
            report.summary = "No diagnostic tests were run."
            return

        total_tests = len(report.results)
        passed = len([r for r in report.results if r.status == "pass"])
        warnings = len([r for r in report.results if r.status == "warning"])
        failed = len([r for r in report.results if r.status == "fail"])
        errors = len([r for r in report.results if r.status == "error"])

        # Score: pass=100, warning=60, error/fail=0
        score = int(
            ((passed * 100) + (warnings * 60)) / total_tests
        ) if total_tests > 0 else 0

        report.health_score = score

        if score >= 80:
            report.overall_health = "healthy"
        elif score >= 60:
            report.overall_health = "degraded"
        elif score >= 30:
            report.overall_health = "impaired"
        else:
            report.overall_health = "critical"

        lines = [
            f"Diagnostic target: {report.target}",
            f"Tests run: {total_tests} | Passed: {passed} | Warnings: {warnings} | Failed: {failed} | Errors: {errors}",
            f"Health score: {score}/100 ({report.overall_health.upper()})",
        ]

        # Collect all recommendations
        all_recs = []
        for r in report.results:
            if r.status in ("fail", "warning") and r.recommendations:
                all_recs.extend(r.recommendations)

        if all_recs:
            lines.append("")
            lines.append("Key recommendations:")
            for rec in all_recs[:5]:
                lines.append(f"  - {rec.split(chr(10))[0]}")

        report.summary = "\n".join(lines)
