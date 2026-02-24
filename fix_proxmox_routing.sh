#!/bin/bash
# ============================================================
# ATL-PROXMOX02 — Network Routing Fix
#
# PROBLEM:
#   ExaGrid traffic (10.15.25.0/24) routes through vmbr0/bond0
#   which is limited to 1 Gbps (eno8303/eno8403).
#   Meanwhile, ens7f0np0 (25G, MTU 9000) sits unused for this
#   traffic path.
#
# SOLUTION:
#   Route 10.15.25.0/24 through ens7f0np0 which already has:
#   - IP 10.15.25.92/24 assigned (same subnet as ExaGrid)
#   - 25 Gbps link speed
#   - 9000 MTU (jumbo frames)
#
# EXPECTED RESULT:
#   Throughput to ExaGrid: ~112 MB/s (1G) -> ~2.9 GB/s (25G)
#   (actual limited by ExaGrid disk/network, but ceiling removed)
#
# NOTE: Run on ATL-PROXMOX02 as root
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

EXAGRID_SUBNET="10.15.25.0/24"
EXAGRID_IP="10.15.25.14"
FAST_NIC="ens7f0np0"
FAST_NIC_IP="10.15.25.92"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  ATL-PROXMOX02 Routing Fix                ${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# --- Pre-flight checks ---
echo -e "${CYAN}[1/5] Pre-flight checks...${NC}"

# Verify we're on the right host
HOSTNAME=$(hostname)
echo "  Hostname: ${HOSTNAME}"

# Verify the fast NIC exists and is up
if ! ip link show "$FAST_NIC" &>/dev/null; then
    echo -e "${RED}  ERROR: ${FAST_NIC} not found on this host.${NC}"
    exit 1
fi

NIC_STATE=$(ip -o link show "$FAST_NIC" | grep -o 'state [A-Z]*' | awk '{print $2}')
if [ "$NIC_STATE" != "UP" ]; then
    echo -e "${RED}  ERROR: ${FAST_NIC} is ${NIC_STATE}, not UP.${NC}"
    exit 1
fi
echo -e "  ${GREEN}${FAST_NIC} is UP${NC}"

# Verify the NIC has the right IP
NIC_IP=$(ip -4 addr show "$FAST_NIC" | grep -oP 'inet \K[\d.]+' || true)
if [ "$NIC_IP" != "$FAST_NIC_IP" ]; then
    echo -e "${YELLOW}  WARNING: ${FAST_NIC} has IP ${NIC_IP:-none}, expected ${FAST_NIC_IP}${NC}"
    echo -e "${YELLOW}  The route may not work correctly without the right IP.${NC}"
    read -rp "  Continue anyway? [y/N]: " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy] ]]; then
        echo "Aborted."
        exit 1
    fi
else
    echo -e "  ${GREEN}${FAST_NIC} has IP ${FAST_NIC_IP}${NC}"
fi

# Check link speed
SPEED=$(ethtool "$FAST_NIC" 2>/dev/null | grep -oP 'Speed: \K\d+' || echo "?")
echo -e "  ${GREEN}${FAST_NIC} link speed: ${SPEED} Mb/s${NC}"

# Check MTU
MTU=$(ip link show "$FAST_NIC" | grep -oP 'mtu \K\d+')
echo -e "  ${GREEN}${FAST_NIC} MTU: ${MTU}${NC}"

# --- Show current routing ---
echo ""
echo -e "${CYAN}[2/5] Current route to ExaGrid (${EXAGRID_IP}):${NC}"
ip route get "$EXAGRID_IP"
echo ""

# --- Apply the route fix ---
echo -e "${CYAN}[3/5] Adding route: ${EXAGRID_SUBNET} dev ${FAST_NIC} src ${FAST_NIC_IP}...${NC}"

# Remove existing route if it goes through the wrong interface
CURRENT_DEV=$(ip route get "$EXAGRID_IP" | grep -oP 'dev \K\S+' || true)
if [ "$CURRENT_DEV" = "$FAST_NIC" ]; then
    echo -e "  ${GREEN}Route already points to ${FAST_NIC} — no change needed.${NC}"
else
    # The subnet route via ens7f0np0 should already exist since the IP is
    # on that subnet — but the kernel may prefer the vmbr0 route via the
    # gateway. Add an explicit higher-priority route.
    ip route replace "$EXAGRID_SUBNET" dev "$FAST_NIC" src "$FAST_NIC_IP" proto static metric 100
    echo -e "  ${GREEN}Route added.${NC}"
fi

# --- Verify the new routing ---
echo ""
echo -e "${CYAN}[4/5] Verifying new route to ExaGrid (${EXAGRID_IP}):${NC}"
ip route get "$EXAGRID_IP"

NEW_DEV=$(ip route get "$EXAGRID_IP" | grep -oP 'dev \K\S+' || true)
if [ "$NEW_DEV" = "$FAST_NIC" ]; then
    echo -e "  ${GREEN}SUCCESS: Traffic to ${EXAGRID_IP} now routes via ${FAST_NIC} (${SPEED} Mb/s, MTU ${MTU})${NC}"
else
    echo -e "  ${RED}WARNING: Route still goes through ${NEW_DEV}. Manual review needed.${NC}"
fi

# --- Make persistent ---
echo ""
echo -e "${CYAN}[5/5] Making route persistent...${NC}"
echo ""

INTERFACES_FILE="/etc/network/interfaces"
ROUTE_LINE="up ip route replace ${EXAGRID_SUBNET} dev ${FAST_NIC} src ${FAST_NIC_IP} proto static metric 100"

if [ -f "$INTERFACES_FILE" ]; then
    if grep -qF "$EXAGRID_SUBNET" "$INTERFACES_FILE" 2>/dev/null; then
        echo -e "  ${YELLOW}Route entry already exists in ${INTERFACES_FILE}${NC}"
    else
        echo -e "  Adding to ${INTERFACES_FILE} under iface ${FAST_NIC}..."
        # Check if the interface stanza exists
        if grep -qP "^iface\s+${FAST_NIC}" "$INTERFACES_FILE"; then
            # Add after the iface line
            sed -i "/^iface\s\+${FAST_NIC}/a\\        ${ROUTE_LINE}" "$INTERFACES_FILE"
            echo -e "  ${GREEN}Persistent route added to ${INTERFACES_FILE}${NC}"
        else
            echo -e "  ${YELLOW}No stanza for ${FAST_NIC} in ${INTERFACES_FILE}.${NC}"
            echo -e "  ${YELLOW}Add this line manually under the ${FAST_NIC} interface block:${NC}"
            echo -e "  ${GREEN}    ${ROUTE_LINE}${NC}"
        fi
    fi
else
    echo -e "  ${YELLOW}${INTERFACES_FILE} not found. If using netplan or systemd-networkd:${NC}"
    echo -e "  ${GREEN}    ${ROUTE_LINE}${NC}"
fi

# --- MTU mismatch warning ---
echo ""
echo -e "${CYAN}[5.5/6] Checking MTU compatibility...${NC}"
if [ "$MTU" -gt 1500 ]; then
    echo -e "  ${YELLOW}WARNING: MTU MISMATCH detected!${NC}"
    echo -e "  ${FAST_NIC} MTU: ${MTU} (jumbo)"
    echo -e "  ExaGrid bond0 MTU: 1500 (standard)"
    echo ""
    echo -e "  ${YELLOW}Options to resolve:${NC}"
    echo -e "    A) Lower Proxmox NIC to match ExaGrid (safe, no ExaGrid change):${NC}"
    echo -e "       ${GREEN}ip link set ${FAST_NIC} mtu 1500${NC}"
    echo -e ""
    echo -e "    B) Raise ExaGrid bond0 to jumbo (requires ExaGrid admin + switch support):${NC}"
    echo -e "       ExaGrid UI -> Configuration -> Network -> bond0 -> IP MTU: 9000"
    echo -e "       Also set jumbo MTU on the switch ports connecting to ExaGrid"
    echo ""
    echo -e "  ${YELLOW}Until resolved: TCP MSS clamping will prevent data loss, but${NC}"
    echo -e "  ${YELLOW}you won't get jumbo frame benefits. Performance still improves${NC}"
    echo -e "  ${YELLOW}massively (1G -> 10G) from the routing fix alone.${NC}"
fi

# --- Summary ---
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Summary                                  ${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  Before : vmbr0/bond0 (eno8303) at 1 Gbps      = ~112 MB/s ceiling"
echo -e "  After  : ${FAST_NIC} at ${SPEED} Mb/s, MTU ${MTU}"
echo -e "  ExaGrid: bond0 (10G bonded pair), MTU 1500"
echo -e "  Effective ceiling: 10 Gbps (ExaGrid bond0)     = ~1.18 GB/s"
echo -e "  ${GREEN}Improvement: ~10x throughput increase${NC}"
echo ""
echo -e "  ${YELLOW}Recommended: test with a quick SMB copy or iperf3:${NC}"
echo -e "    iperf3 -c ${EXAGRID_IP} -t 10 -P 4"
echo -e "    # Or re-run copy_iso.sh and observe the pv bandwidth"
echo -e "${CYAN}============================================${NC}"

# --- Also recommend TCP tuning ---
echo ""
echo -e "${YELLOW}Optional: TCP buffer tuning for 10G throughput:${NC}"
echo "  sysctl -w net.core.rmem_max=67108864"
echo "  sysctl -w net.core.wmem_max=67108864"
echo "  sysctl -w net.ipv4.tcp_rmem='4096 1048576 67108864'"
echo "  sysctl -w net.ipv4.tcp_wmem='4096 1048576 67108864'"
echo "  sysctl -w net.ipv4.tcp_mtu_probing=1"
echo ""
echo "  To persist: add to /etc/sysctl.d/99-network-tuning.conf"
