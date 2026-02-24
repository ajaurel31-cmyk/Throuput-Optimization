#!/bin/bash
# ============================================================
# Proxmox ISO Copy Script with Bandwidth Monitoring
# Copies an ISO from SMB/CIFS share to local Proxmox host
# Source: //10.15.25.14/backup003
# Destination: 10.2.25.92 (this host)
# ============================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Paths ---
ISO_DIR="/mnt/pve/ATL-PURE01-NFS01/template/iso"
MOUNT_POINT="/mnt/backup003"
SMB_SHARE="//10.15.25.14/backup003"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Proxmox ISO Copy with Bandwidth Monitor   ${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  Source      : ${GREEN}${SMB_SHARE}${NC}"
echo -e "  Destination : ${GREEN}${ISO_DIR}${NC}"
echo ""

# --- Check for required tools ---
for cmd in pv mount.cifs; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${YELLOW}Installing missing dependency: ${cmd}...${NC}"
        apt-get update -qq && apt-get install -y -qq pv cifs-utils 2>/dev/null
        break
    fi
done

# --- Mount the SMB share (guest access) ---
echo -e "${CYAN}Mounting ${SMB_SHARE} (guest access)...${NC}"
mkdir -p "$MOUNT_POINT"

# Unmount if already mounted
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${YELLOW}Mount point already in use, unmounting...${NC}"
    umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT"
fi

mount -t cifs "$SMB_SHARE" "$MOUNT_POINT" -o guest 2>&1

if ! mountpoint -q "$MOUNT_POINT"; then
    echo -e "${RED}Error: Failed to mount ${SMB_SHARE}.${NC}"
    exit 1
fi
echo -e "${GREEN}Mounted successfully.${NC}"

# --- Cleanup function ---
cleanup() {
    echo ""
    echo -e "${CYAN}Cleaning up...${NC}"
    sync
    umount "$MOUNT_POINT" 2>/dev/null || umount -l "$MOUNT_POINT" 2>/dev/null
    echo -e "${GREEN}Unmounted ${SMB_SHARE}.${NC}"
}
trap cleanup EXIT

# --- List available ISO files on the SMB share ---
echo ""
echo -e "${CYAN}Available ISO files on ${SMB_SHARE}:${NC}"
echo "--------------------------------------------"

mapfile -t ISO_FILES < <(find "$MOUNT_POINT" -maxdepth 1 -name "*.iso" -type f 2>/dev/null | sort)

if [ ${#ISO_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}No ISO files found on ${SMB_SHARE}.${NC}"
    read -rp "Enter filename on share (or full path): " SELECTION
    if [[ "$SELECTION" == /* ]]; then
        ISO_FILE="$SELECTION"
    else
        ISO_FILE="${MOUNT_POINT}/${SELECTION}"
    fi
else
    for i in "${!ISO_FILES[@]}"; do
        SIZE=$(du -h "${ISO_FILES[$i]}" | cut -f1)
        echo -e "  ${GREEN}[$((i+1))]${NC} $(basename "${ISO_FILES[$i]}") (${SIZE})"
    done
    echo ""
    read -rp "Select ISO by number (or enter filename): " SELECTION

    if [[ "$SELECTION" =~ ^[0-9]+$ ]] && [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le ${#ISO_FILES[@]} ]; then
        ISO_FILE="${ISO_FILES[$((SELECTION-1))]}"
    elif [[ "$SELECTION" == /* ]]; then
        ISO_FILE="$SELECTION"
    else
        ISO_FILE="${MOUNT_POINT}/${SELECTION}"
    fi
fi

# --- Validate source ISO file ---
if [ ! -f "$ISO_FILE" ]; then
    echo -e "${RED}Error: File not found: ${ISO_FILE}${NC}"
    exit 1
fi

ISO_NAME=$(basename "$ISO_FILE")
ISO_SIZE=$(stat -c%s "$ISO_FILE")
ISO_SIZE_HUMAN=$(du -h "$ISO_FILE" | cut -f1)
echo ""
echo -e "${GREEN}Selected: ${ISO_NAME} (${ISO_SIZE_HUMAN})${NC}"

# --- Validate destination directory ---
if [ ! -d "$ISO_DIR" ]; then
    echo -e "${RED}Error: Destination directory ${ISO_DIR} does not exist.${NC}"
    exit 1
fi

# --- Check destination space ---
DEST_AVAIL=$(df --output=avail "$ISO_DIR" | tail -1)
DEST_AVAIL_BYTES=$((DEST_AVAIL * 1024))
if [ "$ISO_SIZE" -gt "$DEST_AVAIL_BYTES" ]; then
    DEST_AVAIL_HUMAN=$(df -h --output=avail "$ISO_DIR" | tail -1 | xargs)
    echo -e "${RED}Error: Not enough space on destination.${NC}"
    echo -e "  File size : ${ISO_SIZE_HUMAN}"
    echo -e "  Available : ${DEST_AVAIL_HUMAN}"
    exit 1
fi

# --- Copy with bandwidth monitoring using pv ---
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Starting ISO copy with bandwidth monitor  ${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  File   : ${ISO_NAME}"
echo -e "  Size   : ${ISO_SIZE_HUMAN}"
echo -e "  From   : ${SMB_SHARE}/${ISO_NAME}"
echo -e "  To     : ${ISO_DIR}/${ISO_NAME}"
echo ""

START_TIME=$(date +%s)

pv -petabrI 0.5 "$ISO_FILE" > "${ISO_DIR}/${ISO_NAME}"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# --- Calculate summary ---
if [ "$ELAPSED" -gt 0 ]; then
    AVG_SPEED_BYTES=$((ISO_SIZE / ELAPSED))
    AVG_SPEED_MB=$(echo "scale=2; $AVG_SPEED_BYTES / 1048576" | bc)
    AVG_SPEED_MBITS=$(echo "scale=2; $AVG_SPEED_BYTES * 8 / 1000000" | bc)
else
    AVG_SPEED_MB="N/A"
    AVG_SPEED_MBITS="N/A"
fi

MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

# --- Verify copy ---
DEST_FILE="${ISO_DIR}/${ISO_NAME}"
if [ -f "$DEST_FILE" ]; then
    DEST_SIZE=$(stat -c%s "$DEST_FILE")
    if [ "$ISO_SIZE" -eq "$DEST_SIZE" ]; then
        VERIFY_STATUS="${GREEN}VERIFIED (sizes match)${NC}"
    else
        VERIFY_STATUS="${RED}WARNING: Size mismatch (src=${ISO_SIZE}, dst=${DEST_SIZE})${NC}"
    fi
else
    VERIFY_STATUS="${RED}FAILED: Destination file not found${NC}"
fi

# --- Print summary ---
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}            Copy Complete                   ${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  File           : ${ISO_NAME}"
echo -e "  Size           : ${ISO_SIZE_HUMAN}"
echo -e "  Duration       : ${MINUTES}m ${SECONDS}s"
echo -e "  Avg Speed      : ${AVG_SPEED_MB} MB/s (${AVG_SPEED_MBITS} Mbps)"
echo -e "  Integrity      : ${VERIFY_STATUS}"
echo -e "${CYAN}============================================${NC}"
