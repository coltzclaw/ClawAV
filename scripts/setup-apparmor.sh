#!/usr/bin/env bash
set -euo pipefail

# ClawAV — AppArmor Profile Setup for OpenClaw Agent
# Installs and enforces AppArmor profiles:
#   1. usr.bin.openclaw — restricts openclaw user from accessing ClawAV files
#   2. etc.clawav.protect — restricts common tools from modifying /etc/clawav/

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE_SRC="${SCRIPT_DIR}/../apparmor/usr.bin.openclaw"
PROFILE_DST="/etc/apparmor.d/usr.bin.openclaw"
PROTECT_SRC="${SCRIPT_DIR}/../apparmor/etc.clawav.protect"
PROTECT_DST="/etc/apparmor.d/etc.clawav.protect"

log()  { echo "[AppArmor] $*"; }
warn() { echo "[AppArmor WARN] $*"; }

echo "=== ClawAV AppArmor Setup ==="

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Graceful check: is AppArmor available at all?
if ! command -v apparmor_parser &>/dev/null; then
    log "apparmor_parser not found. Attempting install..."
    apt-get update -qq && apt-get install -y apparmor apparmor-utils 2>/dev/null || {
        warn "Could not install AppArmor — skipping AppArmor setup entirely"
        log "INFO: ClawAV will still function. chattr +i and auditd provide primary protection."
        exit 0
    }
fi

# Check if AppArmor is enabled in kernel
if command -v aa-enabled &>/dev/null; then
    if aa-enabled --quiet 2>/dev/null; then
        log "AppArmor is enabled in kernel"
    else
        warn "AppArmor is NOT enabled in the kernel"
        warn "Add 'apparmor=1 security=apparmor' to kernel command line"
        warn "Edit /boot/firmware/cmdline.txt on Raspberry Pi"
        log "Installing profiles anyway — they will activate on next boot with AppArmor enabled"
    fi
else
    log "aa-enabled not found — cannot verify kernel support"
fi

# ── Install and load openclaw restriction profile ─────────────────────────
if [[ -f "${PROFILE_SRC}" ]]; then
    cp "${PROFILE_SRC}" "${PROFILE_DST}"
    log "Installed ${PROFILE_DST}"
    apparmor_parser -r "${PROFILE_DST}" 2>/dev/null && {
        log "Profile usr.bin.openclaw loaded in enforce mode"
    } || {
        warn "Failed to load usr.bin.openclaw (non-fatal — will load on boot)"
    }
else
    warn "Profile source not found: ${PROFILE_SRC}"
fi

# ── Install and load config protection profile ───────────────────────────
if [[ -f "${PROTECT_SRC}" ]]; then
    cp "${PROTECT_SRC}" "${PROTECT_DST}"
    log "Installed ${PROTECT_DST}"
    apparmor_parser -r "${PROTECT_DST}" 2>/dev/null && {
        log "Profile etc.clawav.protect loaded"
    } || {
        warn "Failed to load etc.clawav.protect (non-fatal — will load on boot)"
    }
else
    log "Config protection profile not found at ${PROTECT_SRC} — skipping"
fi

# Verify
if command -v aa-status &>/dev/null; then
    echo ""
    log "AppArmor status:"
    aa-status 2>/dev/null | grep -A5 "enforce" || true
fi

echo ""
echo "=== AppArmor Setup Complete ==="
echo "Profiles: ${PROFILE_DST}, ${PROTECT_DST}"
echo "To check status: sudo aa-status"
