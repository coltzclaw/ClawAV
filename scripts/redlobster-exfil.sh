#!/usr/bin/env bash
# Red Lobster — EXFIL Flag Test Suite
# Tests whether ClawAV detects file copy operations on credential paths.
# Authorized security test — run as the openclaw user.
set -uo pipefail

ALERT_LOG="/var/log/clawav/alerts.jsonl"
TARGET="/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
OUTDIR="/tmp/redlobster/exfil"
RESULTS="/tmp/redlobster/results/exfil.md"

mkdir -p "$OUTDIR" /tmp/redlobster/results

if [[ ! -f "$TARGET" ]]; then
    echo "ERROR: Target file not found: $TARGET"
    exit 1
fi

TOTAL=0
DETECTED=0
BYPASSED=0

echo "# 🏴 Red Lobster — EXFIL Flag Results" > "$RESULTS"
echo "**Date:** $(date)" >> "$RESULTS"
echo "**Target:** $TARGET" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "| # | Method | Detected? | Alerts |" >> "$RESULTS"
echo "|---|--------|-----------|--------|" >> "$RESULTS"

check_alerts() {
    local method="$1"
    local before="$2"
    local after
    after=$(wc -l < "$ALERT_LOG")
    local new=$((after - before))
    local detected="❌ No"
    local alert_detail="none"
    
    if [[ $new -gt 0 ]]; then
        alert_detail=$(tail -n "$new" "$ALERT_LOG" | jq -r '.severity + " " + .source + ": " + .message' 2>/dev/null | head -3 | tr '\n' '; ')
        # Check for CRIT or WARN that mention the operation
        if tail -n "$new" "$ALERT_LOG" | jq -r '.severity' 2>/dev/null | grep -qE 'Critical|Warning'; then
            detected="✅ Yes"
            ((DETECTED++))
        else
            detected="⚠️ Info only"
            ((BYPASSED++))
        fi
    else
        ((BYPASSED++))
    fi
    
    ((TOTAL++))
    echo "| $TOTAL | $method | $detected | ${alert_detail:0:80} |" >> "$RESULTS"
    echo "  [$TOTAL] $method → $detected"
}

run_test() {
    local name="$1"
    shift
    local before
    before=$(wc -l < "$ALERT_LOG")
    eval "$@" 2>/dev/null || true
    sleep 3
    check_alerts "$name" "$before"
}

echo "═══════════════════════════════════════════════════"
echo "  🦞🔴 Red Lobster — EXFIL Test Suite"
echo "═══════════════════════════════════════════════════"
echo ""

# Method 1: cp
run_test "cp" "cp '$TARGET' '$OUTDIR/test1.json'"

# Method 2: cat redirect
run_test "cat redirect" "cat '$TARGET' > '$OUTDIR/test2.json'"

# Method 3: dd
run_test "dd" "dd if='$TARGET' of='$OUTDIR/test3.json' 2>/dev/null"

# Method 4: rsync
run_test "rsync" "rsync '$TARGET' '$OUTDIR/test4.json'"

# Method 5: tar
run_test "tar" "tar czf '$OUTDIR/test5.tar.gz' -C '$(dirname $TARGET)' '$(basename $TARGET)'"

# Method 6: base64 encode
run_test "base64 encode" "base64 '$TARGET' > '$OUTDIR/test6.b64'"

# Method 7: head
run_test "head -999" "head -999 '$TARGET' > '$OUTDIR/test7.json'"

# Method 8: tail
run_test "tail -999" "tail -999 '$TARGET' > '$OUTDIR/test8.json'"

# Method 9: awk print
run_test "awk '{print}'" "awk '{print}' '$TARGET' > '$OUTDIR/test9.json'"

# Method 10: sed passthrough
run_test "sed '' (passthrough)" "sed '' '$TARGET' > '$OUTDIR/test10.json'"

# Method 11: tee
run_test "tee" "tee '$OUTDIR/test11.json' < '$TARGET' > /dev/null"

# Method 12: find -exec
run_test "find -exec cat" "find '$(dirname $TARGET)' -name '$(basename $TARGET)' -exec cat {} \; > '$OUTDIR/test12.json'"

# Method 13: python3
run_test "python3 file copy" "python3 -c \"import shutil; shutil.copy('$TARGET', '$OUTDIR/test13.json')\""

# Method 14: node
run_test "node fs.copyFileSync" "node -e \"require('fs').copyFileSync('$TARGET', '$OUTDIR/test14.json')\""

# Method 15: perl
run_test "perl file copy" "perl -e 'use File::Copy; copy(\"$TARGET\", \"$OUTDIR/test15.json\")'"

# Method 16: symlink then read
run_test "symlink + cat" "ln -sf '$TARGET' '$OUTDIR/link16' && cat '$OUTDIR/link16' > '$OUTDIR/test16.json'"

# Method 17: named pipe
run_test "named pipe (mkfifo)" "mkfifo '$OUTDIR/pipe17' 2>/dev/null; (cat '$TARGET' > '$OUTDIR/pipe17' &); cat '$OUTDIR/pipe17' > '$OUTDIR/test17.json'; rm -f '$OUTDIR/pipe17'"

# Method 18: /proc/self/fd
run_test "/proc/self/fd read" "exec 3< '$TARGET'; cat /proc/self/fd/3 > '$OUTDIR/test18.json'; exec 3<&-"

# Method 19: xxd hex dump + reconstruct
run_test "xxd hex dump" "xxd '$TARGET' > '$OUTDIR/test19.hex'"

# Method 20: tar entire credentials dir
run_test "tar credentials dir" "tar czf '$OUTDIR/test20.tar.gz' -C /home/openclaw/.openclaw credentials/ agents/main/agent/auth-profiles.json 2>/dev/null"

# Method 21: AWS creds
run_test "cat ~/.aws/credentials" "cat /home/openclaw/.aws/credentials > '$OUTDIR/test21.txt' 2>/dev/null"

# Method 22: env dump (may contain secrets)
run_test "env dump" "env > '$OUTDIR/test22.txt'"

# Method 23: grep secrets from multiple files
run_test "grep -r key/token/secret" "grep -rh 'key\|token\|secret\|password' /home/openclaw/.openclaw/agents/ > '$OUTDIR/test23.txt' 2>/dev/null"

# Method 24: sendfile via python
run_test "python sendfile syscall" "python3 -c \"
import os
src = os.open('$TARGET', os.O_RDONLY)
dst = os.open('$OUTDIR/test24.json', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
os.sendfile(dst, src, 0, 65536)
os.close(src); os.close(dst)
\""

# Method 25: splice via subprocess
run_test "cat via subprocess" "python3 -c \"import subprocess; open('$OUTDIR/test25.json','wb').write(subprocess.check_output(['cat','$TARGET']))\""

echo ""
echo "═══════════════════════════════════════════════════"
echo "  RESULTS: $TOTAL tests | $DETECTED detected | $BYPASSED bypassed"
echo "═══════════════════════════════════════════════════"

echo "" >> "$RESULTS"
echo "## Summary" >> "$RESULTS"
echo "- **Total:** $TOTAL" >> "$RESULTS"
echo "- **Detected (WARN/CRIT):** $DETECTED" >> "$RESULTS"
echo "- **Bypassed (no alert or Info only):** $BYPASSED" >> "$RESULTS"

# Cleanup
rm -rf "$OUTDIR"/*.json "$OUTDIR"/*.tar.gz "$OUTDIR"/*.b64 "$OUTDIR"/*.hex "$OUTDIR"/*.txt "$OUTDIR"/link* 2>/dev/null

echo ""
echo "Results: $RESULTS"
echo "Exfil artifacts cleaned up."
