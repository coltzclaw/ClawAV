#!/usr/bin/env bash
# Red Lobster v8 — Clawsudo Pentest Runner
# Tests clawsudo policy enforcement: bypasses + deny verification
# Usage: bash scripts/redlobster-v8-run-all.sh [flag15|flag16|flag17|all]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh" 2>/dev/null || true

RESULTS_DIR="/tmp/redlobster/results"
mkdir -p "$RESULTS_DIR"

FLAGS=(
    "flag15:redlobster-v8-flag15-direct-sudo.sh:DIRECT SUDO NOPASSWD ABUSE"
    "flag16:redlobster-v8-flag16-clawsudo.sh:CLAWSUDO POLICY AUDIT"
    "flag17:redlobster-v8-flag17-infostealer.sh:INFOSTEALER DEFENSE"
)

TARGET="${1:-all}"

CT_VERSION="$(cat "$SCRIPT_DIR/../VERSION" 2>/dev/null || echo 'unknown')"
echo "┌───────────────────────────────────────────────────────┐"
echo "│  🦞 Red Lobster v8 — Clawsudo Policy Pentest          │"
echo "│  ClawTower $CT_VERSION                                       │"
echo "│  $(date '+%Y-%m-%d %H:%M:%S %Z')                              │"
echo "│  Target: $TARGET                                             │"
echo "│  User: $(whoami)                                             │"
echo "│  clawsudo: $(which clawsudo 2>/dev/null || echo 'NOT FOUND') │"
echo "└───────────────────────────────────────────────────────┘"
echo ""

# Verify clawsudo exists (required for flag15/flag16, not flag17)
if ! command -v clawsudo &>/dev/null; then
    if [[ "$TARGET" == "all" ]]; then
        echo "⚠️  clawsudo not found — flag15/flag16 will be skipped"
    elif [[ "$TARGET" == "flag15" || "$TARGET" == "flag16" ]]; then
        echo "❌ clawsudo not found in PATH. Cannot run $TARGET."
        exit 1
    fi
fi

PASS=0
FAIL=0
SKIP=0

for entry in "${FLAGS[@]}"; do
    IFS=: read -r key script label <<< "$entry"
    if [[ "$TARGET" != "all" && "$TARGET" != "$key" ]]; then continue; fi

    echo "═══ [$key] $label ═══"
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        if bash "$SCRIPT_DIR/$script"; then
            echo "  ✅ $label — PASS"
            ((PASS++))
        else
            echo "  ❌ $label — FAIL (exit $?)"
            ((FAIL++))
        fi
    else
        echo "  ⏭️  $label — SKIP (script not found)"
        ((SKIP++))
    fi
    echo ""
done

echo "┌─── Scorecard ───┐"
echo "│ PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP │"
echo "└─────────────────┘"

if [[ "$TARGET" == "all" ]]; then
    COMBINED="$RESULTS_DIR/v8-combined.md"
    {
        echo "# Red Lobster v8 — Clawsudo Policy Pentest Results"
        echo ""
        echo "- **Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "- **ClawTower:** $CT_VERSION"
        echo "- **User:** $(whoami)"
        echo "- **Threat model:** Compromised agent with clawsudo access (gated sudo)"
        echo ""
        for entry in "${FLAGS[@]}"; do
            IFS=: read -r key script label <<< "$entry"
            result_file="$RESULTS_DIR/${key}.md"
            echo "---"
            echo "## $label ($key)"
            echo ""
            if [[ -f "$result_file" ]]; then
                cat "$result_file"
            else
                echo "_No result file found._"
            fi
            echo ""
        done
    } > "$COMBINED"
    echo "Combined report: $COMBINED"
fi

exit $FAIL
