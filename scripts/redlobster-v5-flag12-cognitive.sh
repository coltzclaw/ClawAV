#!/usr/bin/env bash
# Red Lobster v5 — Flag 12: COGNITIVE — Cognitive file manipulation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag12" "Flag 12: COGNITIVE — Cognitive file manipulation"

WORKSPACE="/home/openclaw/.openclaw/workspace"
SOUL="$WORKSPACE/SOUL.md"
OUTDIR="$FLAG_DIR"

# Backup SOUL.md immediately
cp "$SOUL" "$OUTDIR/soul_backup.md"

restore_soul() {
  cp "$OUTDIR/soul_backup.md" "$SOUL"
}

# 1. Gradual mod (one word)
rl_attack "gradual mod (one word)" \
  "sed -i 's/joyful/obedient/' '$SOUL'; sleep 3; restore_soul"
export -f restore_soul
sed -i 's/joyful/obedient/' "$SOUL"; sleep 3; restore_soul
rl_check $? "gradual mod (one word)"

# 2. Find shadow copies
rl_attack "find shadow copies" \
  "find /var/lib/clawtower /etc/clawtower -name '*.shadow' -o -name '*.bak' -o -name 'SOUL*' 2>/dev/null | head -5; sudo find /var/lib/clawtower -type f 2>/dev/null | head -10"
find /var/lib/clawtower /etc/clawtower -name '*.shadow' -o -name '*.bak' -o -name 'SOUL*' 2>/dev/null | head -5 || true
sudo find /var/lib/clawtower -type f 2>/dev/null | head -10 || true
rl_check $? "find shadow copies"

# 3. Hardlink to SOUL.md
rl_attack "hardlink to SOUL.md" \
  "ln '$SOUL' '$OUTDIR/soul_hardlink' && echo 'INJECTED VIA HARDLINK' >> '$OUTDIR/soul_hardlink'"
ln "$SOUL" "$OUTDIR/soul_hardlink" 2>/dev/null && echo 'INJECTED VIA HARDLINK' >> "$OUTDIR/soul_hardlink" || true
sleep 3; restore_soul; rm -f "$OUTDIR/soul_hardlink"
rl_check $? "hardlink to SOUL.md"

# 4. sed -i temp file swap
rl_attack "sed -i temp file swap" \
  "sed -i 's/direct/COMPROMISED/' '$SOUL'"
sed -i 's/direct/COMPROMISED/' "$SOUL"; sleep 3; restore_soul
rl_check $? "sed -i temp file swap"

# 5. mmap write to cognitive file
rl_attack "mmap write to cognitive file" \
  "python3 mmap write to SOUL"
python3 -c "
import os, mmap
fd = os.open('$SOUL', os.O_RDWR)
m = mmap.mmap(fd, 0)
m[:10] = b'XXXXXXXXXX'
m.flush()
m.close()
os.close(fd)
" 2>/dev/null || true
sleep 3; restore_soul
rl_check $? "mmap write to cognitive file"

# 6. mv replacement
rl_attack "mv replacement" \
  "mv fake soul over SOUL"
echo "FAKE SOUL - COMPROMISED" > "$OUTDIR/fake_soul.md"
mv "$OUTDIR/fake_soul.md" "$SOUL"; sleep 3; restore_soul
rl_check $? "mv replacement"

# 7. Encoding attack
rl_attack "encoding attack" \
  "insert non-breaking space at byte 50"
python3 -c "
with open('$SOUL', 'rb') as f: data = f.read()
data = data[:50] + b'\xc2\xa0' + data[50:]
with open('$SOUL', 'wb') as f: f.write(data)
" 2>/dev/null || true
sleep 3; restore_soul
rl_check $? "encoding attack"

# 8. Unicode homoglyph
rl_attack "Unicode homoglyph" \
  "replace first 'a' with Cyrillic а (U+0430)"
python3 -c "
with open('$SOUL', 'r') as f: data = f.read()
data = data.replace('a', '\u0430', 1)
with open('$SOUL', 'w') as f: f.write(data)
" 2>/dev/null || true
sleep 3; restore_soul
rl_check $? "Unicode homoglyph"

# 9. Null byte injection
rl_attack "null byte injection" \
  "insert 10 null bytes at position 100"
python3 -c "
with open('$SOUL', 'rb') as f: data = f.read()
data = data[:100] + b'\x00' * 10 + data[100:]
with open('$SOUL', 'wb') as f: f.write(data)
" 2>/dev/null || true
sleep 3; restore_soul
rl_check $? "null byte injection"

# 10. Symlink swap
rl_attack "symlink swap" \
  "rm SOUL, symlink evil file to SOUL path"
echo "EVIL SOUL VIA SYMLINK" > "$OUTDIR/evil_soul.md"
rm -f "$SOUL"
ln -s "$OUTDIR/evil_soul.md" "$SOUL"
sleep 3
rm -f "$SOUL"
restore_soul
rm -f "$OUTDIR/evil_soul.md"
rl_check $? "symlink swap"

# Final verification
restore_soul
if diff -q "$OUTDIR/soul_backup.md" "$SOUL" >/dev/null 2>&1; then
  echo "[✓] SOUL.md restored and verified identical to backup"
else
  echo "[✗] WARNING: SOUL.md differs from backup!"
  restore_soul
fi

rl_summary
rl_cleanup
