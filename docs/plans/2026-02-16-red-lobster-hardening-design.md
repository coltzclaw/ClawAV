# Red Lobster Hardening — 3-Tier Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all bypasses found in Red Lobster pentest v1 (0/6 flags defended). Run Red Lobster after each tier to measure progress. Target: 6/6 flags defended by Tier 3.

**Approach:** 3 tiers, each followed by a Red Lobster run. Ship after each tier passes CI.

---

## Tier 1 — Immediate Lockdown (Config + Policy, No Code)

**Expected impact:** Fix ESCALATE flag, partially fix PERSIST and TAMPER flags.
**Effort:** ~30 minutes. Config/sudoers changes only.

### T1.1: Sudoers GTFOBins Lockdown

**Problem:** `sudo awk 'BEGIN{system("sh")}'`, `sudo sed 'e id'`, `sudo systemd-run --scope /bin/sh` all give instant root.

**Current sudoers allows NOPASSWD:**
- awk, sed, curl, wget (all have shell escapes)
- systemd-run * (wildcard = any command as root)
- tee, cp, mv, rm, chmod, chown (file ops as root)
- mount (can mount attacker-controlled filesystems)

**Fix:** Replace permissive sudoers with strict clawsudo-mediated access.

**New sudoers (`/etc/sudoers.d/010-openclaw`):**
```
# OpenClaw agent — all sudo goes through clawsudo
openclaw ALL=(ALL) NOPASSWD: /usr/local/bin/clawsudo *

# Read-only system inspection (no shell escape risk)
openclaw ALL=(ALL) NOPASSWD: /usr/bin/cat, /usr/bin/ls, /usr/bin/head, /usr/bin/tail, /usr/bin/grep, /usr/bin/find, /usr/bin/stat, /usr/bin/wc, /usr/bin/diff, /usr/bin/file, /usr/bin/readlink, /usr/bin/getent, /usr/bin/id, /usr/bin/whoami, /usr/bin/test, /usr/bin/sort, /usr/bin/uniq, /usr/bin/tr, /usr/bin/cut, /usr/bin/md5sum, /usr/bin/sha256sum, /usr/bin/strings

# System monitoring (read-only, no shell escape)
openclaw ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/bin/dmesg, /usr/bin/ss, /usr/sbin/lsof, /usr/bin/df, /usr/bin/du, /usr/bin/free, /usr/bin/uptime, /usr/bin/ps, /usr/bin/ip, /usr/sbin/ip

# Systemctl — status/start/restart only (no stop/disable/mask)
openclaw ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl is-active *, /usr/bin/systemctl show *, /usr/bin/systemctl list-units *, /usr/bin/systemctl start *, /usr/bin/systemctl restart *, /usr/bin/systemctl enable *, /usr/bin/systemctl daemon-reload

# Package management
openclaw ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/apt-cache

# DENY everything else explicitly
openclaw ALL=(ALL) !ALL
```

**Removed (shell escape vectors):**
- ❌ awk, sed, curl, wget (use clawsudo for these)
- ❌ systemd-run * (wildcard)
- ❌ tee, cp, mv, rm, chmod, chown, ln, mkdir, touch, install (use clawsudo)
- ❌ mount, top, netstat, lsof (unnecessary or redundant)
- ❌ dd (already denied but was in deny list, not allow list)

**clawsudo update:** Add argument inspection for remaining allowed binaries — reject if args contain shell metacharacters (`;`, `|`, `` ` ``, `$(`).

### T1.2: Remove Docker Group

**Problem:** `docker run -v /:/host -it alpine sh` = root
**Fix:** `sudo gpasswd -d openclaw docker`
**Note:** OpenClaw can still use Docker via `sudo docker` through clawsudo if needed.

### T1.3: Upgrade MEMORY.md to Protected

**Problem:** Watched policy accepts tampered content as new baseline after one Warning.
**Fix:** Change MEMORY.md from `WatchPolicy::Watched` to `WatchPolicy::Protected` in sentinel defaults.
**Impact:** Any unauthorized MEMORY.md change will be quarantined and restored. OpenClaw's own writes will also trigger — need to add OpenClaw's PID to a sentinel allowlist (or handle via shadow pre-update).

**Better approach:** Add a new policy level `WatchPolicy::CognitiveProtected` that:
1. Fires WARN (not CRIT) on change
2. Does NOT auto-update shadow
3. Requires explicit confirmation to accept the change
4. Falls back to restoring from shadow after timeout (e.g., 60s)

Actually, simplest fix: keep MEMORY.md as Watched but **don't auto-update shadow for .md/.txt files**. Require a sentinel API call or admin key to accept a cognitive file change. This prevents shadow poisoning without breaking OpenClaw's workflow.

**Simplest v1:** Just promote MEMORY.md to Protected. OpenClaw already handles quarantine gracefully (rewrites the file). The sentinel will quarantine + restore, OpenClaw will rewrite, sentinel quarantines again — but this is better than silent tampering. We can add the approval workflow in Tier 3.

### T1.4: Harden install.sh Sudoers Template

Update the sudoers template in `scripts/install.sh` and `scripts/oneshot-install.sh` to match the locked-down version above, so new installs get it automatically.

---

## Tier 2 — Detection Gaps (New Code in Existing Modules)

**Expected impact:** Fix EXFIL flag, fix PERSIST flag, partially fix BLIND and ESCAPE flags.
**Effort:** ~2-3 hours. New scanner functions + behavior patterns + sentinel enhancements.

### T2.1: File-Read Auditing on Credential Paths

**Problem:** All credential reads are invisible.
**Fix:** Add auditd watch rules for credential paths:
```
-w /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json -p r -k cred-read
-w /home/openclaw/.openclaw/credentials -p r -k cred-read  
-w /home/openclaw/.aws/credentials -p r -k cred-read
```
**Code changes:**
- `src/auditd.rs`: Parse `key=cred-read` events, classify as WARN/CRIT based on reading process
- `scripts/setup-auditd.sh`: Add the watch rules
- Allowlist OpenClaw's own PID (it legitimately reads auth-profiles.json)

### T2.2: User Persistence Scanner

**Problem:** 14/15 user-level persistence mechanisms undetected.
**Fix:** New scanner function `scan_user_persistence()` that checks:
- `crontab -l` for openclaw user
- `~/.config/systemd/user/*.timer` and `*.service`
- `~/.bashrc`, `~/.profile`, `~/.bash_login` — hash and compare to known-good baseline
- `~/.config/autostart/*.desktop`
- `.git/hooks/*` in workspace repos (non-sample files)
- `~/.ssh/rc`, `~/.ssh/environment`
- `~/.local/lib/python*/site-packages/usercustomize.py`
- `~/.npmrc` (preinstall/postinstall scripts)
- `PYTHONSTARTUP`, `PERL5OPT`, `NODE_OPTIONS` in environment

**Alert level:** CRIT for new entries not in baseline, WARN for modified entries.
**Baseline:** Store hashes of known-good files on first scan, alert on changes.

### T2.3: Network Binary Watchlist Expansion

**Problem:** Node.js, Python scripts, Perl, Ruby all make network connections invisibly.
**Fix:** Add to behavior engine `NETWORK_CAPABLE_BINARIES`:
```rust
const NETWORK_CAPABLE_BINARIES: &[&str] = &[
    "curl", "wget", "nc", "ncat", "socat", "telnet",  // existing
    "node", "nodejs",                                    // new
    "python3", "python",                                 // new  
    "perl", "ruby",                                      // new
    "ssh", "scp", "rsync", "sftp",                      // new
    "php", "lua",                                        // new
];
```
**Behavior classification:** When these binaries make outbound connections (detected via auditd connect/sendto syscalls), classify based on destination.

### T2.4: Sentinel xattr Monitoring

**Problem:** Extended attributes can inject payloads invisibly.
**Fix:** In sentinel `handle_change()`, after content comparison:
```rust
// Check xattrs
let current_xattrs = xattr::list(file_path)
    .map(|attrs| attrs.filter_map(|a| {
        let name = a.to_string_lossy().to_string();
        xattr::get(file_path, &a).ok().flatten()
            .map(|v| (name, v))
    }).collect::<Vec<_>>())
    .unwrap_or_default();

if !current_xattrs.is_empty() {
    // Any user.* xattr on a cognitive file is suspicious
    for (name, value) in &current_xattrs {
        if name.starts_with("user.") {
            alert!(CRIT, "Suspicious xattr on {}: {} = {:?}", path, name, value);
            // Remove it
            let _ = xattr::remove(file_path, name);
        }
    }
}
```
**Dependency:** Add `xattr` crate to Cargo.toml.

### T2.5: Exfiltration Tool Expansion

**Problem:** rsync, python -m http.server, dd, tee not flagged as exfil tools.
**Fix:** Add to behavior engine:
```rust
const EXFIL_COMMANDS: &[&str] = &[
    "curl", "wget",           // existing
    "rsync", "scp", "sftp",  // new: file transfer tools
    "nc", "ncat", "socat",   // existing: raw connections
    "dd", "tee",             // new: when targeting sensitive paths
];
```
Also add pattern: `python3 -m http.server` and `python3 -m SimpleHTTPServer`.

---

## Tier 3 — Architecture Improvements (Deeper Changes)

**Expected impact:** Fix BLIND flag, harden ESCAPE flag, defense in depth.
**Effort:** ~4-6 hours. New subsystems and deeper integration.

### T3.1: Recursive Directory Watches

**Problem:** New file creation anywhere in workspace is invisible.
**Fix:** Add `RecursiveMode::Recursive` watch on workspace root directory. Alert on:
- New executable files (any file with +x permission)
- New script files (.sh, .py, .pl, .rb, .js)
- Files created in suspicious locations (/tmp, /var/tmp, /dev/shm)
- Any new .so file (potential LD_PRELOAD payload)

**Config:**
```toml
[sentinel]
watch_new_files = true
watch_dirs_recursive = [
    "/home/openclaw/.openclaw/workspace",
    "/home/openclaw/.local/bin",
    "/tmp",
]
new_file_alert_patterns = ["*.sh", "*.py", "*.pl", "*.rb", "*.js", "*.so"]
```

### T3.2: Syscall-Level Network Monitoring

**Problem:** Binary-name-based detection is bypassable (rename binary, use script file).
**Fix:** Add auditd rules for connect() and sendto() syscalls:
```
-a always,exit -F arch=b64 -S connect -F a0!=0x2 -F uid=1000 -k net-connect
-a always,exit -F arch=b64 -S sendto -F uid=1000 -k net-send
```
Parse in auditd.rs, extract destination IP/port from syscall args, feed to netpolicy for allowlist check.

**Note:** This is high-volume. Need smart filtering:
- Skip loopback (127.0.0.1, ::1)
- Skip LAN (192.168.x.x, 10.x.x.x)  
- Skip known OpenClaw API endpoints
- Only alert on connections to unknown external IPs

### T3.3: Cognitive File Approval Workflow

**Problem:** MEMORY.md as Protected blocks legitimate OpenClaw writes.
**Fix:** New sentinel policy `WatchPolicy::CognitiveProtected`:
1. On change: fire WARN, hold new content in quarantine
2. Start 60-second approval timer
3. If approved (via sentinel API or admin key): update shadow, keep new content
4. If not approved: restore from shadow
5. Auto-approve changes from OpenClaw's own PID (detect via /proc/PID/exe)

This allows OpenClaw to write to MEMORY.md normally (auto-approved) while blocking external tampering.

### T3.4: Shadow Poisoning Prevention

**Problem:** Once sentinel accepts a tampered file as baseline, future tampers are invisible.
**Fix:** 
- Hash-chain the shadow copies (like audit_chain.rs)
- Periodic integrity check: compare shadow hash chain to stored baseline
- Alert if shadow was modified outside of sentinel's own update path

### T3.5: Process Lineage Tracking

**Problem:** Can't distinguish "OpenClaw writing MEMORY.md" from "attacker writing MEMORY.md" — both are uid=1000.
**Fix:** Track process lineage via /proc/PID/status (PPid chain):
- OpenClaw → node → child process = legitimate
- bash → manual command = suspicious
- Any process not in OpenClaw's lineage tree modifying cognitive files = CRIT

---

## Red Lobster Schedule

| Milestone | Action |
|-----------|--------|
| After Tier 1 | Tag v0.3.1, rebuild, install, run Red Lobster v2 |
| After Tier 2 | Tag v0.3.1, rebuild, install, run Red Lobster v3 |
| After Tier 3 | Tag v0.3.1, rebuild, install, run Red Lobster v4 (final) |

**Target: 6/6 flags defended by Red Lobster v4.**
