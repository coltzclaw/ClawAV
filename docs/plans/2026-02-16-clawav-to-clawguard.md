# ClawAV → ClawGuard Rename Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rename all references from ClawAV to ClawGuard across the entire codebase, including file names, system paths, and Cargo.toml configuration.

**Architecture:** Bulk sed find/replace in careful order (case-sensitive patterns, most-specific first to avoid double-replacement), then file renames, then Cargo.toml update, then build/test verification.

**Tech Stack:** sed, git mv, cargo

**Design doc:** `docs/plans/2026-02-16-clawav-to-clawguard-design.md`

---

### Task 1: Bulk string replacement

**Files:** All 78 files containing clawav/ClawAV/CLAWAV references

**IMPORTANT:** Do NOT rename `clawsudo`, `secureclaw`, or `openclaw` references. Only rename `clawav`/`ClawAV`/`CLAWAV` patterns.

**Step 1: Run bulk sed replacements**

Order matters — do the most specific patterns first to avoid double-replacement:

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV

# Find all non-binary, non-git files
FILES=$(grep -rl "clawav\|ClawAV\|CLAWAV" --include="*.rs" --include="*.toml" --include="*.yaml" --include="*.yml" --include="*.md" --include="*.sh" --include="*.json" --include="*.service" --include="*.desktop" --include="*.rules" --include="*.policy" --include="*.protect" . 2>/dev/null | grep -v target | grep -v .git)

# Replace in order: longest/most-specific first
# 1. CLAWAV → CLAWGUARD (env vars, constants)
sed -i 's/CLAWAV/CLAWGUARD/g' $FILES

# 2. ClawAV → ClawGuard (product name)
sed -i 's/ClawAV/ClawGuard/g' $FILES

# 3. clawav-tray → clawguard-tray (before generic clawav)
sed -i 's/clawav-tray/clawguard-tray/g' $FILES

# 4. clawav-ctl → clawguard-ctl
sed -i 's/clawav-ctl/clawguard-ctl/g' $FILES

# 5. clawav-deny → clawguard-deny (sudoers file)
sed -i 's/clawav-deny/clawguard-deny/g' $FILES

# 6. clawav-tamper → clawguard-tamper (auditd key)
sed -i 's/clawav-tamper/clawguard-tamper/g' $FILES

# 7. clawav-config → clawguard-config (auditd key)
sed -i 's/clawav-config/clawguard-config/g' $FILES

# 8. clawav\.service → clawguard.service
sed -i 's/clawav\.service/clawguard.service/g' $FILES

# 9. clawav\.protect → clawguard.protect
sed -i 's/clawav\.protect/clawguard.protect/g' $FILES

# 10. clawav\.deny → clawguard.deny
sed -i 's/clawav\.deny/clawguard.deny/g' $FILES

# 11. clawav\.rules → clawguard.rules
sed -i 's/clawav\.rules/clawguard.rules/g' $FILES

# 12. Generic clawav → clawguard (catches remaining: binary name, paths, crate name)
sed -i 's/clawav/clawguard/g' $FILES
```

**Step 2: Verify no clawav references remain (except clawsudo, secureclaw, openclaw)**

```bash
grep -rn "clawav" --include="*.rs" --include="*.toml" --include="*.yaml" --include="*.yml" --include="*.md" --include="*.sh" . | grep -v target | grep -v .git | grep -v clawsudo | grep -v secureclaw | grep -v openclaw
```

Expected: no output (all references replaced)

**Step 3: Verify clawsudo references are intact**

```bash
grep -c "clawsudo" src/bin/clawsudo.rs policies/clawsudo.yaml
```

Expected: non-zero counts (clawsudo untouched)

**Step 4: Commit string replacements**

```bash
git add -A
git commit -m "chore: rename ClawAV → ClawGuard (string replacements)"
```

---

### Task 2: File and directory renames

**Step 1: Rename files using git mv**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV

git mv src/bin/clawav-ctl.rs src/bin/clawguard-ctl.rs
git mv src/bin/clawav-tray.rs src/bin/clawguard-tray.rs
git mv openclawav.service clawguard.service
git mv apparmor/etc.clawav.protect apparmor/etc.clawguard.protect
git mv assets/clawav-tray.desktop assets/clawguard-tray.desktop
git mv assets/com.clawav.policy assets/com.clawguard.policy
```

**Step 2: Update Cargo.toml binary paths and crate name**

The file already has string replacements from Task 1, but verify the `[[bin]]` sections point to renamed files:

```toml
[package]
name = "clawguard"
version = "0.3.0"

[[bin]]
name = "clawguard"
path = "src/main.rs"

[[bin]]
name = "clawsudo"
path = "src/bin/clawsudo.rs"

[[bin]]
name = "clawguard-tray"
path = "src/bin/clawguard-tray.rs"
required-features = ["tray"]

[[bin]]
name = "clawguard-ctl"
path = "src/bin/clawguard-ctl.rs"
required-features = ["tray"]
```

Make sure `version = "0.3.0"` (not `0.3.0-beta` or `0.2.11`).

**Step 3: Verify no references to old filenames**

```bash
grep -rn "clawav-ctl\.rs\|clawav-tray\.rs\|openclawav\.service\|etc\.clawav\.protect\|clawav-tray\.desktop\|com\.clawav\.policy" . | grep -v target | grep -v .git
```

Expected: no output

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: rename ClawAV → ClawGuard (file renames)"
```

---

### Task 3: Build, test, and verify

**Step 1: Build**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1 | tail -20
```

Expected: compiles successfully. If there are errors, fix references that sed missed.

**Step 2: Run tests**

```bash
cargo test 2>&1 | grep "test result"
```

Expected: all tests pass (274+)

**Step 3: Verify binary names**

```bash
ls -la target/debug/clawguard target/debug/clawsudo
```

Expected: both binaries exist

**Step 4: Spot-check key files**

```bash
# Config paths should reference clawguard
grep "/etc/clawguard/" src/config.rs | head -5

# Auditd keys should be clawguard-*
grep "clawguard-tamper\|clawguard-config" src/auditd.rs

# Service name should be clawguard
grep "clawguard.service" src/scanner.rs
```

**Step 5: Final grep for any remaining clawav**

```bash
grep -rn "clawav" --include="*.rs" --include="*.toml" --include="*.yaml" --include="*.yml" --include="*.md" --include="*.sh" . | grep -v target | grep -v .git | grep -v clawsudo | grep -v secureclaw | grep -v openclaw | grep -v "ClawAV → ClawGuard"
```

Expected: no output (allow "ClawAV → ClawGuard" in rename commit messages/docs)

**Step 6: Commit any fixes, push**

```bash
git add -A
# Only commit if there are changes
git diff --cached --quiet || git commit -m "fix: remaining ClawAV → ClawGuard references"
```

---

### Task 4: Git remote, tag, and uninstall checklist

This task is done by the main session (not a subagent) because it requires human interaction.

**Step 1: J.R. renames GitHub repo**

Go to https://github.com/coltz108/ClawAV → Settings → General → Repository name → `ClawGuard` → Rename

**Step 2: Update git remote**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawAV
git remote set-url origin git@github.com:coltz108/ClawGuard.git
```

**Step 3: Push and tag**

```bash
git push origin main
git tag v0.3.0
git push origin v0.3.0
```

**Step 4: Rename local project directory**

```bash
mv /home/openclaw/.openclaw/workspace/projects/ClawAV /home/openclaw/.openclaw/workspace/projects/ClawGuard
```

**Step 5: Uninstall old ClawAV from Pi**

```bash
# Stop the service
sudo systemctl stop clawav
sudo systemctl disable clawav

# Remove immutable flags
sudo chattr -i /usr/local/bin/clawav 2>/dev/null
sudo chattr -i /usr/local/bin/clawsudo 2>/dev/null
sudo chattr -i /etc/clawav/admin.key.hash 2>/dev/null
sudo chattr -i /etc/systemd/system/clawav.service 2>/dev/null
sudo chattr -i /etc/sudoers.d/clawav-deny 2>/dev/null

# Remove binaries
sudo rm -f /usr/local/bin/clawav
sudo rm -f /usr/local/bin/clawav-tray

# Remove service
sudo rm -f /etc/systemd/system/clawav.service
sudo systemctl daemon-reload

# Remove config (SAVE admin key hash first if you want to reuse it)
sudo cp /etc/clawav/admin.key.hash /tmp/admin.key.hash.backup
sudo rm -rf /etc/clawav/

# Remove sudoers deny
sudo rm -f /etc/sudoers.d/clawav-deny

# Remove auditd rules
sudo auditctl -D -k clawav-tamper 2>/dev/null
sudo auditctl -D -k clawav-config 2>/dev/null

# Remove logs (optional, might want to keep for history)
# sudo rm -rf /var/log/clawav/

# Remove AppArmor profile if present
sudo rm -f /etc/apparmor.d/clawav.protect
sudo apparmor_parser -R clawav.protect 2>/dev/null

# Verify clean
which clawav     # should return nothing
ls /etc/clawav/  # should not exist
systemctl status clawav  # should say not found
```

**Step 6: Install ClawGuard**

Build and install from the renamed repo, or wait for the v0.3.0 GitHub release to use oneshot-install.
