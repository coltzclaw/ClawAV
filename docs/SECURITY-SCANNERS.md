# Security Scanners Reference Guide

ClawAV's periodic security scanner runs 30+ checks against the host system, producing **Pass**, **Warn**, or **Fail** results that feed into the alert pipeline.

## Table of Contents

- [Overview](#overview)
- [ScanResult System](#scanresult-system)
- [Scan Interval](#scan-interval)
- [All Scanners](#all-scanners)
  - [Core Security](#core-security)
  - [System Hardening](#system-hardening)
  - [Process & Resource Monitoring](#process--resource-monitoring)
  - [Network & DNS](#network--dns)
  - [User & Access Control](#user--access-control)
  - [Package & File Integrity](#package--file-integrity)
  - [Cognitive Integrity](#cognitive-integrity)
  - [OpenClaw-Specific](#openclaw-specific)
- [SecureClaw Pattern Engine](#secureclaw-pattern-engine)
- [Adding New Scanners](#adding-new-scanners)

---

## Overview

The scanner lives in `src/scanner.rs`. On a configurable interval, `run_periodic_scans()` spawns a blocking task that calls `SecurityScanner::run_all_scans()`, which invokes every `scan_*` function. Results are:

1. Stored in a `SharedScanResults` (Arc<Mutex<Vec<ScanResult>>>) for the API
2. Converted to `Alert`s — **Warn** → `Severity::Warning`, **Fail** → `Severity::Critical`
3. Sent through the alert pipeline via an `mpsc::Sender<Alert>`

**Pass** results are recorded but never generate alerts.

## ScanResult System

```rust
pub struct ScanResult {
    pub category: String,      // e.g. "firewall", "auditd"
    pub status: ScanStatus,    // Pass | Warn | Fail
    pub details: String,       // Human-readable findings
    pub timestamp: DateTime<Local>,
}
```

| Status | Alert Severity | Meaning |
|--------|---------------|---------|
| **Pass** | *(none)* | Check passed, no action needed |
| **Warn** | Warning | Degraded posture, should investigate |
| **Fail** | Critical | Security control missing or broken, act immediately |

---

## Scan Interval

Configured via the `interval_secs` parameter passed to `run_periodic_scans()`. Set in your ClawAV config file (typically `/etc/clawav/config.toml`). The scanner sleeps for `interval_secs` between full scan cycles.

Each individual command has a 30-second timeout (`DEFAULT_CMD_TIMEOUT`).

---

## All Scanners

### Core Security

#### `scan_firewall()`
**Category:** `firewall`

Checks UFW firewall status and rule count.

| Status | Condition |
|--------|-----------|
| Pass | UFW active with ≥1 rule |
| Warn | UFW active but zero rules |
| Fail | UFW inactive or cannot be checked |

**Remediation:** `sudo ufw enable && sudo ufw default deny incoming`

---

#### `scan_auditd()`
**Category:** `auditd`

Checks auditd status and immutability flag.

| Status | Condition |
|--------|-----------|
| Pass | enabled=2 (immutable) with rules loaded |
| Warn | enabled=1 (mutable) or immutable with no rules |
| Fail | enabled=0 or cannot check |

**Remediation:** Set `enabled 2` in audit rules and load rules with `sudo auditctl -R /etc/audit/rules.d/audit.rules`

---

#### `scan_integrity()`
**Category:** `integrity`

Verifies SHA-256 checksums of ClawAV binary and config against `/etc/clawav/checksums.sha256`.

| Status | Condition |
|--------|-----------|
| Pass | All hashes match baseline |
| Warn | No checksums file exists (no baseline) |
| Fail | Hash mismatch or file missing |

**Remediation:** If legitimate update: `clawav --store-checksums`. If unexpected: investigate tampering.

---

#### `scan_immutable_flags()`
**Category:** `immutable_flags`

Checks `chattr +i` on critical files: binary, config, admin key hash, service file, sudoers deny.

| Status | Condition |
|--------|-----------|
| Pass | All critical files have immutable flag |
| Fail | Missing immutable flag or missing files |

**Remediation:** `sudo chattr +i /usr/local/bin/clawav /etc/clawav/config.toml ...`

---

#### `scan_apparmor_protection()`
**Category:** `apparmor_protection`

Checks if AppArmor profiles for OpenClaw restriction and config protection are loaded.

| Status | Condition |
|--------|-----------|
| Pass | Both profiles loaded, or AppArmor not available (optional) |
| Warn | Partial profiles or cannot check |

**Remediation:** `sudo scripts/setup-apparmor.sh`

---

#### `scan_secureclaw_sync()`
**Category:** `secureclaw`

Checks age of SecureClaw vendor pattern database via git log.

| Status | Condition |
|--------|-----------|
| Pass | Updated within 7 days, or vendor dir not present (embedded defaults) |
| Warn | Older than 7 days |
| Fail | Cannot check status |

**Remediation:** `scripts/sync-secureclaw.sh`

---

#### `scan_sidechannel_mitigations()`
**Category:** `sidechannel`

Reads `/sys/devices/system/cpu/vulnerabilities/` for Spectre, Meltdown, MDS, Retbleed, etc. (10 CVEs).

| Status | Condition |
|--------|-----------|
| Pass | All mitigations active or "Not affected" |
| Warn | Any "Vulnerable" status or missing files |

**Remediation:** Update kernel and firmware. Check BIOS/UEFI microcode settings.

---

### System Hardening

#### `scan_ssh()`
**Category:** `ssh`

Checks if SSH daemon is running.

| Status | Condition |
|--------|-----------|
| Pass | SSH not active |
| Warn | SSH daemon is running |

**Remediation:** `sudo systemctl disable --now ssh` (use Tailscale/VPN instead)

---

#### `scan_listening_services()`
**Category:** `listening`

Lists TCP listeners, flags anything not on the expected ports list (default: only 18791 for ClawAV API).

| Status | Condition |
|--------|-----------|
| Pass | Only expected ports listening |
| Warn | Unexpected listeners found |

**Remediation:** Investigate and stop unauthorized services.

---

#### `scan_password_policy()`
**Category:** `password_policy`

Checks `/etc/login.defs` for PASS_MAX_DAYS (≤90) and PAM for pam_pwquality/pam_cracklib.

| Status | Condition |
|--------|-----------|
| Pass | Reasonable expiry and quality checks configured |
| Warn | Expiry too long (>90 days/99999) or no quality module |

**Remediation:** Set `PASS_MAX_DAYS 90` in `/etc/login.defs`; install `libpam-pwquality`.

---

#### `scan_systemd_hardening()`
**Category:** `systemd_hardening`

Checks ClawAV service file (`/etc/systemd/system/clawav.service`) for 8 security directives: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictRealtime`, `MemoryDenyWriteExecute`.

| Status | Condition |
|--------|-----------|
| Pass | All 8 directives present |
| Warn | Any missing directives or service file not found |

**Remediation:** Add missing directives to the `[Service]` section and `systemctl daemon-reload`.

---

#### `scan_swap_tmpfs_security()`
**Category:** `swap_tmpfs`

Checks swap encryption, `/tmp` mount options (noexec, nosuid, nodev), and `/dev/shm` noexec.

| Status | Condition |
|--------|-----------|
| Pass | All tmpfs/swap security good |
| Warn | Missing mount options or unencrypted swap |

**Remediation:** Add `noexec,nosuid,nodev` to `/tmp` in `/etc/fstab`; encrypt swap.

---

#### `scan_core_dump_settings()`
**Category:** `core_dumps`

Checks core dump configuration: systemd-coredump, ulimit, `/proc/sys/kernel/core_pattern`, and recent dumps.

| Status | Condition |
|--------|-----------|
| Pass | Core dumps disabled |
| Warn | Core dumps enabled or recent dumps found |

**Remediation:** Set `kernel.core_pattern=|/bin/false` in sysctl; disable systemd-coredump.

---

#### `scan_docker_security()`
**Category:** `docker_security`

If Docker is running: checks for privileged containers, world-writable socket, host-network containers.

| Status | Condition |
|--------|-----------|
| Pass | Docker not running, or no issues found |
| Warn | Privileged containers, exposed socket, or host networking |

**Remediation:** Remove `--privileged`; restrict docker socket permissions; use bridge networking.

---

#### `scan_kernel_modules()`
**Category:** `kernel_modules`

Lists loaded kernel modules, flags suspicious names (rootkit, backdoor, keylog, etc.).

| Status | Condition |
|--------|-----------|
| Pass | Normal module count, no suspicious names |
| Warn | >100 modules loaded or cannot check |
| Fail | Suspicious module names detected |

**Remediation:** Investigate and `sudo modprobe -r <module>`; add to module blacklist.

---

### Process & Resource Monitoring

#### `scan_resources()`
**Category:** `resources`

Checks root filesystem disk usage.

| Status | Condition |
|--------|-----------|
| Pass | Usage ≤90% |
| Warn | Usage >90% |

**Remediation:** Free disk space or expand partition.

---

#### `scan_zombie_processes()`
**Category:** `process_health`

Scans `ps aux` for zombie processes (stat=Z) and high CPU (>80%) processes.

| Status | Condition |
|--------|-----------|
| Pass | No zombies or high-CPU processes |
| Warn | Zombies or runaway processes found |

**Remediation:** Kill parent of zombie processes; investigate high-CPU processes.

---

#### `scan_open_file_descriptors()`
**Category:** `open_fds`

Checks for suspicious network connections (IRC ports, backdoor ports) and processes with >1000 open FDs.

| Status | Condition |
|--------|-----------|
| Pass | Normal FD usage |
| Warn | Suspicious connections or FD-heavy processes |

**Remediation:** Investigate connections on ports 6667, 6697, 4444, 1234.

---

#### `scan_updates()`
**Category:** `updates`

Counts pending apt packages.

| Status | Condition |
|--------|-----------|
| Pass | ≤10 pending updates |
| Warn | >10 pending updates |

**Remediation:** `sudo apt update && sudo apt upgrade`

---

#### `scan_ntp_sync()`
**Category:** `ntp_sync`

Checks NTP synchronization via timedatectl, ntp, or chronyd.

| Status | Condition |
|--------|-----------|
| Pass | NTP synchronized and enabled |
| Warn | NTP enabled but not synced, or no NTP service |

**Remediation:** `sudo timedatectl set-ntp true`

---

### Network & DNS

#### `scan_dns_resolver()`
**Category:** `dns_resolver`

Parses `/etc/resolv.conf` for nameservers and suspicious search domains.

| Status | Condition |
|--------|-----------|
| Pass | Standard nameservers configured |
| Warn | Unusual DNS servers or suspicious search domains |
| Fail | No nameservers or can't read resolv.conf |

**Remediation:** Verify DNS servers are trusted; remove suspicious search domains.

---

#### `scan_network_interfaces()`
**Category:** `network_interfaces`

Checks for promiscuous mode, tunnel/tap interfaces, IP forwarding, and suspicious routes.

| Status | Condition |
|--------|-----------|
| Pass | Normal interface configuration |
| Warn | Promiscuous mode, tunnels, or IP forwarding enabled |

**Remediation:** Disable IP forwarding: `sysctl net.ipv4.ip_forward=0`; investigate promiscuous interfaces.

---

### User & Access Control

#### `scan_user_account_audit()`
**Category:** `user_accounts`

Checks for non-root UID 0 users, passwordless accounts with shell access, excessive regular users, and many sudo users.

| Status | Condition |
|--------|-----------|
| Pass | Clean account configuration |
| Warn | Any of the above anomalies |

**Remediation:** Remove non-root UID 0; lock unused accounts; audit sudo group membership.

---

#### `scan_failed_login_attempts()`
**Category:** `failed_logins`

Counts failed SSH passwords in the last 24h via journalctl and auth.log. Flags successful logins after many failures (brute force indicator).

| Status | Condition |
|--------|-----------|
| Pass | ≤10 failed attempts |
| Warn | >10 failed attempts, or success-after-failure pattern |

**Remediation:** Install fail2ban; consider key-only SSH auth; investigate successful logins after brute force.

---

#### `scan_crontab_audit()`
**Category:** `crontab_audit`

Scans user and system crontabs for suspicious commands: wget, curl, nc, /dev/tcp, python -c, base64.

| Status | Condition |
|--------|-----------|
| Pass | No suspicious cron entries |
| Fail | Suspicious commands found in cron |

**Remediation:** Review and remove suspicious cron entries; audit who created them.

---

### Package & File Integrity

#### `scan_world_writable_files()`
**Category:** `world_writable`

Finds world-writable files in /etc, /usr/bin, /usr/sbin, /bin, /sbin, /var/log.

| Status | Condition |
|--------|-----------|
| Pass | None found |
| Warn | 1–10 found |
| Fail | >10 found |

**Remediation:** `chmod o-w <file>` on each world-writable file.

---

#### `scan_suid_sgid_binaries()`
**Category:** `suid_sgid`

Finds all SUID/SGID files system-wide, compares against a known-safe list (sudo, su, passwd, mount, ping, etc.).

| Status | Condition |
|--------|-----------|
| Pass | All SUID/SGID files are known-safe |
| Warn | Unknown SUID/SGID binaries found |

**Remediation:** `chmod u-s <file>` on unnecessary SUID binaries; investigate unknown ones.

---

#### `scan_package_integrity()`
**Category:** `package_integrity`

Runs `dpkg --verify` (or `rpm -Va`) to detect modified package files. Also flags >2000 installed packages.

| Status | Condition |
|--------|-----------|
| Pass | All packages intact |
| Warn | Modified package files or high package count |

**Remediation:** Reinstall modified packages: `sudo apt install --reinstall <package>`

---

#### `scan_environment_variables()`
**Category:** `environment_vars`

Checks for suspicious `LD_PRELOAD`, `LD_LIBRARY_PATH` containing /tmp, proxy/tor settings, debug flags, and credentials in env vars (KEY/SECRET/TOKEN).

| Status | Condition |
|--------|-----------|
| Pass | Clean environment |
| Warn | Suspicious variables detected |

**Remediation:** Remove suspicious env vars; rotate any exposed credentials.

---

### Cognitive Integrity

#### `scan_cognitive_integrity()` *(in `src/cognitive.rs`)*

Verifies SHA-256 hashes of AI identity files (SOUL.md, AGENTS.md, etc.) against `/etc/clawav/cognitive-baselines.sha256`. Also runs SecureClaw pattern scans on file content for injection attempts.

| Status | Condition |
|--------|-----------|
| Pass | All cognitive files match baseline |
| Warn | Files changed from baseline |
| Fail | Injection patterns detected in identity files |

**Remediation:** Verify changes are legitimate; update baselines with `clawav --store-cognitive-baselines`.

---

#### `scan_audit_log_health()` *(in `src/logtamper.rs`)*

Checks audit log file existence, permissions, and health at `/var/log/audit/audit.log`.

---

### OpenClaw-Specific

#### `scan_openclaw_security()`

Returns multiple results covering OpenClaw gateway configuration:

| Check | Category | What it verifies |
|-------|----------|-----------------|
| **Gateway binding** | `openclaw:gateway` | Gateway bound to loopback (127.0.0.1), not 0.0.0.0 |
| **Authentication** | `openclaw:auth` | Token auth enabled (not mode=none) |
| **Filesystem scope** | `openclaw:filesystem` | Workspace scoped to /home/*, not / |
| **Tunnel/VPN** | `openclaw:tunnel` | Tailscale, SSH tunnel, or Connectify detected for remote access |

**Pass:** Loopback binding, auth enabled, scoped workspace, VPN active.
**Warn:** Unclear config or no VPN detected.
**Fail:** Public binding, auth disabled, or workspace set to `/`.

**Remediation:**
- Bind to loopback: set `"bind": "127.0.0.1"` in `openclaw.json`
- Enable auth: configure token-based auth
- Scope workspace: set to `/home/openclaw/.openclaw/workspace`
- Use Tailscale or SSH tunnel for remote access

---

## SecureClaw Pattern Engine

The SecureClaw engine (`src/secureclaw.rs`) loads regex-based threat patterns from JSON files and compiles them at startup for fast matching.

### Four Pattern Databases

| Database | File | Purpose | Default Action |
|----------|------|---------|---------------|
| **Injection Patterns** | `injection-patterns.json` | Prompt injection, code injection | WARN |
| **Dangerous Commands** | `dangerous-commands.json` | Categorized dangerous shell commands with severity | Per-category (BLOCK/REQUIRE_APPROVAL) |
| **Privacy Rules** | `privacy-rules.json` | PII detection, credential patterns | Per-rule (REMOVE/WARN) |
| **Supply Chain IOCs** | `supply-chain-ioc.json` | Suspicious skill patterns, ClawHavoc C2 indicators | BLOCK |

### How Patterns Are Loaded

1. `SecureClawEngine::load(config_dir)` reads 4 JSON files from the vendor directory
2. Each regex string is compiled to a `regex::Regex` at load time (invalid patterns are skipped with a warning)
3. Compiled patterns are stored as `CompiledPattern` structs with name, category, severity, regex, and action
4. The engine provides `check_text()`, `check_command()`, and `check_privacy()` methods

### Command Checking

`check_command()` has special logic beyond raw pattern matching:
- **Sudo allowlist** — ~100 known-safe sudo prefixes (ufw, systemctl, apt, journalctl, etc.) that won't trigger `permission_escalation` alerts
- **Crontab exclusions** — `crontab -l` (read-only) and crontab mentioned in grep/ps commands are skipped
- **Word-boundary checks** — "sudo" as part of a larger word (e.g. "clawsudo") is ignored
- **AWS CLI skip** — sudo in AWS CLI remote command payloads is ignored

### JSON File Formats

**injection-patterns.json:**
```json
{
  "version": "2.0.0",
  "patterns": {
    "category_name": ["regex1", "regex2"]
  }
}
```

**dangerous-commands.json:**
```json
{
  "version": "2.0.0",
  "categories": {
    "category_name": {
      "severity": "critical",
      "action": "block",
      "patterns": ["regex1", "regex2"]
    }
  }
}
```

**privacy-rules.json:**
```json
{
  "version": "2.0.0",
  "rules": [
    { "id": "rule_name", "regex": "pattern", "severity": "high", "action": "remove" }
  ]
}
```

**supply-chain-ioc.json:**
```json
{
  "version": "2.0.0",
  "suspicious_skill_patterns": ["regex1"],
  "clawhavoc": {
    "name_patterns": ["regex1"],
    "c2_servers": ["exact.domain.com"]
  }
}
```

### Adding Custom Patterns

1. Edit the appropriate JSON file in your vendor/config directory
2. Add your regex pattern to the relevant category or create a new one
3. Restart ClawAV — patterns are loaded at startup
4. Test with: write a unit test calling `engine.check_command("your test input")`

C2 server entries in `supply-chain-ioc.json` are auto-escaped (treated as literal strings, not regex).

---

## Adding New Scanners

### Step-by-Step

1. **Add the function** in `src/scanner.rs`:

```rust
pub fn scan_my_new_check() -> ScanResult {
    // Run system commands with timeout
    match run_cmd("some-tool", &["--flag"]) {
        Ok(output) => {
            if output.contains("bad thing") {
                ScanResult::new(
                    "my_check",           // category (used in alert source as "scan:my_check")
                    ScanStatus::Fail,
                    "Description of failure",
                )
            } else {
                ScanResult::new("my_check", ScanStatus::Pass, "All good")
            }
        }
        Err(e) => ScanResult::new(
            "my_check",
            ScanStatus::Warn,
            &format!("Cannot run check: {}", e),
        ),
    }
}
```

2. **Register it** in `SecurityScanner::run_all_scans()`:

```rust
pub fn run_all_scans() -> Vec<ScanResult> {
    let mut results = vec![
        // ... existing scans ...
        scan_my_new_check(),  // Add here
    ];
    // ...
}
```

3. **Add tests**:

```rust
#[test]
fn test_my_new_check_logic() {
    // Test your parsing logic with known inputs
    // Use helper functions (like parse_ufw_status) for testability
}
```

### Helpers Available

| Helper | Purpose |
|--------|---------|
| `run_cmd(cmd, args)` | Run command with 30s timeout |
| `run_cmd_timeout(cmd, args, secs)` | Run command with custom timeout |
| `run_cmd_with_sudo(cmd, args)` | Try without sudo first, fall back to sudo |
| `ScanResult::new(category, status, details)` | Create a result |
| `compute_file_sha256(path)` | SHA-256 hash a file |

### Conventions

- Category names use `snake_case` (appears in alerts as `scan:<category>`)
- Return `Warn` (not `Fail`) when a tool is unavailable — missing tools ≠ security failure
- For scanners returning multiple results, return `Vec<ScanResult>` and use `results.extend()`
- Keep individual scan functions quick (<30s) — they run sequentially
