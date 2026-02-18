# Harden ClawTower Against OpenClaw Infostealer Threat

## Context

[Security Affairs article](https://securityaffairs.com/188097/malware/hackers-steal-openclaw-configuration-in-emerging-ai-agent-threat.html) reports infostealer malware exfiltrating OpenClaw files: `openclaw.json` (gateway tokens), `device.json` (private keys), and soul/memory files. The attack uses broad file-harvesting — **reads files without modifying them** — then uses stolen gateway tokens to impersonate the victim.

**Biggest gap:** `device.json` has **zero coverage** in ClawTower — not in sentinel, not in scanners, not in audit rules, not in behavior detection.

**Second gap:** No auditd rules for `device.json` or `openclaw.json` reads, meaning infostealers can silently read these credential files undetected (sentinel only catches modifications, not reads).

## Threat vs Current Protection

| Article Threat | Current Protection | Gap |
|---|---|---|
| `openclaw.json` stolen (gateway tokens) | Permissions (0o600), sentinel (Watched), config drift, hardcoded secrets scanner | No auditd read-watch — silent reads undetected |
| `device.json` stolen (private keys) | **NOTHING** | ZERO coverage across all layers |
| Soul/memory files stolen | Sentinel (Protected), SHA-256 cognitive baselines | Only detects modifications, not reads |
| Gateway token enables impersonation | Gateway bind check, auth mode check | Token read/exfil not detected |
| Broad file-harvesting | Behavioral detection for exfil tools (curl, scp, etc.) | No bulk-read correlation, no inotify read events |

---

## Changes (5 files)

### 1. behavior.rs:61 — Add to `AGENT_SENSITIVE_PATHS`

Add `device.json`, `settings.json`, `openclaw.json` to the array. This automatically gives coverage in:
- Interpreter credential access (python/node reading files → Critical)
- `script -c` wrapper detection → Critical
- Direct file reads via cat/less/cp/scp/tar/base64 → Critical

### 2. auditd.rs:37 — Add to `RECOMMENDED_AUDIT_RULES`

Insert after the `gateway.yaml` rule (line 37), before the system credential section (line 38):
```
-w /home/openclaw/.openclaw/device.json -p r -k clawtower_cred_read
-w /home/openclaw/.openclaw/openclaw.json -p r -k clawtower_cred_read
```
Uses existing `clawtower_cred_read` key — parser already handles these events, no changes needed in auditd parsing.

### 3. config.rs:535 — Add `device.json` sentinel watch

Insert after the `openclaw.json` watch (line 535), before `credentials` dir watch (line 536):
```rust
WatchPathConfig {
    path: "/home/openclaw/.openclaw/device.json".to_string(),
    patterns: vec!["*".to_string()],
    policy: WatchPolicy::Protected,  // Critical alert on modification
},
```
Note: Sentinel detects tampering (key replacement), not reads. Read detection is handled by auditd (Change 2).

### 4. scanner.rs — Two additions

**4a.** After line 2471 (`openclaw.json` permission check), add `device.json` permission check:
```rust
results.push(check_path_permissions(
    &format!("{}/device.json", state_dir), 0o600, "device_key"));
```

**4b.** New function `scan_openclaw_credential_audit()` after `scan_openclaw_version_freshness()` (line 2403). Runs `auditctl -l` and checks that read-watch rules exist for critical credential files (`device.json`, `openclaw.json`, `auth-profiles.json`, `gateway.yaml`, `.aws/credentials`, `.ssh/id_*`). Category: `openclaw:credential_audit`. Register at line 1938 after `scan_openclaw_version_freshness()`.

### 5. docs/openclaw-integration.md — Document new coverage

Add "Phase 4: Infostealer Defense" section and new alert categories (`openclaw:credential_audit`, `openclaw:perms:device_key`).

---

## What this does NOT address (acknowledged)

- **Bulk read detection** — Detecting "process reads 10+ credential files in 30s" needs time-windowed correlation. Separate effort.
- **Sentinel read-blindness** — inotify can't detect reads. Addressed by auditd, not sentinel.
- **Token value in network traffic** — DLP-style content inspection of outbound connections. Separate effort.

---

## Verification

1. `cargo test` — all existing + new tests pass
2. `cargo build --release --target aarch64-unknown-linux-gnu` — cross-compile succeeds
3. Deploy to target, verify `auditctl -l | grep device.json` shows the rule
4. `cat /home/openclaw/.openclaw/device.json` as agent → should trigger Critical via both auditd and behavior layers
5. New scanner shows `Pass` for `openclaw:credential_audit` when rules are installed
6. Pentest suite — no regressions
