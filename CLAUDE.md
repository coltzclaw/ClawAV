# CLAUDE.md — ClawTower LLM Onboarding Guide

> **Rule:** Never include "Generated with Claude Code" or similar AI attribution lines in commit messages, PR descriptions, or any output.

> **ClawTower** is a tamper-proof, OS-level security watchdog for AI agents. It monitors the host system for threats, policy violations, and tampering — then alerts via TUI dashboard and Slack. It is designed so that even the AI agent it protects **cannot disable or modify it** (the "swallowed key" pattern).

---

## Project Overview

ClawTower continuously monitors a Linux host where an AI agent (e.g., OpenClaw) runs. It watches for:

- **Command execution** via auditd log tailing (syscalls, EXECVE records)
- **Behavioral threats** — data exfiltration, privilege escalation, reconnaissance, side-channel attacks, container escapes, persistence mechanisms, financial theft
- **File integrity** — real-time inotify-based sentinel + periodic cognitive file baselines
- **Firewall/network** — UFW state changes, iptables log parsing, network policy enforcement
- **Log tampering** — detects truncation, deletion, or inode replacement of audit logs
- **Security posture** — 30+ periodic system scans (see `.docs/SECURITY-SCANNERS.md`)

### The "Swallowed Key" Pattern

Critical files are protected with `chattr +i` (immutable). The admin key (`OCAV-` + 64 hex, Argon2-hashed) is generated once, displayed, and never stored. The AI agent cannot stop ClawTower, modify its config, remove immutable flags, or escalate via sudo.

**How it actually works:** `chattr +i` is a Linux ext4 file attribute that prevents even root from modifying or deleting the file until the flag is removed. That's the entire enforcement mechanism. But root can always run `chattr -i` to remove it — so the real defense is that the AI agent doesn't have direct root access (it goes through clawsudo, which denies `chattr` on ClawTower files).

### Binaries

- **`clawtower`** — Main watchdog binary (TUI dashboard, headless daemon, scanner, updater)
- **`clawsudo`** — Sudo proxy/gatekeeper that evaluates commands against YAML policies before allowing `sudo` execution

---

## Architecture

Binary crate only (`src/main.rs`), no `lib.rs`. All modules declared as `mod` in `main.rs`.

### Event Pipeline

```
Sources (auditd, network, falco, samhain, SSH, firewall, scanner, sentinel, proxy)
    │
    ▼ raw_tx (mpsc::channel<Alert>, cap=1000)
    │
    ▼ Aggregator (dedup + rate limiting)
    │
    ├──▶ alert_tx → TUI (render in dashboard)
    ├──▶ slack_tx → SlackNotifier (webhook)
    ├──▶ api_store → HTTP API (/api/alerts, /api/security)
    └──▶ audit.chain (hash-linked JSONL log)
```

**Runtime:** Tokio async. Root escalation in `main()` before tokio starts. Each source is a `tokio::spawn`ed task. Blocking scans use `spawn_blocking`.

### Module List

Modules are organized into directories under `src/`. A few top-level files remain in `src/` directly.

#### Top-level (`src/`)

| Module | Purpose |
|--------|---------|
| `main.rs` | Entry point, CLI dispatch, spawns all tasks, wires channels |
| `cli.rs` | CLI argument parsing and subcommand definitions |

#### `agent/` — AI agent integration

| Module | Purpose |
|--------|---------|
| `profile.rs` | Agent profile definitions and management |
| `envelope.rs` | Agent message envelope types |
| `identity.rs` | Agent identity verification |
| `auth_hooks.rs` | Authentication hook integrations |

#### `behavior/` — Behavioral threat detection rules

| Module | Purpose |
|--------|---------|
| `mod.rs` | Behavioral detection orchestration and `classify_behavior()` |
| `exfiltration.rs` | Data exfiltration detection patterns |
| `financial.rs` | Financial theft detection patterns |
| `patterns.rs` | Shared pattern constants and safe host lists |
| `privilege.rs` | Privilege escalation detection patterns |
| `recon.rs` | Reconnaissance detection patterns |
| `social.rs` | Social engineering detection patterns |
| `tamper.rs` | Tampering detection patterns |
| `tests.rs` | Behavioral detection test suite |

#### `config/` — Configuration loading and management

| Module | Purpose |
|--------|---------|
| `mod.rs` | TOML config deserialization (`Config` struct with all sections) |
| `merge.rs` | TOML config merge engine with `_add`/`_remove` list semantics for config.d/ overlays |
| `cloud.rs` | Cloud provider configuration |
| `openclaw.rs` | OpenClaw-specific configuration |
| `export.rs` | Configuration export utilities |

#### `core/` — Core infrastructure and runtime

| Module | Purpose |
|--------|---------|
| `mod.rs` | Core module re-exports |
| `alerts.rs` | `Alert`, `Severity`, `AlertStore` ring buffer types |
| `aggregator.rs` | Deduplication (fuzzy shape matching), per-source rate limiting |
| `admin.rs` | Admin key generation (Argon2), verification, Unix socket for authenticated commands |
| `audit_chain.rs` | Hash-linked integrity log (SHA-256 chain, tamper-evident) |
| `app_state.rs` | Shared application state |
| `orchestrator.rs` | Task orchestration and lifecycle management |
| `response.rs` | Automated response actions |
| `readiness.rs` | Service readiness checks |
| `risk_latch.rs` | Risk level latch (monotonic escalation) |
| `update.rs` | Self-updater (GitHub releases, SHA-256 + Ed25519 signature verification, chattr dance) |
| `util.rs` | Shared utility functions |

#### `detect/` — Detection engines and analysis

| Module | Purpose |
|--------|---------|
| `mod.rs` | Detection module orchestration |
| `behavior_adapter.rs` | Adapter bridging behavior rules into the detection pipeline |
| `traits.rs` | Detection engine trait definitions |
| `compliance.rs` | Compliance report generation (SOC 2, NIST 800-53, CIS Controls v8) |
| `cognitive.rs` | Cognitive file protection — SHA-256 baselines for identity files (SOUL.md, etc.) |
| `correlator.rs` | Cross-source event correlation |
| `forensics.rs` | Forensic analysis utilities |
| `barnacle.rs` | Pattern engine loading 4 JSON databases (injection, dangerous commands, privacy, supply chain) |
| `prompt_firewall.rs` | LLM prompt injection detection |
| `detector_runner.rs` | Detection engine runner and scheduling |
| `registry.rs` | Detection engine registry |

#### `enforcement/` — OS-level sandboxing

| Module | Purpose |
|--------|---------|
| `mod.rs` | Enforcement module orchestration |
| `capabilities.rs` | Linux capabilities management |
| `process_cage.rs` | Process sandboxing via namespaces/cgroups |
| `seccomp.rs` | Seccomp BPF filter management |
| `apparmor.rs` | AppArmor profile management |

#### `interface/` — External interfaces (API, Slack, TUI client)

| Module | Purpose |
|--------|---------|
| `api.rs` | HTTP API server (hyper, endpoints: `/api/status`, `/api/alerts`, `/api/security`, `/api/health`) |
| `slack.rs` | Slack webhook notifier (primary + backup webhook, heartbeat) |
| `tui_client.rs` | TUI client connection handling |

#### `policy/` — Policy engines

| Module | Purpose |
|--------|---------|
| `rules.rs` | YAML-based policy engine for detection (match criteria, actions, allowlisting) |
| `network.rs` | Network policy enforcement (allowlist/blocklist mode for outbound connections) |

#### `proxy/` — API key proxy

| Module | Purpose |
|--------|---------|
| `mod.rs` | API key proxy with DLP scanning (virtual-to-real key mapping, SSN/credit card/AWS key detection) |

#### `safe/` — Safe wrappers for system operations

| Module | Purpose |
|--------|---------|
| `safe_cmd.rs` | Safe command execution with timeouts |
| `safe_io.rs` | Safe I/O operations |
| `safe_match.rs` | Safe pattern matching utilities |
| `safe_tail.rs` | Safe file tailing |

#### `scanner/` — Periodic security scanners

| Module | Purpose |
|--------|---------|
| `mod.rs` | Scanner orchestration and `SecurityScanner::run_all_scans()` |
| `user_accounts.rs` | User account security scans |
| `filesystem.rs` | Filesystem security scans (SUID, world-writable, etc.) |
| `hardening.rs` | System hardening checks |
| `helpers.rs` | Shared scanner helper functions |
| `network.rs` | Network security scans |
| `process.rs` | Process health scans |

#### `sentinel/` — Real-time file integrity monitoring

| Module | Purpose |
|--------|---------|
| `mod.rs` | Real-time file watching via `notify` (inotify), shadow copies, quarantine, content scanning |
| `intake.rs` | Sentinel event intake and processing |
| `shadow.rs` | Shadow copy management |

#### `sources/` — Monitoring data sources

| Module | Purpose |
|--------|---------|
| `mod.rs` | Source module orchestration |
| `traits.rs` | Source trait definitions |
| `auditd.rs` | Audit log parser (SYSCALL/EXECVE/AVC records), aarch64 syscall table, user filtering |
| `falco.rs` | Falco JSON log parser (eBPF-based syscall monitoring) |
| `samhain.rs` | Samhain FIM log parser |
| `journald.rs` | Journalctl-based log sources (kernel messages for network, SSH login events) |
| `network.rs` | iptables log line parser, CIDR/port allowlisting |
| `firewall.rs` | Periodic UFW status monitoring with diff-based change detection |
| `logtamper.rs` | Audit log integrity monitor (size decrease, inode change, permissions) |
| `memory_sentinel.rs` | Memory-based sentinel monitoring |

#### `tui/` — Terminal UI dashboard

| Module | Purpose |
|--------|---------|
| `mod.rs` | Ratatui TUI dashboard (6 tabs: Alerts, Network, Falco, FIM, System, Config editor) |
| `config_editor.rs` | TUI configuration editor tab |

#### `bin/` — Standalone binaries

| Module | Purpose |
|--------|---------|
| `clawsudo.rs` | Standalone sudo gatekeeper binary with YAML policy evaluation and Slack approval flow |
| `clawtower-ctl.rs` | ClawTower control utility |
| `clawtower-tray.rs` | System tray integration |

#### `testing/` — Cross-module test suites (`#[cfg(test)]` only)

| Module | Purpose |
|--------|---------|
| `adversarial.rs` | Adversarial attack pattern simulations |
| `integration.rs` | Cross-module integration tests |
| `benchmarks.rs` | Lightweight performance benchmarks |

For detailed module internals, see `.docs/ARCHITECTURE.md` and `.docs/MONITORING-SOURCES.md`.

---

## Key Patterns & Gotchas

### Alert Pipeline

Sources `clone()` `raw_tx` and send `Alert`s. The `Aggregator` deduplicates (fuzzy shape matching — digits replaced with `#`, 30s window, 1h for scans, 5s for Critical), rate-limits (20/source/60s, Critical bypasses), and fans out to TUI, Slack, API store, and audit chain.

### Config Layering

- **Config:** base `config.toml` + `config.d/*.toml` overlays (scalar replace, list `_add`/`_remove`). See `config/merge.rs`.
- **Policies:** `default.yaml` loaded first, then alphabetical `*.yaml` files merged by rule name. `enabled: false` disables a rule.
- Updates replace base files, never touch user overrides.

### watched_users Takes UIDs, Not Usernames

`watched_users = ["1000"]` — numeric UIDs matched against auditd `uid=`/`auid=` fields. Find with `id -u <username>`.

### iptables Log Prefix Must Match Exactly

The `[network] log_prefix` in config **must exactly match** the `--log-prefix` in iptables rules from `setup-iptables.sh`. A mismatch silently drops all network alerts.

### Sentinel Policies

- **Protected**: quarantine modified file → restore from shadow → Critical alert
- **Watched**: update shadow copy → Info alert with diff

### Cognitive File Protection

- **Protected** (CRIT on change): `SOUL.md`, `IDENTITY.md`, `TOOLS.md`, `AGENTS.md`, `USER.md`, `HEARTBEAT.md`
- **Watched** (INFO with diff, auto-rebaseline): `MEMORY.md`

### Scanner Conventions

- `ScanResult` has category (snake_case), status (`Pass`/`Warn`/`Fail`), details
- `ScanResult::to_alert()` converts `Warn`→Warning, `Fail`→Critical; `Pass` produces no alert
- Function names and categories sometimes differ (e.g., `scan_zombie_processes()` → `"process_health"`)

### clawsudo (bin/clawsudo.rs)

Standalone sudo gatekeeper. Fail-secure: no rules → deny all. Exit codes: 0 (ok), 1 (fail), 77 (denied), 78 (timeout).

### Grouped `use` Imports Hide from Simple Greps

When refactoring module paths, `use crate::{netpolicy, proxy, ...}` does **not** match a grep for `crate::netpolicy`. Always search for the bare module name (e.g., `netpolicy::`) in addition to the fully-qualified path when doing import refactoring.

---

## Configuration

Config file: `/etc/clawtower/config.toml`. Full reference with all fields, types, and defaults: `.docs/CONFIGURATION.md`.

**Config sections:** `general`, `slack`, `auditd`, `network`, `falco`, `samhain`, `ssh`, `api`, `scans`, `proxy`, `policy`, `barnacle`, `netpolicy`, `sentinel`, `auto_update`.

**Key methods:** `Config::load(path)`, `Config::save(path)`, `Config::load_with_overrides(base_path, config_d)`

All config section structs are public, `Deserialize + Serialize + Default`. Most in `config/mod.rs`; `BarnacleDefenseConfig` in `detect/barnacle.rs`.

---

## Testing

```bash
cargo test                    # All tests
cargo test -- --nocapture     # With stdout
cargo test test_name          # Specific test
```

Tests are inline `#[cfg(test)] mod tests` in each module. Dev dependency: `tempfile = "3"`.

**PATH note:** If `cargo` is not found, source the Rust environment first: `export PATH="$HOME/.cargo/bin:$PATH"` (or `source "$HOME/.cargo/env"`).

---

## Build & Deploy

```bash
cargo build --release         # Release (strip=true, lto=true, opt-level=z)
```

**CI:** `ci.yml` runs build + test + clippy on push/PR. `release.yml` cross-compiles for x86_64 + aarch64 on tag push, generates checksums, creates GitHub release.

**Release signing:** Ed25519 key embedded at `src/release-key.pub`. Auto-updater verifies `.sig` if present.

**Install:** `curl -sSL .../oneshot-install.sh | sudo bash` or `clawtower setup --source --auto`. Scripts in `scripts/` directory.

### Remote Deploy & Pentest

Two gitignored scripts automate deploying to the target machine (`claw` = `192.168.1.85`):

```bash
./scripts/deploy.sh           # Deploy ARM binary to remote (sshpass as jr, chattr dance)
./scripts/deploy.sh --build   # Cross-compile for aarch64 first, then deploy
./scripts/pentest.sh           # Ship & run latest Red Lobster suite as openclaw
./scripts/pentest.sh v7        # Run a specific version
./scripts/pentest.sh v8 flag15 # Pass args to run-all.sh
```

- `deploy.sh` cross-compiles for `aarch64-unknown-linux-gnu`, uploads binary + config + policies, stops the service, does the `chattr -i` → replace → `chattr +i` immutable dance, restarts. **Gitignored** (contains credentials).
- `pentest.sh` auto-detects the highest `redlobster-v*-run-all.sh`, ships all scripts for that version + `redlobster-lib.sh` to the remote, and runs as `openclaw`. **Gitignored** (contains credentials).

### Pre-Push Checklist

**Before pushing, always run deploy + pentest to verify on the target machine:**

```bash
cargo test                     # 1. Unit tests pass locally
cargo build --release --target aarch64-unknown-linux-gnu  # 2. Release build succeeds
./scripts/deploy.sh            # 3. Deploy to remote
./scripts/pentest.sh           # 4. Red Lobster pentest suite passes on remote
```

Do not push until steps 3 and 4 succeed. If the pentest reveals regressions, fix them before pushing.

---

## Common Tasks for LLMs

### Adding a New Scanner

1. Add scan function in the appropriate `src/scanner/` submodule (or create a new one) returning `ScanResult`:

```rust
pub fn scan_my_check() -> ScanResult {
    // Use run_cmd() for external commands (30s timeout), run_cmd_with_sudo() for privileged
    // Return ScanResult::new("my_check", ScanStatus::Pass|Warn|Fail, "details")
    // Use Warn (not Fail) when tools are unavailable
}
```

2. Register in `SecurityScanner::run_all_scans()` results vec
3. Add tests — category appears in alerts as `scan:my_check`

### Adding a New Monitoring Source

1. Create `src/sources/my_source.rs` with a `pub async fn tail_...(tx: mpsc::Sender<Alert>)` function
2. Add `pub mod my_source;` in `src/sources/mod.rs` and re-export as needed
3. Spawn in `async_main()`: `tokio::spawn(async move { sources::my_source::tail_...(raw_tx.clone()).await; });`
4. Optionally add config section (struct with `enabled: bool`, add to `Config`, gate spawn)

See `.docs/MONITORING-SOURCES.md` for full patterns and existing source implementations.

### Adding Sentinel Watch Paths

```toml
[[sentinel.watch_paths]]
path = "/path/to/file"
patterns = ["*"]
policy = "protected"  # or "watched"
```

To add compile-time defaults, modify `SentinelConfig::default()` in `src/config/mod.rs`.

### Modifying Alert Behavior

- **Dedup window**: `AggregatorConfig::default()` in `core/aggregator.rs`
- **Slack threshold**: `min_slack_level` in config
- **Behavior rule**: Add pattern to the appropriate `behavior/*.rs` submodule, handle in `classify_behavior()` in `behavior/mod.rs`
- **Safe host**: Add to `SAFE_HOSTS` in `behavior/patterns.rs`
- **Sudo allowlist**: Add to `BarnacleDefenseEngine::SUDO_ALLOWLIST` in `detect/barnacle.rs`
- **Policy rule**: Create/edit YAML in `policies/` directory

### Adding a New TUI Tab

1. Add tab title to `App::new()` `tab_titles` vec
2. Create `render_my_tab()` function
3. Add match arm in `ui()` function
4. Note: `sentinel`, `ssh`, `auto_update` are NOT exposed in the TUI config editor

---

## See Also

| Document | Description |
|----------|-------------|
| [`.docs/ARCHITECTURE.md`](.docs/ARCHITECTURE.md) | Module dependency graph, data flow diagrams, threat model |
| [`.docs/CONFIGURATION.md`](.docs/CONFIGURATION.md) | Full config reference — every field, type, default, and TOML example |
| [`.docs/ALERT-PIPELINE.md`](.docs/ALERT-PIPELINE.md) | Alert model, pipeline architecture, aggregator tuning |
| [`.docs/SENTINEL.md`](.docs/SENTINEL.md) | Real-time file integrity monitoring deep dive |
| [`.docs/SECURITY-SCANNERS.md`](.docs/SECURITY-SCANNERS.md) | All 30+ periodic security scanners |
| [`.docs/MONITORING-SOURCES.md`](.docs/MONITORING-SOURCES.md) | Every real-time data source (auditd, journald, falco, samhain, etc.) |
| [`.docs/POLICIES.md`](.docs/POLICIES.md) | YAML policy writing guide |
| [`.docs/CLAWSUDO-AND-POLICY.md`](.docs/CLAWSUDO-AND-POLICY.md) | clawsudo, admin key, audit chain, API proxy, LD_PRELOAD guard |
| [`.docs/API.md`](.docs/API.md) | HTTP REST API endpoints and response formats |
| [`.docs/INSTALL.md`](.docs/INSTALL.md) | Installation, hardening steps, CLI commands, recovery |
| [`.docs/openclaw-integration.md`](.docs/openclaw-integration.md) | OpenClaw security integration |