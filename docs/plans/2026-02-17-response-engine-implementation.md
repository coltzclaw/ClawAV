# Response Engine Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a response engine that intercepts (gate) or reacts to security threats, holds them for human approval via Slack/TUI/API, and executes containment actions on approval or auto-denies on 2-minute timeout.

**Architecture:** New `src/response.rs` module (~600 lines) owns all response logic. Integrates with the aggregator output, TUI (popup), API (2 new endpoints), Slack (notification), proxy (hold/release), and clawsudo (upgraded Ask flow). Config additions in `src/config.rs`. Playbooks loaded from YAML files.

**Tech Stack:** Rust, tokio (channels, timers), serde/serde_yaml, uuid, hyper

**Important:** No `cargo` on this machine. Edit code, commit, push — CI handles the rest.

---

### Task 1: Add `uuid` dependency

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add uuid to dependencies**

After the `zeroize` line, add:

```toml
uuid = { version = "1", features = ["v4"] }
```

**Step 2: Commit**

```bash
git add Cargo.toml
git commit -m "chore: add uuid dependency for response engine"
```

---

### Task 2: Add response engine config to config.rs

**Files:**
- Modify: `src/config.rs`

**Step 1: Add ResponseConfig struct**

After the `NetPolicyConfig` struct, add:

```rust
/// Configuration for the response engine — automated threat containment with human approval.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseConfig {
    /// Enable the response engine.
    #[serde(default)]
    pub enabled: bool,

    /// Default timeout for human approval in seconds (default: 120 = 2 minutes).
    #[serde(default = "default_response_timeout")]
    pub timeout_secs: u64,

    /// What to do with Warning-level alerts. Options: "gate", "alert_only", "auto_deny".
    /// Critical alerts always use "gate" regardless of this setting.
    #[serde(default = "default_warning_mode")]
    pub warning_mode: String,

    /// Directory containing response playbook YAML files.
    #[serde(default = "default_playbook_dir")]
    pub playbook_dir: String,

    /// Message returned to agent when an action is denied.
    #[serde(default = "default_deny_message")]
    pub deny_message: String,
}

fn default_response_timeout() -> u64 { 120 }
fn default_warning_mode() -> String { "gate".to_string() }
fn default_playbook_dir() -> String { "/etc/clawtower/playbooks".to_string() }
fn default_deny_message() -> String {
    "Action blocked by ClawTower security policy. Contact administrator.".to_string()
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_response_timeout(),
            warning_mode: default_warning_mode(),
            playbook_dir: default_playbook_dir(),
            deny_message: default_deny_message(),
        }
    }
}
```

**Step 2: Add response field to Config struct**

In the main `Config` struct, add after `netpolicy`:

```rust
    #[serde(default)]
    pub response: ResponseConfig,
```

**Step 3: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): add ResponseConfig for response engine"
```

---

### Task 3: Create the core response engine module

**Files:**
- Create: `src/response.rs`

**Step 1: Write the full module**

```rust
//! Response Engine — automated threat containment with human approval.
//!
//! Evaluates alerts against playbooks, creates pending actions, and waits for
//! human approval via Slack, TUI, or API. Auto-denies on timeout (default 2 min).
//!
//! Two modes:
//! - **Gate**: action is held mid-flight (clawsudo, proxy). Agent blocks until resolved.
//! - **Reactive**: threat detected after the fact. Containment proposed.
//!
//! Critical alerts always require human approval. Warning behavior is configurable.

use crate::alerts::{Alert, Severity};
use crate::config::ResponseConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, oneshot};

// ── Core Types ───────────────────────────────────────────────────────────────

/// A pending action awaiting human approval.
#[derive(Clone, Serialize)]
pub struct PendingAction {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Which module detected the threat.
    pub threat_source: String,
    /// Human-readable description of the threat.
    pub threat_message: String,
    /// Alert severity.
    pub severity: Severity,
    /// Gate (action held) or Reactive (post-detection containment).
    pub mode: ResponseMode,
    /// Proposed containment actions.
    pub actions: Vec<ContainmentAction>,
    /// Which playbook matched, if any.
    pub playbook: Option<String>,
    /// When the pending action was created (serialized as elapsed secs for JSON).
    #[serde(skip)]
    pub created_at: Instant,
    /// How long to wait for approval.
    #[serde(skip)]
    pub timeout: Duration,
    /// Current status.
    pub status: PendingStatus,
}

/// Whether the response engine intercepted the action or is reacting after detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseMode {
    /// Action is held at a control point. Agent is blocked.
    Gate,
    /// Threat detected post-fact. Containment proposed.
    Reactive,
}

/// A containment action the response engine can execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainmentAction {
    KillProcess { pid: u32 },
    SuspendProcess { pid: u32 },
    DropNetwork { uid: u32 },
    RevokeApiKeys,
    FreezeFilesystem { paths: Vec<String> },
    LockClawsudo,
}

impl std::fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainmentAction::KillProcess { pid } => write!(f, "kill_process(pid={})", pid),
            ContainmentAction::SuspendProcess { pid } => write!(f, "suspend_process(pid={})", pid),
            ContainmentAction::DropNetwork { uid } => write!(f, "drop_network(uid={})", uid),
            ContainmentAction::RevokeApiKeys => write!(f, "revoke_api_keys"),
            ContainmentAction::FreezeFilesystem { paths } => write!(f, "freeze_filesystem({} paths)", paths.len()),
            ContainmentAction::LockClawsudo => write!(f, "lock_clawsudo"),
        }
    }
}

/// Current status of a pending action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingStatus {
    AwaitingApproval,
    Approved {
        by: String,
        message: Option<String>,
        surface: String,
    },
    Denied {
        by: String,
        message: Option<String>,
        surface: String,
    },
    Expired,
}

// ── Playbooks ────────────────────────────────────────────────────────────────

/// A response playbook — a preconfigured bundle of containment actions.
#[derive(Debug, Clone, Deserialize)]
pub struct Playbook {
    /// Human-readable name.
    pub name: String,
    /// Description of what this playbook does.
    pub description: String,
    /// Containment actions to propose (as string tags).
    pub actions: Vec<String>,
    /// Alert source/message patterns that trigger this playbook.
    pub trigger_on: Vec<String>,
}

/// Top-level playbook file structure.
#[derive(Debug, Deserialize)]
struct PlaybookFile {
    playbooks: HashMap<String, Playbook>,
}

/// Load playbooks from a directory of YAML files.
pub fn load_playbooks(dir: &Path) -> Vec<(String, Playbook)> {
    let mut result = Vec::new();
    if !dir.exists() {
        return result;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match serde_yaml::from_str::<PlaybookFile>(&content) {
                        Ok(file) => {
                            for (name, playbook) in file.playbooks {
                                result.push((name, playbook));
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: failed to parse playbook {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }
    result
}

// ── Gate Request (for clawsudo/proxy integration) ────────────────────────────

/// A gate request from clawsudo or the proxy, waiting for approval.
pub struct GateRequest {
    /// The pending action ID this gate is associated with.
    pub action_id: String,
    /// Channel to send the decision back to the blocked caller.
    pub reply_tx: oneshot::Sender<GateDecision>,
}

/// The decision for a gated request.
#[derive(Debug, Clone)]
pub enum GateDecision {
    Approved,
    Denied { reason: String },
}

// ── Response Engine ──────────────────────────────────────────────────────────

/// Shared state for pending actions, accessible from TUI, API, and Slack handlers.
pub type SharedPendingActions = Arc<Mutex<Vec<PendingAction>>>;

/// Create a new shared pending actions store.
pub fn new_shared_pending() -> SharedPendingActions {
    Arc::new(Mutex::new(Vec::new()))
}

/// Message sent to the response engine to request approval.
pub enum ResponseRequest {
    /// Evaluate an alert and create a pending action if it matches a playbook.
    EvaluateAlert(Alert),
    /// A gate request from clawsudo/proxy — block until approved or denied.
    GateAction {
        alert: Alert,
        actions: Vec<ContainmentAction>,
        reply_tx: oneshot::Sender<GateDecision>,
    },
    /// Resolve a pending action (approve or deny from any surface).
    Resolve {
        id: String,
        approved: bool,
        by: String,
        message: Option<String>,
        surface: String,
    },
}

/// Run the response engine as a long-lived tokio task.
///
/// Receives requests via `request_rx`, manages pending actions, sends notifications
/// via `slack_tx` and `tui_tx`, auto-expires after timeout.
pub async fn run_response_engine(
    mut request_rx: mpsc::Receiver<ResponseRequest>,
    slack_tx: mpsc::Sender<Alert>,
    pending_store: SharedPendingActions,
    config: ResponseConfig,
    playbooks: Vec<(String, Playbook)>,
) {
    // Map from pending action ID → gate reply channel (if gated)
    let mut gate_channels: HashMap<String, oneshot::Sender<GateDecision>> = HashMap::new();

    let timeout = Duration::from_secs(config.timeout_secs);
    let deny_message = config.deny_message.clone();

    loop {
        // Check for expired pending actions every 500ms
        let request = tokio::time::timeout(Duration::from_millis(500), request_rx.recv()).await;

        // Expire old pending actions
        {
            let mut pending = pending_store.lock().await;
            let now = Instant::now();
            for action in pending.iter_mut() {
                if matches!(action.status, PendingStatus::AwaitingApproval)
                    && now.duration_since(action.created_at) >= action.timeout
                {
                    action.status = PendingStatus::Expired;

                    // Notify gate channel if this was a gated request
                    if let Some(reply_tx) = gate_channels.remove(&action.id) {
                        let _ = reply_tx.send(GateDecision::Denied {
                            reason: format!("{} (approval timed out)", deny_message),
                        });
                    }

                    // Send expiry alert
                    let expiry_alert = Alert::new(
                        Severity::Warning,
                        "response",
                        &format!(
                            "Pending action expired (no human response in {}s): {} — {}",
                            config.timeout_secs, action.threat_source, action.threat_message
                        ),
                    );
                    let _ = slack_tx.send(expiry_alert).await;
                }
            }

            // Garbage collect resolved/expired actions older than 10 minutes
            pending.retain(|a| {
                matches!(a.status, PendingStatus::AwaitingApproval)
                    || now.duration_since(a.created_at) < Duration::from_secs(600)
            });
        }

        // Process incoming request
        let request = match request {
            Ok(Some(r)) => r,
            Ok(None) => break, // channel closed
            Err(_) => continue, // timeout, loop back to expire check
        };

        match request {
            ResponseRequest::EvaluateAlert(alert) => {
                // Skip if not critical or warning
                if alert.severity < Severity::Warning {
                    continue;
                }

                // Check warning mode
                if alert.severity == Severity::Warning && config.warning_mode == "alert_only" {
                    continue;
                }

                // Match against playbooks
                let matched = find_matching_playbook(&alert, &playbooks);

                if let Some((name, playbook)) = matched {
                    let actions = parse_containment_actions(&playbook.actions, &alert);
                    let id = uuid::Uuid::new_v4().to_string();

                    let pending_action = PendingAction {
                        id: id.clone(),
                        threat_source: alert.source.clone(),
                        threat_message: alert.message.clone(),
                        severity: alert.severity.clone(),
                        mode: ResponseMode::Reactive,
                        actions: actions.clone(),
                        playbook: Some(name.clone()),
                        created_at: Instant::now(),
                        timeout,
                        status: PendingStatus::AwaitingApproval,
                    };

                    // Store
                    {
                        let mut pending = pending_store.lock().await;
                        pending.push(pending_action);
                    }

                    // Send Slack notification
                    let actions_str: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
                    let notif = Alert::new(
                        Severity::Critical,
                        "response",
                        &format!(
                            "🚨 PENDING APPROVAL ({}s timeout) [{}]: {} — {} | Proposed: {} | Reply APPROVE-{} or DENY-{}",
                            config.timeout_secs, name, alert.source, alert.message,
                            actions_str.join(", "), id, id
                        ),
                    );
                    let _ = slack_tx.send(notif).await;
                }
            }

            ResponseRequest::GateAction { alert, actions, reply_tx } => {
                let id = uuid::Uuid::new_v4().to_string();

                let actions_str: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
                let pending_action = PendingAction {
                    id: id.clone(),
                    threat_source: alert.source.clone(),
                    threat_message: alert.message.clone(),
                    severity: alert.severity.clone(),
                    mode: ResponseMode::Gate,
                    actions: actions.clone(),
                    playbook: None,
                    created_at: Instant::now(),
                    timeout,
                    status: PendingStatus::AwaitingApproval,
                };

                // Store pending action and gate channel
                {
                    let mut pending = pending_store.lock().await;
                    pending.push(pending_action);
                }
                gate_channels.insert(id.clone(), reply_tx);

                // Slack notification
                let notif = Alert::new(
                    Severity::Critical,
                    "response",
                    &format!(
                        "🔒 GATED ACTION ({}s timeout): {} — {} | Actions: {} | Reply APPROVE-{} or DENY-{}",
                        config.timeout_secs, alert.source, alert.message,
                        actions_str.join(", "), id, id
                    ),
                );
                let _ = slack_tx.send(notif).await;
            }

            ResponseRequest::Resolve { id, approved, by, message, surface } => {
                let mut pending = pending_store.lock().await;
                if let Some(action) = pending.iter_mut().find(|a| a.id == id) {
                    if !matches!(action.status, PendingStatus::AwaitingApproval) {
                        continue; // already resolved
                    }

                    if approved {
                        action.status = PendingStatus::Approved {
                            by: by.clone(),
                            message: message.clone(),
                            surface: surface.clone(),
                        };

                        // Execute containment actions
                        for containment in &action.actions {
                            execute_containment(containment).await;
                        }

                        // Release gate if present
                        if let Some(reply_tx) = gate_channels.remove(&id) {
                            let _ = reply_tx.send(GateDecision::Approved);
                        }
                    } else {
                        action.status = PendingStatus::Denied {
                            by: by.clone(),
                            message: message.clone(),
                            surface: surface.clone(),
                        };

                        // Deny gate if present
                        if let Some(reply_tx) = gate_channels.remove(&id) {
                            let _ = reply_tx.send(GateDecision::Denied {
                                reason: format!(
                                    "{} Denied by {} via {}.{}",
                                    deny_message,
                                    by,
                                    surface,
                                    message.as_deref().map(|m| format!(" Reason: {}", m)).unwrap_or_default()
                                ),
                            });
                        }
                    }

                    // Audit log alert
                    let decision = if approved { "APPROVED" } else { "DENIED" };
                    let audit_alert = Alert::new(
                        Severity::Warning,
                        "response",
                        &format!(
                            "Action {} {} by {} via {}. Source: {} — {}{}",
                            id, decision, by, surface,
                            action.threat_source, action.threat_message,
                            message.as_deref().map(|m| format!(". Note: {}", m)).unwrap_or_default()
                        ),
                    );
                    drop(pending); // release lock before sending
                    let _ = slack_tx.send(audit_alert).await;
                }
            }
        }
    }
}

// ── Playbook Matching ────────────────────────────────────────────────────────

fn find_matching_playbook<'a>(
    alert: &Alert,
    playbooks: &'a [(String, Playbook)],
) -> Option<(&'a String, &'a Playbook)> {
    let alert_text = format!("{} {}", alert.source, alert.message).to_lowercase();
    for (name, playbook) in playbooks {
        for trigger in &playbook.trigger_on {
            if alert_text.contains(&trigger.to_lowercase()) {
                return Some((name, playbook));
            }
        }
    }
    None
}

/// Parse string action tags into ContainmentAction enums.
/// Some actions need context from the alert (e.g., PID, UID).
fn parse_containment_actions(action_tags: &[String], alert: &Alert) -> Vec<ContainmentAction> {
    let mut result = Vec::new();
    for tag in action_tags {
        match tag.as_str() {
            "kill_process" => {
                if let Some(pid) = extract_pid(&alert.message) {
                    result.push(ContainmentAction::KillProcess { pid });
                }
            }
            "suspend_process" => {
                if let Some(pid) = extract_pid(&alert.message) {
                    result.push(ContainmentAction::SuspendProcess { pid });
                }
            }
            "drop_network" => {
                if let Some(uid) = extract_uid(&alert.message) {
                    result.push(ContainmentAction::DropNetwork { uid });
                }
            }
            "revoke_api_keys" => {
                result.push(ContainmentAction::RevokeApiKeys);
            }
            "freeze_filesystem" => {
                let paths = extract_paths(&alert.message);
                if !paths.is_empty() {
                    result.push(ContainmentAction::FreezeFilesystem { paths });
                }
            }
            "lock_clawsudo" => {
                result.push(ContainmentAction::LockClawsudo);
            }
            _ => {
                eprintln!("Warning: unknown containment action tag: {}", tag);
            }
        }
    }
    result
}

/// Extract a PID from an alert message (looks for pid=NNNN or PID NNNN patterns).
fn extract_pid(message: &str) -> Option<u32> {
    // Try pid=NNNN
    if let Some(idx) = message.find("pid=") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = num.parse() {
            return Some(pid);
        }
    }
    // Try PID NNNN
    if let Some(idx) = message.to_uppercase().find("PID ") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = num.parse() {
            return Some(pid);
        }
    }
    None
}

/// Extract a UID from an alert message (looks for uid=NNNN patterns).
fn extract_uid(message: &str) -> Option<u32> {
    if let Some(idx) = message.find("uid=") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(uid) = num.parse() {
            return Some(uid);
        }
    }
    None
}

/// Extract file paths from an alert message (looks for /absolute/paths).
fn extract_paths(message: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for word in message.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '-' && c != '_');
        if clean.starts_with('/') && clean.len() > 1 {
            paths.push(clean.to_string());
        }
    }
    paths
}

// ── Containment Execution ────────────────────────────────────────────────────

/// Execute a single containment action. Logs success/failure.
async fn execute_containment(action: &ContainmentAction) {
    let result = match action {
        ContainmentAction::KillProcess { pid } => {
            let r = unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
            if r == 0 { Ok(()) } else { Err(format!("kill failed: errno {}", std::io::Error::last_os_error())) }
        }
        ContainmentAction::SuspendProcess { pid } => {
            let r = unsafe { libc::kill(*pid as i32, libc::SIGSTOP) };
            if r == 0 { Ok(()) } else { Err(format!("SIGSTOP failed: errno {}", std::io::Error::last_os_error())) }
        }
        ContainmentAction::DropNetwork { uid } => {
            let output = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-m", "owner", "--uid-owner", &uid.to_string(), "-j", "DROP"])
                .output();
            match output {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        ContainmentAction::RevokeApiKeys => {
            // Write a lockfile that the proxy checks
            match std::fs::write("/var/run/clawtower/proxy.locked", "revoked by response engine") {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        ContainmentAction::FreezeFilesystem { paths } => {
            let mut errors = Vec::new();
            for path in paths {
                let output = std::process::Command::new("chattr")
                    .args(["+i", path])
                    .output();
                if let Err(e) = output {
                    errors.push(format!("{}: {}", path, e));
                } else if let Ok(o) = output {
                    if !o.status.success() {
                        errors.push(format!("{}: {}", path, String::from_utf8_lossy(&o.stderr)));
                    }
                }
            }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
        }
        ContainmentAction::LockClawsudo => {
            // Write a lockfile that clawsudo checks
            match std::fs::write("/var/run/clawtower/clawsudo.locked", "locked by response engine") {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    };

    match result {
        Ok(()) => eprintln!("✅ Containment executed: {}", action),
        Err(e) => eprintln!("❌ Containment failed: {} — {}", action, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pid() {
        assert_eq!(extract_pid("process pid=12345 did something"), Some(12345));
        assert_eq!(extract_pid("PID 42 exited"), Some(42));
        assert_eq!(extract_pid("no pid here"), None);
    }

    #[test]
    fn test_extract_uid() {
        assert_eq!(extract_uid("user uid=1000 accessed file"), Some(1000));
        assert_eq!(extract_uid("no uid"), None);
    }

    #[test]
    fn test_extract_paths() {
        let paths = extract_paths("modified /etc/passwd and /home/user/.ssh/authorized_keys");
        assert_eq!(paths, vec!["/etc/passwd", "/home/user/.ssh/authorized_keys"]);
    }

    #[test]
    fn test_playbook_matching() {
        let playbooks = vec![
            ("exfil".to_string(), Playbook {
                name: "exfiltration".to_string(),
                description: "test".to_string(),
                actions: vec!["suspend_process".to_string()],
                trigger_on: vec!["dns_exfil".to_string(), "data_staging".to_string()],
            }),
        ];
        let alert = Alert::new(Severity::Critical, "network", "DNS exfil detected: dns_exfil pattern");
        let matched = find_matching_playbook(&alert, &playbooks);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().0, "exfil");

        let benign = Alert::new(Severity::Info, "system", "startup complete");
        assert!(find_matching_playbook(&benign, &playbooks).is_none());
    }
}
```

**Step 2: Commit**

```bash
git add src/response.rs
git commit -m "feat: add response engine module — core types, playbooks, containment, approval flow"
```

---

### Task 4: Wire response engine into main.rs

**Files:**
- Modify: `src/main.rs`

**Step 1: Add mod declaration**

After `mod tui;` add:

```rust
mod response;
```

**Step 2: Import response types**

In the `use` block near the top, add:

```rust
use response::{ResponseRequest, SharedPendingActions};
```

**Step 3: Spawn response engine after aggregator setup**

After the aggregator spawn block (around line 438 where `tokio::spawn(async move { aggregator::run_aggregator(...) })` is), add:

```rust
    // Spawn response engine if enabled
    let response_tx: Option<mpsc::Sender<ResponseRequest>> = if config.response.enabled {
        let (resp_tx, resp_rx) = mpsc::channel::<ResponseRequest>(100);
        let pending_store = response::new_shared_pending();
        let resp_slack_tx = raw_tx.clone(); // responses go through aggregator
        let resp_config = config.response.clone();
        let playbook_dir = std::path::Path::new(&resp_config.playbook_dir);
        let playbooks = response::load_playbooks(playbook_dir);
        eprintln!("Response engine enabled: {} playbooks loaded, {}s timeout",
            playbooks.len(), resp_config.timeout_secs);

        let resp_pending = pending_store.clone();
        tokio::spawn(async move {
            response::run_response_engine(
                resp_rx,
                resp_slack_tx,
                resp_pending,
                resp_config,
                playbooks,
            ).await;
        });
        Some(resp_tx)
    } else {
        None
    };
```

**Step 4: Forward high-severity alerts to response engine**

In the headless mode alert drain loop, after the eprintln line, add:

```rust
                    // Forward to response engine
                    if let Some(ref resp_tx) = response_tx {
                        if alert.severity >= Severity::Warning {
                            let _ = resp_tx.send(ResponseRequest::EvaluateAlert(alert.clone())).await;
                        }
                    }
```

For TUI mode, the response engine evaluation happens via the aggregator output. We need a second receiver. Since mpsc doesn't broadcast, we should instead have the aggregator forward to the response engine. But to keep changes minimal, add a `response_tx` clone into the TUI and forward from there.

Actually, the cleanest approach: tap into the aggregator. Modify the `run_tui` call to also pass the response sender, and have the TUI forward alerts to it. But that couples TUI to response. Better: subscribe to the raw_tx output.

Simplest for now: clone the aggregator's output by adding another channel. In the aggregator spawn, after creating `alert_tx`:

Find the aggregator spawn:
```rust
    tokio::spawn(async move {
        aggregator::run_aggregator(raw_rx, alert_tx, slack_tx, agg_config, min_slack, agg_store).await;
    });
```

We need to also forward aggregated alerts to the response engine. The cleanest way without modifying aggregator.rs: create a wrapper receiver that tees to both TUI and response engine.

Add after the aggregator spawn:

```rust
    // Tee aggregated alerts to response engine
    let alert_rx = if let Some(ref resp_tx) = response_tx {
        let (tee_tx, tee_rx) = mpsc::channel::<Alert>(1000);
        let resp_tx = resp_tx.clone();
        tokio::spawn(async move {
            let mut rx = alert_rx;
            while let Some(alert) = rx.recv().await {
                if alert.severity >= Severity::Warning {
                    let _ = resp_tx.send(ResponseRequest::EvaluateAlert(alert.clone())).await;
                }
                let _ = tee_tx.send(alert).await;
            }
        });
        tee_rx
    } else {
        alert_rx
    };
```

This shadows `alert_rx` with the tee'd version. The TUI/headless consumer receives alerts as before, and the response engine also gets a copy of warnings/criticals.

**Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire response engine into main orchestration loop"
```

---

### Task 5: Add TUI approval popup

**Files:**
- Modify: `src/tui.rs`

**Step 1: Add response imports**

At the top of `src/tui.rs`, add:

```rust
use crate::response::{PendingAction, PendingStatus, ResponseRequest, SharedPendingActions};
```

**Step 2: Add pending actions state to App**

Add these fields to the `App` struct:

```rust
    // Response engine integration
    pub pending_actions: SharedPendingActions,
    pub response_tx: Option<mpsc::Sender<ResponseRequest>>,
    pub approval_popup: Option<ApprovalPopup>,
```

**Step 3: Add ApprovalPopup struct**

After `SudoStatus` enum:

```rust
/// State for the response engine approval popup.
pub struct ApprovalPopup {
    /// The pending action being reviewed.
    pub action_id: String,
    pub threat_source: String,
    pub threat_message: String,
    pub severity: Severity,
    pub actions_display: Vec<String>,
    pub playbook: Option<String>,
    /// Currently selected: 0 = Approve, 1 = Deny
    pub selected: usize,
    /// Optional message/annotation
    pub message_buffer: String,
    /// Whether the message field is being edited
    pub editing_message: bool,
}
```

**Step 4: Initialize new fields in App::new()**

Update `App::new()` to accept and store `pending_actions` and `response_tx`:

Change the signature:
```rust
    pub fn new(pending_actions: SharedPendingActions, response_tx: Option<mpsc::Sender<ResponseRequest>>) -> Self {
```

Add to the initialization:
```rust
            pending_actions,
            response_tx,
            approval_popup: None,
```

**Step 5: Add approval popup keyboard handler**

In `on_key`, after the sudo popup handler block, add:

```rust
        // Handle approval popup if active
        if let Some(ref mut popup) = self.approval_popup {
            if popup.editing_message {
                match key {
                    KeyCode::Esc => { popup.editing_message = false; }
                    KeyCode::Backspace => { popup.message_buffer.pop(); }
                    KeyCode::Char(c) => { popup.message_buffer.push(c); }
                    KeyCode::Enter => { popup.editing_message = false; }
                    _ => {}
                }
                return;
            }
            match key {
                KeyCode::Up | KeyCode::Down => {
                    popup.selected = if popup.selected == 0 { 1 } else { 0 };
                }
                KeyCode::Char('m') => {
                    popup.editing_message = true;
                }
                KeyCode::Enter => {
                    let approved = popup.selected == 0;
                    let action_id = popup.action_id.clone();
                    let msg = if popup.message_buffer.is_empty() { None } else { Some(popup.message_buffer.clone()) };
                    self.approval_popup = None;

                    // Send resolution
                    if let Some(ref tx) = self.response_tx {
                        let resolve = ResponseRequest::Resolve {
                            id: action_id,
                            approved,
                            by: "admin".to_string(),
                            message: msg,
                            surface: "tui".to_string(),
                        };
                        // Use try_send since we're not async
                        let _ = tx.try_send(resolve);
                    }
                }
                KeyCode::Esc => {
                    self.approval_popup = None;
                }
                _ => {}
            }
            return;
        }
```

**Step 6: Add approval popup renderer**

```rust
fn render_approval_popup(f: &mut Frame, area: Rect, popup: &ApprovalPopup) {
    let popup_width = 70.min(area.width.saturating_sub(4));
    let popup_height = (14 + popup.actions_display.len() as u16).min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let severity_style = match popup.severity {
        Severity::Critical => Style::default().fg(Color::Red).bold(),
        Severity::Warning => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(Color::Blue).bold(),
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!("🚨 {} THREAT DETECTED", popup.severity),
            severity_style,
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_source),
        ]),
        Line::from(vec![
            Span::styled("Threat: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_message),
        ]),
    ];

    if let Some(ref pb) = popup.playbook {
        lines.push(Line::from(vec![
            Span::styled("Playbook: ", Style::default().fg(Color::DarkGray)),
            Span::styled(pb.as_str(), Style::default().fg(Color::Cyan)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Proposed actions:", Style::default().fg(Color::DarkGray))));
    for action in &popup.actions_display {
        lines.push(Line::from(format!("  • {}", action)));
    }

    lines.push(Line::from(""));

    // Approve/Deny buttons
    let approve_style = if popup.selected == 0 {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::Green)
    };
    let deny_style = if popup.selected == 1 {
        Style::default().fg(Color::Black).bg(Color::Red).bold()
    } else {
        Style::default().fg(Color::Red)
    };

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(" APPROVE ", approve_style),
        Span::raw("    "),
        Span::styled("  DENY  ", deny_style),
    ]));

    lines.push(Line::from(""));

    // Message box
    let msg_display = if popup.editing_message {
        format!("Note: {}▌", popup.message_buffer)
    } else if popup.message_buffer.is_empty() {
        "Press 'm' to add a note".to_string()
    } else {
        format!("Note: {}", popup.message_buffer)
    };
    lines.push(Line::from(Span::styled(msg_display, Style::default().fg(Color::DarkGray))));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑↓: select │ Enter: confirm │ m: add note │ Esc: dismiss",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(" ⚡ Action Required ")
            .style(Style::default().bg(Color::Black)));
    f.render_widget(paragraph, popup_area);
}
```

**Step 7: Render approval popup in ui()**

In the `ui()` function, after the sudo popup render, add:

```rust
    // Approval popup overlay
    if let Some(ref popup) = app.approval_popup {
        render_approval_popup(f, f.area(), popup);
    }
```

**Step 8: Check for new pending actions on each tick**

In `run_tui`, inside the main loop after draining the alert channel, add:

```rust
        // Check for new pending actions and show popup
        if app.approval_popup.is_none() {
            let pending = app.pending_actions.lock().await;
            if let Some(action) = pending.iter().find(|a| matches!(a.status, PendingStatus::AwaitingApproval)) {
                app.approval_popup = Some(ApprovalPopup {
                    action_id: action.id.clone(),
                    threat_source: action.threat_source.clone(),
                    threat_message: action.threat_message.clone(),
                    severity: action.severity.clone(),
                    actions_display: action.actions.iter().map(|a| a.to_string()).collect(),
                    playbook: action.playbook.clone(),
                    selected: 1, // default to DENY for safety
                    message_buffer: String::new(),
                    editing_message: false,
                });
            }
        }
```

**Step 9: Update run_tui signature**

Change `run_tui` to accept the new params:

```rust
pub async fn run_tui(
    mut alert_rx: mpsc::Receiver<Alert>,
    config_path: Option<PathBuf>,
    pending_actions: SharedPendingActions,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
) -> Result<()> {
```

And update `App::new()` call:

```rust
    let mut app = App::new(pending_actions, response_tx);
```

**Step 10: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): approval popup for response engine pending actions"
```

---

### Task 6: Add API endpoints for pending actions

**Files:**
- Modify: `src/api.rs`

**Step 1: Add response imports**

```rust
use crate::response::{PendingAction, PendingStatus, ResponseRequest, SharedPendingActions};
```

**Step 2: Update run_api_server signature to accept response state**

Change `run_api_server` to also accept pending store and response sender:

```rust
pub async fn run_api_server(
    bind: &str,
    port: u16,
    store: SharedAlertStore,
    auth_token: String,
    pending_store: SharedPendingActions,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
) -> anyhow::Result<()> {
```

Pass them into the handler closure. Update the `handle` function signature too:

```rust
async fn handle(
    req: Request<Body>,
    store: SharedAlertStore,
    start_time: Instant,
    auth_token: Arc<String>,
    pending_store: SharedPendingActions,
    response_tx: Option<Arc<mpsc::Sender<ResponseRequest>>>,
) -> Result<Response<Body>, Infallible> {
```

**Step 3: Add /api/pending endpoint**

In the match on `req.uri().path()`, add before the `_` catch-all:

```rust
        "/api/pending" => {
            let pending = pending_store.lock().await;
            let items: Vec<serde_json::Value> = pending.iter().map(|a| {
                serde_json::json!({
                    "id": a.id,
                    "threat_source": a.threat_source,
                    "threat_message": a.threat_message,
                    "severity": format!("{}", a.severity),
                    "mode": a.mode,
                    "actions": a.actions.iter().map(|act| act.to_string()).collect::<Vec<_>>(),
                    "playbook": a.playbook,
                    "status": a.status,
                    "age_seconds": a.created_at.elapsed().as_secs(),
                })
            }).collect();
            json_response(StatusCode::OK, serde_json::to_string(&items).unwrap())
        }
```

**Step 4: Add /api/pending/{id}/approve and /api/pending/{id}/deny**

These are POST routes. Add pattern matching for paths starting with `/api/pending/`:

```rust
        path if path.starts_with("/api/pending/") && (path.ends_with("/approve") || path.ends_with("/deny")) => {
            if req.method() != &hyper::Method::POST {
                json_response(StatusCode::METHOD_NOT_ALLOWED, r#"{"error":"POST required"}"#.to_string())
            } else if let Some(ref resp_tx) = response_tx {
                let parts: Vec<&str> = path.split('/').collect();
                // /api/pending/{id}/approve → parts = ["", "api", "pending", "{id}", "approve"]
                if parts.len() == 5 {
                    let id = parts[3].to_string();
                    let approved = parts[4] == "approve";

                    // Read body for optional message
                    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
                    let message = body_json.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let by = body_json.get("by").and_then(|v| v.as_str()).unwrap_or("api_user").to_string();

                    let resolve = ResponseRequest::Resolve {
                        id: id.clone(),
                        approved,
                        by,
                        message,
                        surface: "api".to_string(),
                    };
                    match resp_tx.send(resolve).await {
                        Ok(_) => json_response(StatusCode::OK, format!(r#"{{"id":"{}","result":"{}"}}"#, id, if approved { "approved" } else { "denied" })),
                        Err(_) => json_response(StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"response engine unavailable"}"#.to_string()),
                    }
                } else {
                    json_response(StatusCode::BAD_REQUEST, r#"{"error":"invalid path"}"#.to_string())
                }
            } else {
                json_response(StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"response engine not enabled"}"#.to_string())
            }
        }
```

**Step 5: Update API index page**

In the HTML index, add the new endpoints:

```html
<li><a href="/api/pending">/api/pending</a> — Pending approval actions</li>
```

**Step 6: Update main.rs to pass new params to API server**

In `main.rs`, update the API spawn to pass pending store and response sender:

```rust
    if config.api.enabled {
        let store = alert_store.clone();
        let bind = config.api.bind.clone();
        let port = config.api.port;
        let auth_token = config.api.auth_token.clone();
        let api_pending = pending_store.clone(); // from response engine setup
        let api_resp_tx = response_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = api::run_api_server(&bind, port, store, auth_token, api_pending, api_resp_tx).await {
                eprintln!("API server error: {}", e);
            }
        });
    }
```

Note: `pending_store` and `response_tx` need to be available even when response engine is disabled. Create them unconditionally in main.rs:

```rust
    let pending_store = response::new_shared_pending();
```

Move this before the response engine spawn block so it's always available.

**Step 7: Commit**

```bash
git add src/api.rs src/main.rs
git commit -m "feat(api): add /api/pending, /api/pending/{id}/approve, /api/pending/{id}/deny endpoints"
```

---

### Task 7: Update main.rs for TUI signature changes and wiring

**Files:**
- Modify: `src/main.rs`

**Step 1: Update TUI invocation**

Find the TUI call:

```rust
            result = tui::run_tui(alert_rx, Some(config_path.clone())) => { result?; }
```

Replace with:

```rust
            result = tui::run_tui(alert_rx, Some(config_path.clone()), pending_store.clone(), response_tx.clone()) => { result?; }
```

**Step 2: Ensure pending_store is created unconditionally**

Before the response engine spawn block, add:

```rust
    let pending_store = response::new_shared_pending();
```

And in the response engine spawn, use `pending_store.clone()` instead of creating a new one.

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: pass response engine state to TUI and API"
```

---

### Task 8: Create default playbook files

**Files:**
- Create: `playbooks/exfiltration.yaml`
- Create: `playbooks/persistence.yaml`
- Create: `playbooks/compromise.yaml`

**Step 1: Write exfiltration playbook**

```yaml
playbooks:
  exfiltration:
    name: "Data Exfiltration Response"
    description: "Containment for data exfiltration attempts — suspends the process, drops network, and revokes API keys"
    actions:
      - suspend_process
      - drop_network
      - revoke_api_keys
    trigger_on:
      - dns_exfil
      - data_staging
      - unauthorized_upload
      - exfiltration
      - data_exfil
      - base64_encoded_transfer
```

**Step 2: Write persistence playbook**

```yaml
playbooks:
  persistence:
    name: "Persistence Mechanism Response"
    description: "Containment for persistence attempts — suspends process, locks sudo, freezes filesystem"
    actions:
      - suspend_process
      - lock_clawsudo
      - freeze_filesystem
    trigger_on:
      - cron_persistence
      - service_install
      - startup_modification
      - systemd_persist
      - crontab_modify
      - authorized_keys
```

**Step 3: Write compromise playbook**

```yaml
playbooks:
  compromise:
    name: "Full Agent Compromise Response"
    description: "Maximum containment for suspected agent compromise — suspends, drops network, revokes keys, freezes fs, locks sudo"
    actions:
      - suspend_process
      - drop_network
      - revoke_api_keys
      - freeze_filesystem
      - lock_clawsudo
    trigger_on:
      - prompt_injection
      - container_escape
      - privilege_escalation
      - shell_injection
      - cognitive_tamper
```

**Step 4: Commit**

```bash
git add playbooks/
git commit -m "feat: add default response playbooks (exfiltration, persistence, compromise)"
```

---

### Task 9: Add response config to TUI config editor

**Files:**
- Modify: `src/tui.rs`

**Step 1: Add "response" to config_sections**

In `App::new()`, add `"response".into()` to the `config_sections` vec.

**Step 2: Add response fields to get_section_fields**

Add a new match arm:

```rust
        "response" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.response.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "timeout_secs".to_string(),
                value: config.response.timeout_secs.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
            ConfigField {
                name: "warning_mode".to_string(),
                value: config.response.warning_mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["gate".into(), "alert_only".into(), "auto_deny".into()]),
            },
            ConfigField {
                name: "playbook_dir".to_string(),
                value: config.response.playbook_dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "deny_message".to_string(),
                value: config.response.deny_message.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
```

**Step 3: Add response apply handler to apply_field_to_config**

```rust
        "response" => match field_name {
            "enabled" => config.response.enabled = value == "true",
            "timeout_secs" => if let Ok(t) = value.parse::<u64>() { config.response.timeout_secs = t; },
            "warning_mode" => config.response.warning_mode = value.to_string(),
            "playbook_dir" => config.response.playbook_dir = value.to_string(),
            "deny_message" => config.response.deny_message = value.to_string(),
            _ => {}
        },
```

**Step 4: Add "Pending" indicator to tab titles**

In the `ui()` function where tab titles are computed, update the Alerts tab to also show pending count:

```rust
    let pending_count = {
        // Try to get pending count without blocking
        if let Ok(pending) = app.pending_actions.try_lock() {
            pending.iter().filter(|a| matches!(a.status, PendingStatus::AwaitingApproval)).count()
        } else {
            0
        }
    };

    let alerts_title = if pending_count > 0 {
        format!("Alerts ({}) 🔴{}", total, pending_count)
    } else {
        format!("Alerts ({})", total)
    };
```

Use `alerts_title` instead of the hardcoded format for the first tab.

**Step 5: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): response engine config editor + pending action indicator"
```

---

### Task 10: Update clawsudo to use response engine lockfile

**Files:**
- Modify: `src/bin/clawsudo.rs`

**Step 1: Add lockfile check at the start of main()**

After the help flag check and before policy loading, add:

```rust
    // Check if clawsudo is locked by the response engine
    if Path::new("/var/run/clawtower/clawsudo.locked").exists() {
        eprintln!("🔴 clawsudo is locked by ClawTower response engine. All sudo requests denied.");
        eprintln!("   Action blocked by ClawTower security policy. Contact administrator.");
        log_line("DENIED-LOCKED", &full_cmd);
        if let Some(ref url) = load_webhook_url() {
            send_slack_sync(
                url,
                &format!(
                    "🔴 clawsudo locked — denied: `{}` (response engine lockdown active)",
                    full_cmd
                ),
            );
        }
        return ExitCode::from(EXIT_DENIED);
    }
```

Note: the `webhook_url` is loaded after policies currently. Move the `load_webhook_url()` call above, or inline it in the lockfile check. Simplest: inline it as shown above.

**Step 2: Commit**

```bash
git add src/bin/clawsudo.rs
git commit -m "feat(clawsudo): check response engine lockfile before policy evaluation"
```

---

### Task 11: Update proxy to check revocation lockfile

**Files:**
- Modify: `src/proxy.rs`

**Step 1: Add lockfile check in the request handler**

In the proxy's request handler function (the `service_fn` closure), at the top before key lookup, add a check:

Find the request handling logic (around where `lookup_virtual_key` is called) and add before it:

```rust
    // Check if API keys are revoked by response engine
    if std::path::Path::new("/var/run/clawtower/proxy.locked").exists() {
        let _ = state.alert_tx.send(Alert::new(
            Severity::Warning,
            "proxy",
            &format!("API request blocked — keys revoked by response engine: {} {}", req.method(), req.uri()),
        )).await;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"API access revoked by ClawTower security policy. Contact administrator."}"#))
            .unwrap());
    }
```

**Step 2: Commit**

```bash
git add src/proxy.rs
git commit -m "feat(proxy): check response engine revocation lockfile"
```

---

### Task 12: Final review and commit

**Step 1: Verify all mod declarations and imports compile logically**

Check:
- `src/main.rs` has `mod response;`
- `src/response.rs` exists with all types
- `src/tui.rs` imports response types
- `src/api.rs` imports response types
- `Cargo.toml` has `uuid`
- No circular dependencies

**Step 2: Verify no syntax errors by checking all files are well-formed**

```bash
grep -n "fn \|struct \|enum \|impl \|mod " src/response.rs | head -30
```

**Step 3: Push**

```bash
git push origin main
```

---

## Summary

| Task | Files | What |
|---|---|---|
| 1 | Cargo.toml | uuid dependency |
| 2 | config.rs | ResponseConfig struct |
| 3 | response.rs (NEW) | Core engine: types, playbooks, containment, approval loop |
| 4 | main.rs | Wire engine, alert tee, spawn task |
| 5 | tui.rs | Approval popup (render + keyboard + tick check) |
| 6 | api.rs, main.rs | /api/pending, approve/deny endpoints |
| 7 | main.rs | TUI signature update, wiring cleanup |
| 8 | playbooks/ (NEW) | 3 default YAML playbooks |
| 9 | tui.rs | Config editor + pending indicator |
| 10 | clawsudo.rs | Lockfile check |
| 11 | proxy.rs | Revocation lockfile check |
| 12 | — | Review + push |

**New files:** `src/response.rs` (~500 lines), 3 playbook YAMLs
**Modified:** main.rs, tui.rs, api.rs, config.rs, clawsudo.rs, proxy.rs, Cargo.toml
**Estimated total:** ~800 lines added
