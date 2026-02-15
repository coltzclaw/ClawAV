//! Journald-based log monitoring for network and SSH events.
//!
//! Provides two async tail functions:
//! - [`tail_journald_network`]: Tails kernel messages (`journalctl -k`) for iptables
//!   log entries matching a configured prefix.
//! - [`tail_journald_ssh`]: Tails `ssh`/`sshd` unit logs for login successes and failures.
//!
//! Falls back to file-based monitoring when journald is unavailable.

use anyhow::{Context, Result};
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::alerts::{Alert, Severity};
use crate::network::parse_iptables_line;

/// Check if journald is available on this system
pub fn journald_available() -> bool {
    std::process::Command::new("journalctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Tail kernel messages from journald for iptables log entries.
/// Spawns `journalctl -k -f -o json --since now` and parses JSON lines.
pub async fn tail_journald_network(
    prefix: &str,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let mut child = Command::new("journalctl")
        .args(["-k", "-f", "-o", "json", "--since", "now"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture journalctl stdout"))?;

    let mut reader = BufReader::new(stdout).lines();

    // Send startup notification
    let _ = tx.send(Alert::new(
        Severity::Info,
        "network",
        "Network monitor started (journald source)",
    )).await;

    while let Some(line) = reader.next_line().await? {
        // Parse JSON line from journalctl
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            // The kernel message is in the "MESSAGE" field
            if let Some(message) = json.get("MESSAGE").and_then(|v| v.as_str()) {
                if let Some(alert) = parse_iptables_line(message, prefix) {
                    let _ = tx.send(alert).await;
                }
            }
        }
    }

    // If journalctl exits, report it
    let _ = tx.send(Alert::new(
        Severity::Warning,
        "network",
        "journalctl process exited unexpectedly",
    )).await;

    Ok(())
}

/// Tail SSH login events from journald
pub async fn tail_journald_ssh(tx: mpsc::Sender<Alert>) -> Result<()> {
    let mut child = Command::new("journalctl")
        .args(["-u", "ssh", "-u", "sshd", "-f", "-o", "cat", "--since", "now"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn journalctl for SSH monitoring")?;

    let stdout = child.stdout.take().context("No stdout")?;
    let mut reader = BufReader::new(stdout).lines();

    while let Some(line) = reader.next_line().await? {
        let (severity, msg) = if line.contains("Accepted") {
            (Severity::Info, format!("SSH login: {}", line))
        } else if line.contains("Failed password") || line.contains("Failed publickey") {
            (Severity::Warning, format!("SSH failed login: {}", line))
        } else if line.contains("Invalid user") {
            (Severity::Warning, format!("SSH invalid user: {}", line))
        } else {
            continue;
        };
        let _ = tx.send(Alert::new(severity, "ssh", &msg)).await;
    }
    Ok(())
}
