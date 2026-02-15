//! UFW firewall state monitor.
//!
//! Captures a baseline of `ufw status verbose` on startup, then polls every 30
//! seconds for changes. Any rule modification or firewall disablement triggers
//! a Critical alert with a diff of the changes.

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use std::process::Command;

use crate::alerts::{Alert, Severity};

/// Capture current UFW status
fn get_ufw_status() -> Result<String, String> {
    let output = Command::new("ufw")
        .arg("status")
        .arg("verbose")
        .output()
        .map_err(|e| format!("Failed to run ufw: {}", e))?;

    if !output.status.success() {
        // Try with sudo
        let output = Command::new("sudo")
            .args(["ufw", "status", "verbose"])
            .output()
            .map_err(|e| format!("Failed to run sudo ufw: {}", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Check if firewall is active based on status output
fn is_firewall_active(status: &str) -> bool {
    status.contains("Status: active")
}

/// Generate a simple diff between two status strings
fn diff_status(baseline: &str, current: &str) -> String {
    let old_lines: Vec<&str> = baseline.lines().collect();
    let new_lines: Vec<&str> = current.lines().collect();

    let mut diff = String::new();
    // Show removed lines
    for line in &old_lines {
        if !new_lines.contains(line) {
            diff.push_str(&format!("- {}\n", line));
        }
    }
    // Show added lines
    for line in &new_lines {
        if !old_lines.contains(line) {
            diff.push_str(&format!("+ {}\n", line));
        }
    }
    if diff.is_empty() {
        diff = "(no visible diff)".to_string();
    }
    diff
}

/// Monitor firewall state periodically and send alerts on changes
pub async fn monitor_firewall(tx: mpsc::Sender<Alert>) {
    // Capture baseline
    let baseline = match get_ufw_status() {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "firewall",
                &format!("Cannot monitor firewall: {}", e),
            )).await;
            return;
        }
    };

    if !is_firewall_active(&baseline) {
        let _ = tx.send(Alert::new(
            Severity::Critical,
            "firewall",
            "Firewall is NOT active on startup!",
        )).await;
    } else {
        let _ = tx.send(Alert::new(
            Severity::Info,
            "firewall",
            "Firewall baseline captured (active)",
        )).await;
    }

    let mut last_status = baseline;

    loop {
        sleep(Duration::from_secs(30)).await;

        let current = match get_ufw_status() {
            Ok(s) => s,
            Err(_) => continue,
        };

        if current == last_status {
            continue;
        }

        // Status changed!
        if !is_firewall_active(&current) {
            let diff = diff_status(&last_status, &current);
            let _ = tx.send(Alert::new(
                Severity::Critical,
                "firewall",
                &format!("🚨 FIREWALL DISABLED!\nDiff:\n{}", diff),
            )).await;
        } else {
            let diff = diff_status(&last_status, &current);
            let _ = tx.send(Alert::new(
                Severity::Critical,
                "firewall",
                &format!("🚨 Firewall rules changed!\nDiff:\n{}", diff),
            )).await;
        }

        last_status = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_active_detection() {
        let active = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n";
        assert!(is_firewall_active(active));

        let inactive = "Status: inactive\n";
        assert!(!is_firewall_active(inactive));
    }

    #[test]
    fn test_diff_detects_changes() {
        let old = "Status: active\nRule1\nRule2\n";
        let new = "Status: active\nRule1\nRule3\n";
        let diff = diff_status(old, new);
        assert!(diff.contains("- Rule2"));
        assert!(diff.contains("+ Rule3"));
    }

    #[test]
    fn test_diff_no_change() {
        let s = "Status: active\nRule1\n";
        let diff = diff_status(s, s);
        assert!(diff.contains("no visible diff"));
    }
}
