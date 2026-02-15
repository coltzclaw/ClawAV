//! Network log parser for iptables/netfilter entries.
//!
//! Parses iptables log lines from syslog or kernel messages, extracting SRC, DST,
//! DPT, and PROTO fields. Uses a configurable [`NetworkAllowlist`] of CIDR ranges
//! and ports to classify traffic as known-good (Info) or suspicious (Warning).
//!
//! Default allowlist includes RFC1918 ranges, multicast, and common ports (443, 53, 123).

use anyhow::Result;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::fs::File;
use std::path::Path;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use ipnet::IpNet;

use crate::alerts::{Alert, Severity};

/// Parse an iptables log line
pub fn parse_iptables_line(line: &str, prefix: &str) -> Option<Alert> {
    if !line.contains(prefix) {
        return None;
    }

    let src = extract_iptables_field(line, "SRC").unwrap_or("?");
    let dst = extract_iptables_field(line, "DST").unwrap_or("?");
    let dpt = extract_iptables_field(line, "DPT").unwrap_or("?");
    let proto = extract_iptables_field(line, "PROTO").unwrap_or("?");

    let msg = format!("Outbound: {} → {}:{} ({})", src, dst, dpt, proto);

    // Determine severity based on destination
    let severity = if is_known_good_destination(dst, dpt) {
        Severity::Info
    } else {
        Severity::Warning
    };

    Some(Alert::new(severity, "network", &msg))
}

fn extract_iptables_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{}=", field);
    line.split_whitespace()
        .find(|s| s.starts_with(&prefix))
        .map(|s| &s[prefix.len()..])
}

fn is_known_good_destination(dst: &str, dpt: &str) -> bool {
    // Legacy fallback — uses default allowlist
    let allowlist = NetworkAllowlist::from_config(
        &crate::config::default_allowlisted_cidrs(),
        &crate::config::default_allowlisted_ports(),
    );
    allowlist.is_allowed(dst, dpt)
}

/// CIDR and port-based allowlist for classifying network traffic.
pub struct NetworkAllowlist {
    cidrs: Vec<IpNet>,
    ports: Vec<u16>,
}

impl NetworkAllowlist {
    pub fn from_config(cidrs: &[String], ports: &[u16]) -> Self {
        let parsed_cidrs: Vec<IpNet> = cidrs.iter()
            .filter_map(|c| c.parse().ok())
            .collect();
        Self { cidrs: parsed_cidrs, ports: ports.to_vec() }
    }

    pub fn is_allowed(&self, dst: &str, dpt: &str) -> bool {
        if let Ok(port) = dpt.parse::<u16>() {
            if self.ports.contains(&port) { return true; }
        }
        if let Ok(ip) = dst.parse::<IpAddr>() {
            for cidr in &self.cidrs {
                if cidr.contains(&ip) { return true; }
            }
        }
        false
    }
}

/// Tail syslog for iptables entries
pub async fn tail_network_log(
    path: &Path,
    prefix: &str,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => sleep(Duration::from_millis(500)).await,
            Ok(_) => {
                if let Some(alert) = parse_iptables_line(&line, prefix) {
                    let _ = tx.send(alert).await;
                }
            }
            Err(e) => {
                let _ = tx.send(Alert::new(
                    Severity::Warning,
                    "network",
                    &format!("Error reading network log: {}", e),
                )).await;
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    fn default_allowlist() -> NetworkAllowlist {
        NetworkAllowlist::from_config(
            &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4"]
                .iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &[443, 53, 123, 5353],
        )
    }

    #[test]
    fn test_lan_traffic_allowed() {
        assert!(default_allowlist().is_allowed("192.168.1.50", "8080"));
    }

    #[test]
    fn test_mdns_allowed() {
        assert!(default_allowlist().is_allowed("224.0.0.251", "5353"));
    }

    #[test]
    fn test_public_ip_not_allowed() {
        assert!(!default_allowlist().is_allowed("8.8.8.8", "8080"));
    }

    #[test]
    fn test_known_port_allowed() {
        assert!(default_allowlist().is_allowed("8.8.8.8", "443"));
    }

    #[test]
    fn test_docker_bridge_allowed() {
        assert!(default_allowlist().is_allowed("172.17.0.2", "3000"));
    }

    #[test]
    fn test_localhost_allowed() {
        assert!(default_allowlist().is_allowed("127.0.0.1", "9999"));
    }
}
