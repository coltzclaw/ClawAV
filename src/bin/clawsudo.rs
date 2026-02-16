//! clawsudo — sudo proxy/gatekeeper for ClawAV
//!
//! Every privileged command goes through policy evaluation before execution.
//! Usage: `clawsudo <command> [args...]`

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};


use chrono::Local;
use serde::Deserialize;

// ─── Exit codes ───
const EXIT_OK: u8 = 0;
const EXIT_FAIL: u8 = 1;
const EXIT_DENIED: u8 = 77;
const EXIT_TIMEOUT: u8 = 78;

// ─── Policy types ───

#[derive(Debug, Clone, Deserialize)]
struct PolicyRule {
    name: String,
    #[serde(rename = "match")]
    match_spec: MatchSpec,
    #[serde(default)]
    action: String,
    #[serde(default)]
    enforcement: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MatchSpec {
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    command_contains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Enforcement {
    Allow,
    Deny,
    Ask,
}

struct MatchResult {
    rule_name: String,
    enforcement: Enforcement,
}

// ─── Config (minimal, just need webhook_url) ───

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    slack: Option<SlackSection>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SlackSection {
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    backup_webhook_url: String,
}

// ─── Policy engine ───

fn load_policies(dirs: &[&Path]) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yaml") | Some("yml") => {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(pf) = serde_yaml::from_str::<PolicyFile>(&content) {
                            rules.extend(pf.rules);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    rules
}

fn evaluate(rules: &[PolicyRule], cmd_binary: &str, full_cmd: &str) -> Option<MatchResult> {
    let cmd_lower = cmd_binary.to_lowercase();
    let full_lower = full_cmd.to_lowercase();

    for rule in rules {
        let spec = &rule.match_spec;
        let mut matched = false;

        // Exact command match
        if !spec.command.is_empty()
            && spec.command.iter().any(|c| c.to_lowercase() == cmd_lower)
        {
            matched = true;
        }

        // Substring match
        if !matched
            && !spec.command_contains.is_empty()
            && spec
                .command_contains
                .iter()
                .any(|p| full_lower.contains(&p.to_lowercase()))
        {
            matched = true;
        }

        if matched {
            let enforcement = match rule.enforcement.as_deref() {
                Some("allow") => Enforcement::Allow,
                Some("deny") => Enforcement::Deny,
                Some("ask") => Enforcement::Ask,
                _ => {
                    // Infer from action
                    match rule.action.to_lowercase().as_str() {
                        "critical" | "block" => Enforcement::Deny,
                        _ => Enforcement::Ask,
                    }
                }
            };
            return Some(MatchResult {
                rule_name: rule.name.clone(),
                enforcement,
            });
        }
    }
    None
}

// ─── Logging ───

fn log_line(status: &str, full_cmd: &str) {
    let ts = Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string();
    let line = format!("[{}] [{}] user=openclaw cmd=\"{}\"\n", ts, status, full_cmd);

    // Try production path, fall back to local
    let log_paths: &[&str] = &["/var/log/clawav/clawsudo.log", "./clawsudo.log"];
    for path in log_paths {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
            break;
        }
    }

    // Also append to audit chain if it exists
    let chain_path = "/var/log/clawav/audit.chain";
    if Path::new(chain_path).exists() {
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(chain_path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

// ─── Slack ───

fn load_webhook_url() -> Option<String> {
    let paths = [
        PathBuf::from("/etc/clawav/config.toml"),
        PathBuf::from("./config.toml"),
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(cf) = toml::from_str::<ConfigFile>(&content) {
                if let Some(slack) = cf.slack {
                    if !slack.webhook_url.is_empty() {
                        return Some(slack.webhook_url);
                    }
                }
            }
        }
    }
    None
}

fn send_slack_sync(webhook_url: &str, text: &str) {
    let payload = serde_json::json!({
        "username": "ClawSudo",
        "icon_emoji": ":lock:",
        "text": text
    });
    // Fire-and-forget sync HTTP POST
    let _ = reqwest::blocking::Client::new()
        .post(webhook_url)
        .json(&payload)
        .timeout(Duration::from_secs(5))
        .send();
}

// ─── GTFOBins shell escape detection ───

const GTFOBINS_PATTERNS: &[&str] = &[
    // awk shell escapes
    "BEGIN{system(", "BEGIN {system(", "BEGIN{exec(", "|getline",
    // curl/wget shell escapes
    "-o /etc/", "-O /etc/", "--output /etc/",
    // tee to sensitive paths
    "/etc/sudoers", "/etc/shadow", "/etc/passwd",
    // cp/mv to sensitive paths
    " /usr/local/bin/clawav", " /etc/clawav/",
    // systemd-run
    "systemd-run",
    // Generic shell metacharacters in args
    ";", "$(", "`",
    // Pipe to shell
    "|sh", "|bash", "|dash", "|zsh",
    "| sh", "| bash", "| dash", "| zsh",
];

/// Check if a command contains GTFOBins shell escape patterns.
/// Returns Some(pattern) if a dangerous pattern is found, None if safe.
fn check_gtfobins(cmd_binary: &str, args: &[String], full_cmd: &str) -> Option<String> {
    let full_lower = full_cmd.to_lowercase();

    // Special handling for sed: block standalone 'e' command (executes pattern space)
    if cmd_binary == "sed" {
        for (i, arg) in args.iter().enumerate() {
            // Skip the binary name (first arg after "sed")
            // A standalone 'e' arg or an arg starting with 'e' that isn't preceded by '-e'/'-f'/etc
            if arg == "e" {
                // Check it's not a flag value: previous arg should not be "-e", "-f", etc.
                let prev_is_flag = i > 0 && args[i - 1].starts_with('-') && args[i - 1].contains('e');
                if !prev_is_flag {
                    return Some("sed 'e' command (shell execution)".to_string());
                }
            }
            // Also catch patterns like 'e id' or '1e' passed as sed script
            if !arg.starts_with('-') && arg != "sed" {
                // If the arg looks like a sed script containing 'e' command
                // e.g., "e id", "1e", etc. but NOT substitutions like 's/foo/bar/'
                let trimmed = arg.trim_matches('\'').trim_matches('"');
                if trimmed == "e" || trimmed.starts_with("e ") || trimmed.ends_with("\\e") {
                    let prev_is_flag = i > 0 && args[i - 1] == "-e";
                    if !prev_is_flag {
                        return Some("sed 'e' command (shell execution)".to_string());
                    }
                }
            }
        }
    }

    // Check all generic patterns against the full command string
    for pattern in GTFOBINS_PATTERNS {
        if full_lower.contains(&pattern.to_lowercase()) {
            return Some(format!("GTFOBins pattern: {}", pattern));
        }
    }

    None
}

// ─── Main ───

fn print_help() {
    eprintln!("clawsudo — sudo proxy/gatekeeper for ClawAV");
    eprintln!();
    eprintln!("Usage: clawsudo <command> [args...]");
    eprintln!();
    eprintln!("Every privileged command is evaluated against ClawAV policy rules");
    eprintln!("before being passed to sudo for execution.");
    eprintln!();
    eprintln!("Policy decisions:");
    eprintln!("  ALLOW  — command runs via sudo immediately");
    eprintln!("  DENY   — command is blocked, alert sent to Slack");
    eprintln!("  ASK    — unknown command, waits for human approval via touch file");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0   success");
    eprintln!("  1   general failure");
    eprintln!("  77  denied by policy");
    eprintln!("  78  approval timeout");
    eprintln!();
    eprintln!("Policy files: /etc/clawav/policies/*.yaml");
    eprintln!("Logs: /var/log/clawav/clawsudo.log");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: clawsudo <command> [args...]");
        return ExitCode::from(EXIT_FAIL);
    }

    // Handle help flags before policy evaluation
    if matches!(args[0].as_str(), "--help" | "-h" | "help") {
        print_help();
        return ExitCode::from(EXIT_OK);
    }

    let cmd_binary = args[0]
        .rsplit('/')
        .next()
        .unwrap_or(&args[0])
        .to_string();
    let full_cmd = args.join(" ");

    // Load policies
    let policy_dirs: Vec<&Path> = vec![
        Path::new("/etc/clawav/policies/"),
        Path::new("./policies/"),
    ];
    let rules = load_policies(&policy_dirs);

    let webhook_url = load_webhook_url();

    // Fail-secure: no rules → deny all
    if rules.is_empty() {
        eprintln!("🔴 No policy files found — DENY ALL (fail-secure)");
        log_line("DENIED", &full_cmd);
        if let Some(ref url) = webhook_url {
            send_slack_sync(
                url,
                &format!(
                    "🔴 *CRITICAL* clawsudo: No policy files found. Denied command: `{}`",
                    full_cmd
                ),
            );
        }
        return ExitCode::from(EXIT_DENIED);
    }

    let result = evaluate(&rules, &cmd_binary, &full_cmd);

    match result {
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Allow,
        }) => {
            // GTFOBins check — even if policy allows, block shell escape patterns
            if let Some(reason) = check_gtfobins(&cmd_binary, &args, &full_cmd) {
                eprintln!("🔴 Blocked by GTFOBins defense: {}", reason);
                log_line("DENIED-GTFOBINS", &full_cmd);
                if let Some(ref url) = webhook_url {
                    send_slack_sync(
                        url,
                        &format!(
                            "🔴 *CRITICAL* clawsudo GTFOBins block: `{}` ({})",
                            full_cmd, reason
                        ),
                    );
                }
                return ExitCode::from(EXIT_DENIED);
            }

            eprintln!("✅ Allowed by policy: {}", rule_name);
            log_line("ALLOWED", &full_cmd);
            // Execute via sudo
            let status = std::process::Command::new("sudo")
                .args(&args)
                .status();
            match status {
                Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                Err(e) => {
                    eprintln!("Failed to execute sudo: {}", e);
                    ExitCode::from(EXIT_FAIL)
                }
            }
        }
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Deny,
        }) => {
            eprintln!("🔴 Denied by policy: {}", rule_name);
            log_line("DENIED", &full_cmd);
            if let Some(ref url) = webhook_url {
                send_slack_sync(
                    url,
                    &format!(
                        "🔴 *CRITICAL* clawsudo denied command: `{}` (rule: {})",
                        full_cmd, rule_name
                    ),
                );
            }
            ExitCode::from(EXIT_DENIED)
        }
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Ask,
        }) => {
            eprintln!(
                "⏳ Awaiting approval (5 min timeout)... (rule: {})",
                rule_name
            );
            log_line("PENDING", &full_cmd);

            // Create approval file path
            let mut hasher = DefaultHasher::new();
            full_cmd.hash(&mut hasher);
            let hash = hasher.finish();
            let approval_file = format!("/tmp/clawsudo-{:x}.approved", hash);

            if let Some(ref url) = webhook_url {
                send_slack_sync(
                    url,
                    &format!(
                        "⚠️ *WARNING* clawsudo awaiting approval for: `{}`\nTo approve: `touch {}`",
                        full_cmd, approval_file
                    ),
                );
            }

            // Wait up to 5 minutes
            let start = Instant::now();
            let timeout = Duration::from_secs(300);
            loop {
                if Path::new(&approval_file).exists() {
                    let _ = std::fs::remove_file(&approval_file);
                    eprintln!("✅ Approved!");
                    log_line("ALLOWED", &full_cmd);
                    let status = std::process::Command::new("sudo")
                        .args(&args)
                        .status();
                    return match status {
                        Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                        Err(e) => {
                            eprintln!("Failed to execute sudo: {}", e);
                            ExitCode::from(EXIT_FAIL)
                        }
                    };
                }
                if start.elapsed() >= timeout {
                    eprintln!("⏰ Approval timed out");
                    log_line("TIMEOUT", &full_cmd);
                    return ExitCode::from(EXIT_TIMEOUT);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        None => {
            // No rule matched → ambiguous → ask
            eprintln!("⏳ No matching rule — awaiting approval (5 min timeout)...");
            log_line("PENDING", &full_cmd);

            let mut hasher = DefaultHasher::new();
            full_cmd.hash(&mut hasher);
            let hash = hasher.finish();
            let approval_file = format!("/tmp/clawsudo-{:x}.approved", hash);

            if let Some(ref url) = webhook_url {
                send_slack_sync(
                    url,
                    &format!(
                        "⚠️ *WARNING* clawsudo: unknown command awaiting approval: `{}`\nTo approve: `touch {}`",
                        full_cmd, approval_file
                    ),
                );
            }

            let start = Instant::now();
            let timeout = Duration::from_secs(300);
            loop {
                if Path::new(&approval_file).exists() {
                    let _ = std::fs::remove_file(&approval_file);
                    eprintln!("✅ Approved!");
                    log_line("ALLOWED", &full_cmd);
                    let status = std::process::Command::new("sudo")
                        .args(&args)
                        .status();
                    return match status {
                        Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                        Err(e) => {
                            eprintln!("Failed to execute sudo: {}", e);
                            ExitCode::from(EXIT_FAIL)
                        }
                    };
                }
                if start.elapsed() >= timeout {
                    eprintln!("⏰ Approval timed out");
                    log_line("TIMEOUT", &full_cmd);
                    return ExitCode::from(EXIT_TIMEOUT);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_rules() -> Vec<PolicyRule> {
        let yaml = include_str!("../../policies/clawsudo.yaml");
        let pf: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        pf.rules
    }

    #[test]
    fn test_apt_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "apt", "apt install curl").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
        assert_eq!(result.rule_name, "allow-apt");
    }

    #[test]
    fn test_apt_get_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "apt-get", "apt-get update").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_docker_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "docker", "docker ps").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_bash_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "bash", "bash").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
        assert_eq!(result.rule_name, "deny-sudo-shell");
    }

    #[test]
    fn test_sh_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "sh", "sh -c whoami").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_ufw_disable_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "ufw", "ufw disable").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_dangerous_rm_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "rm", "rm -rf /etc").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_systemctl_openclaw_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "systemctl", "systemctl restart openclaw").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_unknown_command_ambiguous() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "htop", "htop");
        assert!(result.is_none(), "unknown command should return None (ambiguous)");
    }

    #[test]
    fn test_no_rules_scenario() {
        let rules: Vec<PolicyRule> = vec![];
        // With empty rules, evaluate returns None — caller handles fail-secure
        let result = evaluate(&rules, "apt", "apt install curl");
        assert!(result.is_none());
    }

    #[test]
    fn test_clawav_tamper_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "chattr", "chattr +i /etc/clawav/config.toml").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_deny_exit_code() {
        // Verify the exit code constant
        assert_eq!(EXIT_DENIED, 77);
    }

    #[test]
    fn test_timeout_exit_code() {
        assert_eq!(EXIT_TIMEOUT, 78);
    }

    // ─── GTFOBins tests ───

    #[test]
    fn test_gtfobins_awk_system() {
        let args: Vec<String> = vec!["awk".into(), "BEGIN{system(\"id\")}".into()];
        let full = "awk BEGIN{system(\"id\")}";
        assert!(check_gtfobins("awk", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_sed_e_command() {
        let args: Vec<String> = vec!["sed".into(), "e".into(), "id".into()];
        let full = "sed e id";
        assert!(check_gtfobins("sed", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_sed_e_flag_allowed() {
        // sed -e 's/foo/bar/' file — legitimate use, should NOT be blocked
        let args: Vec<String> = vec!["sed".into(), "-e".into(), "s/foo/bar/".into(), "file".into()];
        let full = "sed -e s/foo/bar/ file";
        assert!(check_gtfobins("sed", &args, full).is_none());
    }

    #[test]
    fn test_gtfobins_curl_output_etc() {
        let args: Vec<String> = vec!["curl".into(), "-o".into(), "/etc/evil".into(), "http://x".into()];
        let full = "curl -o /etc/evil http://x";
        assert!(check_gtfobins("curl", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_tee_sudoers() {
        let args: Vec<String> = vec!["tee".into(), "/etc/sudoers".into()];
        let full = "tee /etc/sudoers";
        assert!(check_gtfobins("tee", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_cp_clawav() {
        let args: Vec<String> = vec!["cp".into(), "file".into(), "/usr/local/bin/clawav".into()];
        let full = "cp file /usr/local/bin/clawav";
        assert!(check_gtfobins("cp", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_systemd_run() {
        let args: Vec<String> = vec!["systemd-run".into(), "bash".into()];
        let full = "systemd-run bash";
        assert!(check_gtfobins("systemd-run", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_pipe_to_shell() {
        let args: Vec<String> = vec!["cat".into(), "file".into(), "|".into(), "bash".into()];
        let full = "cat file | bash";
        assert!(check_gtfobins("cat", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_shell_metachar_semicolon() {
        let args: Vec<String> = vec!["ls".into(), ";".into(), "bash".into()];
        let full = "ls ; bash";
        assert!(check_gtfobins("ls", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_command_substitution() {
        let args: Vec<String> = vec!["echo".into(), "$(id)".into()];
        let full = "echo $(id)";
        assert!(check_gtfobins("echo", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_apt_install_safe() {
        let args: Vec<String> = vec!["apt".into(), "install".into(), "vim".into()];
        let full = "apt install vim";
        assert!(check_gtfobins("apt", &args, full).is_none());
    }

    #[test]
    fn test_gtfobins_systemctl_restart_safe() {
        let args: Vec<String> = vec!["systemctl".into(), "restart".into(), "clawav".into()];
        let full = "systemctl restart clawav";
        assert!(check_gtfobins("systemctl", &args, full).is_none());
    }
}
