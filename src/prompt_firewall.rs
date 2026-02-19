// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Prompt Firewall — intercepts malicious prompts before they reach LLM providers.
//!
//! Scans outbound LLM request bodies against pre-compiled regex patterns organized
//! into threat categories: prompt injection, exfiltration-via-prompt, jailbreak,
//! tool abuse, and system prompt extraction.
//!
//! Enforcement is controlled by a 3-tier system:
//! - Tier 1 (Permissive): Log all matches, block nothing
//! - Tier 2 (Standard): Block injection + exfil (real system threats), log the rest
//! - Tier 3 (Strict): Block all categories

use anyhow::{Context, Result};
use regex::RegexSet;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Threat categories for prompt classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    PromptInjection,
    ExfilViaPrompt,
    Jailbreak,
    ToolAbuse,
    SystemPromptExtract,
}

/// Action to take when a pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Block,
    Warn,
    Log,
}

/// A single pattern match with metadata.
#[derive(Debug, Clone)]
pub struct FirewallMatch {
    pub category: ThreatCategory,
    pub pattern_name: String,
    pub description: String,
    pub action: FirewallAction,
}

/// Result of scanning a prompt through the firewall.
#[derive(Debug)]
pub enum FirewallResult {
    /// No patterns matched.
    Pass,
    /// Matches found — highest action is Log (forward, record).
    Log { matches: Vec<FirewallMatch> },
    /// Matches found — highest action is Warn (forward, alert).
    Warn { matches: Vec<FirewallMatch> },
    /// Matches found — highest action is Block (reject request).
    Block { matches: Vec<FirewallMatch> },
}

/// Resolve the default action for a category at a given tier.
pub fn tier_default_action(tier: u8, category: ThreatCategory) -> FirewallAction {
    match tier {
        1 => FirewallAction::Log,
        2 => match category {
            ThreatCategory::PromptInjection | ThreatCategory::ExfilViaPrompt => {
                FirewallAction::Block
            }
            _ => FirewallAction::Log,
        },
        _ => FirewallAction::Block,
    }
}

fn category_config_key(category: ThreatCategory) -> &'static str {
    match category {
        ThreatCategory::PromptInjection => "prompt_injection",
        ThreatCategory::ExfilViaPrompt => "exfil_via_prompt",
        ThreatCategory::Jailbreak => "jailbreak",
        ThreatCategory::ToolAbuse => "tool_abuse",
        ThreatCategory::SystemPromptExtract => "system_prompt_extract",
    }
}

fn parse_action(s: &str) -> Option<FirewallAction> {
    match s {
        "block" => Some(FirewallAction::Block),
        "warn" => Some(FirewallAction::Warn),
        "log" => Some(FirewallAction::Log),
        _ => None,
    }
}

/// Resolve the effective action for a category given tier defaults + overrides.
pub fn resolve_action(
    tier: u8,
    category: ThreatCategory,
    overrides: &HashMap<String, String>,
) -> FirewallAction {
    let key = category_config_key(category);
    if let Some(action_str) = overrides.get(key) {
        if let Some(action) = parse_action(action_str) {
            return action;
        }
    }
    tier_default_action(tier, category)
}

#[derive(Debug, Deserialize)]
struct PatternsFile {
    #[allow(dead_code)]
    version: Option<String>,
    patterns: Vec<RawPattern>,
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    name: String,
    category: String,
    #[allow(dead_code)]
    severity: String,
    pattern: String,
    description: String,
}

#[derive(Debug, Clone)]
struct PatternMeta {
    name: String,
    description: String,
}

struct CategoryScanner {
    category: ThreatCategory,
    regex_set: RegexSet,
    patterns: Vec<PatternMeta>,
    action: FirewallAction,
}

pub struct PromptFirewall {
    scanners: Vec<CategoryScanner>,
}

fn parse_category(s: &str) -> Option<ThreatCategory> {
    match s {
        "prompt_injection" => Some(ThreatCategory::PromptInjection),
        "exfil_via_prompt" => Some(ThreatCategory::ExfilViaPrompt),
        "jailbreak" => Some(ThreatCategory::Jailbreak),
        "tool_abuse" => Some(ThreatCategory::ToolAbuse),
        "system_prompt_extract" => Some(ThreatCategory::SystemPromptExtract),
        _ => None,
    }
}

impl PromptFirewall {
    pub fn load(
        patterns_path: &(impl AsRef<Path> + ?Sized),
        tier: u8,
        overrides: &HashMap<String, String>,
    ) -> Result<Self> {
        let path = patterns_path.as_ref();
        if !path.exists() {
            tracing::warn!("Prompt firewall patterns not found: {}", path.display());
            return Ok(Self {
                scanners: Vec::new(),
            });
        }

        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let file: PatternsFile =
            serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;

        let mut grouped: HashMap<ThreatCategory, Vec<(String, PatternMeta)>> = HashMap::new();
        for raw in &file.patterns {
            if let Some(cat) = parse_category(&raw.category) {
                grouped.entry(cat).or_default().push((
                    raw.pattern.clone(),
                    PatternMeta {
                        name: raw.name.clone(),
                        description: raw.description.clone(),
                    },
                ));
            }
        }

        let mut scanners = Vec::new();
        for (category, entries) in grouped {
            let (regexes, metas): (Vec<String>, Vec<PatternMeta>) =
                entries.into_iter().unzip();
            match RegexSet::new(&regexes) {
                Ok(regex_set) => {
                    let action = resolve_action(tier, category, overrides);
                    scanners.push(CategoryScanner {
                        category,
                        regex_set,
                        patterns: metas,
                        action,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to compile RegexSet for {:?}: {}", category, e);
                }
            }
        }

        Ok(Self { scanners })
    }

    pub fn category_count(&self) -> usize {
        self.scanners.len()
    }

    pub fn total_patterns(&self) -> usize {
        self.scanners.iter().map(|s| s.patterns.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_all_log() {
        for cat in [
            ThreatCategory::PromptInjection,
            ThreatCategory::ExfilViaPrompt,
            ThreatCategory::Jailbreak,
            ThreatCategory::ToolAbuse,
            ThreatCategory::SystemPromptExtract,
        ] {
            assert_eq!(
                tier_default_action(1, cat),
                FirewallAction::Log,
                "Tier 1 should log everything, got non-Log for {:?}",
                cat
            );
        }
    }

    #[test]
    fn test_tier2_blocks_injection_and_exfil() {
        assert_eq!(
            tier_default_action(2, ThreatCategory::PromptInjection),
            FirewallAction::Block
        );
        assert_eq!(
            tier_default_action(2, ThreatCategory::ExfilViaPrompt),
            FirewallAction::Block
        );
    }

    #[test]
    fn test_tier2_logs_non_threats() {
        assert_eq!(
            tier_default_action(2, ThreatCategory::Jailbreak),
            FirewallAction::Log
        );
        assert_eq!(
            tier_default_action(2, ThreatCategory::ToolAbuse),
            FirewallAction::Log
        );
        assert_eq!(
            tier_default_action(2, ThreatCategory::SystemPromptExtract),
            FirewallAction::Log
        );
    }

    #[test]
    fn test_tier3_blocks_everything() {
        for cat in [
            ThreatCategory::PromptInjection,
            ThreatCategory::ExfilViaPrompt,
            ThreatCategory::Jailbreak,
            ThreatCategory::ToolAbuse,
            ThreatCategory::SystemPromptExtract,
        ] {
            assert_eq!(
                tier_default_action(3, cat),
                FirewallAction::Block,
                "Tier 3 should block everything, got non-Block for {:?}",
                cat
            );
        }
    }

    #[test]
    fn test_override_downgrades_block_to_log() {
        let mut overrides = HashMap::new();
        overrides.insert("prompt_injection".to_string(), "log".to_string());
        assert_eq!(
            resolve_action(2, ThreatCategory::PromptInjection, &overrides),
            FirewallAction::Log,
        );
    }

    #[test]
    fn test_override_upgrades_log_to_block() {
        let mut overrides = HashMap::new();
        overrides.insert("jailbreak".to_string(), "block".to_string());
        assert_eq!(
            resolve_action(2, ThreatCategory::Jailbreak, &overrides),
            FirewallAction::Block,
        );
    }

    #[test]
    fn test_no_override_uses_tier_default() {
        let overrides = HashMap::new();
        assert_eq!(
            resolve_action(2, ThreatCategory::PromptInjection, &overrides),
            FirewallAction::Block,
        );
    }

    #[test]
    fn test_load_patterns_from_json() {
        let json = r#"{
            "version": "1.0.0",
            "patterns": [
                {
                    "name": "role_hijack",
                    "category": "prompt_injection",
                    "severity": "critical",
                    "pattern": "(?i)ignore\\s+previous\\s+instructions",
                    "description": "Role hijacking attempt"
                },
                {
                    "name": "exfil_encode",
                    "category": "exfil_via_prompt",
                    "severity": "critical",
                    "pattern": "(?i)base64.{0,20}contents?\\s+of",
                    "description": "Encode-and-exfil attempt"
                }
            ]
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prompt-firewall-patterns.json");
        std::fs::write(&path, json).unwrap();

        let firewall = PromptFirewall::load(&path, 2, &HashMap::new()).unwrap();
        assert_eq!(firewall.category_count(), 2);
        assert!(firewall.total_patterns() >= 2);
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let firewall =
            PromptFirewall::load("/nonexistent/patterns.json", 2, &HashMap::new()).unwrap();
        assert_eq!(firewall.total_patterns(), 0);
    }
}
