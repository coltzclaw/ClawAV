// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Agent Identity Registry — runtime identity and risk tracking for AI agents.
//!
//! Each monitored agent gets an [`AgentIdentity`] with a trust level, risk score,
//! and lifecycle state. The [`IdentityRegistry`] is built from loaded agent profiles
//! and updated at runtime as alerts accumulate.
//!
//! Risk scores increase on Critical/Warning alerts and decay over time. Trust levels
//! can be set administratively or automatically demoted on high risk.

#![allow(dead_code, unused_imports)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::agent::profile::AgentProfile;
use crate::core::alerts::Severity;

/// Trust level assigned to an agent. Determines baseline permissions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Untrusted — maximum monitoring, no permissions
    Untrusted,
    /// Restricted — limited permissions, elevated monitoring
    Restricted,
    /// Standard — normal monitoring and permissions
    Standard,
    /// Elevated — reduced monitoring, expanded permissions (admin-granted)
    Elevated,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Standard
    }
}

/// Agent lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleState {
    /// Agent is active and being monitored
    Active,
    /// Agent is suspended (high risk or admin action)
    Suspended,
    /// Agent has been decommissioned
    Decommissioned,
}

impl Default for LifecycleState {
    fn default() -> Self {
        LifecycleState::Active
    }
}

/// Runtime identity for a monitored AI agent.
///
/// Tracks the agent's trust posture and risk score. Risk score increases on
/// alerts and decays over time toward zero.
#[derive(Debug, Clone, Serialize)]
pub struct AgentIdentity {
    /// Unique identifier (derived from profile name, lowercase, hyphenated)
    pub agent_id: String,
    /// Display name from the agent profile
    pub display_name: String,
    /// Unix user the agent runs as
    pub user: String,
    /// Current trust level
    pub trust_level: TrustLevel,
    /// Cumulative risk score (0.0 = no risk, 100.0 = maximum)
    pub risk_score: f64,
    /// Current lifecycle state
    pub lifecycle_state: LifecycleState,
    /// Total alerts attributed to this agent
    pub total_alerts: u64,
    /// Critical alerts attributed to this agent
    pub critical_alerts: u64,
    /// Timestamp of last risk score update (not serialized)
    #[serde(skip)]
    pub last_update: Option<Instant>,
}

/// Risk score increment per alert severity.
const RISK_INCREMENT_CRITICAL: f64 = 25.0;
const RISK_INCREMENT_WARNING: f64 = 5.0;
const RISK_INCREMENT_INFO: f64 = 0.5;

/// Risk score decay rate per minute of inactivity.
const RISK_DECAY_PER_MINUTE: f64 = 0.5;

/// Risk score threshold for automatic trust demotion.
const AUTO_DEMOTE_THRESHOLD: f64 = 75.0;

/// Risk score threshold for automatic suspension.
const AUTO_SUSPEND_THRESHOLD: f64 = 95.0;

impl AgentIdentity {
    /// Create a new identity from an agent profile.
    pub fn from_profile(profile: &AgentProfile) -> Self {
        let agent_id = profile.agent.name.to_lowercase().replace(' ', "-");
        Self {
            agent_id,
            display_name: profile.agent.name.clone(),
            user: profile.agent.user.clone(),
            trust_level: TrustLevel::Standard,
            risk_score: 0.0,
            lifecycle_state: LifecycleState::Active,
            total_alerts: 0,
            critical_alerts: 0,
            last_update: None,
        }
    }

    /// Record an alert against this agent, updating risk score and counters.
    ///
    /// Returns true if the agent's lifecycle state changed (e.g., suspended).
    pub fn record_alert(&mut self, severity: &Severity) -> bool {
        // Apply time decay first
        self.apply_decay();

        let increment = match severity {
            Severity::Critical => RISK_INCREMENT_CRITICAL,
            Severity::Warning => RISK_INCREMENT_WARNING,
            Severity::Info => RISK_INCREMENT_INFO,
        };

        self.risk_score = (self.risk_score + increment).min(100.0);
        self.total_alerts += 1;
        if *severity == Severity::Critical {
            self.critical_alerts += 1;
        }
        self.last_update = Some(Instant::now());

        // Check for automatic state transitions
        let mut state_changed = false;

        if self.risk_score >= AUTO_SUSPEND_THRESHOLD
            && self.lifecycle_state == LifecycleState::Active
        {
            self.lifecycle_state = LifecycleState::Suspended;
            state_changed = true;
        } else if self.risk_score >= AUTO_DEMOTE_THRESHOLD
            && self.trust_level > TrustLevel::Restricted
        {
            self.trust_level = TrustLevel::Restricted;
            state_changed = true;
        }

        state_changed
    }

    /// Apply time-based risk decay since last update.
    fn apply_decay(&mut self) {
        if let Some(last) = self.last_update {
            let elapsed = last.elapsed();
            let minutes = elapsed.as_secs_f64() / 60.0;
            let decay = minutes * RISK_DECAY_PER_MINUTE;
            self.risk_score = (self.risk_score - decay).max(0.0);
        }
    }

    /// Manually set the trust level (admin action).
    pub fn set_trust_level(&mut self, level: TrustLevel) {
        self.trust_level = level;
    }

    /// Manually set the lifecycle state (admin action).
    pub fn set_lifecycle_state(&mut self, state: LifecycleState) {
        self.lifecycle_state = state;
    }

    /// Reset risk score to zero (admin action after investigation).
    pub fn reset_risk(&mut self) {
        self.risk_score = 0.0;
        self.last_update = Some(Instant::now());
    }
}

/// Registry of all monitored agent identities.
///
/// Built from loaded agent profiles at startup. Provides lookup by agent_id
/// or by Unix user, and methods for recording alerts and querying risk.
pub struct IdentityRegistry {
    agents: HashMap<String, AgentIdentity>,
    /// Index from Unix username to agent_id for quick lookup
    user_index: HashMap<String, String>,
}

impl IdentityRegistry {
    /// Build the registry from a set of loaded agent profiles.
    pub fn from_profiles(profiles: &[AgentProfile]) -> Self {
        let mut agents = HashMap::new();
        let mut user_index = HashMap::new();

        for profile in profiles {
            let identity = AgentIdentity::from_profile(profile);
            user_index.insert(identity.user.clone(), identity.agent_id.clone());
            agents.insert(identity.agent_id.clone(), identity);
        }

        Self {
            agents,
            user_index,
        }
    }

    /// Look up an agent identity by agent_id.
    pub fn get(&self, agent_id: &str) -> Option<&AgentIdentity> {
        self.agents.get(agent_id)
    }

    /// Look up an agent identity by agent_id (mutable).
    pub fn get_mut(&mut self, agent_id: &str) -> Option<&mut AgentIdentity> {
        self.agents.get_mut(agent_id)
    }

    /// Look up an agent identity by Unix username.
    pub fn get_by_user(&self, user: &str) -> Option<&AgentIdentity> {
        self.user_index.get(user).and_then(|id| self.agents.get(id))
    }

    /// Look up an agent identity by Unix username (mutable).
    pub fn get_by_user_mut(&mut self, user: &str) -> Option<&mut AgentIdentity> {
        if let Some(id) = self.user_index.get(user).cloned() {
            self.agents.get_mut(&id)
        } else {
            None
        }
    }

    /// Record an alert for the agent identified by Unix user.
    /// Returns Some(agent_id) if the agent's state changed, None otherwise.
    pub fn record_alert_for_user(&mut self, user: &str, severity: &Severity) -> Option<String> {
        if let Some(id) = self.user_index.get(user).cloned() {
            if let Some(agent) = self.agents.get_mut(&id) {
                if agent.record_alert(severity) {
                    return Some(id);
                }
            }
        }
        None
    }

    /// Get all registered agent identities.
    pub fn all_agents(&self) -> Vec<&AgentIdentity> {
        self.agents.values().collect()
    }

    /// Get the number of registered agents.
    pub fn count(&self) -> usize {
        self.agents.len()
    }

    /// Check if any agent is currently suspended.
    pub fn has_suspended_agents(&self) -> bool {
        self.agents.values().any(|a| a.lifecycle_state == LifecycleState::Suspended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile(name: &str, user: &str) -> AgentProfile {
        toml::from_str(&format!(r#"
[agent]
name = "{name}"
user = "{user}"
home_dir = "/home/{user}"
workspace_dir = "/home/{user}/workspace"
"#)).unwrap()
    }

    #[test]
    fn test_identity_from_profile() {
        let profile = test_profile("OpenClaw", "openclaw");
        let identity = AgentIdentity::from_profile(&profile);
        assert_eq!(identity.agent_id, "openclaw");
        assert_eq!(identity.display_name, "OpenClaw");
        assert_eq!(identity.user, "openclaw");
        assert_eq!(identity.trust_level, TrustLevel::Standard);
        assert_eq!(identity.risk_score, 0.0);
        assert_eq!(identity.lifecycle_state, LifecycleState::Active);
        assert_eq!(identity.total_alerts, 0);
    }

    #[test]
    fn test_identity_id_normalization() {
        let profile = test_profile("Claude Code", "developer");
        let identity = AgentIdentity::from_profile(&profile);
        assert_eq!(identity.agent_id, "claude-code");
    }

    #[test]
    fn test_record_alert_increments_risk() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.record_alert(&Severity::Warning);
        assert!(identity.risk_score > 0.0);
        assert_eq!(identity.total_alerts, 1);
        assert_eq!(identity.critical_alerts, 0);
    }

    #[test]
    fn test_record_critical_alert() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.record_alert(&Severity::Critical);
        assert!(identity.risk_score >= RISK_INCREMENT_CRITICAL);
        assert_eq!(identity.critical_alerts, 1);
    }

    #[test]
    fn test_risk_score_capped_at_100() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        for _ in 0..10 {
            identity.record_alert(&Severity::Critical);
        }
        assert!(identity.risk_score <= 100.0);
    }

    #[test]
    fn test_auto_demote_on_high_risk() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);
        assert_eq!(identity.trust_level, TrustLevel::Standard);

        // 3 criticals + 1 warning ≈ 80.0 risk → clearly above 75.0 demote threshold
        // (accounts for sub-microsecond time decay between calls)
        for _ in 0..3 {
            identity.record_alert(&Severity::Critical);
        }
        identity.record_alert(&Severity::Warning);
        assert_eq!(identity.trust_level, TrustLevel::Restricted);
    }

    #[test]
    fn test_auto_suspend_on_extreme_risk() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        // 4 criticals = 100.0 risk → should suspend
        for _ in 0..4 {
            identity.record_alert(&Severity::Critical);
        }
        assert_eq!(identity.lifecycle_state, LifecycleState::Suspended);
    }

    #[test]
    fn test_reset_risk() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.record_alert(&Severity::Critical);
        assert!(identity.risk_score > 0.0);

        identity.reset_risk();
        assert_eq!(identity.risk_score, 0.0);
    }

    #[test]
    fn test_manual_trust_level() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.set_trust_level(TrustLevel::Elevated);
        assert_eq!(identity.trust_level, TrustLevel::Elevated);

        identity.set_trust_level(TrustLevel::Untrusted);
        assert_eq!(identity.trust_level, TrustLevel::Untrusted);
    }

    #[test]
    fn test_registry_from_profiles() {
        let profiles = vec![
            test_profile("OpenClaw", "openclaw"),
            test_profile("Claude Code", "developer"),
        ];
        let registry = IdentityRegistry::from_profiles(&profiles);

        assert_eq!(registry.count(), 2);
        assert!(registry.get("openclaw").is_some());
        assert!(registry.get("claude-code").is_some());
    }

    #[test]
    fn test_registry_lookup_by_user() {
        let profiles = vec![test_profile("OpenClaw", "openclaw")];
        let registry = IdentityRegistry::from_profiles(&profiles);

        let agent = registry.get_by_user("openclaw").unwrap();
        assert_eq!(agent.agent_id, "openclaw");

        assert!(registry.get_by_user("unknown").is_none());
    }

    #[test]
    fn test_registry_record_alert_for_user() {
        let profiles = vec![test_profile("OpenClaw", "openclaw")];
        let mut registry = IdentityRegistry::from_profiles(&profiles);

        // Info alert should not change state
        let result = registry.record_alert_for_user("openclaw", &Severity::Info);
        assert!(result.is_none());

        let agent = registry.get("openclaw").unwrap();
        assert_eq!(agent.total_alerts, 1);
    }

    #[test]
    fn test_registry_record_alert_unknown_user() {
        let profiles = vec![test_profile("OpenClaw", "openclaw")];
        let mut registry = IdentityRegistry::from_profiles(&profiles);

        // Unknown user should return None without panicking
        let result = registry.record_alert_for_user("unknown", &Severity::Critical);
        assert!(result.is_none());
    }

    #[test]
    fn test_registry_has_suspended() {
        let profiles = vec![test_profile("Test", "test")];
        let mut registry = IdentityRegistry::from_profiles(&profiles);

        assert!(!registry.has_suspended_agents());

        // Suspend via enough criticals
        for _ in 0..4 {
            registry.record_alert_for_user("test", &Severity::Critical);
        }
        assert!(registry.has_suspended_agents());
    }

    #[test]
    fn test_registry_empty() {
        let registry = IdentityRegistry::from_profiles(&[]);
        assert_eq!(registry.count(), 0);
        assert!(!registry.has_suspended_agents());
    }

    #[test]
    fn test_risk_decay() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.risk_score = 50.0;
        // Simulate 10 minutes ago
        identity.last_update = Some(Instant::now() - Duration::from_secs(600));

        identity.apply_decay();
        // 10 minutes * 0.5/min = 5.0 decay → 50.0 - 5.0 = 45.0
        assert!((identity.risk_score - 45.0).abs() < 1.0);
    }

    #[test]
    fn test_risk_decay_floors_at_zero() {
        let profile = test_profile("Test", "test");
        let mut identity = AgentIdentity::from_profile(&profile);

        identity.risk_score = 1.0;
        identity.last_update = Some(Instant::now() - Duration::from_secs(600));

        identity.apply_decay();
        assert_eq!(identity.risk_score, 0.0);
    }
}
