#![allow(dead_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Unified approval system core types.
//!
//! Defines the data model for approval requests that flow between clawsudo,
//! the response engine, notification channels (Slack, TUI, API), and the
//! approval orchestrator.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

pub mod store;

use crate::core::alerts::Severity;
use crate::notify::{ChannelRegistry, NotificationChannel};
use store::ApprovalStore;

/// Where an approval request originated from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalSource {
    /// Request came from clawsudo policy evaluation.
    ClawSudo {
        /// The policy rule name that triggered the approval, if known.
        policy_rule: Option<String>,
    },
    /// Request came from the automated response engine.
    ResponseEngine {
        /// The threat ID that triggered the response action.
        threat_id: String,
        /// The playbook being executed, if any.
        playbook: Option<String>,
    },
}

impl fmt::Display for ApprovalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalSource::ClawSudo { policy_rule: Some(rule) } => write!(f, "clawsudo (rule: {})", rule),
            ApprovalSource::ClawSudo { policy_rule: None } => write!(f, "clawsudo"),
            ApprovalSource::ResponseEngine { threat_id, playbook: Some(pb) } => write!(f, "response-engine (threat: {}, playbook: {})", threat_id, pb),
            ApprovalSource::ResponseEngine { threat_id, playbook: None } => write!(f, "response-engine (threat: {})", threat_id),
        }
    }
}

/// The outcome of an approval decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalResolution {
    /// The request was approved.
    Approved {
        /// Who approved (e.g., "admin", "jr", Slack user ID).
        by: String,
        /// Channel used to approve (e.g., "slack", "tui", "api").
        via: String,
        /// Optional message from the approver.
        message: Option<String>,
        /// When the approval was granted.
        at: DateTime<Utc>,
    },
    /// The request was denied.
    Denied {
        /// Who denied (e.g., "admin", Slack user ID).
        by: String,
        /// Channel used to deny (e.g., "slack", "tui", "api").
        via: String,
        /// Optional reason for denial.
        message: Option<String>,
        /// When the denial was issued.
        at: DateTime<Utc>,
    },
    /// The request expired before anyone responded.
    TimedOut {
        /// When the timeout occurred.
        at: DateTime<Utc>,
    },
}

impl fmt::Display for ApprovalResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalResolution::Approved { by, via, .. } => {
                write!(f, "Approved by {} via {}", by, via)
            }
            ApprovalResolution::Denied { by, via, .. } => {
                write!(f, "Denied by {} via {}", by, via)
            }
            ApprovalResolution::TimedOut { .. } => write!(f, "Timed out"),
        }
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "Pending"),
            ApprovalStatus::Resolved(r) => write!(f, "{}", r),
        }
    }
}

/// Current status of an approval request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Awaiting a decision.
    Pending,
    /// A decision has been made.
    Resolved(ApprovalResolution),
}

/// A request for human approval before executing a privileged action.
///
/// Created by clawsudo or the response engine, routed through the approval
/// orchestrator to one or more notification channels, and resolved when a
/// human responds or the timeout expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Where this request originated.
    pub source: ApprovalSource,
    /// The command or action requiring approval.
    pub command: String,
    /// The agent requesting the action.
    pub agent: String,
    /// How serious this action is.
    pub severity: Severity,
    /// Additional context about why this action is being requested.
    pub context: String,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// How long to wait for a response before timing out.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
}

impl ApprovalRequest {
    /// Create a new approval request with a generated UUID and current timestamp.
    pub fn new(
        source: ApprovalSource,
        command: String,
        agent: String,
        severity: Severity,
        context: String,
        timeout: Duration,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source,
            command,
            agent,
            severity,
            context,
            created_at: Utc::now(),
            timeout,
        }
    }

    /// Returns `true` if this request has exceeded its timeout duration.
    pub fn is_expired(&self) -> bool {
        let deadline = self.created_at + chrono::Duration::from_std(self.timeout)
            .unwrap_or_else(|_| chrono::Duration::zero());
        Utc::now() > deadline
    }
}

/// The approval orchestrator — coordinates approval requests across all notification channels.
///
/// Receives approval requests (from clawsudo, the response engine, or the API),
/// fans them out to every registered [`NotificationChannel`], then waits for the
/// first resolution (approve / deny / timeout) and broadcasts that outcome back
/// to the other channels.
pub struct ApprovalOrchestrator {
    store: Mutex<ApprovalStore>,
    channels: ChannelRegistry,
    request_tx: mpsc::Sender<ApprovalRequest>,
    request_rx: Mutex<Option<mpsc::Receiver<ApprovalRequest>>>,
    resolution_tx: mpsc::Sender<(String, ApprovalResolution)>,
    resolution_rx: Mutex<Option<mpsc::Receiver<(String, ApprovalResolution)>>>,
}

impl ApprovalOrchestrator {
    /// Create a new orchestrator with the given channel registry and history capacity.
    pub fn new(channels: ChannelRegistry, max_history: usize) -> Self {
        let (request_tx, request_rx) = mpsc::channel(100);
        let (resolution_tx, resolution_rx) = mpsc::channel(100);
        Self {
            store: Mutex::new(ApprovalStore::new(max_history)),
            channels,
            request_tx,
            request_rx: Mutex::new(Some(request_rx)),
            resolution_tx,
            resolution_rx: Mutex::new(Some(resolution_rx)),
        }
    }

    /// Clone of the request sender (for API endpoints / clawsudo to submit requests).
    pub fn request_tx(&self) -> mpsc::Sender<ApprovalRequest> {
        self.request_tx.clone()
    }

    /// Clone of the resolution sender (for webhook callbacks / TUI to submit resolutions).
    pub fn resolution_tx(&self) -> mpsc::Sender<(String, ApprovalResolution)> {
        self.resolution_tx.clone()
    }

    /// Check the status of an approval request by ID.
    pub fn get_status(&self, id: &str) -> Option<ApprovalStatus> {
        let store = self.store.lock().unwrap();
        if store.is_pending(id) {
            Some(ApprovalStatus::Pending)
        } else if let Some(resolution) = store.get_resolution(id) {
            Some(ApprovalStatus::Resolved(resolution.clone()))
        } else {
            None
        }
    }

    /// Number of currently pending approval requests.
    pub fn pending_count(&self) -> usize {
        self.store.lock().unwrap().pending_count()
    }

    /// Submit an approval request. Returns the request ID.
    pub async fn submit(&self, request: ApprovalRequest) -> anyhow::Result<String> {
        let id = request.id.clone();
        self.request_tx.send(request).await?;
        Ok(id)
    }

    /// Resolve an approval request by ID.
    pub async fn resolve(&self, id: String, resolution: ApprovalResolution) -> anyhow::Result<()> {
        self.resolution_tx.send((id, resolution)).await?;
        Ok(())
    }
}

/// Main orchestrator loop. Takes ownership of the rx halves from the orchestrator
/// (via the `Mutex<Option<>>` pattern) and runs until all senders are dropped.
pub async fn run_orchestrator(orchestrator: Arc<ApprovalOrchestrator>) {
    let mut request_rx = orchestrator
        .request_rx
        .lock()
        .unwrap()
        .take()
        .expect("run_orchestrator called more than once");
    let mut resolution_rx = orchestrator
        .resolution_rx
        .lock()
        .unwrap()
        .take()
        .expect("run_orchestrator called more than once");

    let mut tick = tokio::time::interval(Duration::from_millis(500));

    loop {
        tokio::select! {
            Some(request) = request_rx.recv() => {
                let req_clone = request.clone();
                let timeout_duration = request.timeout;
                let req_id = request.id.clone();

                // Insert into store
                orchestrator.store.lock().unwrap().insert(request);

                // Fan out to all available channels
                for ch in orchestrator.channels.available() {
                    let ch: Arc<dyn NotificationChannel> = Arc::clone(ch);
                    let req = req_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = ch.send_approval_request(&req).await {
                            eprintln!("[approval] failed to send request to {}: {}", ch.name(), e);
                        }
                    });
                }

                // Spawn a timeout watcher
                let res_tx = orchestrator.resolution_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(timeout_duration).await;
                    let _ = res_tx.send((
                        req_id,
                        ApprovalResolution::TimedOut { at: Utc::now() },
                    )).await;
                });
            }
            Some((id, resolution)) = resolution_rx.recv() => {
                // Grab a clone of the request before resolving (resolve removes from pending)
                let original_request = orchestrator.store.lock().unwrap().get(&id).cloned();

                let was_pending = orchestrator.store.lock().unwrap().resolve(&id, resolution.clone());
                if !was_pending {
                    continue; // Duplicate or late resolution — silently drop
                }

                // Determine which channel resolved it so we skip notifying that one
                let via = match &resolution {
                    ApprovalResolution::Approved { via, .. } => Some(via.clone()),
                    ApprovalResolution::Denied { via, .. } => Some(via.clone()),
                    ApprovalResolution::TimedOut { .. } => None,
                };

                // Notify all other channels about the resolution
                if let Some(req) = original_request {
                    for ch in orchestrator.channels.available() {
                        if let Some(ref v) = via {
                            if ch.name() == v {
                                continue; // Skip the channel that originated this resolution
                            }
                        }
                        let ch: Arc<dyn NotificationChannel> = Arc::clone(ch);
                        let req_clone = req.clone();
                        let res_clone = resolution.clone();
                        tokio::spawn(async move {
                            if let Err(e) = ch.send_resolution(&req_clone, &res_clone).await {
                                eprintln!("[approval] failed to send resolution to {}: {}", ch.name(), e);
                            }
                        });
                    }
                }
            }
            _ = tick.tick() => {
                // Belt-and-suspenders: collect expired requests and send TimedOut resolutions
                let expired = orchestrator.store.lock().unwrap().collect_expired();
                for id in expired {
                    let _ = orchestrator.resolution_tx.send((
                        id,
                        ApprovalResolution::TimedOut { at: Utc::now() },
                    )).await;
                }
            }
        }
    }
}

/// Serde helper for `std::time::Duration` serialized as whole seconds (u64).
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Notification;
    use async_trait::async_trait;

    /// Helper: create a test approval request with the given timeout.
    fn make_request(timeout: Duration) -> ApprovalRequest {
        ApprovalRequest::new(
            ApprovalSource::ClawSudo {
                policy_rule: Some("test-rule".to_string()),
            },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "test context".to_string(),
            timeout,
        )
    }

    /// Mock notification channel that records calls via a shared log.
    struct MockChannel {
        channel_name: String,
        log: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl MockChannel {
        fn new(name: &str, log: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
            Self {
                channel_name: name.to_string(),
                log,
            }
        }
    }

    #[async_trait]
    impl NotificationChannel for MockChannel {
        fn name(&self) -> &str {
            &self.channel_name
        }

        fn is_available(&self) -> bool {
            true
        }

        async fn send_approval_request(&self, request: &ApprovalRequest) -> anyhow::Result<()> {
            self.log.lock().unwrap().push(format!(
                "{}:request:{}",
                self.channel_name, request.id
            ));
            Ok(())
        }

        async fn send_resolution(
            &self,
            request: &ApprovalRequest,
            resolution: &ApprovalResolution,
        ) -> anyhow::Result<()> {
            self.log.lock().unwrap().push(format!(
                "{}:resolution:{}:{}",
                self.channel_name, request.id, resolution
            ));
            Ok(())
        }

        async fn send_notification(&self, _notification: &Notification) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_orchestrator_submit_and_get_status() {
        let orch = Arc::new(ApprovalOrchestrator::new(ChannelRegistry::new(), 100));
        let orch2 = Arc::clone(&orch);
        let handle = tokio::spawn(async move {
            run_orchestrator(orch2).await;
        });

        let req = make_request(Duration::from_secs(300));
        let id = orch.submit(req).await.expect("submit failed");

        // Give the loop time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(orch.get_status(&id), Some(ApprovalStatus::Pending));

        handle.abort();
    }

    #[tokio::test]
    async fn test_orchestrator_resolve_changes_status() {
        let orch = Arc::new(ApprovalOrchestrator::new(ChannelRegistry::new(), 100));
        let orch2 = Arc::clone(&orch);
        let handle = tokio::spawn(async move {
            run_orchestrator(orch2).await;
        });

        let req = make_request(Duration::from_secs(300));
        let id = orch.submit(req).await.expect("submit failed");
        tokio::time::sleep(Duration::from_millis(50)).await;

        orch.resolve(
            id.clone(),
            ApprovalResolution::Approved {
                by: "admin".to_string(),
                via: "api".to_string(),
                message: None,
                at: Utc::now(),
            },
        )
        .await
        .expect("resolve failed");

        tokio::time::sleep(Duration::from_millis(50)).await;

        match orch.get_status(&id) {
            Some(ApprovalStatus::Resolved(ApprovalResolution::Approved { .. })) => {}
            other => panic!("expected Resolved(Approved), got {:?}", other),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_orchestrator_broadcasts_to_all_channels() {
        let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = ChannelRegistry::new();
        registry.register(Arc::new(MockChannel::new("slack", Arc::clone(&log))));
        registry.register(Arc::new(MockChannel::new("tui", Arc::clone(&log))));

        let orch = Arc::new(ApprovalOrchestrator::new(registry, 100));
        let orch2 = Arc::clone(&orch);
        let handle = tokio::spawn(async move {
            run_orchestrator(orch2).await;
        });

        let req = make_request(Duration::from_secs(300));
        let id = orch.submit(req).await.expect("submit failed");

        // Give spawned tasks time to execute
        tokio::time::sleep(Duration::from_millis(100)).await;

        let entries = log.lock().unwrap().clone();
        let slack_received = entries
            .iter()
            .any(|e| e.starts_with("slack:request:") && e.ends_with(&id));
        let tui_received = entries
            .iter()
            .any(|e| e.starts_with("tui:request:") && e.ends_with(&id));

        assert!(
            slack_received,
            "slack should have received the request, log: {:?}",
            entries
        );
        assert!(
            tui_received,
            "tui should have received the request, log: {:?}",
            entries
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_orchestrator_first_responder_wins() {
        let orch = Arc::new(ApprovalOrchestrator::new(ChannelRegistry::new(), 100));
        let orch2 = Arc::clone(&orch);
        let handle = tokio::spawn(async move {
            run_orchestrator(orch2).await;
        });

        let req = make_request(Duration::from_secs(300));
        let id = orch.submit(req).await.expect("submit failed");
        tokio::time::sleep(Duration::from_millis(50)).await;

        // First resolution from slack
        orch.resolve(
            id.clone(),
            ApprovalResolution::Approved {
                by: "admin".to_string(),
                via: "slack".to_string(),
                message: None,
                at: Utc::now(),
            },
        )
        .await
        .expect("resolve failed");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second resolution from tui — should be silently dropped
        orch.resolve(
            id.clone(),
            ApprovalResolution::Denied {
                by: "jr".to_string(),
                via: "tui".to_string(),
                message: None,
                at: Utc::now(),
            },
        )
        .await
        .expect("resolve failed");

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Status should still reflect the first resolution (Approved via slack)
        match orch.get_status(&id) {
            Some(ApprovalStatus::Resolved(ApprovalResolution::Approved { via, .. })) => {
                assert_eq!(via, "slack");
            }
            other => panic!("expected Resolved(Approved via slack), got {:?}", other),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_orchestrator_timeout_resolves_as_timed_out() {
        let orch = Arc::new(ApprovalOrchestrator::new(ChannelRegistry::new(), 100));
        let orch2 = Arc::clone(&orch);
        let handle = tokio::spawn(async move {
            run_orchestrator(orch2).await;
        });

        let req = make_request(Duration::from_millis(50));
        let id = orch.submit(req).await.expect("submit failed");

        // Wait for the timeout to fire and be processed
        tokio::time::sleep(Duration::from_millis(200)).await;

        match orch.get_status(&id) {
            Some(ApprovalStatus::Resolved(ApprovalResolution::TimedOut { .. })) => {}
            other => panic!("expected Resolved(TimedOut), got {:?}", other),
        }

        handle.abort();
    }

    #[test]
    fn test_approval_request_creation() {
        let req = ApprovalRequest::new(
            ApprovalSource::ClawSudo { policy_rule: Some("allow-apt".to_string()) },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "Package installation request".to_string(),
            Duration::from_secs(300),
        );

        assert!(!req.id.is_empty());
        // UUID v4 format: 8-4-4-4-12 hex chars
        assert_eq!(req.id.len(), 36);
        assert!(matches!(req.source, ApprovalSource::ClawSudo { .. }));
        assert_eq!(req.command, "apt install curl");
        assert_eq!(req.agent, "openclaw");
        assert_eq!(req.severity, Severity::Warning);
        // Timestamp should be very recent (within last 5 seconds)
        let age = Utc::now() - req.created_at;
        assert!(age.num_seconds() < 5);
    }

    #[test]
    fn test_approval_resolution_display() {
        let approved = ApprovalResolution::Approved {
            by: "admin".to_string(),
            via: "slack".to_string(),
            message: None,
            at: Utc::now(),
        };
        assert_eq!(format!("{}", approved), "Approved by admin via slack");

        let denied = ApprovalResolution::Denied {
            by: "jr".to_string(),
            via: "tui".to_string(),
            message: Some("too risky".to_string()),
            at: Utc::now(),
        };
        assert_eq!(format!("{}", denied), "Denied by jr via tui");

        let timed_out = ApprovalResolution::TimedOut { at: Utc::now() };
        assert_eq!(format!("{}", timed_out), "Timed out");
    }

    #[test]
    fn test_approval_source_serialization() {
        let source = ApprovalSource::ClawSudo {
            policy_rule: Some("allow-apt".to_string()),
        };
        let json = serde_json::to_string(&source).expect("serialize");
        let deserialized: ApprovalSource = serde_json::from_str(&json).expect("deserialize");

        match deserialized {
            ApprovalSource::ClawSudo { policy_rule } => {
                assert_eq!(policy_rule, Some("allow-apt".to_string()));
            }
            _ => panic!("expected ClawSudo variant"),
        }
    }

    #[test]
    fn test_is_expired() {
        let req = ApprovalRequest::new(
            ApprovalSource::ResponseEngine {
                threat_id: "THR-001".to_string(),
                playbook: None,
            },
            "kill -9 1234".to_string(),
            "openclaw".to_string(),
            Severity::Critical,
            "Suspicious process detected".to_string(),
            Duration::from_millis(0),
        );

        assert!(req.is_expired());
    }
}
