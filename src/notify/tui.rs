// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! TUI notification channel.
//!
//! Bridges approval requests into the TUI popup system by sending them over a
//! tokio mpsc channel. The TUI main loop drains the receiver end and renders a
//! lightbox popup for each incoming request.
//!
//! Resolutions and generic notifications are no-ops — the TUI auto-updates by
//! polling the orchestrator store, and already receives alerts via its own
//! `alert_rx` channel.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use super::{Notification, NotificationChannel};

/// Notification channel that forwards approval requests to the TUI via an mpsc sender.
pub struct TuiChannel {
    request_tx: mpsc::Sender<ApprovalRequest>,
}

impl TuiChannel {
    /// Create a new TUI channel that sends approval requests on the given sender.
    pub fn new(request_tx: mpsc::Sender<ApprovalRequest>) -> Self {
        Self { request_tx }
    }
}

#[async_trait]
impl NotificationChannel for TuiChannel {
    fn name(&self) -> &str {
        "tui"
    }

    fn is_available(&self) -> bool {
        !self.request_tx.is_closed()
    }

    async fn send_approval_request(&self, request: &ApprovalRequest) -> anyhow::Result<()> {
        // Graceful degradation: if the channel is closed (TUI exited), silently succeed.
        let _ = self.request_tx.send(request.clone()).await;
        Ok(())
    }

    async fn send_resolution(
        &self,
        _request: &ApprovalRequest,
        _resolution: &ApprovalResolution,
    ) -> anyhow::Result<()> {
        // No-op: the TUI auto-updates by polling the orchestrator store.
        Ok(())
    }

    async fn send_notification(&self, _notification: &Notification) -> anyhow::Result<()> {
        // No-op: the TUI already receives alerts via its own alert_rx channel.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::approval::ApprovalSource;
    use crate::core::alerts::Severity;

    /// Helper: create a test approval request.
    fn make_request() -> ApprovalRequest {
        ApprovalRequest::new(
            ApprovalSource::ClawSudo {
                policy_rule: Some("test-rule".to_string()),
            },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "test context".to_string(),
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_tui_channel_name() {
        let (tx, _rx) = mpsc::channel(1);
        let channel = TuiChannel::new(tx);
        assert_eq!(channel.name(), "tui");
    }

    #[test]
    fn test_tui_available_when_sender_connected() {
        let (tx, _rx) = mpsc::channel(1);
        let channel = TuiChannel::new(tx);
        assert!(channel.is_available());
    }

    #[test]
    fn test_tui_not_available_when_receiver_dropped() {
        let (tx, rx) = mpsc::channel::<ApprovalRequest>(1);
        drop(rx);
        let channel = TuiChannel::new(tx);
        assert!(!channel.is_available());
    }

    #[tokio::test]
    async fn test_tui_sends_request_on_channel() {
        let (tx, mut rx) = mpsc::channel(1);
        let channel = TuiChannel::new(tx);

        let request = make_request();
        let expected_id = request.id.clone();

        channel
            .send_approval_request(&request)
            .await
            .expect("send should succeed");

        let received = rx.recv().await.expect("should receive request");
        assert_eq!(received.id, expected_id);
        assert_eq!(received.command, "apt install curl");
    }
}
