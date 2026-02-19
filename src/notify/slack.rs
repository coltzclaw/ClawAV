#![allow(dead_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Slack notification channel with Block Kit interactive messages.
//!
//! Supports two modes of operation:
//!
//! - **Interactive (Block Kit):** When `app_token` is configured, approval requests
//!   are sent as Block Kit messages via `chat.postMessage` with Approve/Deny buttons.
//!   Slack interactive callbacks are verified with HMAC-SHA256 signatures.
//!
//! - **Webhook fallback:** When only a webhook URL is configured (no `app_token`),
//!   all messages use incoming webhooks — approval requests are text-only without
//!   interactive buttons.
//!
//! One-way notifications always use webhooks with color-coded attachments.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use crate::config::SlackConfig;
use crate::core::alerts::Severity;
use super::{Notification, NotificationChannel};

type HmacSha256 = Hmac<Sha256>;

/// Slack notification channel with Block Kit approvals and webhook fallback.
///
/// When `app_token` is set, sends interactive Block Kit messages for approvals.
/// Otherwise falls back to plain webhook messages for all notification types.
pub struct SlackChannel {
    webhook_url: String,
    backup_webhook_url: String,
    app_token: String,
    signing_secret: String,
    channel: String,
    approval_channel: String,
    enabled: bool,
    client: reqwest::Client,
}

impl SlackChannel {
    /// Create a new Slack channel from configuration.
    ///
    /// Automatically derives `enabled` from config if not explicitly set.
    /// Falls back `approval_channel` to the main channel if not specified.
    pub fn new(config: &SlackConfig) -> Self {
        let enabled = config.enabled.unwrap_or(!config.webhook_url.is_empty());
        let approval_channel = if config.approval_channel.is_empty() {
            config.channel.clone()
        } else {
            config.approval_channel.clone()
        };
        Self {
            webhook_url: config.webhook_url.clone(),
            backup_webhook_url: config.backup_webhook_url.clone(),
            app_token: config.app_token.clone(),
            signing_secret: config.signing_secret.clone(),
            channel: config.channel.clone(),
            approval_channel,
            enabled,
            client: reqwest::Client::new(),
        }
    }

    /// Post a JSON payload to the primary webhook, failing over to the backup.
    async fn post_webhook(&self, payload: &serde_json::Value) -> anyhow::Result<()> {
        let resp = self.client.post(&self.webhook_url).json(payload).send().await;

        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            _ => {
                if !self.backup_webhook_url.is_empty() {
                    self.client
                        .post(&self.backup_webhook_url)
                        .json(payload)
                        .send()
                        .await?;
                    Ok(())
                } else if let Err(e) = resp {
                    Err(e.into())
                } else {
                    anyhow::bail!("Primary webhook failed, no backup configured")
                }
            }
        }
    }
}

/// Build a Block Kit message payload for an approval request.
///
/// The message includes:
/// - Header with severity emoji and "Approval Request"
/// - Section with command, agent, source, and context
/// - Actions block with Approve (primary/green) and Deny (danger/red) buttons
/// - Each button's `value` field contains the request ID for callback routing
fn build_approval_block_kit(request: &ApprovalRequest) -> serde_json::Value {
    json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} Approval Request", request.severity.emoji()),
                    "emoji": true
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": format!("*Command:*\n`{}`", request.command)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Agent:*\n{}", request.agent)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Source:*\n{}", request.source)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Context:*\n{}", request.context)
                    }
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Approve",
                            "emoji": true
                        },
                        "style": "primary",
                        "action_id": "approve",
                        "value": request.id
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Deny",
                            "emoji": true
                        },
                        "style": "danger",
                        "action_id": "deny",
                        "value": request.id
                    }
                ]
            }
        ]
    })
}

#[async_trait]
impl NotificationChannel for SlackChannel {
    fn name(&self) -> &str {
        "slack"
    }

    fn is_available(&self) -> bool {
        self.enabled && !self.webhook_url.is_empty()
    }

    async fn send_approval_request(&self, request: &ApprovalRequest) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if !self.app_token.is_empty() {
            // Interactive Block Kit via chat.postMessage API
            let mut payload = build_approval_block_kit(request);
            payload["channel"] = json!(self.approval_channel);

            self.client
                .post("https://slack.com/api/chat.postMessage")
                .bearer_auth(&self.app_token)
                .json(&payload)
                .send()
                .await?;

            Ok(())
        } else {
            // Webhook fallback: text-only, no interactive buttons
            let payload = json!({
                "channel": self.approval_channel,
                "username": "ClawTower",
                "icon_emoji": ":shield:",
                "text": format!(
                    "{} *Approval Request*\n*Command:* `{}`\n*Agent:* {}\n*Source:* {}\n*Context:* {}\n_Respond via TUI or API — webhook mode has no interactive buttons._",
                    request.severity.emoji(),
                    request.command,
                    request.agent,
                    request.source,
                    request.context,
                )
            });
            self.post_webhook(&payload).await
        }
    }

    async fn send_resolution(
        &self,
        request: &ApprovalRequest,
        resolution: &ApprovalResolution,
    ) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let text = format!(
            "Resolved: {} for `{}`",
            resolution, request.command,
        );

        let payload = json!({
            "channel": self.approval_channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "text": text
        });

        self.post_webhook(&payload).await
    }

    async fn send_notification(&self, notification: &Notification) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let color = match notification.severity {
            Severity::Info => "#36a64f",
            Severity::Warning => "#daa520",
            Severity::Critical => "#dc3545",
        };

        let payload = json!({
            "channel": self.channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": format!("{} {}", notification.severity.emoji(), notification.title),
                "text": notification.body,
                "fields": [
                    { "title": "Severity", "value": notification.severity.to_string(), "short": true },
                    { "title": "Source", "value": notification.source, "short": true },
                ],
            }]
        });

        self.post_webhook(&payload).await
    }
}

/// Verify a Slack interactive callback signature.
///
/// Computes `v0={HMAC-SHA256(signing_secret, "v0:{timestamp}:{body}")}` and
/// compares with the provided `signature` (the `X-Slack-Signature` header).
///
/// Returns `true` if the signature is valid.
pub fn verify_slack_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &str,
    signature: &str,
) -> bool {
    let sig_basestring = format!("v0:{}:{}", timestamp, body);
    let mut mac = match HmacSha256::new_from_slice(signing_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(sig_basestring.as_bytes());
    let result = mac.finalize();
    let computed = format!("v0={}", hex::encode(result.into_bytes()));
    computed == signature
}

/// Parse a Slack interactive payload into an approval decision.
///
/// Slack sends interactive callbacks as URL-encoded form data with a `payload`
/// field containing JSON. This function decodes the payload and extracts:
///
/// - `request_id` — the button's `value` field (the approval request UUID)
/// - `approved` — `true` if `action_id == "approve"`, `false` for "deny"
/// - `username` — the Slack user who clicked the button
///
/// # Returns
///
/// A tuple of `(request_id, approved, username)` on success.
pub fn parse_slack_interaction(body: &str) -> anyhow::Result<(String, bool, String)> {
    // Slack posts: payload=URL_ENCODED_JSON
    let payload_json = if body.starts_with("payload=") {
        let encoded = &body["payload=".len()..];
        urlencoding_decode(encoded)?
    } else {
        body.to_string()
    };

    let payload: serde_json::Value = serde_json::from_str(&payload_json)?;

    let actions = payload
        .get("actions")
        .and_then(|a| a.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing actions array in Slack payload"))?;

    let action = actions
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty actions array in Slack payload"))?;

    let action_id = action
        .get("action_id")
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing action_id in Slack action"))?;

    let request_id = action
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing value in Slack action"))?
        .to_string();

    let approved = action_id == "approve";

    let username = payload
        .get("user")
        .and_then(|u| u.get("username"))
        .and_then(|u| u.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok((request_id, approved, username))
}

/// Simple percent-decode for Slack's URL-encoded payload.
///
/// Handles `%XX` hex sequences and `+` as space. This avoids pulling in
/// a full URL-encoding crate for a single use case.
fn urlencoding_decode(input: &str) -> anyhow::Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hi = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("truncated percent-encoding"))?;
                let lo = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("truncated percent-encoding"))?;
                let byte = u8::from_str_radix(&format!("{}{}", hi, lo), 16)?;
                output.push(byte as char);
            }
            '+' => output.push(' '),
            _ => output.push(c),
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::approval::ApprovalSource;
    use crate::core::alerts::Severity;

    /// Helper: build a SlackConfig for testing.
    fn test_config(webhook_url: &str, app_token: &str) -> SlackConfig {
        SlackConfig {
            enabled: None,
            webhook_url: webhook_url.to_string(),
            backup_webhook_url: String::new(),
            channel: "#alerts".to_string(),
            min_slack_level: "warning".to_string(),
            heartbeat_interval: 3600,
            app_token: app_token.to_string(),
            signing_secret: "test-signing-secret".to_string(),
            approval_channel: String::new(),
        }
    }

    /// Helper: create a test approval request.
    fn make_request() -> ApprovalRequest {
        ApprovalRequest::new(
            ApprovalSource::ClawSudo {
                policy_rule: Some("allow-apt".to_string()),
            },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "Package installation request".to_string(),
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_slack_channel_name() {
        let config = test_config("https://hooks.slack.com/services/T/B/X", "");
        let channel = SlackChannel::new(&config);
        assert_eq!(channel.name(), "slack");
    }

    #[test]
    fn test_slack_not_available_without_webhook() {
        let config = test_config("", "");
        let channel = SlackChannel::new(&config);
        assert!(!channel.is_available());
    }

    #[test]
    fn test_slack_available_with_webhook() {
        let config = test_config("https://hooks.slack.com/services/T/B/X", "");
        let channel = SlackChannel::new(&config);
        assert!(channel.is_available());
    }

    #[test]
    fn test_slack_approval_block_kit_format() {
        let request = make_request();
        let payload = build_approval_block_kit(&request);

        // Must have a blocks array
        let blocks = payload.get("blocks").and_then(|b| b.as_array());
        assert!(blocks.is_some(), "payload must have a blocks array");
        let blocks = blocks.unwrap();

        // Header block
        assert_eq!(blocks[0]["type"], "header");

        // Section block with fields
        assert_eq!(blocks[1]["type"], "section");
        let fields = blocks[1]["fields"].as_array().unwrap();
        assert!(fields.len() >= 4, "section must have at least 4 fields");

        // Actions block with approve and deny buttons
        assert_eq!(blocks[2]["type"], "actions");
        let elements = blocks[2]["elements"].as_array().unwrap();
        assert_eq!(elements.len(), 2, "must have exactly 2 action buttons");

        let approve_btn = &elements[0];
        assert_eq!(approve_btn["action_id"], "approve");
        assert_eq!(approve_btn["style"], "primary");
        assert_eq!(approve_btn["value"], request.id);

        let deny_btn = &elements[1];
        assert_eq!(deny_btn["action_id"], "deny");
        assert_eq!(deny_btn["style"], "danger");
        assert_eq!(deny_btn["value"], request.id);
    }

    #[test]
    fn test_slack_notification_payload_format() {
        let notification = Notification::new(
            Severity::Critical,
            "Privilege escalation detected".to_string(),
            "User 1000 ran sudo chattr".to_string(),
            "auditd".to_string(),
        );

        let color = match notification.severity {
            Severity::Info => "#36a64f",
            Severity::Warning => "#daa520",
            Severity::Critical => "#dc3545",
        };

        let payload = json!({
            "channel": "#alerts",
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": format!("{} {}", notification.severity.emoji(), notification.title),
                "text": notification.body,
                "fields": [
                    { "title": "Severity", "value": notification.severity.to_string(), "short": true },
                    { "title": "Source", "value": notification.source, "short": true },
                ],
            }]
        });

        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0]["color"], "#dc3545");
        assert!(attachments[0]["title"]
            .as_str()
            .unwrap()
            .contains("Privilege escalation"));
    }

    #[test]
    fn test_slack_signature_verification() {
        let secret = "8f742231b10e8888abcd99yez";
        let timestamp = "1531420618";
        let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J";

        // Compute expected HMAC
        let sig_basestring = format!("v0:{}:{}", timestamp, body);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(sig_basestring.as_bytes());
        let expected = format!("v0={}", hex::encode(mac.finalize().into_bytes()));

        // Correct signature should verify
        assert!(verify_slack_signature(secret, timestamp, body, &expected));

        // Wrong signature should fail
        assert!(!verify_slack_signature(secret, timestamp, body, "v0=bad"));

        // Wrong body should fail
        assert!(!verify_slack_signature(
            secret, timestamp, "tampered body", &expected
        ));
    }

    #[test]
    fn test_parse_slack_interaction() {
        let request_id = "550e8400-e29b-41d4-a716-446655440000";
        let payload_json = json!({
            "type": "block_actions",
            "user": {
                "id": "U12345",
                "username": "jrmorton"
            },
            "actions": [
                {
                    "action_id": "approve",
                    "value": request_id,
                    "type": "button"
                }
            ]
        });

        // URL-encode the payload as Slack would send it
        let payload_str = serde_json::to_string(&payload_json).unwrap();
        let encoded: String = payload_str
            .chars()
            .map(|c| match c {
                ' ' => "+".to_string(),
                c if c.is_ascii_alphanumeric() || "-._~".contains(c) => c.to_string(),
                c => format!("%{:02X}", c as u8),
            })
            .collect();
        let body = format!("payload={}", encoded);

        let (id, approved, username) = parse_slack_interaction(&body).unwrap();
        assert_eq!(id, request_id);
        assert!(approved, "action_id 'approve' should yield approved=true");
        assert_eq!(username, "jrmorton");

        // Test deny action
        let deny_payload = json!({
            "type": "block_actions",
            "user": {
                "id": "U12345",
                "username": "admin"
            },
            "actions": [
                {
                    "action_id": "deny",
                    "value": request_id,
                    "type": "button"
                }
            ]
        });

        let deny_str = serde_json::to_string(&deny_payload).unwrap();
        let deny_encoded: String = deny_str
            .chars()
            .map(|c| match c {
                ' ' => "+".to_string(),
                c if c.is_ascii_alphanumeric() || "-._~".contains(c) => c.to_string(),
                c => format!("%{:02X}", c as u8),
            })
            .collect();
        let deny_body = format!("payload={}", deny_encoded);

        let (id2, approved2, username2) = parse_slack_interaction(&deny_body).unwrap();
        assert_eq!(id2, request_id);
        assert!(!approved2, "action_id 'deny' should yield approved=false");
        assert_eq!(username2, "admin");
    }
}
