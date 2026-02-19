#![allow(dead_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Approval request store — tracks pending and resolved approval requests.
//!
//! The [`ApprovalStore`] is the data layer for the approval orchestrator. It
//! maintains a map of pending requests (awaiting human response) and a bounded
//! ring buffer of resolved requests (for audit and API queries).

use std::collections::{HashMap, VecDeque};

use super::{ApprovalRequest, ApprovalResolution};

/// Tracks pending and resolved approval requests.
///
/// Pending requests are keyed by their unique ID. Resolved requests are stored
/// in a bounded ring buffer that trims to `max_history` entries.
pub struct ApprovalStore {
    pending: HashMap<String, ApprovalRequest>,
    resolved: VecDeque<(String, ApprovalResolution)>,
    max_history: usize,
}

impl ApprovalStore {
    /// Create an empty store with the given resolved-history capacity.
    pub fn new(max_history: usize) -> Self {
        Self {
            pending: HashMap::new(),
            resolved: VecDeque::new(),
            max_history,
        }
    }

    /// Add a request to the pending map, keyed by its ID.
    pub fn insert(&mut self, request: ApprovalRequest) {
        self.pending.insert(request.id.clone(), request);
    }

    /// Look up a pending request by ID.
    pub fn get(&self, id: &str) -> Option<&ApprovalRequest> {
        self.pending.get(id)
    }

    /// Returns `true` if the given ID is currently pending.
    pub fn is_pending(&self, id: &str) -> bool {
        self.pending.contains_key(id)
    }

    /// Move a request from pending to resolved.
    ///
    /// Returns `false` if the ID is not in the pending map (idempotent).
    /// Trims the resolved history to `max_history` after insertion.
    pub fn resolve(&mut self, id: &str, resolution: ApprovalResolution) -> bool {
        if self.pending.remove(id).is_none() {
            return false;
        }
        self.resolved.push_back((id.to_string(), resolution));
        while self.resolved.len() > self.max_history {
            self.resolved.pop_front();
        }
        true
    }

    /// Returns IDs of pending requests that have exceeded their timeout.
    ///
    /// Does **not** remove them from the pending map — the caller is expected
    /// to resolve each as [`ApprovalResolution::TimedOut`].
    pub fn collect_expired(&mut self) -> Vec<String> {
        self.pending
            .values()
            .filter(|req| req.is_expired())
            .map(|req| req.id.clone())
            .collect()
    }

    /// Number of currently pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Iterate over all pending requests.
    pub fn pending_iter(&self) -> impl Iterator<Item = &ApprovalRequest> {
        self.pending.values()
    }

    /// Look up a resolution in the resolved history by ID.
    pub fn get_resolution(&self, id: &str) -> Option<&ApprovalResolution> {
        self.resolved
            .iter()
            .rev()
            .find(|(rid, _)| rid == id)
            .map(|(_, res)| res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalSource;
    use crate::core::alerts::Severity;
    use chrono::Utc;
    use std::time::Duration;

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

    /// Helper: create an Approved resolution.
    fn make_approved() -> ApprovalResolution {
        ApprovalResolution::Approved {
            by: "admin".to_string(),
            via: "slack".to_string(),
            message: None,
            at: Utc::now(),
        }
    }

    #[test]
    fn test_insert_and_get() {
        let mut store = ApprovalStore::new(100);
        let req = make_request(Duration::from_secs(300));
        let id = req.id.clone();

        store.insert(req);

        assert!(store.get(&id).is_some());
        assert_eq!(store.get(&id).unwrap().command, "apt install curl");
        assert!(store.is_pending(&id));
        assert_eq!(store.pending_count(), 1);
    }

    #[test]
    fn test_resolve_pending() {
        let mut store = ApprovalStore::new(100);
        let req = make_request(Duration::from_secs(300));
        let id = req.id.clone();
        store.insert(req);

        let resolution = make_approved();
        assert!(store.resolve(&id, resolution));

        assert!(!store.is_pending(&id));
        assert!(store.get(&id).is_none());

        let res = store.get_resolution(&id);
        assert!(res.is_some());
        assert!(matches!(res.unwrap(), ApprovalResolution::Approved { .. }));
    }

    #[test]
    fn test_resolve_idempotent() {
        let mut store = ApprovalStore::new(100);
        let req = make_request(Duration::from_secs(300));
        let id = req.id.clone();
        store.insert(req);

        assert!(store.resolve(&id, make_approved()));
        // Second resolve of the same ID should return false.
        assert!(!store.resolve(&id, make_approved()));
    }

    #[test]
    fn test_is_pending_after_resolve() {
        let mut store = ApprovalStore::new(100);
        let req = make_request(Duration::from_secs(300));
        let id = req.id.clone();
        store.insert(req);

        assert!(store.is_pending(&id));
        store.resolve(&id, make_approved());
        assert!(!store.is_pending(&id));
    }

    #[test]
    fn test_resolved_history_ring_buffer() {
        let max = 100;
        let mut store = ApprovalStore::new(max);

        let mut ids = Vec::new();
        for _ in 0..200 {
            let req = make_request(Duration::from_secs(300));
            ids.push(req.id.clone());
            store.insert(req);
        }

        // Resolve all 200.
        for id in &ids {
            store.resolve(id, make_approved());
        }

        // Only the most recent 100 should be retained.
        assert_eq!(store.resolved.len(), max);

        // First 100 should have been evicted.
        for id in &ids[..100] {
            assert!(store.get_resolution(id).is_none());
        }

        // Last 100 should still be present.
        for id in &ids[100..] {
            assert!(store.get_resolution(id).is_some());
        }
    }

    #[test]
    fn test_collect_expired() {
        let mut store = ApprovalStore::new(100);

        // Insert a request with zero timeout — immediately expired.
        let expired_req = make_request(Duration::from_millis(0));
        let expired_id = expired_req.id.clone();
        store.insert(expired_req);

        // Give it a moment to be definitively past the deadline.
        std::thread::sleep(Duration::from_millis(1));

        let expired = store.collect_expired();
        assert!(
            expired.contains(&expired_id),
            "expected expired list to contain {}, got {:?}",
            expired_id,
            expired
        );

        // Insert a request with a long timeout — should NOT be expired.
        let fresh_req = make_request(Duration::from_secs(300));
        let fresh_id = fresh_req.id.clone();
        store.insert(fresh_req);

        let expired = store.collect_expired();
        assert!(
            !expired.contains(&fresh_id),
            "fresh request should not be expired"
        );

        // The expired request should still be in pending (collect_expired does not remove).
        assert!(store.is_pending(&expired_id));
    }
}
