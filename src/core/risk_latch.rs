// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Risk latch: session-level risk accumulator for containment decisions.
//!
//! Tracks weighted risk events within a sliding window. When the accumulated
//! risk exceeds a threshold, the latch triggers (one-way) and the system
//! should enter containment mode. Critical events count double.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::alerts::Severity;

/// One-way risk accumulator that triggers when session risk exceeds a threshold.
///
/// Events are weighted by severity (Critical=2, Warning=1, Info=0) and expire
/// after a configurable window. Once triggered, the latch stays triggered for
/// the remainder of the session.
pub struct RiskLatch {
    threshold: u32,
    window: Duration,
    events: VecDeque<(Instant, u32)>,
    triggered: bool,
}

impl RiskLatch {
    pub fn new(threshold: u32, window: Duration) -> Self {
        Self {
            threshold,
            window,
            events: VecDeque::new(),
            triggered: false,
        }
    }

    /// Record a risk event. Returns true if the latch has triggered.
    pub fn record_event(&mut self, _description: &str, severity: Severity) -> bool {
        let now = Instant::now();

        // Expire old events
        while let Some(&(ts, _)) = self.events.front() {
            if now.duration_since(ts) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }

        // Weight: Critical=2, Warning=1, Info=0
        let weight = match severity {
            Severity::Critical => 2,
            Severity::Warning => 1,
            Severity::Info => 0,
        };

        if weight > 0 {
            self.events.push_back((now, weight));
        }

        let total: u32 = self.events.iter().map(|(_, w)| w).sum();
        if total >= self.threshold {
            self.triggered = true;
        }

        self.triggered
    }

    /// Check if the latch has been triggered.
    pub fn is_triggered(&self) -> bool {
        self.triggered
    }

    /// Current accumulated risk weight (within window).
    pub fn current_risk(&self) -> u32 {
        self.events.iter().map(|(_, w)| w).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_latch_triggers_on_threshold() {
        let mut latch = RiskLatch::new(5, Duration::from_secs(300));

        for i in 0..4 {
            let triggered = latch.record_event(&format!("event {}", i), Severity::Warning);
            assert!(!triggered, "Should not trigger before threshold (event {})", i);
        }
        let triggered = latch.record_event("event 4", Severity::Warning);
        assert!(triggered, "Should trigger at threshold");
    }

    #[test]
    fn test_risk_latch_window_expiry() {
        let mut latch = RiskLatch::new(3, Duration::from_millis(50));
        latch.record_event("old event", Severity::Warning);
        std::thread::sleep(Duration::from_millis(60));
        // Old events should have expired
        assert!(!latch.record_event("new event", Severity::Warning));
    }

    #[test]
    fn test_risk_latch_critical_counts_double() {
        let mut latch = RiskLatch::new(4, Duration::from_secs(300));
        latch.record_event("crit 1", Severity::Critical); // weight 2
        latch.record_event("crit 2", Severity::Critical); // weight 2, total = 4
        assert!(latch.is_triggered(), "Two Critical events should trigger threshold of 4");
    }

    #[test]
    fn test_risk_latch_info_ignored() {
        let mut latch = RiskLatch::new(2, Duration::from_secs(300));
        for _ in 0..100 {
            latch.record_event("info", Severity::Info);
        }
        assert!(!latch.is_triggered(), "Info events (weight 0) should never trigger");
    }

    #[test]
    fn test_risk_latch_stays_triggered() {
        let mut latch = RiskLatch::new(1, Duration::from_millis(10));
        latch.record_event("trigger", Severity::Warning);
        assert!(latch.is_triggered());

        // Even after window expires, latch stays triggered (one-way)
        std::thread::sleep(Duration::from_millis(20));
        assert!(latch.is_triggered(), "Latch is one-way — stays triggered");
    }

    #[test]
    fn test_risk_latch_current_risk() {
        let mut latch = RiskLatch::new(100, Duration::from_secs(300));
        latch.record_event("w1", Severity::Warning);   // 1
        latch.record_event("c1", Severity::Critical);  // 2
        latch.record_event("i1", Severity::Info);       // 0
        assert_eq!(latch.current_risk(), 3);
    }

    #[test]
    fn test_risk_latch_mixed_severity() {
        let mut latch = RiskLatch::new(5, Duration::from_secs(300));
        latch.record_event("w1", Severity::Warning);   // 1
        latch.record_event("w2", Severity::Warning);   // 1 (total 2)
        latch.record_event("c1", Severity::Critical);  // 2 (total 4)
        assert!(!latch.is_triggered());
        latch.record_event("w3", Severity::Warning);   // 1 (total 5)
        assert!(latch.is_triggered(), "Mixed severity should trigger at exact threshold");
    }
}
