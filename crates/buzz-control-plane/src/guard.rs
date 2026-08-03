//! In-memory abuse guards: NIP-98 replay cache and sliding-window rate
//! limiting. Both are per-process; for multi-replica deployments swap in a
//! Redis-backed implementation with the same semantics.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Remembers recently seen NIP-98 event ids so a captured Authorization
/// header cannot be replayed within its 60-second validity window.
pub struct ReplayCache {
    seen: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    /// Create a cache with a 120-second TTL (NIP-98 window is 60s; keep a
    /// margin so boundary replays are still caught).
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(120),
        }
    }

    /// Returns true if this event id is fresh; false if it is a replay.
    /// Expired entries are swept on the same call.
    pub fn check_and_insert(&self, event_id: &str) -> bool {
        let now = Instant::now();
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.retain(|_, at| now.duration_since(*at) < self.ttl);
        seen.insert(event_id.to_string(), now).is_none()
    }
}

/// Per-key sliding-window rate limiter.
pub struct RateLimiter {
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
    window: Duration,
    max: usize,
}

impl RateLimiter {
    /// Allow at most `max` calls per `window` for each key.
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
            max: max as usize,
        }
    }

    /// Record an attempt for `key`; returns true if it is within the limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = match self.hits.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let deque = hits.entry(key.to_string()).or_default();
        while let Some(front) = deque.front() {
            if now.duration_since(*front) >= self.window {
                deque.pop_front();
            } else {
                break;
            }
        }
        if deque.len() >= self.max {
            return false;
        }
        deque.push_back(now);
        true
    }
}
