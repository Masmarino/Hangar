//! Rate limiting for failed login attempts. In-memory only, per-instance, keyed by username rather than client IP — fine for a self-hosted tool, not a distributed one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_LOGIN_ATTEMPTS: usize = 10;
pub const LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(300);
/// Evicts the quietest entry once reached, bounding memory against an attacker cycling through unbounded distinct usernames.
pub const MAX_TRACKED_USERNAMES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedUsername {
    pub username: String,
    pub remaining_seconds: u64,
}

#[derive(Clone)]
pub struct LoginThrottle {
    attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self { attempts: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Expired entries are pruned lazily here, not by a background sweeper.
    pub fn is_throttled(&self, key: &str, max_attempts: usize, window: Duration) -> bool {
        let mut attempts = self.lock();
        let Some(timestamps) = attempts.get_mut(key) else {
            return false;
        };
        prune(timestamps, window);
        if timestamps.is_empty() {
            attempts.remove(key);
            return false;
        }
        timestamps.len() >= max_attempts
    }

    pub fn record_failure(&self, key: &str, max_attempts: usize, window: Duration) {
        let mut attempts = self.lock();
        if !attempts.contains_key(key) && attempts.len() >= MAX_TRACKED_USERNAMES {
            // LRU-by-last-attempt eviction to keep the map bounded.
            if let Some(evict_key) = attempts
                .iter()
                .min_by_key(|(_, timestamps)| timestamps.last())
                .map(|(key, _)| key.clone())
            {
                attempts.remove(&evict_key);
            }
        }
        let timestamps = attempts.entry(key.to_string()).or_default();
        prune(timestamps, window);
        if timestamps.len() <= max_attempts {
            timestamps.push(Instant::now());
        }
    }

    pub fn clear(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Reports every currently-blocked key against the given limits — a caller with several
    /// orgs' worth of tracked keys would call this once per distinct limit it cares about.
    pub fn blocked_usernames(&self, max_attempts: usize, window: Duration) -> Vec<BlockedUsername> {
        let mut attempts = self.lock();
        let now = Instant::now();
        let mut blocked = Vec::new();
        attempts.retain(|username, timestamps| {
            prune(timestamps, window);
            if timestamps.is_empty() {
                return false;
            }
            if timestamps.len() >= max_attempts {
                let oldest = *timestamps.iter().min().expect("just checked non-empty");
                let remaining = window.saturating_sub(now.duration_since(oldest));
                blocked.push(BlockedUsername { username: username.clone(), remaining_seconds: remaining.as_secs() });
            }
            true
        });
        blocked.sort_by_key(|b| std::cmp::Reverse(b.remaining_seconds));
        blocked
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Instant>>> {
        self.attempts.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn prune(timestamps: &mut Vec<Instant>, window: Duration) {
    let now = Instant::now();
    timestamps.retain(|at| now.duration_since(*at) < window);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_username_is_not_throttled() {
        let throttle = LoginThrottle::new();
        assert!(!throttle.is_throttled("florian", MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW));
    }

    #[test]
    fn stays_below_the_threshold_until_the_limit_is_reached() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 3, LOGIN_ATTEMPT_WINDOW);
        throttle.record_failure("florian", 3, LOGIN_ATTEMPT_WINDOW);
        assert!(!throttle.is_throttled("florian", 3, LOGIN_ATTEMPT_WINDOW));
        throttle.record_failure("florian", 3, LOGIN_ATTEMPT_WINDOW);
        assert!(throttle.is_throttled("florian", 3, LOGIN_ATTEMPT_WINDOW));
    }

    #[test]
    fn throttling_is_scoped_to_one_username() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        assert!(throttle.is_throttled("florian", 2, LOGIN_ATTEMPT_WINDOW));
        assert!(!throttle.is_throttled("someone-else", 2, LOGIN_ATTEMPT_WINDOW));
    }

    #[test]
    fn clearing_resets_the_tally() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        assert!(throttle.is_throttled("florian", 2, LOGIN_ATTEMPT_WINDOW));
        throttle.clear("florian");
        assert!(!throttle.is_throttled("florian", 2, LOGIN_ATTEMPT_WINDOW));
    }

    #[test]
    fn lists_blocked_usernames_but_not_ones_below_the_threshold() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        throttle.record_failure("florian", 2, LOGIN_ATTEMPT_WINDOW);
        throttle.record_failure("almost-blocked", 2, LOGIN_ATTEMPT_WINDOW);

        let blocked = throttle.blocked_usernames(2, LOGIN_ATTEMPT_WINDOW);

        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].username, "florian");
        assert!(blocked[0].remaining_seconds > 0 && blocked[0].remaining_seconds <= LOGIN_ATTEMPT_WINDOW.as_secs());
    }

    #[test]
    fn blocked_usernames_is_empty_when_nobody_is_throttled() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW);
        assert!(throttle.blocked_usernames(MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW).is_empty());
    }

    #[test]
    fn a_username_drops_off_blocked_usernames_once_its_window_expires() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 2, Duration::from_millis(30));
        throttle.record_failure("florian", 2, Duration::from_millis(30));
        assert_eq!(throttle.blocked_usernames(2, Duration::from_millis(30)).len(), 1);

        std::thread::sleep(Duration::from_millis(60));

        assert!(throttle.blocked_usernames(2, Duration::from_millis(30)).is_empty());
    }

    #[test]
    fn failures_older_than_the_window_are_pruned() {
        let throttle = LoginThrottle::new();
        throttle.record_failure("florian", 2, Duration::from_millis(30));
        throttle.record_failure("florian", 2, Duration::from_millis(30));
        assert!(throttle.is_throttled("florian", 2, Duration::from_millis(30)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!throttle.is_throttled("florian", 2, Duration::from_millis(30)));
    }

    #[test]
    fn the_tracked_username_map_never_grows_past_the_cap() {
        let throttle = LoginThrottle::new();
        for i in 0..(MAX_TRACKED_USERNAMES + 50) {
            throttle.record_failure(&format!("attacker-{i}"), MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW);
            assert!(throttle.len() <= MAX_TRACKED_USERNAMES);
        }
        assert_eq!(throttle.len(), MAX_TRACKED_USERNAMES);

        assert!(!throttle.is_throttled("attacker-0", MAX_LOGIN_ATTEMPTS, LOGIN_ATTEMPT_WINDOW));
    }
}
