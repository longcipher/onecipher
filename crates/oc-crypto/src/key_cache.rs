//! Generic TTL + LRU cache for derived keys with zeroizing storage.
//!
//! The cache is generic over the value type `V`. Callers typically use
//! [`crate::HardenedBytes`], whose `Drop` impl triggers zeroize + munlock.
//! All eviction paths drop entries via standard `Drop` semantics, so any
//! `Drop`-based cleanup (zeroize, munlock) runs automatically.
//!
//! Per R51/R52: this module uses only `std::sync` / `std::time` / `std::collections`
//! — zero I/O, zero network deps.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Default TTL: 5 seconds (R77 — unchanged from the Open Wallet Standard).
pub const DEFAULT_TTL: Duration = Duration::from_secs(5);

/// Default max entries: 32 (R77 — unchanged from the Open Wallet Standard).
pub const DEFAULT_MAX_ENTRIES: usize = 32;

struct CacheEntry<V> {
    key: V,
    last_accessed: Instant,
}

/// A TTL + LRU cache for derived keys.
///
/// All entries are dropped (and thus zeroized if `V` is `HardenedBytes`)
/// on eviction or `Drop`. The cache is keyed by an opaque `String` id
/// (typically a CAIP-2 chain id like `"eip155:1"`).
///
/// For the T13 MVP, the Key-Agent is assumed to be single-wallet-per-process;
/// if multi-wallet support is added later, the cache key must include a
/// wallet id to avoid returning a key derived from one wallet's mnemonic to
/// a different wallet's signing request.
pub struct KeyCache<V: Clone + Send + Sync + 'static> {
    entries: Mutex<HashMap<String, CacheEntry<V>>>,
    ttl: Duration,
    max_entries: usize,
}

impl<V: Clone + Send + Sync + 'static> KeyCache<V> {
    /// Create a cache with an explicit TTL and max-entries cap.
    ///
    /// Useful in tests where a short TTL is needed to verify expiry without
    /// sleeping for 5 seconds.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), ttl, max_entries }
    }

    /// Look up a key by id. Returns `None` if missing or expired.
    ///
    /// Updates `last_accessed` on hit (LRU semantics). Returns a clone of the
    /// stored value — for `HardenedBytes`, the clone is independently
    /// page-locked + zeroized on `Drop`, so the caller's copy is bounded by
    /// the caller's scope.
    pub fn get(&self, id: &str) -> Option<V> {
        let mut map = self.entries.lock().unwrap();
        let entry = map.get(id)?;
        if entry.last_accessed.elapsed() > self.ttl {
            map.remove(id);
            return None;
        }
        let cloned = entry.key.clone();
        // Update access time for LRU ordering.
        map.get_mut(id).unwrap().last_accessed = Instant::now();
        Some(cloned)
    }

    /// Insert a key under `id`, evicting expired entries and the LRU entry
    /// if at capacity. The cache takes ownership of the value — evicting it
    /// later triggers `Drop` (zeroize + munlock for `HardenedBytes`).
    pub fn insert(&self, id: &str, key: V) {
        let mut map = self.entries.lock().unwrap();
        self.evict_expired_inner(&mut map);

        if map.len() >= self.max_entries && !map.contains_key(id) {
            // Evict the least-recently-used entry. Iterating the whole map is
            // O(n) but n ≤ 32, so this is negligible.
            if let Some(lru_key) =
                map.iter().min_by_key(|(_, e)| e.last_accessed).map(|(k, _)| k.clone())
            {
                map.remove(&lru_key);
            }
        }

        map.insert(id.to_string(), CacheEntry { key, last_accessed: Instant::now() });
    }

    /// Clear all entries. Triggers `Drop` on every value.
    pub fn clear(&self) {
        let mut map = self.entries.lock().unwrap();
        map.clear();
    }

    /// Evict only expired entries. Called opportunistically by `insert`.
    pub fn evict_expired(&self) {
        let mut map = self.entries.lock().unwrap();
        self.evict_expired_inner(&mut map);
    }

    fn evict_expired_inner(&self, map: &mut HashMap<String, CacheEntry<V>>) {
        map.retain(|_, entry| entry.last_accessed.elapsed() <= self.ttl);
    }

    /// Current number of entries (including any that are expired but not yet
    /// reaped).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// TTL configured for this cache.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Max entries configured for this cache.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
}

impl<V: Clone + Send + Sync + 'static> Default for KeyCache<V> {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_MAX_ENTRIES)
    }
}

impl<V: Clone + Send + Sync + 'static> Drop for KeyCache<V> {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_insert_and_get() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(5), 10);
        cache.insert("key1", 42);
        assert_eq!(cache.get("key1"), Some(42));
    }

    #[test]
    fn test_missing_key() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(5), 10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_expiry() {
        let cache = KeyCache::<u32>::new(Duration::from_millis(50), 10);
        cache.insert("key1", 1);
        assert!(cache.get("key1").is_some());

        thread::sleep(Duration::from_millis(100));
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_max_entries_evicts_lru() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(5), 2);
        cache.insert("a", 1);
        thread::sleep(Duration::from_millis(10));
        cache.insert("b", 2);
        thread::sleep(Duration::from_millis(10));

        // Access "a" to make it more recent than "b".
        cache.get("a");
        thread::sleep(Duration::from_millis(10));

        // Insert "c" — should evict "b" (least recently accessed).
        cache.insert("c", 3);
        assert_eq!(cache.len(), 2);
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn test_clear() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(5), 10);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_evict_expired() {
        let cache = KeyCache::<u32>::new(Duration::from_millis(50), 10);
        cache.insert("a", 1);
        thread::sleep(Duration::from_millis(100));
        cache.insert("b", 2);

        cache.evict_expired();
        assert_eq!(cache.len(), 1);
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_TTL, Duration::from_secs(5));
        assert_eq!(DEFAULT_MAX_ENTRIES, 32);
        let cache = KeyCache::<u32>::default();
        assert_eq!(cache.ttl(), DEFAULT_TTL);
        assert_eq!(cache.max_entries(), DEFAULT_MAX_ENTRIES);
    }
}
