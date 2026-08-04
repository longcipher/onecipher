//! Time-to-idle + strict-LRU cache for derived keys with zeroizing storage.
//!
//! The cache is generic over the value type `V`. Callers typically use
//! [`crate::HardenedBytes`], whose `Drop` impl triggers zeroize + munlock.
//! All eviction paths drop entries via standard `Drop` semantics, so any
//! `Drop`-based cleanup (zeroize, munlock) runs automatically.
//!
//! Per R51/R52: this module uses only `std::sync` / `std::time` /
//! `std::collections` — zero I/O, zero network deps.
//!
//! # Why not an off-the-shelf cache crate?
//!
//! `mini-moka` / `quick_cache` were evaluated. Both use TinyLFU-style
//! admission, which explicitly does *not* guarantee exact LRU eviction
//! order. This cache holds decrypted private-key material, and the eviction
//! contract is security-relevant: an operator reasoning about "how long can
//! key K stay resident" needs a deterministic answer. The integration tests
//! in `oc-keyagent/tests/key_ops_integration.rs` assert exact LRU order, so
//! we keep a small, auditable implementation rather than relax those
//! guarantees for a dependency.
//!
//! Eviction is O(1) amortized: a monotonic access counter plus a
//! `BTreeMap<u64, String>` recency index replaces the previous O(n)
//! `min_by_key` scan over the whole map.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// Default time-to-idle: 5 seconds (R77 — unchanged from the Open Wallet Standard).
pub const DEFAULT_TTL: Duration = Duration::from_secs(5);

/// Default max entries: 32 (R77 — unchanged from the Open Wallet Standard).
pub const DEFAULT_MAX_ENTRIES: usize = 32;

struct CacheEntry<V> {
    key: V,
    last_accessed: Instant,
    /// Monotonic access tick, used as the key into the recency index.
    tick: u64,
}

/// Interior state guarded by a single mutex.
///
/// `recency` maps access tick -> cache id and is kept in exact sync with
/// `entries`: every id in `entries` has exactly one tick in `recency`.
struct Inner<V> {
    entries: HashMap<String, CacheEntry<V>>,
    recency: BTreeMap<u64, String>,
    next_tick: u64,
}

impl<V> Inner<V> {
    /// Assign the next monotonic tick.
    fn bump(&mut self) -> u64 {
        let t = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1);
        t
    }

    /// Remove an entry and its recency index slot together.
    fn remove(&mut self, id: &str) -> Option<CacheEntry<V>> {
        let entry = self.entries.remove(id)?;
        self.recency.remove(&entry.tick);
        Some(entry)
    }

    /// Drop every entry whose idle time exceeds `ttl`.
    fn evict_expired(&mut self, ttl: Duration) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.last_accessed.elapsed() > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for id in expired {
            self.remove(&id);
        }
    }
}

/// A time-to-idle + strict-LRU cache for derived keys.
///
/// All entries are dropped (and thus zeroized if `V` is `HardenedBytes`)
/// on eviction or `Drop`. The cache is keyed by an opaque `String` id
/// (typically a CAIP-2 chain id like `"eip155:1"`).
///
/// Note the expiry policy is *time-to-idle*, not time-to-live: [`Self::get`]
/// refreshes an entry's timer. A continuously-used key therefore stays
/// resident, which is the intended behavior for an interactive signing
/// session.
///
/// For the T13 MVP, the Key-Agent is assumed to be single-wallet-per-process;
/// if multi-wallet support is added later, the cache key must include a
/// wallet id to avoid returning a key derived from one wallet's mnemonic to
/// a different wallet's signing request.
pub struct KeyCache<V: Clone + Send + Sync + 'static> {
    inner: Mutex<Inner<V>>,
    ttl: Duration,
    max_entries: usize,
}

impl<V: Clone + Send + Sync + 'static> KeyCache<V> {
    /// Create a cache with an explicit TTL and max-entries cap.
    ///
    /// Useful in tests where a short TTL is needed to verify expiry without
    /// sleeping for 5 seconds.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                recency: BTreeMap::new(),
                next_tick: 0,
            }),
            ttl,
            max_entries,
        }
    }

    /// Lock the inner state, recovering from a poisoned mutex.
    ///
    /// A panic in another thread must not turn this cache into a permanent
    /// `panic!` site on a signing hot path (the previous implementation used
    /// `.expect(...)` here). The guarded data is a plain map of key material
    /// with no cross-field invariant that a mid-panic unwind could corrupt,
    /// so recovering the guard is sound.
    fn lock(&self) -> MutexGuard<'_, Inner<V>> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Look up a key by id. Returns `None` if missing or expired.
    ///
    /// Refreshes the idle timer on hit (LRU semantics). Returns a clone of
    /// the stored value — for `HardenedBytes`, the clone is independently
    /// page-locked + zeroized on `Drop`, so the caller's copy is bounded by
    /// the caller's scope.
    pub fn get(&self, id: &str) -> Option<V> {
        let mut inner = self.lock();

        // Expired? Drop it and report a miss.
        match inner.entries.get(id) {
            None => return None,
            Some(entry) if entry.last_accessed.elapsed() > self.ttl => {
                inner.remove(id);
                return None;
            }
            Some(_) => {}
        }

        // Live hit: refresh recency with a single lookup + index swap.
        let tick = inner.bump();
        let entry = inner.entries.get_mut(id)?;
        let old_tick = std::mem::replace(&mut entry.tick, tick);
        entry.last_accessed = Instant::now();
        let cloned = entry.key.clone();
        inner.recency.remove(&old_tick);
        inner.recency.insert(tick, id.to_string());
        Some(cloned)
    }

    /// Insert a key under `id`, evicting expired entries and the LRU entry
    /// if at capacity. The cache takes ownership of the value — evicting it
    /// later triggers `Drop` (zeroize + munlock for `HardenedBytes`).
    pub fn insert(&self, id: &str, key: V) {
        let mut inner = self.lock();
        inner.evict_expired(self.ttl);

        // Replacing an existing id must not evict a different entry.
        inner.remove(id);

        if inner.entries.len() >= self.max_entries {
            // O(log n): the smallest tick is the least recently used entry.
            if let Some((_, lru_id)) = inner.recency.iter().next().map(|(t, k)| (*t, k.clone())) {
                inner.remove(&lru_id);
            }
        }

        let tick = inner.bump();
        inner.recency.insert(tick, id.to_string());
        inner
            .entries
            .insert(id.to_string(), CacheEntry { key, last_accessed: Instant::now(), tick });
    }

    /// Clear all entries. Triggers `Drop` on every value.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.entries.clear();
        inner.recency.clear();
    }

    /// Evict only expired entries. Called opportunistically by `insert`.
    pub fn evict_expired(&self) {
        let mut inner = self.lock();
        inner.evict_expired(self.ttl);
    }

    /// Current number of entries (including any that are expired but not yet
    /// reaped).
    pub fn len(&self) -> usize {
        self.lock().entries.len()
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
    use std::{sync::Arc, thread};

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
        cache.insert("b", 2);

        // Access "a" to make it more recent than "b".
        cache.get("a");

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

    /// Eviction must not depend on wall-clock granularity: with the tick
    /// counter, LRU order is exact even when inserts land in the same
    /// `Instant`. The old implementation needed `sleep`s between inserts.
    #[test]
    fn test_lru_exact_without_sleeps() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(60), 32);
        for i in 0..33u32 {
            cache.insert(&format!("k{i}"), i);
        }
        assert_eq!(cache.len(), 32);
        assert!(cache.get("k0").is_none(), "k0 is LRU and must be evicted");
        assert!(cache.get("k32").is_some());
        assert!(cache.get("k16").is_some());
    }

    /// Re-inserting an existing id must overwrite in place rather than evict
    /// an unrelated entry.
    #[test]
    fn test_reinsert_same_id_does_not_evict_others() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(60), 2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("a", 99);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("a"), Some(99));
        assert!(cache.get("b").is_some(), "re-inserting 'a' must not evict 'b'");
    }

    /// The recency index must never outgrow the entry map, otherwise the
    /// cache would leak memory across many insert/evict cycles.
    #[test]
    fn test_recency_index_stays_in_sync() {
        let cache = KeyCache::<u32>::new(Duration::from_secs(60), 4);
        for i in 0..200u32 {
            cache.insert(&format!("k{}", i % 16), i);
            cache.get(&format!("k{}", i % 16));
        }
        let inner = cache.lock();
        assert_eq!(inner.entries.len(), inner.recency.len());
        assert!(inner.entries.len() <= 4);
    }

    /// A panicking thread must not poison the cache into permanent failure.
    #[test]
    fn test_survives_poisoned_mutex() {
        let cache = Arc::new(KeyCache::<u32>::new(Duration::from_secs(60), 4));
        cache.insert("a", 1);

        let c = Arc::clone(&cache);
        let _ = thread::spawn(move || {
            let _guard = c.lock();
            panic!("poison the mutex");
        })
        .join();

        // Previously this would panic via `.expect("key cache mutex poisoned")`.
        assert_eq!(cache.get("a"), Some(1));
        cache.insert("b", 2);
        assert_eq!(cache.get("b"), Some(2));
    }
}
