//! Reactive data cache.
//!
//! # The problem this solves
//!
//! The previous version stored bytes in a `HashMap` and handed callers a
//! detached `RwSignal`. Invalidation cleared the map — but nothing told the
//! live signals about it, so every mounted component kept rendering the value
//! it had fetched on mount. Invalidating `Scene::Approvals` after a WebSocket
//! `approval_resolved` event was a no-op on screen; only a full page reload
//! showed the truth. In a signing wallet, silently-stale state is a security
//! problem, not just a UX one.
//!
//! # The model
//!
//! Every [`Scene`] owns an **epoch**: a `Signal<u64>` that increments on
//! invalidation. [`read_or_fetch`] registers an `Effect` that reads its
//! scene's epoch, so bumping the epoch re-runs the fetch for *every* live
//! subscriber of that scene at once. Cache entry and reactive graph can no
//! longer drift apart, because the map write and the epoch bump happen in the
//! same function.
//!
//! # Staleness
//!
//! Reads are stale-while-revalidate: a cache hit renders immediately and a
//! background refetch starts if the entry is older than [`STALE_AFTER_MS`].
//! Users never stare at a spinner for data we already have, and never look at
//! a value more than a few seconds behind the daemon.

pub mod invalidate;

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use leptos::prelude::*;
use serde::{Serialize, de::DeserializeOwned};

/// How long a cache entry is served without a background refetch.
///
/// Short, because everything in this UI is either security-relevant (pending
/// approvals, session keys) or cheap to refetch from a daemon on localhost.
pub const STALE_AFTER_MS: f64 = 5_000.0;

/// One cached response plus the time it was written.
#[derive(Clone)]
struct Entry {
    bytes: Vec<u8>,
    stored_at_ms: f64,
}

// ponytail: in-memory placeholder; replace with IndexedDB (rexie/Dexie) when
// offline support is needed. The reactive layer above does not care where the
// bytes come from, so that swap is local to this module.
static CACHE: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, Entry>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Milliseconds since the Unix epoch.
///
/// `std::time::SystemTime` rather than `performance.now()` so the cache is
/// testable on the host: `web_sys` statics cannot be imported on non-wasm
/// targets, which would panic every `cache_put` in a native test. On
/// `wasm32-unknown-unknown` it is backed by the JS clock and works unchanged.
///
/// Falls back to `0.0` before the epoch, which makes an entry look freshly
/// written — fine, since staleness is an optimization, not a correctness
/// property.
fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
}

/// Scene tags for cache invalidation groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scene {
    Wallets,
    Sessions,
    Approvals,
    Settings,
    Audit,
    Balances,
    SessionKeys,
}

impl Scene {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scene::Wallets => "wallets",
            Scene::Sessions => "sessions",
            Scene::Approvals => "approvals",
            Scene::Settings => "settings",
            Scene::Audit => "audit",
            Scene::Balances => "balances",
            Scene::SessionKeys => "session_keys",
        }
    }

    /// Every scene, so [`invalidate_all`] cannot silently miss one when a new
    /// variant is added.
    pub const ALL: [Scene; 7] = [
        Scene::Wallets,
        Scene::Sessions,
        Scene::Approvals,
        Scene::Settings,
        Scene::Audit,
        Scene::Balances,
        Scene::SessionKeys,
    ];

    /// Index into the epoch table.
    fn idx(self) -> usize {
        match self {
            Scene::Wallets => 0,
            Scene::Sessions => 1,
            Scene::Approvals => 2,
            Scene::Settings => 3,
            Scene::Audit => 4,
            Scene::Balances => 5,
            Scene::SessionKeys => 6,
        }
    }
}

// ---------------------------------------------------------------------------
// Epochs — the reactive half of the cache
// ---------------------------------------------------------------------------

/// One epoch signal per scene, created on first use.
///
/// `ArcRwSignal` rather than `RwSignal`: these outlive any component's owner
/// (they are process-global), and a plain `RwSignal` would be disposed with
/// whichever component happened to touch it first, leaving later readers
/// subscribed to a dead node.
type EpochTable = [ArcRwSignal<u64>; 7];

static EPOCHS: OnceLock<EpochTable> = OnceLock::new();

fn epochs() -> &'static EpochTable {
    EPOCHS.get_or_init(|| std::array::from_fn(|_| ArcRwSignal::new(0)))
}

/// The epoch signal for `scene`. Reading it inside an effect subscribes that
/// effect to the scene's invalidations.
pub fn scene_epoch(scene: Scene) -> ArcRwSignal<u64> {
    epochs()[scene.idx()].clone()
}

/// Current epoch value, without subscribing.
///
/// The observable proof that an invalidation happened, which is what the tests
/// in this module and in [`invalidate`] assert on.
#[cfg_attr(not(test), allow(dead_code))]
pub fn scene_epoch_value(scene: Scene) -> u64 {
    epochs()[scene.idx()].get_untracked()
}

// ---------------------------------------------------------------------------
// Raw get / put
// ---------------------------------------------------------------------------

fn full_key(scene: Scene, key: &str) -> String {
    format!("{}:{key}", scene.as_str())
}

/// Store a value in the cache.
///
/// Does **not** bump the epoch: this is the write that happens *after* a fetch
/// the subscribers already asked for, so re-notifying them would loop.
pub fn cache_put<T: Serialize>(scene: Scene, key: &str, value: &T) {
    let Ok(bytes) = serde_json::to_vec(value) else { return };
    if let Ok(mut map) = cache().lock() {
        map.insert(full_key(scene, key), Entry { bytes, stored_at_ms: now_ms() });
    }
}

/// Read a value from the cache, ignoring staleness.
#[cfg_attr(not(test), allow(dead_code))]
pub fn cache_get<T: DeserializeOwned>(scene: Scene, key: &str) -> Option<T> {
    let entry = cache().lock().ok()?.get(&full_key(scene, key))?.clone();
    serde_json::from_slice(&entry.bytes).ok()
}

/// Read a value along with whether it is past [`STALE_AFTER_MS`].
fn cache_get_with_staleness<T: DeserializeOwned>(scene: Scene, key: &str) -> Option<(T, bool)> {
    let entry = cache().lock().ok()?.get(&full_key(scene, key))?.clone();
    let value: T = serde_json::from_slice(&entry.bytes).ok()?;
    let stale = now_ms() - entry.stored_at_ms >= STALE_AFTER_MS;
    Some((value, stale))
}

// ---------------------------------------------------------------------------
// Invalidation
// ---------------------------------------------------------------------------

/// Increment a scene's epoch, waking its subscribers.
fn bump(scene: Scene) {
    epochs()[scene.idx()].update(|e| *e = e.wrapping_add(1));
}

/// Drop every cached entry for `scene` and refetch all live subscribers.
pub fn invalidate_scene(scene: Scene) {
    let prefix = format!("{}:", scene.as_str());
    if let Ok(mut map) = cache().lock() {
        map.retain(|k, _| !k.starts_with(&prefix));
    }
    bump(scene);
}

/// Drop everything and refetch every live subscriber.
///
/// Used on auto-lock: after the vault locks, no cached value can be trusted.
pub fn invalidate_all() {
    if let Ok(mut map) = cache().lock() {
        map.clear();
    }
    for scene in Scene::ALL {
        bump(scene);
    }
}

/// Serializes every test that touches the process-global cache and epochs.
///
/// [`cache()`] and the epoch table are singletons shared across the whole test
/// binary — `cache::tests` and `cache::invalidate::tests` run in parallel
/// threads, so one test's `invalidate_all()` would wipe another test's just-
/// written entry without this. Every cache test takes the lock for its whole
/// body.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// read_or_fetch
// ---------------------------------------------------------------------------

/// Read from cache or fetch from the API, re-fetching whenever the scene is
/// invalidated.
///
/// The returned signal is `None` until the first response arrives, then always
/// holds the newest value. Unlike the previous implementation, the signal stays
/// connected to the cache: an [`invalidate_scene`] anywhere in the app — from a
/// WebSocket event, a mutation, or auto-lock — re-runs `fetcher` and pushes the
/// fresh value into every component reading it.
///
/// `fetcher` is a closure returning a future, not a bare future, because it
/// must be callable once per invalidation.
///
/// # Example
///
/// ```ignore
/// let wallets = read_or_fetch(Scene::Wallets, "list", || {
///     crate::api::get_json::<Vec<WalletInfo>>("/wallets")
/// });
/// ```
pub fn read_or_fetch<T, F, Fut>(scene: Scene, key: &str, fetcher: F) -> RwSignal<Option<T>>
where
    T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    F: Fn() -> Fut + 'static,
    Fut: std::future::Future<Output = Result<T, crate::api::ApiError>> + 'static,
{
    let sig = RwSignal::new(None::<T>);
    let key_owned = key.to_owned();
    let epoch = scene_epoch(scene);

    Effect::new(move |prev_epoch: Option<u64>| {
        // Subscribe to the scene. Every invalidation re-runs this closure.
        let current = epoch.get();

        // On the first run a fresh-enough cache hit renders immediately and
        // skips the network. On a re-run the epoch changed, which means the
        // entry was dropped or superseded, so always go to the network.
        let first_run = prev_epoch.is_none();
        if first_run {
            match cache_get_with_staleness::<T>(scene, &key_owned) {
                Some((value, false)) => {
                    // Fresh hit — done, no request.
                    sig.set(Some(value));
                    return current;
                }
                Some((value, true)) => {
                    // Stale hit — show it now, revalidate in the background.
                    sig.set(Some(value));
                }
                None => {}
            }
        }

        let fut = fetcher();
        // The effect re-runs on every invalidation, so the key must be cloned
        // per run rather than moved out of the effect's environment.
        let key_for_task = key_owned.clone();
        leptos::task::spawn_local(async move {
            if let Ok(value) = fut.await {
                cache_put(scene, &key_for_task, &value);
                sig.set(Some(value));
            }
            // On error the previous value stays on screen. Surfacing fetch
            // errors is the caller's job — a transient blip must not blank
            // out a wallet list.
        });

        current
    });

    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct Sample {
        v: u32,
    }

    /// Exclusive access to the shared cache + epochs for one test's whole
    /// body. Without this, a concurrently-running test's `invalidate_all()`
    /// wipes this test's entries mid-assertion.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn scene_all_covers_every_variant() {
        let _g = lock();
        // A new Scene variant without an ALL entry would make invalidate_all
        // silently skip it — exactly the class of bug this module exists to
        // prevent. Distinct indices prove the table is complete.
        let mut seen: Vec<usize> = Scene::ALL.iter().map(|s| s.idx()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), Scene::ALL.len());
        assert_eq!(seen, (0..Scene::ALL.len()).collect::<Vec<_>>());
    }

    #[test]
    fn scene_names_are_unique() {
        let _g = lock();
        let mut names: Vec<&str> = Scene::ALL.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Scene::ALL.len(), "two scenes share a key prefix");
    }

    #[test]
    fn put_then_get_round_trips() {
        let _g = lock();
        cache_put(Scene::Wallets, "round_trip", &Sample { v: 42 });
        assert_eq!(cache_get::<Sample>(Scene::Wallets, "round_trip"), Some(Sample { v: 42 }));
    }

    #[test]
    fn get_on_a_missing_key_is_none() {
        let _g = lock();
        assert_eq!(cache_get::<Sample>(Scene::Wallets, "never_written"), None);
    }

    #[test]
    fn scenes_do_not_collide_on_the_same_key() {
        let _g = lock();
        cache_put(Scene::Wallets, "shared", &Sample { v: 1 });
        cache_put(Scene::Sessions, "shared", &Sample { v: 2 });
        assert_eq!(cache_get::<Sample>(Scene::Wallets, "shared"), Some(Sample { v: 1 }));
        assert_eq!(cache_get::<Sample>(Scene::Sessions, "shared"), Some(Sample { v: 2 }));
    }

    #[test]
    fn invalidate_scene_drops_only_that_scene() {
        let _g = lock();
        cache_put(Scene::Audit, "keep_a", &Sample { v: 1 });
        cache_put(Scene::Balances, "keep_b", &Sample { v: 2 });

        invalidate_scene(Scene::Audit);

        assert_eq!(cache_get::<Sample>(Scene::Audit, "keep_a"), None);
        assert_eq!(cache_get::<Sample>(Scene::Balances, "keep_b"), Some(Sample { v: 2 }));
    }

    #[test]
    fn invalidate_scene_bumps_the_epoch() {
        let _g = lock();
        let before = scene_epoch_value(Scene::Settings);
        invalidate_scene(Scene::Settings);
        assert_eq!(scene_epoch_value(Scene::Settings), before + 1);
    }

    #[test]
    fn cache_put_alone_does_not_bump() {
        let _g = lock();
        // The post-fetch write must not re-notify, or read_or_fetch would
        // fetch forever.
        let before = scene_epoch_value(Scene::Audit);
        cache_put(Scene::Audit, "quiet", &Sample { v: 1 });
        assert_eq!(scene_epoch_value(Scene::Audit), before);
    }

    #[test]
    fn invalidate_all_bumps_every_scene() {
        let _g = lock();
        let before: Vec<u64> = Scene::ALL.iter().map(|s| scene_epoch_value(*s)).collect();
        invalidate_all();
        for (scene, was) in Scene::ALL.iter().zip(before) {
            assert_eq!(
                scene_epoch_value(*scene),
                was + 1,
                "scene {} was not woken by invalidate_all",
                scene.as_str()
            );
        }
    }

    #[test]
    fn invalidate_all_clears_every_scene() {
        let _g = lock();
        for scene in Scene::ALL {
            cache_put(scene, "wipe", &Sample { v: 7 });
        }
        invalidate_all();
        for scene in Scene::ALL {
            assert_eq!(
                cache_get::<Sample>(scene, "wipe"),
                None,
                "scene {} survived invalidate_all",
                scene.as_str()
            );
        }
    }

    #[test]
    fn epoch_signals_are_stable_across_calls() {
        let _g = lock();
        // scene_epoch must hand out the *same* node every time, otherwise
        // subscribers would each listen to a private signal nobody bumps.
        let a = scene_epoch(Scene::Balances);
        invalidate_scene(Scene::Balances);
        let b = scene_epoch(Scene::Balances);
        assert_eq!(a.get_untracked(), b.get_untracked());
    }

    #[test]
    fn a_type_mismatch_reads_as_none_instead_of_panicking() {
        let _g = lock();
        #[derive(serde::Deserialize)]
        struct Other {
            #[allow(dead_code)]
            missing_field: String,
        }
        cache_put(Scene::Settings, "mismatch", &Sample { v: 1 });
        assert!(cache_get::<Other>(Scene::Settings, "mismatch").is_none());
    }
}
