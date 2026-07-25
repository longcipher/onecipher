pub mod invalidate;

use std::collections::HashMap;
use std::sync::Mutex;

use leptos::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

// ponytail: in-memory placeholder; replace with IndexedDB (rexie/Dexie) when offline support is needed.
static CACHE: std::sync::LazyLock<Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

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
}

/// Store a value in the in-memory cache.
pub fn cache_put<T: Serialize>(scene: Scene, key: &str, value: &T) {
    let full_key = format!("{}:{key}", scene.as_str());
    if let Ok(bytes) = serde_json::to_vec(value) {
        if let Ok(mut map) = CACHE.lock() {
            map.insert(full_key, bytes);
        }
    }
}

/// Read a value from the in-memory cache.
pub fn cache_get<T: DeserializeOwned>(scene: Scene, key: &str) -> Option<T> {
    let full_key = format!("{}:{key}", scene.as_str());
    let bytes = CACHE.lock().ok()?.get(&full_key)?.clone();
    serde_json::from_slice(&bytes).ok()
}

/// Invalidate all entries for a given scene.
pub fn invalidate_scene(scene: Scene) {
    let prefix = format!("{}:", scene.as_str());
    if let Ok(mut map) = CACHE.lock() {
        map.retain(|k, _| !k.starts_with(&prefix));
    }
}

/// Invalidate all cache entries.
pub fn invalidate_all() {
    if let Ok(mut map) = CACHE.lock() {
        map.clear();
    }
}

/// Read from cache or fetch from API, storing result on success.
/// Returns a reactive signal that updates when data changes.
pub fn read_or_fetch<T, F>(scene: Scene, key: &str, fetcher: F) -> RwSignal<Option<T>>
where
    T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    F: std::future::Future<Output = Result<T, crate::api::ApiError>> + 'static,
{
    let sig = RwSignal::new(cache_get::<T>(scene, key));

    // If cache hit, return immediately; otherwise fetch
    if sig.get().is_some() {
        return sig;
    }

    let key_owned = key.to_owned();
    leptos::task::spawn_local(async move {
        if let Ok(val) = fetcher.await {
            cache_put(scene, &key_owned, &val);
            sig.set(Some(val));
        }
    });

    sig
}
