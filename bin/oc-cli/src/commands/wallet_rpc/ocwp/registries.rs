//! Daemon-side registries for OCWP: connected dApp sites and EVM chains.
//!
//! - `sites.json` — authorized dApp origins (design §6.4). Centralizing site authorization in the
//!   daemon makes revocation global across ends (CLI, Web UI, extension) instead of per-browser.
//! - `chains.json` — user-added custom EVM chains (design §6.5). Built-in chains come from
//!   `oc_core::chain::KNOWN_CHAINS` with RPC endpoints from the user config (`Config::rpc`) and
//!   built-in defaults.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use oc_core::Config;
use serde::{Deserialize, Serialize};

/// Validate a dApp origin: `http(s)://<host>[:port]` with no path, userinfo,
/// query, or fragment. Returns the normalized (lowercased) origin.
pub(super) fn validate_origin(origin: &str) -> Result<String, String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| "origin must be an http(s) origin".to_string())?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err("origin must include a host".into());
    }
    if rest != authority {
        // An origin is scheme://host[:port] — no path, query, or fragment.
        return Err("origin must not contain a path, query, or fragment".into());
    }
    if authority.contains('@') {
        return Err("origin must not contain credentials".into());
    }
    Ok(origin.to_ascii_lowercase())
}

/// A connected dApp origin record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SiteRecord {
    /// Account the site is connected with (a CAIP-2 chain id, e.g. `eip155:1`).
    pub account_id: String,
    pub chain_id: String,
    pub connected_at: u64,
    pub last_seen_at: u64,
}

/// Persistent authorized-sites store at `<state_dir>/sites.json` (0600).
pub(crate) struct SiteStore {
    path: PathBuf,
    sites: Mutex<BTreeMap<String, SiteRecord>>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl SiteStore {
    /// Open (or create) the store. A corrupt file fails closed with an error
    /// rather than silently dropping authorizations.
    pub(crate) fn open(state_dir: &Path) -> Result<Self, String> {
        let path = state_dir.join("sites.json");
        let sites = match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => BTreeMap::new(),
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| format!("corrupt sites store {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(format!("cannot read sites store: {e}")),
        };
        Ok(Self { path, sites: Mutex::new(sites) })
    }

    /// Record (or refresh) a site connection.
    pub(crate) fn connect(
        &self,
        origin: &str,
        account_id: &str,
        chain_id: &str,
    ) -> Result<SiteRecord, String> {
        let origin = validate_origin(origin)?;
        let now = now_unix();
        let mut guard = self.sites.lock().map_err(|_| "sites store poisoned")?;
        let record = SiteRecord {
            account_id: account_id.to_string(),
            chain_id: chain_id.to_string(),
            connected_at: guard.get(&origin).map_or(now, |r| r.connected_at),
            last_seen_at: now,
        };
        guard.insert(origin, record.clone());
        self.save(&guard)?;
        Ok(record)
    }

    /// Revoke a site. Returns whether it existed.
    pub(crate) fn revoke(&self, origin: &str) -> Result<bool, String> {
        let origin = validate_origin(origin)?;
        let mut guard = self.sites.lock().map_err(|_| "sites store poisoned")?;
        let removed = guard.remove(&origin).is_some();
        self.save(&guard)?;
        Ok(removed)
    }

    /// Refresh `last_seen_at` for a known site (no-op for unknown origins).
    #[allow(dead_code)] // reserved for OCWP clients that refresh site presence
    pub(crate) fn touch(&self, origin: &str) -> Result<(), String> {
        let origin = validate_origin(origin)?;
        let mut guard = self.sites.lock().map_err(|_| "sites store poisoned")?;
        if let Some(record) = guard.get_mut(&origin) {
            record.last_seen_at = now_unix();
            self.save(&guard)?;
        }
        Ok(())
    }

    /// All records, ordered by origin.
    pub(crate) fn list(&self) -> Vec<(String, SiteRecord)> {
        let guard = self.sites.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn save(&self, sites: &BTreeMap<String, SiteRecord>) -> Result<(), String> {
        let json = serde_json::to_string_pretty(sites).map_err(|e| e.to_string())?;
        oc_core::paths::write_atomic_private(&self.path, json.as_bytes())
            .map_err(|e| format!("cannot write sites store: {e}"))
    }
}

/// A chain entry served to extension clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChainRecord {
    pub chain_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    pub native_currency: String,
    #[serde(default = "ChainRecord::default_is_evm")]
    pub is_evm: bool,
    /// `true` for built-in/config-derived entries; `false` for user-added.
    #[serde(default)]
    pub builtin: bool,
}

impl ChainRecord {
    fn default_is_evm() -> bool {
        true
    }
}

/// Chain registry: built-ins (KNOWN_CHAINS + config RPC overrides) plus user
/// custom chains from `<state_dir>/chains.json`.
pub(crate) struct ChainRegistry {
    path: PathBuf,
    custom: Mutex<Vec<ChainRecord>>,
}

impl ChainRegistry {
    pub(crate) fn open(state_dir: &Path) -> Self {
        let path = state_dir.join("chains.json");
        let custom = match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => Vec::new(),
            Ok(text) => {
                // A corrupt custom-chain file must not take the whole registry
                // down: log and continue with built-ins only.
                match serde_json::from_str::<Vec<ChainRecord>>(&text) {
                    Ok(records) => records,
                    Err(e) => {
                        tracing::warn!(error = %e, "ocwp: corrupt chains.json - using built-ins only");
                        Vec::new()
                    }
                }
            }
            Err(_) => Vec::new(),
        };
        Self { path, custom: Mutex::new(custom) }
    }

    /// Full listing: built-ins first, then user custom chains.
    pub(crate) fn list(&self, config: &Config) -> Vec<ChainRecord> {
        let defaults = Config::default();
        let mut out: Vec<ChainRecord> = oc_core::chain::KNOWN_CHAINS
            .iter()
            .map(|c| ChainRecord {
                chain_id: c.chain_id.to_string(),
                name: c.name.to_string(),
                rpc_url: config
                    .rpc_url(c.chain_id)
                    .or_else(|| defaults.rpc_url(c.chain_id))
                    .map(String::from),
                explorer_url: None,
                native_currency: if c.chain_type == oc_core::ChainType::Evm {
                    "ETH".to_string()
                } else {
                    String::new()
                },
                is_evm: c.chain_type == oc_core::ChainType::Evm,
                builtin: true,
            })
            .collect();
        let guard = self.custom.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(guard.iter().cloned());
        out
    }

    /// Resolve an RPC endpoint: custom entry > user config > built-in default.
    pub(crate) fn rpc_url(&self, chain_id: &str, config: &Config) -> Option<String> {
        {
            let guard = self.custom.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(record) = guard.iter().find(|c| c.chain_id == chain_id) {
                if let Some(url) = &record.rpc_url {
                    return Some(url.clone());
                }
            }
        }
        let defaults = Config::default();
        config.rpc_url(chain_id).or_else(|| defaults.rpc_url(chain_id)).map(String::from)
    }

    /// Add or replace a custom EVM chain after validation (design §4.10).
    pub(crate) fn add_custom(&self, record: ChainRecord) -> Result<ChainRecord, String> {
        let chain_id = record.chain_id.trim().to_string();
        // v1 custom chains are EVM-only: `eip155:<digits>`.
        let reference = chain_id
            .strip_prefix("eip155:")
            .filter(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()))
            .ok_or_else(|| "custom chain_id must be eip155:<numeric id>".to_string())?;
        if reference.parse::<u64>().is_err() {
            return Err("custom chain_id number is out of range".into());
        }
        let name = record.name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err("custom chain name must be 1..=64 characters".into());
        }
        let rpc_url = match record.rpc_url.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => {
                validate_rpc_url(url)?;
                Some(url.to_string())
            }
            _ => None,
        };
        let explorer_url = match record.explorer_url.as_deref().map(str::trim) {
            Some(url) if !url.is_empty() => {
                if !url.starts_with("https://") {
                    return Err("explorer_url must be https://".into());
                }
                Some(url.to_string())
            }
            _ => None,
        };
        let record = ChainRecord {
            chain_id,
            name: name.to_string(),
            rpc_url,
            explorer_url,
            native_currency: if record.native_currency.trim().is_empty() {
                "ETH".to_string()
            } else {
                record.native_currency.trim().to_string()
            },
            is_evm: true,
            builtin: false,
        };
        let mut guard = self.custom.lock().map_err(|_| "chains registry poisoned")?;
        guard.retain(|c| c.chain_id != record.chain_id);
        guard.push(record.clone());
        let json = serde_json::to_string_pretty(&*guard).map_err(|e| e.to_string())?;
        oc_core::paths::write_atomic_private(&self.path, json.as_bytes())
            .map_err(|e| format!("cannot write chains registry: {e}"))?;
        Ok(record)
    }
}

/// Validate an RPC endpoint URL: `https://` always; `http://` only for
/// loopback hosts (local dev nodes).
fn validate_rpc_url(url: &str) -> Result<(), String> {
    if let Some(rest) = url.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err("rpc_url must include a host".into());
        }
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("");
        if matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
            return Ok(());
        }
    }
    Err("rpc_url must be https:// (http:// allowed for loopback dev nodes only)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        tempfile::tempdir().expect("tempdir").keep()
    }

    #[test]
    fn origin_validation_normalizes_and_rejects_junk() {
        assert_eq!(validate_origin("https://App.Example.com").unwrap(), "https://app.example.com");
        assert_eq!(
            validate_origin("https://app.example.com:8443").unwrap(),
            "https://app.example.com:8443"
        );
        assert!(validate_origin("javascript:alert(1)").is_err());
        assert!(validate_origin("https://user@evil.com").is_err());
        assert!(validate_origin("https://app.example.com/path").is_err());
        assert!(validate_origin("https://").is_err());
    }

    #[test]
    fn site_store_round_trip_and_revoke() {
        let dir = temp_dir();
        let store = SiteStore::open(&dir).expect("open");
        store.connect("https://app.example.com", "eip155:1", "eip155:1").expect("connect");
        assert_eq!(store.list().len(), 1);
        // Idempotent connect keeps connected_at stable.
        store.connect("https://app.example.com", "eip155:8453", "eip155:8453").expect("reconnect");
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1.chain_id, "eip155:8453");
        assert!(store.revoke("https://app.example.com").expect("revoke"));
        assert!(!store.revoke("https://app.example.com").expect("revoke again"));
        assert!(store.list().is_empty());
        // Persisted across reopen.
        store.connect("https://b.example.com", "eip155:1", "eip155:1").expect("connect b");
        drop(store);
        let reopened = SiteStore::open(&dir).expect("reopen");
        assert_eq!(reopened.list().len(), 1);
    }

    #[test]
    fn corrupt_sites_store_fails_closed() {
        let dir = temp_dir();
        std::fs::write(dir.join("sites.json"), b"{ not json").unwrap();
        assert!(SiteStore::open(&dir).is_err(), "corrupt store must fail closed");
    }

    #[test]
    fn chain_registry_lists_builtins_with_rpc() {
        let dir = temp_dir();
        let registry = ChainRegistry::open(&dir);
        let config = Config::default();
        let chains = registry.list(&config);
        assert!(chains.iter().any(|c| c.chain_id == "eip155:1" && c.builtin));
        let base = chains.iter().find(|c| c.chain_id == "eip155:8453").expect("base");
        assert!(base.rpc_url.is_some(), "built-in chains ship default RPCs");
        assert!(base.is_evm);
    }

    #[test]
    fn custom_chain_validation_and_rpc_precedence() {
        let dir = temp_dir();
        let registry = ChainRegistry::open(&dir);
        // Rejects non-EVM / bad URLs.
        assert!(
            registry
                .add_custom(ChainRecord {
                    chain_id: "solana:mainnet".into(),
                    name: "sol".into(),
                    rpc_url: None,
                    explorer_url: None,
                    native_currency: "SOL".into(),
                    is_evm: false,
                    builtin: false,
                })
                .is_err()
        );
        assert!(
            registry
                .add_custom(ChainRecord {
                    chain_id: "eip155:7777777".into(),
                    name: "evil".into(),
                    rpc_url: Some("http://evil.example.com".into()),
                    explorer_url: None,
                    native_currency: "ETH".into(),
                    is_evm: true,
                    builtin: false,
                })
                .is_err(),
            "plain http non-loopback RPC must be rejected"
        );
        // Accepts a valid entry; custom RPC wins over config/default.
        let record = registry
            .add_custom(ChainRecord {
                chain_id: "eip155:7777777".into(),
                name: "My Chain".into(),
                rpc_url: Some("https://rpc.example.com".into()),
                explorer_url: Some("https://scan.example.com".into()),
                native_currency: "ETH".into(),
                is_evm: true,
                builtin: false,
            })
            .expect("valid custom chain");
        assert!(!record.builtin);
        let config = Config::default();
        assert_eq!(
            registry.rpc_url("eip155:7777777", &config).as_deref(),
            Some("https://rpc.example.com")
        );
        // Loopback http is allowed (dev node).
        assert!(
            registry
                .add_custom(ChainRecord {
                    chain_id: "eip155:31337".into(),
                    name: "anvil".into(),
                    rpc_url: Some("http://127.0.0.1:8545".into()),
                    explorer_url: None,
                    native_currency: "ETH".into(),
                    is_evm: true,
                    builtin: false,
                })
                .is_ok()
        );
        // Persisted across reopen.
        drop(registry);
        let reopened = ChainRegistry::open(&dir);
        assert!(reopened.list(&config).iter().any(|c| c.chain_id == "eip155:7777777"));
    }
}
