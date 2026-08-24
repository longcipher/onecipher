use std::{collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};

/// Backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backups: Option<u32>,
}

/// WalletConnect v2 relay configuration section.
///
/// Controls which relay the daemon's wallet server, the CLI dApp client, and
/// generated pairing URIs target. `relay_url` may be a local/self-hosted relay
/// (`wss://127.0.0.1:7443`) or the official cloud relay
/// (`wss://relay.walletconnect.com`, which additionally requires `project_id`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WcConfig {
    /// Relay WSS URL. Defaults to `wss://relay.walletconnect.com`.
    #[serde(default)]
    pub relay_url: String,
    /// WalletConnect Cloud project ID (required by the cloud relay).
    #[serde(default)]
    pub project_id: String,
    /// dApp origin allowlist for `wc_sessionPropose` approval.
    ///
    /// An entry matches the dApp's origin host exactly or as a dot-boundary
    /// subdomain (`example.com` matches `app.example.com` but not
    /// `evil-example.com`). An empty list denies **all** session proposals
    /// (secure default) — add the relying party's origin(s) before expecting
    /// a dApp to connect.
    #[serde(default)]
    pub trusted_origins: Vec<String>,
}

impl WcConfig {
    pub fn default_relay_url() -> String {
        "wss://relay.walletconnect.com".to_string()
    }
}

/// Web UI configuration section.
///
/// Controls the local browser-based approval surface served by the daemon.
/// All fields have sensible defaults so that existing config files without
/// this section continue to parse (backward compatibility).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebuiConfig {
    /// Whether the Web UI HTTP server is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Whether signing requests require explicit browser approval.
    #[serde(default)]
    pub approval_mode: bool,
    /// Seconds before an unanswered approval times out.
    #[serde(default = "WebuiConfig::default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
    /// Loopback listen address (e.g. "127.0.0.1:0" for random port).
    #[serde(default = "WebuiConfig::default_listen")]
    pub listen: String,
    /// Session inactivity timeout in seconds.
    #[serde(default = "WebuiConfig::default_session_timeout_secs")]
    pub session_timeout_secs: u64,
    /// ISO-8601 or unix timestamp at which sessions auto-lock.
    /// Empty string means no deadline set.
    #[serde(default)]
    pub auto_lock_at: String,
}

impl Default for WebuiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            approval_mode: false,
            approval_timeout_secs: Self::default_approval_timeout_secs(),
            listen: Self::default_listen(),
            session_timeout_secs: Self::default_session_timeout_secs(),
            auto_lock_at: String::new(),
        }
    }
}

impl WebuiConfig {
    fn default_approval_timeout_secs() -> u64 {
        300
    }

    fn default_listen() -> String {
        "127.0.0.1:0".to_string()
    }

    fn default_session_timeout_secs() -> u64 {
        1800
    }
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Vault directory. Defaults to `~/.onecipher` when absent from a user
    /// config file (so partial configs that only set e.g. `wc.*` still parse).
    #[serde(default = "Config::default_vault_path")]
    pub vault_path: PathBuf,
    #[serde(default)]
    pub rpc: HashMap<String, String>,
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
    /// Web UI configuration. Defaults to disabled if absent.
    #[serde(default)]
    pub webui: WebuiConfig,
    /// WalletConnect v2 relay configuration. Defaults to the cloud relay.
    #[serde(default)]
    pub wc: WcConfig,
}

impl Config {
    /// Default vault path (`~/.onecipher`), or a relative `.onecipher` when
    /// HOME is unavailable. Used by `#[serde(default)]` so partial user config
    /// files still parse.
    fn default_vault_path() -> PathBuf {
        crate::paths::state_dir().unwrap_or_else(|_| PathBuf::from(crate::paths::STATE_DIR_NAME))
    }

    /// Returns the built-in default RPC endpoints for well-known chains.
    pub fn default_rpc() -> HashMap<String, String> {
        let mut rpc = HashMap::new();
        rpc.insert("eip155:1".into(), "https://eth.llamarpc.com".into());
        rpc.insert("eip155:137".into(), "https://polygon-rpc.com".into());
        rpc.insert("eip155:42161".into(), "https://arb1.arbitrum.io/rpc".into());
        rpc.insert("eip155:10".into(), "https://mainnet.optimism.io".into());
        rpc.insert("eip155:8453".into(), "https://mainnet.base.org".into());
        rpc.insert("eip155:9745".into(), "https://rpc.plasma.to".into());
        rpc.insert("eip155:56".into(), "https://bsc-dataseed.binance.org".into());
        rpc.insert("eip155:43114".into(), "https://api.avax.network/ext/bc/C/rpc".into());
        rpc.insert(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            "https://api.mainnet-beta.solana.com".into(),
        );
        rpc.insert(
            "bip122:000000000019d6689c085ae165831e93".into(),
            "https://mempool.space/api".into(),
        );
        rpc.insert("cosmos:cosmoshub-4".into(), "https://cosmos-rest.publicnode.com".into());
        rpc.insert("tron:mainnet".into(), "https://api.trongrid.io".into());
        rpc.insert("ton:mainnet".into(), "https://toncenter.com/api/v2".into());
        rpc.insert("fil:mainnet".into(), "https://api.node.glif.io/rpc/v1".into());
        rpc.insert("sui:mainnet".into(), "https://fullnode.mainnet.sui.io:443".into());
        rpc.insert("xrpl:mainnet".into(), "https://s1.ripple.com:51234".into());
        rpc.insert("xrpl:testnet".into(), "https://s.altnet.rippletest.net:51234".into());
        rpc.insert("xrpl:devnet".into(), "https://s.devnet.rippletest.net:51234".into());
        rpc.insert("nano:mainnet".into(), "https://rpc.nano.to".into());
        rpc.insert("near:mainnet".into(), "https://rpc.mainnet.near.org".into());
        rpc.insert("near:testnet".into(), "https://rpc.testnet.near.org".into());
        rpc.insert("eip155:4217".into(), "https://rpc.tempo.xyz".into());
        rpc.insert("eip155:999".into(), "https://rpc.hyperliquid.xyz/evm".into());
        rpc
    }
}

impl Default for Config {
    /// Build the default config.
    ///
    /// `vault_path` resolves to `~/.onecipher`. If the home directory cannot
    /// be determined, it falls back to the *relative* path `.onecipher` in the
    /// current working directory. This is deliberate: the previous fallback
    /// was the absolute, world-writable `/tmp/.onecipher`, which silently
    /// placed the vault somewhere any local user could tamper with. A
    /// relative path stays inside whatever directory the operator chose.
    ///
    /// Callers that need a hard failure instead of a fallback should use
    /// [`crate::paths::state_dir`] directly.
    fn default() -> Self {
        let vault_path = Self::default_vault_path();
        Self {
            vault_path,
            rpc: Self::default_rpc(),
            plugins: HashMap::new(),
            backup: None,
            webui: WebuiConfig::default(),
            wc: WcConfig {
                relay_url: WcConfig::default_relay_url(),
                project_id: String::new(),
                trusted_origins: Vec::new(),
            },
        }
    }
}

impl Config {
    /// Look up an RPC URL by chain identifier.
    pub fn rpc_url(&self, chain: &str) -> Option<&str> {
        self.rpc.get(chain).map(|s| s.as_str())
    }

    /// Load config from a file path, or return defaults if file doesn't exist.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::OcError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::error::OcError::InvalidInput { message: format!("failed to read config: {}", e) }
        })?;
        serde_json::from_str(&contents).map_err(|e| crate::error::OcError::InvalidInput {
            message: format!("failed to parse config: {}", e),
        })
    }

    /// Load `~/.onecipher/config.json`, merging user overrides on top of defaults.
    /// If the file doesn't exist, returns the built-in defaults.
    pub fn load_or_default() -> Self {
        match crate::paths::config_path() {
            Ok(p) => Self::load_or_default_from(&p),
            // No home directory: there is no user config to merge, so the
            // built-in defaults are the correct answer. Previously this read
            // from `/tmp/.onecipher/config.json`, meaning any local user could
            // plant a config file that redirected the vault and RPC endpoints.
            Err(_) => Self::default(),
        }
    }

    /// Load config from a specific path, merging user overrides on top of defaults.
    pub fn load_or_default_from(path: &std::path::Path) -> Self {
        let mut config = Self::default();
        if path.exists() &&
            let Ok(contents) = std::fs::read_to_string(path) &&
            let Ok(user_config) = serde_json::from_str::<Self>(&contents)
        {
            for (k, v) in user_config.rpc {
                config.rpc.insert(k, v);
            }
            config.plugins = user_config.plugins;
            config.backup = user_config.backup;
            config.webui = user_config.webui;
            // Honor any non-empty user-specified WC relay settings.
            if !user_config.wc.relay_url.is_empty() {
                config.wc.relay_url = user_config.wc.relay_url;
            }
            if !user_config.wc.project_id.is_empty() {
                config.wc.project_id = user_config.wc.project_id;
            }
            // Honor user-specified trusted origins (empty list is a deliberate
            // deny-all and must round-trip, so there is no "non-empty" guard).
            if !user_config.wc.trusted_origins.is_empty() {
                config.wc.trusted_origins = user_config.wc.trusted_origins;
            }
            // Honor any non-empty user-specified vault path. The previous
            // code also ignored the literal `/tmp/.onecipher`, because that
            // used to be the `Default` value when HOME was unset and would
            // otherwise be round-tripped back in as an explicit setting.
            // That fallback is gone, so the sentinel check would now only
            // serve to silently ignore a deliberate operator choice.
            if !user_config.vault_path.as_os_str().is_empty() {
                config.vault_path = user_config.vault_path;
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_vault_path() {
        let config = Config::default();
        let path_str = config.vault_path.to_string_lossy();
        assert!(path_str.ends_with(".onecipher"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut rpc = HashMap::new();
        rpc.insert("eip155:1".to_string(), "https://eth.rpc.example".to_string());

        let config = Config {
            vault_path: PathBuf::from("/home/test/.onecipher"),
            rpc,
            plugins: HashMap::new(),
            backup: None,
            webui: WebuiConfig::default(),
            wc: WcConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.vault_path, config2.vault_path);
        assert_eq!(config.rpc, config2.rpc);
    }

    #[test]
    fn test_rpc_lookup_hit() {
        let mut config = Config::default();
        config.rpc.insert("eip155:1".to_string(), "https://eth.rpc.example".to_string());
        assert_eq!(config.rpc_url("eip155:1"), Some("https://eth.rpc.example"));
    }

    #[test]
    fn test_default_rpc_endpoints() {
        let config = Config::default();
        assert_eq!(config.rpc_url("eip155:1"), Some("https://eth.llamarpc.com"));
        assert_eq!(config.rpc_url("eip155:137"), Some("https://polygon-rpc.com"));
        assert_eq!(config.rpc_url("eip155:9745"), Some("https://rpc.plasma.to"));
        assert_eq!(
            config.rpc_url("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(
            config.rpc_url("bip122:000000000019d6689c085ae165831e93"),
            Some("https://mempool.space/api")
        );
        assert_eq!(
            config.rpc_url("cosmos:cosmoshub-4"),
            Some("https://cosmos-rest.publicnode.com")
        );
        assert_eq!(config.rpc_url("tron:mainnet"), Some("https://api.trongrid.io"));
        assert_eq!(config.rpc_url("ton:mainnet"), Some("https://toncenter.com/api/v2"));
        assert_eq!(config.rpc_url("eip155:4217"), Some("https://rpc.tempo.xyz"));
        assert_eq!(config.rpc_url("eip155:999"), Some("https://rpc.hyperliquid.xyz/evm"));
    }

    #[test]
    fn test_rpc_lookup_miss() {
        let config = Config::default();
        assert_eq!(config.rpc_url("eip155:99999"), None);
    }

    #[test]
    fn test_optional_backup() {
        let config = Config::default();
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_none());
    }

    #[test]
    fn test_backup_config_serde() {
        let config = Config {
            vault_path: PathBuf::from("/tmp/.onecipher"),
            rpc: HashMap::new(),
            plugins: HashMap::new(),
            backup: Some(BackupConfig {
                path: PathBuf::from("/tmp/backup"),
                auto_backup: Some(true),
                max_backups: Some(5),
            }),
            webui: WebuiConfig::default(),
            wc: WcConfig::default(),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_some());
        assert_eq!(json["backup"]["auto_backup"], true);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(std::path::Path::new("/nonexistent/path/config.json")).unwrap();
        assert!(config.vault_path.to_string_lossy().ends_with(".onecipher"));
    }

    #[test]
    fn test_load_or_default_nonexistent() {
        let config = Config::load_or_default_from(std::path::Path::new("/nonexistent/config.json"));
        // Should have all default RPCs
        assert_eq!(config.rpc.len(), 23);
        assert_eq!(config.rpc_url("eip155:1"), Some("https://eth.llamarpc.com"));
        assert_eq!(config.rpc_url("near:mainnet"), Some("https://rpc.mainnet.near.org"));
        assert_eq!(config.rpc_url("near:testnet"), Some("https://rpc.testnet.near.org"));
    }

    #[test]
    fn test_load_or_default_merges_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "vault_path": "/tmp/custom-vault",
            "rpc": {
                "eip155:1": "https://custom-eth.rpc",
                "eip155:11155111": "https://sepolia.rpc"
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        // User override replaces default
        assert_eq!(config.rpc_url("eip155:1"), Some("https://custom-eth.rpc"));
        // User-added chain
        assert_eq!(config.rpc_url("eip155:11155111"), Some("https://sepolia.rpc"));
        // Defaults preserved
        assert_eq!(config.rpc_url("eip155:137"), Some("https://polygon-rpc.com"));
        // Custom vault path
        assert_eq!(config.vault_path, PathBuf::from("/tmp/custom-vault"));
    }

    #[test]
    fn test_config_without_webui_parses_to_defaults() {
        // A config JSON without a "webui" key must still parse and yield defaults.
        let json = r#"{"vault_path": "/tmp/.onecipher", "rpc": {}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.webui, WebuiConfig::default());
        assert!(!config.webui.enabled);
        assert!(!config.webui.approval_mode);
        assert_eq!(config.webui.approval_timeout_secs, 300);
        assert_eq!(config.webui.listen, "127.0.0.1:0");
        assert_eq!(config.webui.session_timeout_secs, 1800);
        assert_eq!(config.webui.auto_lock_at, "");
    }

    #[test]
    fn test_webui_config_roundtrip() {
        let webui = WebuiConfig {
            enabled: true,
            approval_mode: true,
            approval_timeout_secs: 600,
            listen: "127.0.0.1:8080".to_string(),
            session_timeout_secs: 3600,
            auto_lock_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&webui).unwrap();
        let parsed: WebuiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(webui, parsed);
    }

    #[test]
    fn test_webui_config_partial_fields() {
        // Only some fields provided; rest default.
        let json = r#"{"enabled": true}"#;
        let webui: WebuiConfig = serde_json::from_str(json).unwrap();
        assert!(webui.enabled);
        assert!(!webui.approval_mode);
        assert_eq!(webui.approval_timeout_secs, 300);
        assert_eq!(webui.listen, "127.0.0.1:0");
    }

    #[test]
    fn test_wc_config_defaults_to_empty_trusted_origins() {
        // A config without `wc` section, or with a partial `wc` section, must
        // yield an empty trusted_origins (deny-all secure default).
        let json = r#"{"vault_path": "/tmp/.onecipher"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.wc.trusted_origins.len(), 0);

        let partial = r#"{"wc": {"relay_url": "wss://127.0.0.1:7443"}}"#;
        let config: Config = serde_json::from_str(partial).unwrap();
        assert_eq!(config.wc.relay_url, "wss://127.0.0.1:7443");
        assert_eq!(config.wc.trusted_origins.len(), 0);
    }

    #[test]
    fn test_wc_trusted_origins_serde_roundtrip() {
        let wc = WcConfig {
            relay_url: "wss://relay.walletconnect.com".into(),
            project_id: "abc123".into(),
            trusted_origins: vec!["iam.example.com".into(), "app.uniswap.org".into()],
        };
        let json = serde_json::to_string(&wc).unwrap();
        let parsed: WcConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(wc, parsed);
        assert_eq!(parsed.trusted_origins, vec!["iam.example.com", "app.uniswap.org"]);
    }

    #[test]
    fn test_wc_trusted_origins_json_array_parse() {
        // The `onecipher config set wc.trusted_origins '["iam.example.com"]'`
        // command writes a JSON array into the config file — verify Config
        // parses it.
        let json = r#"{"wc": {"trusted_origins": ["iam.example.com", "x.com"]}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.wc.trusted_origins, vec!["iam.example.com", "x.com"]);
    }

    #[test]
    fn test_load_or_default_merges_trusted_origins() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "wc": { "trusted_origins": ["iam.example.com"] }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        assert_eq!(config.wc.trusted_origins, vec!["iam.example.com"]);
        // Default relay URL preserved when not overridden.
        assert_eq!(config.wc.relay_url, WcConfig::default_relay_url());
    }
}
