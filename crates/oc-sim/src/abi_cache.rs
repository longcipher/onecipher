use std::{collections::HashMap, path::PathBuf, sync::OnceLock};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiFunction {
    pub name: String,
    pub selector: String,
    #[serde(default)]
    pub inputs: Vec<AbiParam>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractAbi {
    pub contract_name: String,
    pub functions: Vec<AbiFunction>,
}

#[derive(Debug, Clone)]
pub struct ResolvedFunction {
    pub contract_name: String,
    pub name: String,
    pub inputs: Vec<AbiParam>,
}

/// Global in-memory cache: selector hex (lowercase, no 0x) → ResolvedFunction.
static SELECTOR_MAP: OnceLock<HashMap<String, ResolvedFunction>> = OnceLock::new();

fn selector_key(selector: &str) -> String {
    selector.strip_prefix("0x").unwrap_or(selector).to_lowercase()
}

fn load_curated_abis() -> Vec<ContractAbi> {
    let mut out = Vec::new();
    let curated: &[(&str, &str)] = &[
        ("ERC20", include_str!("../res/abis/erc20.json")),
        ("ERC721", include_str!("../res/abis/erc721.json")),
        ("ERC1155", include_str!("../res/abis/erc1155.json")),
        ("UniswapV2Router02", include_str!("../res/abis/uniswap_v2_router.json")),
        ("UniswapV3Router", include_str!("../res/abis/uniswap_v3_router.json")),
        ("Permit2", include_str!("../res/abis/permit2.json")),
        ("AaveV3Pool", include_str!("../res/abis/aave_v3_pool.json")),
        ("Comptroller", include_str!("../res/abis/comptroller.json")),
    ];
    for (_name, json) in curated {
        match serde_json::from_str::<ContractAbi>(json) {
            Ok(abi) => out.push(abi),
            Err(e) => tracing::warn!("failed to parse curated ABI {_name}: {e}"),
        }
    }
    out
}

fn load_user_cached_abis() -> Vec<ContractAbi> {
    let dir = match user_cache_dir() {
        Some(d) => d,
        None => return Vec::new(),
    };
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Some(abi) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<ContractAbi>(&s).ok())
            {
                out.push(abi);
            } else {
                tracing::warn!("skipping bad ABI cache file {}", path.display());
            }
        }
    }
    out
}

fn user_cache_dir() -> Option<PathBuf> {
    dirs_or_fallback().map(|d| d.join(".onecipher").join("abi_cache"))
}

fn dirs_or_fallback() -> Option<PathBuf> {
    // ponytail: HOME/USERPROFILE is enough; no dep on dirs crate for one path
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(not(unix))]
    {
        std::env::var("USERPROFILE").ok().or_else(|| std::env::var("HOME").ok()).map(PathBuf::from)
    }
}

/// Build the global selector map once. Returns a reference.
fn global_map() -> &'static HashMap<String, ResolvedFunction> {
    SELECTOR_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        let all = {
            let mut a = load_curated_abis();
            a.extend(load_user_cached_abis());
            a
        };
        for contract in all {
            for func in &contract.functions {
                let key = selector_key(&func.selector);
                map.insert(
                    key,
                    ResolvedFunction {
                        contract_name: contract.contract_name.clone(),
                        name: func.name.clone(),
                        inputs: func.inputs.clone(),
                    },
                );
            }
        }
        tracing::info!("ABI cache loaded {} selectors", map.len());
        map
    })
}

/// Look up a function by its 4-byte selector.
///
/// `selector` should be 4 bytes (8 hex chars), with or without `0x` prefix.
pub fn lookup(selector: &[u8; 4]) -> Option<ResolvedFunction> {
    let hex = hex::encode(selector);
    global_map().get(&hex).cloned()
}

/// Force-rebuild the cache (for tests or hot-reload).
///
/// # Panics
/// Panics if the cache was already initialized (only safe to call early).
pub fn _reload() {
    let all = {
        let mut a = load_curated_abis();
        a.extend(load_user_cached_abis());
        a
    };
    let mut map = HashMap::new();
    for contract in all {
        for func in &contract.functions {
            let key = selector_key(&func.selector);
            map.insert(
                key,
                ResolvedFunction {
                    contract_name: contract.contract_name.clone(),
                    name: func.name.clone(),
                    inputs: func.inputs.clone(),
                },
            );
        }
    }
    let _ = SELECTOR_MAP.set(map);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_curated_abi_count() {
        let abis = load_curated_abis();
        assert_eq!(abis.len(), 8, "expected 8 curated ABIs");
        assert!(abis.iter().any(|a| a.contract_name == "ERC20"));
        assert!(abis.iter().any(|a| a.contract_name == "AaveV3Pool"));
    }

    #[test]
    fn erc20_transfer_selector_found() {
        let result = lookup(&[0xa9, 0x05, 0x9c, 0xbb]);
        assert!(result.is_some(), "ERC20.transfer selector should be in cache");
        let f = result.unwrap();
        assert_eq!(f.name, "transfer");
        assert_eq!(f.contract_name, "ERC20");
        assert_eq!(f.inputs.len(), 2);
    }

    #[test]
    fn unknown_selector_returns_none() {
        let result = lookup(&[0xff, 0xff, 0xff, 0xff]);
        assert!(result.is_none());
    }

    #[test]
    fn erc20_approve_found() {
        // approve(address,uint256) = 0x095ea7b3
        let result = lookup(&[0x09, 0x5e, 0xa7, 0xb3]);
        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.name, "approve");
    }
}
