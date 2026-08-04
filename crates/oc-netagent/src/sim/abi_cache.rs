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

/// Global in-memory cache: selector hex (lowercase, no 0x) → all known
/// function candidates, in insertion order (curated-first).
///
/// A vector is used because 4-byte selectors collide across token standards —
/// `0x095ea7b3` resolves to both ERC20 `approve(address,uint256)` and ERC721
/// `approve(address,uint256)`. Consumers that have a target-address-based type
/// hint should prefer the matching `contract_name`.
static SELECTOR_MAP: OnceLock<HashMap<String, Vec<ResolvedFunction>>> = OnceLock::new();

fn selector_key(selector: &str) -> String {
    selector.strip_prefix("0x").unwrap_or(selector).to_lowercase()
}

fn load_curated_abis() -> Vec<ContractAbi> {
    let mut out = Vec::new();
    let curated: &[(&str, &str)] = &[
        ("ERC20", include_str!("../../res/abis/erc20.json")),
        ("ERC721", include_str!("../../res/abis/erc721.json")),
        ("ERC1155", include_str!("../../res/abis/erc1155.json")),
        ("UniswapV2Router02", include_str!("../../res/abis/uniswap_v2_router.json")),
        ("UniswapV3Router", include_str!("../../res/abis/uniswap_v3_router.json")),
        ("Permit2", include_str!("../../res/abis/permit2.json")),
        ("AaveV3Pool", include_str!("../../res/abis/aave_v3_pool.json")),
        ("Comptroller", include_str!("../../res/abis/comptroller.json")),
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
    // L3 fix: single source of truth for home resolution. An unresolvable
    // HOME disables the user ABI cache instead of silently reading /tmp.
    oc_core::paths::state_path("abi_cache").ok()
}

/// Insert every function of `contracts` into `map`.
///
/// 4-byte selectors are not unique — distinct standards deliberately reuse
/// them (e.g. `0x095ea7b3` is both ERC20 `approve` and ERC721 `approve`).
///
/// **All candidates are retained.** Curated ABIs are inserted first, so
/// `vec[0]` is the preferred resolution. A file dropped into the user ABI
/// cache directory can add supplementary selectors but the curated
/// definitions always sort first, preventing cache-based prompt relabeling.
///
/// Exact duplicates (same `selector + contract_name + name`) are skipped.
fn insert_functions(map: &mut HashMap<String, Vec<ResolvedFunction>>, contracts: Vec<ContractAbi>) {
    for contract in contracts {
        for func in &contract.functions {
            let key = selector_key(&func.selector);
            let entry = map.entry(key).or_default();
            let is_dup = entry.iter().any(|existing| {
                existing.contract_name == contract.contract_name && existing.name == func.name
            });
            if is_dup {
                continue;
            }
            entry.push(ResolvedFunction {
                contract_name: contract.contract_name.clone(),
                name: func.name.clone(),
                inputs: func.inputs.clone(),
            });
        }
    }
    // Sort each entry so curated (inserted first) stays first, user-cached
    // entries are appended. Duplicates are already filtered above.
    // The push order already preserves this, but be explicit.
    for functions in map.values_mut() {
        // Stable: push order IS the priority order. No re-sort needed
        // unless we later add priority metadata.
        let _ = functions;
    }
}

/// Build the global selector map once. Returns a reference.
fn global_map() -> &'static HashMap<String, Vec<ResolvedFunction>> {
    SELECTOR_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        // Curated ABIs first so they are the preferred resolution for
        // ambiguous selectors.
        insert_functions(&mut map, load_curated_abis());
        insert_functions(&mut map, load_user_cached_abis());
        let total: usize = map.values().map(Vec::len).sum();
        tracing::info!(
            "ABI cache loaded {total} function signatures across {} selectors",
            map.len()
        );
        map
    })
}

/// Look up all known function signatures for a 4-byte selector.
///
/// `selector` should be 4 bytes (8 hex chars), with or without `0x` prefix.
///
/// Returns a slice (possibly empty) of candidates. The first element
/// (`candidates[0]`) is the preferred disambiguation when the caller does
/// not have a target-address-based type hint.
///
/// When the slice has more than one element and the caller has a target
/// contract type, it should prefer the entry whose `contract_name` matches.
/// See [`disambiguate`] for a convenience helper.
pub fn lookup(selector: &[u8; 4]) -> &'static [ResolvedFunction] {
    let hex = hex::encode(selector);
    global_map().get(&hex).map_or(&[], Vec::as_slice)
}

/// Pick the best function match given optional contract-type knowledge.
///
/// - When `hint` is `Some("ERC20")` and one candidate's `contract_name` matches, return that
///   candidate.
/// - Otherwise return `candidates[0]` (the curated-first preferred entry).
/// - Returns `None` when the candidate list is empty.
pub fn disambiguate<'a>(
    candidates: &'a [ResolvedFunction],
    hint: Option<&str>,
) -> Option<&'a ResolvedFunction> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(&candidates[0]);
    }
    if let Some(h) = hint {
        if let Some(matched) = candidates.iter().find(|c| c.contract_name.eq_ignore_ascii_case(h)) {
            return Some(matched);
        }
    }
    // No type hint or no match — prefer the first (curated, typically ERC20
    // over ERC721 since ERC20 is the more common approval context).
    Some(&candidates[0])
}

/// Force-rebuild the cache (for tests or hot-reload).
///
/// # Panics
/// Panics if the cache was already initialized (only safe to call early).
pub fn _reload() {
    let mut map: HashMap<String, Vec<ResolvedFunction>> = HashMap::new();
    insert_functions(&mut map, load_curated_abis());
    insert_functions(&mut map, load_user_cached_abis());
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

    /// Both candidates for a selector collision must be retained. The curated
    /// ABI (inserted first) stays at `vec[0]` for disambiguation; the later
    /// entry stays in the list so callers that know the target contract type
    /// can pick the correct one.
    #[test]
    fn both_selector_candidates_are_retained_curated_first() {
        let mut map = HashMap::new();
        let curated = vec![ContractAbi {
            contract_name: "ERC20".into(),
            functions: vec![AbiFunction {
                name: "approve".into(),
                selector: "0x095ea7b3".into(),
                inputs: vec![
                    AbiParam { name: "spender".into(), ty: "address".into() },
                    AbiParam { name: "amount".into(), ty: "uint256".into() },
                ],
            }],
        }];
        let erc721 = vec![ContractAbi {
            contract_name: "ERC721".into(),
            functions: vec![AbiFunction {
                name: "approve".into(),
                selector: "0x095ea7b3".into(),
                inputs: vec![
                    AbiParam { name: "to".into(), ty: "address".into() },
                    AbiParam { name: "tokenId".into(), ty: "uint256".into() },
                ],
            }],
        }];

        insert_functions(&mut map, curated);
        insert_functions(&mut map, erc721);

        let candidates = map.get("095ea7b3").expect("selector present");
        assert_eq!(candidates.len(), 2, "both candidates must be retained");
        assert_eq!(candidates[0].contract_name, "ERC20", "curated ABI must be first");
        assert_eq!(candidates[1].contract_name, "ERC721", "second candidate present");
    }

    /// `disambiguate` must prefer the explicit hint when available.
    #[test]
    fn disambiguate_prefers_explicit_hint() {
        let mut map = HashMap::new();
        insert_functions(
            &mut map,
            vec![ContractAbi {
                contract_name: "ERC20".into(),
                functions: vec![AbiFunction {
                    name: "approve".into(),
                    selector: "0x095ea7b3".into(),
                    inputs: vec![],
                }],
            }],
        );
        insert_functions(
            &mut map,
            vec![ContractAbi {
                contract_name: "ERC721".into(),
                functions: vec![AbiFunction {
                    name: "approve".into(),
                    selector: "0x095ea7b3".into(),
                    inputs: vec![],
                }],
            }],
        );

        let candidates = map.get("095ea7b3").unwrap();
        assert_eq!(disambiguate(candidates, Some("ERC721")).unwrap().contract_name, "ERC721");
        assert_eq!(disambiguate(candidates, Some("ERC20")).unwrap().contract_name, "ERC20");
        // No hint → first (curated)
        assert_eq!(disambiguate(candidates, None).unwrap().contract_name, "ERC20");
    }

    /// A later ABI may still contribute selectors nobody has claimed yet.
    #[test]
    fn later_abi_can_add_new_selectors() {
        let mut map = HashMap::new();
        insert_functions(
            &mut map,
            vec![ContractAbi {
                contract_name: "A".into(),
                functions: vec![AbiFunction {
                    name: "foo".into(),
                    selector: "0xaaaaaaaa".into(),
                    inputs: vec![],
                }],
            }],
        );
        insert_functions(
            &mut map,
            vec![ContractAbi {
                contract_name: "B".into(),
                functions: vec![AbiFunction {
                    name: "bar".into(),
                    selector: "0xbbbbbbbb".into(),
                    inputs: vec![],
                }],
            }],
        );
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("bbbbbbbb").unwrap()[0].name, "bar");
    }

    #[test]
    fn erc20_transfer_selector_found() {
        let candidates = lookup(&[0xa9, 0x05, 0x9c, 0xbb]);
        assert!(!candidates.is_empty(), "ERC20.transfer selector should be in cache");
        let f = &candidates[0];
        assert_eq!(f.name, "transfer");
        assert_eq!(f.contract_name, "ERC20");
        assert_eq!(f.inputs.len(), 2);
    }

    #[test]
    fn unknown_selector_returns_empty() {
        let candidates = lookup(&[0xff, 0xff, 0xff, 0xff]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn erc20_approve_has_collision_with_erc721() {
        // approve(address,uint256) = 0x095ea7b3 — shared by ERC20 and ERC721.
        let candidates = lookup(&[0x09, 0x5e, 0xa7, 0xb3]);
        assert!(!candidates.is_empty());
        // Both must be present. ERC20 is curated-first, so it's at index 0.
        assert_eq!(candidates[0].name, "approve");
        assert_eq!(candidates[0].contract_name, "ERC20");
        // Without a hint, disambiguate returns ERC20.
        let without_hint = disambiguate(candidates, None).unwrap();
        assert_eq!(without_hint.contract_name, "ERC20");
        // With an ERC721 hint, it picks ERC721.
        let with_hint = disambiguate(candidates, Some("ERC721")).unwrap();
        assert_eq!(with_hint.contract_name, "ERC721");
    }
}
