// Single-table chain registry for Phase2 signer convergence (C1).
//
// One line per chain family: Variant, display string, CAIP-2 namespace,
// SLIP-44 coin type, whether the family uses Ed25519, and the default
// derivation-path template (`{index}` is the account index placeholder,
// also referred to as `signer_path` in the Phase2 task list).
//
// Adding a chain means adding ONE line here. `ChainType` helpers in
// `chain.rs` and the `oc-signer` dispatch helpers expand from this table
// via the macro, so they cannot drift.
//
// The macro itself has no dependencies (no `use`, no types, no functions),
// hence it is R56-safe: expanding it never pulls `tokio`, `reqwest`,
// `tungstenite`, `hyper`, `async-std`, or `smol` into an isolated crate.
//
// The macro expands to consecutive callback invocations separated by `;`
// (statement position). Callbacks must therefore expand to self-contained
// blocks/statements (e.g. `{ assert!(...); }`), NOT to array elements or
// match arms. Statement style works uniformly for checks, counters, and
// `if`-chain dispatch in `oc-signer`.
//
// Usage:
// ```ignore
// macro_rules! check_entry {
//     ($variant:ident, $display:expr, $ns:expr, $coin:expr, $ed:expr, $path:expr) => {
//         { assert_eq!(ChainType::$variant.to_string(), $display); }
//     };
// }
// crate::for_each_chain!(check_entry);
// ```
#[macro_export]
macro_rules! for_each_chain {
    ($callback:ident) => {
        $callback!(Evm, "evm", "eip155", 60, false, "m/44'/60'/0'/0/{index}");
        $callback!(Solana, "solana", "solana", 501, true, "m/44'/501'/{index}'/0'");
        $callback!(Cosmos, "cosmos", "cosmos", 118, false, "m/44'/118'/0'/0/{index}");
        $callback!(Bitcoin, "bitcoin", "bip122", 0, false, "m/84'/0'/0'/0/{index}");
        $callback!(Tron, "tron", "tron", 195, false, "m/44'/195'/0'/0/{index}");
        $callback!(Ton, "ton", "ton", 607, true, "m/44'/607'/{index}'");
        $callback!(Spark, "spark", "spark", 8797555, false, "m/84'/0'/0'/0/{index}");
        $callback!(Filecoin, "filecoin", "fil", 461, false, "m/44'/461'/0'/0/{index}");
        $callback!(Sui, "sui", "sui", 784, true, "m/44'/784'/{index}'/0'/0'");
        $callback!(Xrpl, "xrpl", "xrpl", 144, false, "m/44'/144'/0'/0/{index}");
        $callback!(Nano, "nano", "nano", 165, true, "m/44'/165'/{index}'");
        $callback!(Near, "near", "near", 397, true, "m/44'/397'/{index}'");
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn registry_has_twelve_entries() {
        // Statement-style counter: each expansion bumps `count`.
        let mut count = 0usize;
        macro_rules! count_entry {
            ($_v:ident, $_d:expr, $_n:expr, $_c:expr, $_e:expr, $_p:expr) => {{
                count += 1;
            }};
        }
        crate::for_each_chain!(count_entry);
        assert_eq!(count, 12);
    }

    #[test]
    fn spark_entry_documents_coin_type_vs_path_split() {
        // Spark is the intentional outlier: SLIP-44 registers 8797555 for the
        // Spark namespace, but derivation reuses the Bitcoin BIP-84 path
        // (`m/84'/0'/...`) because Spark is a Bitcoin L2 operating on the
        // same key. See the Spark constant-source comment in
        // `oc-signer/src/chains/spark.rs`.
        // Collected via push (not assignment) to avoid `unused_assignments`
        // lint noise under `-D warnings`.
        let mut found: Vec<(u32, &'static str)> = Vec::new();
        macro_rules! find_spark {
            (Spark, $_d:expr, $_n:expr, $coin:expr, $_e:expr, $path:expr) => {{
                found.push(($coin, $path));
            }};
            ($_v:ident, $_d:expr, $_n:expr, $_c:expr, $_e:expr, $_p:expr) => {{}};
        }
        crate::for_each_chain!(find_spark);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 8797555);
        assert_eq!(found[0].1, "m/84'/0'/0'/0/{index}");
    }
}
