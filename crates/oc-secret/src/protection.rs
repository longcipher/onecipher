//! Asymmetric P1 protection check with five-state distinction.
//!
//! The sealed (authoritative) generation is compared against the local
//! generation:
//! - `local >= sealed` allows,
//! - `local < sealed` denies,
//! - a missing sealed index allows in weak mode (warn, never deny on absence).
//!
//! Five states are distinguished for `doctor` census output:
//! [`ProtectionStatus::Protected`], [`ProtectionStatus::Lag`],
//! [`ProtectionStatus::Stale`], [`ProtectionStatus::Missing`],
//! [`ProtectionStatus::Tombstone`].

use std::collections::BTreeMap;

/// Five-state protection census for one secret path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtectionStatus {
    /// Local generation covers sealed generation.
    Protected,
    /// Exactly one generation behind (deny).
    Lag,
    /// More than one generation behind (deny).
    Stale,
    /// No sealed record (or no local record while sealed exists): allow in
    /// weak mode with a warning.
    Missing,
    /// Path is tombstoned (deleted upstream): deny.
    Tombstone,
}

/// Outcome of a single protection check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionDecision {
    /// Whether the read is allowed.
    pub allow: bool,
    /// Five-state classification.
    pub status: ProtectionStatus,
    /// Human-readable reason.
    pub reason: String,
    /// True when the allow is weak (missing index) and should warn.
    pub weak: bool,
}

/// Check one path.
///
/// - `tombstoned` forces [`ProtectionStatus::Tombstone`] (deny).
/// - `sealed_gen == None` yields [`ProtectionStatus::Missing`] (allow, weak).
/// - `local_gen == None` with a sealed record yields `Missing` (allow, weak).
/// - `local < sealed`: deny; gap of 1 is `Lag`, larger is `Stale`.
/// - otherwise allow as `Protected`.
pub fn check_protection(
    path: &str,
    local_gen: Option<u64>,
    sealed_gen: Option<u64>,
    tombstoned: bool,
) -> ProtectionDecision {
    if tombstoned {
        return ProtectionDecision {
            allow: false,
            status: ProtectionStatus::Tombstone,
            reason: format!("'{path}' is tombstoned upstream"),
            weak: false,
        };
    }
    let Some(sealed) = sealed_gen else {
        return ProtectionDecision {
            allow: true,
            status: ProtectionStatus::Missing,
            reason: format!("'{path}' has no sealed generation; weak allow"),
            weak: true,
        };
    };
    let Some(local) = local_gen else {
        return ProtectionDecision {
            allow: true,
            status: ProtectionStatus::Missing,
            reason: format!("'{path}' has no local generation; weak allow"),
            weak: true,
        };
    };
    if local >= sealed {
        ProtectionDecision {
            allow: true,
            status: ProtectionStatus::Protected,
            reason: format!("'{path}' up to date ({local} >= {sealed})"),
            weak: false,
        }
    } else if sealed - local == 1 {
        ProtectionDecision {
            allow: false,
            status: ProtectionStatus::Lag,
            reason: format!("'{path}' lags by 1 ({local} < {sealed})"),
            weak: false,
        }
    } else {
        ProtectionDecision {
            allow: false,
            status: ProtectionStatus::Stale,
            reason: format!("'{path}' stale ({local} < {sealed})"),
            weak: false,
        }
    }
}

/// Census over all paths in the union of local/sealed/tombstone sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenerationCensus {
    /// Fully protected paths.
    pub sealed: usize,
    /// Exactly-one-behind paths.
    pub lag: usize,
    /// More-than-one-behind paths.
    pub stale: usize,
    /// Missing on either side.
    pub missing: usize,
    /// Tombstoned paths.
    pub tombstones: usize,
    /// Alias for `sealed` kept for the doctor JSON contract.
    pub fully_protected: usize,
}

/// Build a census from local/sealed maps plus a tombstone set.
///
/// Wallet keys (legacy keystore files) are counted separately via
/// [`census_including_wallets`]: they ride vault-file sealing (0600 +
/// authenticated encryption) rather than generation sealing.
pub fn census(
    local: &BTreeMap<String, u64>,
    sealed: &BTreeMap<String, u64>,
    tombstones: &std::collections::BTreeSet<String>,
) -> GenerationCensus {
    census_including_wallets(local, sealed, tombstones, &[])
}

/// Build a census that also folds wallet keys into the sealed count.
///
/// Every `wallet_name` absent from the local/sealed/tombstone sets counts as
/// one sealed + fully-protected entry (vault-file sealing is the wallet
/// equivalent of generation sealing). Names already covered by the secret
/// sets are not double-counted: the secret classification wins.
pub fn census_including_wallets(
    local: &BTreeMap<String, u64>,
    sealed: &BTreeMap<String, u64>,
    tombstones: &std::collections::BTreeSet<String>,
    wallet_names: &[String],
) -> GenerationCensus {
    let mut out = GenerationCensus::default();
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(local.keys().cloned());
    keys.extend(sealed.keys().cloned());
    keys.extend(tombstones.iter().cloned());
    for k in &keys {
        let d = check_protection(
            k,
            local.get(k).copied(),
            sealed.get(k).copied(),
            tombstones.contains(k),
        );
        match d.status {
            ProtectionStatus::Protected => {
                out.sealed += 1;
                out.fully_protected += 1;
            }
            ProtectionStatus::Lag => out.lag += 1,
            ProtectionStatus::Stale => out.stale += 1,
            ProtectionStatus::Missing => out.missing += 1,
            ProtectionStatus::Tombstone => out.tombstones += 1,
        }
    }
    // Wallet keys live outside the generation namespace (keystore files, not
    // age entries). Each wallet name not already covered by the secret sets
    // counts as sealed + fully-protected: vault-file sealing (0600 +
    // authenticated encryption) is the wallet equivalent of a covered
    // generation. The secret classification always wins on overlap.
    let mut wallet_only = 0usize;
    for w in wallet_names {
        if !local.contains_key(w) && !sealed.contains_key(w) && !tombstones.contains(w) {
            wallet_only += 1;
        }
    }
    out.sealed += wallet_only;
    out.fully_protected += wallet_only;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_when_local_covers_sealed() {
        let d = check_protection("a", Some(5), Some(5), false);
        assert!(d.allow);
        assert_eq!(d.status, ProtectionStatus::Protected);
        let d = check_protection("a", Some(9), Some(5), false);
        assert!(d.allow);
    }

    #[test]
    fn deny_when_behind_with_lag_stale_split() {
        let lag = check_protection("a", Some(4), Some(5), false);
        assert!(!lag.allow);
        assert_eq!(lag.status, ProtectionStatus::Lag);
        let stale = check_protection("a", Some(1), Some(5), false);
        assert!(!stale.allow);
        assert_eq!(stale.status, ProtectionStatus::Stale);
    }

    #[test]
    fn missing_index_allows_weak() {
        let d = check_protection("a", Some(1), None, false);
        assert!(d.allow && d.weak);
        assert_eq!(d.status, ProtectionStatus::Missing);
        let d = check_protection("a", None, Some(3), false);
        assert!(d.allow && d.weak);
    }

    #[test]
    fn tombstone_denies() {
        let d = check_protection("a", Some(9), Some(9), true);
        assert!(!d.allow);
        assert_eq!(d.status, ProtectionStatus::Tombstone);
    }

    #[test]
    fn census_counts_five_states() {
        let local: BTreeMap<String, u64> =
            [("p", 5), ("l", 4), ("s", 1), ("m", 1)].map(|(k, v)| (k.to_string(), v)).into();
        let sealed: BTreeMap<String, u64> =
            [("p", 5), ("l", 5), ("s", 5)].map(|(k, v)| (k.to_string(), v)).into();
        let tomb: std::collections::BTreeSet<String> = ["t".to_string()].into();
        let c = census(&local, &sealed, &tomb);
        assert_eq!(c.sealed, 1);
        assert_eq!(c.lag, 1);
        assert_eq!(c.stale, 1);
        assert_eq!(c.missing, 1);
        assert_eq!(c.tombstones, 1);
        assert_eq!(c.fully_protected, 1);
    }

    #[test]
    fn census_folds_wallet_keys_into_sealed() {
        let local: BTreeMap<String, u64> = [("p", 5)].map(|(k, v)| (k.to_string(), v)).into();
        let sealed: BTreeMap<String, u64> = [("p", 5)].map(|(k, v)| (k.to_string(), v)).into();
        let tomb: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // Two wallets, one colliding with a secret path (no double count).
        let wallets = vec!["main".to_string(), "p".to_string()];
        let c = census_including_wallets(&local, &sealed, &tomb, &wallets);
        assert_eq!(c.sealed, 2, "one secret + one wallet-only name");
        assert_eq!(c.fully_protected, 2);
        assert_eq!(c.missing, 0);
    }
}
