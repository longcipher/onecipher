#!/usr/bin/env bash
#
# Duplicate-dependency ratchet.
#
# The workspace currently resolves 68 crates to more than one semver-
# incompatible version. Most of that is the in-flight RustCrypto 0.10 -> 0.11
# transition (digest, sha2, block-buffer, cipher, aead, ...) plus the alloy /
# k256 stack pulling older elliptic-curve releases. Those cannot be collapsed
# unilaterally, so a hard "zero duplicates" gate would be permanently red and
# would simply be ignored.
#
# Instead this is a ratchet: it fails only when the count *increases*. That
# catches the realistic regression -- someone adding a dependency that drags in
# yet another copy of an already-duplicated tree -- while allowing the existing
# debt to be paid down incrementally. Lower the baseline whenever the count
# drops so the gain is locked in.
#
# Usage:
#   scripts/check-duplicate-deps.sh          # enforce the baseline
#   scripts/check-duplicate-deps.sh --list   # show what is duplicated

set -euo pipefail

# Maximum number of crates allowed to appear at more than one version.
# Only ever decrease this. See the header for why it is not 0.
#
# Bumped 64 -> 67: the committed Cargo.lock already resolved to 67 duplicate
# crates (the previous BASELINE=64 was stale and no longer matched the lock).
# The increase is driven by the RustCrypto 0.10/0.11 split plus totp-rs v6
# moving to hmac/sha1/sha2 0.11 and base32 0.5 — single-version additions that
# are not collapsible from this workspace. Locked in at 67 so future increases
# are again caught by the ratchet.
BASELINE=67

cd "$(dirname "$0")/.."

# `--edges normal` excludes dev- and build-dependencies: a duplicate that only
# affects test or proc-macro builds does not bloat the shipped binary and is
# not worth blocking a PR over.
duplicates="$(cargo tree --duplicates --workspace --edges normal 2>/dev/null \
  | grep -E '^[a-z0-9_-]+ v' \
  | sed -E 's/ \(\*\)$//' \
  | awk '{print $1}' \
  | sort -u)"

if [ -z "$duplicates" ]; then
  count=0
else
  count="$(printf '%s\n' "$duplicates" | wc -l | tr -d ' ')"
fi

if [ "${1:-}" = "--list" ]; then
  echo "Crates resolved at multiple versions ($count):"
  cargo tree --duplicates --workspace --edges normal 2>/dev/null \
    | grep -E '^[a-z0-9_-]+ v' \
    | sed -E 's/ \(\*\)$//' \
    | sort -u
  exit 0
fi

echo "Duplicate crates: $count (baseline: $BASELINE)"

if [ "$count" -gt "$BASELINE" ]; then
  echo
  echo "FAIL: duplicate dependency count increased from $BASELINE to $count."
  echo
  echo "A new dependency has pulled in another copy of an already-duplicated"
  echo "tree. Run 'scripts/check-duplicate-deps.sh --list' to see the details,"
  echo "then either align the version via [workspace.dependencies] or justify"
  echo "the addition and raise BASELINE in this script."
  exit 1
fi

if [ "$count" -lt "$BASELINE" ]; then
  echo
  echo "Duplicate count dropped to $count. Lower BASELINE in"
  echo "scripts/check-duplicate-deps.sh to $count to lock in the improvement."
fi

echo "PASS"
