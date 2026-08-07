#!/usr/bin/env bash
#
# R12 hard gate — no TCP in the isolated crates.
#
# History: this gate used to be `nm <binary> | grep -i tcp`. That check was
# unsound in both directions:
#
#   - False negative: `[profile.release]` sets `strip = "symbols"`, so `nm`
#     reports "no symbols" and the grep passes vacuously no matter what the
#     binary actually links.
#   - False positive by design: R12b explicitly permits TCP in the `onecipher`
#     daemon, which links axum/hyper for the Web UI and the WalletConnect
#     relay. A binary that genuinely had no TCP symbols would mean the Web UI
#     had been dropped.
#
# R12a (source-level isolation) is the part that is both meaningful and
# reliably checkable, so that is what this script enforces: the isolated
# crates must not name `TcpListener` or `TcpStream` anywhere in their source.
# When a binary is supplied and happens to carry a symbol table, its symbols
# are inspected as a best-effort extra signal.
#
# Referenced by:
#   - .github/workflows/ci.yml (hard-gates job)
#
# Usage: ci/check_symbols.sh [path/to/binary]

set -uo pipefail

cd "$(dirname "$0")/.."

BINARY="${1:-}"
status=0

# --- R12a: source-level isolation (authoritative) --------------------------

ISOLATED_SRC=(
  crates/oc-keyagent/src
  crates/oc-crypto/src
  crates/oc-policy/src
  crates/oc-session-key/src
)

present=()
for dir in "${ISOLATED_SRC[@]}"; do
  [ -d "$dir" ] && present+=("$dir")
done

if [ "${#present[@]}" -eq 0 ]; then
  echo "R12a ERROR: none of the isolated crate source directories were found"
  exit 1
fi

if hits="$(grep -rnE 'TcpListener|TcpStream' "${present[@]}" 2>/dev/null)"; then
  if [ -n "$hits" ]; then
    echo "R12a VIOLATION: TCP types found in isolated crate sources:"
    printf '%s\n' "$hits"
    status=1
  fi
fi

if [ "$status" -eq 0 ]; then
  echo "R12a PASS: no TcpListener/TcpStream in isolated crate sources"
fi

# --- R12 (best effort): symbol inspection ----------------------------------

if [ -n "$BINARY" ]; then
  if [ ! -f "$BINARY" ]; then
    echo "R12 ERROR: binary not found: $BINARY"
    exit 1
  fi

  symbols="$(nm "$BINARY" 2>/dev/null || true)"
  if [ -z "$symbols" ] || printf '%s' "$symbols" | grep -qi 'no symbols'; then
    echo "R12 NOTE: $BINARY is stripped; symbol inspection skipped (see header)."
  else
    # Only Rust std's TCP types are checked. Bare libc `socket`/`bind`/
    # `connect` are shared with Unix-domain sockets, which are required, so
    # matching on them would be meaningless.
    if tcp_hits="$(printf '%s' "$symbols" | grep -E 'TcpListener|TcpStream' | sort -u)"; then
      if [ -n "$tcp_hits" ]; then
        echo "R12 NOTE: $BINARY references Rust TCP types:"
        printf '%s\n' "$tcp_hits" | head -20
        echo "This is permitted for the 'onecipher' daemon per R12b (Web UI +"
        echo "WalletConnect relay). R12c (loopback-only bind) governs runtime."
      fi
    fi
  fi
fi

exit $status
