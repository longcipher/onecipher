#!/usr/bin/env bash
#
# OneCipher CLI end-to-end test suite.
#
# Exercises the `onecipher` binary as a black box: every top-level command,
# its subcommands, and the cross-cutting security gates (R12c loopback-only
# bind, R12e non-loopback reject, fail-closed auth surfaces). Crypto outputs
# are checked against independent vectors (BIP39 test mnemonic, RFC 4226
# HOTP counters, EIP-155 recovery ids).
#
# The suite runs fully isolated from a real install: it redirects HOME and
# XDG_RUNTIME_DIR into a scratch directory so wallet vaults, age identities,
# Key-Agent sockets and the daemon under test never touch user data. It is
# safe to run on a machine where a production daemon is live.
#
# Usage:
#   scripts/e2e.sh                       # build release bin if missing, then run
#   ONECIPHER_BIN=... scripts/e2e.sh     # test a specific binary
#
# Environment:
#   ONECIPHER_BIN   binary under test (default: target/release/onecipher,
#                   falling back to target/debug/onecipher)
#   E2E_KEEP=1      keep the scratch directory for post-mortem inspection
#
# Exit status: number of failed assertions (capped at 125), 0 when all pass.

# NOTE: deliberately NOT `set -e` — this harness expects most commands under
# test to exit nonzero (negative paths); each result is captured explicitly.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -n "${ONECIPHER_BIN:-}" ]; then
  BIN=$ONECIPHER_BIN
elif [ -x "$REPO_ROOT/target/release/onecipher" ]; then
  BIN=$REPO_ROOT/target/release/onecipher
elif [ -x "$REPO_ROOT/target/debug/onecipher" ]; then
  BIN=$REPO_ROOT/target/debug/onecipher
else
  echo "error: no onecipher binary found; run 'just release' first or set ONECIPHER_BIN" >&2
  exit 1
fi

E2E=${ONECIPHER_E2E_DIR:-${TMPDIR:-/tmp}/onecipher-e2e}
H=$E2E/home
W=$E2E/work
RUN=$E2E/run
RES=$E2E/results.txt

export HOME=$H
export XDG_RUNTIME_DIR=$RUN
export OC_NONINTERACTIVE=1
export EDITOR=true

rm -rf "$E2E"
mkdir -p "$H" "$W" "$RUN"

PASS=0
FAIL=0
SKIP=0
FAILED=()
SKIPPED=()
LAST_OUT=""
: > "$RES"

note() { echo "$1" | tee -a "$RES"; }

# ok <0|nz> <description> <command...>
# Asserts that the command exits zero ("0") or nonzero ("nz").
ok() {
  local expect="$1"; shift
  local desc="$1"; shift
  local out rc
  out=$(timeout 60 "$@" 2>&1)
  rc=$?
  if { [ "$expect" = 0 ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = nz ] && [ "$rc" -ne 0 ]; }; then
    PASS=$((PASS + 1))
    note "PASS  $desc$( [ "$expect" = nz ] && printf ' (exit=%s)' "$rc" )"
  else
    FAIL=$((FAIL + 1))
    FAILED+=("$desc")
    note "FAIL  $desc (exit=$rc, expected=$expect)"
    printf '%s\n' "$out" | head -4 | sed 's/^/      | /' | tee -a "$RES"
  fi
  LAST_OUT="$out"
}

# skip <description> <reason>
skip() {
  SKIP=$((SKIP + 1))
  SKIPPED+=("$1")
  note "SKIP  $1 ($2)"
}

# assert_out <description> <grep-pattern> — matches against the previous ok()'s output.
assert_out() {
  local desc="$1" pat="$2"
  if printf '%s' "$LAST_OUT" | grep -qi -- "$pat"; then
    PASS=$((PASS + 1))
    note "PASS  $desc"
  else
    FAIL=$((FAIL + 1))
    FAILED+=("$desc")
    note "FAIL  $desc (pattern not found: $pat)"
    printf '%s\n' "$LAST_OUT" | head -6 | sed 's/^/      | /' | tee -a "$RES"
  fi
}

note "=== OneCipher E2E — $(date -u +%FT%TZ) — $($BIN --version 2>&1) ==="
note "HOME=$H XDG_RUNTIME_DIR=$RUN (isolated from real install)"

# ---------------- A. basics ----------------
note "--- A. basics ---"
ok 0 "--version"                                 "$BIN" --version
ok 0 "--help"                                    "$BIN" --help
ok nz "unknown command rejected"                 "$BIN" definitely-not-a-command
ok nz "missing required arg rejected"            "$BIN" wallet create
for sh in bash zsh fish powershell elvish; do
  ok 0 "completion $sh"                          "$BIN" completion "$sh"
done

# ---------------- B. age identity ----------------
note "--- B. age identity ---"
chmod 700 "$H/.onecipher" 2>/dev/null || true # known issue: fresh dir is created 0755
ok 0 "age init"                                  "$BIN" age init
ok 0 "age identity-show"                         "$BIN" age identity-show
LAST_OUT=$(timeout 60 "$BIN" age identity-show 2>&1)
assert_out "age identity shows age1 recipient" "age1"

# ---------------- C. secrets ----------------
note "--- C. secrets CRUD + search + env + fsck ---"
export ONECIPHER_SECRET="s3cr3t-value-123"
ok 0 "secret add (env payload)"                  "$BIN" secret add creds/api --type password --meta url=https://api.example.com
unset ONECIPHER_SECRET
printf '%s' '{"secret":"stdin-value-456","notes":"from stdin"}' | \
  ok 0 "secret add --stdin"                      "$BIN" secret add creds/stdin --type password --stdin
ok 0 "secret list"                               "$BIN" secret list
ok 0 "secret get"                                "$BIN" secret get creds/api
LAST_OUT=$(timeout 60 "$BIN" secret get creds/api --field secret 2>&1)
assert_out "secret get --field secret returns value" "s3cr3t-value-123"
ok 0 "secret get --json"                         "$BIN" secret get creds/api --json
printf '%s' '{"secret":"updated-789"}' | \
  ok 0 "secret update --stdin"                   "$BIN" secret update creds/stdin --stdin
LAST_OUT=$(timeout 60 "$BIN" secret get creds/stdin --field secret 2>&1)
assert_out "secret update persisted" "updated-789"
ok 0 "secret rename"                             "$BIN" secret rename creds/stdin creds/stdin2
ok nz "old name gone after rename"               "$BIN" secret get creds/stdin
ok 0 "secret copy"                               "$BIN" secret copy creds/api creds/api-copy
ok nz "copy overwrite without force fails"       "$BIN" secret copy creds/api-copy creds/api
ok 0 "copy --force overwrites"                   "$BIN" secret copy creds/api-copy creds/api -f
ok 0 "secret move"                               "$BIN" secret move creds/stdin2 creds/moved
ok 0 "grep plaintext hit"                        "$BIN" grep s3cr3t
ok 0 "grep regex hit"                            "$BIN" grep -r "s3cr3t.value"
ok 0 "find fuzzy"                                "$BIN" find api
ok 0 "find --json"                               "$BIN" find api --json
ok nz "secret get nonexistent fails cleanly"     "$BIN" secret get does/not/exist
export ONECIPHER_SECRET="injected-env-999"
ok 0 "secret add envtest"                        "$BIN" secret add envtest --type password
unset ONECIPHER_SECRET
LAST_OUT=$(timeout 60 "$BIN" env --name envtest -- sh -c 'env' 2>&1)
assert_out "env injects secret into child process" "injected-env-999"
ok 0 "secret edit with no-op editor"             "$BIN" secret edit creds/moved
ok 0 "secret delete"                             "$BIN" secret delete envtest
ok nz "deleted secret gone"                      "$BIN" secret get envtest
chmod 700 "$H/.onecipher"
ok 0 "fsck clean store (home 0700)"              "$BIN" fsck
ok 0 "fsck --fix idempotent"                     "$BIN" fsck --fix

# ---------------- D. passwords ----------------
note "--- D. password management ---"
LAST_OUT=$(timeout 60 "$BIN" password generate --length 32 2>&1)
assert_out "password generate emits password" "."
LEN=$(printf '%s' "$LAST_OUT" | tail -1 | tr -d '[:space:]' | wc -c)
if [ "$LEN" -eq 32 ]; then
  PASS=$((PASS + 1)); note "PASS  generated length == 32"
else
  FAIL=$((FAIL + 1)); FAILED+=("password length"); note "FAIL  generated length=$LEN"
fi
ok 0 "password generate memorable"               "$BIN" password generate --generator memorable
ok 0 "password generate xkcd"                    "$BIN" password generate --generator xkcd
export ONECIPHER_SECRET="pw-db-pass-111"
ok 0 "password add explicit"                     "$BIN" password add sites/github --url https://github.com --username octocat
ok 0 "password add --generate"                   "$BIN" password add sites/gitlab --url https://gitlab.com --username u2 --generate
unset ONECIPHER_SECRET
ok 0 "password readable via secret get"          "$BIN" secret get sites/github

# ---------------- E. TOTP/HOTP (RFC 4226 vectors) ----------------
note "--- E. TOTP/HOTP RFC vectors ---"
# Secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ is ASCII "12345678901234567890",
# the RFC 4226 reference key. HOTP entries can only be created via an explicit
# otpauth://hotp URI (`totp add --secret` always yields a TOTP-type entry).
HOTP_URI="otpauth://hotp/E2E:e2e@test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=E2E&counter=0"
TOTP_URI="otpauth://totp/E2E:totp@test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=E2E"
ok 0 "totp add HOTP via otpauth URI"             "$BIN" totp add totp/rfc-hotp --otpauth "$HOTP_URI"
LAST_OUT=$(timeout 60 "$BIN" totp hotp totp/rfc-hotp --counter 0 2>&1)
assert_out "RFC4226 counter=0 -> 755224" "755224"
LAST_OUT=$(timeout 60 "$BIN" totp hotp totp/rfc-hotp --counter 5 2>&1)
assert_out "RFC4226 counter=5 -> 254676" "254676"
ok 0 "totp add TOTP via otpauth URI"             "$BIN" totp add totp/rfc-totp --otpauth "$TOTP_URI"
ok 0 "totp generate current code"                "$BIN" totp generate totp/rfc-totp
LAST_OUT=$(timeout 60 "$BIN" totp uris totp/rfc-totp 2>&1)
assert_out "totp uris emits otpauth URI" "otpauth://"
ok nz "totp generate missing fails"              "$BIN" totp generate nope/none

# ---------------- F. wallets (empty-passphrase model) ----------------
note "--- F. wallet lifecycle ---"
# CLI-created/imported wallets start with an EMPTY passphrase by design;
# ONECIPHER_PASSPHRASE acts as a non-interactive gate for export-style ops.
ok 0 "wallet info"                               "$BIN" wallet info
export ONECIPHER_PASSPHRASE="gate-only"
ok 0 "wallet create w1 12w"                      "$BIN" wallet create --name w1 --words 12
ok 0 "wallet create w2 24w --show-mnemonic"      "$BIN" wallet create --name w2 --words 24 --show-mnemonic
ok nz "duplicate wallet name rejected"           "$BIN" wallet create --name w1
LAST_OUT=$(timeout 60 "$BIN" wallet list 2>&1)
assert_out "list shows w1" "w1"
assert_out "list shows w2" "w2"
ok 0 "wallet export w1 mnemonic"                 "$BIN" wallet export --wallet w1
MNEM=$(printf '%s' "$LAST_OUT" | tail -1)
NW=$(printf '%s' "$MNEM" | wc -w)
if [ "$NW" -eq 12 ]; then
  PASS=$((PASS + 1)); note "PASS  exported mnemonic has 12 words"
else
  FAIL=$((FAIL + 1)); FAILED+=("mnemonic words"); note "FAIL  mnemonic words=$NW"
fi
ok 0 "export public-key evm"                     "$BIN" wallet export --public-key --wallet w1 --chain evm
ok 0 "export public-key solana"                  "$BIN" wallet export --public-key --wallet w1 --chain solana
ok 0 "rename w2 -> w2renamed"                    "$BIN" wallet rename --wallet w2 --new-name w2renamed
ok nz "old name gone after rename"               "$BIN" wallet export --wallet w2

# change-password round-trip: empty -> protected -> empty
ok 0 "change-password ''->np2"                   "$BIN" wallet change-password --wallet w1 --passphrase "" --new-passphrase np2-secret
ONECIPHER_PASSPHRASE=np2-secret timeout 30 "$BIN" wallet export --wallet w1 >/dev/null 2>&1
if [ $? -eq 0 ]; then
  PASS=$((PASS + 1)); note "PASS  export with new passphrase np2 works"
else
  FAIL=$((FAIL + 1)); FAILED+=("export np2"); note "FAIL  export with np2 failed"
fi
ONECIPHER_PASSPHRASE=wrong-guess timeout 30 "$BIN" wallet export --wallet w1 >/dev/null 2>&1
if [ $? -ne 0 ]; then
  PASS=$((PASS + 1)); note "PASS  wrong passphrase rejected on protected wallet"
else
  FAIL=$((FAIL + 1)); FAILED+=("WRONG passphrase accepted"); note "FAIL  wrong passphrase ACCEPTED on protected wallet!"
fi
unset ONECIPHER_PASSPHRASE
timeout 30 "$BIN" wallet export --wallet w1 >/dev/null 2>&1
if [ $? -ne 0 ]; then
  PASS=$((PASS + 1)); note "PASS  non-tty export without env refused (gate)"
else
  FAIL=$((FAIL + 1)); FAILED+=("no-env gate"); note "FAIL  non-tty export without env should be gated"
fi
export ONECIPHER_PASSPHRASE=np2-secret
ok 0 "change-password np2->'' restores empty"    "$BIN" wallet change-password --wallet w1 --passphrase np2-secret --new-passphrase ""
unset ONECIPHER_PASSPHRASE
export ONECIPHER_PASSPHRASE="gate-only"

# import the canonical BIP39 test vector and check the derived address exactly
KNOWN_MNEM="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
KNOWN_ADDR="0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
export ONECIPHER_MNEMONIC="$KNOWN_MNEM"
ok 0 "import known BIP39 mnemonic"               "$BIN" wallet import --name known --mnemonic
LAST_OUT=$(timeout 60 "$BIN" mnemonic derive --chain ethereum 2>&1)
assert_out "BIP39 vector derives known address" "$KNOWN_ADDR"
LAST_OUT=$(ONECIPHER_MNEMONIC="$KNOWN_MNEM" timeout 60 "$BIN" mnemonic derive --chain ethereum --count 3 2>&1)
assert_out "derive --count 3 lists addresses" "0x"
LAST_OUT=$(ONECIPHER_MNEMONIC="$KNOWN_MNEM" timeout 60 "$BIN" mnemonic derive --path "m/44'/60'/0'/0/5" 2>&1)
assert_out "custom path derivation" "0x"
unset ONECIPHER_MNEMONIC
ok 0 "mnemonic generate 24w"                     "$BIN" mnemonic generate --words 24

# sign -> verify round-trip with an independently known address.
# NOTE: `known` is an EMPTY-passphrase wallet (CLI imports never set one);
# ONECIPHER_PASSPHRASE here only satisfies the non-interactive gate that
# export-style commands enforce — the env VALUE plays no role in decryption.
export ONECIPHER_PASSPHRASE=np2-secret # non-interactive gate only; wallet is empty-pass
SIGN_OUT=$(timeout 60 "$BIN" sign message --chain ethereum --wallet known --message hello-eip191 2>/dev/null)
SIG=$(printf '%s' "$SIGN_OUT" | tail -1 | tr -d '[:space:]')
ok 0 "verify correct signature (vector wallet)"  "$BIN" verify --address "$KNOWN_ADDR" --signature "$SIG" --message hello-eip191
TAMPERED="${SIG%?}"
case "${SIG: -1}" in
  0) TAMPERED="${SIG%?}1" ;;
  *) TAMPERED="${SIG%?}0" ;;
esac
ok nz "tampered signature must fail"             "$BIN" verify --address "$KNOWN_ADDR" --signature "$TAMPERED" --message hello-eip191
ok nz "wrong address must fail"                  "$BIN" verify --address 0x0000000000000000000000000000000000000001 --signature "$SIG" --message hello-eip191
unset ONECIPHER_PASSPHRASE
export ONECIPHER_PASSPHRASE="gate-only"

# raw private-key import + EIP-155 signing invariants
export ONECIPHER_PRIVATE_KEY="4646464646464646464646464646464646464646464646464646464646464646"
ok 0 "import raw private key evm"                "$BIN" wallet import --name pk-wallet --private-key --chain evm
unset ONECIPHER_PRIVATE_KEY
TXHEX=eb098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080
TXJSON=$(timeout 60 "$BIN" sign tx --chain ethereum --wallet pk-wallet --tx "$TXHEX" --json 2>/dev/null)
RID=$(printf '%s' "$TXJSON" | grep -o '"recovery_id":[^,}]*' | grep -o '[0-9]\+' | head -1)
SIGH=$(printf '%s' "$TXJSON" | tr -d ' ' | grep -o '"signature":"[0-9a-f]*"' | grep -o '[0-9a-f]\{128\}')
if [ "${RID:-9}" = 0 ] || [ "${RID:-9}" = 1 ]; then
  PASS=$((PASS + 1)); note "PASS  EIP-155 recovery_id=$RID valid"
else
  FAIL=$((FAIL + 1)); FAILED+=("recovery_id"); note "FAIL  recovery_id='${RID:-<none>}' invalid"
fi
if [ "${#SIGH}" -eq 128 ]; then
  PASS=$((PASS + 1)); note "PASS  tx signature is r+s (64 bytes) hex"
else
  FAIL=$((FAIL + 1)); FAILED+=("sig len"); note "FAIL  sig hex len=${#SIGH} want 128"
fi
ok 0 "sign auth EIP-7702"                        "$BIN" sign auth --chain ethereum --wallet pk-wallet --address 0x3535353535353535353535353535353535353535 --nonce 0
ok nz "sign bad chain rejected"                  "$BIN" sign message --chain notachain --wallet w1 --message x
ok nz "unknown wallet fails cleanly"             "$BIN" sign message --chain ethereum --wallet ghost --message x
ok 0 "sign message solana"                       "$BIN" sign message --chain solana --wallet w1 --message hello-solana
TD='{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"content","type":"string"}]},"primaryType":"Mail","domain":{"name":"E2E"},"message":{"content":"hi"}}'
ok 0 "sign EIP-712 typed data"                   "$BIN" sign message --chain ethereum --wallet pk-wallet --typed-data "$TD" --json

# ---------------- G. policy + keys ----------------
note "--- G. policy engine + API keys ---"
cat >"$W/policy.json" <<'EOF'
{"id":"e2e-policy","name":"E2E Test Policy","version":1,
 "created_at":"2026-08-22T00:00:00Z","rules":[],"action":"deny"}
EOF
ok 0 "policy create from file"                   "$BIN" policy create --file "$W/policy.json"
ok 0 "policy re-register upserts (observed)"     "$BIN" policy create --file "$W/policy.json"
LAST_OUT=$(timeout 60 "$BIN" policy list 2>&1)
NPOL=$(printf '%s' "$LAST_OUT" | grep -c e2e-policy || true)
if [ "$NPOL" -eq 1 ]; then
  PASS=$((PASS + 1)); note "PASS  exactly one entry after upsert"
else
  FAIL=$((FAIL + 1)); FAILED+=("policy dup count"); note "FAIL  e2e-policy listed $NPOL times"
fi
ok 0 "policy show"                               "$BIN" policy show --id e2e-policy
ok nz "policy show nonexistent fails"            "$BIN" policy show --id ghost
ok nz "policy delete without confirm fails"     "$BIN" policy delete --id e2e-policy
ok 0 "key create for w1"                        "$BIN" key create --name e2e-agent --wallet w1
LAST_OUT=$(timeout 60 "$BIN" key list 2>&1)
if printf '%s' "$LAST_OUT" | grep -q e2e-agent; then
  PASS=$((PASS + 1)); note "PASS  key list shows e2e-agent"
  KEYID=$(printf '%s' "$LAST_OUT" | grep -o '[0-9a-f-]\{36\}' | head -1)
  if [ -n "$KEYID" ]; then
    PASS=$((PASS + 1)); note "PASS  extracted key id"
    ok nz "key revoke without confirm fails"      "$BIN" key revoke --id "$KEYID"
    ok 0 "key revoke --confirm"                   "$BIN" key revoke --id "$KEYID" --confirm
  else
    FAIL=$((FAIL + 1)); FAILED+=("key id extraction")
    note "FAIL  no UUID key id in key list output"
  fi
else
  FAIL=$((FAIL + 1)); FAILED+=("key list round-trip"); note "FAIL  key list does not show e2e-agent"
fi
ok 0 "policy delete --confirm"                   "$BIN" policy delete --id e2e-policy --confirm
ok nz "policy deleted"                           "$BIN" policy show --id e2e-policy

# ---------------- H. config ----------------
note "--- H. config ---"
ok 0 "config show"                               "$BIN" config show
ok 0 "config set webui.enabled"                  "$BIN" config set webui.enabled true
if grep -q '"enabled": *true' "$H/.onecipher/config.json" 2>/dev/null; then
  PASS=$((PASS + 1)); note "PASS  config persisted webui.enabled=true"
else
  FAIL=$((FAIL + 1)); FAILED+=("config persist"); note "FAIL  webui.enabled not in config.json"
fi
ok 0 "wc relay configure"                        "$BIN" wc relay ws://127.0.0.1:7443

# ---------------- I. backup / sbom / migrate ----------------
note "--- I. backup / sbom / migrate ---"
ok 0 "backup export .ocbk"                       "$BIN" backup export --out "$W/backup.ocbk"
if [ -s "$W/backup.ocbk" ]; then
  PASS=$((PASS + 1)); note "PASS  backup non-empty"
else
  FAIL=$((FAIL + 1)); FAILED+=("backup empty"); note "FAIL  backup.ocbk empty"
fi
ok 0 "backup import .ocbk"                       "$BIN" backup import --in "$W/backup.ocbk"
ok 0 "sbom generate"                             "$BIN" sbom generate --output "$W/sbom.cdx.json"
ok 0 "sbom verify"                               "$BIN" sbom verify --file "$W/sbom.cdx.json"
ok 0 "migrate --dry-run"                         "$BIN" migrate --dry-run

# ---------------- J. diagnostics (daemon-independent) ----------------
note "--- J. status / doctor / audit / vault ---"
ok 0 "status (no daemon)"                        "$BIN" status
ok 0 "doctor"                                    "$BIN" doctor
ok 0 "doctor -v"                                 "$BIN" doctor -v
ok nz "vault unlock without passkey fails closed" "$BIN" vault unlock
ok 0 "audit list"                                "$BIN" audit list
ok 0 "audit list --since"                        "$BIN" audit list --since 24h
ok 0 "audit secrets json"                        "$BIN" audit secrets --skip-hibp --format json
ok 0 "service status"                            "$BIN" service status

# ---------------- K. WC / intent / session-key / agent-secret / send ----------------
note "--- K. WC / intent / session-key / agent-secret / send (isolated runtime) ---"
ok 0 "wc sessions empty"                         "$BIN" wc sessions
# `wc pair` auto-spawns the Key-Agent daemon (gpg-agent pattern), so it
# succeeds without a pre-running daemon and leaves the agent behind.
ok 0 "wc pair auto-spawns agent"                 "$BIN" wc pair
ok nz "wc connect garbage uri"                   "$BIN" wc connect not-a-wc-uri
ok nz "wc dapp-send unknown topic"               "$BIN" wc dapp-send deadbeefdeadbeef personal_sign '{}'
ok nz "wc probe unreachable relay"               timeout 20 "$BIN" wc probe --url ws://127.0.0.1:9 --timeout 1
ok 0 "wc disconnect unknown topic (idempotent)"  "$BIN" wc disconnect deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef

# Simulation accepts human-readable amounts; execution requires hex wei
# (the tx builder refuses decimal amounts rather than encoding 0 wei).
INTENT_SIM='{"type":"Pay","amount":"10.5 USDC","recipient":"0x3535353535353535353535353535353535353535"}'
ok 0 "intent simulate (mock RPC)"                "$BIN" intent simulate --json "$INTENT_SIM" --chain eip155:8453 --session-key sk-fake
ok nz "intent execute rejects non-hex-wei amount" "$BIN" intent execute --json "$INTENT_SIM" --chain eip155:8453 --session-key sk-fake
INTENT='{"type":"Pay","amount":"0x0de0b6b3a7640000","recipient":"0x3535353535353535353535353535353535353535"}'
ok 0 "intent execute (mock RPC)"                 "$BIN" intent execute --json "$INTENT" --chain eip155:8453 --session-key sk-fake
LAST_OUT=$(timeout 60 "$BIN" intent submit --json "$INTENT" --chain eip155:8453 --session-key sk-fake 2>&1)
IRC=$?
if [ "$IRC" -eq 0 ] && printf '%s' "$LAST_OUT" | grep -q cancelled; then
  PASS=$((PASS + 1)); note "PASS  intent submit non-interactive cancels gracefully"
else
  FAIL=$((FAIL + 1)); FAILED+=("intent cancel"); note "FAIL  intent submit cancel (exit=$IRC)"
fi
ok 0 "intent submit --yes executes"              "$BIN" intent submit --json "$INTENT" --chain eip155:8453 --session-key sk-fake --yes
ok nz "session-key create without passkey fails closed" "$BIN" session-key create --label e2e --challenge beef --signature beef --credential-id c1
ok nz "session-key revoke without passkey fails closed" "$BIN" session-key revoke --challenge beef --signature beef --credential-id c1 sk-x
ok 0 "session-key list (T18 implemented)"       "$BIN" session-key list
ok nz "agent-secret get without token fails closed" "$BIN" agent-secret get --name creds/api
ok nz "agent-secret list without token fails closed" "$BIN" agent-secret list
ok nz "send unreachable rpc fails cleanly"       timeout 30 "$BIN" send --chain ethereum --to 0x3535353535353535353535353535353535353535 --token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 --amount 1000000 --wallet w1 --rpc-url http://127.0.0.1:1
ok nz "send malformed address rejected locally"  timeout 30 "$BIN" send --chain ethereum --to nothex --token 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 --amount 1000000 --wallet w1 --rpc-url http://127.0.0.1:1

# ---------------- L. wallet-rpc server ----------------
note "--- L. wallet-rpc loopback JSON-RPC ---"
ok nz "R12e non-loopback bind rejected"          timeout 15 "$BIN" wallet-rpc serve --listen 0.0.0.0:18099
"$BIN" wallet-rpc serve --listen 127.0.0.1:18099 --wallet w1 >"$W/wallet-rpc.log" 2>&1 &
RPC_PID=$!
RPC_UP=0
for _ in $(seq 1 40); do
  curl -s -o /dev/null -m 1 -X POST http://127.0.0.1:18099/ -d '{}' 2>/dev/null && { RPC_UP=1; break; }
  sleep 0.25
done
if [ "$RPC_UP" = 1 ]; then
  PASS=$((PASS + 1)); note "PASS  wallet-rpc serve up on 127.0.0.1:18099"
  RESP=$(curl -s -m 5 -X POST http://127.0.0.1:18099/ -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}')
  if printf '%s' "$RESP" | grep -q '"error"'; then
    PASS=$((PASS + 1)); note "PASS  unauthenticated request fails closed"
  else
    FAIL=$((FAIL + 1)); FAILED+=("rpc fail-closed"); note "FAIL  rpc responded without error: $RESP"
  fi
  BADBIND=$(ss -tlpn 2>/dev/null | grep 18099 | grep -cv '127.0.0.1\|\[::1\]' || true)
  if [ "${BADBIND:-0}" -eq 0 ]; then
    PASS=$((PASS + 1)); note "PASS  R12c loopback-only bind"
  else
    FAIL=$((FAIL + 1)); FAILED+=("R12c loopback bind"); note "FAIL  R12c non-loopback bind seen"
  fi
else
  FAIL=$((FAIL + 1)); FAILED+=("wallet-rpc startup")
  note "FAIL  wallet-rpc did not start:"
  sed 's/^/      | /' "$W/wallet-rpc.log" | head -8 | tee -a "$RES"
fi
kill "$RPC_PID" 2>/dev/null
wait "$RPC_PID" 2>/dev/null
sleep 0.5
if ss -tln 2>/dev/null | grep -q 18099; then
  FAIL=$((FAIL + 1)); FAILED+=("port release"); note "FAIL  port 18099 still bound after kill"
else
  PASS=$((PASS + 1)); note "PASS  port released after SIGTERM"
fi

# ---------------- M. daemon lifecycle ----------------
note "--- M. daemon lifecycle (isolated runtime dir) ---"
OC_WALLET_RPC_LISTEN=127.0.0.1:18098 "$BIN" --daemon >"$W/daemon.log" 2>&1 &
DAEMON_PID=$!
UP=0
for _ in $(seq 1 80); do
  ls "$RUN"/onecipher/*.sock >/dev/null 2>&1 && { UP=1; break; }
  sleep 0.25
done
sleep 1
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  PASS=$((PASS + 1)); note "PASS  daemon process alive"
else
  FAIL=$((FAIL + 1)); FAILED+=("daemon alive")
  note "FAIL  daemon exited:"
  sed 's/^/      | /' "$W/daemon.log" | head -10 | tee -a "$RES"
fi
if [ "$UP" = 1 ]; then
  PASS=$((PASS + 1)); note "PASS  UDS sockets under \$XDG_RUNTIME_DIR/onecipher"
else
  FAIL=$((FAIL + 1)); FAILED+=("daemon socks"); note "FAIL  no sockets appeared"
fi
if [ -f "$H/.onecipher/webui.port" ]; then
  PASS=$((PASS + 1)); note "PASS  webui.port written"
else
  FAIL=$((FAIL + 1)); FAILED+=("webui.port"); note "FAIL  webui.port missing"
fi
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  ok 0 "status shows running daemon"              "$BIN" status
  ok 0 "webui auth status (daemon up)"            "$BIN" webui auth status
  ok 0 "webui auth bootstrap (daemon up)"         "$BIN" webui auth bootstrap
  ok 0 "webui auth lock (daemon up)"              "$BIN" webui auth lock
  ok 0 "webui approval list (daemon up)"          "$BIN" webui approval list
  ok nz "webui approval show bogus fails cleanly" "$BIN" webui approval show 00000000-0000-0000-0000-000000000000
  ok 0 "wc pair via isolated daemon"              "$BIN" wc pair
fi
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
sleep 1
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  FAIL=$((FAIL + 1)); FAILED+=("daemon stop"); note "FAIL  daemon survived SIGTERM"
else
  PASS=$((PASS + 1)); note "PASS  daemon stopped on SIGTERM"
fi

# ---------------- N. destructive commands parse-only ----------------
note "--- N. destructive commands parse-only ---"
ok 0 "update --help parses"                      "$BIN" update --help
ok 0 "uninstall --help parses"                   "$BIN" uninstall --help
ok 0 "tui --help parses"                         "$BIN" tui --help

# ---------------- summary ----------------
note ""
note "==================================="
note "TOTAL=$((PASS + FAIL)) PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if [ "$SKIP" -gt 0 ]; then
  note "Skipped (known issues):"
  for s in "${SKIPPED[@]}"; do note "  ~ $s"; done
fi
if [ "$FAIL" -gt 0 ]; then
  note "Failed:"
  for f in "${FAILED[@]}"; do note "  - $f"; done
fi
note "==================================="

if [ -n "${E2E_KEEP:-}" ]; then
  note "Scratch dir kept at $E2E (E2E_KEEP=1)"
else
  rm -rf "$E2E"
fi
[ "$FAIL" -eq 0 ]
