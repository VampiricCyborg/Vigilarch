#!/usr/bin/env bash
#
# demo.sh — the whole Vigilarch thesis in one run, using only what v1 ships.
#
#   1  honest partition       vigil-sim   — two nodes meet, O0 sealed by U
#   2  equivocation           vigil-sim   — the fork caught, quarantined, sibling never sealed
#   3  export                 vigil-ledger — export_pack over step 1's resulting store
#   4  verify (honest)        vigil-verify — independent recheck: exit 0, SEALED
#   5  verify (tampered T2)   vigil-verify — re-signed genesis: exit 1, BrokenLink, named key
#   6  the runnable server    vigil-node   — a real HTTP node: capture one record, read it back
#
# There is no cross-process networking between node instances anywhere here: that
# needs vigil-sync, which is a v2 item and is not built. Steps 1–5 simulate the
# meeting on one machine; step 6 is the real server, shown on its own and making
# no sealed claim.
#
# Requirements: a Rust toolchain (cargo) and curl. Run from anywhere:
#
#     ./demo.sh
#
set -uo pipefail
cd "$(dirname "$0")"

command -v cargo >/dev/null || { echo "demo.sh needs a Rust toolchain (cargo) on PATH" >&2; exit 1; }
command -v curl  >/dev/null || { echo "demo.sh needs curl on PATH (step 6)" >&2; exit 1; }

# The org identity every pack in this repo is labelled with — the spec/03 §6.1
# worked-example org key, seed 0x11..11. vigil-sim prints it too; it is pinned
# here so step 5 can be run against a static fixture.
ORG_PUBKEY=d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
SEED=1
PORT=8799

# A stable, git-ignored working directory, so the transcript is byte-reproducible
# run to run (mktemp paths would leak into the output).
DEMO_DIR="target/demo"
mkdir -p "$DEMO_DIR"
NODE_PID=""
cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null
}
trap cleanup EXIT

rule() { printf '\n════════════════════════════════════════════════════════════════════\n%s\n════════════════════════════════════════════════════════════════════\n\n' "$1"; }

FAILED=0
expect_exit() { # expect_exit <want> <got> <label>
  if [ "$2" -ne "$1" ]; then
    printf '\n>>> DEMO FAILURE: %s exited %s, expected %s\n' "$3" "$2" "$1" >&2
    FAILED=1
  fi
}

echo "Building release binaries (vigil-sim, vigil-verify, vigil-node)…"
cargo build --release -q -p vigil-sim -p vigil-verify -p vigil-node
SIM=./target/release/vigil-sim
VERIFY=./target/release/vigil-verify
NODE=./target/release/vigil-node

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 1 — honest partition: a meeting is the proof of time"
cat <<'EOF'
Two nodes, no network. Node A writes observation O0 while disconnected. A and B
meet: B co-signs A's current chain head as attestation U, and A embeds U in its
next entry. From B's ledger alone, bracket(O0) is SEALED by U — proof O0 existed
no later than the meeting — with the unwitnessed window left honestly open below
to genesis, because nothing proves O0 did not exist earlier.
  spec/02 §5.2 (sealing theorem), §8.1 (upper bound only).
EOF
"$SIM" --scenario minimal --seed "$SEED"
expect_exit 0 $? "step 1 (vigil-sim minimal)"

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 2 — equivocation: two stories from one key, caught"
cat <<'EOF'
The same author signs two irreconcilable entries at seq 1 and lets an honest
witness see only one of them. Once a verifier ends up holding both, verify_chain
convicts the author and detect_forks emits exactly one self-verifying ForkProof.
Quarantine then changes only what that key's *own* attestations buy going
forward: an honest witness's earlier attestation of the branch it actually saw
is not retroactively undone, and the withheld sibling entry is never sealed.
  spec/02 §6 (fork detection), §6.4–6.5 (quarantine semantics); ADR-0003.
EOF
"$SIM" --scenario equivocation --seed "$SEED"
expect_exit 0 $? "step 2 (vigil-sim equivocation)"

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 3 — export: package step 1's result as portable evidence"
cat <<'EOF'
vigil-ledger's export_pack — the exact path testdata/packs/ fixtures come from,
which CI regenerates and byte-diffs — run over node B's store from step 1. The
pack is the minimal object set the claim follows from: O0 and the attestation U.
Reading it back needs no database, no node, and no network.
  spec/03 §2–§4.
EOF
PACK="$DEMO_DIR/honest.vgl"
if ! "$SIM" --scenario minimal --seed "$SEED" --export-pack "$PACK" > "$DEMO_DIR/step3.log" 2>&1; then
  cat "$DEMO_DIR/step3.log" >&2
  echo ">>> DEMO FAILURE: step 3 export failed" >&2
  exit 1
fi
grep -E '^(pack|verify):' "$DEMO_DIR/step3.log"

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 4 — verify the honest pack independently"
cat <<'EOF'
vigil-verify links only vigil-core. It re-parses the pack, re-checks every
signature, rebuilds the chain and the attestation DAG, and recomputes the
bracket from scratch — a second implementation of the verification path, not a
call back into the code that built the pack. No database, no node.
Expected: exit 0, SEALED, witness depth 1, upper bound U.
  spec/03 §5.
EOF
"$VERIFY" "$PACK" "$ORG_PUBKEY"
V_HONEST=$?
echo "exit: $V_HONEST  (0 = every claim reproduced from the pack's own evidence)"
expect_exit 0 "$V_HONEST" "step 4 (vigil-verify honest)"

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 5 — verify a tampered pack: the detection has to fire"
cat <<'EOF'
testdata/packs/t2-resigned-genesis.vgl replaces the genesis entry with a validly
re-signed one (hlc counter 1, not 0). Every carried object self-checks — the
signature is real — but A@1.prev no longer matches the held predecessor, so the
hash chain does not close. This is an attributable finding against a specific
key, not an ambiguous error.
Expected: exit 1, chain VIOLATED, BrokenLink at seq 1, attributed to the author.
A "success" here would mean the tamper detection had broken.
  spec/03 §6.5 T2; spec/04 (threat model).
EOF
"$VERIFY" testdata/packs/t2-resigned-genesis.vgl "$ORG_PUBKEY"
V_T2=$?
echo "exit: $V_T2  (1 = tamper detected)"
expect_exit 1 "$V_T2" "step 5 (vigil-verify tampered T2)"

# ─────────────────────────────────────────────────────────────────────────────
rule "STEP 6 — the runnable server  (this step makes NO sealed claim)"
cat <<'EOF'
Everything above is a simulated meeting. This step is different in kind: it
starts vigil-node as a real HTTP server a person could actually run, POSTs one
observation, and reads its provenance back. A lone node has met no one, so it
holds no attestations — and it correctly reports the record UNWITNESSED, with
the window open in BOTH directions. That honest "I cannot vouch for when this
happened" is the correct output, not a gap: cross-node sealing needs vigil-sync
(v2). The chain itself still verifies — internal integrity and sealing in time
are different properties.
EOF

"$NODE" --addr "127.0.0.1:$PORT" > "$DEMO_DIR/node.log" 2>&1 &
NODE_PID=$!

ready=0
for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.2
done
if [ "$ready" -ne 1 ]; then
  cat "$DEMO_DIR/node.log" >&2
  echo ">>> DEMO FAILURE: vigil-node did not come up on port $PORT" >&2
  exit 1
fi

echo "\$ curl -s http://127.0.0.1:$PORT/health"
curl -s "http://127.0.0.1:$PORT/health"; echo

echo
echo "\$ curl -s -XPOST --data 'shoring on grid B4 is out of plumb' http://127.0.0.1:$PORT/obs"
OBS_JSON=$(curl -s -XPOST --data 'shoring on grid B4 is out of plumb' "http://127.0.0.1:$PORT/obs")
echo "$OBS_JSON"
OBS_ID=$(printf '%s' "$OBS_JSON" | sed -n 's/.*"id": *"\([0-9a-f]\{64\}\)".*/\1/p')

echo
echo "\$ curl -s http://127.0.0.1:$PORT/obs/$OBS_ID/provenance"
curl -s "http://127.0.0.1:$PORT/obs/$OBS_ID/provenance"; echo

kill "$NODE_PID" 2>/dev/null
wait "$NODE_PID" 2>/dev/null
NODE_PID=""

# ─────────────────────────────────────────────────────────────────────────────
rule "DEMO COMPLETE"
if [ "$FAILED" -eq 0 ]; then
  cat <<'EOF'
Steps 1, 2, 4 passed; step 5 correctly FAILED verification (exit 1); step 6
served a live node that honestly reported its lone record as unwitnessed.

A record written offline by an untrusted actor was shown to a third party with a
defensible, independently checkable claim about when it was created — and a
backdated one was caught and attributed — with no central authority, no
consensus, and no assumption of connectivity.
EOF
  exit 0
else
  echo "One or more steps did not behave as expected — see the DEMO FAILURE lines above." >&2
  exit 1
fi
