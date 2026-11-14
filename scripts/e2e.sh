#!/usr/bin/env bash
# End-to-end run of the whole demo against a real local node, through the same CLI a user would type:
# fresh MPC ceremony -> deploy -> anonymous encrypted votes via a relayer -> double vote rejected -> tally.
#
# Usage: npm run test:e2e              (100 voters)
#        E2E_VOTERS=1024 npm run test:e2e   (up to 2^Depth = 1024, the voter tree capacity)
set -euo pipefail

cd "$(dirname "$0")/.."

RPC=http://127.0.0.1:8545
LOG=zk/build/e2e-node.log
export DURATION_SECONDS=600
# Fresh identities in a file of its own, so a manual walkthrough's zk/build/voters.json is left alone.
export VOTER_COUNT=${E2E_VOTERS:-100}
export VOTERS_FILE=zk/build/e2e-voters.json
rm -f "$VOTERS_FILE"

# Milliseconds since the epoch: bash 5 has EPOCHREALTIME, macOS ships bash 3.2, so fall back to perl.
now_ms() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local t=${EPOCHREALTIME/[.,]/}
    echo $((t / 1000))
  else
    perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'
  fi
}

# 850 -> 0.8s (truncated), 12345 -> 12.3s, 245000 -> 4m 05s, 3725000 -> 1h 02m 05s
human() {
  local ms=$1 s=$(($1 / 1000))
  if ((s < 60)); then
    printf '%d.%ds' "$s" $(((ms % 1000) / 100))
  elif ((s < 3600)); then
    printf '%dm %02ds' $((s / 60)) $((s % 60))
  else
    printf '%dh %02dm %02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
  fi
}

TOTAL_START=$(now_ms)
STEP_START=""

end_step() {
  if [[ -n "$STEP_START" ]]; then
    printf '\033[2m⏱  %s\033[0m\n' "$(human $(($(now_ms) - STEP_START)))"
    STEP_START=""
  fi
}

step() {
  end_step
  printf '\n\033[1m▶ %s\033[0m\n' "$*"
  STEP_START=$(now_ms)
}

fail() {
  printf '\033[31m✖ %s (after %s)\033[0m\n' "$*" "$(human $(($(now_ms) - TOTAL_START)))" >&2
  exit 1
}
hh() { npx hardhat --network localhost "$@"; }

if curl -s -o /dev/null "$RPC"; then
  fail "something is already listening on $RPC; stop it first"
fi

# Always a new ceremony: the run proves the whole pipeline from toxic-waste-free keys onwards.
step "🔐 Building zkvote and running the MPC trusted-setup ceremony"
npm run --silent zk:setup

step "⛓️  Starting a local node (log: $LOG)"
npx hardhat node --no-deploy >"$LOG" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do
  curl -s -o /dev/null -X POST "$RPC" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' && break
  sleep 1
done
curl -s -o /dev/null "$RPC" || fail "node did not start, see $LOG"

step "🚀 Deploying the verifier and the vote with $VOTER_COUNT registered voters"
hh deploy --reset

step "🗳️  Every registered voter casts an anonymous encrypted ballot through the relayer"
expected=$(hh task:vote-batch | tee /dev/stderr | tail -1)
expected=${expected#Expected: }

step "🚫 Voting twice with the same identity must fail"
if out=$(hh task:vote --support no --voter 0 2>&1); then
  fail "second vote was accepted"
fi
grep -q NullifierAlreadyUsed <<<"$out" || fail "unexpected error: $out"
echo "rejected: NullifierAlreadyUsed"

step "⏳ Tallying before the deadline must fail"
if out=$(hh task:tally 2>&1); then
  fail "tally was accepted before the deadline"
fi
grep -q VotingStillOpen <<<"$out" || fail "unexpected error: $out"
echo "rejected: VotingStillOpen"

step "📊 Status while voting is open"
hh task:status

step "🔓 Advancing past the deadline and revealing the tally"
hh task:advance-time --seconds "$DURATION_SECONDS"
result=$(hh task:tally | tee /dev/stderr | tail -1)
[[ "$result" == "Result: $expected" ]] || fail "expected 'Result: $expected', got '$result'"

end_step
printf '\n\033[32m✔ e2e passed: %s, total time %s\033[0m\n' "$result" "$(human $(($(now_ms) - TOTAL_START)))"
