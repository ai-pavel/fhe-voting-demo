#!/usr/bin/env bash
# End-to-end run of the whole demo against a real local node, through the same CLI a user would type:
# MPC ceremony keys -> deploy -> anonymous encrypted votes via a relayer -> double vote rejected -> tally.
set -euo pipefail

cd "$(dirname "$0")/.."

RPC=http://127.0.0.1:8545
LOG=$(mktemp -t e2e-node.XXXXXX)
export DURATION_SECONDS=60

step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }
hh() { npx hardhat --network localhost "$@"; }

if curl -s -o /dev/null "$RPC"; then
  fail "something is already listening on $RPC; stop it first"
fi

step "Building zkvote and running the MPC ceremony if keys are missing"
npm run --silent zk:ensure

step "Starting a local node (log: $LOG)"
npx hardhat node --no-deploy >"$LOG" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do
  curl -s -o /dev/null -X POST "$RPC" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' && break
  sleep 1
done
curl -s -o /dev/null "$RPC" || fail "node did not start, see $LOG"

step "Deploying the verifier and the vote"
hh deploy --reset

step "Casting anonymous encrypted ballots through the relayer"
hh task:vote --support yes --voter 0
hh task:vote --support no --voter 1
hh task:vote --support yes --voter 2

step "Voting twice with the same identity must fail"
if out=$(hh task:vote --support no --voter 2 2>&1); then
  fail "second vote was accepted"
fi
grep -q NullifierAlreadyUsed <<<"$out" || fail "unexpected error: $out"
echo "rejected: NullifierAlreadyUsed"

step "Tallying before the deadline must fail"
if out=$(hh task:tally 2>&1); then
  fail "tally was accepted before the deadline"
fi
grep -q VotingStillOpen <<<"$out" || fail "unexpected error: $out"
echo "rejected: VotingStillOpen"

step "Status while voting is open"
hh task:status

step "Advancing past the deadline and revealing the tally"
hh task:advance-time --seconds "$DURATION_SECONDS"
result=$(hh task:tally | tee /dev/stderr | tail -1)
[[ "$result" == "Result: yes=2 no=1" ]] || fail "expected 'Result: yes=2 no=1', got '$result'"

printf '\n\033[32m✔ e2e passed: %s\033[0m\n' "$result"
