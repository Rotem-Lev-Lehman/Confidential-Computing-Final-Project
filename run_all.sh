#!/usr/bin/env bash
# Launch all 4 hospital nodes locally for a full run of the system:
# Phase 1 (secure sum) -> Phase 2 (share reduction) -> Phase 3 (garbled circuit)
# -> the quarantine alert list, printed by node 2.
#
#   ./run_all.sh                     # full-strength run (2048-bit OT)
#   ./run_all.sh --ot-group 1024     # ~5x faster, weaker group, for a quick demo
#   ./run_all.sh --seed 7            # a different demo scenario
#   ./run_all.sh --show-shares       # also print each node's raw share
#
# There is NO shared secret.  Each node authenticates with its own Ed25519
# identity key from keys/node<N>.key; the matching public keys live in
# config.json.  demo_setup.py generates both, plus the synthetic records.
#
# DEMO NOTE: all four nodes print to this one console, so the transcript shows
# more than any single hospital would see.  That is deliberate -- it is how we
# demonstrate the protocol.  In a real deployment the four nodes run on four
# machines under four organizations and no such combined view exists.
# See THREAT_MODEL.md.
set -euo pipefail

cd "$(dirname "$0")"

SEED=2024
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --seed) SEED="$2"; shift 2 ;;
    *)      EXTRA+=("$1"); shift ;;
  esac
done

# 1. Identity keys, matching public keys in config.json, synthetic records.
#    Skipped if a previous run already produced them.
if [ ! -d keys ] || [ ! -d data ]; then
  echo "== preparing demo (keys + config + records) =="
  uv run python src/demo_setup.py --seed "$SEED"
else
  echo "== reusing existing keys/ and data/ (delete them to regenerate) =="
fi

# 2. Run the four nodes as four separate processes.
echo
echo "== launching 4 hospital nodes =="
pids=()
for i in 1 2 3 4; do
  uv run python src/main.py \
      --node-id "$i" \
      --records "data/hospital$i.txt" \
      --connect-delay 2.0 \
      "${EXTRA[@]+"${EXTRA[@]}"}" &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=$?
done
exit "$status"
