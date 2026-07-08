#!/usr/bin/env bash
# Launch all 4 hospital nodes locally for a full Secure Sum run.
# Usage:  HOSPITAL_PSK='your-shared-secret' ./run_all.sh
set -euo pipefail

if [ -z "${HOSPITAL_PSK:-}" ]; then
  echo "Set HOSPITAL_PSK first, e.g.:  export HOSPITAL_PSK='shared-secret'" >&2
  exit 1
fi

for i in 1 2 3 4; do
  python3 main.py --node-id "$i" --records "data/hospital$i.txt" --connect-delay 2.0 &
done
wait
