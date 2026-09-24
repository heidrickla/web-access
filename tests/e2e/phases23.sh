#!/usr/bin/env bash
# Phase 2 (revocation) and phase 3 (GUI cutover), coordinating Samba and the second proxy.
# Exits nonzero if either phase fails.
set -uo pipefail
cd "$(dirname "$0")"
status=0

rm -f revoke-ready
./run-e2e.sh e2e2 > e2e2.out 2>&1 &
runner=$!
for i in $(seq 1 180); do [ -f revoke-ready ] && break; sleep 1; done
if [ -f revoke-ready ]; then
  docker exec wa-dc samba-tool user disable jdoe >/dev/null && echo "jdoe disabled at $(date +%T)"
else
  echo "FAIL phase 2 never reached the revocation point"
  status=1
fi
wait $runner || status=1
grep -v 'status of 401' e2e2.out
docker exec wa-dc samba-tool user enable jdoe >/dev/null && echo "jdoe re-enabled"

./proxy.sh stop 2; rm -rf data2 log2
./proxy.sh start 2 || status=1
./run-e2e.sh e2e3 > e2e3.out 2>&1 || status=1
grep -v 'status of 401' e2e3.out

if [ "$status" -eq 0 ]; then echo "phases 2 and 3 passed"; else echo "phases 2 and 3 FAILED"; fi
exit "$status"
