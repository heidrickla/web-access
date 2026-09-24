#!/usr/bin/env bash
# Phase 2 (revocation) and phase 3 (GUI cutover), coordinating Samba and the second proxy.
set -uo pipefail
cd "$(dirname "$0")"
rm -f revoke-ready
./run-e2e.sh e2e2 > e2e2.out 2>&1 &
runner=$!
for i in $(seq 1 180); do [ -f revoke-ready ] && break; sleep 1; done
if [ -f revoke-ready ]; then
  docker exec wa-dc samba-tool user disable jdoe >/dev/null && echo "jdoe disabled at $(date +%T)"
fi
wait $runner
grep -v 'status of 401' e2e2.out
docker exec wa-dc samba-tool user enable jdoe >/dev/null && echo "jdoe re-enabled"
# Revocation also unbound nothing: the account is the same, so jdoe signs in again in phase 3.

./proxy.sh stop 2; rm -rf data2 log2
./proxy.sh start 2
./run-e2e.sh e2e3 2>&1 | grep -v 'status of 401'
