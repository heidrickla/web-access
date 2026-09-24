#!/usr/bin/env bash
# Everything, in order, against fresh fixtures. Exits nonzero if any stage fails.
set -uo pipefail
cd "$(dirname "$0")"
status=0
stage() { echo "== $1"; shift; "$@" || { echo "== FAILED"; status=1; }; }

stage "build" bash -c 'cd ../.. && cargo build --offline --release -q'
stage "fixtures" ./up.sh
./proxy.sh stop 1; ./proxy.sh stop 2; rm -rf data1 log1
stage "proxy 1" ./proxy.sh start 1
stage "api" ./smoke.sh
stage "local accounts" ./smoke-local.sh
stage "browser 1" bash -c './run-e2e.sh e2e1 2>&1 | grep -v "status of 401"; exit ${PIPESTATUS[0]}'
stage "browser 2 and 3" ./phases23.sh
./proxy.sh stop 1; ./proxy.sh stop 2
stage "guards" ./mutate.sh

if [ "$status" -eq 0 ]; then echo "ALL STAGES PASSED"; else echo "SOME STAGES FAILED"; fi
exit "$status"
