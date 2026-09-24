#!/usr/bin/env bash
# A proxy with no directory: a local account created on the command line signs in and administers.
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./fixtures.env; set +a
bin=$(cd ../.. && pwd)/target/release/web-access-proxy
B=http://127.0.0.1:8445
O=(-H "Origin: $B" -H "Content-Type: application/json")
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1: expected $2, got $3"; fail=$((fail+1)); fi; }
code() { curl -s -o /tmp/wa-body -w '%{http_code}' "$@"; }

./proxy.sh stop 3; rm -rf data3 log3
mkdir -p data3
printf '%s\n%s\n' "$LOCAL_PASS" "$LOCAL_PASS" | "$bin" local-account proxy3.toml devtest --admin >/dev/null
./proxy.sh start 3 >/dev/null

check "wrong local password refused" 401 "$(code "${O[@]}" -d '{"username":"devtest","password":"not-the-password"}' "$B/api/login")"
check "local account signs in" 200 "$(code -c local.jar "${O[@]}" -d "{\"username\":\"devtest\",\"password\":\"$LOCAL_PASS\"}" "$B/api/login")"
check "local account is an administrator" 200 "$(code -b local.jar "$B/api/admin/users")"
check "a directory username is refused without a directory" 401 "$(code "${O[@]}" -d '{"username":"jdoe","password":"anything-at-all"}' "$B/api/login")"
sid=$(curl -s -b local.jar "${O[@]}" -d '{"name":"xrdp-01","host":"127.0.0.1","port":13389}' "$B/api/admin/servers" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
uid=$(curl -s -b local.jar "$B/api/admin/users" | python3 -c 'import sys,json;print(json.load(sys.stdin)["users"][0]["id"])')
check "local account assigns itself a server" 200 "$(code -X PUT -b local.jar "${O[@]}" -d "{\"server_ids\":[$sid]}" "$B/api/admin/users/$uid/servers")"
check "local account gets a connect ticket" 64 "$(curl -s -b local.jar "${O[@]}" -d "{\"server\":$sid}" "$B/api/connect" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["ticket"]))')"
./proxy.sh stop 3
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
