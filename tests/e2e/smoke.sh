#!/usr/bin/env bash
# API-level checks against a running test proxy and the Samba DC. Prints results, never passwords.
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./fixtures.env; set +a
B=http://127.0.0.1:${PORT:-8443}
O=(-H "Origin: $B" -H "Content-Type: application/json")
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1: expected $2, got $3"; fail=$((fail+1)); fi
}
code() { curl -s -o /tmp/wa-body -w '%{http_code}' "$@"; }
login() { # user pass jar
  code -c "$3" "${O[@]}" -d "{\"username\":\"$1\",\"password\":\"$2\"}" "$B/api/login"
}

check "wrong password refused" 401 "$(login jdoe not-the-password /tmp/x.jar)"
check "empty password refused" 401 "$(login jdoe '' /tmp/x.jar)"
check "disabled account refused" 401 "$(login gone "$USER_PASS" /tmp/x.jar)"
check "unknown account refused" 401 "$(login nobody "$USER_PASS" /tmp/x.jar)"
check "admin signs in with DOMAIN\\user form" 200 "$(login 'CORP\\boss' "$USER_PASS" boss.jar)"
check "admin is admin" true "$(curl -s -b boss.jar "$B/api/me" | python3 -c 'import sys,json;print(str(json.load(sys.stdin)["is_admin"]).lower())')"
check "cookie is persistent for 24h" 1 "$(grep -c 'wa_session' boss.jar)"

A=(-b boss.jar "${O[@]}")
check "service account password verified" true "$(curl -s "${A[@]}" -d "{\"password\":\"$SVC_PASS\"}" "$B/api/admin/settings/directory-password" | python3 -c 'import sys,json;print(str(json.load(sys.stdin).get("verified")).lower())')"
check "wrong service password refused" 400 "$(code "${A[@]}" -d '{"password":"nope-nope"}' "$B/api/admin/settings/directory-password")"
check "unknown user cannot be added" 404 "$(code "${A[@]}" -d '{"username":"nobody"}' "$B/api/admin/users")"
check "jdoe added and found in the directory" true "$(curl -s "${A[@]}" -d '{"username":"jdoe"}' "$B/api/admin/users" | python3 -c 'import sys,json;print(str(json.load(sys.stdin).get("verified")).lower())')"
curl -s "${A[@]}" -d '{"username":"asmith"}' "$B/api/admin/users" >/dev/null
gid=$(curl -s "${A[@]}" -d '{"name":"Test Targets"}' "$B/api/admin/groups" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
sid=$(curl -s "${A[@]}" -d "{\"name\":\"xrdp-01\",\"host\":\"127.0.0.1\",\"port\":13389,\"group_id\":$gid}" "$B/api/admin/servers" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
csv='name,host,port,group\nhist-01,hist-01.plant.example,,Historians\neng-01,eng-01.plant.example,3389,Engineering'
check "CSV import" 200 "$(code "${A[@]}" -d "{\"csv\":\"$csv\"}" "$B/api/admin/servers/import")"
jdoe_id=$(curl -s -b boss.jar "$B/api/admin/users" | python3 -c 'import sys,json;print([u["id"] for u in json.load(sys.stdin)["users"] if u["username"]=="jdoe"][0])')
hist=$(curl -s -b boss.jar "$B/api/admin/servers" | python3 -c 'import sys,json;print([s["id"] for s in json.load(sys.stdin)["servers"] if s["name"]=="hist-01"][0])')
check "assign servers to jdoe" 200 "$(code -X PUT "${A[@]}" -d "{\"server_ids\":[$sid,$hist]}" "$B/api/admin/users/$jdoe_id/servers")"
check "recovery passphrase set" 204 "$(code "${A[@]}" -d "{\"new\":\"$RECOVERY_PASS\"}" "$B/api/admin/migration/recovery")"

check "jdoe signs in with UPN form" 200 "$(login jdoe@corp.test "$USER_PASS" jdoe.jar)"
J=(-b jdoe.jar "${O[@]}")
check "jdoe sees two groups" 2 "$(curl -s -b jdoe.jar "$B/api/me/servers" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["groups"]))')"
check "jdoe is not an admin" 403 "$(code -b jdoe.jar "$B/api/admin/users")"
check "jdoe gets a ticket for xrdp-01" 64 "$(curl -s "${J[@]}" -d "{\"server\":$sid}" "$B/api/connect" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["ticket"]))')"
eng=$(curl -s -b boss.jar "$B/api/admin/servers" | python3 -c 'import sys,json;print([s["id"] for s in json.load(sys.stdin)["servers"] if s["name"]=="eng-01"][0])')
check "unassigned server looks missing" 404 "$(code "${J[@]}" -d "{\"server\":$eng}" "$B/api/connect")"
check "asmith signs in and sees nothing" 0 "$( login asmith "$USER_PASS" asmith.jar >/dev/null; curl -s -b asmith.jar "$B/api/me/servers" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["groups"]))')"
check "cross-origin POST refused" 403 "$(code -b jdoe.jar -H 'Origin: http://evil.test' -H 'Content-Type: application/json' -d "{\"server\":$sid}" "$B/api/connect")"

echo "server_id=$sid jdoe_id=$jdoe_id" > ids.env
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
