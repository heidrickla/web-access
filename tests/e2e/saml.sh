#!/usr/bin/env bash
# Single sign-on against a Keycloak identity provider: proxy 5 over HTTPS with [saml], accounts
# from the Samba DC. Needs ./up.sh first. Prints results, never passwords.
set -uo pipefail
cd "$(dirname "$0")"
grep -q '^KC_PASS=' fixtures.env || echo "KC_PASS=Kc-$(openssl rand -hex 10)" >> fixtures.env
set -a; . ./fixtures.env; set +a
KC_IMAGE=quay.io/keycloak/keycloak:26.2.5
IDP=http://127.0.0.1:8180
B=https://localhost:8447
SP=$B/api/saml/metadata
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1: expected $2, got $3"; fail=$((fail+1)); fi
}

# The identity provider, with a realm, a SAML client for proxy 5, and two users: jdoe carrying
# jdoe's SID from the DC, and ghost carrying a SID no directory account has.
docker rm -f wa-idp >/dev/null 2>&1 || true
docker run -d --name wa-idp -p 127.0.0.1:8180:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_PASS" "$KC_IMAGE" start-dev >/dev/null || exit 1
up=0
for i in $(seq 1 90); do
  if curl -sf -o /dev/null "$IDP/realms/master"; then echo "idp up after ${i} tries"; up=1; break; fi
  sleep 2
done
[ "$up" = 1 ] || { echo "idp did not come up"; docker logs --tail 40 wa-idp; exit 1; }

kc() { docker exec -i wa-idp /opt/keycloak/bin/kcadm.sh "$@"; }
docker exec -e KC_PASS wa-idp sh -c '/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password "$KC_PASS"' >/dev/null || exit 1
kc create realms -s realm=corp -s enabled=true >/dev/null || exit 1
kc create clients -r corp -f - >/dev/null <<EOF || exit 1
{
  "clientId": "$SP",
  "protocol": "saml",
  "enabled": true,
  "redirectUris": ["$B/*"],
  "frontchannelLogout": false,
  "attributes": {
    "saml_assertion_consumer_url_post": "$B/api/saml/acs",
    "saml.authnstatement": "true",
    "saml.server.signature": "true",
    "saml.assertion.signature": "true",
    "saml.client.signature": "false",
    "saml.encrypt": "false",
    "saml.signature.algorithm": "RSA_SHA256",
    "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
    "saml_name_id_format": "username"
  },
  "protocolMappers": [{
    "name": "sid",
    "protocol": "saml",
    "protocolMapper": "saml-user-attribute-mapper",
    "config": {
      "user.attribute": "objectSid",
      "attribute.name": "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
      "attribute.nameformat": "URI Reference",
      "aggregate.attrs": "false"
    }
  }]
}
EOF
# Users may carry an attribute the user profile does not declare: the SID.
kc get users/profile -r corp \
  | python3 -c 'import sys,json; p=json.load(sys.stdin); p["unmanagedAttributePolicy"]="ENABLED"; print(json.dumps(p))' \
  | kc update users/profile -r corp -f - >/dev/null || exit 1
JDOE_SID=$(docker exec wa-dc samba-tool user show jdoe --attributes=objectSid | awk '/^objectSid:/{print $2}')
[ -n "$JDOE_SID" ] || { echo "could not read jdoe's SID"; exit 1; }
for u in jdoe ghost; do
  sid=$JDOE_SID
  [ "$u" = ghost ] && sid=S-1-5-21-1111111111-2222222222-3333333333-4444
  kc create users -r corp -s username=$u -s enabled=true -s email=$u@corp.test -s emailVerified=true \
    -s firstName=$u -s lastName=Test -s "attributes.objectSid=[\"$sid\"]" >/dev/null || exit 1
  docker exec -e USER_PASS wa-idp sh -c "/opt/keycloak/bin/kcadm.sh set-password -r corp --username $u --new-password \"\$USER_PASS\"" >/dev/null || exit 1
done
check "jdoe's SID is on the identity provider's account" "$JDOE_SID" \
  "$(kc get users -r corp -q username=jdoe -q exact=true | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["attributes"]["objectSid"][0])')"
curl -sf "$IDP/realms/corp/protocol/saml/descriptor" -o idp-metadata.xml || { echo "no idp metadata"; exit 1; }

# Proxy 5, over HTTPS, with the directory service account's password set by an administrator.
if [ -f pid5 ]; then kill "$(cat pid5)" 2>/dev/null; rm -f pid5; sleep 1; fi
rm -rf data5 log5 boss5.jar; mkdir -p data5
RUST_LOG=web_access_proxy=debug nohup ../../target/release/web-access-proxy proxy5.toml >> log5 2>&1 &
echo $! > pid5
started=0
for i in $(seq 1 30); do
  if curl -sk -o /dev/null "$B/"; then echo "proxy 5 up"; started=1; break; fi
  sleep 0.5
done
[ "$started" = 1 ] || { echo "proxy 5 did not start"; tail -20 log5; exit 1; }
O=(-k -H "Origin: $B" -H "Content-Type: application/json")
code() { curl -s -o /tmp/wa-body -w '%{http_code}' "$@"; }
check "boss signs in with a password" 200 "$(code -c boss5.jar "${O[@]}" -d "{\"username\":\"boss\",\"password\":\"$USER_PASS\"}" "$B/api/login")"
INSTANCE=$(curl -sk -D - -o /dev/null -b boss5.jar "$B/api/me" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-data-instance"{print $2}')
check "service account password set" true "$(curl -s -b boss5.jar "${O[@]}" -H "X-Data-Instance: $INSTANCE" -d "{\"password\":\"$SVC_PASS\"}" "$B/api/admin/settings/directory-password" | python3 -c 'import sys,json;print(str(json.load(sys.stdin).get("verified")).lower())')"

check "the sign-in page is told single sign-on is offered" true "$(curl -sk "$B/api/sign-in-methods" | python3 -c 'import sys,json;print(str(json.load(sys.stdin)["sso"]).lower())')"
check "metadata is served" 200 "$(code -k "$B/api/saml/metadata")"
check "metadata names the proxy" 1 "$(grep -c "entityID=\"$SP\"" /tmp/wa-body)"
check "start redirects to the identity provider" 303 "$(code -k "$B/api/saml/start")"
check "the redirect goes to the realm's endpoint" "$IDP/realms/corp/protocol/saml" \
  "$(curl -sk -o /dev/null -w '%{redirect_url}' "$B/api/saml/start" | cut -d'?' -f1)"

echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] || exit 1
./run-e2e.sh sso
