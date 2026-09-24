#!/usr/bin/env bash
# Bring up the web-access test fixtures: a Samba AD DC and an xrdp target.
# Fixture passwords are generated here, kept in fixtures.env (0600), and never printed.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f fixtures.env ]; then
  umask 077
  {
    echo "ADMIN_PASS=Adm-$(openssl rand -hex 10)"
    echo "USER_PASS=Usr-$(openssl rand -hex 10)"
    echo "SVC_PASS=Svc-$(openssl rand -hex 10)"
    echo "OPS_PASS=Ops-$(openssl rand -hex 10)"
    echo "RECOVERY_PASS=Rec-$(openssl rand -hex 10)"
  } > fixtures.env
fi
grep -q '^LOCAL_PASS=' fixtures.env || echo "LOCAL_PASS=Loc-$(openssl rand -hex 10)" >> fixtures.env

docker build -q -t wa-test-dc dc >/dev/null
docker build -q -t wa-test-rdp rdp >/dev/null

docker rm -f wa-dc wa-rdp >/dev/null 2>&1 || true
docker run -d --name wa-dc --hostname dc1 --privileged --env-file fixtures.env \
  -p 127.0.0.1:1636:636 wa-test-dc >/dev/null
docker run -d --name wa-rdp --hostname rdp1 --env-file fixtures.env \
  -p 127.0.0.1:13389:3389 wa-test-rdp >/dev/null

grep -q 'dc1.corp.test' /etc/hosts || echo '127.0.0.1 dc1.corp.test' | sudo tee -a /etc/hosts >/dev/null

# Each fixture must answer; a CA file left by an earlier run proves nothing about this one.
rm -f dc-ca.pem
dc=0
for i in $(seq 1 90); do
  if timeout 3 openssl s_client -connect 127.0.0.1:1636 -servername dc1.corp.test </dev/null >/dev/null 2>&1; then
    docker cp wa-dc:/var/lib/samba/private/tls/wa/ca.pem ./dc-ca.pem
    echo "dc up after ${i} tries"
    dc=1
    break
  fi
  sleep 2
done
[ "$dc" = 1 ] && [ -f dc-ca.pem ] || { echo "dc did not come up"; docker logs --tail 40 wa-dc; exit 1; }

rdp=0
for i in $(seq 1 30); do
  if timeout 2 bash -c 'echo > /dev/tcp/127.0.0.1/13389' 2>/dev/null; then echo "rdp up"; rdp=1; break; fi
  sleep 1
done
[ "$rdp" = 1 ] || { echo "rdp did not come up"; docker logs --tail 40 wa-rdp; exit 1; }
