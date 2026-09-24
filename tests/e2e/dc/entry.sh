#!/bin/sh
# Throwaway Samba AD DC for web-access tests. Realm CORP.TEST, DC dc1.corp.test.
# Fixture passwords come from the environment; nothing here is an estate credential.
set -eu
PRIV=/var/lib/samba/private
if [ ! -f "$PRIV/sam.ldb" ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=CORP.TEST --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$ADMIN_PASS" --use-rfc2307 \
    --option="dns forwarder = 127.0.0.1"

  # A CA and a server certificate for dc1.corp.test, so the proxy validates LDAPS properly.
  mkdir -p "$PRIV/tls/wa" && cd "$PRIV/tls/wa"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=corp.test test CA" \
    -keyout ca.key -out ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=dc1.corp.test" -keyout key.pem -out req.csr
  printf 'subjectAltName=DNS:dc1.corp.test\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -out cert.pem -extfile ext.cnf
  chmod 600 key.pem
  sed -i '/^\[global\]/a \	tls enabled = yes\n\ttls keyfile = /var/lib/samba/private/tls/wa/key.pem\n\ttls certfile = /var/lib/samba/private/tls/wa/cert.pem\n\ttls cafile = /var/lib/samba/private/tls/wa/ca.pem' /etc/samba/smb.conf

  samba-tool domain passwordsettings set --complexity=off --min-pwd-length=8 --max-pwd-age=0
  samba-tool user create jdoe "$USER_PASS" --given-name=Jane --surname=Doe
  samba-tool user create boss "$USER_PASS" --given-name=Admin --surname=Boss
  samba-tool user create asmith "$USER_PASS" --given-name=Alex --surname=Smith
  samba-tool user create gone "$USER_PASS"
  samba-tool user disable gone
  samba-tool user create svc-webaccess "$SVC_PASS"
fi
exec samba -i --debug-stdout
