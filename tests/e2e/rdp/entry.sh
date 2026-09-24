#!/bin/sh
# Throwaway xrdp target for web-access tests. The fixture user's password comes from the environment.
set -eu
echo "ops:$OPS_PASS" | chpasswd
mkdir -p /var/run/dbus && dbus-daemon --system --fork || true
/usr/sbin/xrdp-sesman
exec /usr/sbin/xrdp --nodaemon
