#!/usr/bin/env bash
# Run all.sh detached, logging to all.log, with its pid in all.pid. `background.sh stop` ends it.
cd "$(dirname "$0")"
if [ "${1:-}" = "stop" ]; then
  [ -f all.pid ] && kill -- -"$(cat all.pid)" 2>/dev/null; rm -f all.pid; exit 0
fi
export PATH=$HOME/.cargo/bin:$PATH
setsid bash -c 'timeout 7200 ./all.sh > all.log 2>&1; echo "exit=$?" >> all.log; rm -f all.pid' > /dev/null 2>&1 < /dev/null &
echo $! > all.pid
echo "started $(cat all.pid)"
