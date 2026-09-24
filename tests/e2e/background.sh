#!/usr/bin/env bash
# Run all.sh detached, logging to all.log, with its session id in all.pid. `background.sh stop`
# ends it. The session, not the process group: `timeout` moves all.sh into a group of its own.
cd "$(dirname "$0")"
if [ "${1:-}" = "stop" ]; then
  [ -f all.pid ] && pkill -TERM -s "$(cat all.pid)"
  docker ps -q --filter ancestor=mcr.microsoft.com/playwright:v1.63.0-noble | xargs -r docker stop >/dev/null
  rm -f all.pid; exit 0
fi
export PATH=$HOME/.cargo/bin:$PATH
setsid bash -c 'timeout 7200 ./all.sh > all.log 2>&1; echo "exit=$?" >> all.log; rm -f all.pid' > /dev/null 2>&1 < /dev/null &
echo $! > all.pid
echo "started $(cat all.pid)"
