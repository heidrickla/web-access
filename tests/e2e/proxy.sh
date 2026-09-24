#!/usr/bin/env bash
# start|stop|restart a test proxy instance: proxy.sh start 1 → proxy1.toml, data1, log1, pid1
set -uo pipefail
cd "$(dirname "$0")"
n=${2:-1}
bin=$(cd ../.. && pwd)/target/release/web-access-proxy
stop() {
  if [ -f "pid$n" ]; then kill "$(cat "pid$n")" 2>/dev/null; rm -f "pid$n"; sleep 1; fi
}
start() {
  mkdir -p "data$n"
  RUST_LOG=web_access_proxy=debug nohup "$bin" "proxy$n.toml" >> "log$n" 2>&1 &
  echo $! > "pid$n"
  for i in $(seq 1 30); do
    if curl -s -o /dev/null "http://127.0.0.1:$((8442 + n))/"; then echo "proxy $n up"; return 0; fi
    sleep 0.5
  done
  echo "proxy $n did not start"; tail -20 "log$n"; return 1
}
case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
esac
