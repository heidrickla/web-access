#!/usr/bin/env bash
# Run one browser test phase in the Playwright container, against proxies on the host network.
#   run-e2e.sh e2e1
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p shots
IMAGE=mcr.microsoft.com/playwright:v1.63.0-noble
if [ ! -d browser/node_modules/playwright ]; then
  docker run --rm -v "$PWD/browser:/e2e" -w /e2e "$IMAGE" bash -c 'npm init -y >/dev/null && npm i -s playwright@1.63.0 >/dev/null' || exit 1
fi
docker run --rm --network host --ipc=host \
  -v "$PWD/browser:/e2e" -v "$PWD:/work" -w /e2e "$IMAGE" node "$1.mjs"
