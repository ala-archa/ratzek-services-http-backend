#!/usr/bin/env bash
#
# Build the aarch64 release binary on THIS (x86_64) host via Docker and ship it to
# production — replacing the old "git pull + cargo build on the Raspberry Pi" flow.
#
# Why: the Pi has 4 slow ARM cores; this box has many fast x86 cores. We cross-
# compile in a container (Rust + aarch64 cross-gcc inside the image, glibc 2.31 to
# match the Pi) and scp the finished binary. The Pi never compiles.
#
# Usage:  scripts/deploy.sh [ssh-host]      (default host: ratzek)
# Prereqs: docker (no rustup needed — it can't run on Guix anyway).
set -euo pipefail

IMAGE=ratzek-cross-aarch64
TARGET=aarch64-unknown-linux-gnu
BIN=ala-archa-http-backend
PROFILE=deploy                       # faster build than `release` (see Cargo.toml)
MAX_GLIBC=2.31                       # production (Debian 11) glibc ceiling
REMOTE="${1:-ratzek}"
REMOTE_BIN=/usr/bin/ratzek-services-http-backend
SERVICE=ratzek-services-http-backend

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
SSH=(ssh -o LogLevel=ERROR "$REMOTE")

# 1) Build the cross image once (cached afterwards).
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo ">> building cross image $IMAGE (one-time)…"
  docker build -t "$IMAGE" -f scripts/cross-aarch64.Dockerfile scripts
fi

# 2) Cross-compile. Run as the host user with a repo-local CARGO_HOME so the
#    target/ and cache stay host-owned (no root-owned droppings). target/ and the
#    cache persist on the host -> incremental rebuilds are fast.
echo ">> cross-compiling $BIN for $TARGET (profile: $PROFILE)…"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e CARGO_HOME=/src/.cross-cargo \
  -v "$REPO":/src -w /src \
  "$IMAGE" \
  cargo build --profile "$PROFILE" --target "$TARGET"

BINARY="target/$TARGET/$PROFILE/$BIN"
[ -x "$BINARY" ] || { echo "!! binary not produced: $BINARY" >&2; exit 1; }

# 3) Verify the binary won't out-require the Pi's glibc.
NEED="$(docker run --rm -v "$REPO":/src -w /src "$IMAGE" \
  bash -c "aarch64-linux-gnu-objdump -T '$BINARY' | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1" \
  | sed 's/GLIBC_//')"
echo ">> max glibc required: ${NEED:-none} (ceiling $MAX_GLIBC)"
if [ -n "$NEED" ] && [ "$(printf '%s\n%s\n' "$MAX_GLIBC" "$NEED" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
  echo "!! binary needs glibc $NEED > $MAX_GLIBC — would not run on the Pi. Aborting." >&2
  exit 1
fi
echo ">> size: $(du -h "$BINARY" | cut -f1)"

# 4) Ship: scp to a temp path, then atomically swap + restart on prod (with backup).
echo ">> shipping to $REMOTE…"
scp -o LogLevel=ERROR "$BINARY" "$REMOTE:/tmp/$BIN.new"
"${SSH[@]}" "set -e
  D=\$(date +%Y%m%d-%H%M%S)
  cp -a $REMOTE_BIN $REMOTE_BIN.bak-\$D
  install -m 0755 /tmp/$BIN.new $REMOTE_BIN && rm -f /tmp/$BIN.new
  echo \"deployed: \$($REMOTE_BIN --version)\"
  systemctl restart $SERVICE
  sleep 5
  echo \"backend: \$(systemctl is-active $SERVICE)  (backup: $REMOTE_BIN.bak-\$D)\""
echo ">> done."
