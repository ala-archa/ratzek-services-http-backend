#!/usr/bin/env bash
# node_exporter textfile metric: mtime of the newest NON-EMPTY webcam snapshot.
# (The webcam cron writes a file every 5 min even on failure, but a failed grab is
# 0 bytes — so we track the newest non-empty file to detect a hung/dead camera.)
set -euo pipefail
DIR=/var/www/webcam_archive
OUT=/var/lib/node_exporter/webcam.prom
ts=$(find "$DIR" -maxdepth 1 -name "*.jpg" -size +0c -printf "%T@\n" 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
tmp=$(mktemp)
{
  echo "# HELP ratzek_webcam_last_image_timestamp Unix mtime of the newest non-empty webcam snapshot (0=none)."
  echo "# TYPE ratzek_webcam_last_image_timestamp gauge"
  echo "ratzek_webcam_last_image_timestamp ${ts:-0}"
} > "$tmp"
chmod 0644 "$tmp"; mv "$tmp" "$OUT"
