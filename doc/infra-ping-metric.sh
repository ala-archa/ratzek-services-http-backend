#!/usr/bin/env bash
# node_exporter textfile metric: ICMP packet loss / RTT / reachability of the infra
# devices, pinged FROM the Pi (the collection point). Deployed to
# /usr/local/bin/infra-ping-metric.sh, run by cron */1 behind flock. Mirrors
# doc/webcam-freshness-metric.sh.
#
# Correctness notes (see plan / review):
#  - The whole file is built in a temp file in the SAME dir, then atomically renamed:
#    a crash mid-sweep never leaves a partial .prom (which would silently drop a
#    device's series -> its alerts stop evaluating = false negative).
#  - `ping` exits non-zero on ANY loss, so each call is guarded with `|| true`;
#    likewise the parse pipelines — otherwise `set -euo pipefail` would abort on the
#    first unreachable device, which is exactly what we monitor for.
#  - ratzek_infra_ping_last_check_timestamp lets a stale-alert fire if this stops
#    running (else node_exporter serves the last file forever).
set -euo pipefail

OUT=/var/lib/node_exporter/infra_ping.prom

# name=ip  (names match the mikrotik-exporter device names so dashboards can join).
# Per-hop chain for loss localization: 3.1 (bridge/gateway) -> 2.1 (bridge) -> 1.1 (LTE dish).
TARGETS=(
  "zvonilka-Mikrotik-LHG=10.11.1.1"   # LTE dish (far end)
  "zvonilka-bridge-server=10.11.2.1"  # radio bridge
  "zvonilka-bridge-client=10.11.3.1"  # radio bridge / gateway hop
  "ratzek-switch=10.11.5.2"
  "ratzek-free-inside=10.11.5.3"
  "ratzek-free-outside=10.11.5.4"
  "webcam=10.11.3.4"
)

tmp=$(mktemp -p "$(dirname "$OUT")")
trap 'rm -f "$tmp"' EXIT

{
  echo "# HELP ratzek_infra_ping_loss_ratio Fraction of ICMP packets lost from the Pi to the device (0..1)."
  echo "# TYPE ratzek_infra_ping_loss_ratio gauge"
  echo "# HELP ratzek_infra_ping_rtt_ms Average ICMP round-trip time in ms (0 when unreachable)."
  echo "# TYPE ratzek_infra_ping_rtt_ms gauge"
  echo "# HELP ratzek_infra_ping_up 1 if the device replied to at least one ping, else 0."
  echo "# TYPE ratzek_infra_ping_up gauge"
  for t in "${TARGETS[@]}"; do
    name=${t%%=*}
    ip=${t#*=}
    # `|| true`: ping returns non-zero on loss; we parse its text regardless.
    out=$(ping -c 10 -W 1 -i 0.2 "$ip" 2>&1 || true)
    # loss %: e.g. "10% packet loss" -> 10 . Missing (total failure / no output) -> 100.
    loss=$(printf '%s\n' "$out" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' \
      | grep -oE '[0-9]+(\.[0-9]+)?' | head -1 || true)
    loss=${loss:-100}
    # avg rtt: "rtt min/avg/max/mdev = 12.3/15.6/20.1/2.1 ms" -> field 5 when split on '/'.
    rtt=$(printf '%s\n' "$out" | awk -F'/' '/^(rtt|round-trip)/{print $5; exit}' || true)
    rtt=${rtt:-0}
    loss_ratio=$(awk -v l="$loss" 'BEGIN{printf "%.4f", l/100}')
    up=$(awk -v l="$loss" 'BEGIN{print (l+0 < 100) ? 1 : 0}')
    echo "ratzek_infra_ping_loss_ratio{device=\"$name\",ip=\"$ip\"} $loss_ratio"
    echo "ratzek_infra_ping_rtt_ms{device=\"$name\",ip=\"$ip\"} $rtt"
    echo "ratzek_infra_ping_up{device=\"$name\",ip=\"$ip\"} $up"
  done
  echo "# HELP ratzek_infra_ping_last_check_timestamp Unix time of the last completed ping sweep."
  echo "# TYPE ratzek_infra_ping_last_check_timestamp gauge"
  echo "ratzek_infra_ping_last_check_timestamp $(date +%s)"
} > "$tmp"

chmod 0644 "$tmp"
mv "$tmp" "$OUT"
trap - EXIT
