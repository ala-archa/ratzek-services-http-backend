#!/bin/sh
# Canonical copy of /usr/local/bin/ipset-save-atomic.sh on ratzek (the Pi).
# Deployed BY HAND: scp here -> /usr/local/bin/, chmod 0755. Called from root's crontab in place of
# `netfilter-persistent save`.
#
# Why this exists. The stock plugin (/usr/share/netfilter-persistent/plugins.d/10-ipset) does:
#
#     ipset save > /etc/iptables/ipsets
#
# a truncating redirect with no temp file and no fsync, and root's crontab ran it EVERY MINUTE.
# That was survivable while reboots were rare accidents. It stops being survivable now that the
# hardware watchdog makes a hard reset a routine, designed-for outcome: a reset landing inside the
# write window leaves the file truncated, and on the next boot `ipset restore` runs under `set -e`
# and fails, so the captive-portal sets come up empty or missing while 17 iptables rules still
# reference them. The portal would be in an undefined state exactly when nobody is watching.
#
# Compare src/persistent_state.rs::atomic_write, which does this correctly for the backend's own
# state and documents the same reasoning.
set -eu

# cron runs with PATH=/usr/bin:/bin, and ipset lives in /usr/sbin. Without this the script dies
# with 127 "ipset: not found" on every tick — and because the crontab entry redirects to
# /dev/null, it dies silently, leaving ipset persistence entirely broken while looking healthy.
# (Observed exactly that on the first deploy.) The stock plugin sets PATH for the same reason.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DEST=/etc/iptables/ipsets
TMP="$DEST.tmp.$$"

trap 'rm -f "$TMP"' EXIT

# Failures go to syslog, not just stderr: cron discards stderr here, and a persistence job that
# fails quietly is worse than no job at all.
fail() {
    logger -t ipset-save-atomic -p daemon.err "$1"
    echo "ipset-save-atomic: $1" >&2
    exit 1
}

ipset save > "$TMP" || fail "ipset save failed, keeping previous $DEST"

# A truncated save is worse than a stale one, so refuse to publish anything that does not look like
# a complete dump. `create` is the first thing ipset emits for every set; no `create` line means we
# caught a partial write or an ipset error that `set -e` did not surface.
[ -s "$TMP" ] || fail "empty dump, keeping previous $DEST"
grep -q '^create ' "$TMP" || fail "no create lines, keeping previous $DEST"

chmod 0640 "$TMP"

# Flush the temp file before it becomes the destination: rename is atomic, but renaming a file whose
# contents are still only in page cache just moves the corruption window.
sync
mv -f "$TMP" "$DEST"
sync
