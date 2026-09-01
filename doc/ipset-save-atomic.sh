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

DEST=/etc/iptables/ipsets
TMP="$DEST.tmp.$$"

trap 'rm -f "$TMP"' EXIT

ipset save > "$TMP"

# A truncated save is worse than a stale one, so refuse to publish anything that does not look like
# a complete dump. `create` is the first thing ipset emits for every set; no `create` line means we
# caught a partial write or an ipset error that `set -e` did not surface.
[ -s "$TMP" ] || { echo "ipset-save-atomic: empty dump, keeping previous $DEST" >&2; exit 1; }
grep -q '^create ' "$TMP" || { echo "ipset-save-atomic: no create lines, keeping previous $DEST" >&2; exit 1; }

chmod 0640 "$TMP"

# Flush the temp file before it becomes the destination: rename is atomic, but renaming a file whose
# contents are still only in page cache just moves the corruption window.
sync
mv -f "$TMP" "$DEST"
sync
