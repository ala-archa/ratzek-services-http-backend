#!/usr/bin/python3
"""Root-SSD write canary for the portal host.

Deployed by hand to /usr/local/bin/disk-canary.py, run by disk-canary.service
(see doc/disk-canary.service). This file in ratzek-services-http-backend/doc/ is
the source of truth; the Ansible roles for this host are stale.

Why it exists: the USB-SSD (VIA Labs 2109:0716 on the `uas` driver) stalls
spontaneously. In that state the kernel keeps forwarding traffic and PID 1 keeps
petting the hardware watchdog, so RuntimeWatchdogSec never fires, while every
process that touches the disk wedges in D-state: journald, Prometheus, the
backend, dnsmasq, sshd logins. Night of 2026-09-13: 12 hours down until a manual
power-cycle, the OpenVPN client renegotiating happily the whole time.

How it works: every INTERVAL seconds write + fsync a heartbeat file on the root
filesystem, then send WATCHDOG=1 to systemd. A stalled or failing write means no
ping; after WatchdogSec systemd marks the unit failed and its
FailureAction=reboot-immediate issues reboot(2) straight from PID 1 without
touching the disk. One long-lived process, no exec per iteration: nothing here
has to be read from the dead disk once we are running.

The heartbeat timestamp is also exported through the node_exporter textfile
collector (ratzek_disk_canary_timestamp_seconds) so a dead canary is visible.
"""

import os
import socket
import sys
import time

HEARTBEAT_DIR = "/var/lib/disk-canary"
HEARTBEAT = os.path.join(HEARTBEAT_DIR, "heartbeat")
METRIC = "/var/lib/node_exporter/disk-canary.prom"
INTERVAL = float(os.environ.get("CANARY_INTERVAL", "10"))


def notify(state: str) -> None:
    """Best-effort sd_notify(3). Silence is the failure signal, never an exception."""
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return
    if path.startswith("@"):
        path = "\0" + path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(state.encode(), path)
    except OSError as err:
        print(f"sd_notify failed: {err}", file=sys.stderr, flush=True)


def write_synced(path: str, payload: str) -> None:
    """Write payload to path.tmp, fsync it, rename over path. Raises on any I/O error."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, payload.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)


def main() -> None:
    os.makedirs(HEARTBEAT_DIR, exist_ok=True)
    while True:
        now = int(time.time())
        try:
            write_synced(HEARTBEAT, f"{now}\n")
            # The metric is best-effort: its directory may not exist on a fresh host
            # and a broken exporter path must not stop the watchdog pings.
            try:
                write_synced(
                    METRIC,
                    "# HELP ratzek_disk_canary_timestamp_seconds Unix time of the last "
                    "successful fsync'ed heartbeat write on the root SSD.\n"
                    "# TYPE ratzek_disk_canary_timestamp_seconds gauge\n"
                    f"ratzek_disk_canary_timestamp_seconds {now}\n",
                )
            except OSError as err:
                print(f"metric write failed: {err}", file=sys.stderr, flush=True)
        except OSError as err:
            # EIO / ENOSPC / read-only remount: the disk is not healthy, withhold the ping.
            print(f"heartbeat write failed: {err}", file=sys.stderr, flush=True)
        else:
            notify("WATCHDOG=1")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
