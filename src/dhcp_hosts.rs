//! Manage DHCP reservations for unlimited clients via a generated dnsmasq
//! `dhcp-hostsfile`, instead of OMAPI/omshell (unreliable on this box — an internal
//! omshell threading race made connects fail ~90% of the time).
//!
//! The backend owns one hostsfile, regenerates it from the unlimited-clients store
//! (the single source of truth) on every CRUD change and on startup reconcile,
//! validates the config (`dnsmasq --test`), then reloads dnsmasq (SIGHUP). [`render`]
//! emits `MAC,IP,name` lines; [`apply`] writes + validates + reloads with rollback.
//!
//! Two optional [`DhcpReservations`] knobs: `active_unit` (skip the reload when the
//! target daemon is deliberately down, leaving the change pending for the next
//! reconcile) and `reload_log` (scrape the daemon log after reload — dnsmasq applies
//! a hostsfile silently on SIGHUP, so `dnsmasq --test` can't catch a rejected
//! reservation).

use anyhow::{anyhow, bail, Context, Result};
use slog_scope::{error, info, warn};

use crate::config::DhcpReservations;
use crate::unlimited_clients::UnlimitedClient;

/// Timeout for the external validate/reload commands. A hung command must
/// never block the async worker indefinitely.
const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Outcome of [`apply`]: whether the DHCP daemon actually had to be reloaded.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    Changed,
    Unchanged,
    /// The configured `active_unit` was inactive, so the reload was skipped (the
    /// change is left pending for the next reconcile). See `DhcpReservations::active_unit`.
    SkippedInactive,
}

/// Render the dnsmasq hostsfile content from the store. Deterministic (sorted by
/// `name`) so an unchanged store yields a byte-identical file — that lets [`apply`]
/// skip the reload when nothing changed.
///
/// Defense in depth: although `name`/`mac`/`ip` are validated on the write path
/// (`is_valid_name`, `normalize_mac`, `UnlimitedClient::validate`),
/// `UnlimitedClientsStore::load` does NOT re-validate YAML read from disk. A
/// hand-edited or corrupted store could carry values that inject extra fields/lines
/// into the hostsfile, so we re-check each record here and skip (with a `warn!`)
/// anything that does not pass, emitting only safe records verbatim.
pub fn render(clients: &[UnlimitedClient]) -> String {
    let mut sorted: Vec<&UnlimitedClient> = clients
        .iter()
        .filter(|c| {
            // dnsmasq `dhcp-host` is IPv4-only in the `MAC,IP,name` form.
            let safe = crate::unlimited_clients::is_valid_name(&c.name)
                && crate::unlimited_clients::normalize_mac(&c.mac).as_deref()
                    == Some(c.mac.as_str())
                && c.ip.parse::<std::net::Ipv4Addr>().is_ok();
            if !safe {
                warn!(
                    "dhcp render: skipping unsafe client record (name={:?}, mac={:?}, ip={:?})",
                    c.name, c.mac, c.ip
                );
            }
            safe
        })
        .collect();
    sorted.sort_by_key(|c| c.name.as_str());

    // dnsmasq `--dhcp-hostsfile` lines: `MAC,IP,name` (no `dhcp-host=` prefix), one
    // per client. Deterministic (sorted) so an unchanged store yields a byte-identical
    // file and [`apply`] can skip the reload.
    let mut out = String::from(
        "# Managed by ala-archa-http-backend. DO NOT EDIT.\n\
         # Regenerated from the unlimited-clients store; read via dhcp-hostsfile.\n",
    );
    for c in sorted {
        out.push_str(&format!("{},{},{}\n", c.mac, c.ip, c.name));
    }
    out
}

/// Write `content` to the reservation file, validate the config, then reload the
/// daemon. No-ops ([`Applied::Unchanged`]) when the file already matches `content`.
///
/// Three outcomes: `Unchanged`, `Changed` (written + reloaded), and
/// `SkippedInactive` (a configured `active_unit` was down — the change is left
/// pending, nothing written or reloaded).
///
/// # Errors
/// Returns an error (with the file always rolled back to its prior content) when:
/// validation fails; the reload command fails; or, under `reload_log`, the daemon
/// log reports a rejected reservation after the reload. Error messages flag the
/// rare case where the rollback itself failed and the file is left broken.
pub async fn apply(cfg: &DhcpReservations, content: &str) -> Result<Applied> {
    let path = &cfg.include_path;
    // Read the current hostsfile carefully: a missing file is a legitimate "no
    // previous content" case, but any other error (e.g. EACCES) must NOT be
    // masked as "file absent" — otherwise restore would `remove_file` and wipe
    // a hostsfile we simply failed to read.
    let previous = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read reservations hostsfile {:?}", path));
        }
    };

    if previous.as_deref() == Some(content) {
        return Ok(Applied::Unchanged);
    }

    // active_unit guard: never (re)start a daemon that is deliberately stopped.
    // Leave the change pending — the next reconcile heals it once the daemon is back.
    if let Some(unit) = &cfg.active_unit {
        if !unit_is_active(unit).await {
            warn!(
                "dhcp reservations: reload target {unit:?} is inactive — skipping apply \
                 (pending until next reconcile)"
            );
            return Ok(Applied::SkippedInactive);
        }
    }

    write_file(path, content)
        .with_context(|| format!("failed to write reservations hostsfile {:?}", path))?;

    if let Err(err) = run_cmd(&cfg.validate_command).await {
        match restore(path, previous.as_deref()) {
            Ok(()) => bail!(
                "dhcp reservations validation ({:?}) failed; reverted hostsfile: {err}",
                cfg.validate_command
            ),
            Err(re) => {
                error!("hostsfile restore after failed validation FAILED: {re}");
                bail!(
                    "dhcp reservations validation ({:?}) failed AND hostsfile restore failed — \
                     hostsfile LEFT BROKEN: {err} (restore error: {re})",
                    cfg.validate_command
                );
            }
        }
    }

    // For the dnsmasq post-reload scrape: note where the log ends BEFORE the reload
    // so we only read lines the reload itself emits. `Some` iff a scrape is configured.
    let scrape_from = cfg.reload_log.as_ref().map(|rl| log_len(&rl.file));

    if let Err(err) = run_cmd(&cfg.reload_command).await {
        return Err(rollback(
            cfg,
            path,
            previous.as_deref(),
            format!("dhcp reload ({:?}) failed: {err}", cfg.reload_command),
        )
        .await);
    }

    // dnsmasq applies the hostsfile silently on SIGHUP — `validate` (dnsmasq --test)
    // can't catch a bad reservation line. Scrape the log the reload just wrote; a
    // rejected reservation (e.g. duplicate IP) means the daemon is now serving a
    // reservation set that doesn't match our file, so roll fully back.
    if let (Some(rl), Some(from)) = (&cfg.reload_log, scrape_from) {
        if let Some(errline) = scrape_reload_log(rl, path, from).await {
            return Err(rollback(
                cfg,
                path,
                previous.as_deref(),
                format!("dnsmasq rejected a reservation ({errline:?})"),
            )
            .await);
        }
    }

    info!("dhcp reservations applied ({} bytes)", content.len());
    Ok(Applied::Changed)
}

/// Restore the reservation file to `previous` and re-run the reload to bring the
/// daemon back onto the known-good file. Only called on a failure path — always
/// returns an error describing the combined (restore, recovery-reload) outcome,
/// prefixed by `cause`. A failed recovery reload / restore is additionally `error!`d
/// (the network may be left degraded).
async fn rollback(
    cfg: &DhcpReservations,
    path: &std::path::Path,
    previous: Option<&str>,
    cause: String,
) -> anyhow::Error {
    let restored = restore(path, previous);
    let recovery = run_cmd(&cfg.reload_command).await;
    if let Err(ref re) = recovery {
        error!(
            "dhcp reservations recovery reload after rollback FAILED — daemon may be DOWN: {re}"
        );
    }
    match (restored, recovery) {
        (Ok(()), Ok(())) => anyhow!("{cause}; reverted the file and reloaded onto it"),
        (Ok(()), Err(re)) => anyhow!(
            "{cause}; reverted the file but the recovery reload FAILED — daemon may be DOWN: {re}"
        ),
        (Err(se), _) => {
            error!("dhcp reservations file restore after rollback FAILED: {se}");
            anyhow!("{cause}; AND the file restore FAILED — file LEFT BROKEN: {se}")
        }
    }
}

/// Current length of the log file in bytes (0 if absent/unreadable) — the scrape
/// start offset captured before a reload.
fn log_len(file: &std::path::Path) -> u64 {
    std::fs::metadata(file).map(|m| m.len()).unwrap_or(0)
}

/// `systemctl is-active --quiet <unit>`, bounded by [`CMD_TIMEOUT`]. A spawn error
/// OR a timeout counts as inactive (fail-safe: skip the reload rather than risk
/// reviving a deliberately-stopped daemon, and never hang `apply()` on a wedged
/// systemd — this runs under the reservation mutation lock).
async fn unit_is_active(unit: &str) -> bool {
    let fut = tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .kill_on_drop(true)
        .status();
    matches!(tokio::time::timeout(CMD_TIMEOUT, fut).await, Ok(Ok(s)) if s.success())
}

/// Poll interval for [`scrape_reload_log`].
const SCRAPE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Poll the dnsmasq log (from byte `start`) for the outcome of a hostsfile reload.
/// Returns `Some(line)` for a hostsfile-referencing error line (→ rollback), else
/// `None` (clean). Each pass scans the WHOLE new region and lets an error win over
/// the success marker regardless of their order. `None` also covers two fail-open
/// cases — the marker never appearing within the bounded poll, and the log being
/// unreadable — because the reload already succeeded and a false rollback of a good
/// reservation is worse than a missed error. An unreadable log is `error!`d LOUDLY
/// (the safety net is blind); a merely-missing marker only `warn!`s.
async fn scrape_reload_log(
    rl: &crate::config::ReloadLog,
    hostsfile: &std::path::Path,
    start: u64,
) -> Option<String> {
    let path_str = hostsfile.to_string_lossy();
    let timeout_secs = rl.timeout_secs.max(1);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut read_failed = false;
    loop {
        match read_from(&rl.file, start) {
            Ok(text) => {
                let mut saw_success = false;
                for line in text.lines() {
                    if !line.contains(path_str.as_ref()) {
                        continue;
                    }
                    if line.contains(&rl.error_contains) {
                        return Some(line.to_string());
                    }
                    if line.contains(&rl.success_contains) {
                        saw_success = true;
                    }
                }
                if saw_success {
                    return None;
                }
            }
            Err(e) => {
                if !read_failed {
                    read_failed = true;
                    error!(
                        "dnsmasq reload scrape: cannot read log {:?}: {e} — rejected \
                         reservations will NOT be detected (safety net blind)",
                        rl.file
                    );
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            if !read_failed {
                warn!(
                    "dnsmasq reload scrape: no success/error marker for {:?} within {}s — \
                     assuming clean",
                    hostsfile, timeout_secs
                );
            }
            return None;
        }
        tokio::time::sleep(SCRAPE_POLL_INTERVAL).await;
    }
}

/// Read `file` from byte offset `start` to EOF. `Err` only on a real open/read
/// failure (missing file, EACCES) — which lets the scraper log loudly when its log
/// source is unreadable. A rotation shorter than `start` yields `Ok("")` (seeking
/// past EOF is not an error on Linux), i.e. "no new lines yet".
fn read_from(file: &std::path::Path, start: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(file)?;
    f.seek(std::io::SeekFrom::Start(start))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

fn write_file(path: &std::path::Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {:?}", parent))?;
    }
    // Atomic replace: temp file in the same dir + rename. The PID suffix keeps
    // concurrent writers from clobbering a shared temp file before the rename.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, content).with_context(|| format!("failed to write {:?}", tmp))?;
    std::fs::rename(&tmp, path).with_context(|| format!("failed to rename into {:?}", path))?;
    Ok(())
}

/// Restore the hostsfile to its previous content (or delete it if there was
/// none). Returns the result so the caller can report when a rollback itself
/// failed (i.e. the hostsfile is left in a broken state).
fn restore(path: &std::path::Path, previous: Option<&str>) -> Result<()> {
    match previous {
        Some(prev) => write_file(path, prev),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            // Nothing to remove is a successful restore-to-absent.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("failed to remove {:?}", path)),
        },
    }
}

async fn run_cmd(cmd: &str) -> Result<()> {
    // `tokio::process` does not block the async worker, and `kill_on_drop`
    // ensures a timed-out command is SIGKILLed rather than left orphaned.
    let fut = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .kill_on_drop(true)
        .output();
    let out = match tokio::time::timeout(CMD_TIMEOUT, fut).await {
        Ok(res) => res.with_context(|| format!("failed to spawn {cmd:?}"))?,
        Err(_) => bail!("command {cmd:?} timed out after {CMD_TIMEOUT:?} (killed)"),
    };
    if !out.status.success() {
        bail!(
            "{cmd:?} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn client(name: &str, mac: &str, ip: &str) -> UnlimitedClient {
        UnlimitedClient {
            name: name.into(),
            mac: mac.into(),
            ip: ip.into(),
            comment: None,
            ..Default::default()
        }
    }

    #[test]
    fn render_dnsmasq_hostsfile_format() {
        let clients = vec![
            client("bravo", "aa:bb:cc:dd:ee:02", "10.11.5.3"),
            client("alpha", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        ];
        let out = render(&clients);
        assert!(out.starts_with("# Managed by ala-archa-http-backend"));
        // `MAC,IP,name`, no `dhcp-host=` prefix, no ISC `host {`; sorted by name.
        assert!(out.contains("aa:bb:cc:dd:ee:01,10.11.5.2,alpha\n"));
        assert!(out.contains("aa:bb:cc:dd:ee:02,10.11.5.3,bravo\n"));
        assert!(!out.contains("dhcp-host="));
        assert!(!out.contains("host "));
        assert!(out.find(",alpha").unwrap() < out.find(",bravo").unwrap());
    }

    #[test]
    fn render_is_deterministic() {
        let a = vec![
            client("b", "aa:bb:cc:dd:ee:02", "10.11.5.3"),
            client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        ];
        let b = vec![
            client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
            client("b", "aa:bb:cc:dd:ee:02", "10.11.5.3"),
        ];
        assert_eq!(render(&a), render(&b));
    }

    fn cfg(path: PathBuf, validate: &str, reload: &str) -> DhcpReservations {
        DhcpReservations {
            include_path: path,
            validate_command: validate.into(),
            reload_command: reload.into(),
            active_unit: None,
            reload_log: None,
        }
    }

    #[tokio::test]
    async fn apply_skips_when_unchanged() {
        let dir = std::env::temp_dir().join(format!("dh-skip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        // marker files prove the commands did/didn't run
        let ran = dir.join("ran");
        let content = render(&[client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        std::fs::write(&path, &content).unwrap();

        let c = cfg(path.clone(), &format!("touch {}", ran.display()), "true");
        assert_eq!(apply(&c, &content).await.unwrap(), Applied::Unchanged);
        assert!(
            !ran.exists(),
            "validate must not run when content is unchanged"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_restores_previous_on_validation_failure() {
        let dir = std::env::temp_dir().join(format!("dh-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        let old = render(&[client("old", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        std::fs::write(&path, &old).unwrap();

        // validate always fails -> the bad content must be reverted to `old`
        let c = cfg(path.clone(), "false", "true");
        let new = render(&[client("new", "aa:bb:cc:dd:ee:02", "10.11.5.3")]);
        assert!(apply(&c, &new).await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_restores_previous_on_reload_failure() {
        let dir = std::env::temp_dir().join(format!("dh-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        let old = render(&[client("old", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        std::fs::write(&path, &old).unwrap();

        // validate passes but reload fails -> the new content must be rolled back.
        let c = cfg(path.clone(), "true", "false");
        let new = render(&[client("new", "aa:bb:cc:dd:ee:02", "10.11.5.3")]);
        assert!(apply(&c, &new).await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_removes_file_when_no_previous_and_validation_fails() {
        let dir = std::env::temp_dir().join(format!("dh-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        // No pre-existing hostsfile; validation fails -> the freshly written file
        // must be removed, leaving no hostsfile behind.
        let c = cfg(path.clone(), "false", "true");
        let new = render(&[client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        assert!(apply(&c, &new).await.is_err());
        assert!(
            !path.exists(),
            "hostsfile must not exist after rollback of a new file"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_changes_when_validation_passes() {
        let dir = std::env::temp_dir().join(format!("dh-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        let c = cfg(path.clone(), "true", "true");
        let new = render(&[client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        assert_eq!(apply(&c, &new).await.unwrap(), Applied::Changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), new);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn dnsmasq_reservation(name: &str, mac: &str, ip: &str) -> String {
        render(&[client(name, mac, ip)])
    }

    #[tokio::test]
    async fn apply_skips_reload_when_active_unit_inactive() {
        // active_unit guard: an inactive `active_unit` must skip validate+reload entirely
        // and leave the on-disk hostsfile untouched (change pending for reconcile).
        let dir = std::env::temp_dir().join(format!("dh-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.conf");
        let ran = dir.join("ran");
        std::fs::write(&path, "OLD HOSTSFILE\n").unwrap();

        let mut c = cfg(
            path.clone(),
            &format!("touch {}", ran.display()),
            &format!("touch {}", ran.display()),
        );
        c.active_unit = Some("ratzek-nonexistent-guard-unit.service".to_string());

        assert_eq!(
            apply(&c, "NEW CONTENT\n").await.unwrap(),
            Applied::SkippedInactive
        );
        assert!(
            !ran.exists(),
            "validate/reload must not run under the guard"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "OLD HOSTSFILE\n",
            "hostsfile must be untouched when the reload target is inactive"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_rolls_back_when_dnsmasq_logs_reservation_error() {
        // dnsmasq reload succeeds (exit 0) but logs a rejected reservation -> the
        // scrape must detect it and roll the hostsfile fully back.
        let dir = std::env::temp_dir().join(format!("dh-scrape-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let log = dir.join("dnsmasq.log");
        let old = dnsmasq_reservation("old", "aa:bb:cc:dd:ee:01", "10.11.5.2");
        std::fs::write(&path, &old).unwrap();
        std::fs::write(&log, "old startup line\n").unwrap();

        // reload "succeeds" but appends a real dnsmasq error line for THIS hostsfile.
        let reload = format!(
            "printf 'dnsmasq[1]: duplicate dhcp-host IP address 10.11.5.3 at line 2 of {}\\n' >> {}",
            path.display(),
            log.display()
        );
        let mut c = cfg(path.clone(), "true", &reload);
        c.reload_log = Some(crate::config::ReloadLog {
            file: log.clone(),
            success_contains: "read".into(),
            error_contains: "at line".into(),
            timeout_secs: 2,
        });
        let new = dnsmasq_reservation("new", "aa:bb:cc:dd:ee:02", "10.11.5.3");

        assert!(
            apply(&c, &new).await.is_err(),
            "a logged reservation error must fail the apply"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            old,
            "hostsfile must be rolled back after a scrape error"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_keeps_change_when_scrape_sees_success_marker() {
        let dir = std::env::temp_dir().join(format!("dh-scrape-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let log = dir.join("dnsmasq.log");
        std::fs::write(
            &path,
            dnsmasq_reservation("old", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        )
        .unwrap();
        std::fs::write(&log, "old startup line\n").unwrap();

        // reload logs the clean "read <hostsfile>" completion marker, no error.
        let reload = format!(
            "printf 'dnsmasq-dhcp[1]: read {}\\n' >> {}",
            path.display(),
            log.display()
        );
        let mut c = cfg(path.clone(), "true", &reload);
        c.reload_log = Some(crate::config::ReloadLog {
            file: log.clone(),
            success_contains: "read".into(),
            error_contains: "at line".into(),
            timeout_secs: 2,
        });
        let new = dnsmasq_reservation("new", "aa:bb:cc:dd:ee:02", "10.11.5.3");

        assert_eq!(apply(&c, &new).await.unwrap(), Applied::Changed);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            new,
            "hostsfile kept on a clean reload"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn dnsmasq_scrape_cfg(path: PathBuf, log: PathBuf, reload: &str) -> DhcpReservations {
        let mut c = cfg(path, "true", reload);
        c.reload_log = Some(crate::config::ReloadLog {
            file: log,
            success_contains: "read".into(),
            error_contains: "at line".into(),
            timeout_secs: 1,
        });
        c
    }

    #[tokio::test]
    async fn apply_is_clean_when_scrape_times_out_without_marker() {
        // Fail-open: reload succeeds but logs nothing about the hostsfile -> the
        // change is kept (a false rollback of a good reservation is worse). This is
        // the path where a bad reservation could slip through, so pin it.
        let dir = std::env::temp_dir().join(format!("dh-scrape-to-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let log = dir.join("dnsmasq.log");
        std::fs::write(
            &path,
            dnsmasq_reservation("old", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        )
        .unwrap();
        std::fs::write(&log, "old line\n").unwrap();

        let reload = format!("printf 'unrelated dnsmasq chatter\\n' >> {}", log.display());
        let c = dnsmasq_scrape_cfg(path.clone(), log, &reload);
        let new = dnsmasq_reservation("new", "aa:bb:cc:dd:ee:02", "10.11.5.3");

        assert_eq!(apply(&c, &new).await.unwrap(), Applied::Changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), new);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_ignores_error_line_before_the_reload_offset() {
        // An OLD error line (with our hostsfile path) already in the log, from a
        // previous reload, must NOT trigger a rollback — the scrape reads only bytes
        // after the pre-reload offset. Guards the offset mechanism itself.
        let dir = std::env::temp_dir().join(format!("dh-scrape-off-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let log = dir.join("dnsmasq.log");
        std::fs::write(
            &path,
            dnsmasq_reservation("old", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        )
        .unwrap();
        // Stale error referencing OUR hostsfile, written before this apply.
        std::fs::write(
            &log,
            format!(
                "dnsmasq[1]: bad DHCP host name at line 3 of {}\n",
                path.display()
            ),
        )
        .unwrap();

        let reload = format!(
            "printf 'dnsmasq-dhcp[1]: read {}\\n' >> {}",
            path.display(),
            log.display()
        );
        let c = dnsmasq_scrape_cfg(path.clone(), log, &reload);
        let new = dnsmasq_reservation("new", "aa:bb:cc:dd:ee:02", "10.11.5.3");

        assert_eq!(
            apply(&c, &new).await.unwrap(),
            Applied::Changed,
            "a stale error before the offset must not roll back"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), new);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn apply_ignores_reload_error_for_a_different_hostsfile() {
        // dnsmasq logs into a shared log; an error for ANOTHER file must not roll our
        // change back. The path filter is load-bearing.
        let dir = std::env::temp_dir().join(format!("dh-scrape-other-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        let log = dir.join("dnsmasq.log");
        std::fs::write(
            &path,
            dnsmasq_reservation("old", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        )
        .unwrap();
        std::fs::write(&log, "old line\n").unwrap();

        // error for a different file + success marker for OURS in the same reload.
        let reload = format!(
            "printf 'dnsmasq[1]: bad DHCP host name at line 1 of /etc/other-hosts\\n\
             dnsmasq-dhcp[1]: read {}\\n' >> {}",
            path.display(),
            log.display()
        );
        let c = dnsmasq_scrape_cfg(path.clone(), log, &reload);
        let new = dnsmasq_reservation("new", "aa:bb:cc:dd:ee:02", "10.11.5.3");

        assert_eq!(apply(&c, &new).await.unwrap(), Applied::Changed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), new);
        std::fs::remove_dir_all(&dir).ok();
    }
}
