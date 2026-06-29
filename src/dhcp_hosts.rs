//! Manage dhcpd `host` reservations for unlimited clients via a generated
//! include file, instead of OMAPI/omshell (which is unreliable on this box — an
//! internal omshell threading race makes connects fail ~90% of the time, and the
//! OMAPI model can't represent one MAC with two reservations).
//!
//! The backend owns one include file (referenced by `include "...";` in
//! `dhcpd.conf`), regenerates it from the unlimited-clients store on every CRUD
//! change and on startup reconcile, validates the config with `dhcpd -t`, then
//! restarts dhcpd. The store is the single source of truth; the file is derived.

use anyhow::{bail, Context, Result};
use slog_scope::{error, info, warn};

use crate::config::DhcpReservations;
use crate::unlimited_clients::UnlimitedClient;

/// Timeout for the external dhcpd validate/reload commands. A hung command must
/// never block the async worker indefinitely.
const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Outcome of [`apply`]: whether dhcpd actually had to be restarted.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    Changed,
    Unchanged,
}

/// Render the include-file content from the store. Deterministic (sorted by
/// `name`) so an unchanged store yields a byte-identical file — that lets
/// [`apply`] skip the dhcpd restart when nothing changed.
///
/// Defense in depth: although `name`/`mac`/`ip` are validated on the write path
/// (`is_valid_name`, `normalize_mac`, `UnlimitedClient::validate`),
/// `UnlimitedClientsStore::load` does NOT re-validate YAML read from disk. A
/// hand-edited or corrupted store could therefore carry values that would inject
/// arbitrary directives into the dhcpd include. So we re-check each record here
/// and skip (with a `warn!`) anything that does not pass, emitting only safe
/// records verbatim. Note dhcpd allows several `host` blocks to share a
/// `hardware ethernet` (one device, two reservations on different subnets) —
/// this renderer supports that natively.
pub fn render(clients: &[UnlimitedClient]) -> String {
    let mut sorted: Vec<&UnlimitedClient> = clients
        .iter()
        .filter(|c| {
            let safe = crate::unlimited_clients::is_valid_name(&c.name)
                && crate::unlimited_clients::normalize_mac(&c.mac).as_deref()
                    == Some(c.mac.as_str())
                && c.ip.parse::<std::net::IpAddr>().is_ok();
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

    let mut out = String::from(
        "# Managed by ala-archa-http-backend. DO NOT EDIT.\n\
         # Regenerated from the unlimited-clients store on every CRUD change and\n\
         # on startup. Referenced from dhcpd.conf via `include`.\n",
    );
    for c in sorted {
        out.push_str(&format!(
            "host {} {{\n  hardware ethernet {};\n  fixed-address {};\n}}\n",
            c.name, c.mac, c.ip
        ));
    }
    out
}

/// Write `content` to the include file, validate the dhcpd config, then restart
/// dhcpd. No-ops (no restart) when the file already matches `content`. On a
/// validation or restart failure the previous file content is restored so dhcpd
/// is never left referencing a broken include.
pub async fn apply(cfg: &DhcpReservations, content: &str) -> Result<Applied> {
    let path = &cfg.include_path;
    // Read the current include carefully: a missing file is a legitimate "no
    // previous content" case, but any other error (e.g. EACCES) must NOT be
    // masked as "file absent" — otherwise restore would `remove_file` and wipe
    // an include we simply failed to read.
    let previous = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read dhcp include {:?}", path));
        }
    };

    if previous.as_deref() == Some(content) {
        return Ok(Applied::Unchanged);
    }

    write_file(path, content)
        .with_context(|| format!("failed to write dhcp include {:?}", path))?;

    if let Err(err) = run_cmd(&cfg.validate_command).await {
        match restore(path, previous.as_deref()) {
            Ok(()) => bail!(
                "dhcpd validation ({:?}) failed; reverted include: {err}",
                cfg.validate_command
            ),
            Err(re) => {
                error!("dhcp include restore after failed validation FAILED: {re}");
                bail!(
                    "dhcpd validation ({:?}) failed AND include restore failed — \
                     include LEFT BROKEN: {err} (restore error: {re})",
                    cfg.validate_command
                );
            }
        }
    }

    if let Err(err) = run_cmd(&cfg.reload_command).await {
        // Roll the file back and try once more to bring dhcpd up on the old config.
        let restored = restore(path, previous.as_deref());
        let recovery = run_cmd(&cfg.reload_command).await;
        if let Err(ref re) = recovery {
            error!("dhcpd recovery reload after rollback FAILED — dhcpd may be DOWN: {re}");
        }
        match (restored, recovery) {
            (Ok(()), Ok(())) => bail!(
                "dhcpd reload ({:?}) failed; reverted include and dhcpd recovered: {err}",
                cfg.reload_command
            ),
            (Ok(()), Err(re)) => bail!(
                "dhcpd reload ({:?}) failed; reverted include but recovery reload also \
                 FAILED — dhcpd may be DOWN: {err} (recovery error: {re})",
                cfg.reload_command
            ),
            (Err(se), Ok(())) => {
                error!("dhcp include restore after failed reload FAILED: {se}");
                bail!(
                    "dhcpd reload ({:?}) failed AND include restore failed — \
                     include LEFT BROKEN: {err} (restore error: {se})",
                    cfg.reload_command
                );
            }
            (Err(se), Err(re)) => {
                error!("dhcp include restore after failed reload FAILED: {se}");
                bail!(
                    "dhcpd reload ({:?}) failed; include restore FAILED (LEFT BROKEN) AND \
                     recovery reload FAILED — dhcpd may be DOWN: {err} \
                     (restore error: {se}, recovery error: {re})",
                    cfg.reload_command
                );
            }
        }
    }

    info!("dhcp reservations applied ({} bytes)", content.len());
    Ok(Applied::Changed)
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

/// Restore the include file to its previous content (or delete it if there was
/// none). Returns the result so the caller can report when a rollback itself
/// failed (i.e. the include is left in a broken state).
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
        }
    }

    #[test]
    fn render_is_sorted_and_well_formed() {
        let clients = vec![
            client("bravo", "aa:bb:cc:dd:ee:02", "10.11.5.3"),
            client("alpha", "aa:bb:cc:dd:ee:01", "10.11.5.2"),
        ];
        let out = render(&clients);
        assert!(out.starts_with("# Managed by ala-archa-http-backend"));
        // sorted by name: alpha before bravo
        assert!(out.find("host alpha").unwrap() < out.find("host bravo").unwrap());
        assert!(out.contains(
            "host alpha {\n  hardware ethernet aa:bb:cc:dd:ee:01;\n  fixed-address 10.11.5.2;\n}\n"
        ));
    }

    #[test]
    fn render_supports_one_mac_two_reservations() {
        // One device dual-homed on .4 and .5 — two host blocks, same MAC.
        let mac = "d4:3a:2c:a1:3d:b4";
        let clients = vec![
            client("dev", mac, "10.11.5.221"),
            client("dev-private", mac, "10.11.4.221"),
        ];
        let out = render(&clients);
        assert_eq!(out.matches(&format!("hardware ethernet {mac};")).count(), 2);
        assert!(out.contains("fixed-address 10.11.5.221;"));
        assert!(out.contains("fixed-address 10.11.4.221;"));
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
        // No pre-existing include; validation fails -> the freshly written file
        // must be removed, leaving no include behind.
        let c = cfg(path.clone(), "false", "true");
        let new = render(&[client("a", "aa:bb:cc:dd:ee:01", "10.11.5.2")]);
        assert!(apply(&c, &new).await.is_err());
        assert!(
            !path.exists(),
            "include must not exist after rollback of a new file"
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
}
