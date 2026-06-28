//! Thin wrapper around `omshell` (ISC DHCP OMAPI) to create and remove `host`
//! reservations on the live dhcpd without a restart.
//!
//! `omshell` returns exit code 0 even on errors, so success/failure is decided
//! by scanning its combined output for known markers. Inputs are validated
//! defensively before they reach the script to prevent OMAPI command injection.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use slog_scope::{error, info};
use tokio::io::AsyncWriteExt;

use crate::config::Omapi;

const OMSHELL_TIMEOUT: Duration = Duration::from_secs(10);

/// Reject anything outside an explicit allowlist so a value can never break out
/// of the omshell script (defense in depth; the store validates too).
fn ensure_safe(field: &str, value: &str, allowed: impl Fn(char) -> bool) -> Result<()> {
    if value.is_empty() {
        bail!("OMAPI {field} is empty");
    }
    if let Some(bad) = value.chars().find(|c| !allowed(*c)) {
        bail!("OMAPI {field} contains an illegal character {bad:?}: {value:?}");
    }
    Ok(())
}

fn check_name(name: &str) -> Result<()> {
    ensure_safe("host name", name, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
    })
}

fn check_mac(mac: &str) -> Result<()> {
    ensure_safe("MAC", mac, |c| {
        c.is_ascii_hexdigit() || c == ':'
    })
}

fn check_ip(ip: &str) -> Result<()> {
    ip.parse::<std::net::IpAddr>()
        .with_context(|| format!("OMAPI ip-address is not a valid IP: {ip:?}"))?;
    Ok(())
}

/// Scan omshell output; `idempotent_markers` are messages that mean "the desired
/// state already holds" and should be treated as success.
fn check_output(op: &str, out: &str, idempotent_markers: &[&str]) -> Result<()> {
    let lower = out.to_lowercase();
    for m in idempotent_markers {
        if lower.contains(m) {
            return Ok(());
        }
    }
    // More specific phrases than a bare "error"/"failed" substring, which would
    // false-positive on benign output like "no errors" or "Reference".
    const ERROR_MARKERS: &[&str] = &[
        "can't",
        "cannot",
        "not found",
        "no such",
        "is invalid",
        "invalid ",
        "unable to",
        "failed to",
        ": error",
        "error:",
        "connection refused",
        "timed out",
    ];
    if let Some(marker) = ERROR_MARKERS.iter().find(|m| lower.contains(**m)) {
        bail!("omshell {op} reported error (marker {marker:?}): {}", out.trim());
    }
    Ok(())
}

async fn run_omshell(cfg: &Omapi, script: String) -> Result<String> {
    let mut child = tokio::process::Command::new(&cfg.omshell_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn {}", cfg.omshell_path))?;

    {
        let mut stdin = child.stdin.take().context("omshell stdin unavailable")?;
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    let output = tokio::time::timeout(OMSHELL_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| anyhow!("omshell timed out after {:?}", OMSHELL_TIMEOUT))??;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(combined)
}

/// Common preamble: authenticate and connect. The secret is never logged.
fn preamble(cfg: &Omapi) -> String {
    format!(
        "key {} {}\nserver {}\nport {}\nconnect\n",
        cfg.key_name, cfg.key_secret, cfg.server, cfg.port
    )
}

/// Create a `host` reservation (MAC -> fixed IP). Idempotent: an existing
/// identical host is treated as success.
pub async fn add_host(cfg: &Omapi, name: &str, mac: &str, ip: &str) -> Result<()> {
    check_name(name)?;
    check_mac(mac)?;
    check_ip(ip)?;

    let script = format!(
        "{preamble}new host\nset name = \"{name}\"\nset hardware-address = {mac}\nset hardware-type = 1\nset ip-address = {ip}\ncreate\n",
        preamble = preamble(cfg),
    );

    let out = run_omshell(cfg, script).await?;
    info!("OMAPI add_host {name} ({ip})");
    check_output("create host", &out, &["already exists", "duplicate"])
}

/// Remove a `host` reservation by name. Idempotent: a missing host is success.
pub async fn remove_host(cfg: &Omapi, name: &str) -> Result<()> {
    check_name(name)?;

    let script = format!(
        "{preamble}new host\nset name = \"{name}\"\nopen\nremove\n",
        preamble = preamble(cfg),
    );

    let out = run_omshell(cfg, script).await?;
    info!("OMAPI remove_host {name}");
    // "not found"/"no such" => the host is already gone, which is what we want.
    check_output("remove host", &out, &["not found", "no such", "not exist"])
        .map_err(|err| {
            error!("OMAPI remove_host {name} failed: {err}");
            err
        })
}
