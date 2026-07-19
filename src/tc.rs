//! Thin wrapper over the `tc` CLI for the one thing the backend toggles at runtime:
//! the ceil of the aggregate global-shaping HTB class. The class + leaf qdisc + fw
//! filter skeleton is created by the boot script (`access-point-tc-restore`); here we
//! only change the class ceil to enable / disable / adjust the shared cap for all
//! non-unlimited clients. Mirrors the subprocess style of [`crate::ipset`].

use anyhow::{bail, Result};

/// Format bits-per-second as a `tc` rate token, e.g. `5_000_000` -> `"5000000bit"`.
pub fn bps_to_tc(bps: u64) -> String {
    format!("{bps}bit")
}

pub struct Tc {
    interface: String,
}

impl Tc {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    fn run(&self, verb: &str, classid: &str, value: &str) -> std::io::Result<std::process::Output> {
        // Parent of a classid `M:N` is the root qdisc `M:0`.
        let major = classid.split(':').next().unwrap_or("1");
        let parent = format!("{major}:0");
        // `rate` == `ceil` on purpose: the class is a direct child of the root qdisc
        // (top-level), so it cannot BORROW above its `rate` — a `ceil > rate` would
        // stall traffic at ~`rate`. Setting the guaranteed rate equal to the cap lets it
        // send up to `value` without borrowing.
        std::process::Command::new("tc")
            .args([
                "class",
                verb,
                "dev",
                &self.interface,
                "parent",
                &parent,
                "classid",
                classid,
                "htb",
                "rate",
                value,
                "ceil",
                value,
            ])
            .output()
    }

    /// Set the global-shaping class limit (both `rate` and `ceil` to `value`). Prefers
    /// `tc class change` (the class is created by the boot script); if that fails (e.g.
    /// the boot script hasn't run yet at a very early start), falls back to `tc class
    /// replace`, which creates it — so the limit self-heals. Fails loudly if both fail.
    pub fn set_class_limit(&self, classid: &str, value: &str) -> Result<()> {
        let changed = self.run("change", classid, value)?;
        if changed.status.success() {
            return Ok(());
        }
        let change_err = String::from_utf8_lossy(&changed.stderr).trim().to_string();
        let replaced = self.run("replace", classid, value)?;
        if !replaced.status.success() {
            bail!(
                "tc class change/replace {classid} dev {} to {value} failed: {change_err} / {}",
                self.interface,
                String::from_utf8_lossy(&replaced.stderr).trim()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_to_tc_appends_bit_unit() {
        assert_eq!(bps_to_tc(5_000_000), "5000000bit");
        assert_eq!(bps_to_tc(0), "0bit");
    }
}
