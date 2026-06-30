use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::{collections::VecDeque, process::Stdio};

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub ip: String,
    pub timeout: Option<std::time::Duration>,
    pub bytes: Option<usize>,
    pub packets: Option<usize>,
}

pub struct IPSet {
    name: String,
}

impl IPSet {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    pub fn entries(&self) -> Result<Vec<Entry>> {
        let output = std::process::Command::new("ipset")
            .args(["save", &self.name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        // Fail loudly on a non-zero exit (e.g. missing set / no permission) instead
        // of silently treating empty stdout as an empty set.
        if !output.status.success() {
            bail!(
                "ipset save {} failed: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let output = String::from_utf8(output.stdout)
            .map_err(|err| anyhow!("Decode command output: {}", err))?;

        let mut result = Vec::new();

        for line in output.split('\n') {
            let elts = line.split(' ').collect::<Vec<_>>();
            let (ip, tail) = match elts.as_slice() {
                ["add", _, ip, tail @ ..] => (ip.to_string(), tail),
                ["create", ..] => continue,
                [""] => continue,
                _ => bail!("Unexpected line in ipset output: {}", line),
            };

            let mut tail = VecDeque::from(tail.to_vec());

            let mut timeout = None;
            let mut bytes = None;
            let mut packets = None;

            while tail.len() > 1 {
                if let Some(name) = tail.pop_front() {
                    match name {
                        "timeout" => {
                            timeout = tail.pop_front().and_then(|v| {
                                v.parse::<u64>().ok().map(std::time::Duration::from_secs)
                            })
                        }
                        "bytes" => bytes = tail.pop_front().and_then(|v| v.parse::<usize>().ok()),
                        "packets" => {
                            packets = tail.pop_front().and_then(|v| v.parse::<usize>().ok())
                        }
                        _ => continue,
                    }
                }
            }

            result.push(Entry {
                ip,
                timeout,
                bytes,
                packets,
            })
        }

        Ok(result)
    }

    pub fn add(&self, entry: &str, timeout: Option<u64>) -> Result<()> {
        // `-exist` makes re-adding an existing entry a no-op (idempotent) and
        // updates its timeout instead of failing.
        let mut args = vec![
            "add".to_owned(),
            "-exist".to_owned(),
            self.name.clone(),
            entry.to_owned(),
        ];
        if let Some(timeout) = timeout {
            args.push("timeout".to_owned());
            args.push(format!("{}", timeout))
        }
        let r = std::process::Command::new("ipset").args(args).output()?;

        if !r.status.success() {
            bail!(
                "ipset add failed: {}",
                String::from_utf8_lossy(&r.stderr).trim()
            )
        }

        Ok(())
    }

    /// Remove an entry. Removing an absent entry is treated as success so the
    /// operation is idempotent (safe to retry / use during reconcile).
    pub fn del(&self, entry: &str) -> Result<()> {
        let r = std::process::Command::new("ipset")
            .args(["del", &self.name, entry])
            .output()?;

        if !r.status.success() {
            let stderr = String::from_utf8_lossy(&r.stderr);
            if stderr.contains("not in set") || stderr.contains("element is missing") {
                return Ok(());
            }
            bail!("ipset del failed: {}", stderr.trim())
        }

        Ok(())
    }
}
