use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::{collections::VecDeque, process::Stdio};

#[derive(Debug, Serialize)]
pub struct Entry {
    pub ip: String,
    pub timeout: Option<std::time::Duration>,
    pub bytes: Option<usize>,
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
            .args(&["save", &self.name])
            .stdout(Stdio::piped())
            .output()?;

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

            while tail.len() > 1 {
                if let Some(name) = tail.pop_front() {
                    match name {
                        "timeout" => {
                            timeout = tail.pop_front().and_then(|v| {
                                v.parse::<u64>().ok().map(std::time::Duration::from_secs)
                            })
                        }
                        "bytes" => bytes = tail.pop_front().and_then(|v| v.parse::<usize>().ok()),
                        _ => continue,
                    }
                }
            }

            result.push(Entry { ip, timeout, bytes })
        }

        Ok(result)
    }

    pub fn add(&self, entry: &str) -> Result<()> {
        let r = std::process::Command::new("ipset")
            .args(&["add", &self.name, entry])
            .output()?;

        if !r.status.success() {
            bail!("Got non-zero exit code")
        }

        Ok(())
    }
}
