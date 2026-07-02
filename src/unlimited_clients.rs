//! Runtime-mutable store of "unlimited" (no-shaping) clients.
//!
//! Replaces the immutable `config.no_shaping_ips` as the source consulted by
//! client classification. Backed by a YAML file written atomically; the
//! in-memory cache is updated only after a successful write so memory and disk
//! never diverge. A dedicated mutation lock serializes whole CRUD transactions
//! (store + dhcp reservations + ipset) so concurrent requests can't interleave.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

/// One unlimited client. Equals a dnsmasq `dhcp-host` reservation 1:1.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlimitedClient {
    pub name: String,
    pub mac: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Unix epoch seconds when the client was first added (set by the store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// Unix epoch seconds of the last store change (add / comment edit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

const MAX_COMMENT_LEN: usize = 256;

/// `true` for a valid slug: 1..=63 chars of `[a-z0-9-]`.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Normalize a MAC to canonical lowercase `aa:bb:cc:dd:ee:ff`, or `None` if it
/// isn't a well-formed 6-octet MAC.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    if parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        Some(mac.to_lowercase())
    } else {
        None
    }
}

impl UnlimitedClient {
    /// Validate all fields. `mac` must already be normalized.
    pub fn validate(&self, subnet: IpNet) -> Result<()> {
        if !is_valid_name(&self.name) {
            bail!(
                "invalid name {:?}: expected slug [a-z0-9-]{{1,63}}",
                self.name
            );
        }
        if normalize_mac(&self.mac).as_deref() != Some(self.mac.as_str()) {
            bail!("invalid/non-normalized MAC {:?}", self.mac);
        }
        let ip: std::net::IpAddr = self
            .ip
            .parse()
            .with_context(|| format!("invalid IP {:?}", self.ip))?;
        if !subnet.contains(&ip) {
            bail!("IP {} is outside the allowed subnet {}", ip, subnet);
        }
        if let Some(comment) = &self.comment {
            if comment.len() > MAX_COMMENT_LEN {
                bail!("comment too long ({} > {MAX_COMMENT_LEN})", comment.len());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct UnlimitedClientsStore {
    path: PathBuf,
    /// Keyed by client name.
    cache: Arc<RwLock<HashMap<String, UnlimitedClient>>>,
    /// Serializes whole CRUD transactions (store + side effects).
    mutation_lock: Arc<Mutex<()>>,
}

impl UnlimitedClientsStore {
    /// Load from disk; a missing file yields an empty store.
    pub fn load(path: &Path) -> Result<Self> {
        let map = if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {:?}", path))?;
            let list: Vec<UnlimitedClient> = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse {:?}", path))?;
            list.into_iter().map(|c| (c.name.clone(), c)).collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            path: path.to_path_buf(),
            cache: Arc::new(RwLock::new(map)),
            mutation_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Acquire the transaction lock; hold it across a whole CRUD operation.
    pub async fn lock_for_mutation(&self) -> OwnedMutexGuard<()> {
        self.mutation_lock.clone().lock_owned().await
    }

    /// All clients, sorted by name.
    pub async fn list(&self) -> Vec<UnlimitedClient> {
        let mut v: Vec<UnlimitedClient> = self.cache.read().await.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Look up a client by name.
    pub async fn get(&self, name: &str) -> Option<UnlimitedClient> {
        self.cache.read().await.get(name).cloned()
    }

    /// Whether any managed client currently holds `ip`.
    pub async fn contains_ip(&self, ip: &str) -> bool {
        self.cache.read().await.values().any(|c| c.ip == ip)
    }

    /// Whether a client with `name` exists.
    pub async fn contains_name(&self, name: &str) -> bool {
        self.cache.read().await.contains_key(name)
    }

    /// Insert/replace a client. Persists to disk first, then swaps the in-memory
    /// cache, so memory never gets ahead of disk. The (synchronous) disk write
    /// runs without holding the cache lock, so readers aren't blocked on I/O.
    /// Concurrent writers are serialized by the caller via [`Self::lock_for_mutation`].
    pub async fn add(&self, mut client: UnlimitedClient) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        // Preserve an existing created_at across a re-add; otherwise stamp now.
        let prior_created = self
            .cache
            .read()
            .await
            .get(&client.name)
            .and_then(|c| c.created_at);
        client.created_at = client.created_at.or(prior_created).or(Some(now));
        client.updated_at = Some(now);

        let mut next = self.cache.read().await.clone();
        next.insert(client.name.clone(), client);
        self.persist(&next)?;
        *self.cache.write().await = next;
        Ok(())
    }

    /// Remove a client by name. Persists first, then swaps the cache (see [`Self::add`]).
    pub async fn remove(&self, name: &str) -> Result<()> {
        let mut next = self.cache.read().await.clone();
        next.remove(name);
        self.persist(&next)?;
        *self.cache.write().await = next;
        Ok(())
    }

    /// Update only the `comment` of an existing client. Returns `false` if the
    /// name is unknown. Validates comment length. Atomic write (see [`Self::add`]).
    pub async fn set_comment(&self, name: &str, comment: Option<String>) -> Result<bool> {
        if let Some(c) = &comment {
            if c.len() > MAX_COMMENT_LEN {
                bail!("comment too long ({} > {MAX_COMMENT_LEN})", c.len());
            }
        }
        let mut next = self.cache.read().await.clone();
        let found = match next.get_mut(name) {
            Some(client) => {
                client.comment = comment;
                client.updated_at = Some(chrono::Utc::now().timestamp());
                true
            }
            None => false,
        };
        if found {
            self.persist(&next)?;
            *self.cache.write().await = next;
        }
        Ok(found)
    }

    fn persist(&self, map: &HashMap<String, UnlimitedClient>) -> Result<()> {
        let mut list: Vec<&UnlimitedClient> = map.values().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let yaml = serde_yaml::to_string(&list)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {:?}", parent))?;
        }
        // Atomic write: temp file on the same dir + rename.
        let tmp = self.path.with_extension("yaml.tmp");
        std::fs::write(&tmp, yaml).with_context(|| format!("Failed to write {:?}", tmp))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("Failed to rename into {:?}", self.path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet() -> IpNet {
        "10.11.5.0/24".parse().unwrap()
    }

    #[test]
    fn name_validation() {
        assert!(is_valid_name("evgenii-phone"));
        assert!(!is_valid_name("Evgenii"));
        assert!(!is_valid_name("a b"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name(&"x".repeat(64)));
        // injection attempt
        assert!(!is_valid_name("a\";set"));
    }

    #[test]
    fn mac_normalization() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(normalize_mac("zz:bb:cc:dd:ee:ff"), None);
    }

    #[test]
    fn client_validation() {
        let ok = UnlimitedClient {
            name: "phone".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: "10.11.5.50".into(),
            comment: None,
            ..Default::default()
        };
        assert!(ok.validate(subnet()).is_ok());

        let wrong_subnet = UnlimitedClient {
            ip: "10.11.4.50".into(),
            ..ok.clone()
        };
        assert!(wrong_subnet.validate(subnet()).is_err());

        let bad_name = UnlimitedClient {
            name: "Phone!".into(),
            ..ok.clone()
        };
        assert!(bad_name.validate(subnet()).is_err());
    }

    #[tokio::test]
    async fn store_crud_and_persistence() {
        let dir = std::env::temp_dir().join(format!("uc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clients.yaml");

        let store = UnlimitedClientsStore::load(&path).unwrap();
        store
            .add(UnlimitedClient {
                name: "phone".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ip: "10.11.5.50".into(),
                comment: Some("test".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(store.contains_ip("10.11.5.50").await);
        assert!(store.contains_name("phone").await);
        assert_eq!(store.list().await.len(), 1);

        // Reload from disk: data survived.
        let reloaded = UnlimitedClientsStore::load(&path).unwrap();
        assert_eq!(reloaded.get("phone").await.unwrap().ip, "10.11.5.50");

        store.remove("phone").await.unwrap();
        assert!(!store.contains_ip("10.11.5.50").await);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn set_comment_updates_persists_and_validates() {
        let dir = std::env::temp_dir().join(format!("uc-cmt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clients.yaml");

        let store = UnlimitedClientsStore::load(&path).unwrap();
        store
            .add(UnlimitedClient {
                name: "phone".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ip: "10.11.5.50".into(),
                comment: None,
                ..Default::default()
            })
            .await
            .unwrap();

        // updates and persists
        assert!(store.set_comment("phone", Some("hi".into())).await.unwrap());
        let reloaded = UnlimitedClientsStore::load(&path).unwrap();
        assert_eq!(
            reloaded.get("phone").await.unwrap().comment.as_deref(),
            Some("hi")
        );

        // unknown name -> false, no error
        assert!(!store.set_comment("nope", None).await.unwrap());

        // too long -> error
        assert!(store
            .set_comment("phone", Some("x".repeat(257)))
            .await
            .is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
