//! Runtime-mutable MAC blacklist. A blacklisted MAC can't register for internet
//! access (enforced in `client_get`/`client_register`), in **union** with the
//! static `config.blacklisted_macs`. Backed by a YAML file written atomically;
//! an in-memory `HashSet` keeps the membership check O(1) on the hot client path.
//!
//! Enforcement is registration-time (soft): a newly blacklisted device can't
//! register, but an already-granted ipset entry persists until its timeout.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

/// Max length of a blacklist entry comment (matches the unlimited-clients limit).
pub const MAX_COMMENT_LEN: usize = 256;

/// One blacklist entry. Keyed by normalized lowercase MAC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BlacklistEntry {
    pub mac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Unix epoch seconds when the entry was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}

#[derive(Clone)]
pub struct BlacklistStore {
    path: PathBuf,
    /// Entries keyed by normalized MAC.
    cache: Arc<RwLock<HashMap<String, BlacklistEntry>>>,
    /// Membership set for the hot client path (normalized MACs).
    macs: Arc<RwLock<HashSet<String>>>,
    /// Serializes whole CRUD transactions.
    mutation_lock: Arc<Mutex<()>>,
}

impl BlacklistStore {
    /// Load from disk; a missing file yields an empty store.
    pub fn load(path: &Path) -> Result<Self> {
        let map = if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {path:?}"))?;
            let list: Vec<BlacklistEntry> = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse {path:?}"))?;
            list.into_iter().map(|e| (e.mac.clone(), e)).collect()
        } else {
            HashMap::new()
        };
        let set: HashSet<String> = map.keys().cloned().collect();
        Ok(Self {
            path: path.to_path_buf(),
            cache: Arc::new(RwLock::new(map)),
            macs: Arc::new(RwLock::new(set)),
            mutation_lock: Arc::new(Mutex::new(())),
        })
    }

    /// An empty store (used as a fail-open fallback when load fails).
    pub fn empty(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            macs: Arc::new(RwLock::new(HashSet::new())),
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn lock_for_mutation(&self) -> OwnedMutexGuard<()> {
        self.mutation_lock.clone().lock_owned().await
    }

    /// O(1) membership check for the hot client path. `mac` must be normalized
    /// lowercase (as produced by `normalize_mac` / `Hardware.mac.to_lowercase()`).
    pub async fn contains(&self, mac: &str) -> bool {
        self.macs.read().await.contains(mac)
    }

    /// All entries, sorted by MAC.
    pub async fn list(&self) -> Vec<BlacklistEntry> {
        let mut v: Vec<BlacklistEntry> = self.cache.read().await.values().cloned().collect();
        v.sort_by(|a, b| a.mac.cmp(&b.mac));
        v
    }

    pub async fn get(&self, mac: &str) -> Option<BlacklistEntry> {
        self.cache.read().await.get(mac).cloned()
    }

    /// Insert/replace an entry. Persists to disk first, then swaps the caches.
    /// `entry.mac` must already be normalized.
    pub async fn add(&self, mut entry: BlacklistEntry) -> Result<()> {
        if let Some(c) = &entry.comment {
            if c.len() > MAX_COMMENT_LEN {
                bail!("comment too long ({} > {MAX_COMMENT_LEN})", c.len());
            }
        }
        if entry.created_at.is_none() {
            entry.created_at = Some(chrono::Utc::now().timestamp());
        }
        let mut next = self.cache.read().await.clone();
        next.insert(entry.mac.clone(), entry);
        self.persist(&next)?;
        let set: HashSet<String> = next.keys().cloned().collect();
        *self.cache.write().await = next;
        *self.macs.write().await = set;
        Ok(())
    }

    /// Remove an entry by MAC. Returns `false` if it wasn't present.
    pub async fn remove(&self, mac: &str) -> Result<bool> {
        let mut next = self.cache.read().await.clone();
        let removed = next.remove(mac).is_some();
        if removed {
            self.persist(&next)?;
            let set: HashSet<String> = next.keys().cloned().collect();
            *self.cache.write().await = next;
            *self.macs.write().await = set;
        }
        Ok(removed)
    }

    fn persist(&self, map: &HashMap<String, BlacklistEntry>) -> Result<()> {
        let mut list: Vec<&BlacklistEntry> = map.values().collect();
        list.sort_by(|a, b| a.mac.cmp(&b.mac));
        let yaml = serde_yaml::to_string(&list)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {parent:?}"))?;
        }
        let tmp = self.path.with_extension("yaml.tmp");
        std::fs::write(&tmp, yaml).with_context(|| format!("Failed to write {tmp:?}"))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("Failed to rename into {:?}", self.path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bl-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("blacklist.yaml")
    }

    #[tokio::test]
    async fn crud_persist_and_contains() {
        let path = tmp_path("crud");
        let _ = std::fs::remove_file(&path);
        let store = BlacklistStore::load(&path).unwrap();

        assert!(!store.contains("aa:bb:cc:dd:ee:ff").await);
        store
            .add(BlacklistEntry {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                comment: Some("abuser".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(store.contains("aa:bb:cc:dd:ee:ff").await);
        assert_eq!(store.list().await.len(), 1);
        assert!(store
            .get("aa:bb:cc:dd:ee:ff")
            .await
            .unwrap()
            .created_at
            .is_some());

        // survives reload
        let reloaded = BlacklistStore::load(&path).unwrap();
        assert!(reloaded.contains("aa:bb:cc:dd:ee:ff").await);

        assert!(store.remove("aa:bb:cc:dd:ee:ff").await.unwrap());
        assert!(!store.contains("aa:bb:cc:dd:ee:ff").await);
        assert!(!store.remove("aa:bb:cc:dd:ee:ff").await.unwrap()); // already gone

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn rejects_long_comment() {
        let path = tmp_path("longcomment");
        let _ = std::fs::remove_file(&path);
        let store = BlacklistStore::load(&path).unwrap();
        let r = store
            .add(BlacklistEntry {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                comment: Some("x".repeat(257)),
                ..Default::default()
            })
            .await;
        assert!(r.is_err());
        std::fs::remove_file(&path).ok();
    }
}
