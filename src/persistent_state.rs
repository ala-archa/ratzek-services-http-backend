use crate::speedtest::SpeedTest;
use serde::{Deserialize, Serialize};
use slog_scope::error;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TelegramMessage {
    pub chat_id: String,
    pub text: String,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistentState {
    pub is_wide_network_available: Option<bool>,
    pub speedtest: Option<SpeedTest>,
    pub last_tariff_update: Option<chrono::DateTime<chrono::Utc>>,
    pub balance: Option<f64>,
    #[serde(default)]
    pub telegram_queue: Vec<TelegramMessage>,
    /// Global aggregate shaping cap for all non-unlimited clients, in bits/sec.
    /// `Some(x)` = enabled at `x` bps; `None` = disabled. Persisted so the cap is
    /// re-applied after a restart/reboot (see `State::reconcile_global_shaping`).
    #[serde(default)]
    pub global_shaping_limit_bps: Option<u64>,
}

impl PersistentState {
    pub fn load_from_yaml(path: &std::path::Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                error!("Unable to read persistent state: {err}");
                return Self::default();
            }
        };
        match serde_yaml::from_str(&content) {
            Ok(state) => state,
            Err(err) => {
                error!("Unable to parse persistent state: {err}");
                Self::default()
            }
        }
    }
}

#[derive(Clone)]
pub struct PersistentStateGuard {
    persistent_state_path: std::path::PathBuf,
    last_read_time: Arc<Mutex<chrono::DateTime<chrono::Utc>>>,
    state: Arc<Mutex<PersistentState>>,
}

impl PersistentStateGuard {
    pub fn load_from_yaml(path: &std::path::Path) -> Self {
        Self {
            persistent_state_path: path.to_path_buf(),
            last_read_time: Arc::new(Mutex::new(chrono::Utc::now())),
            state: Arc::new(Mutex::new(PersistentState::load_from_yaml(path))),
        }
    }

    async fn is_changed_on_disk(&self) -> bool {
        let metadata = match std::fs::metadata(&self.persistent_state_path) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        let last_modified = match metadata.modified() {
            Ok(last_modified) => last_modified,
            Err(_) => return false,
        };
        let last_read_time = self.last_read_time.lock().await;
        chrono::DateTime::<chrono::Utc>::from(last_modified) > *last_read_time
    }

    async fn reload(&self) {
        if self.is_changed_on_disk().await {
            let state = PersistentState::load_from_yaml(&self.persistent_state_path);
            let mut state_guard = self.state.lock().await;
            *state_guard = state;
            (*self.last_read_time.lock().await) = chrono::Utc::now();
        }
    }

    pub async fn update<F, R>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut PersistentState) -> R,
    {
        self.reload().await;
        let mut state = self.state.lock().await;
        let r = f(&mut state);
        let content = serde_yaml::to_string(&*state)?;
        // Atomic write: a truncated file from a mid-write hard reboot (frequent on
        // this host) would fail to parse on boot and drop the entire persisted state
        // (queue, balance, speedtest). Write to a temp file in the same directory,
        // then rename over the target — rename is atomic within one filesystem.
        // 0o644: `atomic_write` sets the mode explicitly (umask-independent), so pass the
        // effective historical mode directly — NOT 0o666, which would be world-writable.
        atomic_write(&self.persistent_state_path, content.as_bytes(), 0o644)?;
        Ok(r)
    }

    pub async fn get(&self) -> PersistentState {
        self.reload().await;
        self.state.lock().await.clone()
    }
}

/// Write `content` to `path` atomically with the given unix `mode`: create the parent
/// dir if needed, fill a sibling temp file (opened with `mode`, so the final file's
/// permissions are set at creation — no world-readable window for PII), fsync it, then
/// rename it over `path`, then fsync the directory so the rename itself survives a
/// power loss. A crash mid-write leaves either the old file or the temp file, never a
/// truncated target.
///
/// The fixed `.tmp` name (`path.with_extension("tmp")`) requires **one writer per
/// path**: each writer must own a distinct target path (its `.tmp` is a sibling of that
/// path). `PersistentStateGuard::update` serializes its own writes via the state mutex;
/// the shaper-quota persist-job owns a different path (config `validate()` enforces it
/// is distinct from the other state files). Two writers sharing one path would race the
/// same `.tmp` and tear.
pub(crate) fn atomic_write(
    path: &std::path::Path,
    content: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        // `.mode()` only applies when the temp is newly created; a leftover temp from a
        // prior crash would keep its old perms. Set them explicitly so the PII mode
        // holds before any content is written.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // fsync the parent directory: on ext4 with frequent power loss (this host) the
    // rename can otherwise be lost, reverting to stale state. Best-effort.
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
