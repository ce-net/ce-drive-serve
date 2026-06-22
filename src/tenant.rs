//! Multi-tenant drive registry — one host may serve many drives, each `(host, drive_id)` a separate
//! [`Drive`] CRDT + [`Feed`] + [`Quota`]. Authorization roots at the host's own key (the workspace
//! root), so every member's cap chains to it; membership is the set of issued caps, not a table.

use std::collections::HashMap;

use anyhow::{Result, bail};
use ce_drive_core::{Drive, DriveState, Workspace};
use ce_identity::Identity;

use crate::feed::Feed;
use crate::wire::Quota;

/// A single hosted drive: its CRDT state, change feed, sharing workspace, and billing terms. The
/// `snapshot_cid` caches the CID of the last published bootstrap snapshot (the `Open` reply value),
/// recomputed lazily when the drive advances.
pub struct Tenant {
    pub drive: Drive,
    pub feed: Feed,
    pub workspace: Workspace,
    pub quota: Quota,
    /// CID of the last-published bootstrap snapshot, and the feed cursor it was taken at.
    pub snapshot: Option<(String, u64)>,
}

impl Tenant {
    /// A fresh empty drive named `drive_id`, owned by `identity` (whose key is the cap root). A
    /// second handle to the same on-disk key backs the [`Workspace`] (it consumes its `Identity`).
    pub fn new(drive_id: &str, identity: Identity, quota: Quota) -> Self {
        let replica = identity.node_id_hex();
        let drive = Drive::init(drive_id, &replica);
        let workspace = Workspace::new(identity);
        Tenant { drive, feed: Feed::new(), workspace, quota, snapshot: None }
    }

    /// Rebuild a tenant from a persisted [`DriveState`] (e.g. a standby host resuming from a pinned
    /// snapshot). The feed restarts at 0 (clients re-bootstrap from the snapshot, then Poll forward).
    pub fn from_state(state: DriveState, identity: Identity, quota: Quota) -> Self {
        let drive = Drive::from_state(state);
        let workspace = Workspace::new(identity);
        Tenant { drive, feed: Feed::new(), workspace, quota, snapshot: None }
    }
}

/// The registry of all drives a host serves, keyed by drive-id. The host identity is shared (one
/// key) — every drive's workspace roots at it. Guarded behind a single mutex in the serve loop.
pub struct Registry {
    /// The host's identity dir (so each [`Tenant`]'s [`Workspace`] gets its own handle to the key).
    key_dir: std::path::PathBuf,
    host_id_hex: String,
    drives: HashMap<String, Tenant>,
}

impl Registry {
    /// A registry whose host identity lives in `key_dir` (the node key dir). Each created drive gets
    /// its own [`Identity`] handle to that key so the [`Workspace`] (which consumes one) works while
    /// the registry retains the host id.
    pub fn new(key_dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        let key_dir = key_dir.into();
        let identity = Identity::load_or_generate(&key_dir)?;
        Ok(Registry { host_id_hex: identity.node_id_hex(), key_dir, drives: HashMap::new() })
    }

    /// The host (and cap-root) NodeId hex.
    pub fn host_id_hex(&self) -> &str {
        &self.host_id_hex
    }

    /// Load a fresh [`Identity`] handle to the host key (each [`Workspace`] needs to own one).
    fn identity_handle(&self) -> Result<Identity> {
        Identity::load_or_generate(&self.key_dir)
    }

    /// Create a new empty drive `drive_id` with the given billing terms. Errors if it already exists.
    pub fn create(&mut self, drive_id: &str, quota: Quota) -> Result<()> {
        if self.drives.contains_key(drive_id) {
            bail!("drive '{drive_id}' already exists");
        }
        let tenant = Tenant::new(drive_id, self.identity_handle()?, quota);
        self.drives.insert(drive_id.to_string(), tenant);
        Ok(())
    }

    /// Register a drive rebuilt from persisted state (standby resume).
    pub fn restore(&mut self, drive_id: &str, state: DriveState, quota: Quota) -> Result<()> {
        if self.drives.contains_key(drive_id) {
            bail!("drive '{drive_id}' already exists");
        }
        let tenant = Tenant::from_state(state, self.identity_handle()?, quota);
        self.drives.insert(drive_id.to_string(), tenant);
        Ok(())
    }

    /// Borrow a drive by id.
    pub fn get(&self, drive_id: &str) -> Option<&Tenant> {
        self.drives.get(drive_id)
    }

    /// Mutably borrow a drive by id.
    pub fn get_mut(&mut self, drive_id: &str) -> Option<&mut Tenant> {
        self.drives.get_mut(drive_id)
    }

    /// The set of drive-ids this host serves.
    pub fn drive_ids(&self) -> Vec<String> {
        self.drives.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_drive_core::FileContent;

    fn key_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("ce-drive-tenant-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_get_and_list_drives() {
        let mut reg = Registry::new(key_dir("reg")).unwrap();
        assert!(reg.drive_ids().is_empty());
        assert!(reg.get("nope").is_none());

        reg.create("team", Quota::default()).unwrap();
        reg.create("personal", Quota::default()).unwrap();

        assert!(reg.get("team").is_some());
        assert!(reg.get_mut("personal").is_some());
        let mut ids = reg.drive_ids();
        ids.sort();
        assert_eq!(ids, vec!["personal".to_string(), "team".to_string()]);
    }

    #[test]
    fn duplicate_create_errors() {
        let mut reg = Registry::new(key_dir("dup")).unwrap();
        reg.create("team", Quota::default()).unwrap();
        let err = reg.create("team", Quota::default()).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn host_id_hex_is_stable_64_hex() {
        let dir = key_dir("hex");
        let reg = Registry::new(&dir).unwrap();
        let h = reg.host_id_hex().to_string();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // A second registry over the same key dir resolves the same host id (key is persisted).
        let reg2 = Registry::new(&dir).unwrap();
        assert_eq!(reg2.host_id_hex(), h);
    }

    #[test]
    fn restore_rebuilds_drive_from_state_and_rejects_duplicates() {
        // Build a drive, mutate it, snapshot its state, restore into a fresh registry.
        let mut reg = Registry::new(key_dir("restore-src")).unwrap();
        reg.create("team", Quota::default()).unwrap();
        {
            let t = reg.get_mut("team").unwrap();
            t.drive.mkdir("/", "docs").unwrap();
            let fc = FileContent::new("cid123", 10, 0o644, 1);
            t.drive.add_file("/docs", "f.txt", fc).unwrap();
        }
        let state = reg.get("team").unwrap().drive.state().clone();

        let mut reg2 = Registry::new(key_dir("restore-dst")).unwrap();
        reg2.restore("team", state.clone(), Quota::default()).unwrap();
        // The restored drive reflects the snapshot.
        let entries = reg2.get("team").unwrap().drive.ls("/docs").unwrap();
        assert!(entries.iter().any(|e| e.name == "f.txt"));
        // The feed restarts at 0 (clients re-bootstrap from the snapshot, then Poll forward).
        assert_eq!(reg2.get("team").unwrap().feed.cursor(), 0);
        // Restoring the same id twice errors.
        assert!(reg2.restore("team", state, Quota::default()).is_err());
    }

    #[test]
    fn quota_is_carried_per_drive() {
        let mut reg = Registry::new(key_dir("quota")).unwrap();
        let q = Quota {
            price_per_gib_month: "5".into(),
            price_per_gib_egress: "2".into(),
            free_tier_bytes: 1024,
            channel_required: true,
        };
        reg.create("paid", q.clone()).unwrap();
        let got = &reg.get("paid").unwrap().quota;
        assert_eq!(got.price_per_gib_month, "5");
        assert!(got.channel_required);
        assert_eq!(got.free_tier_bytes, 1024);
    }
}
