//! Multi-tenant drive registry — one host may serve many drives, each `(host, drive_id)` a separate
//! [`Drive`] CRDT + [`Feed`] + [`Quota`]. Authorization roots at the host's own key (the workspace
//! root), so every member's cap chains to it; membership is the set of issued caps, not a table.

use std::collections::HashMap;

use anyhow::{Result, bail};
use ce_coord::Coord;
use ce_drive_core::{DriveState, SyncedDrive, Workspace};
use ce_identity::Identity;

use crate::feed::Feed;
use crate::wire::Quota;

/// A single hosted drive: its CRDT state, change feed, sharing workspace, and billing terms. The
/// `snapshot_cid` caches the CID of the last published bootstrap snapshot (the `Open` reply value),
/// recomputed lazily when the drive advances.
pub struct Tenant {
    /// The drive itself, MULTI-WRITER.
    ///
    /// This was a single-writer `Drive`, and that is why nothing ever synced: every write through
    /// the mesh API landed in a local CRDT that no other device followed. Opening a replicated drive
    /// *alongside* it would only have produced a replica that no request ever wrote to. Serving from
    /// the replicated drive is the switch.
    pub drive: SyncedDrive,
    pub feed: Feed,
    pub workspace: Workspace,
    pub quota: Quota,
    /// CID of the last-published bootstrap snapshot, and the feed cursor it was taken at.
    pub snapshot: Option<(String, u64)>,
}

impl Tenant {
    /// A fresh empty drive named `drive_id`, owned by `identity` (whose key is the cap root). A
    /// second handle to the same on-disk key backs the [`Workspace`] (it consumes its `Identity`).
    pub async fn new(
        coord: &Coord,
        drive_id: &str,
        identity: Identity,
        quota: Quota,
        peers: &[String],
    ) -> Result<Self> {
        let drive = SyncedDrive::open(coord, drive_id, peers).await?;
        let workspace = Workspace::new(identity);
        Ok(Tenant { drive, feed: Feed::new(), workspace, quota, snapshot: None })
    }

    /// Rebuild a tenant from a persisted [`DriveState`] (e.g. a standby host resuming from a pinned
    /// snapshot). The feed restarts at 0 (clients re-bootstrap from the snapshot, then Poll forward).
    /// Rebuild a tenant from durable local state.
    ///
    /// Uses `restore_state`, never `adopt`: restore is silent and local, while adopting would
    /// publish every op in the drive's history one at a time -- thousands of round trips on a
    /// long-lived drive, degrading every other app on the node while it runs.
    pub async fn from_state(
        coord: &Coord,
        drive_id: &str,
        state: DriveState,
        identity: Identity,
        quota: Quota,
        peers: &[String],
    ) -> Result<Self> {
        let drive = SyncedDrive::open(coord, drive_id, peers).await?;
        drive.restore_state(&state)?;
        let workspace = Workspace::new(identity);
        Ok(Tenant { drive, feed: Feed::new(), workspace, quota, snapshot: None })
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
    pub async fn create(
        &mut self,
        coord: &Coord,
        drive_id: &str,
        quota: Quota,
        peers: &[String],
    ) -> Result<()> {
        if self.drives.contains_key(drive_id) {
            bail!("drive '{drive_id}' already exists");
        }
        let tenant = Tenant::new(coord, drive_id, self.identity_handle()?, quota, peers).await?;
        self.drives.insert(drive_id.to_string(), tenant);
        Ok(())
    }

    /// Register a drive rebuilt from persisted state (standby resume).
    pub async fn restore(
        &mut self,
        coord: &Coord,
        drive_id: &str,
        state: DriveState,
        quota: Quota,
        peers: &[String],
    ) -> Result<()> {
        if self.drives.contains_key(drive_id) {
            bail!("drive '{drive_id}' already exists");
        }
        let tenant =
            Tenant::from_state(coord, drive_id, state, self.identity_handle()?, quota, peers)
                .await?;
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

    // Everything else that used to live here needs a live node: a tenant now opens a replicated log
    // through `ce-coord`, so it cannot be built offline. Those assertions moved to
    // `tests/registry_live.rs` rather than being dropped.

    #[test]
    fn host_id_hex_is_stable_64_hex() {
        let dir = std::env::temp_dir()
            .join(format!("ce-drive-tenant-hex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let reg = Registry::new(&dir).unwrap();
        let h = reg.host_id_hex().to_string();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // A second registry over the same key dir resolves the same host id (key is persisted).
        let reg2 = Registry::new(&dir).unwrap();
        assert_eq!(reg2.host_id_hex(), h);
    }
}
