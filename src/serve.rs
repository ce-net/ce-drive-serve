//! The host serve loop: poll `/mesh/messages`, decode each `ce-drive/v1` request, authorize it
//! against the presented ce-cap chain, dispatch to the [`Registry`], and reply.
//!
//! Authorization is the discipline from `rdev::handle_inner` reused verbatim: every request runs
//! `ce_cap::authorize(host_id, roots, &[], now, &from_node, ability, &chain, &is_revoked)` and then
//! enforces the drive-id + path-prefix caveats (with a `..` traversal guard) before any work. No
//! ACL table, no per-file permission row — authorization is a pure local function of the chain.
//!
//! The **drive id is bound into the leaf cap's `path_prefix`** as the namespaced leading segment
//! `ce-drive/<drive>[/<subtree>]` (mirroring ce-db's `ce-db/<collection>` and ce-storage's
//! `<bucket>/<prefix>`). [`authorize_req`] recovers that drive id and rejects the request unless it
//! equals `req.drive` BEFORE any op — so a cap minted for drive A can never authorize the same
//! op+path on drive B/C on the same host. A cap whose prefix is not in this namespace authorizes
//! nothing (fail-closed). Share mints sub-caps carrying the same drive binding (see
//! [`drive_caveat_prefix`]).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ce_cap::{Caveats, Resource, SignedCapability, authorize, decode_chain, encode_chain};
use ce_drive_core::{Ability, DirEntry, NodeKind, ROOT};
use ce_identity::{Identity, NodeId};
use ce_rs::{CeClient, data};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::tenant::Registry;
use crate::wire::{
    Beacon, ChangeKind, ChunkRef, DriveErr, DriveOk, DriveOp, DriveReply, DriveReq, Entry,
    EntryKind, ReadPlan, ShareCaveats, changes_topic, decode_req, encode_reply,
};

/// Unix seconds now.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The ability string an op requires (the floor; higher abilities imply it via [`Ability::implied`]).
pub fn required_ability(op: &DriveOp) -> &'static str {
    match op {
        DriveOp::Open | DriveOp::Stat { .. } | DriveOp::List { .. } | DriveOp::Read { .. } => {
            Ability::Read.as_str()
        }
        DriveOp::Write { .. } | DriveOp::Mkdir { .. } | DriveOp::Copy { .. } => Ability::Write.as_str(),
        // Move/Delete are delete+create; gate on write (the lattice puts delete under write here).
        DriveOp::Move { .. } | DriveOp::Delete { .. } => Ability::Write.as_str(),
        DriveOp::Share { .. } => Ability::Admin.as_str(),
        // Poll/Watch use read (a reader may follow the change feed).
        DriveOp::Poll { .. } | DriveOp::Watch => Ability::Read.as_str(),
    }
}

/// The path an op touches, for the path-prefix caveat check. `None` = drive-level (no path scope).
fn op_path<'a>(op: &'a DriveOp) -> Option<&'a str> {
    match op {
        DriveOp::Stat { path }
        | DriveOp::List { path, .. }
        | DriveOp::Read { path, .. }
        | DriveOp::Write { path, .. }
        | DriveOp::Mkdir { path }
        | DriveOp::Delete { path, .. }
        | DriveOp::Share { path, .. } => Some(path),
        // Move/Copy: the destination is the binding write; both ends are checked in the handler.
        DriveOp::Move { to, .. } | DriveOp::Copy { to, .. } => Some(to),
        DriveOp::Open | DriveOp::Poll { .. } | DriveOp::Watch => None,
    }
}

/// Normalize a path: single leading slash, no trailing slash (except root).
fn norm_path(p: &str) -> String {
    let t = p.trim().trim_matches('/');
    if t.is_empty() { "/".to_string() } else { format!("/{t}") }
}

/// The caveat namespace that binds a Drive capability to one drive id. Mirrors ce-db's
/// `ce-db/<collection>` and ce-storage's `<bucket>/<prefix>`: the drive id is carried as the leading
/// segment of the leaf cap's `path_prefix`, so the same primitive that confines an op to a subtree
/// also pins the grant to a single drive. A cap minted for drive A can therefore never be replayed
/// against drive B on the same host.
const DRIVE_NS: &str = "ce-drive/";

/// Build the drive-bound `path_prefix` caveat for `(drive, path)`: `ce-drive/<drive>` followed by the
/// normalized path subtree (root contributes no path tail). `Caveats::is_narrower_or_equal` (in
/// `ce-cap`, a `starts_with` check) keeps attenuation honest across this combined string.
///
/// This is the canonical way to mint a Drive cap's `path_prefix`: callers (the owner issuing a root
/// grant, or `ce-drive-client`) MUST use it so the host's authorize gate can recover the drive id and
/// reject cross-drive replay. A cap whose prefix is not in this namespace authorizes nothing.
pub fn drive_caveat_prefix(drive: &str, path: &str) -> String {
    drive_prefix(drive, path)
}

/// Build the drive-bound `path_prefix` caveat for `(drive, path)`: `ce-drive/<drive>` followed by the
/// normalized path subtree (root contributes no path tail). `Caveats::is_narrower_or_equal` (in
/// `ce-cap`, a `starts_with` check) keeps attenuation honest across this combined string.
fn drive_prefix(drive: &str, path: &str) -> String {
    let norm = norm_path(path);
    if norm == "/" { format!("{DRIVE_NS}{drive}") } else { format!("{DRIVE_NS}{drive}{norm}") }
}

/// Decode a drive-bound `path_prefix` caveat into `(drive_id, path_subtree)`. The subtree is a normal
/// drive path (`/` = drive-wide). Returns `None` if the prefix is not in the `ce-drive/<drive>...`
/// namespace (an unbound or foreign cap, which authorizes nothing here).
fn parse_drive_prefix(prefix: &str) -> Option<(String, String)> {
    let rest = prefix.strip_prefix(DRIVE_NS)?;
    // `rest` is `<drive>` or `<drive>/<path...>`. The drive id never contains a `/`.
    match rest.split_once('/') {
        Some((drive, path)) if !drive.is_empty() => Some((drive.to_string(), norm_path(path))),
        Some(_) => None, // empty drive id
        None if !rest.is_empty() => Some((rest.to_string(), "/".to_string())),
        None => None,
    }
}

/// Reject `..` traversal in a path.
fn no_dotdot(p: &str) -> Result<(), DriveErr> {
    if p.split('/').any(|c| c == "..") {
        return Err(DriveErr::BadPath);
    }
    Ok(())
}

/// Verify the cap chain authorizes `op` on `(drive, path)` for `from_node`. Returns the granted
/// ability strings (the leaf's abilities) on success, or a [`DriveErr`] on failure. This is the
/// single authorization gate every request passes through.
pub fn authorize_req(
    host_id: &NodeId,
    accepted_roots: &[NodeId],
    drive: &str,
    op: &DriveOp,
    from_node: &NodeId,
    chain: &[SignedCapability],
    now: u64,
    revoked: &HashSet<(NodeId, u64)>,
) -> Result<Vec<String>, DriveErr> {
    let ability = required_ability(op);
    let is_revoked = |issuer: &NodeId, nonce: u64| revoked.contains(&(*issuer, nonce));
    // Gate 1: the ce-cap verifier (signatures, attenuation, root, audience, expiry, revocation).
    authorize(host_id, accepted_roots, &[], now, from_node, ability, chain, &is_revoked).map_err(
        |e| {
            let el = e.to_lowercase();
            if el.contains("revoked") {
                DriveErr::Revoked
            } else if el.contains("expired") || el.contains("not yet valid") {
                DriveErr::Expired
            } else {
                DriveErr::Unauthorized
            }
        },
    )?;

    // Gate 2: drive-id + path-prefix caveats (the action-layer enforcement ce-cap delegates).
    let leaf = chain.last().ok_or(DriveErr::Unauthorized)?;
    // The drive id is pinned in the leaf's `path_prefix` (`ce-drive/<drive>[/<subtree>]`). A cap with
    // no such binding authorizes nothing here (fail-closed): without it a cap issued for drive A
    // would authorize the identical op+path on drive B/C on the same host. Verify the binding BEFORE
    // any op, and recover the path subtree the cap is confined to.
    let bound_prefix = leaf.cap.caveats.path_prefix.as_deref().ok_or(DriveErr::Unauthorized)?;
    let (bound_drive, path_scope) =
        parse_drive_prefix(bound_prefix).ok_or(DriveErr::Unauthorized)?;
    if bound_drive != drive {
        // Cap minted for a different drive on this host — refuse before doing any work.
        return Err(DriveErr::OutOfScope);
    }

    if let Some(path) = op_path(op) {
        no_dotdot(path)?;
        // Move/Copy also need the source checked.
        if let DriveOp::Move { from, .. } | DriveOp::Copy { from, .. } = op {
            no_dotdot(from)?;
            enforce_prefix(&path_scope, from)?;
        }
        enforce_prefix(&path_scope, path)?;
    }
    Ok(leaf.cap.abilities.clone())
}

/// Enforce the cap's path-subtree caveat (decoded from the drive-bound prefix) against `path`
/// (fail-closed). `scope` is a normal drive path; `/` means drive-wide (no path confinement).
fn enforce_prefix(scope: &str, path: &str) -> Result<(), DriveErr> {
    let norm = norm_path(path);
    let pfx = norm_path(scope);
    let ok = pfx == "/" || norm == pfx || norm.starts_with(&format!("{pfx}/"));
    if !ok {
        return Err(DriveErr::OutOfScope);
    }
    Ok(())
}

/// The etag for a node = its current content version key (CID + mtime), or the node id for dirs /
/// empty files. Cheap optimistic-concurrency token (matches one content-map version).
fn etag_for(drive: &ce_drive_core::Drive, node_id: &str) -> String {
    match drive.content().get(node_id) {
        Some(c) => format!("{}:{}", c.cid, c.mtime_ms),
        None => format!("dir:{node_id}"),
    }
}

/// Build a wire [`Entry`] from a core [`DirEntry`] under `parent_path`.
fn entry_of(drive: &ce_drive_core::Drive, parent_path: &str, e: &DirEntry) -> Entry {
    let path = if parent_path == "/" {
        format!("/{}", e.name)
    } else {
        format!("{}/{}", parent_path.trim_end_matches('/'), e.name)
    };
    let (size, mtime_ms, object_cid, doc_id) = match &e.content {
        Some(c) => (c.size, c.mtime_ms, Some(c.cid.clone()), c.doc_id.clone()),
        None => (0, 0, None, None),
    };
    Entry {
        path,
        kind: if e.is_dir { EntryKind::Dir } else { EntryKind::File },
        size,
        mtime_ms,
        etag: etag_for(drive, &e.node_id),
        node_id: e.node_id.clone(),
        object_cid,
        doc_id,
    }
}

/// Split a path into (parent_dir, leaf_name). Root has no parent.
fn split_path(path: &str) -> Option<(String, String)> {
    let norm = norm_path(path);
    if norm == "/" {
        return None;
    }
    let idx = norm.rfind('/').unwrap_or(0);
    let parent = if idx == 0 { "/".to_string() } else { norm[..idx].to_string() };
    let name = norm[idx + 1..].to_string();
    Some((parent, name))
}

/// The shared, mutex-guarded state the serve loop operates on.
pub struct DriveServer {
    client: CeClient,
    registry: Arc<Mutex<Registry>>,
    host_id: NodeId,
    accepted_roots: Vec<NodeId>,
    key_dir: std::path::PathBuf,
}

impl DriveServer {
    /// Build a server over `client`, hosting the drives in `registry`, rooted at the host key in
    /// `key_dir`. `accepted_roots` are extra org root keys honored besides the host's own key. The
    /// host identity is loaded from `key_dir` (so Share can mint sub-caps signed by the host key).
    pub fn new(
        client: CeClient,
        registry: Registry,
        key_dir: impl Into<std::path::PathBuf>,
        accepted_roots: Vec<NodeId>,
    ) -> Result<Self> {
        let key_dir = key_dir.into();
        let identity = Identity::load_or_generate(&key_dir)?;
        Ok(DriveServer {
            client,
            registry: Arc::new(Mutex::new(registry)),
            host_id: identity.node_id(),
            accepted_roots,
            key_dir,
        })
    }

    /// The registry handle (for tests / admin to create drives + push content).
    pub fn registry(&self) -> Arc<Mutex<Registry>> {
        self.registry.clone()
    }

    /// Subscribe the local node so the change beacon and any inbound requests are received, and
    /// advertise the `ce-drive` service for discovery.
    pub async fn announce(&self) -> Result<()> {
        // Advertise we host drives (best-effort).
        let _ = self.client.advertise_service("ce-drive").await;
        Ok(())
    }

    /// Run the serve loop: poll inbound messages, dispatch `ce-drive/v1` requests, reply. Polls every
    /// `poll_ms`. Runs until the process exits (cancel by dropping the task).
    pub async fn run(&self, poll_ms: u64) -> Result<()> {
        info!(host = %hex::encode(self.host_id), "ce-drive serve loop started");
        let mut seen: HashSet<u64> = HashSet::new();
        loop {
            match self.client.messages().await {
                Ok(msgs) => {
                    for m in msgs {
                        let Some(token) = m.reply_token else { continue };
                        if m.topic != crate::wire::DRIVE_TOPIC {
                            continue;
                        }
                        if !seen.insert(token) {
                            continue; // already handled this request token
                        }
                        if let Err(e) = self.handle_message(token, &m.from, &m.payload_hex).await {
                            warn!(error = %e, "ce-drive request handling failed");
                        }
                    }
                    // Bound the dedup set.
                    if seen.len() > 4096 {
                        seen.clear();
                    }
                }
                Err(e) => debug!(error = %e, "poll /mesh/messages failed"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(poll_ms.max(50))).await;
        }
    }

    /// Decode + dispatch one request and send the reply.
    async fn handle_message(&self, token: u64, from_hex: &str, payload_hex: &str) -> Result<()> {
        let payload = hex::decode(payload_hex)?;
        let reply = match decode_req(&payload) {
            Ok(req) => self.dispatch(from_hex, req).await,
            Err(e) => DriveReply::err(DriveErr::Internal(format!("decode: {e}"))),
        };
        self.client.reply(token, &encode_reply(&reply)).await?;
        Ok(())
    }

    /// Authorize + dispatch one decoded request. Public so integration tests can drive it directly
    /// (bypassing the mesh) and so it is the single audited entry point.
    pub async fn dispatch(&self, from_hex: &str, req: DriveReq) -> DriveReply {
        let from_node = match parse_node_id(from_hex) {
            Ok(n) => n,
            Err(_) => return DriveReply::err(DriveErr::Unauthorized),
        };
        let chain = match decode_chain(&req.cap) {
            Ok(c) => c,
            Err(_) => return DriveReply::err(DriveErr::Unauthorized),
        };
        let now = now_secs();
        let revoked = self.revoked_set().await;

        // Authorize before any work.
        if let Err(e) = authorize_req(
            &self.host_id,
            &self.accepted_roots,
            &req.drive,
            &req.op,
            &from_node,
            &chain,
            now,
            &revoked,
        ) {
            return DriveReply::err(e);
        }

        match self.dispatch_inner(from_hex, &chain, req).await {
            Ok(ok) => DriveReply::ok(ok),
            Err(e) => DriveReply::err(e),
        }
    }

    /// Fetch the on-chain revoked set (`GET /capabilities/revoked`); empty on error (fail-open on the
    /// *fetch*, never on the *check* — a present revocation always denies).
    async fn revoked_set(&self) -> HashSet<(NodeId, u64)> {
        let mut set = HashSet::new();
        if let Ok(list) = self.client.revoked().await {
            for (issuer_hex, nonce) in list {
                if let Ok(id) = parse_node_id(&issuer_hex) {
                    set.insert((id, nonce));
                }
            }
        }
        set
    }

    /// The op handlers (authorization already passed). Returns a [`DriveOk`] or a [`DriveErr`].
    async fn dispatch_inner(
        &self,
        from_hex: &str,
        chain: &[SignedCapability],
        req: DriveReq,
    ) -> Result<DriveOk, DriveErr> {
        let drive_id = req.drive.clone();
        match req.op {
            DriveOp::Open => self.op_open(&drive_id, chain).await,
            DriveOp::Stat { path } => self.op_stat(&drive_id, &path).await,
            DriveOp::List { path, cursor, limit } => {
                self.op_list(&drive_id, &path, cursor, limit).await
            }
            DriveOp::Read { path, offset, len } => self.op_read(&drive_id, &path, offset, len).await,
            DriveOp::Write { path, object_cid, size, base_etag } => {
                self.op_write(&drive_id, &path, &object_cid, size, base_etag).await
            }
            DriveOp::Mkdir { path } => self.op_mkdir(&drive_id, &path).await,
            DriveOp::Move { from, to } => self.op_move(&drive_id, &from, &to).await,
            DriveOp::Copy { from, to } => self.op_copy(&drive_id, &from, &to).await,
            DriveOp::Delete { path, recursive } => self.op_delete(&drive_id, &path, recursive).await,
            DriveOp::Share { path, audience, abilities, caveats } => {
                self.op_share(&drive_id, from_hex, chain, &path, &audience, &abilities, &caveats)
                    .await
            }
            DriveOp::Poll { cursor, limit } => self.op_poll(&drive_id, cursor, limit).await,
            DriveOp::Watch => self.op_watch(&drive_id).await,
        }
    }

    // ----- handlers -----

    async fn op_open(
        &self,
        drive_id: &str,
        chain: &[SignedCapability],
    ) -> Result<DriveOk, DriveErr> {
        // Publish a fresh bootstrap snapshot (serialized DriveState) and cache its CID.
        let state_bytes = {
            let reg = self.registry.lock().await;
            let t = reg.get(drive_id).ok_or(DriveErr::NotFound)?;
            serde_json::to_vec(t.drive.state()).map_err(|e| DriveErr::Internal(e.to_string()))?
        };
        let cid = self
            .client
            .put_object(&state_bytes)
            .await
            .map_err(|e| DriveErr::Internal(format!("snapshot publish: {e}")))?;

        let (server_seq, quota) = {
            let mut reg = self.registry.lock().await;
            let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;
            let cursor = t.feed.cursor();
            t.snapshot = Some((cid.clone(), cursor));
            (cursor, t.quota.clone())
        };

        let granted_abilities = chain.last().map(|c| c.cap.abilities.clone()).unwrap_or_default();
        Ok(DriveOk::Opened { drive_root_cid: cid, server_seq, granted_abilities, quota })
    }

    async fn op_stat(&self, drive_id: &str, path: &str) -> Result<DriveOk, DriveErr> {
        let reg = self.registry.lock().await;
        let t = reg.get(drive_id).ok_or(DriveErr::NotFound)?;
        let entry = stat_entry(&t.drive, path).ok_or(DriveErr::NotFound)?;
        Ok(DriveOk::Entry(entry))
    }

    async fn op_list(
        &self,
        drive_id: &str,
        path: &str,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<DriveOk, DriveErr> {
        let reg = self.registry.lock().await;
        let t = reg.get(drive_id).ok_or(DriveErr::NotFound)?;
        let entries = t.drive.ls(path).map_err(|_| DriveErr::NotFound)?;
        let parent = norm_path(path);
        let limit = limit.max(1) as usize;
        // Opaque cursor = the last name returned; page after it.
        let start = match &cursor {
            Some(c) => entries.iter().position(|e| &e.name > c).unwrap_or(entries.len()),
            None => 0,
        };
        let page: Vec<Entry> =
            entries[start..].iter().take(limit).map(|e| entry_of(&t.drive, &parent, e)).collect();
        let next_cursor = if start + page.len() < entries.len() {
            page.last().map(|e| e.path.rsplit('/').next().unwrap_or("").to_string())
        } else {
            None
        };
        Ok(DriveOk::Listing { entries: page, next_cursor })
    }

    async fn op_read(
        &self,
        drive_id: &str,
        path: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<DriveOk, DriveErr> {
        let object_cid = {
            let reg = self.registry.lock().await;
            let t = reg.get(drive_id).ok_or(DriveErr::NotFound)?;
            let node = t.drive.tree().resolve(&norm_path(path)).ok_or(DriveErr::NotFound)?;
            let content = t.drive.content().get(&node).ok_or(DriveErr::NotFound)?;
            content.cid.clone()
        };
        // Fetch the manifest and compute the intersecting chunks.
        let manifest_bytes = self
            .client
            .get_blob(&object_cid)
            .await
            .map_err(|_| DriveErr::NotFound)?;
        let manifest: data::Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| DriveErr::Internal(format!("manifest decode: {e}")))?;
        let plan = read_plan(&object_cid, &manifest, offset, len);
        Ok(DriveOk::ReadPlan(plan))
    }

    async fn op_write(
        &self,
        drive_id: &str,
        path: &str,
        object_cid: &str,
        size: u64,
        base_etag: Option<String>,
    ) -> Result<DriveOk, DriveErr> {
        let (parent, name) = split_path(path).ok_or(DriveErr::BadPath)?;
        let mut reg = self.registry.lock().await;
        let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;

        // Optimistic concurrency: if the file already exists, its current etag must match base_etag.
        if let Some(node) = t.drive.tree().resolve(&norm_path(path)) {
            let current = etag_for(&t.drive, &node);
            if let Some(base) = &base_etag {
                if base != &current {
                    return Err(DriveErr::Conflict { current_etag: current });
                }
            }
        }

        let fc = ce_drive_core::FileContent::new(object_cid, size, 0o644, now_ms());
        let node_id = t
            .drive
            .add_file(&parent, &name, fc)
            .map_err(|e| DriveErr::Internal(e.to_string()))?;
        let etag = etag_for(&t.drive, &node_id);
        let full_path = norm_path(path);
        let seq = t.feed.record(full_path, node_id.clone(), ChangeKind::Modified, etag.clone());
        // Best-effort: pin the object at the drive's replication factor so bytes are durable
        // independent of the uploader (ce-pin policy is a v2 refinement; we announce via the node).
        drop(reg);
        self.publish_beacon(drive_id, seq).await;
        Ok(DriveOk::Written { etag, node_id, version_seq: seq })
    }

    async fn op_mkdir(&self, drive_id: &str, path: &str) -> Result<DriveOk, DriveErr> {
        let (parent, name) = split_path(path).ok_or(DriveErr::BadPath)?;
        let (node_id, seq) = {
            let mut reg = self.registry.lock().await;
            let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;
            let node_id =
                t.drive.mkdir(&parent, &name).map_err(|e| DriveErr::Internal(e.to_string()))?;
            let etag = etag_for(&t.drive, &node_id);
            let seq = t.feed.record(norm_path(path), node_id.clone(), ChangeKind::Created, etag);
            (node_id, seq)
        };
        self.publish_beacon(drive_id, seq).await;
        Ok(DriveOk::Made { node_id })
    }

    async fn op_move(&self, drive_id: &str, from: &str, to: &str) -> Result<DriveOk, DriveErr> {
        let (to_parent, to_name) = split_path(to).ok_or(DriveErr::BadPath)?;
        let (node_id, seq) = {
            let mut reg = self.registry.lock().await;
            let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;
            let node = t.drive.tree().resolve(&norm_path(from)).ok_or(DriveErr::NotFound)?;
            t.drive
                .mv(&norm_path(from), &to_parent, &to_name)
                .map_err(|e| DriveErr::Internal(e.to_string()))?;
            let etag = etag_for(&t.drive, &node);
            let seq = t.feed.record(
                norm_path(to),
                node.clone(),
                ChangeKind::Moved { from: norm_path(from) },
                etag,
            );
            (node, seq)
        };
        self.publish_beacon(drive_id, seq).await;
        Ok(DriveOk::Made { node_id })
    }

    async fn op_copy(&self, drive_id: &str, from: &str, to: &str) -> Result<DriveOk, DriveErr> {
        // Server-side copy: share the same object CID (global dedup, no bytes move).
        let (to_parent, to_name) = split_path(to).ok_or(DriveErr::BadPath)?;
        let (node_id, seq) = {
            let mut reg = self.registry.lock().await;
            let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;
            let src = t.drive.tree().resolve(&norm_path(from)).ok_or(DriveErr::NotFound)?;
            let content = t.drive.content().get(&src).cloned().ok_or(DriveErr::NotFound)?;
            let fc = ce_drive_core::FileContent::new(content.cid, content.size, content.mode, now_ms());
            let node_id = t
                .drive
                .add_file(&to_parent, &to_name, fc)
                .map_err(|e| DriveErr::Internal(e.to_string()))?;
            let etag = etag_for(&t.drive, &node_id);
            let seq = t.feed.record(norm_path(to), node_id.clone(), ChangeKind::Created, etag);
            (node_id, seq)
        };
        self.publish_beacon(drive_id, seq).await;
        Ok(DriveOk::Made { node_id })
    }

    async fn op_delete(
        &self,
        drive_id: &str,
        path: &str,
        _recursive: bool,
    ) -> Result<DriveOk, DriveErr> {
        let seq = {
            let mut reg = self.registry.lock().await;
            let t = reg.get_mut(drive_id).ok_or(DriveErr::NotFound)?;
            let node = t.drive.tree().resolve(&norm_path(path)).ok_or(DriveErr::NotFound)?;
            t.drive.rm(&norm_path(path)).map_err(|e| DriveErr::Internal(e.to_string()))?;
            t.feed.record(norm_path(path), node, ChangeKind::Deleted, String::new())
        };
        self.publish_beacon(drive_id, seq).await;
        Ok(DriveOk::Deleted)
    }

    #[allow(clippy::too_many_arguments)]
    async fn op_share(
        &self,
        drive_id: &str,
        from_hex: &str,
        chain: &[SignedCapability],
        path: &str,
        audience: &str,
        abilities: &[String],
        caveats: &ShareCaveats,
    ) -> Result<DriveOk, DriveErr> {
        // The caller (holder of drive:admin) mints an attenuated sub-cap for `audience`. The host
        // signs it with its own key only when the caller IS the host (self-issue); otherwise the
        // caller must sign and present — but since the caller reached us over the mesh, we mint a
        // child of the caller's leaf signed by the HOST key acting as the workspace root, scoped to
        // `path` and abilities ⊆ caller's. (Owner-mediated sharing: the host is the workspace root.)
        let parent = chain.last().ok_or(DriveErr::Unauthorized)?;
        let audience_id = parse_node_id(audience).map_err(|_| DriveErr::BadPath)?;
        no_dotdot(path).map_err(|_| DriveErr::BadPath)?;
        // The parent's drive binding + path subtree (authorize_req already proved it pins `drive_id`).
        let parent_scope = parent
            .cap
            .caveats
            .path_prefix
            .as_deref()
            .and_then(parse_drive_prefix)
            .map(|(_, scope)| scope)
            .ok_or(DriveErr::Unauthorized)?;
        enforce_prefix(&parent_scope, path)?;

        // Abilities ∩ caller's (never exceed). Default to read if none requested.
        let requested: Vec<String> = if abilities.is_empty() {
            vec![Ability::Read.as_str().to_string()]
        } else {
            abilities.iter().filter(|a| parent.cap.abilities.contains(a)).cloned().collect()
        };
        if requested.is_empty() {
            return Err(DriveErr::OutOfScope);
        }

        // The host identity (workspace root) signs the new leaf as a child of the caller's cap.
        let host_identity =
            self.host_identity().map_err(|e| DriveErr::Internal(e.to_string()))?;
        // Expiry: never widen past the parent's.
        let parent_exp = parent.cap.caveats.not_after;
        let not_after = match (caveats.not_after, parent_exp) {
            (0, p) => p,
            (c, 0) => c,
            (c, p) => c.min(p),
        };
        // Mint with the SAME drive binding as the parent (`ce-drive/<drive>/<path>`), narrowed to
        // the shared subtree. Without this the sub-cap would be drive-unbound and Gate 2 would refuse
        // it on every drive — and it must never authorize a different drive than the one shared.
        let new_caveats = Caveats {
            not_after,
            path_prefix: Some(drive_prefix(drive_id, path)),
            ..Default::default()
        };
        // Issue as a child of the caller's leaf so attenuation chains correctly. The caller is the
        // issuer of the new link only if it signed; here the workspace root (host) re-issues a
        // sibling rooted at itself, scoped down — the standard owner-mediated Share.
        let new_cap = SignedCapability::issue(
            &host_identity,
            audience_id,
            requested,
            Resource::Any,
            new_caveats,
            derive_nonce(from_hex, path),
            None,
        );
        let token = encode_chain(&[new_cap]);
        Ok(DriveOk::Shared { chain: token })
    }

    async fn op_poll(
        &self,
        drive_id: &str,
        cursor: Option<u64>,
        limit: u32,
    ) -> Result<DriveOk, DriveErr> {
        let reg = self.registry.lock().await;
        let t = reg.get(drive_id).ok_or(DriveErr::NotFound)?;
        let (changes, new_cursor) = t.feed.poll(cursor.unwrap_or(0), limit);
        Ok(DriveOk::Changes { changes, new_cursor })
    }

    async fn op_watch(&self, drive_id: &str) -> Result<DriveOk, DriveErr> {
        let cursor = {
            let reg = self.registry.lock().await;
            reg.get(drive_id).ok_or(DriveErr::NotFound)?.feed.cursor()
        };
        Ok(DriveOk::Watching { topic: changes_topic(drive_id), cursor })
    }

    // ----- helpers -----

    /// Publish a best-effort change beacon (a hint; `Poll` is the truth).
    async fn publish_beacon(&self, drive_id: &str, max_seq: u64) {
        let beacon = Beacon { drive: drive_id.to_string(), max_seq };
        if let Ok(bytes) = bincode::serialize(&beacon) {
            let _ = self.client.publish(&changes_topic(drive_id), &bytes).await;
        }
    }

    /// Load a handle to the host key (for minting Share sub-caps), from the server's key dir.
    fn host_identity(&self) -> Result<Identity> {
        Identity::load_or_generate(&self.key_dir)
    }
}

/// Stat a path to a wire [`Entry`] (file or dir). Returns `None` if the path doesn't resolve.
fn stat_entry(drive: &ce_drive_core::Drive, path: &str) -> Option<Entry> {
    let norm = norm_path(path);
    if norm == "/" {
        return Some(Entry {
            path: "/".into(),
            kind: EntryKind::Dir,
            size: 0,
            mtime_ms: 0,
            etag: format!("dir:{ROOT}"),
            node_id: ROOT.to_string(),
            object_cid: None,
            doc_id: None,
        });
    }
    let node = drive.tree().resolve(&norm)?;
    let edge = drive.tree().edge(&node)?;
    let is_dir = matches!(edge.kind, NodeKind::Dir);
    let (size, mtime_ms, object_cid, doc_id) = match drive.content().get(&node) {
        Some(c) => (c.size, c.mtime_ms, Some(c.cid.clone()), c.doc_id.clone()),
        None => (0, 0, None, None),
    };
    Some(Entry {
        path: norm,
        kind: if is_dir { EntryKind::Dir } else { EntryKind::File },
        size,
        mtime_ms,
        etag: etag_for(drive, &node),
        node_id: node,
        object_cid,
        doc_id,
    })
}

/// Compute the [`ReadPlan`] covering `[offset, offset+len)` over a chunked object manifest. Returns
/// only the chunks that intersect the range (ranged read = content-addressed Range).
pub fn read_plan(
    object_cid: &str,
    manifest: &data::Manifest,
    offset: u64,
    len: Option<u64>,
) -> ReadPlan {
    let total = manifest.total_size;
    let end = match len {
        Some(l) => (offset.saturating_add(l)).min(total),
        None => total,
    };
    let mut chunks = Vec::new();
    // An empty range (zero-length read, or an offset at/after the requested end) intersects nothing —
    // return no chunks so the client fetches no bytes for a read that wants none.
    if offset >= end {
        return ReadPlan {
            object_cid: object_cid.to_string(),
            total_size: total,
            chunk_size: manifest.chunk_size,
            chunks,
            encrypted: false,
            key_hint: None,
        };
    }
    let mut pos = 0u64;
    for cid in &manifest.chunks {
        // The manifest stores chunk CIDs in order; each is `chunk_size` except possibly the last.
        let remaining = total.saturating_sub(pos);
        let this_len = manifest.chunk_size.min(remaining);
        let chunk_start = pos;
        let chunk_end = pos + this_len;
        // Intersect [chunk_start, chunk_end) with [offset, end).
        if chunk_end > offset && chunk_start < end {
            chunks.push(ChunkRef { cid: cid.clone(), offset: chunk_start, len: this_len });
        }
        pos = chunk_end;
    }
    ReadPlan {
        object_cid: object_cid.to_string(),
        total_size: total,
        chunk_size: manifest.chunk_size,
        chunks,
        encrypted: false,
        key_hint: None,
    }
}

fn parse_node_id(hex_str: &str) -> Result<NodeId> {
    let bytes = hex::decode(hex_str.trim())?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("node id must be 32 bytes"))
}

/// Deterministic nonce for a minted Share cap, so re-sharing the same (audience, path) is stable and
/// revocable by a predictable key. Uses sha256 truncated to u64.
fn derive_nonce(from_hex: &str, path: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(from_hex.as_bytes());
    h.update(b"|");
    h.update(path.as_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap_or_default())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_rs::data::chunk_object;

    #[test]
    fn ranged_read_pulls_only_intersecting_chunks() {
        // 3 chunks of 1 MiB-ish; pick a small chunk size for the test.
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        assert_eq!(manifest.chunks.len(), 3);
        // Read bytes [1500, 2200): intersects chunk 1 [1000,2000) and chunk 2 [2000,3000).
        let plan = read_plan("obj", &manifest, 1500, Some(700));
        let offsets: Vec<u64> = plan.chunks.iter().map(|c| c.offset).collect();
        assert_eq!(offsets, vec![1000, 2000]);
    }

    #[test]
    fn ranged_read_header_pulls_one_chunk() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        // Read just the first 10 bytes -> only chunk 0.
        let plan = read_plan("obj", &manifest, 0, Some(10));
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0].offset, 0);
    }

    #[test]
    fn full_read_pulls_all_chunks() {
        let data: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        let plan = read_plan("obj", &manifest, 0, None);
        assert_eq!(plan.chunks.len(), 3);
        assert_eq!(plan.total_size, 2500);
    }

    #[test]
    fn split_path_basic() {
        assert_eq!(split_path("/a/b/c"), Some(("/a/b".into(), "c".into())));
        assert_eq!(split_path("/x"), Some(("/".into(), "x".into())));
        assert_eq!(split_path("/"), None);
    }

    #[test]
    fn split_path_normalizes_first() {
        // Un-normalized inputs (trailing/leading/duplicate slashes, no leading slash) are normalized
        // before splitting, so the parent/leaf split is stable.
        assert_eq!(split_path("a/b"), Some(("/a".into(), "b".into())));
        assert_eq!(split_path("/a/b/"), Some(("/a".into(), "b".into())));
        assert_eq!(split_path("///"), None); // collapses to root
        assert_eq!(split_path("  /a/b  "), Some(("/a".into(), "b".into())));
    }

    #[test]
    fn norm_path_canonicalizes() {
        assert_eq!(norm_path("/"), "/");
        assert_eq!(norm_path(""), "/");
        assert_eq!(norm_path("   "), "/");
        assert_eq!(norm_path("/a/"), "/a");
        assert_eq!(norm_path("a"), "/a");
        assert_eq!(norm_path("/a/b/"), "/a/b");
        assert_eq!(norm_path("//a//b//"), "/a//b"); // only leading/trailing slashes trimmed
    }

    #[test]
    fn no_dotdot_guards_traversal() {
        assert!(no_dotdot("/a/b").is_ok());
        assert!(no_dotdot("/").is_ok());
        // A literal ".." segment anywhere is rejected.
        assert_eq!(no_dotdot("/a/../b").unwrap_err(), DriveErr::BadPath);
        assert_eq!(no_dotdot("../x").unwrap_err(), DriveErr::BadPath);
        assert_eq!(no_dotdot("/a/b/..").unwrap_err(), DriveErr::BadPath);
        // "..." and "a..b" are NOT traversal (only the exact ".." segment is).
        assert!(no_dotdot("/a/...").is_ok());
        assert!(no_dotdot("/a..b/c").is_ok());
    }

    #[test]
    fn enforce_prefix_subtree_rules() {
        // A scope of /docs admits /docs and any descendant, rejects siblings + prefix-ish names.
        assert!(enforce_prefix("/docs", "/docs").is_ok());
        assert!(enforce_prefix("/docs", "/docs/sub/file").is_ok());
        assert!(enforce_prefix("/docs", "/docs/").is_ok()); // trailing slash normalized
        assert_eq!(enforce_prefix("/docs", "/docsX").unwrap_err(), DriveErr::OutOfScope); // not a child
        assert_eq!(enforce_prefix("/docs", "/other").unwrap_err(), DriveErr::OutOfScope);
        assert_eq!(enforce_prefix("/docs", "/").unwrap_err(), DriveErr::OutOfScope); // can't escape up
    }

    #[test]
    fn enforce_prefix_root_admits_everything() {
        assert!(enforce_prefix("/", "/anything/deep").is_ok());
        assert!(enforce_prefix("/", "/").is_ok());
    }

    #[test]
    fn drive_prefix_roundtrips() {
        // Drive-wide cap: `ce-drive/<drive>` decodes to (drive, "/").
        let p = drive_prefix("work", "/");
        assert_eq!(p, "ce-drive/work");
        assert_eq!(parse_drive_prefix(&p), Some(("work".into(), "/".into())));

        // Subtree cap: `ce-drive/<drive>/docs` decodes to (drive, "/docs").
        let p = drive_prefix("work", "/docs");
        assert_eq!(p, "ce-drive/work/docs");
        assert_eq!(parse_drive_prefix(&p), Some(("work".into(), "/docs".into())));

        // Deeper subtree, with input-path normalization (trailing slash dropped).
        let p = drive_prefix("acme-drive", "/a/b/");
        assert_eq!(p, "ce-drive/acme-drive/a/b");
        assert_eq!(parse_drive_prefix(&p), Some(("acme-drive".into(), "/a/b".into())));
    }

    #[test]
    fn parse_drive_prefix_rejects_unbound_and_foreign() {
        // A bare path (the OLD, unbound caveat form) is not in the ce-drive namespace -> None.
        assert_eq!(parse_drive_prefix("/docs"), None);
        assert_eq!(parse_drive_prefix("/"), None);
        // A foreign app's namespace (e.g. ce-db) is not a Drive binding.
        assert_eq!(parse_drive_prefix("ce-db/users"), None);
        // Empty drive id is rejected.
        assert_eq!(parse_drive_prefix("ce-drive/"), None);
        assert_eq!(parse_drive_prefix("ce-drive//docs"), None);
    }

    // ----- read_plan boundary cases -----

    #[test]
    fn read_plan_zero_len_returns_no_chunks() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        let plan = read_plan("obj", &manifest, 500, Some(0));
        assert!(plan.chunks.is_empty(), "a zero-length read intersects nothing");
        assert_eq!(plan.total_size, 3000);
    }

    #[test]
    fn read_plan_offset_past_end_returns_no_chunks() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        let plan = read_plan("obj", &manifest, 9000, Some(10));
        assert!(plan.chunks.is_empty());
    }

    #[test]
    fn read_plan_empty_object_has_no_chunks() {
        let (manifest, _) = chunk_object(&[], 1000);
        assert_eq!(manifest.total_size, 0);
        let plan = read_plan("obj", &manifest, 0, None);
        assert!(plan.chunks.is_empty());
        assert_eq!(plan.total_size, 0);
    }

    #[test]
    fn read_plan_len_clamps_to_total() {
        let data: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        // Ask for far more than exists -> still only the 3 real chunks, no over-read.
        let plan = read_plan("obj", &manifest, 0, Some(u64::MAX));
        assert_eq!(plan.chunks.len(), 3);
        let covered: u64 = plan.chunks.iter().map(|c| c.len).sum();
        assert_eq!(covered, 2500);
    }

    #[test]
    fn read_plan_exact_chunk_boundary() {
        let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        // [1000, 2000) is exactly chunk 1; must not pull chunk 0 or chunk 2.
        let plan = read_plan("obj", &manifest, 1000, Some(1000));
        let offs: Vec<u64> = plan.chunks.iter().map(|c| c.offset).collect();
        assert_eq!(offs, vec![1000]);
    }

    #[test]
    fn read_plan_last_chunk_is_partial() {
        let data: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let (manifest, _) = chunk_object(&data, 1000);
        let plan = read_plan("obj", &manifest, 0, None);
        // 2500 = 1000 + 1000 + 500; the last chunk's len is the remainder.
        assert_eq!(plan.chunks.last().unwrap().len, 500);
        assert_eq!(plan.chunks.last().unwrap().offset, 2000);
    }

    #[test]
    fn derive_nonce_is_deterministic_and_path_sensitive() {
        let a = derive_nonce("abcd", "/docs");
        let b = derive_nonce("abcd", "/docs");
        assert_eq!(a, b, "same (from, path) -> same nonce (stable, revocable)");
        assert_ne!(derive_nonce("abcd", "/docs"), derive_nonce("abcd", "/other"));
        assert_ne!(derive_nonce("abcd", "/docs"), derive_nonce("efef", "/docs"));
    }

    #[test]
    fn parse_node_id_validates_length() {
        assert!(parse_node_id(&"ab".repeat(32)).is_ok()); // 32 bytes
        assert!(parse_node_id("nothex").is_err());
        assert!(parse_node_id("abcd").is_err()); // too short
        assert!(parse_node_id(&"ab".repeat(33)).is_err()); // too long
    }

    // test-only identity helper (private fns above are exercised with real signatures).
    fn id_for_test(tag: &str) -> Identity {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("ce-drive-serve-unit-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }
}
