//! The `ce-drive/v1` wire protocol — the request/reply envelope for the mesh-facing Drive API.
//!
//! Every metadata operation is one [`DriveReq`] sent as an `AppRequest` on the topic
//! [`DRIVE_TOPIC`]; the host answers with one [`DriveReply`]. Bulk bytes never travel here — a
//! [`DriveOp::Read`] returns a [`ReadPlan`] (chunk CIDs) and the client fetches the chunks directly
//! from the content-addressed blob store, so the metadata host can stay stateless and need never
//! hold the bytes.
//!
//! These types are `bincode`-encoded on the wire (deterministic, compact). The host authenticates
//! `from_node` for free (Noise/PeerId, verified by the local node); the app authorizes by verifying
//! the attached `cap` chain against `(op, path)`.

use serde::{Deserialize, Serialize};

/// The mesh request topic every Drive host listens on.
pub const DRIVE_TOPIC: &str = "ce-drive/v1";

/// The pubsub change-beacon topic for one drive (host publishes `{drive, max_seq}` on advance).
pub fn changes_topic(drive_id: &str) -> String {
    format!("ce-drive/{drive_id}/changes")
}

/// One metadata request. `cap` is the base64/hex ce-cap chain whose leaf audience MUST equal the
/// authenticated `from_node`; the host verifies it before doing anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveReq {
    /// Drive-id on the host (one host may serve many drives).
    pub drive: String,
    /// Hex-encoded ce-cap chain (root-first), as produced by `ce_cap::encode_chain`.
    pub cap: String,
    /// The operation to perform.
    pub op: DriveOp,
}

/// The closed set of metadata operations. Every Google Drive / WebDAV / S3 / 9P verb maps onto one
/// of these, and none of them requires the node to enforce anything as a primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriveOp {
    /// Handshake: returns the drive root snapshot, the host's current change cursor, the abilities
    /// the cap actually carries, and the quota/billing terms. Cheap, idempotent, no state created.
    Open,
    /// Stat one path -> one [`Entry`].
    Stat { path: String },
    /// List a directory page (opaque continuation `cursor`, `limit`-bounded).
    List { path: String, cursor: Option<String>, limit: u32 },
    /// Resolve a ranged read to a [`ReadPlan`] (chunk CIDs), not bytes.
    Read { path: String, offset: u64, len: Option<u64> },
    /// Commit `path -> object_cid` in the content map, with optimistic concurrency on `base_etag`.
    Write { path: String, object_cid: String, size: u64, base_etag: Option<String> },
    /// Create a directory.
    Mkdir { path: String },
    /// Rename/move a node (one O(1) edge flip; descendants follow).
    Move { from: String, to: String },
    /// Server-side copy (free — shares chunk CIDs via global dedup).
    Copy { from: String, to: String },
    /// Move a node to TRASH (content retained until GC).
    Delete { path: String, recursive: bool },
    /// Mint an attenuated sub-capability for `audience`, scoped to `path`.
    Share { path: String, audience: String, abilities: Vec<String>, caveats: ShareCaveats },
    /// The authoritative change feed: deltas since `cursor` (a monotonic seq), `limit`-bounded.
    Poll { cursor: Option<u64>, limit: u32 },
    /// Returns the pubsub beacon topic + the client's current cursor.
    Watch,
}

/// The caveats a [`DriveOp::Share`] attaches to the minted sub-capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShareCaveats {
    /// Unix seconds the grant expires (0 = inherit/never).
    pub not_after: u64,
    /// Optional egress quota ceiling (attenuates monotonically).
    pub max_bytes_read: Option<u64>,
    /// Optional storage quota ceiling.
    pub max_bytes_write: Option<u64>,
}

/// The reply, encoded as a `Result` so the error code survives bincode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveReply {
    pub result: Result<DriveOk, DriveErr>,
}

impl DriveReply {
    pub fn ok(ok: DriveOk) -> Self {
        DriveReply { result: Ok(ok) }
    }
    pub fn err(err: DriveErr) -> Self {
        DriveReply { result: Err(err) }
    }
}

/// A successful operation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriveOk {
    /// `Open` reply: bootstrap info for the client.
    Opened {
        /// CID of a serialized snapshot the client can bootstrap a DriveTree replica from.
        drive_root_cid: String,
        /// The host's current change cursor (origin for the change feed).
        server_seq: u64,
        /// The abilities the presented cap actually carries (so the UI greys out what it can't do).
        granted_abilities: Vec<String>,
        /// The quota / billing terms.
        quota: Quota,
    },
    Entry(Entry),
    Listing { entries: Vec<Entry>, next_cursor: Option<String> },
    ReadPlan(ReadPlan),
    Written { etag: String, node_id: String, version_seq: u64 },
    /// mkdir/move/copy -> the stable NodeId of the affected node.
    Made { node_id: String },
    Deleted,
    /// `Share` reply: the base64/hex EXTENDED ce-cap chain for the audience.
    Shared { chain: String },
    Changes { changes: Vec<Change>, new_cursor: u64 },
    Watching { topic: String, cursor: u64 },
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_ms: u64,
    /// The content-map version key — a cheap optimistic-concurrency token for `Write`.
    pub etag: String,
    /// The stable DriveTree NodeId (identity across renames).
    pub node_id: String,
    /// None for dirs / files with no content yet.
    pub object_cid: Option<String>,
    /// Set for embedded ce-notes `.cedoc` nodes.
    pub doc_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
}

/// The plan for a ranged read: the manifest CID plus the chunk refs covering `[offset, offset+len)`.
/// The client fetches these chunks directly from the data layer and verifies each against its CID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadPlan {
    pub object_cid: String,
    pub total_size: u64,
    pub chunk_size: u64,
    /// The chunks (with absolute object offsets) that intersect the requested range.
    pub chunks: Vec<ChunkRef>,
    pub encrypted: bool,
    /// Names which read-key generation decrypts the chunks (never the key itself).
    pub key_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub cid: String,
    /// Absolute offset of this chunk within the object.
    pub offset: u64,
    pub len: u64,
}

/// One change-feed delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub seq: u64,
    pub path: String,
    pub node_id: String,
    pub kind: ChangeKind,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
    Moved { from: String },
}

/// The quota / billing terms a host advertises in `Open`. Amounts are base-unit decimal strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Quota {
    /// Price per GiB-month of storage (base-unit decimal string, "0" = free).
    pub price_per_gib_month: String,
    /// Price per GiB of egress (base-unit decimal string, "0" = free).
    pub price_per_gib_egress: String,
    /// Free-tier bytes before metering kicks in.
    pub free_tier_bytes: u64,
    /// Whether a payment channel is required before write/egress.
    pub channel_required: bool,
}

/// A stable numeric error code carried on the wire alongside a human reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriveErr {
    Unauthorized,
    Revoked,
    Expired,
    OutOfScope,
    NotFound,
    /// Optimistic-concurrency clash on Write.
    Conflict { current_etag: String },
    QuotaExceeded,
    PaymentRequired,
    BadPath,
    Internal(String),
}

impl DriveErr {
    /// A stable numeric code for clients that don't decode the variant.
    pub fn code(&self) -> u16 {
        match self {
            DriveErr::Unauthorized => 401,
            DriveErr::Revoked => 410,
            DriveErr::Expired => 419,
            DriveErr::OutOfScope => 403,
            DriveErr::NotFound => 404,
            DriveErr::Conflict { .. } => 409,
            DriveErr::QuotaExceeded => 429,
            DriveErr::PaymentRequired => 402,
            DriveErr::BadPath => 400,
            DriveErr::Internal(_) => 500,
        }
    }
}

impl std::fmt::Display for DriveErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriveErr::Unauthorized => write!(f, "unauthorized"),
            DriveErr::Revoked => write!(f, "capability revoked"),
            DriveErr::Expired => write!(f, "capability expired"),
            DriveErr::OutOfScope => write!(f, "path outside granted scope"),
            DriveErr::NotFound => write!(f, "not found"),
            DriveErr::Conflict { current_etag } => write!(f, "conflict (current etag {current_etag})"),
            DriveErr::QuotaExceeded => write!(f, "quota exceeded"),
            DriveErr::PaymentRequired => write!(f, "payment required"),
            DriveErr::BadPath => write!(f, "bad path"),
            DriveErr::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for DriveErr {}

/// A tiny change beacon published on [`changes_topic`] when a drive advances. The client polls on
/// wake; the beacon is only a hint (gossip is lossy by design).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon {
    pub drive: String,
    pub max_seq: u64,
}

/// Encode a request to bincode bytes.
pub fn encode_req(req: &DriveReq) -> Vec<u8> {
    bincode::serialize(req).unwrap_or_default()
}

/// Decode a request from bincode bytes.
pub fn decode_req(bytes: &[u8]) -> anyhow::Result<DriveReq> {
    bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("malformed DriveReq: {e}"))
}

/// Encode a reply to bincode bytes.
pub fn encode_reply(reply: &DriveReply) -> Vec<u8> {
    bincode::serialize(reply).unwrap_or_default()
}

/// Decode a reply from bincode bytes.
pub fn decode_reply(bytes: &[u8]) -> anyhow::Result<DriveReply> {
    bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("malformed DriveReply: {e}"))
}
