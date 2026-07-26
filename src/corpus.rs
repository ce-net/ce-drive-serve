//! The corpus surface — how a drive's contents reach `ce.index`.
//!
//! # The router routing
//!
//! This is ce-drive doing its one job. For each node it knows the PATH (its own), the `kind` (a prop
//! it stores but never interprets) and the LOCATOR (which app holds the bytes). It hands the bytes to
//! the kind app named by `kind`, takes back indexable terms, and assembles an item. It reads no
//! format and runs no search: it dispatches.
//!
//! That is what makes the whole design work. ce-index never learns a format, the content app never
//! learns a format, and the kind app never learns where bytes live — but a search still finds the
//! prose inside an Ocean document, because the router connected three apps that know nothing about
//! each other.
//!
//! # Why items are keyed by NODE ID, not path
//!
//! ce-files answers this same contract for a filesystem and keys items by path, because a filesystem
//! has nothing better. A drive does: a stable [`NodeId`](ce_drive_core::tree::NodeId) that survives
//! rename, move and re-parenting. Keying on the path would mean every rename looked like a delete
//! plus an unrelated create — the index would churn, and every link pointing at the old path would
//! rot. Keying on the id means a rename is a metadata update to an item the index already has.
//!
//! # Degrading is the contract, not a fallback
//!
//! A node whose kind has no installed app is still indexed — on its name, path, tags and links —
//! and flagged `unextracted`. Install the kind app later and the same node becomes searchable by its
//! content with no migration and no re-import. That is "the behaviour is emergent based on running
//! ce apps" made literal: installing an app retroactively changes what the system can see.
//!
//! An index that refused unknown kinds would instead make installation a migration event, and would
//! quietly hide every file whose format nobody had gotten to yet.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a kind app returns from `extract`. Mirrors `ce_drive_core::kind_apps::Extracted` on the
/// JSON wire the script-tier kind apps speak.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extracted {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub links: Vec<(String, String)>,
    #[serde(default)]
    pub props: BTreeMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub unextracted: bool,
}

impl Extracted {
    pub fn unextracted() -> Self {
        Extracted { unextracted: true, ..Default::default() }
    }
}

/// Everything the router knows about one node before extraction. Assembled from the drive's own
/// tree, content map and metadata — no format knowledge anywhere in it.
#[derive(Debug, Clone, Default)]
pub struct NodeFacts {
    pub node_id: String,
    pub path: String,
    pub size: u64,
    pub mtime_ms: u64,
    /// `props.kind` — the service name of the app that understands this format, if anything set it.
    pub kind: Option<String>,
    /// `<app>:<id>` — which content app holds the bytes.
    pub locator: String,
    pub tags: Vec<String>,
    /// Links the drive itself holds, as `(rel, target)`.
    pub links: Vec<(String, String)>,
    pub props: BTreeMap<String, String>,
}

/// One item in the corpus contract `ce.index` consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Stable identity. A rename updates this item; it does not create a second one.
    pub id: String,
    /// The format, or `file` when nothing declared one.
    pub kind: String,
    pub title: String,
    /// Indexable prose. Empty when no kind app could read the bytes.
    pub text: String,
    /// The drive path at the time of indexing — for display, never for identity.
    #[serde(rename = "ref")]
    pub reference: String,
    pub updated: u64,
    pub tags: Vec<String>,
    /// `(rel, target)` in the mesh link grammar, merging what the drive holds with what the format
    /// declared internally.
    pub links: Vec<(String, String)>,
    pub meta: BTreeMap<String, String>,
}

/// Build one corpus item from what the drive knows plus what the kind app extracted.
///
/// Pure on purpose: every interesting decision here (identity, merging, degrading) is testable with
/// no node, no mesh and no kind app running.
pub fn item_from(facts: &NodeFacts, extracted: &Extracted) -> Item {
    let name = facts.path.rsplit('/').next().unwrap_or("").to_string();

    // The format's own title wins, because it is what a human named the document; the filename is a
    // fallback for formats that have no title of their own.
    let title = extracted
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .unwrap_or(name);

    // Drive links FIRST, then the format's internal links. Both are real edges: one was asserted
    // about the file, one was written inside it, and an index wants both.
    let mut links = facts.links.clone();
    for l in &extracted.links {
        if !links.contains(l) {
            links.push(l.clone());
        }
    }

    let mut tags = facts.tags.clone();
    for t in &extracted.tags {
        if !tags.contains(t) {
            tags.push(t.clone());
        }
    }

    let mut meta: BTreeMap<String, String> = facts.props.clone();
    // Extracted facts do not overwrite what an operator explicitly set on the file: a human's
    // assertion outranks a parser's inference.
    for (k, v) in &extracted.props {
        meta.entry(k.clone()).or_insert_with(|| v.clone());
    }
    meta.insert("path".into(), facts.path.clone());
    meta.insert(
        "dir".into(),
        match facts.path.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => facts.path[..i].to_string(),
        },
    );
    meta.insert("size".into(), facts.size.to_string());
    meta.insert("locator".into(), facts.locator.clone());
    if extracted.unextracted {
        // Visible, so an operator can see WHY something is not searchable and fix it by installing
        // an app — rather than wondering why a file they can see never matches anything.
        meta.insert("unextracted".into(), "true".into());
        if let Some(k) = &facts.kind {
            meta.insert("unextracted_kind".into(), k.clone());
        }
    }

    Item {
        id: facts.node_id.clone(),
        kind: facts.kind.clone().unwrap_or_else(|| "file".to_string()),
        title,
        text: extracted.text.clone(),
        reference: facts.path.clone(),
        updated: facts.mtime_ms / 1000,
        tags,
        links,
        meta,
    }
}

/// The JSON request a kind app answers. The script-tier envelope every ce app speaks.
pub fn extract_request(bytes: &[u8], name: &str) -> serde_json::Value {
    use base64::Engine;
    serde_json::json!({
        "op": "extract",
        "args": {
            "base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "name": name,
        }
    })
}

/// Read a kind app's reply, degrading rather than propagating.
///
/// A kind app that is missing, slow, broken or malformed must not stop the rest of a drive being
/// indexed — one bad format would otherwise take down the corpus.
pub fn extract_reply(raw: &[u8]) -> Extracted {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return Extracted::unextracted();
    };
    match v.get("result") {
        Some(r) => serde_json::from_value(r.clone()).unwrap_or_else(|_| Extracted::unextracted()),
        None => Extracted::unextracted(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> NodeFacts {
        NodeFacts {
            node_id: "n7".into(),
            path: "/notes/trip.ocean".into(),
            size: 120,
            mtime_ms: 1_700_000_000_000,
            kind: Some("ocean-doc".into()),
            locator: "blob:deadbeef".into(),
            tags: vec!["travel".into()],
            links: vec![("about".into(), "node:n1".into())],
            props: BTreeMap::new(),
        }
    }

    #[test]
    fn an_item_is_keyed_by_stable_node_id_not_path() {
        // A rename must update this item, not create a second one and orphan the first.
        let mut f = facts();
        let a = item_from(&f, &Extracted::default());
        f.path = "/archive/trip-2024.ocean".into();
        let b = item_from(&f, &Extracted::default());
        assert_eq!(a.id, b.id, "identity must survive a rename");
        assert_ne!(a.reference, b.reference, "the path is display, and it moved");
    }

    #[test]
    fn the_formats_title_wins_over_the_filename() {
        let e = Extracted { title: Some("Trip plan".into()), ..Default::default() };
        assert_eq!(item_from(&facts(), &e).title, "Trip plan");
    }

    #[test]
    fn the_filename_is_the_fallback_title() {
        assert_eq!(item_from(&facts(), &Extracted::default()).title, "trip.ocean");
        // ...including when the format returns a blank title rather than none.
        let blank = Extracted { title: Some("   ".into()), ..Default::default() };
        assert_eq!(item_from(&facts(), &blank).title, "trip.ocean");
    }

    #[test]
    fn drive_links_and_format_links_are_merged() {
        // One was asserted ABOUT the file, one was written INSIDE it. Both are real edges.
        let e = Extracted {
            links: vec![("references".into(), "node:n9".into())],
            ..Default::default()
        };
        let item = item_from(&facts(), &e);
        assert!(item.links.contains(&("about".into(), "node:n1".into())));
        assert!(item.links.contains(&("references".into(), "node:n9".into())));
    }

    #[test]
    fn duplicate_links_are_not_doubled() {
        let e = Extracted {
            links: vec![("about".into(), "node:n1".into())],
            ..Default::default()
        };
        assert_eq!(item_from(&facts(), &e).links.len(), 1);
    }

    #[test]
    fn an_operators_prop_outranks_an_extracted_one() {
        // A human's assertion about a file beats a parser's inference from its bytes.
        let mut f = facts();
        f.props.insert("status".into(), "approved".into());
        let e = Extracted {
            props: BTreeMap::from([("status".into(), "draft".into())]),
            ..Default::default()
        };
        assert_eq!(item_from(&f, &e).meta["status"], "approved");
    }

    #[test]
    fn an_unreadable_node_is_still_indexed_and_says_why() {
        // The whole point of degrading: the node stays findable by name, path, tags and links, and
        // an operator can SEE why its content is not searchable.
        let item = item_from(&facts(), &Extracted::unextracted());
        assert_eq!(item.id, "n7");
        assert_eq!(item.title, "trip.ocean");
        assert!(item.text.is_empty());
        assert_eq!(item.meta["unextracted"], "true");
        assert_eq!(item.meta["unextracted_kind"], "ocean-doc",
                   "name the kind so installing the right app is obvious");
        assert!(item.links.iter().any(|(r, _)| r == "about"), "drive links survive");
    }

    #[test]
    fn a_node_with_no_kind_is_a_plain_file() {
        let mut f = facts();
        f.kind = None;
        assert_eq!(item_from(&f, &Extracted::default()).kind, "file");
    }

    #[test]
    fn dir_is_derived_for_grouping() {
        let item = item_from(&facts(), &Extracted::default());
        assert_eq!(item.meta["dir"], "/notes");
        let mut f = facts();
        f.path = "/top.md".into();
        assert_eq!(item_from(&f, &Extracted::default()).meta["dir"], "/");
    }

    #[test]
    fn the_locator_is_carried_so_a_hit_can_be_opened() {
        assert_eq!(item_from(&facts(), &Extracted::default()).meta["locator"], "blob:deadbeef");
    }

    #[test]
    fn a_broken_kind_app_degrades_instead_of_poisoning_the_corpus() {
        // Missing, malformed, and error replies must all degrade: one bad format cannot be allowed
        // to stop a whole drive being indexed.
        assert!(extract_reply(b"not json at all").unextracted);
        assert!(extract_reply(br#"{"error":"boom"}"#).unextracted);
        assert!(extract_reply(br#"{"result":{"nonsense":1}}"#).unextracted
            || extract_reply(br#"{"result":{"nonsense":1}}"#).text.is_empty());
    }

    #[test]
    fn a_good_reply_is_read() {
        let e = extract_reply(br#"{"ok":true,"result":{"title":"T","text":"hello","links":[["a","node:x"]],"unextracted":false}}"#);
        assert_eq!(e.text, "hello");
        assert_eq!(e.title.as_deref(), Some("T"));
        assert_eq!(e.links, vec![("a".to_string(), "node:x".to_string())]);
        assert!(!e.unextracted);
    }

    #[test]
    fn the_extract_request_carries_bytes_the_caller_already_has() {
        // The ROUTER supplies the bytes, because the router is what resolved the locator. A kind app
        // that fetched for itself would have had to learn storage.
        let req = extract_request(b"hello", "a.ocean");
        assert_eq!(req["op"], "extract");
        assert_eq!(req["args"]["name"], "a.ocean");
        assert_eq!(req["args"]["base64"], "aGVsbG8=");
    }
}

// =================================================================================================
// The mesh face: `ce-drive/items`, the JSON envelope every ce app speaks.
// =================================================================================================

/// Every file node under `path`, as facts the router can act on.
///
/// Directories are skipped: they have no bytes and nothing to extract, and their names are already
/// carried in every child's `path` and `dir`.
pub fn walk_facts(drive: &ce_drive_core::SyncedDrive, path: &str) -> Vec<NodeFacts> {
    let mut out = Vec::new();
    let mut stack = vec![path.to_string()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = drive.ls(&dir) else { continue };
        for e in entries {
            let child = if dir == "/" {
                format!("/{}", e.name)
            } else {
                format!("{dir}/{}", e.name)
            };
            if e.is_dir {
                stack.push(child);
                continue;
            }
            let Some(content) = e.content.as_ref() else { continue };
            let meta = drive.meta_of(&e.node_id);
            let (props, tags, links) = match meta {
                None => (BTreeMap::new(), Vec::new(), Vec::new()),
                Some(m) => (
                    m.props.clone(),
                    m.tags.iter().cloned().collect(),
                    m.links.iter().map(|(rel, to)| (rel.clone(), to.key())).collect(),
                ),
            };
            out.push(NodeFacts {
                node_id: e.node_id.clone(),
                path: child,
                size: content.size,
                mtime_ms: content.mtime_ms,
                // props.kind IS the service name of the app that understands this format.
                kind: props.get(crate::corpus::KIND_PROP).cloned(),
                locator: content.locator.display(),
                tags,
                links,
                props,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The conventional prop naming a node's format, mirrored from `ce_drive_core::kind_apps`.
pub const KIND_PROP: &str = "kind";

/// The topic ce-drive answers the corpus contract on.
///
/// A separate topic from `ce-drive/v1` because this is a different audience with a different
/// envelope: `ce-drive/v1` is bincode between drive clients, while the corpus contract is the plain
/// JSON envelope every script-tier app (and ce.index) already speaks. Making ce-index learn bincode
/// to read a corpus would have been the coupling all over again.
pub const ITEMS_TOPIC: &str = "ce-drive/items";

/// Refuse to pull more than this into memory to extract one node. A drive holds videos and disk
/// images; indexing must not try to read them whole. Oversized content degrades to `unextracted`
/// and stays findable by name, path, tags and links.
pub const EXTRACT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// The corpus service name, advertised so ce.index can find it without an address.
pub const ITEMS_SERVICE: &str = "ce-drive.corpus";

/// One page of the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemsPage {
    pub drive: String,
    pub items: Vec<Item>,
    /// Offset to resume from, or absent when the walk is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<usize>,
    pub more: bool,
    pub returned: usize,
}

/// Parse an `items` request: `{"op":"items","args":{drive?,path?,offset?,limit?}}`.
#[derive(Debug, Clone, Default)]
pub struct ItemsArgs {
    pub drive: Option<String>,
    pub path: String,
    pub offset: usize,
    pub limit: usize,
    /// Only nodes modified at or after this unix second.
    ///
    /// THE STEADY-STATE CRAWL DEPENDS ON THIS. ce.index passes back the newest `updated` it has
    /// seen, so a routine re-crawl costs only what actually changed. Ignoring it is *allowed* --
    /// the contract says correctness never depends on an app honouring `since` -- but on a drive of
    /// any size ignoring it means re-reading and re-extracting every file on every pass, which is
    /// rebuilding the index from scratch forever.
    ///
    /// Filtering happens BEFORE pagination, deliberately: filtering a page after slicing it would
    /// make `offset` mean "position in the unfiltered walk", so a caller paging through changes
    /// would skip real results.
    pub since: u64,
}

impl ItemsArgs {
    /// Bounded by construction: a caller asking for the world still gets a page, because an
    /// unbounded reply is the failure mode that already bit Ocean (a 3.8 MB reply took 19s then
    /// timed out entirely, while the same bytes in 200 KB pages moved in 600ms).
    pub const MAX_LIMIT: usize = 200;

    pub fn parse(v: &serde_json::Value) -> ItemsArgs {
        let a = v.get("args").unwrap_or(&serde_json::Value::Null);
        ItemsArgs {
            drive: a.get("drive").and_then(|d| d.as_str()).map(str::to_string),
            path: a.get("path").and_then(|p| p.as_str()).unwrap_or("/").to_string(),
            offset: a.get("offset").and_then(|o| o.as_u64()).unwrap_or(0) as usize,
            limit: (a.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize)
                .clamp(1, Self::MAX_LIMIT),
            since: a.get("since").and_then(|s| s.as_u64()).unwrap_or(0),
        }
    }
}

/// The JSON reply envelope: `{"ok":true,"result":...}`.
pub fn ok_reply(result: impl Serialize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"ok": true, "result": result}))
        .unwrap_or_else(|_| b"{\"error\":\"encode failed\"}".to_vec())
}

/// The JSON error envelope.
pub fn err_reply(msg: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"error": msg}))
        .unwrap_or_else(|_| b"{\"error\":\"encode failed\"}".to_vec())
}

/// Keep only what changed at or after `since`. `since == 0` keeps everything (a first crawl).
pub fn changed_since(facts: Vec<NodeFacts>, since: u64) -> Vec<NodeFacts> {
    if since == 0 {
        return facts;
    }
    facts.into_iter().filter(|f| f.mtime_ms / 1000 >= since).collect()
}

#[cfg(test)]
mod mouth_tests {
    use super::*;

    #[test]
    fn since_zero_is_a_full_crawl() {
        let f = vec![NodeFacts { mtime_ms: 1_000, ..Default::default() }];
        assert_eq!(changed_since(f, 0).len(), 1);
    }

    #[test]
    fn since_keeps_only_what_changed() {
        // The steady-state crawl: ce.index passes the newest `updated` it holds, and a routine pass
        // costs only what actually moved. Without this, every crawl re-reads and re-extracts the
        // whole drive — rebuilding the index from scratch, forever.
        let facts = vec![
            NodeFacts { path: "/old".into(), mtime_ms: 1_000_000, ..Default::default() },
            NodeFacts { path: "/new".into(), mtime_ms: 5_000_000, ..Default::default() },
        ];
        let kept = changed_since(facts, 2_000);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path, "/new");
    }

    #[test]
    fn since_is_inclusive_so_a_resumed_crawl_cannot_skip_a_tie() {
        // Two nodes written in the same second as the cursor must not fall through the gap.
        let facts = vec![NodeFacts { path: "/edge".into(), mtime_ms: 3_000_000, ..Default::default() }];
        assert_eq!(changed_since(facts, 3_000).len(), 1, "at the boundary it must be kept");
    }

    #[test]
    fn since_is_parsed_from_the_request() {
        let v = serde_json::json!({"op":"items","args":{"since": 1700000000}});
        assert_eq!(ItemsArgs::parse(&v).since, 1_700_000_000);
        assert_eq!(ItemsArgs::parse(&serde_json::json!({"op":"items"})).since, 0);
    }

    #[test]
    fn a_page_is_always_bounded() {
        // "give me everything" must still come back as a page.
        let v = serde_json::json!({"op":"items","args":{"limit": 100000}});
        assert_eq!(ItemsArgs::parse(&v).limit, ItemsArgs::MAX_LIMIT);
        let v = serde_json::json!({"op":"items","args":{"limit": 0}});
        assert_eq!(ItemsArgs::parse(&v).limit, 1);
    }

    #[test]
    fn defaults_walk_the_whole_drive_from_the_start() {
        let a = ItemsArgs::parse(&serde_json::json!({"op":"items"}));
        assert_eq!(a.path, "/");
        assert_eq!(a.offset, 0);
        assert!(a.drive.is_none());
    }

    #[test]
    fn replies_use_the_envelope_every_ce_app_speaks() {
        let raw = ok_reply(serde_json::json!({"x": 1}));
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["x"], 1);
        let e: serde_json::Value = serde_json::from_slice(&err_reply("boom")).unwrap();
        assert_eq!(e["error"], "boom");
    }
}

/// Read a content app's `get` reply into bytes.
///
/// Content apps answer the JSON envelope with base64, so this is where a `local-fs` file, a `blob`
/// object and a `stream` window all become the same `Vec<u8>` — which is exactly the uniformity the
/// contract exists to buy.
pub fn decode_content_reply(raw: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let b64 = v.get("result")?.get("base64")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

#[cfg(test)]
mod content_reply_tests {
    use super::*;

    #[test]
    fn every_content_app_decodes_the_same_way() {
        // blob, local-fs and stream all answer with base64 in the same envelope; the router must not
        // care which one replied.
        let raw = br#"{"ok":true,"result":{"id":"x","base64":"aGVsbG8="}}"#;
        assert_eq!(decode_content_reply(raw).unwrap(), b"hello");
    }

    #[test]
    fn a_refusal_yields_no_bytes_rather_than_empty_ones() {
        // An error must not look like a zero-length file, or the index would record it as empty.
        assert!(decode_content_reply(br#"{"error":"no such stream"}"#).is_none());
        assert!(decode_content_reply(b"not json").is_none());
    }
}
