//! Registry behaviour against a live node.
//!
//! These assertions used to be unit tests in `tenant.rs`. They moved here when the host switched
//! from the single-writer `Drive` to `SyncedDrive`: opening a drive now opens a replicated log
//! through `ce-coord`, which talks to a real node, so there is no longer such a thing as
//! constructing a tenant offline. Deleting the coverage instead of moving it would have quietly
//! dropped the create/duplicate/restore/quota guarantees.
//!
//! One ephemeral in-process node serves all of them. If it cannot start (a locked-down sandbox),
//! every test prints a skip note and returns rather than failing spuriously — the same discipline as
//! `two_node_drive`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};

use ce_drive_core::{FileContent, persist};
use ce_drive_serve::{Quota, Registry};
use ce_node::{Node, NodeConfig};
use ce_rs::CeClient;

static NEXT_PORT: AtomicU16 = AtomicU16::new(15_310);
const TEST_API_TOKEN: &str = "ce-drive-registry-token";

fn tmpdir(label: &str) -> PathBuf {
    unsafe { std::env::set_var("CE_API_TOKEN", TEST_API_TOKEN) };
    let dir = std::env::temp_dir().join(format!(
        "ce-drive-registry-{}-{label}-{}",
        std::process::id(),
        NEXT_PORT.load(Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start_node(dir: &Path) -> anyhow::Result<(Node, String)> {
    let p2p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    let api = p2p + 1;
    let config = NodeConfig {
        listen_port: p2p,
        data_dir: dir.to_path_buf(),
        api_port: api,
        disable_local_discovery: true,
        ephemeral: true,
        ..Default::default()
    };
    let node = Node::start(config).await?;
    Ok((node, format!("http://127.0.0.1:{api}")))
}

/// A node plus a coordinator over it, or `None` if this sandbox cannot run one.
async fn coord_or_skip(label: &str) -> Option<(Node, PathBuf, ce_coord::Coord)> {
    let dir = tmpdir(label);
    let (node, url) = match start_node(&dir).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip {label}: node failed to start ({e})");
            return None;
        }
    };
    let client = CeClient::new(url);
    match ce_coord::Coord::with_client(client).await {
        Ok(c) => Some((node, dir.join("identity"), c)),
        Err(e) => {
            eprintln!("skip {label}: ce-coord failed to open ({e})");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_get_and_list_drives() {
    let Some((_node, key_dir, coord)) = coord_or_skip("list").await else { return };
    let mut reg = Registry::new(&key_dir).unwrap();
    assert!(reg.drive_ids().is_empty());
    assert!(reg.get("nope").is_none());

    reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
    reg.create(&coord, "personal", Quota::default(), &[]).await.unwrap();

    assert!(reg.get("team").is_some());
    assert!(reg.get_mut("personal").is_some());
    let mut ids = reg.drive_ids();
    ids.sort();
    assert_eq!(ids, vec!["personal".to_string(), "team".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_create_errors() {
    let Some((_node, key_dir, coord)) = coord_or_skip("dup").await else { return };
    let mut reg = Registry::new(&key_dir).unwrap();
    reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
    let err = reg.create(&coord, "team", Quota::default(), &[]).await.unwrap_err();
    assert!(err.to_string().contains("already exists"));
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_is_carried_per_drive() {
    let Some((_node, key_dir, coord)) = coord_or_skip("quota").await else { return };
    let mut reg = Registry::new(&key_dir).unwrap();
    let q = Quota {
        price_per_gib_month: "5".into(),
        price_per_gib_egress: "2".into(),
        free_tier_bytes: 1024,
        channel_required: true,
    };
    reg.create(&coord, "paid", q.clone(), &[]).await.unwrap();
    let got = &reg.get("paid").unwrap().quota;
    assert_eq!(got.price_per_gib_month, "5");
    assert!(got.channel_required);
    assert_eq!(got.free_tier_bytes, 1024);
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_rebuilds_drive_from_state_and_rejects_duplicates() {
    let Some((_node, key_dir, coord)) = coord_or_skip("restore").await else { return };
    let mut reg = Registry::new(&key_dir).unwrap();
    reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
    {
        let t = reg.get_mut("team").unwrap();
        t.drive.mkdir("/", "docs").await.unwrap();
        let fc = FileContent::new("cid123", 10, 0o644, 1);
        t.drive.add_file("/docs", "f.txt", fc).await.unwrap();
    }
    let state = reg.get("team").unwrap().drive.to_state();

    // A fresh registry on its OWN node rebuilds the same drive from that state -- a restart is a
    // different process, and two drives of one name on one Coord would replace each other's topic
    // handler (last-writer-wins per topic), which is a test artefact rather than the property here.
    let Some((_node2, key_dir2, coord2)) = coord_or_skip("restore-dst").await else { return };
    let mut reg2 = Registry::new(&key_dir2).unwrap();
    reg2.restore(&coord2, "team", state.clone(), Quota::default(), &[]).await.unwrap();
    let entries = reg2.get("team").unwrap().drive.ls("/docs").unwrap();
    assert!(entries.iter().any(|e| e.name == "f.txt"));
    // The feed restarts at 0 (clients re-bootstrap from the snapshot, then Poll forward).
    assert_eq!(reg2.get("team").unwrap().feed.cursor(), 0);
    // Restoring the same id twice errors.
    assert!(reg2.restore(&coord2, "team", state, Quota::default(), &[]).await.is_err());
}

/// The durability property the host exists for, now through the replicated drive: what was on disk
/// before a restart is served after it. Restoring must NOT re-propose every op — `restore_state` is
/// silent and local, which is why a drive with a long history still boots instantly.
#[tokio::test(flavor = "multi_thread")]
async fn a_drive_survives_a_restart() {
    let Some((_node, key_dir, coord)) = coord_or_skip("survives").await else { return };
    let state_dir = tmpdir("survives-state");
    let path = state_dir.join("team.cedrive");

    // --- first boot: a drive with real content, persisted the way the host does ---
    {
        let mut reg = Registry::new(&key_dir).unwrap();
        reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
        let t = reg.get_mut("team").unwrap();
        t.drive.mkdir("/", "docs").await.unwrap();
        t.drive
            .add_file("/docs", "report.md", FileContent::new("cid-report", 42, 0o644, 1))
            .await
            .unwrap();
        persist::save(&path, &t.drive.to_state()).unwrap();
    }

    // --- restart: the host loads instead of creating ---
    let loaded = persist::load(&path).unwrap().expect("state file is there");
    let Some((_node2, key_dir2, coord2)) = coord_or_skip("survives-restart").await else { return };
    let mut reg = Registry::new(&key_dir2).unwrap();
    reg.restore(&coord2, "team", loaded, Quota::default(), &[]).await.unwrap();

    let entries = reg.get("team").unwrap().drive.ls("/docs").unwrap();
    assert_eq!(entries.len(), 1, "the file survived the restart");
    assert_eq!(entries[0].name, "report.md");
}

/// THE PROPERTY (d) EXISTS FOR: a crash between snapshots loses nothing.
///
/// Writes used to be made durable by rewriting the whole drive after every op. They are now made
/// durable by the write-ahead journal, and the whole-drive snapshot only runs on a timer. That is a
/// straight win on write cost -- and it would be a straight data-loss bug if the journal were not
/// actually replayed. So: write, never snapshot, restart, and require the writes back.
#[tokio::test(flavor = "multi_thread")]
async fn writes_survive_a_crash_with_no_snapshot_at_all() {
    let Some((_node, key_dir, coord)) = coord_or_skip("crash").await else { return };
    let jpath = tmpdir("crash-journal").join("team.cejournal");

    // --- a host takes writes and dies. No .cedrive is ever written. ---
    {
        let mut reg = Registry::new(&key_dir).unwrap();
        reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
        reg.attach_journal("team", &jpath).unwrap();
        let t = reg.get_mut("team").unwrap();
        t.drive.mkdir("/", "docs").await.unwrap();
        t.drive
            .add_file("/docs", "urgent.md", FileContent::new("cid-urgent", 9, 0o644, 3))
            .await
            .unwrap();
        t.drive.set_prop("/docs/urgent.md", "kind", "ocean-doc").await.unwrap();
        // and the process is gone -- no snapshot, no clean shutdown, nothing else written.
    }

    // --- it comes back with an empty drive and only the journal to go on ---
    let Some((_node2, key_dir2, coord2)) = coord_or_skip("crash-restart").await else { return };
    let mut reg = Registry::new(&key_dir2).unwrap();
    reg.create(&coord2, "team", Quota::default(), &[]).await.unwrap();
    let (applied, replay) = reg.attach_journal("team", &jpath).unwrap();

    assert_eq!(replay.torn_bytes, 0, "a clean journal, since this crash was between ops");
    assert!(replay.records >= 3, "every op reached the journal, got {}", replay.records);
    assert!(applied.moves >= 2 && applied.contents >= 1 && applied.metas >= 1);

    let t = reg.get("team").unwrap();
    let entries = t.drive.ls("/docs").unwrap();
    assert_eq!(entries.len(), 1, "the file is back");
    assert_eq!(entries[0].name, "urgent.md");
    let content = t.drive.content_of(&entries[0].node_id).expect("its bytes are bound again");
    assert_eq!(content.cid(), "cid-urgent");
    // Metadata too -- it is a separate collection and a separate journal record type, so it is
    // entirely possible to recover the tree and silently lose every tag, prop and link.
    let meta = t.drive.meta_of(&entries[0].node_id).expect("its metadata is back");
    assert_eq!(meta.props.get("kind").map(String::as_str), Some("ocean-doc"));
}

/// A journal that has been snapshotted away must not replay -- and must not be lost either.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_journal_replays_nothing_but_the_snapshot_still_has_it() {
    let Some((_node, key_dir, coord)) = coord_or_skip("reset").await else { return };
    let dir = tmpdir("reset-state");
    let jpath = dir.join("team.cejournal");
    let spath = dir.join("team.cedrive");

    let state = {
        let mut reg = Registry::new(&key_dir).unwrap();
        reg.create(&coord, "team", Quota::default(), &[]).await.unwrap();
        reg.attach_journal("team", &jpath).unwrap();
        let t = reg.get_mut("team").unwrap();
        t.drive.mkdir("/", "docs").await.unwrap();
        let state = t.drive.to_state();
        // What the durability tick does: snapshot, THEN reset. Never the other way round.
        persist::save(&spath, &state).unwrap();
        t.drive.journal().unwrap().reset().unwrap();
        state
    };

    let (recs, _) = ce_drive_core::journal::replay(&jpath).unwrap();
    assert!(recs.is_empty(), "the journal was emptied by the reset");

    let Some((_node2, key_dir2, coord2)) = coord_or_skip("reset-restart").await else { return };
    let mut reg = Registry::new(&key_dir2).unwrap();
    reg.restore(&coord2, "team", state, Quota::default(), &[]).await.unwrap();
    let (_, replay) = reg.attach_journal("team", &jpath).unwrap();
    assert_eq!(replay.records, 0, "nothing to replay");
    assert!(
        reg.get("team").unwrap().drive.resolve("/docs").is_some(),
        "and the snapshot carried the work the journal gave up"
    );
}
