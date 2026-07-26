//! Durability: a hosted drive must survive a restart, and must never shadow existing state.
//!
//! The bug these tests exist for: `main.rs` called `registry.create()` unconditionally at boot.
//! `create()` makes a NEW EMPTY drive in a HashMap, so the drive published on the mesh was empty
//! and in-memory — every write through the cap-gated `ce-drive/v1` API was lost on restart — while
//! the real corpus sat in `<data-dir>/ce-drive/<name>.cedrive` where the CLI had written it. Two
//! drives with the same name: one holding everyone's work, one visible on the mesh and empty.
//!
//! `Registry::restore()` already existed and nothing called it.

use ce_drive_core::{Drive, FileContent, persist};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ce-drive-durability-{}-{n}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Put a file in a drive and hand back its persisted state, the way a host does after a Write.
fn drive_with_a_file(name: &str, replica: &str) -> ce_drive_core::DriveState {
    let mut d = Drive::init(name, replica);
    d.mkdir("/", "docs").unwrap();
    d.add_file("/docs", "report.md", FileContent::new("cid-report", 42, 0o644, 1))
        .unwrap();
    d.state().clone()
}

// `a_drive_survives_a_restart` moved to `tests/registry_live.rs`: restoring a drive now opens a
// replicated log, which needs a live node. The bug it guards is unchanged -- boot must LOAD, not
// create -- and the persist-format properties below stay here because they are pure.

#[test]
fn restore_preserves_stable_node_ids() {
    // Links are stored against NodeId, so an id that changed across a restart would silently break
    // every edge pointing into this drive.
    let state = drive_with_a_file("team", "abcd");
    let before = Drive::from_state(state.clone())
        .tree()
        .resolve("/docs/report.md")
        .expect("resolves");

    let dir = temp_dir("ids");
    let path = dir.join("team.cedrive");
    persist::save(&path, &state).unwrap();
    let after = Drive::from_state(persist::load(&path).unwrap().unwrap())
        .tree()
        .resolve("/docs/report.md")
        .expect("resolves after reload");

    assert_eq!(before, after, "NodeId must be stable across persistence");
}

#[test]
fn an_absent_state_file_is_distinguishable_from_an_empty_one() {
    // The host branches on exactly this to decide create-vs-restore. If "missing" and "empty" were
    // conflated, a transient read failure would create an empty drive over real data.
    let dir = temp_dir("absent");
    assert!(persist::load(dir.join("nothing-here.cedrive")).unwrap().is_none());

    let empty_path = dir.join("empty.cedrive");
    persist::save(&empty_path, &Drive::init("empty", "abcd").state().clone()).unwrap();
    let loaded = persist::load(&empty_path).unwrap();
    assert!(loaded.is_some(), "an empty drive is still a drive");
    assert_eq!(loaded.unwrap().name, "empty");
}

#[test]
fn successive_writes_round_trip_through_disk() {
    // Simulates the host's persist-after-every-mutation path: each op is followed by a save, and a
    // reload at any point sees everything committed so far.
    let dir = temp_dir("successive");
    let path = dir.join("team.cedrive");

    let mut d = Drive::init("team", "abcd");
    d.mkdir("/", "docs").unwrap();
    persist::save(&path, d.state()).unwrap();

    for i in 0..5 {
        let mut live = Drive::from_state(persist::load(&path).unwrap().unwrap());
        live.add_file(
            "/docs",
            &format!("f{i}.md"),
            FileContent::new(&format!("cid-{i}"), 10, 0o644, 1),
        )
        .unwrap();
        persist::save(&path, live.state()).unwrap();
    }

    let final_state = persist::load(&path).unwrap().unwrap();
    let entries = Drive::from_state(final_state).ls("/docs").unwrap();
    assert_eq!(entries.len(), 5, "every write is on disk");
}
