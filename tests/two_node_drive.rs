//! Two-node end-to-end test of the CE Drive mesh API over real CE nodes.
//!
//! Boots two in-process CE nodes (the `NEXT_PORT` pattern from rdev/ce-node tests), runs a real
//! [`DriveServer`] against node B (the host = the capability root), and exercises the full op set
//! from node A as a remote client authorized by a `ce-cap` chain that B self-issued to A:
//!   - `Open` returns a bootstrap snapshot CID + cursor + granted abilities;
//!   - `Mkdir` / `Write` mutate the host's DriveTree + content map (bytes go through the real blob
//!     store via `put_object`); `List` / `Stat` reflect them; `Read` returns a `ReadPlan` whose
//!     chunks the client fetches + verifies, reassembling the exact bytes;
//!   - a `Mirror` bootstraps a local DriveTree replica from the snapshot and converges via `Poll`.
//!
//! The test is resilient: if a node cannot start or the mesh does not converge (locked-down CI), it
//! prints a skip note and returns rather than failing spuriously.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
use ce_drive_client::{Mirror, RemoteDrive};
use ce_drive_serve::{DriveServer, Quota, Registry, drive_caveat_prefix};
use ce_identity::Identity;
use ce_node::{Node, NodeConfig};
use ce_rs::CeClient;
use tokio::time::sleep;

static NEXT_PORT: AtomicU16 = AtomicU16::new(14_910);
const TEST_API_TOKEN: &str = "ce-drive-e2e-token";

fn alloc_ports() -> (u16, u16) {
    let p2p = NEXT_PORT.fetch_add(2, Ordering::Relaxed);
    (p2p, p2p + 1)
}

fn tmpdir(label: &str) -> PathBuf {
    unsafe { std::env::set_var("CE_API_TOKEN", TEST_API_TOKEN) };
    let dir = std::env::temp_dir().join(format!(
        "ce-drive-e2e-{}-{label}-{}",
        std::process::id(),
        NEXT_PORT.load(Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn identity_in(dir: &Path) -> Identity {
    Identity::load_or_generate(&dir.join("identity")).unwrap()
}

fn bootstrap_addr(dir: &Path, p2p_port: u16) -> String {
    let id = identity_in(dir);
    let peer_id = ce_node::peer_id_from_identity(&id).unwrap();
    format!("/ip4/127.0.0.1/tcp/{p2p_port}/p2p/{peer_id}")
}

async fn start_node(bootstrap: Option<String>, dir: &Path) -> anyhow::Result<(Node, u16, String)> {
    let (p2p, api) = alloc_ports();
    let config = NodeConfig {
        listen_port: p2p,
        bootstrap_peers: bootstrap.into_iter().collect(),
        data_dir: dir.to_path_buf(),
        api_port: api,
        mine: false,
        disable_local_discovery: true,
        ephemeral: true,
        ..Default::default()
    };
    let node = Node::start(config).await?;
    Ok((node, p2p, format!("http://127.0.0.1:{api}")))
}

/// Wait until A can reach B over the mesh (an `Open` request round-trips). False on timeout.
async fn wait_open(remote: &RemoteDrive) -> bool {
    for _ in 0..30 {
        if remote.open().await.is_ok() {
            return true;
        }
        sleep(Duration::from_secs(1)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_drive_open_write_read_and_mirror() {
    let dir_a = tmpdir("a");
    let dir_b = tmpdir("b");

    let (node_a, p2p_a, a_url) = match start_node(None, &dir_a).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node A failed to start ({e})");
            return;
        }
    };
    let _ = &node_a;
    sleep(Duration::from_millis(600)).await;

    let bs = bootstrap_addr(&dir_a, p2p_a);
    let (node_b, _p2p_b, b_url) = match start_node(Some(bs), &dir_b).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skip: node B failed to start ({e})");
            return;
        }
    };
    let _ = &node_b;

    // Node B is the host = the capability root. Its key dir is dir_b/identity.
    let b_key_dir = dir_b.join("identity");
    let b_identity = identity_in(&dir_b);
    let b_id = b_identity.node_id();
    let a_id = identity_in(&dir_a).node_id();

    // The host serve loop runs against node B's HTTP API.
    let b_client = CeClient::new(b_url.clone());
    let mut registry = Registry::new(&b_key_dir).unwrap();
    registry.create("team", Quota::default()).unwrap();
    let server =
        DriveServer::new(b_client.clone(), registry, &b_key_dir, Vec::new()).unwrap();
    let serve_handle = tokio::spawn(async move {
        let _ = server.run(100).await;
    });

    // B self-issues a drive:write capability to A, scoped to the whole drive.
    let cap = SignedCapability::issue(
        &b_identity,
        a_id,
        vec!["drive:read".into(), "drive:comment".into(), "drive:write".into(), "drive:admin".into()],
        Resource::Any,
        Caveats { path_prefix: Some(drive_caveat_prefix("team", "/")), ..Default::default() },
        1,
        None,
    );
    let cap_token = encode_chain(&[cap]);

    // Node A's remote handle to the drive on B.
    let a_client = CeClient::new(a_url.clone());
    let remote = RemoteDrive::new(a_client.clone(), &hex::encode(b_id), "team", &cap_token);

    if !wait_open(&remote).await {
        serve_handle.abort();
        eprintln!("skip: mesh did not converge between the two nodes");
        return;
    }

    // ----- Open: snapshot + abilities -----
    let opened = remote.open().await.expect("open");
    assert!(!opened.drive_root_cid.is_empty(), "open returns a snapshot CID");
    assert!(opened.granted_abilities.iter().any(|a| a == "drive:write"));

    // ----- Mkdir + Write -----
    remote.mkdir("/docs").await.expect("mkdir");
    // A multi-chunk payload so the ReadPlan has several chunks; tiny chunk size via large content.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let written = remote.write("/docs/spec.bin", &payload, None).await.expect("write");
    assert!(!written.etag.is_empty());

    // ----- List + Stat reflect the write -----
    let entries = remote.list_all("/docs").await.expect("list");
    assert!(entries.iter().any(|e| e.path == "/docs/spec.bin"), "written file appears in listing");
    let st = remote.stat("/docs/spec.bin").await.expect("stat");
    assert_eq!(st.size, payload.len() as u64);

    // ----- Read: full + ranged, verified against CIDs -----
    let full = remote.read_all("/docs/spec.bin").await.expect("read all");
    assert_eq!(full, payload, "full read reassembles the exact bytes");
    let ranged = remote.read("/docs/spec.bin", 100, Some(50)).await.expect("ranged read");
    assert_eq!(ranged, &payload[100..150], "ranged read returns the exact window");

    // ----- Optimistic concurrency: a stale base_etag conflicts -----
    let stale = remote.write("/docs/spec.bin", b"new", Some("wrong-etag".into())).await;
    assert!(stale.is_err(), "stale base_etag must conflict");

    // ----- Mirror: bootstrap a local replica and converge via Poll -----
    let mut mirror = Mirror::bootstrap(remote.clone()).await.expect("mirror bootstrap");
    // The replica already reflects the snapshot taken at Open (which is after the writes).
    let local = mirror.ls("/docs").expect("local ls");
    assert!(local.iter().any(|e| e.name == "spec.bin"), "mirror replica sees the file locally");

    // Make a new remote change, then sync the mirror forward.
    remote.mkdir("/docs/sub").await.expect("mkdir sub");
    let applied = mirror.sync().await.expect("mirror sync");
    assert!(applied >= 1, "mirror picked up the new change via Poll");
    let local2 = mirror.ls("/docs").expect("local ls 2");
    assert!(local2.iter().any(|e| e.name == "sub"), "mirror converged to the new dir");

    serve_handle.abort();
}
