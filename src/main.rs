//! `ce-drive-serve` — host one or more CE drives over the mesh.
//!
//! Boots a [`DriveServer`] against the local CE node, creates the requested drives, and runs the
//! serve loop. The host key (which IS the capability root for every drive it serves) is loaded from
//! `--key-dir` (default: the CE data dir's `identity/` subdir, where the node writes `node.key`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_drive_serve::{DriveServer, Quota, Registry};
use ce_identity::Identity;
use ce_rs::CeClient;
use clap::Parser;
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ce-drive-serve", about = "Host CE drives over the mesh, gated by ce-cap")]
struct Args {
    /// Local CE node HTTP API base URL.
    #[arg(long, default_value = ce_rs::DEFAULT_BASE_URL)]
    api: String,
    /// CE node API token (else discovered from $CE_API_TOKEN / data dir).
    #[arg(long)]
    token: Option<String>,
    /// Directory holding the host's `node.key` (the capability root). Defaults to the CE data dir's
    /// `identity/` subdir.
    #[arg(long)]
    key_dir: Option<PathBuf>,
    /// Directory holding `<drive>.cedrive` state files. Defaults to `$CE_DRIVE_DIR`, else the
    /// platform data dir + `ce-drive` — the same place the `ce-drive` CLI keeps them, so the host
    /// serves the drive that actually holds your files rather than a fresh empty one.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Extra peer NodeIds to follow, beyond the ones discovery finds.
    ///
    /// Almost never needed: peers are DISCOVERED. Syncing is what a distributed drive is for, so it
    /// is not a mode you switch on -- there is no `--synced` flag and there should not be one. This
    /// exists only for a peer that cannot be discovered (a node behind something that breaks the
    /// DHT), and anything set here is additive to what discovery already found.
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Drive ids to create and serve (repeatable).
    #[arg(long = "drive", default_values_t = vec!["default".to_string()])]
    drives: Vec<String>,
    /// Optional human name to claim for discovery (`resolve_name`).
    #[arg(long)]
    name: Option<String>,
    /// Poll interval for the serve loop, in milliseconds.
    #[arg(long, default_value_t = 200)]
    poll_ms: u64,
}

/// Where `<drive>.cedrive` files live.
///
/// This MUST agree with `ce-drive`'s own `Paths::resolve` — `$CE_DRIVE_DIR`, else the platform data
/// dir plus `ce-drive`. The host and the CLI have to open the same files or there are two drives
/// with the same name: a local one holding everyone's work and a mesh one that is empty. That is
/// exactly the state this host shipped in.
fn default_state_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CE_DRIVE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(directories::ProjectDirs::from("", "", "ce-drive")
        .context("cannot resolve the CE drive data dir")?
        .data_dir()
        .to_path_buf())
}

fn default_key_dir() -> Result<PathBuf> {
    let dir = directories::ProjectDirs::from("", "", "ce")
        .context("cannot resolve CE data dir")?
        .data_dir()
        .join("identity");
    Ok(dir)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let key_dir = match args.key_dir {
        Some(d) => d,
        None => default_key_dir()?,
    };
    let identity = Identity::load_or_generate(&key_dir)?;
    info!(host = %identity.node_id_hex(), key_dir = %key_dir.display(), "ce-drive host identity");

    let client = CeClient::with_token(&args.api, args.token.or_else(ce_rs::discover_api_token));

    let state_dir = match args.state_dir {
        Some(d) => d,
        None => default_state_dir()?,
    };
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;

    // SERVE FIRST, DISCOVER AFTER. Peer discovery used to run here, before anything was serving,
    // and a drive is not allowed to depend on the DHT to answer a local read.
    //
    // This host went completely dark for it. On a node whose DHT was degraded -- the bootstrap
    // relay had run out of disk -- `find_service` took 35 seconds to time out, and until it did,
    // the process had not subscribed to anything: alive, healthy to `ce app ps`, writing its
    // journal on schedule, and answering nothing. Every app that waits on the drive looked broken
    // too, so the fault appeared to be everywhere except where it was.
    //
    // Peers are still discovered, on a background task, and added to each drive's replica set as
    // they are found (`add_writer` is idempotent). A drive with no peers yet is a drive serving its
    // own data, which is exactly what it should be doing while it looks for company.
    let coord = ce_coord::Coord::with_client(client.clone())
        .await
        .context("open ce-coord (a drive is a replicated log; there is no single-writer mode)")?;
    // Only what the operator passed explicitly: known without asking anyone.
    let peers: Vec<String> = args.peers.clone();

    let mut registry = Registry::new(&key_dir)?;
    for d in &args.drives {
        let path = state_dir.join(format!("{d}.cedrive"));
        // LOAD, don't create. A `create` here is what made every hosted drive empty and amnesiac:
        // it silently shadowed the real state file sitting right next to it.
        match ce_drive_core::persist::load(&path)? {
            Some(state) => {
                let files = state.content_log.len();
                registry.restore(&coord, d, state, Quota::default(), &peers).await?;
                info!(drive = %d, path = %path.display(), content_ops = files,
                      peers = peers.len(), "serving drive (resumed from disk into the replica set)");
            }
            None => {
                registry.create(&coord, d, Quota::default(), &peers).await?;
                info!(drive = %d, path = %path.display(), peers = peers.len(),
                      "serving drive (new — no state file yet)");
            }
        }

        // The journal goes on top of the snapshot, and only after it: the snapshot is the drive as
        // of the last periodic write, the journal is every op accepted since. This is the half of
        // durability that survives a crash -- the snapshot alone would lose up to a minute of
        // acknowledged writes.
        let jpath = state_dir.join(format!("{d}.cejournal"));
        let (applied, replay) = registry
            .attach_journal(d, &jpath)
            .with_context(|| format!("attach journal {}", jpath.display()))?;
        if replay.records > 0 || replay.torn_bytes > 0 {
            info!(drive = %d, path = %jpath.display(), records = replay.records,
                  moves = applied.moves, contents = applied.contents, metas = applied.metas,
                  torn_bytes = replay.torn_bytes,
                  "replayed the write-ahead journal on top of the snapshot");
        }
        if replay.torn_bytes > 0 {
            // Normal after an unclean shutdown, and worth saying out loud: it means the process
            // died mid-append, and the op in that torn record was never acknowledged to a client.
            warn!(drive = %d, torn_bytes = replay.torn_bytes,
                  "the journal had a torn tail (the last append did not complete); everything \
                   before it was recovered");
        }
    }

    let server = DriveServer::new(client.clone(), registry, &key_dir, Vec::new())?
        .with_state_dir(&state_dir);
    // Now that the drives are open and about to serve, go looking for the rest of the replica set.
    spawn_peer_discovery(client.clone(), server.registry(), args.drives.clone());
    server.announce().await?;
    if let Some(name) = &args.name {
        if let Err(e) = client.claim_name(name).await {
            info!(error = %e, "name claim failed (continuing)");
        } else {
            info!(name = %name, "claimed drive name");
        }
    }

    info!("ce-drive-serve running; press Ctrl-C to stop");
    server.run(args.poll_ms).await
}

/// Find the rest of the replica set, in the background, forever.
///
/// PEERS COME FROM DISCOVERY, always, with no flag to enable it: replicating across devices is this
/// app's job, not a mode. `--peer` only ADDS to what is found, for a node the DHT cannot see.
///
/// OFF THE BOOT PATH, though. Discovery is a DHT query against peers that may be slow, unreachable
/// or out of disk, and a host that waits for it before subscribing is a host that disappears
/// whenever the network is having a bad day -- which is precisely when its data is most wanted.
/// So the server is already serving when this starts, and every peer found is added to the live
/// drives with `add_writer`, which is idempotent.
///
/// It keeps looking rather than sweeping once: a device that joins the drive tomorrow is exactly as
/// much a member as one that was up at boot, and requiring a restart to notice it would make the
/// replica set a function of who happened to be awake first.
fn spawn_peer_discovery(
    client: CeClient,
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    drives: Vec<String>,
) {
    tokio::spawn(async move {
        let mut known: std::collections::HashSet<String> = std::collections::HashSet::new();
        let me = client.status().await.map(|s| s.node_id).unwrap_or_default();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            let found = match client.find_service("ce-drive").await {
                Ok(f) => f,
                // Not an error worth shouting about: a DHT that cannot answer right now means the
                // replica set is smaller than it will be, not that anything is wrong here.
                Err(e) => {
                    debug!(error = %e, "drive peers: discovery unavailable; retrying");
                    continue;
                }
            };
            for peer in found {
                if peer == me || !known.insert(peer.clone()) {
                    continue;
                }
                let reg = registry.lock().await;
                for d in &drives {
                    if let Some(t) = reg.get(d) {
                        match t.drive.add_writer(&peer).await {
                            Ok(()) => info!(drive = %d, peer = %peer,
                                            "drive peers: following a newly discovered writer"),
                            Err(e) => warn!(drive = %d, peer = %peer, error = %e,
                                            "drive peers: could not follow"),
                        }
                    }
                }
            }
        }
    });
}
