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
use tracing::{info, warn};

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

    // Peers and the coordinator come FIRST, because a drive is a replica set from the moment it
    // opens. Building it single-writer and joining afterwards is what created two representations of
    // the same drive.
    let peers = discover_peers(&client, &args.peers).await;
    let coord = ce_coord::Coord::with_client(client.clone())
        .await
        .context("open ce-coord (a drive is a replicated log; there is no single-writer mode)")?;

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
    }

    let server = DriveServer::new(client.clone(), registry, &key_dir, Vec::new())?
        .with_state_dir(&state_dir);
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

/// Everyone else advertising `ce-drive` — the replica set assembles itself.
///
/// PEERS COME FROM DISCOVERY, always, with no flag to enable it. Replicating across devices is the
/// JOB of this app, not a mode: a drive that syncs only when configured to is a local folder with
/// extra steps, and every flag is one more thing an operator (or an AI wiring up infrastructure) has
/// to know before the system behaves correctly. `--peer` only ADDS to what was found, for a node the
/// DHT cannot see.
///
/// Ourselves excluded: a writer does not follow its own log. Discovery failure is not fatal — a host
/// that refused to start because the mesh was unreachable would be strictly worse than one that
/// serves what it has and picks peers up later.
async fn discover_peers(client: &CeClient, extra: &[String]) -> Vec<String> {
    let mut peers: Vec<String> = extra.to_vec();
    match client.find_service("ce-drive").await {
        Ok(found) => {
            let me = client.status().await.map(|s| s.node_id).unwrap_or_default();
            for p in found {
                if p != me && !peers.contains(&p) {
                    peers.push(p);
                }
            }
        }
        Err(e) => warn!(error = %e, "drive peers: discovery failed; starting with --peer only"),
    }
    peers
}
