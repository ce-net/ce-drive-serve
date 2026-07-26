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
use tracing::info;

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

    let mut registry = Registry::new(&key_dir)?;
    for d in &args.drives {
        let path = state_dir.join(format!("{d}.cedrive"));
        // LOAD, don't create. A `create` here is what made every hosted drive empty and amnesiac:
        // it silently shadowed the real state file sitting right next to it.
        match ce_drive_core::persist::load(&path)? {
            Some(state) => {
                let files = state.content_log.len();
                registry.restore(d, state, Quota::default())?;
                info!(drive = %d, path = %path.display(), content_ops = files,
                      "serving drive (resumed from disk)");
            }
            None => {
                registry.create(d, Quota::default())?;
                info!(drive = %d, path = %path.display(),
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
