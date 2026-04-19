//! uTURN - Single-port TURN relay server

use anyhow::{bail, Result};
use clap::Parser;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use uturn::{Config, Server};

#[derive(Parser, Debug)]
#[command(name = "uturn")]
#[command(about = "A single-port TURN relay server for WebRTC")]
#[command(version)]
struct Args {
    /// UDP port to listen on
    #[arg(short, long, env = "UTURN_PORT", default_value = "3478")]
    port: u16,

    /// External/public IP address for relay addresses
    #[arg(short, long, env = "UTURN_EXTERNAL_IP")]
    external_ip: std::net::IpAddr,

    /// TURN realm
    #[arg(short, long, env = "UTURN_REALM", default_value = "uturn")]
    realm: String,

    /// Static credentials in format user:password (can be repeated)
    #[arg(short, long, env = "UTURN_USERS", value_delimiter = ',')]
    user: Vec<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "UTURN_LOG_LEVEL", default_value = "info")]
    log_level: Level,

    /// Maximum allocations per IP address (0 = unlimited)
    #[arg(long, env = "UTURN_MAX_ALLOC_PER_IP", default_value = "200")]
    max_allocations_per_ip: u32,

    /// Rate limit: max allocation requests per IP per minute (0 = unlimited)
    #[arg(long, env = "UTURN_RATE_LIMIT", default_value = "30")]
    rate_limit_per_minute: u32,

    /// Nonce validity period in seconds
    #[arg(long, env = "UTURN_NONCE_LIFETIME", default_value = "3600")]
    nonce_lifetime_secs: u64,

    /// Run as an open relay with no authentication. Without this flag the
    /// server refuses to start when no `--user` is configured. Exposing an
    /// anonymous relay on the public internet will be abused.
    #[arg(long, env = "UTURN_ALLOW_ANONYMOUS", default_value = "false")]
    allow_anonymous: bool,

    /// Maximum number of peer IP permissions per allocation
    #[arg(long, env = "UTURN_MAX_PERMISSIONS", default_value = "64")]
    max_permissions_per_alloc: usize,

    /// Maximum number of bound channels per allocation
    #[arg(long, env = "UTURN_MAX_CHANNELS", default_value = "128")]
    max_channels_per_alloc: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(args.log_level)
        .with_target(false)
        .init();

    // Parse credentials
    let credentials: Vec<(String, String)> = args
        .user
        .iter()
        .filter_map(|s| {
            let parts: Vec<&str> = s.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                tracing::warn!("Invalid credential format: {}", s);
                None
            }
        })
        .collect();

    if credentials.is_empty() && !args.allow_anonymous {
        error!("No credentials configured. Refusing to start an unauthenticated TURN relay.");
        error!(
            "Pass --user USER:PASS (or UTURN_USERS=...) to configure auth, \
             or --allow-anonymous to intentionally run as an open relay."
        );
        bail!("missing credentials");
    }

    // Generate random nonce secret at startup
    use rand::Rng;
    let nonce_secret: [u8; 16] = rand::thread_rng().gen();

    let config = Config {
        port: args.port,
        external_ip: args.external_ip,
        realm: args.realm,
        credentials,
        max_allocations_per_ip: args.max_allocations_per_ip,
        rate_limit_per_minute: args.rate_limit_per_minute,
        nonce_lifetime_secs: args.nonce_lifetime_secs,
        nonce_secret,
        allow_anonymous: args.allow_anonymous,
        max_permissions_per_alloc: args.max_permissions_per_alloc,
        max_channels_per_alloc: args.max_channels_per_alloc,
    };

    info!(
        "Starting uTURN server v{} on :{} (external: {})",
        env!("CARGO_PKG_VERSION"),
        config.port,
        config.external_ip
    );

    if config.credentials.is_empty() {
        warn!(
            "ANONYMOUS MODE: server is running as an open relay with no authentication. \
             This will be abused on the public internet (amplification, free transit, \
             SSRF pivots). Use only on trusted networks."
        );
    }

    let server = Server::new(config).await?;

    // Run server with graceful shutdown on SIGTERM/SIGINT
    tokio::select! {
        result = server.run() => {
            result
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal, exiting gracefully");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
