//! uTURN - Single-port TURN relay server

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
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
    #[arg(long, env = "UTURN_MAX_ALLOC_PER_IP", default_value = "10")]
    max_allocations_per_ip: u32,

    /// Rate limit: max allocation requests per IP per minute (0 = unlimited)
    #[arg(long, env = "UTURN_RATE_LIMIT", default_value = "30")]
    rate_limit_per_minute: u32,

    /// Maximum concurrent packet handling tasks (0 = unlimited)
    #[arg(long, env = "UTURN_MAX_TASKS", default_value = "1000")]
    max_concurrent_tasks: u32,

    /// Nonce validity period in seconds
    #[arg(long, env = "UTURN_NONCE_LIFETIME", default_value = "3600")]
    nonce_lifetime_secs: u64,
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
        max_concurrent_tasks: args.max_concurrent_tasks,
        nonce_lifetime_secs: args.nonce_lifetime_secs,
        nonce_secret,
    };

    info!(
        "Starting uTURN server on :{} (external: {})",
        config.port, config.external_ip
    );

    let server = Server::new(config).await?;
    server.run().await
}
