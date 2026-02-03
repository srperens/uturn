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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let _subscriber = FmtSubscriber::builder()
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

    let config = Config {
        port: args.port,
        external_ip: args.external_ip,
        realm: args.realm,
        credentials,
    };

    info!(
        "Starting uTURN server on :{} (external: {})",
        config.port, config.external_ip
    );

    let server = Server::new(config).await?;
    server.run().await
}
