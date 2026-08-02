// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use shuli::{WpaClient, WpaConfig, WpaState};
use tokio::signal;

#[derive(Parser)]
#[command(name = "shulid", about = "WiFi authentication daemon")]
struct Cli {
    #[arg(short, long, default_value = "/etc/shuli/config.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .init();

    let cli = Cli::parse();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), shuli::WpaError> {
    let config = WpaConfig::load(&cli.config)?;
    log::info!("shulid: iface={}, ssid={}", config.ifname, config.ssid);

    let mut client = WpaClient::new(&config).await?;
    let mut connected = false;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                log::info!("shutting down");
                client.shutdown().await;
                break;
            }
            result = client.process() => {
                match result {
                    Ok(state) => match state {
                        WpaState::ConnectedWithoutOffloadRekey
                        | WpaState::ConnectedWithOffloadRekey => {
                            if !connected {
                                connected = true;
                                log::info!(
                                    "connection established - link up, \
                                     holding (Ctrl-C to disconnect)"
                                );
                            }
                        }
                        WpaState::Failed => {
                            log::warn!("connection failed - retrying");
                        }
                        WpaState::FailedAuthentication => {
                            log::warn!(
                                "authentication failed - retrying in \
                                 10 minutes"
                            );
                        }
                        _ => {}
                    },
                    Err(e) => {
                        log::warn!("{e}");
                    }
                }
            }
        }
    }

    if connected {
        log::info!("connection established");
        Ok(())
    } else {
        Err(shuli::WpaError::new(
            shuli::ErrorKind::ConnectFailed,
            "shutdown before connection established",
        ))
    }
}
