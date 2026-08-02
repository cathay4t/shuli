// SPDX-License-Identifier: Apache-2.0

mod config;

use std::{path::Path, process::ExitCode};

use config::ShuliConfig;
use shuli::{WifiClient, WifiState};
use tokio::{
    signal,
    signal::unix::{SignalKind, signal as unix_signal},
};

const DEFAULT_CONFIG: &str = "/etc/shuli/config.yml";

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());

    match run(Path::new(&config_path)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(config_path: &Path) -> Result<(), shuli::WifiError> {
    let shuli_config = ShuliConfig::load(config_path)?;
    let wifi_config = shuli_config.to_wifi_config()?;
    log::info!(
        "shulid: iface={}, ssid={}",
        wifi_config.iface_name,
        wifi_config.ssid
    );

    let mut client = WifiClient::init(wifi_config).await?;
    let mut connected = false;
    let mut sigterm = unix_signal(SignalKind::terminate()).map_err(|e| {
        shuli::WifiError::new(
            shuli::ErrorKind::ConnectFailed,
            format!("failed to register SIGTERM handler: {e}"),
        )
    })?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                log::info!("received SIGINT, shutting down");
                client.shutdown().await;
                break;
            }
            _ = sigterm.recv() => {
                log::info!("received SIGTERM, shutting down");
                client.shutdown().await;
                break;
            }
            result = client.run() => {
                match result {
                    Ok(state) => match state {
                        WifiState::ConnectedWithoutOffloadRekey
                        | WifiState::ConnectedWithOffloadRekey => {
                            if !connected {
                                connected = true;
                                log::info!(
                                    "connection established - link up, \
                                     holding (Ctrl-C to disconnect)"
                                );
                            }
                        }
                        WifiState::Failed => {
                            log::warn!("connection failed - retrying");
                        }
                        WifiState::FailedAuthentication => {
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
        Err(shuli::WifiError::new(
            shuli::ErrorKind::ConnectFailed,
            "shutdown before connection established",
        ))
    }
}
