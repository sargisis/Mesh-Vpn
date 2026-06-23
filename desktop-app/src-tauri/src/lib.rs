//! Tauri backend commands for AraxMesh VPN daemon control.
//!
//! Manages a single daemon instance through start/stop/status commands,
//! using shared state protected by a Mutex for thread-safe access.

use araxmesh::config::DaemonSettings;
use araxmesh::{DaemonStatus, run_with_settings};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tauri::State;
use tokio::sync::{Mutex, mpsc, oneshot};

/// Settings submitted from the React frontend via JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendSettings {
    pub private_key: String,
    pub tun_name: Option<String>,
    pub tun_ip: Option<String>,
    pub tun_netmask: Option<String>,
    pub local_udp: Option<String>,
    pub coordinator_url: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub public_endpoint: Option<String>,
    pub relay_addr: Option<String>,
    pub peers: Option<Vec<String>>,
    // DPI bypass magic bytes
    pub magic_handshake_init: Option<u8>,
    pub magic_handshake_resp: Option<u8>,
    pub magic_data: Option<u8>,
    pub magic_probe: Option<u8>,
}

/// Global application state shared between Tauri commands.
struct DaemonState {
    /// Shutdown signal sender — consumed once to stop the daemon.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Latest status snapshot received from the daemon.
    latest_status: Option<DaemonStatus>,
    /// Whether the daemon is currently running.
    running: bool,
    /// Error message if the daemon crashed.
    last_error: Option<String>,
}

type SharedState = Arc<Mutex<DaemonState>>;

/// Convert frontend settings JSON into the library's DaemonSettings struct.
fn to_daemon_settings(fs: &FrontendSettings) -> Result<DaemonSettings, String> {
    if fs.private_key.is_empty() {
        return Err("Private key is required".to_string());
    }

    let local_udp: SocketAddr = fs
        .local_udp
        .as_deref()
        .unwrap_or("0.0.0.0:50001")
        .parse()
        .map_err(|e| format!("Invalid local UDP address: {}", e))?;

    Ok(DaemonSettings {
        tun_name: fs.tun_name.clone().unwrap_or_else(|| "arax0".to_string()),
        tun_ip: fs.tun_ip.clone(),
        tun_netmask: fs.tun_netmask.clone().unwrap_or_else(|| "255.255.255.0".to_string()),
        local_udp,
        private_key_hex: fs.private_key.clone(),
        peer_specs: fs.peers.clone().unwrap_or_default(),
        coordinator_url: fs.coordinator_url.clone(),
        relay_addr: fs.relay_addr.clone(),
        auth_key: fs.auth_key.clone(),
        hostname: fs.hostname.clone(),
        public_endpoint: fs.public_endpoint.clone(),
        magic_handshake_init: fs.magic_handshake_init.unwrap_or(0x01),
        magic_handshake_resp: fs.magic_handshake_resp.unwrap_or(0x02),
        magic_data: fs.magic_data.unwrap_or(0x03),
        magic_probe: fs.magic_probe.unwrap_or(0x04),
    })
}

/// Start the VPN daemon with the given settings.
/// Spawns the daemon on a background Tokio task and streams status updates.
#[tauri::command]
async fn start_vpn(
    settings: FrontendSettings,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut guard = state.lock().await;
    if guard.running {
        return Err("VPN is already running".to_string());
    }

    let daemon_settings = to_daemon_settings(&settings)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (status_tx, mut status_rx) = mpsc::channel::<DaemonStatus>(8);

    guard.shutdown_tx = Some(shutdown_tx);
    guard.running = true;
    guard.last_error = None;
    guard.latest_status = Some(DaemonStatus {
        connection_state: "Connecting".to_string(),
        assigned_ip: None,
        total_uploaded: 0,
        total_downloaded: 0,
        peers: vec![],
    });
    drop(guard);

    // Clone state for the status reader task
    let state_for_status = Arc::clone(&state);
    // Clone state for the daemon completion handler
    let state_for_daemon = Arc::clone(&state);

    // Spawn the status reader — drains the mpsc channel and updates shared state
    tokio::spawn(async move {
        while let Some(status) = status_rx.recv().await {
            let mut guard = state_for_status.lock().await;
            guard.latest_status = Some(status);
        }
    });

    // Spawn the daemon itself on a background task
    tokio::spawn(async move {
        let result = run_with_settings(daemon_settings, shutdown_rx, Some(status_tx))
            .await
            .map_err(|e| e.to_string());
        let mut guard = state_for_daemon.lock().await;
        guard.running = false;
        guard.shutdown_tx = None;
        if let Err(err_str) = result {
            tracing::error!("VPN daemon exited with error: {}", err_str);
            guard.last_error = Some(err_str);
            guard.latest_status = Some(DaemonStatus {
                connection_state: "Error".to_string(),
                assigned_ip: None,
                total_uploaded: 0,
                total_downloaded: 0,
                peers: vec![],
            });
        } else {
            guard.latest_status = Some(DaemonStatus {
                connection_state: "Disconnected".to_string(),
                assigned_ip: None,
                total_uploaded: 0,
                total_downloaded: 0,
                peers: vec![],
            });
        }
    });

    Ok("VPN starting".to_string())
}

/// Stop the VPN daemon by sending the shutdown signal.
#[tauri::command]
async fn stop_vpn(state: State<'_, SharedState>) -> Result<String, String> {
    let mut guard = state.lock().await;
    if !guard.running {
        return Err("VPN is not running".to_string());
    }

    if let Some(tx) = guard.shutdown_tx.take() {
        let _ = tx.send(());
        guard.latest_status = Some(DaemonStatus {
            connection_state: "Disconnecting".to_string(),
            assigned_ip: None,
            total_uploaded: 0,
            total_downloaded: 0,
            peers: vec![],
        });
        Ok("Shutdown signal sent".to_string())
    } else {
        Err("No shutdown channel available".to_string())
    }
}

/// Get the current VPN status snapshot.
#[tauri::command]
async fn get_vpn_status(state: State<'_, SharedState>) -> Result<VpnStatusResponse, String> {
    let guard = state.lock().await;
    Ok(VpnStatusResponse {
        running: guard.running,
        status: guard.latest_status.clone(),
        error: guard.last_error.clone(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusResponse {
    pub running: bool,
    pub status: Option<DaemonStatus>,
    pub error: Option<String>,
}

/// Generate a new Noise keypair and return it.
#[tauri::command]
fn generate_keypair() -> Result<KeypairResponse, String> {
    use rand::RngCore;
    let mut private_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut private_bytes);
    let secret = x25519_dalek::StaticSecret::from(private_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(KeypairResponse {
        private_key: hex::encode(private_bytes),
        public_key: hex::encode(public.to_bytes()),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeypairResponse {
    pub private_key: String,
    pub public_key: String,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize tracing for the Tauri process
    tracing_subscriber::fmt()
        .with_env_filter("araxmesh=info,desktop_app=info")
        .init();

    let shared_state: SharedState = Arc::new(Mutex::new(DaemonState {
        shutdown_tx: None,
        latest_status: None,
        running: false,
        last_error: None,
    }));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(shared_state)
        .invoke_handler(tauri::generate_handler![
            start_vpn,
            stop_vpn,
            get_vpn_status,
            generate_keypair,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
