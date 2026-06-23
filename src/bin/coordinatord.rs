//! AraxMesh coordinator daemon (control plane, Phase 3 + relay, Phase 4).
//!
//! A small HTTP/JSON service: nodes POST /register with their Noise public key
//! and a shared pre-auth key, get back an assigned overlay IP and the current
//! peer table, then POST /poll periodically to refresh.  The registry logic and
//! its tests live in the `araxmesh::coordinator` library module.
//!
//! **Phase 4 addition**: a TCP relay server runs alongside the HTTP API.
//! Nodes that cannot reach each other directly (symmetric NAT) connect to the
//! relay, identify with their 32-byte Noise public key, and forward
//! length-prefixed encrypted packets through it.
#![forbid(unsafe_code)]

use araxmesh::control::{PollRequest, PollResponse, RegisterRequest, RegisterResponse};
use araxmesh::coordinator::Registry;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(author, version, about = "AraxMesh coordinator (control plane + relay)")]
struct Args {
    /// Address to listen on for the HTTP API.
    #[arg(long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Overlay address pool to assign node IPs from.
    #[arg(long, default_value = "10.0.99.0/24")]
    cidr: String,

    /// Shared pre-auth key a node must present to register or poll.
    #[arg(long)]
    auth_key: String,

    /// Optional JSON file to persist the registry across restarts.
    #[arg(long)]
    state_file: Option<std::path::PathBuf>,

    /// TCP port for the relay server (DERP-like fallback).
    /// Set to 0 to disable the relay.
    #[arg(long, default_value = "51821")]
    relay_port: u16,
}

#[derive(Clone)]
struct AppState {
    registry: Arc<Mutex<Registry>>,
    auth_key: Arc<String>,
}

/// Relay routing table: maps a 32-byte Noise public key to a channel that
/// delivers frames to that client's TCP writer task.
type RelayRoutes = Arc<Mutex<HashMap<[u8; 32], mpsc::Sender<(/* from */ [u8; 32], Vec<u8>)>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let registry = match &args.state_file {
        Some(path) => Registry::load_or_new(&args.cidr, path.clone())?,
        None => Registry::new(&args.cidr)?,
    };

    let state = AppState {
        registry: Arc::new(Mutex::new(registry)),
        auth_key: Arc::new(args.auth_key),
    };

    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", post(poll))
        .route("/network", get(network))
        .with_state(state);

    // Start the relay server if relay_port > 0.
    if args.relay_port > 0 {
        let relay_addr = format!("0.0.0.0:{}", args.relay_port);
        let relay_listener = TcpListener::bind(&relay_addr).await?;
        tracing::info!("Relay server listening on {}", relay_addr);
        let routes: RelayRoutes = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(run_relay(relay_listener, routes));
    }

    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!(
        "Coordinator listening on {} (pool {})",
        args.listen,
        args.cidr
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Accept relay client connections and route frames between them.
async fn run_relay(listener: TcpListener, routes: RelayRoutes) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!("Relay: new connection from {}", addr);
                let routes = routes.clone();
                tokio::spawn(handle_relay_client(stream, routes));
            }
            Err(e) => {
                tracing::error!("Relay accept error: {:?}", e);
            }
        }
    }
}

/// Handle one relay client: read identity, then split into TX/RX loops.
async fn handle_relay_client(
    mut stream: tokio::net::TcpStream,
    routes: RelayRoutes,
) {
    // 1. Read 32-byte identity.
    let mut identity = [0u8; 32];
    if let Err(e) = stream.read_exact(&mut identity).await {
        tracing::warn!("Relay: failed to read identity: {:?}", e);
        return;
    }
    tracing::info!("Relay: client identified as {}", hex::encode(identity));

    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();

    // 2. Register a channel for inbound frames destined to this client.
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(64);
    {
        let mut r = routes.lock().unwrap();
        r.insert(identity, inbound_tx);
    }

    // 3. TX loop: forward inbound frames from the channel to the TCP writer.
    let tx_task = async {
        while let Some((from_key, payload)) = inbound_rx.recv().await {
            let frame_len = (32 + payload.len()) as u32;
            if wr.write_all(&frame_len.to_be_bytes()).await.is_err() {
                break;
            }
            if wr.write_all(&from_key).await.is_err() {
                break;
            }
            if wr.write_all(&payload).await.is_err() {
                break;
            }
        }
    };

    // 4. RX loop: read frames from the client and route to the destination.
    let routes_rx = routes.clone();
    let rx_task = async {
        loop {
            let mut len_buf = [0u8; 4];
            if rd.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len < 32 || frame_len > 65536 {
                tracing::warn!("Relay: invalid frame length {} from {}", frame_len, hex::encode(identity));
                break;
            }

            let mut frame = vec![0u8; frame_len];
            if rd.read_exact(&mut frame).await.is_err() {
                break;
            }

            let mut dest_key = [0u8; 32];
            dest_key.copy_from_slice(&frame[..32]);
            let payload = frame[32..].to_vec();

            // Route to destination client.
            let sender = {
                let r = routes_rx.lock().unwrap();
                r.get(&dest_key).cloned()
            };

            if let Some(tx) = sender {
                if tx.send((identity, payload)).await.is_err() {
                    tracing::debug!(
                        "Relay: destination {} channel closed",
                        hex::encode(dest_key)
                    );
                }
            } else {
                tracing::debug!(
                    "Relay: no route to destination {}",
                    hex::encode(dest_key)
                );
            }
        }
    };

    tokio::select! {
        _ = tx_task => {}
        _ = rx_task => {}
    }

    // Clean up the route entry.
    {
        let mut r = routes.lock().unwrap();
        r.remove(&identity);
    }
    tracing::info!("Relay: client {} disconnected", hex::encode(identity));
}

fn check_auth(state: &AppState, presented: &str) -> Result<(), (StatusCode, String)> {
    if presented == state.auth_key.as_str() {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid auth key".to_string()))
    }
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    check_auth(&state, &req.auth_key)?;
    let observed = client_addr.to_string();
    let mut reg = state.registry.lock().unwrap();
    let (assigned_ip, observed_endpoint) = reg
        .register(&req.public_key, req.endpoint, req.hostname, Some(observed))
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let peers = reg.peers_for(&req.public_key);
    tracing::info!(
        "Registered {} -> {} (observed {})",
        req.public_key,
        assigned_ip,
        observed_endpoint.as_deref().unwrap_or("none")
    );
    Ok(Json(RegisterResponse {
        assigned_ip,
        peers,
        observed_endpoint,
    }))
}

async fn poll(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, (StatusCode, String)> {
    check_auth(&state, &req.auth_key)?;
    let observed = client_addr.to_string();
    let mut reg = state.registry.lock().unwrap();
    reg.poll(&req.public_key, req.endpoint, Some(observed))
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    let peers = reg.peers_for(&req.public_key);
    Ok(Json(PollResponse { peers }))
}

/// Debug view of the whole network (every node as a peer descriptor).
async fn network(State(state): State<AppState>) -> Json<araxmesh::coordinator::NetworkView> {
    let reg = state.registry.lock().unwrap();
    Json(reg.network_view())
}
