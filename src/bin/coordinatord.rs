//! AraxMesh coordinator daemon (control plane, Phase 3).
//!
//! A small HTTP/JSON service: nodes POST /register with their Noise public key
//! and a shared pre-auth key, get back an assigned overlay IP and the current
//! peer table, then POST /poll periodically to refresh. The registry logic and
//! its tests live in the `araxmesh::coordinator` library module.
#![forbid(unsafe_code)]

use araxmesh::control::{PollRequest, PollResponse, RegisterRequest, RegisterResponse};
use araxmesh::coordinator::Registry;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[command(author, version, about = "AraxMesh coordinator (control plane)")]
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
}

#[derive(Clone)]
struct AppState {
    registry: Arc<Mutex<Registry>>,
    auth_key: Arc<String>,
}

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

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(
        "Coordinator listening on {} (pool {})",
        args.listen,
        args.cidr
    );
    axum::serve(listener, app).await?;
    Ok(())
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
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    check_auth(&state, &req.auth_key)?;
    let mut reg = state.registry.lock().unwrap();
    let assigned_ip = reg
        .register(&req.public_key, req.endpoint, req.hostname)
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let peers = reg.peers_for(&req.public_key);
    tracing::info!("Registered {} -> {}", req.public_key, assigned_ip);
    Ok(Json(RegisterResponse { assigned_ip, peers }))
}

async fn poll(
    State(state): State<AppState>,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, (StatusCode, String)> {
    check_auth(&state, &req.auth_key)?;
    let mut reg = state.registry.lock().unwrap();
    reg.poll(&req.public_key, req.endpoint)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    let peers = reg.peers_for(&req.public_key);
    Ok(Json(PollResponse { peers }))
}

/// Debug view of the whole network (every node as a peer descriptor).
async fn network(State(state): State<AppState>) -> Json<araxmesh::coordinator::NetworkView> {
    let reg = state.registry.lock().unwrap();
    Json(reg.network_view())
}
