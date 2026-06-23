import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

/* ── Types ─────────────────────────────────────────────────────── */
interface PeerStatus {
  pubkey: string;
  endpoint: string | null;
  allowed_ips: string[];
  last_rx_secs_ago: number | null;
  last_tx_secs_ago: number | null;
  is_active: boolean;
}

interface DaemonStatus {
  connection_state: string;
  assigned_ip: string | null;
  total_uploaded: number;
  total_downloaded: number;
  peers: PeerStatus[];
}

interface VpnStatusResponse {
  running: boolean;
  status: DaemonStatus | null;
  error: string | null;
}

interface KeypairResponse {
  private_key: string;
  public_key: string;
}

interface FrontendSettings {
  private_key: string;
  tun_name: string | null;
  tun_ip: string | null;
  tun_netmask: string | null;
  local_udp: string | null;
  coordinator_url: string | null;
  auth_key: string | null;
  hostname: string | null;
  public_endpoint: string | null;
  relay_addr: string | null;
  peers: string[] | null;
  magic_handshake_init: number | null;
  magic_handshake_resp: number | null;
  magic_data: number | null;
  magic_probe: number | null;
}

/* ── Helpers ───────────────────────────────────────────────────── */
function formatBytes(bytes: number): { value: string; unit: string } {
  if (bytes === 0) return { value: "0", unit: "B" };
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
  return { value: val, unit: units[i] };
}

function timeAgo(secs: number | null): string {
  if (secs === null) return "never";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

const STORAGE_KEY = "araxmesh_settings";

function loadSettings(): Partial<FrontendSettings> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveSettings(s: Partial<FrontendSettings>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

/* ── SVG Icons ─────────────────────────────────────────────────── */
const ShieldIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
  </svg>
);

const PowerIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" className="toggle-icon">
    <path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42C17.99 7.86 19 9.81 19 12c0 3.87-3.13 7-7 7s-7-3.13-7-7c0-2.19 1.01-4.14 2.58-5.42L6.17 5.17C4.23 6.82 3 9.26 3 12c0 4.97 4.03 9 9 9s9-4.03 9-9c0-2.74-1.23-5.18-3.17-6.83z"/>
  </svg>
);

const LoadingIcon = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" className="toggle-icon">
    <path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/>
  </svg>
);

const DashboardIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>
);

const PeersIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
);

const SettingsIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
);

const UploadIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M5 20h14v-2H5v2zm0-10h4v6h6v-6h4l-7-7-7 7z"/></svg>
);

const DownloadIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>
);

const KeyIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>
);

const NetworkIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg>
);

const LockIcon = () => (
  <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
);

/* ── App Component ─────────────────────────────────────────────── */
type TabId = "dashboard" | "peers" | "config";

function App() {
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [vpnStatus, setVpnStatus] = useState<VpnStatusResponse>({
    running: false,
    status: null,
    error: null,
  });

  // Configuration form state
  const saved = loadSettings();
  const [privateKey, setPrivateKey] = useState(saved.private_key || "");
  const [publicKey, setPublicKey] = useState("");
  const [tunName, setTunName] = useState(saved.tun_name || "arax0");
  const [tunIp, setTunIp] = useState(saved.tun_ip || "");
  const [tunNetmask, setTunNetmask] = useState(saved.tun_netmask || "255.255.255.0");
  const [localUdp, setLocalUdp] = useState(saved.local_udp || "0.0.0.0:50001");
  const [coordinatorUrl, setCoordinatorUrl] = useState(saved.coordinator_url || "");
  const [authKey, setAuthKey] = useState(saved.auth_key || "");
  const [hostname, setHostname] = useState(saved.hostname || "");
  const [publicEndpoint, setPublicEndpoint] = useState(saved.public_endpoint || "");
  const [relayAddr, setRelayAddr] = useState(saved.relay_addr || "");
  const [magicInit, setMagicInit] = useState(saved.magic_handshake_init?.toString() || "1");
  const [magicResp, setMagicResp] = useState(saved.magic_handshake_resp?.toString() || "2");
  const [magicData, setMagicData] = useState(saved.magic_data?.toString() || "3");
  const [magicProbe, setMagicProbe] = useState(saved.magic_probe?.toString() || "4");
  const [staticPeers, setStaticPeers] = useState<string>(saved.peers?.join("\n") || "");

  // Toast
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const toastTimer = useRef<number | null>(null);

  const showToast = (message: string, type: "success" | "error" = "success") => {
    setToast({ message, type });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 3000);
  };

  // Poll status every second when running
  const pollStatus = useCallback(async () => {
    try {
      const status = await invoke<VpnStatusResponse>("get_vpn_status");
      setVpnStatus(status);
    } catch (e) {
      console.error("Failed to poll status:", e);
    }
  }, []);

  useEffect(() => {
    pollStatus(); // initial fetch
    const interval = setInterval(pollStatus, 1000);
    return () => clearInterval(interval);
  }, [pollStatus]);

  // Connection toggle
  const handleToggle = async () => {
    if (vpnStatus.running) {
      try {
        await invoke("stop_vpn");
        showToast("VPN disconnecting...");
      } catch (e) {
        showToast(`Error: ${e}`, "error");
      }
    } else {
      if (!privateKey) {
        showToast("Private key is required. Go to Settings tab.", "error");
        setActiveTab("config");
        return;
      }
      const parsedPeers = staticPeers
        .split("\n")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      const settings: FrontendSettings = {
        private_key: privateKey,
        tun_name: tunName || null,
        tun_ip: tunIp || null,
        tun_netmask: tunNetmask || null,
        local_udp: localUdp || null,
        coordinator_url: coordinatorUrl || null,
        auth_key: authKey || null,
        hostname: hostname || null,
        public_endpoint: publicEndpoint || null,
        relay_addr: relayAddr || null,
        peers: parsedPeers.length > 0 ? parsedPeers : null,
        magic_handshake_init: magicInit ? parseInt(magicInit) : null,
        magic_handshake_resp: magicResp ? parseInt(magicResp) : null,
        magic_data: magicData ? parseInt(magicData) : null,
        magic_probe: magicProbe ? parseInt(magicProbe) : null,
      };
      try {
        await invoke("start_vpn", { settings });
        showToast("VPN connecting...");
      } catch (e) {
        showToast(`Error: ${e}`, "error");
      }
    }
  };

  // Generate keypair
  const handleGenerate = async () => {
    try {
      const kp = await invoke<KeypairResponse>("generate_keypair");
      setPrivateKey(kp.private_key);
      setPublicKey(kp.public_key);
      showToast("Keypair generated!");
    } catch (e) {
      showToast(`Failed to generate keys: ${e}`, "error");
    }
  };

  // Save settings
  const handleSave = () => {
    const parsedPeers = staticPeers
      .split("\n")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    saveSettings({
      private_key: privateKey,
      tun_name: tunName,
      tun_ip: tunIp,
      tun_netmask: tunNetmask,
      local_udp: localUdp,
      coordinator_url: coordinatorUrl,
      auth_key: authKey,
      hostname,
      public_endpoint: publicEndpoint,
      relay_addr: relayAddr,
      peers: parsedPeers,
      magic_handshake_init: magicInit ? parseInt(magicInit) : undefined,
      magic_handshake_resp: magicResp ? parseInt(magicResp) : undefined,
      magic_data: magicData ? parseInt(magicData) : undefined,
      magic_probe: magicProbe ? parseInt(magicProbe) : undefined,
    });
    showToast("Settings saved!");
  };

  // Derive connection state
  const status = vpnStatus.status;
  const connState = status?.connection_state || "Disconnected";
  const isConnected = connState === "Connected";
  const isConnecting = connState === "Connecting" || connState === "Disconnecting";
  const isError = connState === "Error";

  const uploaded = formatBytes(status?.total_uploaded || 0);
  const downloaded = formatBytes(status?.total_downloaded || 0);
  const peerCount = status?.peers?.length || 0;
  const activePeers = status?.peers?.filter((p) => p.is_active).length || 0;

  return (
    <>
      {/* Animated background */}
      <div className="app-background">
        <div className="orb orb-1"></div>
        <div className="orb orb-2"></div>
        <div className="orb orb-3"></div>
      </div>

      <div className="app-container">
        {/* ── Header ──────────────────────────── */}
        <header className="app-header">
          <div className="app-logo">
            <div className="app-logo-icon">
              <ShieldIcon />
            </div>
            <span className="app-logo-text">AraxMesh</span>
            <span className="app-logo-version">v0.1.0</span>
          </div>
          <div className="header-status">
            <div
              className={`status-indicator ${
                isConnected ? "connected" : isConnecting ? "connecting" : isError ? "error" : ""
              }`}
            />
            <span className="status-label">{connState}</span>
          </div>
        </header>

        {/* ── Navigation ─────────────────────── */}
        <nav className="nav-tabs">
          {([
            { id: "dashboard" as TabId, label: "Dashboard", Icon: DashboardIcon },
            { id: "peers" as TabId, label: "Peers", Icon: PeersIcon },
            { id: "config" as TabId, label: "Settings", Icon: SettingsIcon },
          ]).map(({ id, label, Icon }) => (
            <button
              key={id}
              id={`tab-${id}`}
              className={`nav-tab ${activeTab === id ? "active" : ""}`}
              onClick={() => setActiveTab(id)}
            >
              <Icon />
              {label}
            </button>
          ))}
        </nav>

        {/* ── Content ─────────────────────────── */}
        <main className="main-content">
          {/* Dashboard */}
          {activeTab === "dashboard" && (
            <div className="dashboard fade-in">
              <div className="toggle-container">
                <button
                  id="toggle-vpn"
                  className={`toggle-button ${
                    isConnected ? "active" : isConnecting ? "connecting" : ""
                  }`}
                  onClick={handleToggle}
                  disabled={isConnecting}
                >
                  <div className="toggle-ring" />
                  {isConnecting ? <LoadingIcon /> : <PowerIcon />}
                </button>
                <span className={`toggle-label ${isConnected ? "connected" : ""}`}>
                  {isConnected
                    ? "Protected"
                    : isConnecting
                    ? connState + "..."
                    : "Disconnected"}
                </span>
                {status?.assigned_ip && (
                  <span className="assigned-ip">{status.assigned_ip}</span>
                )}
              </div>

              <div className="stats-grid slide-in">
                <div className="stat-card">
                  <span className="stat-label">
                    <UploadIcon /> Uploaded
                  </span>
                  <span className="stat-value">
                    {uploaded.value}
                    <span className="stat-unit">{uploaded.unit}</span>
                  </span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">
                    <DownloadIcon /> Downloaded
                  </span>
                  <span className="stat-value">
                    {downloaded.value}
                    <span className="stat-unit">{downloaded.unit}</span>
                  </span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">
                    <PeersIcon /> Active Peers
                  </span>
                  <span className="stat-value">
                    {activePeers}
                    <span className="stat-unit">/ {peerCount}</span>
                  </span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">
                    <LockIcon /> Encryption
                  </span>
                  <span className="stat-value" style={{ fontSize: 16 }}>
                    Noise IK
                    <span className="stat-unit">X25519</span>
                  </span>
                </div>
              </div>

              {vpnStatus.error && (
                <div
                  className="stat-card"
                  style={{ borderColor: "var(--rose-400)", width: "100%" }}
                >
                  <span className="stat-label" style={{ color: "var(--rose-400)" }}>
                    Error
                  </span>
                  <span className="stat-value" style={{ fontSize: 14, color: "var(--rose-400)" }}>
                    {vpnStatus.error}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Peers */}
          {activeTab === "peers" && (
            <div className="peers-list fade-in">
              <div className="peers-header">
                <h2 className="peers-title">Mesh Peers</h2>
                <span className="peers-count">
                  {activePeers} active / {peerCount} total
                </span>
              </div>

              {peerCount === 0 ? (
                <div className="no-peers">
                  <PeersIcon />
                  <p>No peers connected yet.</p>
                  <p style={{ marginTop: 8, fontSize: 12 }}>
                    Connect to a coordinator or add peers manually.
                  </p>
                </div>
              ) : (
                status?.peers.map((peer, i) => (
                  <div key={i} className="peer-card slide-in" style={{ animationDelay: `${i * 60}ms` }}>
                    <div className="peer-top">
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <div className={`peer-status-dot ${peer.is_active ? "active" : "inactive"}`} />
                        <span className="peer-pubkey" title={peer.pubkey}>
                          {peer.pubkey.slice(0, 16)}...{peer.pubkey.slice(-8)}
                        </span>
                      </div>
                    </div>
                    <div className="peer-details">
                      <div className="peer-detail">
                        <span className="peer-detail-label">Endpoint</span>
                        <span className="peer-detail-value">{peer.endpoint || "—"}</span>
                      </div>
                      <div className="peer-detail">
                        <span className="peer-detail-label">Allowed IPs</span>
                        <span className="peer-detail-value">
                          {peer.allowed_ips.join(", ") || "—"}
                        </span>
                      </div>
                      <div className="peer-detail">
                        <span className="peer-detail-label">Last RX</span>
                        <span className="peer-detail-value">{timeAgo(peer.last_rx_secs_ago)}</span>
                      </div>
                      <div className="peer-detail">
                        <span className="peer-detail-label">Last TX</span>
                        <span className="peer-detail-value">{timeAgo(peer.last_tx_secs_ago)}</span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Configuration */}
          {activeTab === "config" && (
            <div className="config-container fade-in">
              {/* Identity Section */}
              <div className="config-section">
                <div className="config-section-title">
                  <KeyIcon /> Identity & Keys
                </div>
                <div className="keygen-row">
                  <div className="form-group">
                    <label className="form-label">Private Key (hex)</label>
                    <input
                      id="input-private-key"
                      className="form-input"
                      type="password"
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      placeholder="64 hex characters..."
                    />
                  </div>
                  <button id="btn-generate" className="btn-generate" onClick={handleGenerate}>
                    Generate
                  </button>
                </div>
                {publicKey && (
                  <div className="form-group">
                    <label className="form-label">Public Key</label>
                    <div className="pubkey-display">{publicKey}</div>
                    <span className="form-hint">Share this with peers to establish connections.</span>
                  </div>
                )}
                <div className="form-group">
                  <label className="form-label">Hostname</label>
                  <input
                    id="input-hostname"
                    className="form-input"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="my-node"
                  />
                </div>
              </div>

              {/* Network Section */}
              <div className="config-section">
                <div className="config-section-title">
                  <NetworkIcon /> Network
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">TUN Name</label>
                    <input
                      id="input-tun-name"
                      className="form-input"
                      value={tunName}
                      onChange={(e) => setTunName(e.target.value)}
                      placeholder="arax0"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">TUN IP</label>
                    <input
                      id="input-tun-ip"
                      className="form-input"
                      value={tunIp}
                      onChange={(e) => setTunIp(e.target.value)}
                      placeholder="Auto (from coordinator)"
                    />
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">Netmask</label>
                    <input
                      id="input-tun-netmask"
                      className="form-input"
                      value={tunNetmask}
                      onChange={(e) => setTunNetmask(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Local UDP</label>
                    <input
                      id="input-local-udp"
                      className="form-input"
                      value={localUdp}
                      onChange={(e) => setLocalUdp(e.target.value)}
                      placeholder="0.0.0.0:50001"
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label className="form-label">Public Endpoint</label>
                  <input
                    id="input-public-endpoint"
                    className="form-input"
                    value={publicEndpoint}
                    onChange={(e) => setPublicEndpoint(e.target.value)}
                    placeholder="Auto-detect"
                  />
                  <span className="form-hint">External IP:port advertised to peers.</span>
                </div>
              </div>

              {/* Coordinator Section */}
              <div className="config-section">
                <div className="config-section-title">
                  <ShieldIcon /> Coordinator & Relay
                </div>
                <div className="form-group">
                  <label className="form-label">Coordinator URL</label>
                  <input
                    id="input-coordinator-url"
                    className="form-input"
                    value={coordinatorUrl}
                    onChange={(e) => setCoordinatorUrl(e.target.value)}
                    placeholder="http://your-server:3000"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Auth Key</label>
                  <input
                    id="input-auth-key"
                    className="form-input"
                    type="password"
                    value={authKey}
                    onChange={(e) => setAuthKey(e.target.value)}
                    placeholder="Pre-shared authentication key"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Relay Address</label>
                  <input
                    id="input-relay-addr"
                    className="form-input"
                    value={relayAddr}
                    onChange={(e) => setRelayAddr(e.target.value)}
                    placeholder="Auto (derived from coordinator)"
                  />
                  <span className="form-hint">TCP relay for fallback when UDP is blocked.</span>
                </div>
              </div>

              {/* Static Peers Section */}
              <div className="config-section">
                <div className="config-section-title">
                  <PeersIcon /> Static Peers (direct connections)
                </div>
                <div className="form-group">
                  <label className="form-label">Peers List</label>
                  <textarea
                    id="input-static-peers"
                    className="form-input"
                    rows={4}
                    style={{ resize: "vertical", minHeight: "80px" }}
                    value={staticPeers}
                    onChange={(e) => setStaticPeers(e.target.value)}
                    placeholder="pubkey_hex;[endpoint_ip:port];allowed_ips&#10;Example:&#10;5a3d...;192.168.1.100:50001;10.0.99.2/32"
                  />
                  <span className="form-hint">
                    Enter one peer per line. Format: <code>pubkey;[endpoint];allowed_ips</code>. Endpoint is optional. Allowed IPs can be comma-separated subnets.
                  </span>
                </div>
              </div>

              {/* DPI Bypass Section */}
              <div className="config-section">
                <div className="config-section-title">
                  <LockIcon /> DPI Bypass (Obfuscation)
                </div>
                <span className="form-hint" style={{ marginBottom: 12, display: "block" }}>
                  Custom magic bytes make the protocol signature dynamic, defeating
                  deep packet inspection.
                </span>
                <div className="magic-grid">
                  <div className="form-group">
                    <label className="form-label">Handshake Init</label>
                    <input
                      id="input-magic-init"
                      className="form-input"
                      type="number"
                      min="0"
                      max="255"
                      value={magicInit}
                      onChange={(e) => setMagicInit(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Handshake Resp</label>
                    <input
                      id="input-magic-resp"
                      className="form-input"
                      type="number"
                      min="0"
                      max="255"
                      value={magicResp}
                      onChange={(e) => setMagicResp(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Data</label>
                    <input
                      id="input-magic-data"
                      className="form-input"
                      type="number"
                      min="0"
                      max="255"
                      value={magicData}
                      onChange={(e) => setMagicData(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Probe</label>
                    <input
                      id="input-magic-probe"
                      className="form-input"
                      type="number"
                      min="0"
                      max="255"
                      value={magicProbe}
                      onChange={(e) => setMagicProbe(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <button id="btn-save" className="btn-save" onClick={handleSave}>
                Save Configuration
              </button>
            </div>
          )}
        </main>
      </div>

      {/* Toast */}
      <div className={`toast ${toast?.type || ""} ${toast ? "visible" : ""}`}>
        {toast?.message}
      </div>
    </>
  );
}

export default App;
