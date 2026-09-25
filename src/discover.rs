//! LAN discovery over the legacy XOR UDP broadcast on port 9999.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::net::UdpSocket;

use super::xor::{xor_decrypt_body, xor_encrypt_stream};
use super::{sysinfo_from_response, sysinfo_query};

pub const DISCOVERY_PORT: u16 = 9999;

/// A Kasa device that answered discovery.
#[derive(Clone, Debug)]
pub struct DiscoveredDevice {
    pub ip: String,
    pub model: String,
    pub alias: String,
    pub is_color: bool,
    pub is_dimmable: bool,
}

impl DiscoveredDevice {
    pub fn is_bulb(&self) -> bool {
        self.is_color || self.is_dimmable
    }
}

/// Broadcast the sysinfo query 3× (spaced `timeout/3`) and collect responses
/// until `timeout_secs` elapses, deduplicated by MAC.
///
/// Packets go to both 255.255.255.255 and the subnet-directed broadcast of
/// the primary interface: some APs drop the former, and only the latter is
/// delivered back to the sending host's own listeners.
pub async fn discover_devices(timeout_secs: u64) -> Result<Vec<DiscoveredDevice>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind UDP socket for discovery")?;
    socket.set_broadcast(true).context("enable broadcast")?;

    let mut targets: Vec<SocketAddr> = vec![([255, 255, 255, 255], DISCOVERY_PORT).into()];
    if let Some(bcast) = subnet_broadcast().await {
        targets.push((bcast, DISCOVERY_PORT).into());
    }

    // Real devices only parse the headerless XOR body on UDP — the TCP-style
    // 4-byte length prefix must NOT be sent here.
    let framed = xor_encrypt_stream(serde_json::to_vec(&sysinfo_query()).unwrap().as_slice());
    let spacing = timeout / 3;
    for i in 0..3 {
        if i > 0 {
            tokio::time::sleep(spacing).await;
        }
        for target in &targets {
            socket
                .send_to(&framed, target)
                .await
                .with_context(|| format!("send discovery packet to {target}"))?;
        }
    }

    let mut devices = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await;
        let (n, peer) = match recv {
            Ok(Ok((n, peer))) => (n, peer),
            Ok(Err(e)) => {
                tracing::debug!("recv error: {e}");
                break;
            }
            Err(_) => break, // deadline reached
        };
        let Some(sysinfo) = parse_response(&buf[..n]) else {
            tracing::debug!(%peer, "unparseable discovery response");
            continue;
        };
        let mac = sysinfo
            .get("mac")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let key = if mac.is_empty() { format!("{peer}") } else { mac };
        if !seen.insert(key.clone()) {
            continue;
        }
        devices.push(DiscoveredDevice {
            ip: peer.ip().to_string(),
            model: sysinfo.get("model").and_then(Value::as_str).unwrap_or("?").to_string(),
            alias: sysinfo.get("alias").and_then(Value::as_str).unwrap_or("?").to_string(),
            is_color: sysinfo.get("is_color").and_then(Value::as_i64).unwrap_or(0) != 0,
            is_dimmable: sysinfo.get("is_dimmable").and_then(Value::as_i64).unwrap_or(0) != 0,
        });
    }
    Ok(devices)
}

/// Subnet-directed broadcast of the primary interface (`/24` heuristic),
/// learned without sending a packet via a connected UDP socket.
async fn subnet_broadcast() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("8.8.8.8:80").await.ok()?;
    let local = socket.local_addr().ok()?;
    if let IpAddr::V4(v4) = local.ip() {
        let o = v4.octets();
        Some(Ipv4Addr::new(o[0], o[1], o[2], 255))
    } else {
        None
    }
}

/// Strip an optional 4-byte length header, decrypt, unwrap sysinfo.
fn parse_response(datagram: &[u8]) -> Option<Value> {
    let body = if datagram.len() > 4 {
        let claimed = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]) as usize;
        if claimed == datagram.len() - 4 {
            &datagram[4..]
        } else {
            datagram
        }
    } else {
        datagram
    };
    let plain = xor_decrypt_body(body);
    let value: Value = serde_json::from_slice(&plain).ok()?;
    sysinfo_from_response(&value).ok().cloned()
}
