//! TP-Link Kasa smart home protocol in pure Rust.
//!
//! - [`xor::XorTransport`]: legacy XOR autokey framing over TCP :9999
//! - [`klap::KlapTransport`]: KLAP HTTP/AES (v1 + v2 handshakes) over :80
//! - [`Transport::connect_auto`]: tries XOR, falls back to KLAP, confirms
//!   with a `get_sysinfo` round-trip
//! - [`discover::discover_devices`]: UDP broadcast discovery on :9999
//! - [`bulb::Bulb`]: bulb facade (capabilities, saved state, light commands)
//!
//! The wire format is pinned by the protocol golden-vector test suite.

pub mod bulb;
pub mod discover;
pub mod klap;
pub mod xor;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Kasa cloud credentials (only needed for KLAP devices).
#[derive(Clone, Debug)]
pub struct Creds {
    pub email: String,
    pub password: String,
}

/// The IoT sysinfo query shared by both transports and discovery.
pub fn sysinfo_query() -> Value {
    json!({"system": {"get_sysinfo": {}}})
}

pub const LIGHT_SERVICE: &str = "smartlife.iot.smartbulb.lightingservice";
pub const SET_LIGHT_METHOD: &str = "transition_light_state";

/// Any transport speaking the IoT command set.
pub enum Transport {
    Xor(xor::XorTransport),
    Klap(klap::KlapTransport),
}

impl Transport {
    /// Try legacy XOR first (fast refusal on KLAP-only devices), then KLAP.
    /// Confirms whichever connects with a `get_sysinfo` round-trip.
    pub async fn connect_auto(host: &str, creds: Option<&Creds>) -> Result<Self> {
        let query = sysinfo_query();
        let xor_err: String = match tokio::time::timeout(
            Duration::from_secs(3),
            xor::XorTransport::connect(host),
        )
        .await
        {
            Ok(Ok(mut t)) => match t.send_json(&query).await {
                Ok(_) => {
                    tracing::debug!(host, transport = "xor", "connected");
                    return Ok(Transport::Xor(t));
                }
                Err(e) => format!("xor connected but sysinfo failed: {e:#}"),
            },
            Ok(Err(e)) => format!("xor refused: {e:#}"),
            Err(_) => "xor connect timed out".into(),
        };

        match tokio::time::timeout(
            Duration::from_secs(5),
            klap::KlapTransport::connect(host, creds),
        )
        .await
        {
            Ok(Ok(mut t)) => {
                t.send_json(&query)
                    .await
                    .with_context(|| format!("klap connected to {host} but sysinfo failed"))?;
                tracing::debug!(host, transport = "klap", "connected");
                Ok(Transport::Klap(t))
            }
            Ok(Err(e)) => bail!("no transport for {host}: {xor_err}; klap failed: {e:#}"),
            Err(_) => bail!("no transport for {host}: {xor_err}; klap connect timed out"),
        }
    }

    pub async fn send_json(&mut self, req: &Value) -> Result<Value> {
        match self {
            Transport::Xor(t) => t.send_json(req).await,
            Transport::Klap(t) => t.send_json(req).await,
        }
    }
}

/// Unwrap `system.get_sysinfo` from a query response and reject device-side
/// protocol errors (`err_code != 0` at any level).
pub fn sysinfo_from_response(resp: &Value) -> Result<&Value> {
    check_err_code(resp)?;
    resp.pointer("/system/get_sysinfo")
        .context("response missing system.get_sysinfo")
}

/// Recursively reject `err_code != 0` anywhere in a device response.
pub fn check_err_code(v: &Value) -> Result<()> {
    match v {
        Value::Object(map) => {
            if let Some(code) = map.get("err_code").and_then(Value::as_i64) {
                if code != 0 {
                    let msg = map
                        .get("err_msg")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error");
                    bail!("device returned err_code {code}: {msg}");
                }
            }
            for child in map.values() {
                check_err_code(child)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                check_err_code(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}
