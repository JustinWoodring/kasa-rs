//! Legacy TP-Link XOR smart-home protocol (TCP :9999): a 4-byte big-endian
//! length prefix followed by an autokey-XOR stream (initial key 171).
//! The codec is pure data so it is unit-testable without IO;
//! [`XorTransport`] owns the socket.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const INITIALIZATION_VECTOR: u8 = 171;
const LENGTH_HEADER_BYTES: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_PORT: u16 = 9999;

/// Autokey-XOR stream only (`key = 171`, then `key ^= plain` per byte).
pub fn xor_encrypt_stream(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len());
    let mut key = INITIALIZATION_VECTOR;
    for &b in plain {
        key ^= b;
        out.push(key);
    }
    out
}

/// Encrypt a plaintext request: 4-byte big-endian length prefix followed by
/// the autokey-XOR stream.
pub fn xor_encrypt(plain: &[u8]) -> Vec<u8> {
    let mut out = (plain.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&xor_encrypt_stream(plain));
    out
}

/// Decrypt a response body (no length header): autokey-XOR stream.
pub fn xor_decrypt_body(cipher: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cipher.len());
    let mut key = INITIALIZATION_VECTOR;
    for &c in cipher {
        out.push(key ^ c);
        key = c;
    }
    out
}

/// Persistent TCP connection to a Kasa device speaking the XOR protocol.
pub struct XorTransport {
    host: String,
    stream: Option<TcpStream>,
}

impl XorTransport {
    /// Connect eagerly. `send_json` reconnects lazily afterwards.
    pub async fn connect(host: &str) -> Result<Self> {
        let stream = Self::dial(host).await?;
        Ok(Self {
            host: host.to_string(),
            stream: Some(stream),
        })
    }

    async fn dial(host: &str) -> Result<TcpStream> {
        let stream = tokio::time::timeout(REQUEST_TIMEOUT, TcpStream::connect((host, DEFAULT_PORT)))
            .await
            .with_context(|| format!("timeout connecting to {host}:{DEFAULT_PORT}"))?
            .with_context(|| format!("connect {host}:{DEFAULT_PORT}"))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Send a JSON request and parse the JSON response. Any IO error drops
    /// the connection so the next call reconnects.
    pub async fn send_json(&mut self, req: &serde_json::Value) -> Result<serde_json::Value> {
        if self.stream.is_none() {
            self.stream = Some(Self::dial(&self.host).await?);
        }
        let plain = serde_json::to_vec(req)?;
        let res = self.send_preconnected(&plain).await;
        if let Err(e) = res {
            self.stream = None;
            return Err(e.context(format!("xor transport to {}", self.host)));
        }
        res
    }

    async fn send_preconnected(&mut self, plain: &[u8]) -> Result<serde_json::Value> {
        let stream = self
            .stream
            .as_mut()
            .context("send_preconnected without a connection")?;
        let framed: Vec<u8> = tokio::time::timeout(REQUEST_TIMEOUT, async {
            stream.write_all(&xor_encrypt(plain)).await?;
            stream.flush().await?;
            let mut header = [0u8; LENGTH_HEADER_BYTES];
            stream.read_exact(&mut header).await?;
            let len = u32::from_be_bytes(header) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;
            Ok::<Vec<u8>, anyhow::Error>(body)
        })
        .await
        .with_context(|| format!("request timeout to {}", self.host))??;
        let plain_resp = xor_decrypt_body(&framed);
        Ok(serde_json::from_slice(&plain_resp)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Golden vector for the sysinfo query.
    #[test]
    fn encrypt_sysinfo_golden() {
        let req = br#"{"system":{"get_sysinfo":{}}}"#;
        let framed = xor_encrypt(req);
        assert_eq!(&framed[..4], &unhex("0000001d"));
        assert_eq!(hex(&framed[4..]), "d0f281f88bff9af7d5ef94b6d1b4c09fec95e68fe187e8caf08bf68bf6");
    }

    #[test]
    fn decrypt_sysinfo_golden() {
        let body = unhex("d0f281f88bff9af7d5ef94b6d1b4c09fec95e68fe187e8caf08bf68bf6");
        assert_eq!(xor_decrypt_body(&body), b"{\"system\":{\"get_sysinfo\":{}}}".to_vec());
    }

    #[test]
    fn roundtrip_utf8_and_high_bytes() {
        // Payload with multi-byte UTF-8 and 0xFF bytes.
        let mut payload: Vec<u8> = br#"{"alias":"Lamp #1","extra":"#.to_vec();
        payload.push(0xff);
        payload.extend_from_slice("ö€".as_bytes());
        payload.push(0xff);
        payload.extend_from_slice(b"end}");
        let framed = xor_encrypt(&payload);
        assert_eq!(&framed[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(xor_decrypt_body(&framed[4..]), payload);
    }
}
