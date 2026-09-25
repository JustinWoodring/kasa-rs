//! KLAP HTTP transport (port 80): v1 and v2 handshake hash variants, plus
//! the derived AES-128-CBC session (`KlapSession`).
//!
//! The HTTP layer is a minimal hand-rolled HTTP/1.1 client over a persistent
//! `TcpStream` (keep-alive): KLAP needs no TLS and only ever POSTs
//! `application/octet-stream` bodies.

use std::time::Duration;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use anyhow::{Context, Result, anyhow, bail};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::Creds;

pub const DEFAULT_PORT: u16 = 80;
pub const KASA_DEFAULT_EMAIL: &str = "kasa@tp-link.net";
pub const KASA_DEFAULT_PASSWORD: &str = "kasaSetup";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_COOKIE: &str = "TP_SESSIONID";

fn sha256(payload: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in payload {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// `md5(md5(u) || md5(p))` — KLAP v1 auth hash (16 bytes).
pub fn auth_v1(user: &str, password: &str) -> [u8; 16] {
    let uh = Md5::digest(user.as_bytes());
    let ph = Md5::digest(password.as_bytes());
    let mut h = Md5::new();
    h.update(uh);
    h.update(ph);
    h.finalize().into()
}

/// `sha256(sha1(u) || sha1(p))` — KLAP v2 auth hash (32 bytes).
pub fn auth_v2(user: &str, password: &str) -> [u8; 32] {
    let uh = Sha1::digest(user.as_bytes());
    let ph = Sha1::digest(password.as_bytes());
    let mut h = Sha256::new();
    h.update(uh);
    h.update(ph);
    h.finalize().into()
}

/// handshake1 expected server hash: v1 `sha256(local || auth)`,
/// v2 `sha256(local || remote || auth)`.
fn hs1_hash(v2: bool, local: &[u8], remote: &[u8], auth: &[u8]) -> Vec<u8> {
    if v2 {
        sha256(&[local, remote, auth])
    } else {
        sha256(&[local, auth])
    }
}

/// handshake2 request body: v1 `sha256(remote || auth)`,
/// v2 `sha256(remote || local || auth)`.
fn hs2_hash(v2: bool, local: &[u8], remote: &[u8], auth: &[u8]) -> Vec<u8> {
    if v2 {
        sha256(&[remote, local, auth])
    } else {
        sha256(&[remote, auth])
    }
}

type AesBlock = aes::cipher::Block<aes::Aes128>;

fn block_of(bytes: &[u8]) -> AesBlock {
    AesBlock::try_from(bytes).expect("AES block must be 16 bytes")
}

fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], padded: &[u8]) -> Vec<u8> {
    debug_assert_eq!(padded.len() % 16, 0);
    let cipher = aes::Aes128::new(&block_of(key));
    let mut prev = block_of(iv);
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(16) {
        let mut block = block_of(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        cipher.encrypt_block(&mut block);
        prev = block;
        out.extend_from_slice(&block);
    }
    out
}

fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("ciphertext length {} is not a positive multiple of 16", data.len());
    }
    let cipher = aes::Aes128::new(&block_of(key));
    let mut prev = block_of(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = block_of(chunk);
        let cipherblock = block;
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev = cipherblock;
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn pkcs7_pad(msg: &[u8]) -> Vec<u8> {
    let pad = 16 - (msg.len() % 16);
    let mut out = Vec::with_capacity(msg.len() + pad);
    out.extend_from_slice(msg);
    out.resize(msg.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<&[u8]> {
    let last = *data.last().context("empty plaintext after decrypt")? as usize;
    if last == 0 || last > 16 || last > data.len() {
        bail!("invalid PKCS#7 padding byte {last}");
    }
    if !data[data.len() - last..].iter().all(|&b| b as usize == last) {
        bail!("inconsistent PKCS#7 padding");
    }
    Ok(&data[..data.len() - last])
}

fn i32be(v: i32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Derived session keys plus the incrementing sequence number.
pub struct KlapSession {
    key: [u8; 16],
    iv: [u8; 12],
    seq: i32,
    sig: [u8; 28],
    /// Sequence used by the most recent `encrypt` — the device encrypts its
    /// response with the same one.
    last_seq: i32,
}

impl KlapSession {
    pub fn new(local_seed: [u8; 16], remote_seed: [u8; 16], auth_hash: &[u8]) -> Self {
        let preimage: &[&[u8]] = &[&local_seed, &remote_seed, auth_hash];
        let key: [u8; 16] = sha256(&[b"lsk", &local_seed, &remote_seed, auth_hash])[..16]
            .try_into()
            .unwrap();
        let full_iv = sha256(&[b"iv", &local_seed, &remote_seed, auth_hash]);
        let iv: [u8; 12] = full_iv[..12].try_into().unwrap();
        let seq = i32::from_be_bytes(full_iv[12..16].try_into().unwrap());
        let sig: [u8; 28] = sha256(&[b"ldk", &local_seed, &remote_seed, auth_hash])[..28]
            .try_into()
            .unwrap();
        let _ = preimage;
        Self { key, iv, seq, sig, last_seq: seq }
    }

    /// Encrypt a message: returns `(signature || ciphertext, seq)` with the
    /// sequence post-incremented.
    pub fn encrypt(&mut self, msg: &[u8]) -> (Vec<u8>, i32) {
        self.seq = self.seq.wrapping_add(1);
        self.last_seq = self.seq;
        let mut iv16 = [0u8; 16];
        iv16[..12].copy_from_slice(&self.iv);
        iv16[12..].copy_from_slice(&i32be(self.seq));
        let ciphertext = aes_cbc_encrypt(&self.key, &iv16, &pkcs7_pad(msg));
        let signature = sha256(&[&self.sig, &i32be(self.seq), &ciphertext]);
        let mut out = signature;
        out.extend_from_slice(&ciphertext);
        (out, self.seq)
    }

    /// Decrypt a device response (32-byte signature prefix + ciphertext).
    pub fn decrypt(&mut self, body: &[u8]) -> Result<String> {
        if body.len() < 32 {
            bail!("KLAP response shorter than signature ({}) bytes", body.len());
        }
        let mut iv16 = [0u8; 16];
        iv16[..12].copy_from_slice(&self.iv);
        iv16[12..].copy_from_slice(&i32be(self.last_seq));
        let plain = aes_cbc_decrypt(&self.key, &iv16, &body[32..])?;
        Ok(String::from_utf8(pkcs7_unpad(&plain)?.to_vec())?)
    }
}

/// Candidate auth hashes tried in order during the handshake.
struct Candidate {
    label: &'static str,
    auth: Vec<u8>,
    v2: bool,
}

fn push_variant(out: &mut Vec<Candidate>, creds: Option<&Creds>, v2: bool) {
    if let Some(c) = creds {
        let auth = if v2 {
            auth_v2(&c.email, &c.password).to_vec()
        } else {
            auth_v1(&c.email, &c.password).to_vec()
        };
        out.push(Candidate { label: "user", auth, v2 });
    }
    let auth = if v2 {
        auth_v2(KASA_DEFAULT_EMAIL, KASA_DEFAULT_PASSWORD).to_vec()
    } else {
        auth_v1(KASA_DEFAULT_EMAIL, KASA_DEFAULT_PASSWORD).to_vec()
    };
    out.push(Candidate { label: "kasa-default", auth, v2 });
    let auth = if v2 { auth_v2("", "").to_vec() } else { auth_v1("", "").to_vec() };
    out.push(Candidate { label: "blank", auth, v2 });
}

fn candidates(creds: Option<&Creds>) -> Vec<Candidate> {
    let mut v = Vec::new();
    push_variant(&mut v, creds, false);
    push_variant(&mut v, creds, true);
    v
}

/// Decode a chunked transfer-encoded body.
pub fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(data, b"\r\n").context("chunked body: missing chunk size line")?;
        let size_line = std::str::from_utf8(&data[..line_end])?;
        let size_str = size_line.split(';').next().context("empty chunk size line")?.trim();
        let size = usize::from_str_radix(size_str, 16).context("chunked body: bad size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            bail!("chunked body: truncated chunk");
        }
        out.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            bail!("chunked body: missing chunk terminator");
        }
        data = &data[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Minimal keep-alive HTTP/1.1 connection for KLAP.
struct HttpConn {
    host: String,
    stream: Option<TcpStream>,
    pending: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpConn {
    async fn connect(host: &str) -> Result<Self> {
        let stream =
            TcpStream::connect((host, DEFAULT_PORT)).await.with_context(|| format!("connect {host}:{DEFAULT_PORT}"))?;
        Ok(Self { host: host.to_string(), stream: Some(stream), pending: Vec::new() })
    }

    async fn post(
        &mut self,
        path_query: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        if self.stream.is_none() {
            self.stream = Some(TcpStream::connect((self.host.as_str(), DEFAULT_PORT)).await?);
        }
        let mut req = format!(
            "POST {path_query} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n",
            self.host,
            body.len()
        );
        for (n, v) in extra_headers {
            req.push_str(n);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        let res = self.exchange(req.as_bytes(), body).await;
        if res.is_err() {
            // Connection is in an unknown state; force reconnect next call.
            self.stream = None;
            self.pending.clear();
        }
        res
    }

    async fn exchange(&mut self, head: &[u8], body: &[u8]) -> Result<HttpResponse> {
        let mut stream = self.stream.take().context("exchange with no connection")?;
        let res = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let mut req = Vec::with_capacity(head.len() + body.len());
            req.extend_from_slice(head);
            req.extend_from_slice(body);
            stream.write_all(&req).await?;
            stream.flush().await?;

            // Read until end of headers.
            let hdr_end = loop {
                if let Some(p) = find(&self.pending, b"\r\n\r\n") {
                    break p;
                }
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    bail!("connection closed before response headers complete");
                }
                self.pending.extend_from_slice(&buf[..n]);
            };
            let head_bytes: Vec<u8> = self.pending.drain(..hdr_end + 4).collect();
            let head_str = std::str::from_utf8(&head_bytes)?;
            let mut lines = head_str.split("\r\n");
            let status_line = lines.next().context("empty response")?;
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .context("malformed status line")?
                .parse()?;
            let mut headers = Vec::new();
            for line in lines {
                if let Some((n, v)) = line.split_once(':') {
                    headers.push((n.trim().to_string(), v.trim().to_string()));
                }
            }

            let mut body_bytes = std::mem::take(&mut self.pending);
            let chunked = headers.iter().any(|(n, v)| {
                n.eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
            });
            if chunked {
                // Read until the terminating zero chunk.
                while !ends_with_last_chunk(&body_bytes) {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        bail!("connection closed inside chunked body");
                    }
                    body_bytes.extend_from_slice(&buf[..n]);
                }
                body_bytes = decode_chunked(&body_bytes)?;
            } else if let Some(len) = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse::<usize>().ok())
            {
                while body_bytes.len() < len {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        bail!("connection closed inside body ({}/{})", body_bytes.len(), len);
                    }
                    body_bytes.extend_from_slice(&buf[..n]);
                }
                if body_bytes.len() > len {
                    self.pending = body_bytes.split_off(len);
                }
            } else {
                // Neither length nor chunked: read to EOF (connection closes).
                loop {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    body_bytes.extend_from_slice(&buf[..n]);
                }
                stream = TcpStream::connect((self.host.as_str(), DEFAULT_PORT)).await?;
            }
            Ok(HttpResponse { status, headers, body: body_bytes })
        })
        .await
        .with_context(|| format!("HTTP timeout to {}", self.host))?;
        self.stream = Some(stream);
        res
    }
}

/// True when `data` ends with a complete terminal chunk (`0\r\n` + optional
/// trailers + final `\r\n`).
fn ends_with_last_chunk(data: &[u8]) -> bool {
    find(data, b"\r\n0\r\n").is_some() && find(&data[find(data, b"\r\n0\r\n").unwrap()..], b"\r\n\r\n").is_some()
}

/// KLAP transport: owns the HTTP connection, session cookie and crypto state.
pub struct KlapTransport {
    host: String,
    conn: Option<HttpConn>,
    cookie: Option<String>,
    session: Option<KlapSession>,
    creds: Option<Creds>,
}

impl KlapTransport {
    pub async fn connect(host: &str, creds: Option<&Creds>) -> Result<Self> {
        let mut t = Self {
            host: host.to_string(),
            conn: None,
            cookie: None,
            session: None,
            creds: creds.cloned(),
        };
        t.handshake().await?;
        Ok(t)
    }

    async fn handshake(&mut self) -> Result<()> {
        if self.conn.is_none() {
            self.conn = Some(HttpConn::connect(&self.host).await?);
        }
        let mut local_seed: [u8; 16] = [0u8; 16];
        {
            use rand::Rng;
            rand::rng().fill(&mut local_seed);
        }
        let conn = self.conn.as_mut().unwrap();
        let resp = conn
            .post("/app/handshake1", &[], &local_seed)
            .await
            .with_context(|| format!("handshake1 with {}", self.host))?;
        if resp.status != 200 {
            bail!("device {} responded {} to handshake1", self.host, resp.status);
        }
        if resp.body.len() < 48 {
            bail!("handshake1 body too short ({} bytes) from {}", resp.body.len(), self.host);
        }
        let remote_seed = &resp.body[..16];
        let server_hash = &resp.body[16..48];
        let cookie = resp
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .find_map(|(_, v)| {
                let pair = v.split(';').next()?.trim();
                pair.starts_with(&format!("{SESSION_COOKIE}=")).then(|| pair.to_string())
            })
            .context("handshake1 response missing TP_SESSIONID cookie")?;

        let matched = candidates(self.creds.as_ref())
            .into_iter()
            .find(|c| hs1_hash(c.v2, &local_seed, remote_seed, &c.auth) == server_hash)
            .context(format!(
                "device {} rejected all KLAP credential variants (v1+v2)",
                self.host
            ))?;

        let payload = hs2_hash(matched.v2, &local_seed, remote_seed, &matched.auth);
        let cookie_ref = cookie.as_str();
        let resp2 = conn
            .post("/app/handshake2", &[("Cookie", cookie_ref)], &payload)
            .await
            .with_context(|| format!("handshake2 with {}", self.host))?;
        if resp2.status != 200 {
            bail!("device {} responded {} to handshake2", self.host, resp2.status);
        }
        tracing::debug!(host = %self.host, variant = matched.label, v2 = matched.v2, "KLAP handshake ok");
        self.cookie = Some(cookie);
        self.session = Some(KlapSession::new(local_seed, remote_seed.try_into().unwrap(), &matched.auth));
        Ok(())
    }

    pub async fn send_json(&mut self, req: &serde_json::Value) -> Result<serde_json::Value> {
        if self.session.is_none() {
            self.handshake().await?;
        }
        for attempt in 0..2 {
            if attempt == 1 {
                self.handshake().await?;
            }
            let session = self.session.as_mut().unwrap();
            let (payload, seq) = session.encrypt(&serde_json::to_vec(req)?);
            let conn = self.conn.as_mut().unwrap();
            let cookie = self.cookie.clone().context("handshake done but no cookie")?;
            let resp = conn
                .post(
                    &format!("/app/request?seq={seq}"),
                    &[("Cookie", cookie.as_str())],
                    &payload,
                )
                .await;
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    // Reconnect and continue; attempt 1 re-handshakes.
                    self.conn = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                    continue;
                }
            };
            match resp.status {
                200 => {
                    let session = self.session.as_mut().unwrap();
                    let plain = session.decrypt(&resp.body)?;
                    return Ok(serde_json::from_str(&plain)?);
                }
                403 => continue, // session stale: re-handshake and retry once
                status => bail!("device {} responded {status} to /app/request", self.host),
            }
        }
        Err(anyhow!("device {}: /app/request failed after re-handshake", self.host))
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

    const LOCAL: [u8; 16] = [0x11; 16];
    const REMOTE: [u8; 16] = [0x22; 16];
    const SYSINFO: &[u8] = br#"{"system":{"get_sysinfo":{}}}"#;

    #[test]
    fn auth_hash_goldens() {
        assert_eq!(hex(&auth_v1("kasa@tp-link.net", "kasaSetup")), "74b751bdd208bc155ae2a6d4167cc44d");
        assert_eq!(
            hex(&auth_v2("kasa@tp-link.net", "kasaSetup")),
            "49fc4839a2733ffbf464337648f65dc411778d4c03ec82c5e4cccc682163fa64"
        );
        assert_eq!(hex(&auth_v1("", "")), "5873dd45edd01f09c1ef2e7819369e8e");
        assert_eq!(
            hex(&auth_v2("", "")),
            "b8628ab91c74f531603f6d5b45e730e54c123a7247b8978272c03f1e13560cea"
        );
    }

    fn v1_session() -> KlapSession {
        KlapSession::new(LOCAL, REMOTE, &auth_v1("kasa@tp-link.net", "kasaSetup"))
    }

    fn v2_session() -> KlapSession {
        KlapSession::new(LOCAL, REMOTE, &auth_v2("kasa@tp-link.net", "kasaSetup"))
    }

    #[test]
    fn session_derivation_golden() {
        let s = v1_session();
        assert_eq!(hex(&s.key), "823fcb5d6ed0db0fb73e82658bf15dec");
        assert_eq!(hex(&s.iv), "ab7cde051c012a205fe0a557");
        assert_eq!(s.seq, 1982191677);
        assert_eq!(hex(&s.sig), "a198009174a8881cafc1000a9e9d4b980dbac09980f347cfdccee990");

        let s = v2_session();
        assert_eq!(hex(&s.key), "326305ef7e2c529e016d03b6d5903a93");
        assert_eq!(hex(&s.iv), "726dbd979e12f4dcd030cb6b");
        assert_eq!(s.seq, -1704394101);
        assert_eq!(hex(&s.sig), "765cf6092addd7cf8a3b8e6830bc6002e90405e5722a69c0423f78d5");
    }

    #[test]
    fn encrypt_goldens() {
        let mut s = v1_session();
        let (payload, seq) = s.encrypt(SYSINFO);
        assert_eq!(seq, 1982191678);
        assert_eq!(
            hex(&payload),
            "39de3fcd7ee1bac52756f011a3583ea8bbe113e2ce96e1be8d0f3a189448357e2c229ed2b27a5d1a73584dacafb7177eedc574ca1c21f6573f0dcf3d9e370907"
        );

        let mut s = v2_session();
        let (payload, seq) = s.encrypt(SYSINFO);
        assert_eq!(seq, -1704394100);
        assert_eq!(
            hex(&payload),
            "c4d2bd65a195bb6982a54c17412c4f8667d14dfa4db0084061759e5cbd8851c6277c602a59f7b900a310c83f9874876ed1589181afc4ed11a3b9d8f0378a1f71"
        );
    }

    #[test]
    fn roundtrip_both_versions() {
        for mut s in [v1_session(), v2_session()] {
            let mut unicode_msg = br#"{"system":{"get_sysinfo":{}},"foo":"multi byte "#.to_vec();
            unicode_msg.extend_from_slice("ü€".as_bytes());
            unicode_msg.extend_from_slice(br#""}"#);
            let msgs: Vec<Vec<u8>> = vec![
                SYSINFO.to_vec(),
                unicode_msg,
                vec![0u8; 16], // exact block: pad must be a full block
                vec![7u8; 17], // one byte into second block
            ];
            for msg in msgs {
                let (payload, _) = s.encrypt(&msg);
                assert_eq!(s.decrypt(&payload).unwrap().into_bytes(), msg);
            }
        }
    }

    #[test]
    fn decode_chunked_golden() {
        let data = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(data).unwrap(), b"Wikipedia");
        let ext = b"A;ext=1\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(ext).unwrap(), b"0123456789");
        assert!(decode_chunked(b"zz\r\n").is_err());
    }

    #[test]
    fn candidate_order() {
        let order: Vec<(&str, bool)> = candidates(None).into_iter().map(|c| (c.label, c.v2)).collect();
        assert_eq!(
            order,
            vec![("kasa-default", false), ("blank", false), ("kasa-default", true), ("blank", true)]
        );
        let order: Vec<(&str, bool)> = candidates(Some(&Creds {
            email: "a@b.c".into(),
            password: "pw".into(),
        }))
        .into_iter()
        .map(|c| (c.label, c.v2))
        .collect();
        assert_eq!(
            order,
            vec![
                ("user", false),
                ("kasa-default", false),
                ("blank", false),
                ("user", true),
                ("kasa-default", true),
                ("blank", true)
            ]
        );
    }

}
