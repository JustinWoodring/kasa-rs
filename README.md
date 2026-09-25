<div align="center">

# kasa-rs

**TP-Link Kasa smart home protocol in pure Rust**

[![Crates.io](https://img.shields.io/crates/v/kasa-rs?logo=rust)](https://crates.io/crates/kasa-rs)
[![Docs.rs](https://img.shields.io/docsrs/kasa-rs?logo=docsdotrs)](https://docs.rs/kasa-rs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange?logo=rust)](https://www.rust-lang.org)

Async client library for controlling TP-Link Kasa devices on your LAN —
both the legacy XOR protocol and the newer KLAP encryption, with UDP
discovery and a high-level bulb facade.

</div>

## Features

| | |
|---|---|
| 🔌 **Two transports** | Legacy XOR autokey framing over TCP :9999 and KLAP HTTP/AES (v1 + v2 handshake hashes) over :80 |
| 🤖 **Auto-detection** | `Transport::connect_auto` tries XOR first, falls back to KLAP, and confirms with a `get_sysinfo` round-trip |
| 🔎 **Discovery** | UDP broadcast on :9999 plus subnet-directed broadcast, deduplicated by MAC |
| 💡 **Bulb facade** | Capabilities, saved-state capture, HSV / brightness commands with device-side ramps, restore, RTT probe |
| 🔑 **Credential handling** | Account credentials, Kasa defaults, and blank credentials are all tried during the KLAP handshake; stale sessions re-handshake on 403 |
| 🧪 **Golden-vector tested** | The wire format — XOR framing, KLAP key derivation, session encryption for both handshake versions — is pinned by the test suite |

## Installation

```sh
cargo add kasa-rs
```

```toml
[dependencies]
kasa-rs = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage

### Auto-detect and control a bulb

```rust
use kasa_rs::bulb::Bulb;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Detects XOR or KLAP, reads capabilities and current state.
    let mut bulb = Bulb::connect("192.168.1.83", None).await?;
    println!("{} ({})", bulb.caps.alias, bulb.caps.model);

    // Deep red at 60% brightness with a 400 ms device-side ramp.
    bulb.set_hsv(0, 100, 60, 400).await?;

    // Put the bulb back the way you found it.
    bulb.restore().await?;
    Ok(())
}
```

### Discover devices on the LAN

```rust
let devices = kasa_rs::discover::discover_devices(3).await?;
for d in devices {
    println!(
        "{}  {}  color={} dimmable={}",
        d.ip, d.alias, d.is_color, d.is_dimmable
    );
}
```

### Raw JSON over either transport

```rust
use kasa_rs::{Transport, sysinfo_query};

let mut t = Transport::connect_auto("192.168.1.83", None).await?;
let sysinfo = t.send_json(&sysinfo_query()).await?;
```

Cloud-bound KLAP devices may need credentials:

```rust
use kasa_rs::Creds;
let creds = Creds { email: "you@example.com".into(), password: "secret".into() };
let mut t = Transport::connect_auto("192.168.1.83", Some(&creds)).await?;
```

## Transports

| | XOR | KLAP |
|---|---|---|
| Port | TCP 9999 | HTTP 80 |
| Framing | 4-byte big-endian length + autokey-XOR stream (key 171) | AES-128-CBC, keys derived from 16-byte seeds + auth hash |
| Handshake | none | challenge/response, v1 (`md5`) and v2 (`sha256(sha1‖sha1)`) auth hashes |
| Typical devices | older Kasa firmware | Kasa firmware with encryption enabled |

Devices are asked with the same IoT JSON command set regardless of
transport — [`Transport::connect_auto`] picks the right one per device.

## Protocol notes

- Bulbs accept light updates roughly once per second over WiFi. Use
  `transition_period` (device-side ramping) to hide command jitter instead
  of polling faster.
- Never-seen-the-cloud KLAP devices answer blank credentials; cloud-joined
  devices flip between account and `kasa@tp-link.net` / `kasaSetup`
  defaults. All candidates are matched against a single handshake.
- KLAP responses arrive with either `Content-Length` or chunked transfer
  encoding; both are handled.

## Minimum supported Rust

1.82 (uses `Option::is_none_or`).

## License

MIT — see [LICENSE](LICENSE).
