//! Bulb facade: capabilities, saved state, light commands, RTT probe.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::{Transport, check_err_code, sysinfo_from_response};

/// Device capabilities relevant to this tool, from sysinfo.
#[derive(Clone, Debug)]
pub struct Caps {
    pub is_color: bool,
    pub is_dimmable: bool,
    pub model: String,
    pub alias: String,
}

/// Pre-play light state to restore at exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavedState {
    Off,
    On {
        hue: u16,
        saturation: u8,
        brightness: u8,
        color_temp: u16,
    },
}

pub struct Bulb {
    pub host: String,
    transport: Transport,
    pub caps: Caps,
    pub saved: SavedState,
}

impl Bulb {
    /// Connect, confirm with sysinfo, parse caps and saved state.
    /// Errors when the device is neither color nor dimmable.
    pub async fn connect(host: &str, creds: Option<&super::Creds>) -> Result<Self> {
        let mut transport = Transport::connect_auto(host, creds).await?;
        let resp = transport.send_json(&super::sysinfo_query()).await?;
        let sysinfo = sysinfo_from_response(&resp)?.clone();
        let caps = Caps {
            is_color: sysinfo.get("is_color").and_then(Value::as_i64).unwrap_or(0) != 0,
            is_dimmable: sysinfo.get("is_dimmable").and_then(Value::as_i64).unwrap_or(0) != 0,
            model: sysinfo
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            alias: sysinfo
                .get("alias")
                .and_then(Value::as_str)
                .unwrap_or(host)
                .to_string(),
        };
        if !caps.is_color && !caps.is_dimmable {
            bail!(
                "{} ({}) is neither color nor dimmable — is it really a bulb?",
                caps.alias,
                caps.model
            );
        }
        let saved = saved_state_from_sysinfo(&sysinfo);
        Ok(Self { host: host.to_string(), transport, caps, saved })
    }

    /// Set color and brightness on a color-capable bulb with a device-side
    /// ramp. Hue 0–360, saturation and brightness 0–100.
    pub async fn set_hsv(&mut self, hue: u16, sat: u8, bri: u8, transition_ms: u32) -> Result<()> {
        if !self.caps.is_color {
            bail!("{} ({}) does not support color", self.caps.alias, self.caps.model);
        }
        let state = json!({
            "on_off": 1,
            "ignore_default": 1,
            "hue": hue,
            "saturation": sat,
            "brightness": bri,
            "color_temp": 0,
            "transition_period": transition_ms,
        });
        self.send_light(state).await
    }

    /// Set brightness on a dimmable bulb with a device-side ramp.
    pub async fn set_brightness(&mut self, bri: u8, transition_ms: u32) -> Result<()> {
        if !self.caps.is_dimmable {
            bail!("{} ({}) does not support brightness", self.caps.alias, self.caps.model);
        }
        let state = json!({
            "on_off": 1,
            "brightness": bri,
            "transition_period": transition_ms,
        });
        self.send_light(state).await
    }

    async fn send_light(&mut self, state: Value) -> Result<()> {
        let req = json!({ super::LIGHT_SERVICE: { super::SET_LIGHT_METHOD: state } });
        let resp = self.transport.send_json(&req).await?;
        check_err_code(&resp)?;
        Ok(())
    }

    /// Put the bulb back the way we found it.
    pub async fn restore(&mut self) -> Result<()> {
        let state = match self.saved {
            SavedState::Off => json!({"on_off": 0, "transition_period": 500}),
            SavedState::On { hue, saturation, brightness, color_temp } => {
                if self.caps.is_color {
                    json!({
                        "on_off": 1,
                        "ignore_default": 1,
                        "hue": hue,
                        "saturation": saturation,
                        "brightness": brightness,
                        "color_temp": color_temp,
                        "transition_period": 500,
                    })
                } else {
                    json!({"on_off": 1, "brightness": brightness, "transition_period": 500})
                }
            }
        };
        let req = json!({ super::LIGHT_SERVICE: { super::SET_LIGHT_METHOD: state } });
        let resp = self.transport.send_json(&req).await?;
        check_err_code(&resp)?;
        Ok(())
    }

    /// Median of 5 timed sysinfo round-trips.
    pub async fn rtt_probe(&mut self) -> Result<Duration> {
        let mut times = Vec::with_capacity(5);
        for _ in 0..5 {
            let start = Instant::now();
            self.transport
                .send_json(&super::sysinfo_query())
                .await
                .with_context(|| format!("rtt probe to {}", self.host))?;
            times.push(start.elapsed());
        }
        times.sort();
        Ok(times[2])
    }
}

/// When off, live values live under `light_state.dft_on_state`; storing just
/// Off is sufficient for restore.
fn saved_state_from_sysinfo(sysinfo: &Value) -> SavedState {
    let Some(light) = sysinfo.get("light_state") else {
        return SavedState::Off;
    };
    if light.get("on_off").and_then(Value::as_i64).unwrap_or(0) == 0 {
        return SavedState::Off;
    }
    SavedState::On {
        hue: light.get("hue").and_then(Value::as_i64).unwrap_or(0) as u16,
        saturation: light.get("saturation").and_then(Value::as_i64).unwrap_or(0) as u8,
        brightness: light.get("brightness").and_then(Value::as_i64).unwrap_or(100) as u8,
        color_temp: light.get("color_temp").and_then(Value::as_i64).unwrap_or(0) as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn saved_state_on() {
        let sysinfo = json!({"light_state": {"on_off": 1, "hue": 180, "saturation": 50, "brightness": 77, "color_temp": 2700}});
        assert_eq!(
            saved_state_from_sysinfo(&sysinfo),
            SavedState::On { hue: 180, saturation: 50, brightness: 77, color_temp: 2700 }
        );
    }

    #[test]
    fn saved_state_off_ignores_dft_on_state() {
        let sysinfo = json!({"light_state": {"on_off": 0, "dft_on_state": {"hue": 0, "saturation": 0, "brightness": 50, "color_temp": 2700}}});
        assert_eq!(saved_state_from_sysinfo(&sysinfo), SavedState::Off);
    }

    #[test]
    fn saved_state_missing_defaults_off() {
        assert_eq!(saved_state_from_sysinfo(&json!({})), SavedState::Off);
    }
}
