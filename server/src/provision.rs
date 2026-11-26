//! `svpn init` / `svpn provision`: keys, config and the phone's setup QR.

use crate::keys::Keys;
use crate::wire::*;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// Public host name or IP the phone connects to.
    pub endpoint: String,
    /// UDP (messaging) and TCP (Sync) port.
    pub port: u16,
    pub wg_port: u16,
    pub server_wg_private: String,
    pub client_wg_private: String,
}

pub fn load_config(data: &Path) -> Result<Config> {
    let s = std::fs::read_to_string(data.join("config.toml")).context("no config.toml; run `svpn init` first")?;
    Ok(toml::from_str(&s)?)
}

fn wg_key() -> StaticSecret {
    StaticSecret::random_from_rng(rand::rngs::OsRng)
}

fn b64(k: &[u8]) -> String {
    STANDARD.encode(k)
}

/// The server's WireGuard key and the phone's public key.
pub fn wg_keys(cfg: &Config) -> Result<(StaticSecret, PublicKey)> {
    let client = StaticSecret::from(dec(&cfg.client_wg_private)?);
    Ok((StaticSecret::from(dec(&cfg.server_wg_private)?), PublicKey::from(&client)))
}

fn dec(s: &str) -> Result<[u8; 32]> {
    Ok(STANDARD.decode(s)?.as_slice().try_into()?)
}

/// Writes config.toml and the messaging key; returns the phone setup code (printed by the caller
/// after WhatsApp is linked, so the WhatsApp QRs don't scroll it away).
pub fn init(data: &Path, endpoint: &str, port: u16, wg_port: u16) -> Result<String> {
    std::fs::create_dir_all(data)?;
    // keys, WhatsApp session and messages live here: owner only
    std::fs::set_permissions(data, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    if data.join("config.toml").exists() {
        anyhow::bail!("{} already initialised", data.display());
    }
    let cfg = Config {
        endpoint: endpoint.to_owned(),
        port,
        wg_port,
        server_wg_private: b64(wg_key().as_bytes()),
        client_wg_private: b64(wg_key().as_bytes()),
    };
    std::fs::write(data.join("config.toml"), toml::to_string(&cfg)?)?;
    println!("wrote {}/config.toml", data.display());
    new_keys(data)
}

/// Creates a fresh messaging key (resetting packet counters) and prints the phone setup QR.
/// Run it while the server is stopped.
pub fn provision(data: &Path) -> Result<()> {
    print_setup(&new_keys(data)?)
}

/// Creates a fresh messaging key; returns the phone setup code (`svpn:…`).
fn new_keys(data: &Path) -> Result<String> {
    let cfg = load_config(data)?;
    let mut psk = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut psk);
    Keys::create(&data.join("keys.bin"), psk)?;

    let server_pub = PublicKey::from(&wg_keys(&cfg)?.0);
    let mut b = vec![1u8]; // format version
    put_bytes(&mut b, cfg.endpoint.as_bytes());
    put_uv(&mut b, cfg.port as u64);
    put_uv(&mut b, cfg.wg_port as u64);
    b.extend_from_slice(&dec(&cfg.client_wg_private)?);
    b.extend_from_slice(server_pub.as_bytes());
    b.extend_from_slice(&psk);
    Ok(format!("svpn:{}", URL_SAFE_NO_PAD.encode(&b)))
}

pub fn print_setup(text: &str) -> Result<()> {
    println!("\nScan this in the squeezeVPN app (setup screen) — it contains secret keys, don't share it:");
    qr2term::print_qr(text)?;
    println!("{text}\n");
    Ok(())
}
