//! Sockets: the UDP request/response loop (restricted mode) and the TCP port, which serves Sync and
//! push sessions (see `notify.rs`), told apart by the first frame.

use crate::app::{App, now};
use crate::wire::*;
use anyhow::{Result, anyhow, bail};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub async fn serve_udp(app: Arc<App>, sock: Arc<UdpSocket>) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut last_drop_log: Option<std::time::Instant> = None;
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let Some((slot, pt)) = app.keys.lock().unwrap().open(&buf[..n]) else {
            // not ours / replay: no reply, but say so in the log (at most every 10 s)
            if last_drop_log.is_none_or(|t| t.elapsed().as_secs() >= 10) {
                last_drop_log = Some(std::time::Instant::now());
                log::warn!(
                    "udp {peer}: {n} B not accepted (wrong key or a replay) — if this is your phone, it was set up \
                     with an older QR: stop the server, run `svpn provision` and scan the new QR"
                );
            }
            continue;
        };
        let (app, sock) = (app.clone(), sock.clone());
        tokio::spawn(async move {
            let what = pt.first().map_or("empty", |&h| type_name(split_hdr(h).0));
            let (mut pkts, mut bytes) = (0, 0);
            for r in app.handle(&pt).await {
                let pkt = app.keys.lock().unwrap().seal(slot, &r);
                pkts += 1;
                bytes += pkt.len();
                if let Err(e) = sock.send_to(&pkt, peer).await {
                    log::warn!("udp send to {peer}: {e}");
                }
            }
            log::info!("udp {peer}: {what} ({n} B) -> {pkts} packet(s), {bytes} B");
        });
    }
}

fn type_name(t: u8) -> &'static str {
    match t {
        T_CHECK => "check",
        T_FETCH => "fetch",
        T_SEND => "send",
        T_MEDIA => "media",
        T_PROXY_CFG => "proxy settings",
        T_CA => "certificate",
        T_USAGE => "data usage",
        _ => "unknown request",
    }
}

pub async fn serve_sync(app: Arc<App>, listener: TcpListener) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let (slot, first) = match tokio::time::timeout(std::time::Duration::from_secs(30), recv(&app, &mut stream)).await {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => return log::warn!("tcp from {peer}: {e:#}"),
                Err(_) => return log::debug!("tcp from {peer}: nothing sent"),
            };
            match first.first().map(|&h| split_hdr(h).0) {
                Some(T_PUSH_HELLO) => {
                    if let Err(e) = crate::notify::push_session(&app, stream, peer, slot, &first).await {
                        log::info!("push: phone {peer} left ({e:#})");
                    }
                }
                _ => {
                    log::info!("sync from {peer}: started");
                    match sync_session(&app, stream, slot, &first).await {
                        Ok(()) => log::info!("sync with {peer} done"),
                        Err(e) => log::warn!("sync with {peer} failed: {e:#}"),
                    }
                }
            }
        });
    }
}

const MAX_FRAME: u64 = 32 << 20;

pub async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>> {
    let mut len = 0u64;
    for shift in (0..64).step_by(7) {
        let b = s.read_u8().await?;
        len |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut f = vec![0u8; len as usize];
    s.read_exact(&mut f).await?;
    Ok(f)
}

pub async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, pkt: &[u8]) -> Result<()> {
    let mut b = Vec::with_capacity(pkt.len() + 5);
    put_uv(&mut b, pkt.len() as u64);
    b.extend_from_slice(pkt);
    s.write_all(&b).await?;
    Ok(())
}

async fn recv(app: &App, s: &mut TcpStream) -> Result<(usize, Vec<u8>)> {
    let f = read_frame(s).await?;
    app.keys.lock().unwrap().open(&f).ok_or_else(|| anyhow!("bad frame"))
}

async fn send(app: &App, s: &mut TcpStream, slot: usize, pt: &[u8]) -> Result<()> {
    let pkt = app.keys.lock().unwrap().seal(slot, pt);
    write_frame(s, &pkt).await
}

/// Sync: rotate the key, send every chat's missing history, train + ship a dictionary.
async fn sync_session(app: &App, mut s: TcpStream, slot: usize, hello: &[u8]) -> Result<()> {
    // 1. key rotation, authenticated by the current key
    if hello.len() != 33 || split_hdr(hello[0]).0 != T_SYNC_HELLO {
        bail!("expected SYNC_HELLO");
    }
    let phone_pub = PublicKey::from(<[u8; 32]>::try_from(&hello[1..])?);
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let my_pub = PublicKey::from(&secret);
    let mut r = vec![hdr(T_SYNC_HELLO, CODEC_RAW)];
    r.extend_from_slice(my_pub.as_bytes());
    send(app, &mut s, slot, &r).await?;
    let shared = secret.diffie_hellman(&phone_pub);
    app.keys.lock().unwrap().rotate(slot, shared.as_bytes())?;
    app.hub.key_rotated();

    // 2. cursors (under the new key, which retires the old one)
    let (slot, cur) = recv(app, &mut s).await?;
    if slot != 0 || split_hdr(cur[0]).0 != T_SYNC_CURSORS {
        bail!("expected SYNC_CURSORS under the new key");
    }
    let mut b = &cur[1..];
    let n = get_uv(&mut b)?;
    let mut cursors = std::collections::HashMap::new();
    for _ in 0..n {
        cursors.insert(get_uv(&mut b)? as usize, get_uv(&mut b)?);
    }

    // 3. history of every chat
    let frames: Vec<Vec<u8>> = {
        let st = app.store.lock().unwrap();
        st.chats
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut base = cursors.get(&i).copied().unwrap_or(0);
                let off = c.offset_after(base).unwrap_or_else(|| {
                    base = 0;
                    0
                });
                let mut f = vec![hdr(T_SYNC_CHAT, CODEC_RAW)];
                put_uv(&mut f, i as u64);
                put_bytes(&mut f, c.name.as_bytes());
                f.push(c.service());
                put_uv(&mut f, base);
                f.extend_from_slice(&c.stream[off..]);
                f
            })
            .collect()
    };
    for f in frames {
        send(app, &mut s, 0, &f).await?;
    }

    // 4. dictionary trained on all chats (CPU heavy -> blocking pool)
    let samples: Vec<Vec<u8>> = {
        let st = app.store.lock().unwrap();
        st.chats
            .iter()
            .flat_map(|c| {
                c.index.iter().enumerate().map(|(k, e)| {
                    let end = c.index.get(k + 1).map_or(c.stream.len(), |n| n.1);
                    c.stream[e.1..end].to_vec()
                })
            })
            .collect()
    };
    let trained = tokio::task::spawn_blocking(move || {
        let total: usize = samples.iter().map(|s| s.len()).sum();
        if samples.len() < 64 {
            return None;
        }
        zstd::dict::from_samples(&samples, SYNC_DICT_SIZE.min(total / 4).max(1024)).ok()
    })
    .await?;
    let dict_id = {
        let mut st = app.store.lock().unwrap();
        match trained {
            Some(d) => st.add_dict(d)?,
            None => st.dict_id(),
        }
    };
    let dict = app.store.lock().unwrap().dict(dict_id).unwrap_or_default().to_vec();
    let mut f = vec![hdr(T_SYNC_DICT, CODEC_RAW)];
    put_uv(&mut f, dict_id);
    f.extend_from_slice(&dict);
    send(app, &mut s, 0, &f).await?;

    let mut f = vec![hdr(T_SYNC_DONE, CODEC_RAW)];
    put_uv(&mut f, app.store.lock().unwrap().head);
    f.push(app.states());
    put_uv(&mut f, zz(now()));
    send(app, &mut s, 0, &f).await?;
    s.shutdown().await?;
    Ok(())
}
