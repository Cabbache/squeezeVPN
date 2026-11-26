//! Real-time notifications. While its VPN is on, the phone keeps one quiet TCP connection open on the
//! messaging port (a "push session", opened with T_PUSH_HELLO instead of SYNC_HELLO). When a message
//! arrives that WhatsApp or Signal would notify about, a T_PUSH frame goes down it right away. The phone
//! sends T_PING about every 9 minutes, which keeps the carrier's NAT entry alive.

use crate::app::App;
use crate::net::{read_frame, write_frame};
use crate::wire::*;
use anyhow::{Result, bail};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};

/// A session that hears nothing from the phone for this long is closed (the phone pings every ~9 min).
const IDLE: Duration = Duration::from_secs(30 * 60);
/// Recent notifications kept for a phone that reconnects (e.g. after switching networks).
const RECENT: usize = 64;

/// Should a message notify the phone? Like WhatsApp: not in a muted chat, unless it mentions you or
/// replies to you. `muted_until`: 0 = not muted, -1 = muted for ever, else unix seconds.
pub fn should_notify(muted_until: i64, now: i64, mentioned_me: bool, replied_to_me: bool) -> bool {
    let muted = muted_until == -1 || muted_until > now;
    !muted || mentioned_me || replied_to_me
}

/// A message someone else sent, as stored (`seq` = store head after it).
pub struct Arrived<'a> {
    pub service: u8,
    pub jid: &'a str,
    pub chat: usize,
    pub seq: u64,
    pub chat_name: &'a str,
    /// Who wrote it, in group chats (empty in 1:1 chats).
    pub sender: &'a str,
    pub kind: u8,
    pub text: &'a str,
}

/// Notifies the phone about a message if WhatsApp would (see `should_notify`): muted chats are the
/// ones muted in WhatsApp or in our app.
pub fn message_arrived(app: &App, m: &Arrived, mentioned_me: bool, replied_to_me: bool) {
    let muted_until = app.mutes.lock().unwrap().get(m.jid);
    if !should_notify(muted_until, crate::app::now(), mentioned_me, replied_to_me) {
        return log::debug!("message in muted chat {}: no notification", m.chat_name);
    }
    let preview: String = m.text.chars().take(100).collect();
    let frame = push_frame(m.service, m.seq, m.chat, m.chat_name, m.sender, m.kind, &preview);
    app.hub.publish(Push { service: m.service, seq: m.seq, frame });
}

/// Muted chats by chat id: from WhatsApp's own settings (synced to linked devices, `data/mutes.bin`)
/// and from the bell in our app (any service, `data/app_mutes.bin`).
#[derive(Default)]
pub struct Mutes {
    wa: HashMap<String, i64>,
    app: HashMap<String, i64>,
}

fn load_map(path: &Path) -> HashMap<String, i64> {
    let mut m = HashMap::new();
    if let Ok(b) = std::fs::read(path) {
        let mut s = &b[..];
        while !s.is_empty() {
            let (Ok(jid), Ok(until)) = (get_str(&mut s), get_uv(&mut s)) else { break };
            m.insert(jid, unzz(until));
        }
    }
    m
}

fn save_map(m: &HashMap<String, i64>, path: &Path) {
    let mut b = Vec::new();
    for (jid, until) in m {
        put_bytes(&mut b, jid.as_bytes());
        put_uv(&mut b, zz(*until));
    }
    if let Err(e) = std::fs::write(path, b) {
        log::warn!("saving mutes: {e}");
    }
}

impl Mutes {
    pub fn load(data: &Path) -> Mutes {
        Mutes { wa: load_map(&data.join("mutes.bin")), app: load_map(&data.join("app_mutes.bin")) }
    }

    /// Muted until (see `should_notify`): muted in our app wins, else WhatsApp's own setting.
    pub fn get(&self, jid: &str) -> i64 {
        self.app.get(jid).or(self.wa.get(jid)).copied().unwrap_or(0)
    }

    /// Chats muted in WhatsApp.
    pub fn len(&self) -> usize {
        self.wa.len()
    }

    /// Records a chat's WhatsApp mute state (0 = unmuted) and saves the list.
    pub fn set(&mut self, jid: &str, until: i64, data: &Path) {
        if until == 0 {
            self.wa.remove(jid);
        } else {
            self.wa.insert(jid.to_owned(), until);
        }
        save_map(&self.wa, &data.join("mutes.bin"));
    }

    /// The bell in our app: mutes a chat for ever, or lifts that.
    pub fn set_app(&mut self, jid: &str, muted: bool, data: &Path) {
        if muted {
            self.app.insert(jid.to_owned(), -1);
        } else {
            self.app.remove(jid);
        }
        save_map(&self.app, &data.join("app_mutes.bin"));
    }
}

/// A T_PUSH frame and what it is about.
pub struct Push {
    pub service: u8,
    pub seq: u64,
    pub frame: Vec<u8>,
}

/// Hands notifications to the open push sessions.
pub struct Hub {
    live: broadcast::Sender<Arc<Push>>,
    recent: Mutex<VecDeque<Arc<Push>>>,
    /// Bumped when Sync rotates the key: sessions under the old key close and the phone reconnects.
    key_gen: watch::Sender<u64>,
}

impl Default for Hub {
    fn default() -> Self {
        Hub { live: broadcast::channel(64).0, recent: Mutex::default(), key_gen: watch::channel(0).0 }
    }
}

impl Hub {
    pub fn publish(&self, p: Push) {
        let p = Arc::new(p);
        let mut r = self.recent.lock().unwrap();
        if r.len() == RECENT {
            r.pop_front();
        }
        r.push_back(p.clone());
        let _ = self.live.send(p); // no session open: nothing to do
    }

    #[cfg(test)]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Push>> {
        self.live.subscribe()
    }

    pub fn key_rotated(&self) {
        self.key_gen.send_modify(|g| *g += 1);
    }
}

/// Runs one push session; `slot`/`hello` are the already opened T_PUSH_HELLO.
pub async fn push_session(app: &App, s: TcpStream, peer: SocketAddr, slot: usize, hello: &[u8]) -> Result<()> {
    let mut b = &hello[1..];
    let services = get_u8(&mut b)?;
    let since = get_uv(&mut b).unwrap_or(0);
    let wanted = |p: &Push| services & (1 << p.service) != 0;
    // subscribe before reading the backlog, so nothing falls in between (the phone ignores repeats)
    let mut live = app.hub.live.subscribe();
    let mut key_gen = app.hub.key_gen.subscribe();
    let backlog: Vec<Arc<Push>> = app.hub.recent.lock().unwrap().iter().filter(|p| p.seq > since && wanted(p)).cloned().collect();
    log::info!("push: phone connected from {peer}{}", if backlog.is_empty() { String::new() } else { format!(", {} missed", backlog.len()) });

    let (mut rd, mut wr) = s.into_split();
    // frames from the phone, read in their own task (reading inside select! could lose a half-read frame)
    let (in_tx, mut incoming) = mpsc::channel::<Vec<u8>>(4);
    let reader = tokio::spawn(async move {
        while let Ok(f) = read_frame(&mut rd).await {
            if in_tx.send(f).await.is_err() {
                break;
            }
        }
    });
    let seal = |pt: &[u8]| app.keys.lock().unwrap().seal(slot, pt);
    let r: Result<()> = async {
        for p in backlog {
            write_frame(&mut wr, &seal(&p.frame)).await?;
        }
        loop {
            tokio::select! {
                f = tokio::time::timeout(IDLE, incoming.recv()) => {
                    let Ok(f) = f else { bail!("nothing from the phone for {} min", IDLE.as_secs() / 60) };
                    let Some(f) = f else { bail!("closed by the phone") };
                    let Some((_, pt)) = app.keys.lock().unwrap().open(&f) else { bail!("bad frame") };
                    if pt.first().map(|&h| split_hdr(h).0) == Some(T_PING) {
                        write_frame(&mut wr, &seal(&[hdr(T_PONG, CODEC_RAW)])).await?;
                    }
                }
                p = live.recv() => match p {
                    Ok(p) if wanted(&p) => {
                        write_frame(&mut wr, &seal(&p.frame)).await?;
                        log::debug!("push: notified {peer} (seq {})", p.seq);
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => bail!("server stopping"),
                },
                _ = key_gen.changed() => bail!("key changed by Sync, the phone reconnects"),
            }
        }
    }
    .await;
    reader.abort();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_like_whatsapp() {
        let now = 1_000_000;
        assert!(should_notify(0, now, false, false), "not muted");
        assert!(!should_notify(-1, now, false, false), "muted for ever");
        assert!(!should_notify(now + 60, now, false, false), "muted for another minute");
        assert!(should_notify(now - 60, now, false, false), "mute ran out");
        assert!(should_notify(-1, now, true, false), "muted, but you are mentioned");
        assert!(should_notify(-1, now, false, true), "muted, but it replies to you");
    }

    #[test]
    fn mutes_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("svpn-mutes-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = Mutes::default();
        m.set("123@g.us", -1, &dir);
        m.set("456@s.whatsapp.net", 1_900_000_000, &dir);
        m.set("789@g.us", 1_900_000_000, &dir);
        m.set("789@g.us", 0, &dir);
        let again = Mutes::load(&dir);
        assert_eq!((again.get("123@g.us"), again.get("456@s.whatsapp.net"), again.get("789@g.us"), again.len()), (-1, 1_900_000_000, 0, 2));
        // the bell in our app, on top of WhatsApp's own setting
        m.set_app("sig:abc", true, &dir);
        m.set_app("456@s.whatsapp.net", true, &dir);
        let again = Mutes::load(&dir);
        assert_eq!((again.get("sig:abc"), again.get("456@s.whatsapp.net")), (-1, -1));
        m.set_app("456@s.whatsapp.net", false, &dir);
        assert_eq!(Mutes::load(&dir).get("456@s.whatsapp.net"), 1_900_000_000, "WhatsApp's own mute stays");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
