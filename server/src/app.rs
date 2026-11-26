//! Shared server state and the request handlers of the restricted-mode protocol.

use crate::keys::Keys;
use crate::store::Store;
use crate::wire::*;
use anyhow::{Result, anyhow, bail};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What the protocol needs from a messaging service, WhatsApp or Signal (faked in tests).
pub trait Messenger: Send + Sync {
    /// Sends a text, returns the service's message id.
    fn send_text(&self, jid: String, text: String) -> BoxFut<Result<String>>;
    /// Downloads media from its stored protobuf reference.
    fn download(&self, kind: u8, proto: Vec<u8>) -> BoxFut<Result<Vec<u8>>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyCfg {
    pub enabled: bool,
    pub quality: u8,
    pub max_dim: u32,
    /// Decrypt HTTPS (with the CA the user installed) to recompress images. The app turns it on once the CA is installed.
    pub https: bool,
    /// Speed limit for video responses the proxy can see (kbit/s, 0 = no limit). Video players then pick
    /// a lower quality by themselves.
    pub video_kbps: u32,
}

/// Video speed limit until the phone sends its own (kbit/s).
pub const VIDEO_KBPS: u32 = 400;

impl Default for ProxyCfg {
    fn default() -> Self {
        ProxyCfg { enabled: true, quality: 35, max_dim: 1280, https: false, video_kbps: VIDEO_KBPS }
    }
}

impl ProxyCfg {
    /// `enabled u8, quality u8, max_dim varint, https u8, video_kbps varint` (the last two may be
    /// missing in older data).
    fn decode(b: &mut &[u8]) -> Result<ProxyCfg> {
        Ok(ProxyCfg {
            enabled: get_u8(b)? == 1,
            quality: get_u8(b)?.clamp(1, 100),
            max_dim: get_uv(b)? as u32,
            https: get_u8(b).unwrap_or(0) == 1,
            video_kbps: get_uv(b).map_or(VIDEO_KBPS, |v| v.min(u32::MAX as u64) as u32),
        })
    }
    fn encode(&self) -> Vec<u8> {
        let mut s = vec![self.enabled as u8, self.quality];
        put_uv(&mut s, self.max_dim as u64);
        s.push(self.https as u8);
        put_uv(&mut s, self.video_kbps as u64);
        s
    }
}

/// Max records-packets sent per FETCH; the phone asks again for more.
const FETCH_PACKETS: usize = 8;
/// Max chunks per MEDIA request.
const MEDIA_CHUNKS: u64 = 64;
/// Max decompressed size of a phone-sent text.
const MAX_TEXT: usize = 64 * 1024;

pub struct App {
    pub data: PathBuf,
    pub store: Mutex<Store>,
    pub keys: Mutex<Keys>,
    pub wa_state: AtomicU8,
    pub wa: RwLock<Option<Arc<dyn Messenger>>>,
    /// Signal, the same way (WA_* states; chats with `sig:` / `sig-g:` ids, see `sig.rs`).
    pub sig_state: AtomicU8,
    pub sig: RwLock<Option<Arc<dyn Messenger>>>,
    pub proxy: Arc<RwLock<ProxyCfg>>,
    /// HTTPS-interception CA certificate (DER), handed to the phone on request.
    pub ca: std::sync::OnceLock<Vec<u8>>,
    /// Recent SEND/PROXY_CFG replies by client_id (dedup of retries).
    sent: Mutex<VecDeque<(u64, Vec<u8>)>>,
    in_flight: Mutex<HashSet<u64>>,
    /// WhatsApp ids of messages we sent, so their echo is not logged twice.
    pub own_ids: Mutex<HashSet<String>>,
    /// Real-time notifications to the phone, and WhatsApp's muted chats (see `notify.rs`).
    pub hub: crate::notify::Hub,
    pub mutes: Mutex<crate::notify::Mutes>,
}

fn err(code: u8, reference: u64) -> Vec<Vec<u8>> {
    let mut b = vec![hdr(T_ERR, CODEC_RAW), code];
    put_uv(&mut b, reference);
    vec![b]
}

impl App {
    pub fn new(data: PathBuf, store: Store, keys: Keys) -> App {
        let proxy = std::fs::read(data.join("proxy.bin"))
            .ok()
            .and_then(|b| ProxyCfg::decode(&mut &b[..]).ok())
            .unwrap_or_default();
        let sent = std::fs::read(data.join("sent.bin"))
            .ok()
            .and_then(|b| {
                let mut s = &b[..];
                let mut q = VecDeque::new();
                while !s.is_empty() {
                    q.push_back((get_uv(&mut s).ok()?, get_bytes(&mut s).ok()?.to_vec()));
                }
                Some(q)
            })
            .unwrap_or_default();
        let mutes = Mutex::new(crate::notify::Mutes::load(&data));
        App {
            data,
            store: Mutex::new(store),
            keys: Mutex::new(keys),
            wa_state: AtomicU8::new(WA_STARTING),
            wa: RwLock::new(None),
            sig_state: AtomicU8::new(WA_STARTING),
            sig: RwLock::new(None),
            proxy: Arc::new(RwLock::new(proxy)),
            ca: Default::default(),
            sent: Mutex::new(sent),
            in_flight: Mutex::new(HashSet::new()),
            own_ids: Mutex::new(HashSet::new()),
            hub: crate::notify::Hub::default(),
            mutes,
        }
    }

    fn remember_reply(&self, client_id: u64, reply: &[u8]) {
        let mut q = self.sent.lock().unwrap();
        q.push_back((client_id, reply.to_vec()));
        while q.len() > 256 {
            q.pop_front();
        }
        let mut b = Vec::new();
        for (id, r) in q.iter() {
            put_uv(&mut b, *id);
            put_bytes(&mut b, r);
        }
        if let Err(e) = std::fs::write(self.data.join("sent.bin"), b) {
            log::error!("saving sent.bin: {e}");
        }
    }

    fn cached_reply(&self, client_id: u64) -> Option<Vec<u8>> {
        self.sent.lock().unwrap().iter().rev().find(|e| e.0 == client_id).map(|e| e.1.clone())
    }

    /// WhatsApp's and Signal's state in one byte (SUMMARY, SYNC_DONE).
    pub fn states(&self) -> u8 {
        states_byte(self.wa_state.load(Ordering::Relaxed), self.sig_state.load(Ordering::Relaxed))
    }

    /// The service a chat belongs to.
    fn messenger_for(&self, signal: bool) -> Option<Arc<dyn Messenger>> {
        if signal { self.sig.read().unwrap().clone() } else { self.wa.read().unwrap().clone() }
    }

    /// Handles one decrypted phone packet; returns plaintext replies.
    pub async fn handle(&self, pt: &[u8]) -> Vec<Vec<u8>> {
        match self.handle_inner(pt).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("bad request: {e:#}");
                err(ERR_BAD_REQUEST, 0)
            }
        }
    }

    async fn handle_inner(&self, pt: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (&h, mut b) = pt.split_first().ok_or_else(|| anyhow!("empty"))?;
        let (t, codec) = split_hdr(h);
        match t {
            T_CHECK => self.check(&mut b),
            T_FETCH => self.fetch(&mut b),
            T_SEND => self.send(codec, &mut b).await,
            T_MEDIA => self.media(&mut b).await,
            T_PROXY_CFG => self.proxy_cfg(&mut b),
            T_MUTE => self.mute(&mut b),
            T_CA => {
                let der = self.ca.get().ok_or_else(|| anyhow!("no CA"))?;
                Ok(vec![[&[hdr(T_CA_CERT, CODEC_RAW)][..], der].concat()])
            }
            T_USAGE => {
                let reset = get_u8(&mut b).unwrap_or(0) & 1 == 1;
                let (codec, body) = pack(&crate::activity::usage(40), &build_dict(&[], &[]));
                if reset {
                    crate::activity::reset();
                }
                Ok(vec![[vec![hdr(T_USAGE_REPLY, codec)], body].concat()])
            }
            _ => bail!("unknown type {t}"),
        }
    }

    fn check(&self, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let dict_id = get_uv(b)?;
        let since = get_uv(b)?;
        let known = get_uv(b)? as usize;
        let st = self.store.lock().unwrap();
        let Some(synced) = st.dict(dict_id) else { return Ok(err(ERR_UNKNOWN_DICT, dict_id)) };
        let known = known.min(st.chats.len());
        let mut body = Vec::new();
        put_uv(&mut body, st.head);
        body.push(self.states());
        let entries = st.summary(since);
        put_uv(&mut body, entries.len() as u64);
        for (chat, n) in entries {
            put_uv(&mut body, chat as u64);
            put_uv(&mut body, n as u64);
            if chat >= known {
                put_bytes(&mut body, st.chats[chat].name.as_bytes());
                body.push(st.chats[chat].service());
            }
        }
        let (codec, payload) = pack(&body, &build_dict(synced, &st.names_table(known)));
        let mut out = vec![hdr(T_SUMMARY, codec)];
        out.extend_from_slice(&payload);
        Ok(vec![out])
    }

    fn fetch(&self, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let dict_id = get_uv(b)?;
        let chat_idx = get_uv(b)? as usize;
        let after = get_uv(b)?;
        let st = self.store.lock().unwrap();
        let Some(synced) = st.dict(dict_id) else { return Ok(err(ERR_UNKNOWN_DICT, dict_id)) };
        let Some(chat) = st.chats.get(chat_idx) else { return Ok(err(ERR_UNKNOWN_CHAT, chat_idx as u64)) };
        if chat.offset_after(after).is_none() {
            return Ok(err(ERR_BAD_REQUEST, after));
        }
        let mut i = chat.first_after(after);
        let mut base = after;
        let mut out = Vec::new();
        loop {
            let off = |k: usize| chat.index.get(k).map_or(chat.stream.len(), |e| e.1);
            let start = off(i);
            let dict = build_dict(synced, &chat.stream[..start]);
            let mut header = Vec::new();
            put_uv(&mut header, chat_idx as u64);
            put_uv(&mut header, base);
            let budget = MAX_PACKET - PACKET_OVERHEAD - 2 - header.len();
            // Binary search for the most records that still fit one packet.
            let n_left = chat.index.len() - i;
            let (mut lo, mut hi) = (n_left.min(1), n_left.min(256));
            let mut best = (lo, pack(&chat.stream[start..off(i + lo)], &dict));
            while lo < hi {
                let mid = (lo + hi).div_ceil(2);
                let p = pack(&chat.stream[start..off(i + mid)], &dict);
                if p.1.len() <= budget {
                    lo = mid;
                    best = (mid, p);
                } else {
                    hi = mid - 1;
                }
            }
            let (n, (codec, payload)) = best;
            i += n;
            let done = i >= chat.index.len();
            let last = done || out.len() + 1 == FETCH_PACKETS;
            let flags = (last as u8) | (((!done) as u8) << 1);
            let mut pkt = vec![hdr(T_RECORDS, codec)];
            pkt.extend_from_slice(&header);
            pkt.push(flags);
            pkt.extend_from_slice(&payload);
            out.push(pkt);
            if last {
                return Ok(out);
            }
            base = chat.index[i - 1].0;
        }
    }

    async fn send(&self, codec: u8, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let client_id = get_uv(b)?;
        if let Some(r) = self.cached_reply(client_id) {
            return Ok(vec![r]);
        }
        let dict_id = get_uv(b)?;
        let chat_idx = get_uv(b)? as usize;
        let base = get_uv(b)?;
        let (jid, text) = {
            let st = self.store.lock().unwrap();
            let Some(synced) = st.dict(dict_id) else { return Ok(err(ERR_UNKNOWN_DICT, dict_id)) };
            let Some(chat) = st.chats.get(chat_idx) else { return Ok(err(ERR_UNKNOWN_CHAT, chat_idx as u64)) };
            let Some(off) = chat.offset_after(base) else { return Ok(err(ERR_BAD_REQUEST, client_id)) };
            let text = unpack(codec, b, &build_dict(synced, &chat.stream[..off]), MAX_TEXT)?;
            (chat.jid.clone(), String::from_utf8(text)?)
        };
        let Some(wa) = self.messenger_for(crate::sig::is_signal(&jid)) else { return Ok(err(ERR_WA_OFFLINE, client_id)) };
        if !self.in_flight.lock().unwrap().insert(client_id) {
            return Ok(vec![]); // a retry while the first attempt is still sending
        }
        let res = wa.send_text(jid, text.clone()).await;
        self.in_flight.lock().unwrap().remove(&client_id);
        let msg_id = match res {
            Ok(id) => id,
            Err(e) => {
                log::warn!("send failed: {e:#}");
                return Ok(err(ERR_WA_OFFLINE, client_id));
            }
        };
        self.own_ids.lock().unwrap().insert(msg_id);
        let ts = now();
        let (seq, prev) = self.store.lock().unwrap().append_msg(chat_idx, 0, ts, KIND_TEXT, &text, 0)?;
        let mut r = vec![hdr(T_SENT, CODEC_RAW)];
        put_uv(&mut r, client_id);
        put_uv(&mut r, seq);
        put_uv(&mut r, prev);
        put_uv(&mut r, zz(ts));
        self.remember_reply(client_id, &r);
        Ok(vec![r])
    }

    async fn media(&self, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let seq = get_uv(b)?;
        let max_dim = get_uv(b)? as u32;
        let quality = get_u8(b)?;
        let from = get_uv(b)?;
        let count = get_uv(b)?.min(MEDIA_CHUNKS);
        let data = match self.media_bytes(seq, max_dim, quality).await {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(err(ERR_NO_MEDIA, seq)),
            Err(e) => {
                log::warn!("media {seq}: {e:#}");
                return Ok(err(ERR_WA_OFFLINE, seq));
            }
        };
        let total = data.len().div_ceil(CHUNK_SIZE).max(1) as u64;
        let mut out = Vec::new();
        for idx in from..(from + count).min(total) {
            let s = idx as usize * CHUNK_SIZE;
            let mut p = vec![hdr(T_CHUNK, CODEC_RAW)];
            put_uv(&mut p, seq);
            put_uv(&mut p, idx);
            put_uv(&mut p, total);
            p.extend_from_slice(&data[s..(s + CHUNK_SIZE).min(data.len())]);
            out.push(p);
        }
        Ok(out)
    }

    /// Downloads (once) and optionally recompresses media; cached on disk.
    async fn media_bytes(&self, seq: u64, max_dim: u32, quality: u8) -> Result<Option<Vec<u8>>> {
        let (path, orig_path, mref) = {
            let st = self.store.lock().unwrap();
            let Some(mref) = st.load_media_ref(seq) else { return Ok(None) };
            (st.media_path(&format!("{seq}_{max_dim}_{quality}_w.out")), st.media_path(&format!("{seq}.orig")), mref)
        };
        if let Ok(d) = tokio::fs::read(&path).await {
            return Ok(Some(d));
        }
        let orig = match tokio::fs::read(&orig_path).await {
            Ok(d) => d,
            Err(_) => {
                let signal = mref.0 & crate::sig::MEDIA_SIGNAL != 0;
                let m = self.messenger_for(signal).ok_or_else(|| anyhow!("{} offline", if signal { "signal" } else { "whatsapp" }))?;
                let d = m.download(mref.0 & !crate::sig::MEDIA_SIGNAL, mref.1).await?;
                tokio::fs::write(&orig_path, &d).await?;
                d
            }
        };
        // images become WebP: the phone displays them with BitmapFactory, which decodes WebP
        let out = if mref.0 & !crate::sig::MEDIA_SIGNAL == KIND_IMAGE && quality > 0 {
            match crate::img::shrink_async(orig.clone(), max_dim, quality, true).await {
                Ok(Some((small, _))) => {
                    crate::activity::whatsapp_media(orig.len() as u64, small.len() as u64);
                    small
                }
                _ => orig,
            }
        } else {
            orig
        };
        tokio::fs::write(&path, &out).await?;
        Ok(Some(out))
    }

    /// T_MUTE: the phone turns a chat's notifications off or on.
    fn mute(&self, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let client_id = get_uv(b)?;
        let chat = get_uv(b)? as usize;
        let muted = get_u8(b)? == 1;
        let Some(jid) = self.store.lock().unwrap().chats.get(chat).map(|c| c.jid.clone()) else {
            return Ok(err(ERR_UNKNOWN_CHAT, chat as u64));
        };
        self.mutes.lock().unwrap().set_app(&jid, muted, &self.data);
        log::info!("chat {chat}: notifications {}", if muted { "off" } else { "on" });
        let mut r = vec![hdr(T_ACK, CODEC_RAW)];
        put_uv(&mut r, client_id);
        Ok(vec![r])
    }

    fn proxy_cfg(&self, b: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
        let client_id = get_uv(b)?;
        let cfg = ProxyCfg::decode(b)?;
        *self.proxy.write().unwrap() = cfg;
        std::fs::write(self.data.join("proxy.bin"), cfg.encode())?;
        let mut r = vec![hdr(T_ACK, CODEC_RAW)];
        put_uv(&mut r, client_id);
        Ok(vec![r])
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}
