//! Wire format shared with the Android app (mirrored in `android/.../Wire.kt`).
//!
//! Packet    = pn_lo (1 byte) ‖ ChaCha20-Poly1305(plaintext) ‖ tag (16)
//! Plaintext = (type << 3 | codec) ‖ body
//! All integers are LEB128 varints, strings are varint length + UTF-8.

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

// ---------------------------------------------------------------- types ----

pub const DIR_C2S: u8 = 0;
pub const DIR_S2C: u8 = 1;

// phone -> server
pub const T_CHECK: u8 = 1;
pub const T_FETCH: u8 = 2;
pub const T_SEND: u8 = 3;
pub const T_MEDIA: u8 = 4;
pub const T_PROXY_CFG: u8 = 5;
/// Request the HTTPS-interception CA certificate.
pub const T_CA: u8 = 6;
/// Ask for the "Data usage" numbers. Body: u8 flags (1 = reset after reading).
pub const T_USAGE: u8 = 8;
/// Opens a push session on the TCP port (instead of SYNC_HELLO). Body: u8 services (bit per SERVICE_*),
/// varint since (the phone's Check cursor: notifications after it that it missed are sent first).
pub const T_PUSH_HELLO: u8 = 9;
/// Keepalive in a push session (empty); the server answers T_PONG.
pub const T_PING: u8 = 10;
/// Turn a chat's notifications off/on (a mute set in our app). Body: varint client_id, varint chat,
/// u8 muted. Answered with T_ACK.
pub const T_MUTE: u8 = 11;
// server -> phone
pub const T_SUMMARY: u8 = 16;
pub const T_RECORDS: u8 = 17;
pub const T_SENT: u8 = 18;
pub const T_CHUNK: u8 = 19;
pub const T_ERR: u8 = 20;
pub const T_ACK: u8 = 21;
/// CA certificate (DER).
pub const T_CA_CERT: u8 = 22;

// sync (TCP)
pub const T_SYNC_HELLO: u8 = 24;
pub const T_SYNC_CURSORS: u8 = 25;
pub const T_SYNC_CHAT: u8 = 26;
pub const T_SYNC_DICT: u8 = 27;
pub const T_SYNC_DONE: u8 = 28;
/// zstd (dict = build_dict(&[], &[])) of: varints since, web bytes to the phone, web images before / after,
/// WhatsApp media before / after; number of sites; per site: name, streams, number of kinds,
/// per kind: u8 kind, bytes, saved (see `activity::usage`).
pub const T_USAGE_REPLY: u8 = 29;
/// A notification: u8 service, varint seq (store head after the message), varint chat, str chat name,
/// str sender (empty in 1:1 chats), u8 kind, str preview (text or caption, at most 100 characters).
pub const T_PUSH: u8 = 30;
pub const T_PONG: u8 = 31;

/// Messaging services a push session can ask for (bit numbers in T_PUSH_HELLO).
/// The same ids mark each chat's service (SUMMARY, SYNC_CHAT) and notifications (T_PUSH).
pub const SERVICE_WHATSAPP: u8 = 0;
pub const SERVICE_SIGNAL: u8 = 1;

pub const CODEC_RAW: u8 = 0;
pub const CODEC_ZSTD: u8 = 1;

pub const ERR_BAD_REQUEST: u8 = 1;
pub const ERR_NO_MEDIA: u8 = 2;
pub const ERR_WA_OFFLINE: u8 = 3;
pub const ERR_UNKNOWN_DICT: u8 = 4;
pub const ERR_UNKNOWN_CHAT: u8 = 5;

/// Service states (WA_* values, also used for Signal). SUMMARY and SYNC_DONE carry one byte:
/// WhatsApp's state in the low nibble, Signal's in the high nibble (see `states_byte`).
pub const WA_STARTING: u8 = 0;
pub const WA_NEEDS_PAIRING: u8 = 1;
pub const WA_CONNECTED: u8 = 2;
pub const WA_DISCONNECTED: u8 = 3;
pub const WA_LOGGED_OUT: u8 = 4;
/// The service isn't used on this server (not linked during init).
pub const WA_OFF: u8 = 5;

pub fn states_byte(whatsapp: u8, signal: u8) -> u8 {
    (whatsapp & 15) | (signal << 4)
}

pub const KIND_TEXT: u8 = 0;
pub const KIND_IMAGE: u8 = 1;
pub const KIND_VIDEO: u8 = 2;
pub const KIND_AUDIO: u8 = 3;
pub const KIND_DOC: u8 = 4;
pub const KIND_STICKER: u8 = 5;

/// Max UDP payload we aim for (keeps us below typical path MTUs).
pub const MAX_PACKET: usize = 1200;
/// Bytes of a packet that are not plaintext: pn + tag.
pub const PACKET_OVERHEAD: usize = 1 + 16;
/// Media chunk payload size.
pub const CHUNK_SIZE: usize = 1140;

pub fn hdr(t: u8, codec: u8) -> u8 {
    (t << 3) | (codec & 7)
}
pub fn split_hdr(b: u8) -> (u8, u8) {
    (b >> 3, b & 7)
}

// -------------------------------------------------------------- varints ----

pub fn put_uv(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            return;
        }
        buf.push(b | 0x80);
    }
}

pub fn get_uv(b: &mut &[u8]) -> Result<u64> {
    let mut v: u64 = 0;
    let mut shift = 0;
    loop {
        let (&byte, rest) = b.split_first().ok_or_else(|| anyhow!("varint: eof"))?;
        *b = rest;
        if shift >= 64 {
            bail!("varint: overflow");
        }
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

pub fn zz(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
pub fn unzz(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

pub fn put_bytes(buf: &mut Vec<u8>, s: &[u8]) {
    put_uv(buf, s.len() as u64);
    buf.extend_from_slice(s);
}

pub fn get_bytes<'a>(b: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = get_uv(b)? as usize;
    if n > b.len() {
        bail!("bytes: eof");
    }
    let (s, rest) = b.split_at(n);
    *b = rest;
    Ok(s)
}

pub fn get_str(b: &mut &[u8]) -> Result<String> {
    Ok(String::from_utf8(get_bytes(b)?.to_vec())?)
}

pub fn get_u8(b: &mut &[u8]) -> Result<u8> {
    let (&v, rest) = b.split_first().ok_or_else(|| anyhow!("u8: eof"))?;
    *b = rest;
    Ok(v)
}

// -------------------------------------------------------------- records ----
//
// A chat is a stream of records. Every record starts with
//   head = seq_delta << 1 | is_sender_def
// so the type costs no extra byte.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Introduces the next per-chat sender index (1, 2, ...). 0 is always "me".
    Sender { seq: u64, name: String },
    Msg {
        seq: u64,
        sender: u64,
        ts: i64,
        kind: u8,
        text: String,
        media_size: u64,
    },
}

impl Record {
    pub fn seq(&self) -> u64 {
        match self {
            Record::Sender { seq, .. } | Record::Msg { seq, .. } => *seq,
        }
    }
}

/// Encoding context: the last seq and the last message timestamp in the chat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChatPos {
    pub seq: u64,
    pub ts: i64,
    pub senders: u64,
}

impl ChatPos {
    pub fn encode(&mut self, r: &Record, out: &mut Vec<u8>) {
        match r {
            Record::Sender { seq, name } => {
                put_uv(out, ((seq - self.seq) << 1) | 1);
                put_bytes(out, name.as_bytes());
                self.seq = *seq;
                self.senders += 1;
            }
            Record::Msg { seq, sender, ts, kind, text, media_size } => {
                put_uv(out, (seq - self.seq) << 1);
                put_uv(out, *sender);
                put_uv(out, zz(ts - self.ts));
                out.push(*kind);
                put_bytes(out, text.as_bytes());
                if *kind != KIND_TEXT {
                    put_uv(out, *media_size);
                }
                self.seq = *seq;
                self.ts = *ts;
            }
        }
    }

    pub fn decode(&mut self, b: &mut &[u8]) -> Result<Record> {
        let head = get_uv(b)?;
        let delta = head >> 1;
        if delta == 0 {
            bail!("record: zero seq delta");
        }
        let seq = self.seq + delta;
        let r = if head & 1 == 1 {
            let name = get_str(b)?;
            self.senders += 1;
            Record::Sender { seq, name }
        } else {
            let sender = get_uv(b)?;
            let ts = self.ts + unzz(get_uv(b)?);
            let kind = get_u8(b)?;
            let text = get_str(b)?;
            let media_size = if kind != KIND_TEXT { get_uv(b)? } else { 0 };
            self.ts = ts;
            Record::Msg { seq, sender, ts, kind, text, media_size }
        };
        self.seq = seq;
        Ok(r)
    }

    /// Replays an entire canonical chat stream, returning the position after it.
    pub fn scan(stream: &[u8]) -> Result<(ChatPos, Vec<(u64, usize, bool)>)> {
        let mut pos = ChatPos::default();
        let mut b = stream;
        let mut index = Vec::new();
        while !b.is_empty() {
            let off = stream.len() - b.len();
            let r = pos.decode(&mut b)?;
            index.push((r.seq(), off, matches!(r, Record::Msg { .. })));
        }
        Ok((pos, index))
    }
}

// --------------------------------------------------------- compression ----

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const ZSTD_LEVEL: i32 = 19;
const ZSTD_WINDOW_LOG: u32 = 17;
/// How much chat history goes into the dictionary.
pub const HISTORY_TAIL: usize = 32 * 1024;
/// Target size of the dictionary trained during Sync.
pub const SYNC_DICT_SIZE: usize = 64 * 1024;

/// A T_PUSH notification (plaintext, see the type for the layout).
pub fn push_frame(service: u8, seq: u64, chat: usize, chat_name: &str, sender: &str, kind: u8, preview: &str) -> Vec<u8> {
    let mut f = vec![hdr(T_PUSH, CODEC_RAW), service];
    put_uv(&mut f, seq);
    put_uv(&mut f, chat as u64);
    put_bytes(&mut f, chat_name.as_bytes());
    put_bytes(&mut f, sender.as_bytes());
    f.push(kind);
    put_bytes(&mut f, preview.as_bytes());
    f
}

/// Builds the shared dictionary: 0x00 ‖ synced dict ‖ tail of chat history.
/// The leading 0x00 makes zstd treat the whole thing as raw content.
pub fn build_dict(synced: &[u8], history: &[u8]) -> Vec<u8> {
    let tail = &history[history.len().saturating_sub(HISTORY_TAIL)..];
    let mut d = Vec::with_capacity(1 + synced.len() + tail.len());
    d.push(0);
    d.extend_from_slice(synced);
    d.extend_from_slice(tail);
    d
}

/// zstd frame with the 4 magic bytes stripped, no content size, checksum or dict ID.
pub fn zcompress(data: &[u8], dict: &[u8]) -> Result<Vec<u8>> {
    use zstd::zstd_safe::CParameter as P;
    let mut c = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, dict)?;
    c.set_parameter(P::ContentSizeFlag(false))?;
    c.set_parameter(P::ChecksumFlag(false))?;
    c.set_parameter(P::DictIdFlag(false))?;
    c.set_parameter(P::WindowLog(ZSTD_WINDOW_LOG))?;
    let out = c.compress(data)?;
    debug_assert_eq!(out[..4], ZSTD_MAGIC);
    Ok(out[4..].to_vec())
}

pub fn zdecompress(data: &[u8], dict: &[u8], max: usize) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&ZSTD_MAGIC);
    frame.extend_from_slice(data);
    let mut d = zstd::bulk::Decompressor::with_dictionary(dict)?;
    d.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(ZSTD_WINDOW_LOG))?;
    Ok(d.decompress(&frame, max)?)
}

/// Compresses if that saves bytes. Returns (codec, payload).
pub fn pack(data: &[u8], dict: &[u8]) -> (u8, Vec<u8>) {
    match zcompress(data, dict) {
        Ok(z) if z.len() < data.len() => (CODEC_ZSTD, z),
        _ => (CODEC_RAW, data.to_vec()),
    }
}

pub fn unpack(codec: u8, payload: &[u8], dict: &[u8], max: usize) -> Result<Vec<u8>> {
    match codec {
        CODEC_RAW => Ok(payload.to_vec()),
        CODEC_ZSTD => zdecompress(payload, dict, max),
        c => bail!("unknown codec {c}"),
    }
}

// ------------------------------------------------------------- packets ----

fn nonce(dir: u8, pn: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = dir;
    n[1..9].copy_from_slice(&pn.to_le_bytes());
    n
}

pub fn seal(key: &[u8; 32], dir: u8, pn: u64, plaintext: &[u8]) -> Vec<u8> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    let pn_lo = pn as u8;
    let ct = aead
        .encrypt(Nonce::from_slice(&nonce(dir, pn)), Payload { msg: plaintext, aad: &[pn_lo] })
        .expect("encrypt");
    let mut out = Vec::with_capacity(1 + ct.len());
    out.push(pn_lo);
    out.extend_from_slice(&ct);
    out
}

fn try_open(key: &[u8; 32], dir: u8, pn: u64, pkt: &[u8]) -> Option<Vec<u8>> {
    let aead = ChaCha20Poly1305::new(Key::from_slice(key));
    aead.decrypt(Nonce::from_slice(&nonce(dir, pn)), Payload { msg: &pkt[1..], aad: &pkt[..1] })
        .ok()
}

/// Receive-side state: reconstructs full packet numbers and rejects replays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RxWindow {
    /// Highest accepted pn + 1 (0 = nothing accepted yet).
    pub next: u64,
    pub bitmap: u64,
}

impl RxWindow {
    /// QUIC-style reconstruction of the full pn from its low byte.
    pub fn candidate(&self, lo: u8) -> u64 {
        let expected = self.next;
        let mut c = (expected & !0xff) | lo as u64;
        if c + 128 <= expected {
            c += 256;
        } else if c > expected + 128 && c >= 256 {
            c -= 256;
        }
        c
    }

    fn is_replay(&self, pn: u64) -> bool {
        if pn >= self.next {
            return false;
        }
        let age = self.next - 1 - pn;
        age >= 64 || (self.bitmap >> age) & 1 == 1
    }

    pub fn accept(&mut self, pn: u64) {
        if pn >= self.next {
            let shift = pn + 1 - self.next;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.next = pn + 1;
        } else {
            self.bitmap |= 1 << (self.next - 1 - pn);
        }
    }

    /// Decrypts without updating state. Tries the expected window first, then
    /// further windows ahead (the sender may have skipped numbers after a restart).
    pub fn open(&self, key: &[u8; 32], dir: u8, pkt: &[u8]) -> Option<(u64, Vec<u8>)> {
        if pkt.len() < PACKET_OVERHEAD {
            return None;
        }
        let base = self.candidate(pkt[0]);
        for k in 0..64u64 {
            let pn = base + k * 256;
            if self.is_replay(pn) {
                continue;
            }
            if let Some(p) = try_open(key, dir, pn, pkt) {
                return Some((pn, p));
            }
        }
        None
    }
}

// ----------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn varints() {
        for v in [0u64, 1, 127, 128, 300, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_uv(&mut b, v);
            let mut s = &b[..];
            assert_eq!(get_uv(&mut s).unwrap(), v);
            assert!(s.is_empty());
        }
        for v in [0i64, 1, -1, 63, -64, i64::MIN, i64::MAX] {
            assert_eq!(unzz(zz(v)), v);
        }
    }

    fn sample_chat() -> Vec<Record> {
        vec![
            Record::Sender { seq: 3, name: "Alex".into() },
            Record::Msg { seq: 4, sender: 1, ts: 1_760_000_000, kind: KIND_TEXT, text: "Are we still meeting?".into(), media_size: 0 },
            Record::Msg { seq: 9, sender: 0, ts: 1_760_000_060, kind: KIND_TEXT, text: "Yes, tomorrow.".into(), media_size: 0 },
            Record::Msg { seq: 10, sender: 1, ts: 1_760_000_050, kind: KIND_IMAGE, text: "".into(), media_size: 2_400_000 },
        ]
    }

    fn encode_all(rs: &[Record]) -> Vec<u8> {
        let mut pos = ChatPos::default();
        let mut out = Vec::new();
        for r in rs {
            pos.encode(r, &mut out);
        }
        out
    }

    #[test]
    fn records_roundtrip() {
        let rs = sample_chat();
        let bytes = encode_all(&rs);
        let mut pos = ChatPos::default();
        let mut b = &bytes[..];
        for r in &rs {
            assert_eq!(&pos.decode(&mut b).unwrap(), r);
        }
        assert!(b.is_empty());
        let (p, idx) = ChatPos::scan(&bytes).unwrap();
        assert_eq!(p.seq, 10);
        assert_eq!(p.senders, 1);
        assert_eq!(idx.len(), 4);
    }

    #[test]
    fn seal_open_and_replay() {
        let key = [7u8; 32];
        let mut rx = RxWindow::default();
        for pn in 0..600u64 {
            let p = seal(&key, DIR_C2S, pn, b"hello");
            assert_eq!(p.len(), 5 + PACKET_OVERHEAD);
            let (got, pt) = rx.open(&key, DIR_C2S, &p).unwrap();
            assert_eq!(got, pn);
            assert_eq!(pt, b"hello");
            rx.accept(got);
            assert!(rx.open(&key, DIR_C2S, &p).is_none(), "replay must fail");
        }
        // wrong direction fails
        assert!(rx.open(&key, DIR_S2C, &seal(&key, DIR_C2S, 600, b"x")).is_none());
        // sender skipped ahead (restart with block reservation)
        let p = seal(&key, DIR_C2S, 600 + 1500, b"late");
        let (got, _) = rx.open(&key, DIR_C2S, &p).unwrap();
        assert_eq!(got, 2100);
        rx.accept(got);
        // out of order within window
        let p = seal(&key, DIR_C2S, 2090, b"old");
        assert_eq!(rx.open(&key, DIR_C2S, &p).unwrap().0, 2090);
    }

    #[test]
    fn compression_with_history() {
        let history = encode_all(&sample_chat());
        let mut pos = ChatPos::scan(&history).unwrap().0;
        let mut next = Vec::new();
        pos.encode(
            &Record::Msg { seq: 12, sender: 1, ts: 1_760_000_100, kind: KIND_TEXT, text: "Are we still meeting tomorrow?".into(), media_size: 0 },
            &mut next,
        );
        let dict = build_dict(b"", &history);
        let (codec, z) = pack(&next, &dict);
        assert_eq!(codec, CODEC_ZSTD);
        assert!(z.len() < next.len(), "{} vs {}", z.len(), next.len());
        assert_eq!(unpack(codec, &z, &dict, 4096).unwrap(), next);
        // without the history the payload does not shrink as much
        let (_, z0) = pack(&next, &build_dict(b"", b""));
        assert!(z.len() < z0.len());
    }

    /// Writes golden vectors for the Kotlin implementation (android unit tests).
    #[test]
    fn golden_vectors() {
        let mut lines = Vec::new();
        let mut uv = Vec::new();
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64] {
            put_uv(&mut uv, v);
        }
        lines.push(format!("varints {}", hex(&uv)));
        let history = encode_all(&sample_chat());
        lines.push(format!("records {}", hex(&history)));
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        lines.push(format!("key {}", hex(&key)));
        lines.push(format!("packet_c2s_pn300 {}", hex(&seal(&key, DIR_C2S, 300, b"hello phone"))));
        lines.push(format!("packet_s2c_pn5 {}", hex(&seal(&key, DIR_S2C, 5, b"hello server"))));
        let synced = b"some synced dictionary content: meeting tomorrow see you".to_vec();
        lines.push(format!("synced {}", hex(&synced)));
        let dict = build_dict(&synced, &history);
        lines.push(format!("dict {}", hex(&dict)));
        let plain = b"Are we still meeting tomorrow? see you".to_vec();
        lines.push(format!("plain {}", hex(&plain)));
        lines.push(format!("zstd {}", hex(&zcompress(&plain, &dict).unwrap())));
        lines.push(format!("zstd_nodict {}", hex(&zcompress(&plain, &build_dict(b"", b"")).unwrap())));
        let mut rot = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&key), &[5u8; 32]).expand(b"svpn-rotate", &mut rot).unwrap();
        lines.push(format!("rotated_dh5 {}", hex(&rot)));
        lines.push(format!("push {}", hex(&push_frame(SERVICE_WHATSAPP, 300, 2, "Family", "Alex", KIND_IMAGE, "Look at this 📷"))));
        lines.push(format!("push_signal {}", hex(&push_frame(SERVICE_SIGNAL, 301, 3, "Sam", "", KIND_TEXT, "hi"))));
        lines.push(format!("states_wa2_sig5 {:02x}", states_byte(WA_CONNECTED, WA_OFF)));
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("golden.txt"), lines.join("\n") + "\n").unwrap();
    }
}
