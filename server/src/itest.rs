//! End-to-end protocol test: a fake WhatsApp, a real UDP/TCP server and a test
//! "phone" that implements the client side exactly like the Android app.

use crate::app::{App, BoxFut, Messenger};
use crate::keys::{Keys, derive_rotated};
use crate::store::{Store, tests::tmpdir};
use crate::wire::*;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

struct FakeWa;
impl Messenger for FakeWa {
    fn send_text(&self, _jid: String, _text: String) -> BoxFut<Result<String>> {
        Box::pin(async { Ok("MSGID1".into()) })
    }
    fn download(&self, _kind: u8, _proto: Vec<u8>) -> BoxFut<Result<Vec<u8>>> {
        Box::pin(async { Ok(crate::img::tests::sample_jpeg()) })
    }
}

/// A fake Signal: remembers what was asked of it.
#[derive(Default)]
struct FakeSig(std::sync::Mutex<Vec<String>>);
impl Messenger for Arc<FakeSig> {
    fn send_text(&self, jid: String, text: String) -> BoxFut<Result<String>> {
        self.0.lock().unwrap().push(format!("send {jid} {text}"));
        Box::pin(async { Ok("1700000000000".into()) })
    }
    fn download(&self, kind: u8, proto: Vec<u8>) -> BoxFut<Result<Vec<u8>>> {
        self.0.lock().unwrap().push(format!("download {kind} {}", String::from_utf8_lossy(&proto)));
        Box::pin(async { Ok(crate::img::tests::sample_jpeg()) })
    }
}

struct Phone {
    key: [u8; 32],
    pn: u64,
    rx: RxWindow,
    sock: UdpSocket,
    server: SocketAddr,
    /// Drop the n-th reply packet of the next request (simulated loss).
    drop_nth: Option<usize>,
}

impl Phone {
    async fn req(&mut self, pt: &[u8]) -> Vec<Vec<u8>> {
        let p = seal(&self.key, DIR_C2S, self.pn, pt);
        self.pn += 1;
        self.sock.send_to(&p, self.server).await.unwrap();
        let mut out = Vec::new();
        let mut buf = vec![0u8; 65536];
        let mut i = 0;
        while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(500), self.sock.recv(&mut buf)).await {
            i += 1;
            if self.drop_nth == Some(i) {
                self.drop_nth = None;
                continue;
            }
            let (pn, pt) = self.rx.open(&self.key, DIR_S2C, &buf[..n]).expect("decrypt reply");
            self.rx.accept(pn);
            out.push(pt);
        }
        out
    }
}

fn long_text(i: usize) -> String {
    format!("message number {i}: are we still meeting at the usual place tomorrow at {}:00? bring the {}", 10 + i % 8, ["keys", "cake", "laptop"][i % 3])
}

async fn start() -> (Arc<App>, SocketAddr, [u8; 32]) {
    let dir = tmpdir(&format!("itest-{}", rand::random::<u32>()));
    let mut st = Store::open(&dir).unwrap();
    let c = st.chat_for("alex@s.whatsapp.net", "Alex").unwrap();
    let s = st.sender_for(c, "alex@s.whatsapp.net", "Alex").unwrap();
    for i in 0..300 {
        st.append_msg(c, if i % 3 == 0 { 0 } else { s }, 1_760_000_000 + i as i64 * 37, KIND_TEXT, &long_text(i), 0).unwrap();
    }
    let g = st.chat_for("grp@g.us", "Family").unwrap();
    let b = st.sender_for(g, "bob@s.whatsapp.net", "Bob").unwrap();
    let (img_seq, _) = st.append_msg(g, b, 1_760_100_000, KIND_IMAGE, "look", 123_456).unwrap();
    st.save_media_ref(img_seq, KIND_IMAGE, b"fake-proto").unwrap();
    let key = [42u8; 32];
    let keys = Keys::create(&dir.join("keys.bin"), key).unwrap();
    let app = Arc::new(App::new(dir, st, keys));
    *app.wa.write().unwrap() = Some(Arc::new(FakeWa));
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = udp.local_addr().unwrap();
    let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(crate::net::serve_udp(app.clone(), udp));
    tokio::spawn(crate::net::serve_sync(app.clone(), tcp));
    (app, addr, key)
}

async fn phone(server: SocketAddr, key: [u8; 32]) -> Phone {
    Phone { key, pn: 0, rx: RxWindow::default(), sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(), server, drop_nth: None }
}

/// Phone-side FETCH loop: follows `more`, re-fetches after loss. Returns packets used.
async fn fetch_all(p: &mut Phone, dict_id: u64, synced: &[u8], chat: u64, local: &mut Vec<u8>, pos: &mut ChatPos) -> usize {
    let mut packets = 0;
    loop {
        let mut q = vec![hdr(T_FETCH, CODEC_RAW)];
        put_uv(&mut q, dict_id);
        put_uv(&mut q, chat);
        put_uv(&mut q, pos.seq);
        let replies = p.req(&q).await;
        packets += replies.len();
        let mut more = false;
        let mut complete = false;
        for r in replies {
            let (t, codec) = split_hdr(r[0]);
            assert_eq!(t, T_RECORDS);
            let mut b = &r[1..];
            assert_eq!(get_uv(&mut b).unwrap(), chat);
            let base = get_uv(&mut b).unwrap();
            let flags = get_u8(&mut b).unwrap();
            if base != pos.seq {
                continue; // predecessor lost: ignore, re-fetch below
            }
            let recs = unpack(codec, b, &build_dict(synced, local), 1 << 20).unwrap();
            let mut rb = &recs[..];
            while !rb.is_empty() {
                pos.decode(&mut rb).unwrap();
            }
            local.extend_from_slice(&recs);
            if flags & 1 == 1 {
                complete = true;
                more = flags & 2 == 2;
            }
        }
        if complete && !more {
            return packets;
        }
    }
}

#[tokio::test]
async fn restricted_mode_end_to_end() {
    let (app, addr, key) = start().await;
    let mut p = phone(addr, key).await;

    // CHECK: which chats have news
    let mut q = vec![hdr(T_CHECK, CODEC_RAW)];
    put_uv(&mut q, 0);
    put_uv(&mut q, 0);
    put_uv(&mut q, 0);
    let r = p.req(&q).await;
    assert_eq!(r.len(), 1);
    let (t, codec) = split_hdr(r[0][0]);
    assert_eq!(t, T_SUMMARY);
    let body = unpack(codec, &r[0][1..], &build_dict(b"", b""), 1 << 16).unwrap();
    let mut b = &body[..];
    let head = get_uv(&mut b).unwrap();
    assert_eq!(head, app.store.lock().unwrap().head);
    let _states = get_u8(&mut b).unwrap();
    assert_eq!(get_uv(&mut b).unwrap(), 2);
    let entry = |b: &mut &[u8]| (get_uv(b).unwrap(), get_uv(b).unwrap(), get_str(b).unwrap(), get_u8(b).unwrap());
    assert_eq!(entry(&mut b), (0, 300, "Alex".into(), SERVICE_WHATSAPP));
    assert_eq!(entry(&mut b), (1, 1, "Family".into(), SERVICE_WHATSAPP));

    // FETCH with a lost packet: the phone recovers by re-fetching from its cursor
    let mut local = Vec::new();
    let mut pos = ChatPos::default();
    p.drop_nth = Some(2);
    let packets = fetch_all(&mut p, 0, b"", 0, &mut local, &mut pos).await;
    let server_stream = app.store.lock().unwrap().chats[0].stream.clone();
    assert_eq!(local, server_stream);
    println!("chat of 300 msgs ({} bytes canonical) took {packets} packets", server_stream.len());

    // SEND: text compressed against the chat; the phone appends the record itself
    let text = "are we still meeting at the usual place tomorrow?";
    let mut q = Vec::new();
    put_uv(&mut q, 7); // client_id
    put_uv(&mut q, 0); // dict
    put_uv(&mut q, 0); // chat
    put_uv(&mut q, pos.seq);
    let (codec, z) = pack(text.as_bytes(), &build_dict(b"", &local));
    assert!(z.len() < text.len() / 2, "history should make the text tiny: {}", z.len());
    let mut send = vec![hdr(T_SEND, codec)];
    send.extend_from_slice(&q);
    send.extend_from_slice(&z);
    let r = p.req(&send).await;
    let mut b = &r[0][1..];
    assert_eq!(split_hdr(r[0][0]).0, T_SENT);
    assert_eq!(get_uv(&mut b).unwrap(), 7);
    let seq = get_uv(&mut b).unwrap();
    let prev = get_uv(&mut b).unwrap();
    let ts = unzz(get_uv(&mut b).unwrap());
    assert_eq!(prev, pos.seq);
    pos.encode(&Record::Msg { seq, sender: 0, ts, kind: KIND_TEXT, text: text.into(), media_size: 0 }, &mut local);
    assert_eq!(local, app.store.lock().unwrap().chats[0].stream, "phone-built record must match the server's");
    // a retry with the same client_id is answered from cache, not sent twice
    let r2 = p.req(&send).await;
    assert_eq!(r2, r);
    assert_eq!(app.store.lock().unwrap().chats[0].stream.len(), local.len());

    // MEDIA: tap-to-download, recompressed, in chunks
    let img_seq = app.store.lock().unwrap().chats[1].index.last().unwrap().0;
    let mut q = vec![hdr(T_MEDIA, CODEC_RAW)];
    put_uv(&mut q, img_seq);
    put_uv(&mut q, 320);
    q.push(30);
    put_uv(&mut q, 0);
    put_uv(&mut q, 64);
    let r = p.req(&q).await;
    let mut chunks = std::collections::BTreeMap::new();
    let mut total = 0;
    for c in &r {
        let mut b = &c[1..];
        assert_eq!(get_uv(&mut b).unwrap(), img_seq);
        let idx = get_uv(&mut b).unwrap();
        total = get_uv(&mut b).unwrap();
        chunks.insert(idx, b.to_vec());
    }
    assert_eq!(chunks.len() as u64, total);
    let img: Vec<u8> = chunks.into_values().flatten().collect();
    assert!(img.len() < crate::img::tests::sample_jpeg().len());
    assert_eq!(image::guess_format(&img).unwrap(), image::ImageFormat::WebP);
    assert_eq!(image::load_from_memory(&img).unwrap().width(), 320);

    // HTTPS interception: enable it, then fetch the CA certificate
    let mut q = vec![hdr(T_PROXY_CFG, CODEC_RAW)];
    put_uv(&mut q, 777);
    q.extend_from_slice(&[1, 30]);
    put_uv(&mut q, 800);
    q.push(1);
    let r = p.req(&q).await;
    assert_eq!(r[0][0], hdr(T_ACK, CODEC_RAW));
    assert!(app.proxy.read().unwrap().https);
    // an older app sends no video limit: the default applies
    assert_eq!(app.proxy.read().unwrap().video_kbps, crate::app::VIDEO_KBPS);
    // the video limit (kbit/s) follows; it is kept in proxy.bin like the rest
    let mut q = vec![hdr(T_PROXY_CFG, CODEC_RAW)];
    put_uv(&mut q, 778);
    q.extend_from_slice(&[1, 30]);
    put_uv(&mut q, 800);
    q.push(1);
    put_uv(&mut q, 1200);
    let r = p.req(&q).await;
    assert_eq!(r[0][0], hdr(T_ACK, CODEC_RAW));
    assert_eq!(app.proxy.read().unwrap().video_kbps, 1200);
    let saved = std::fs::read(app.data.join("proxy.bin")).unwrap();
    assert!(saved.ends_with(&[0xB0, 0x09]), "{saved:?}"); // varint 1200
    let _ = app.ca.set(b"fake ca der".to_vec());
    let r = p.req(&[hdr(T_CA, CODEC_RAW)]).await;
    assert_eq!(r[0], [&[hdr(T_CA_CERT, CODEC_RAW)][..], b"fake ca der"].concat());

    // "Data usage": totals and sites, compressed; with the reset flag the next reply starts from zero
    let _l = crate::activity::TEST_LOCK.lock().await;
    crate::activity::whatsapp_media(1000, 200);
    crate::activity::add("v.itest-usage.org", crate::activity::Kind::Video, 5000, 0);
    let read = |r: &Vec<Vec<u8>>| {
        let (t, codec) = split_hdr(r[0][0]);
        assert_eq!(t, T_USAGE_REPLY);
        let body = unpack(codec, &r[0][1..], &build_dict(&[], &[]), 1 << 20).unwrap();
        let mut b = &body[..];
        let totals: Vec<u64> = (0..6).map(|_| get_uv(&mut b).unwrap()).collect();
        let sites: Vec<String> = (0..get_uv(&mut b).unwrap())
            .map(|_| {
                let name = String::from_utf8(get_bytes(&mut b).unwrap().to_vec()).unwrap();
                get_uv(&mut b).unwrap();
                for _ in 0..get_uv(&mut b).unwrap() {
                    (get_u8(&mut b).unwrap(), get_uv(&mut b).unwrap(), get_uv(&mut b).unwrap());
                }
                name
            })
            .collect();
        (totals, sites)
    };
    let (totals, sites) = read(&p.req(&[hdr(T_USAGE, CODEC_RAW), 1]).await);
    assert!(totals[4] >= 1000 && totals[5] >= 200, "{totals:?}");
    assert!(sites.contains(&"itest-usage.org".to_owned()), "{sites:?}");
    let (totals, sites) = read(&p.req(&[hdr(T_USAGE, CODEC_RAW), 0]).await);
    assert!(totals[0] > 0 && totals[4] == 0 && !sites.contains(&"itest-usage.org".to_owned()), "{totals:?} {sites:?}");
}

#[tokio::test]
async fn sync_rotates_key_and_ships_dictionary() {
    let (app, addr, key) = start().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut pn = 0u64;
    let mut rx = RxWindow::default();
    fn send(pn: &mut u64, k: &[u8; 32], pt: &[u8]) -> Vec<u8> {
        *pn += 1;
        seal(k, DIR_C2S, *pn - 1, pt)
    }

    let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let mut hello = vec![hdr(T_SYNC_HELLO, CODEC_RAW)];
    hello.extend_from_slice(x25519_dalek::PublicKey::from(&secret).as_bytes());
    crate::net::write_frame(&mut s, &send(&mut pn, &key, &hello)).await.unwrap();
    let f = crate::net::read_frame(&mut s).await.unwrap();
    let (rpn, r) = rx.open(&key, DIR_S2C, &f).unwrap();
    rx.accept(rpn);
    let server_pub = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(&r[1..]).unwrap());
    let new_key = derive_rotated(&key, secret.diffie_hellman(&server_pub).as_bytes());

    // new key: counters restart
    pn = 0;
    let mut rx = RxWindow::default();
    let mut cur = vec![hdr(T_SYNC_CURSORS, CODEC_RAW)];
    put_uv(&mut cur, 0);
    crate::net::write_frame(&mut s, &send(&mut pn, &new_key, &cur)).await.unwrap();

    let mut chats = Vec::new();
    let (dict_id, dict) = loop {
        let f = crate::net::read_frame(&mut s).await.unwrap();
        let (rpn, r) = rx.open(&new_key, DIR_S2C, &f).expect("server uses the new key");
        rx.accept(rpn);
        let mut b = &r[1..];
        match split_hdr(r[0]).0 {
            T_SYNC_CHAT => {
                let idx = get_uv(&mut b).unwrap();
                let _name = get_str(&mut b).unwrap();
                assert_eq!(get_u8(&mut b).unwrap(), SERVICE_WHATSAPP);
                assert_eq!(get_uv(&mut b).unwrap(), 0);
                chats.push((idx, b.to_vec()));
            }
            T_SYNC_DICT => {
                let id = get_uv(&mut b).unwrap();
                break (id, b.to_vec());
            }
            t => panic!("unexpected {t}"),
        }
    };
    assert_eq!(chats.len(), 2);
    assert_eq!(dict_id, 1);
    assert!(!dict.is_empty());
    let f = crate::net::read_frame(&mut s).await.unwrap();
    assert_eq!(split_hdr(rx.open(&new_key, DIR_S2C, &f).unwrap().1[0]).0, T_SYNC_DONE);

    // the old key is now useless; restricted mode works with new key + dictionary
    let mut old = phone(addr, key).await;
    old.pn = 100;
    let mut q = vec![hdr(T_CHECK, CODEC_RAW)];
    put_uv(&mut q, 1);
    put_uv(&mut q, 0);
    put_uv(&mut q, 2);
    assert!(old.req(&q).await.is_empty(), "old key must be rejected after rotation");

    let mut p = phone(addr, new_key).await;
    p.pn = 1;
    let r = p.req(&q).await;
    assert_eq!(split_hdr(r[0][0]).0, T_SUMMARY);
    let names = app.store.lock().unwrap().names_table(2);
    unpack(split_hdr(r[0][0]).1, &r[0][1..], &build_dict(&dict, &names), 1 << 16).unwrap();

    // a FETCH of nothing new decodes against dict + full synced history
    let (_, stream) = &chats[0];
    let (mut pos, _) = ChatPos::scan(stream).unwrap();
    let mut local = stream.clone();
    fetch_all(&mut p, 1, &dict, 0, &mut local, &mut pos).await;
    assert_eq!(&local, stream);
}

/// Push session on the TCP port: missed notifications first, then live ones that follow WhatsApp's
/// mutes (muted chats only when you are mentioned), PING → PONG, and a Sync key change closes it.
#[tokio::test]
async fn push_session_notifies_like_whatsapp() {
    use crate::notify::{Arrived, message_arrived};
    let (app, addr, key) = start().await;
    let long: String = "x".repeat(150);
    let arrive = |seq: u64, text: &str, mentioned: bool| {
        let m = Arrived { service: SERVICE_WHATSAPP, jid: "grp@g.us", chat: 1, seq, chat_name: "Family", sender: "Bob", kind: KIND_TEXT, text };
        message_arrived(&app, &m, mentioned, false);
    };
    arrive(1000, "already seen", false);
    arrive(1001, "missed while away", false);

    let mut s = TcpStream::connect(addr).await.unwrap();
    let (mut pn, mut rx) = (5000u64, RxWindow::default());
    let mut hello = vec![hdr(T_PUSH_HELLO, CODEC_RAW), 1 << SERVICE_WHATSAPP];
    put_uv(&mut hello, 1000); // the phone has seen everything up to 1000
    crate::net::write_frame(&mut s, &seal(&key, DIR_C2S, pn, &hello)).await.unwrap();
    pn += 1;
    let mut next = async |s: &mut TcpStream, ms: u64| -> Option<Vec<u8>> {
        let f = tokio::time::timeout(Duration::from_millis(ms), crate::net::read_frame(s)).await.ok()?.ok()?;
        let (n, pt) = rx.open(&key, DIR_S2C, &f).expect("decrypt push frame");
        rx.accept(n);
        Some(pt)
    };
    let push_of = |pt: &[u8]| {
        assert_eq!(split_hdr(pt[0]).0, T_PUSH);
        let mut b = &pt[1..];
        let service = get_u8(&mut b).unwrap();
        let seq = get_uv(&mut b).unwrap();
        let chat = get_uv(&mut b).unwrap();
        let (name, sender) = (get_str(&mut b).unwrap(), get_str(&mut b).unwrap());
        let kind = get_u8(&mut b).unwrap();
        (service, seq, chat, name, sender, kind, get_str(&mut b).unwrap())
    };

    let missed = push_of(&next(&mut s, 2000).await.expect("missed notification"));
    assert_eq!((missed.1, missed.6.as_str()), (1001, "missed while away"));

    arrive(1002, &long, false);
    let live = push_of(&next(&mut s, 2000).await.expect("live notification"));
    assert_eq!(live, (SERVICE_WHATSAPP, 1002, 1, "Family".into(), "Bob".into(), KIND_TEXT, "x".repeat(100)));

    app.mutes.lock().unwrap().set("grp@g.us", -1, &app.data);
    arrive(1003, "muted chat", false);
    arrive(1004, "@you look", true);
    let after_mute = push_of(&next(&mut s, 2000).await.expect("mention in a muted chat"));
    assert_eq!(after_mute.1, 1004, "the muted message must not notify, the mention must");

    crate::net::write_frame(&mut s, &seal(&key, DIR_C2S, pn, &[hdr(T_PING, CODEC_RAW)])).await.unwrap();
    let pong = next(&mut s, 2000).await.expect("pong");
    assert_eq!(split_hdr(pong[0]).0, T_PONG);

    app.hub.key_rotated();
    assert!(next(&mut s, 2000).await.is_none(), "session closed after a key change");
}

/// Signal next to WhatsApp: its chats are marked as Signal, SEND and MEDIA reach the Signal client,
/// both states travel in one byte, and the bell (T_MUTE) silences a chat except for mentions.
#[tokio::test]
async fn signal_chats_go_to_signal() {
    let (app, addr, key) = start().await;
    let fake = Arc::new(FakeSig::default());
    *app.sig.write().unwrap() = Some(Arc::new(fake.clone()));
    app.sig_state.store(WA_CONNECTED, std::sync::atomic::Ordering::Relaxed);
    app.wa_state.store(WA_OFF, std::sync::atomic::Ordering::Relaxed);
    let (chat, img) = {
        let mut st = app.store.lock().unwrap();
        let c = st.chat_for("sig-g:abcd", "Climbing").unwrap();
        let s = st.sender_for(c, "sig:7", "Sam").unwrap();
        st.append_msg(c, s, 1_760_200_000, KIND_TEXT, "hi", 0).unwrap();
        let (img, _) = st.append_msg(c, s, 1_760_200_001, KIND_IMAGE, "", 5000).unwrap();
        st.save_media_ref(img, KIND_IMAGE | crate::sig::MEDIA_SIGNAL, b"pointer").unwrap();
        (c, img)
    };
    let mut p = phone(addr, key).await;

    // CHECK from a phone that knows the first two chats: only the new one comes with name + service
    let mut q = vec![hdr(T_CHECK, CODEC_RAW)];
    put_uv(&mut q, 0);
    put_uv(&mut q, 0);
    put_uv(&mut q, 2);
    let r = p.req(&q).await;
    let names = app.store.lock().unwrap().names_table(2);
    let body = unpack(split_hdr(r[0][0]).1, &r[0][1..], &build_dict(b"", &names), 1 << 16).unwrap();
    let mut b = &body[..];
    get_uv(&mut b).unwrap();
    assert_eq!(get_u8(&mut b).unwrap(), states_byte(WA_OFF, WA_CONNECTED));
    assert_eq!(get_uv(&mut b).unwrap(), 3);
    for _ in 0..2 {
        get_uv(&mut b).unwrap();
        get_uv(&mut b).unwrap();
    }
    assert_eq!((get_uv(&mut b).unwrap() as usize, get_uv(&mut b).unwrap(), get_str(&mut b).unwrap()), (chat, 2, "Climbing".into()));
    assert_eq!(get_u8(&mut b).unwrap(), SERVICE_SIGNAL);

    // SEND to the Signal group
    let base = app.store.lock().unwrap().chats[chat].last_seq();
    let mut send = vec![hdr(T_SEND, CODEC_RAW)];
    for v in [9, 0, chat as u64, base] {
        put_uv(&mut send, v);
    }
    send.extend_from_slice(b"on my way");
    assert_eq!(split_hdr(p.req(&send).await[0][0]).0, T_SENT);

    // MEDIA of a Signal attachment (quality 0 = as is, so no slow recompression in this test)
    let mut q = vec![hdr(T_MEDIA, CODEC_RAW)];
    put_uv(&mut q, img);
    put_uv(&mut q, 320);
    q.push(0);
    put_uv(&mut q, 0);
    put_uv(&mut q, 64);
    assert_eq!(split_hdr(p.req(&q).await[0][0]).0, T_CHUNK);
    assert_eq!(*fake.0.lock().unwrap(), vec!["send sig-g:abcd on my way".to_string(), format!("download {KIND_IMAGE} pointer")]);

    // the bell: T_MUTE is acknowledged (and a retry is harmless), then only mentions notify
    let mut mute = vec![hdr(T_MUTE, CODEC_RAW)];
    put_uv(&mut mute, 77);
    put_uv(&mut mute, chat as u64);
    mute.push(1);
    let r = p.req(&mute).await;
    let mut b = &r[0][1..];
    assert_eq!((split_hdr(r[0][0]).0, get_uv(&mut b).unwrap()), (T_ACK, 77));
    let mut live = app.hub.subscribe();
    let arrive = |seq: u64, mentioned: bool| {
        let m = crate::notify::Arrived { service: SERVICE_SIGNAL, jid: "sig-g:abcd", chat, seq, chat_name: "Climbing", sender: "Sam", kind: KIND_TEXT, text: "x" };
        crate::notify::message_arrived(&app, &m, mentioned, false);
    };
    arrive(2000, false);
    arrive(2001, true);
    let got = live.try_recv().expect("the mention notifies");
    assert_eq!((got.service, got.seq), (SERVICE_SIGNAL, 2001));
    assert!(live.try_recv().is_err(), "the muted message did not notify");
    mute[1] = 78;
    *mute.last_mut().unwrap() = 0;
    p.req(&mute).await;
    arrive(2002, false);
    assert_eq!(live.try_recv().expect("unmuted again").seq, 2002);
}
