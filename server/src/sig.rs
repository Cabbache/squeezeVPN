//! Signal linked-device gateway (presage), the counterpart of `wa.rs`: prints the linking QR in the
//! terminal and turns incoming messages into chat records.
//!
//! presage's futures are not `Send`, so Signal runs on its own thread (a single-threaded runtime);
//! the rest of the server reaches it through `Sig`, which forwards requests to that thread.
//!
//! Chat ids in the store: `sig:<service id>` for 1:1 chats, `sig-g:<hex master key>` for groups.
//! Media references are stored with the top bit of the kind byte set (see `MEDIA_SIGNAL`).

use crate::app::{App, BoxFut, Messenger};
use crate::wire::*;
use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use futures::channel::oneshot as link_oneshot;
use presage::Manager;
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::content::{Content, ContentBody, DataMessage, GroupContextV2};
use presage::libsignal_service::prelude::{ProfileKey, ProtobufMessage, Uuid};
use presage::libsignal_service::proto::body_range::AssociatedValue;
use presage::libsignal_service::proto::sync_message::{Content as SyncContent, Sent};
use presage::libsignal_service::proto::{AttachmentPointer, SyncMessage};
use presage::libsignal_service::protocol::ServiceId;
use presage::manager::Registered;
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage::store::{ContentsStore, Thread};
use presage_store_sqlite::SqliteStore;
use std::cell::RefCell;
use std::future::Future;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Set on the stored kind byte of a Signal media reference (WhatsApp's have it clear).
pub const MEDIA_SIGNAL: u8 = 0x80;
const GROUP: &str = "sig-g:";
const CONTACT: &str = "sig:";

type M = Manager<SqliteStore, Registered>;

/// Is this store chat id a Signal chat?
pub fn is_signal(jid: &str) -> bool {
    jid.starts_with(CONTACT) || jid.starts_with(GROUP)
}

fn chat_id(thread: &Thread) -> String {
    match thread {
        Thread::Contact(sid) => format!("{CONTACT}{}", sid.service_id_string()),
        Thread::Group(key) => format!("{GROUP}{}", hex(key)),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Requests from the rest of the server to the Signal thread.
enum Cmd {
    Send(String, String, oneshot::Sender<Result<String>>),
    Download(Vec<u8>, oneshot::Sender<Result<Vec<u8>>>),
}

struct Sig(mpsc::UnboundedSender<Cmd>);

impl Messenger for Sig {
    fn send_text(&self, jid: String, text: String) -> BoxFut<Result<String>> {
        let (tx, rx) = oneshot::channel();
        let sent = self.0.send(Cmd::Send(jid, text, tx));
        Box::pin(async move {
            sent.map_err(|_| anyhow!("signal stopped"))?;
            rx.await.map_err(|_| anyhow!("signal stopped"))?
        })
    }

    fn download(&self, _kind: u8, proto: Vec<u8>) -> BoxFut<Result<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        let sent = self.0.send(Cmd::Download(proto, tx));
        Box::pin(async move {
            sent.map_err(|_| anyhow!("signal stopped"))?;
            rx.await.map_err(|_| anyhow!("signal stopped"))?
        })
    }
}

/// Runs `make()` on a new thread with its own single-threaded runtime (presage needs that).
fn on_own_thread<R, F>(make: impl FnOnce() -> F + Send + 'static) -> oneshot::Receiver<R>
where
    R: Send + 'static,
    F: Future<Output = R> + 'static,
{
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("signal".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("signal runtime");
            let _ = tx.send(tokio::task::LocalSet::new().block_on(&rt, make()));
        })
        .expect("signal thread");
    rx
}

async fn open_store(data: &Path) -> Result<SqliteStore> {
    let path = data.join("signal.db");
    SqliteStore::open(&path.to_string_lossy(), OnNewIdentity::Trust).await.map_err(|e| anyhow!("opening {}: {e}", path.display()))
}

/// `svpn init` / `svpn link signal`: prints the linking QR until Signal is linked, then returns.
pub async fn link(app: Arc<App>) -> Result<()> {
    let data = app.data.clone();
    on_own_thread(move || async move {
        let store = open_store(&data).await?;
        let (tx, rx) = link_oneshot::channel();
        let (linked, _) = futures::future::join(Manager::link_secondary_device(store, SignalServers::Production, "svpn".into(), tx), async move {
            if let Ok(url) = rx.await {
                println!("\nLink Signal: on your phone open Signal > Settings > Linked devices > Link new device and scan this:");
                if let Err(e) = qr2term::print_qr(url.to_string()) {
                    log::error!("printing QR: {e}");
                }
            }
        })
        .await;
        let mut m = linked.map_err(|e| anyhow!("linking Signal: {e}"))?;
        // ask the phone for its contacts, so chats get their names
        let _ = m.request_contacts().await;
        log::info!("signal linked");
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("signal thread stopped"))?
}

/// Runs the Signal client until the process exits. Failures only affect messaging.
pub fn start(app: Arc<App>) {
    let (tx, rx) = mpsc::unbounded_channel();
    *app.sig.write().unwrap() = Some(Arc::new(Sig(tx)));
    drop(on_own_thread(move || run(app, rx)));
}

async fn run(app: Arc<App>, mut cmds: mpsc::UnboundedReceiver<Cmd>) {
    let store = match open_store(&app.data).await {
        Ok(s) => s,
        Err(e) => {
            app.sig_state.store(WA_DISCONNECTED, Ordering::Relaxed);
            return log::error!("signal: {e:#}");
        }
    };
    // the manager of the current connection; requests use a clone of it
    let current: Rc<RefCell<Option<M>>> = Rc::default();
    let cur = current.clone();
    tokio::task::spawn_local(async move {
        while let Some(cmd) = cmds.recv().await {
            let m = cur.borrow().clone();
            tokio::task::spawn_local(async move {
                match cmd {
                    Cmd::Send(jid, text, reply) => {
                        let r = match m {
                            Some(mut m) => send(&mut m, &jid, text).await,
                            None => Err(anyhow!("signal not connected")),
                        };
                        let _ = reply.send(r);
                    }
                    Cmd::Download(proto, reply) => {
                        let r = match m {
                            Some(m) => download(&m, &proto).await,
                            None => Err(anyhow!("signal not connected")),
                        };
                        let _ = reply.send(r);
                    }
                }
            });
        }
    });

    let mut backoff = Duration::from_secs(2);
    loop {
        let m = match Manager::load_registered(store.clone()).await {
            Ok(m) => m,
            Err(e) => {
                app.sig_state.store(WA_LOGGED_OUT, Ordering::Relaxed);
                return log::error!("signal is not linked ({e}) — run `svpn link signal`");
            }
        };
        *current.borrow_mut() = Some(m.clone());
        let began = tokio::time::Instant::now();
        if let Err(e) = receive(&app, m).await {
            log::warn!("signal: {e:#}");
        }
        app.sig_state.store(WA_DISCONNECTED, Ordering::Relaxed);
        if began.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(2); // it had been working
        }
        log::info!("signal disconnected, reconnecting in {} s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(300));
    }
}

async fn receive(app: &App, mut m: M) -> Result<()> {
    let mut rx = m.clone();
    let messages = rx.receive_messages().await.context("connecting")?;
    futures::pin_mut!(messages);
    let me = m.registration_data().service_ids.aci;
    while let Some(r) = messages.next().await {
        match r {
            Received::QueueEmpty => {
                if app.sig_state.swap(WA_CONNECTED, Ordering::Relaxed) != WA_CONNECTED {
                    log::info!("signal connected");
                }
            }
            Received::Contacts { .. } => log::debug!("signal: contacts synced"),
            Received::Content(c) => on_content(app, &mut m, me, &c).await,
            Received::DecryptionError(s) => log::warn!("signal: could not decrypt a message from {}", s.service_id_string()),
        }
    }
    bail!("connection closed")
}

/// One stored message: (kind, text, size, encoded AttachmentPointer).
type Part = (u8, String, u64, Option<Vec<u8>>);

fn kind_of(p: &AttachmentPointer) -> u8 {
    let t = p.content_type.as_deref().unwrap_or("");
    if t.starts_with("image/") {
        KIND_IMAGE
    } else if t.starts_with("video/") {
        KIND_VIDEO
    } else if t.starts_with("audio/") {
        KIND_AUDIO
    } else {
        KIND_DOC
    }
}

/// The messages to store for a DataMessage: one per attachment (the first one carries the text), or
/// just the text. Reactions, deletions, group updates etc. give none.
fn parts(dm: &DataMessage, text: String) -> Vec<Part> {
    let mut out = Vec::new();
    for (i, a) in dm.attachments.iter().enumerate() {
        let kind = kind_of(a);
        let caption = if i == 0 { text.clone() } else { String::new() };
        let text = match (kind, a.file_name.as_deref()) {
            (KIND_DOC, Some(name)) if caption.is_empty() => name.to_owned(),
            (KIND_DOC, Some(name)) => format!("{name}: {caption}"),
            _ => caption,
        };
        out.push((kind, text, a.size.unwrap_or(0) as u64, Some(a.encode_to_vec())));
    }
    if let Some(s) = &dm.sticker {
        let size = s.data.as_ref().and_then(|d| d.size).unwrap_or(0) as u64;
        out.push((KIND_STICKER, s.emoji.clone().unwrap_or_default(), size, s.data.as_ref().map(|d| d.encode_to_vec())));
    }
    if out.is_empty() && !text.is_empty() {
        out.push((KIND_TEXT, text, 0, None));
    }
    out
}

/// Mentioned ACIs as (UTF-16 start, length, aci).
fn mentions(dm: &DataMessage) -> Vec<(usize, usize, Uuid)> {
    dm.body_ranges
        .iter()
        .filter_map(|r| {
            let aci = match r.associated_value.as_ref()? {
                AssociatedValue::MentionAci(s) => Uuid::parse_str(s).ok()?,
                AssociatedValue::MentionAciBinary(b) => Uuid::from_slice(b).ok()?,
                _ => return None,
            };
            Some((r.start? as usize, r.length? as usize, aci))
        })
        .collect()
}

/// Signal puts a placeholder (U+FFFC) where a mention is; this writes `@Name` there instead.
/// Ranges are in UTF-16 code units.
pub fn fill_mentions(body: &str, mut names: Vec<(usize, usize, String)>) -> String {
    let mut u: Vec<u16> = body.encode_utf16().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.0));
    for (start, len, name) in names {
        if start + len <= u.len() {
            u.splice(start..start + len, format!("@{name}").encode_utf16());
        }
    }
    String::from_utf16_lossy(&u)
}

async fn contact_name(m: &mut M, sid: &ServiceId, profile_key: Option<&[u8]>) -> String {
    let contact = m.store().contact_by_id(sid).await.ok().flatten();
    if let Some(c) = contact.as_ref().filter(|c| !c.name.is_empty()) {
        return c.name.clone();
    }
    if let (ServiceId::Aci(aci), Some(key)) = (sid, profile_key.and_then(|k| <[u8; 32]>::try_from(k).ok())) {
        if let Ok(p) = m.retrieve_profile_by_uuid(*aci, ProfileKey::create(key)).await {
            if let Some(name) = p.name.map(|n| n.to_string()).filter(|n| !n.is_empty()) {
                return name;
            }
        }
    }
    match contact.and_then(|c| c.phone_number) {
        Some(p) => p.to_string(),
        None => sid.service_id_string().chars().take(8).collect(),
    }
}

async fn on_content(app: &App, m: &mut M, me: Uuid, c: &Content) {
    let (dm, from_me) = match &c.body {
        ContentBody::DataMessage(dm) => (dm, false),
        ContentBody::SynchronizeMessage(SyncMessage { content: Some(SyncContent::Sent(Sent { message: Some(dm), .. })), .. }) => (dm, true),
        _ => return,
    };
    let Ok(thread) = Thread::try_from(c) else { return };
    let mut names = Vec::new();
    for (start, len, aci) in mentions(dm) {
        let name = if aci == me { "you".to_owned() } else { contact_name(m, &ServiceId::Aci(aci.into()), None).await };
        names.push((start, len, name));
    }
    let text = fill_mentions(dm.body.as_deref().unwrap_or(""), names);
    let parts = parts(dm, text);
    if parts.is_empty() {
        return;
    }
    let jid = chat_id(&thread);
    let is_group = matches!(thread, Thread::Group(_));
    let chat_name = match &thread {
        Thread::Group(key) => m.store().group(*key).await.ok().flatten().map(|g| g.title).filter(|t| !t.is_empty()).unwrap_or_else(|| "Signal group".into()),
        // in a message from me, the profile key is mine, not the chat partner's
        Thread::Contact(sid) => contact_name(m, sid, if from_me { None } else { dm.profile_key.as_deref() }).await,
    };
    let sender = c.metadata.sender;
    let sender_name = if from_me { String::new() } else { contact_name(m, &sender, dm.profile_key.as_deref()).await };
    let ts = dm.timestamp.map_or(c.metadata.server_timestamp.timestamp(), |t| (t / 1000) as i64);

    let res = (|| -> Result<(usize, u64)> {
        let mut st = app.store.lock().unwrap();
        let chat = st.chat_for(&jid, &chat_name)?;
        let s = if from_me { 0 } else { st.sender_for(chat, &format!("{CONTACT}{}", sender.service_id_string()), &sender_name)? };
        let mut first_head = 0;
        for (kind, text, size, media) in &parts {
            let (seq, _) = st.append_msg(chat, s, ts, *kind, text, *size)?;
            if let Some(p) = media {
                st.save_media_ref(seq, kind | MEDIA_SIGNAL, p)?;
            }
            if first_head == 0 {
                first_head = st.head;
            }
        }
        Ok((chat, first_head))
    })();
    let (chat, seq) = match res {
        Ok(r) => r,
        Err(e) => return log::error!("storing signal message: {e:#}"),
    };
    if from_me {
        return;
    }
    let mentioned = mentions(dm).iter().any(|r| r.2 == me);
    let replied = dm.quote.as_ref().is_some_and(|q| {
        let a = q.author_aci.as_deref().and_then(|s| Uuid::parse_str(s).ok());
        a.or_else(|| q.author_aci_binary.as_deref().and_then(|b| Uuid::from_slice(b).ok())) == Some(me)
    });
    let (kind, text, ..) = &parts[0];
    let n = crate::notify::Arrived {
        service: SERVICE_SIGNAL,
        jid: &jid,
        chat,
        seq,
        chat_name: &chat_name,
        sender: if is_group { &sender_name } else { "" },
        kind: *kind,
        text,
    };
    crate::notify::message_arrived(app, &n, mentioned, replied);
}

async fn send(m: &mut M, jid: &str, text: String) -> Result<String> {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    let mut dm = DataMessage { body: Some(text), timestamp: Some(ts), ..Default::default() };
    if let Some(key) = jid.strip_prefix(GROUP) {
        let key: [u8; 32] = unhex(key).and_then(|k| k.try_into().ok()).ok_or_else(|| anyhow!("bad group id"))?;
        let revision = m.store().group(key).await.ok().flatten().map_or(0, |g| g.revision);
        dm.group_v2 = Some(GroupContextV2 { master_key: Some(key.to_vec()), revision: Some(revision), ..Default::default() });
        m.send_message_to_group(&key, dm, ts).await.map_err(|e| anyhow!("{e}"))?;
    } else {
        let sid = jid.strip_prefix(CONTACT).and_then(ServiceId::parse_from_service_id_string).ok_or_else(|| anyhow!("bad chat id {jid}"))?;
        m.send_message(sid, dm, ts).await.map_err(|e| anyhow!("{e}"))?;
    }
    Ok(ts.to_string())
}

async fn download(m: &M, proto: &[u8]) -> Result<Vec<u8>> {
    let p = AttachmentPointer::decode(proto).map_err(|e| anyhow!("media ref: {e}"))?;
    m.get_attachment(&p).await.map_err(|e| anyhow!("download: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use presage::libsignal_service::proto::BodyRange;

    #[test]
    fn mentions_become_names() {
        // "Hi ￼, see 😀 ￼!" with two mention placeholders (the emoji is two UTF-16 units)
        let body = "Hi \u{FFFC}, see 😀 \u{FFFC}!";
        assert_eq!(fill_mentions(body, vec![(3, 1, "Alex".into()), (13, 1, "you".into())]), "Hi @Alex, see 😀 @you!");
        assert_eq!(fill_mentions("x", vec![(5, 1, "out of range".into())]), "x");
    }

    #[test]
    fn mention_and_quote_ranges_are_read() {
        let a = Uuid::from_u128(7);
        let dm = DataMessage {
            body_ranges: vec![
                BodyRange { start: Some(0), length: Some(1), associated_value: Some(AssociatedValue::MentionAci(a.to_string())) },
                BodyRange { start: Some(2), length: Some(1), associated_value: Some(AssociatedValue::MentionAciBinary(a.as_bytes().to_vec())) },
                BodyRange { start: Some(4), length: Some(3), associated_value: Some(AssociatedValue::Style(1)) },
            ],
            ..Default::default()
        };
        assert_eq!(mentions(&dm), vec![(0, 1, a), (2, 1, a)]);
    }

    #[test]
    fn attachments_become_messages() {
        let att = |t: &str, name: Option<&str>, size| AttachmentPointer {
            content_type: Some(t.into()),
            file_name: name.map(Into::into),
            size: Some(size),
            ..Default::default()
        };
        let dm = DataMessage {
            attachments: vec![att("image/jpeg", None, 1000), att("application/pdf", Some("a.pdf"), 2000), att("audio/aac", None, 30)],
            ..Default::default()
        };
        let p = parts(&dm, "look".into());
        let summary: Vec<_> = p.iter().map(|(k, t, s, m)| (*k, t.as_str(), *s, m.is_some())).collect();
        assert_eq!(summary, vec![(KIND_IMAGE, "look", 1000, true), (KIND_DOC, "a.pdf", 2000, true), (KIND_AUDIO, "", 30, true)]);
        // the stored reference decodes back to the pointer
        assert_eq!(AttachmentPointer::decode(&p[0].3.clone().unwrap()[..]).unwrap().size, Some(1000));
        assert_eq!(parts(&DataMessage::default(), "hi".into()).len(), 1);
        assert!(parts(&DataMessage::default(), String::new()).is_empty(), "a reaction or group update stores nothing");
    }

    #[test]
    fn chat_ids() {
        let key = [0xabu8; 32];
        let g = chat_id(&Thread::Group(key));
        assert!(g.starts_with("sig-g:abab") && is_signal(&g));
        assert_eq!(unhex(&g[GROUP.len()..]).unwrap(), key.to_vec());
        let a = ServiceId::Aci(Uuid::from_u128(1).into());
        let c = chat_id(&Thread::Contact(a));
        assert_eq!(ServiceId::parse_from_service_id_string(&c[CONTACT.len()..]), Some(a));
        assert!(is_signal(&c) && !is_signal("123@s.whatsapp.net"));
    }
}
