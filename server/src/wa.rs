//! WhatsApp linked-device gateway (whatsapp-rust). Prints the pairing QR in the
//! terminal and turns incoming messages into chat records.

use crate::app::{App, BoxFut, Messenger};
use crate::wire::*;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use whatsapp_rust::buffa::Message as _;
use whatsapp_rust::prelude::*;

struct Wa(Arc<Client>);

fn decode<M: whatsapp_rust::buffa::Message>(b: &[u8]) -> Result<M> {
    M::decode_from_slice(b).map_err(|e| anyhow!("decode media ref: {e:?}"))
}

impl Messenger for Wa {
    fn send_text(&self, jid: String, text: String) -> BoxFut<Result<String>> {
        let c = self.0.clone();
        Box::pin(async move {
            let jid: Jid = jid.parse().map_err(|e| anyhow!("bad jid: {e:?}"))?;
            let r = c.send_text(jid, text).await.map_err(|e| anyhow!("{e:?}"))?;
            Ok(r.message_id.to_string())
        })
    }

    fn download(&self, kind: u8, proto: Vec<u8>) -> BoxFut<Result<Vec<u8>>> {
        let c = self.0.clone();
        Box::pin(async move {
            use wa::message::*;
            let r = match kind {
                KIND_IMAGE => c.download(&decode::<ImageMessage>(&proto)?, Default::default()).await,
                KIND_VIDEO => c.download(&decode::<VideoMessage>(&proto)?, Default::default()).await,
                KIND_AUDIO => c.download(&decode::<AudioMessage>(&proto)?, Default::default()).await,
                KIND_DOC => c.download(&decode::<DocumentMessage>(&proto)?, Default::default()).await,
                KIND_STICKER => c.download(&decode::<StickerMessage>(&proto)?, Default::default()).await,
                k => return Err(anyhow!("no media of kind {k}")),
            };
            r.map_err(|e| anyhow!("download: {e:?}"))
        })
    }
}

/// (kind, caption/text, size, encoded media sub-message)
fn classify(msg: &wa::Message) -> Option<(u8, String, u64, Option<Vec<u8>>)> {
    let base = msg.get_base_message();
    let caption = msg.get_caption().unwrap_or_default().to_owned();
    if let Some(m) = base.image_message.as_option() {
        return Some((KIND_IMAGE, caption, m.file_length.unwrap_or(0), Some(m.encode_to_vec())));
    }
    if let Some(m) = base.video_message.as_option() {
        return Some((KIND_VIDEO, caption, m.file_length.unwrap_or(0), Some(m.encode_to_vec())));
    }
    if let Some(m) = base.audio_message.as_option() {
        return Some((KIND_AUDIO, String::new(), m.file_length.unwrap_or(0), Some(m.encode_to_vec())));
    }
    if let Some(m) = base.document_message.as_option() {
        let name = m.file_name.clone().unwrap_or_default();
        let text = if caption.is_empty() { name } else { format!("{name}: {caption}") };
        return Some((KIND_DOC, text, m.file_length.unwrap_or(0), Some(m.encode_to_vec())));
    }
    if let Some(m) = base.sticker_message.as_option() {
        return Some((KIND_STICKER, String::new(), m.file_length.unwrap_or(0), Some(m.encode_to_vec())));
    }
    msg.text_content().filter(|t| !t.is_empty()).map(|t| (KIND_TEXT, t.to_owned(), 0, None))
}

async fn on_message(app: Arc<App>, ctx: MessageContext) {
    let info = &ctx.info;
    let chat = info.source.chat.to_string();
    if info.is_status_stanza || chat.contains("status@broadcast") {
        return;
    }
    if app.own_ids.lock().unwrap().remove(info.id.as_str()) {
        return; // echo of a message we sent ourselves
    }
    let Some((kind, text, size, media)) = classify(&ctx.message) else { return };
    let push = info.push_name.to_string();
    let sender = info.source.sender.user.to_string();
    let chat_name = if info.source.is_group {
        match ctx.client.groups().fetch_metadata(&info.source.chat).await {
            Ok(m) => m.subject.unwrap_or_else(|| info.source.chat.user.to_string()),
            Err(_) => info.source.chat.user.to_string(),
        }
    } else if !info.source.is_from_me && !push.is_empty() {
        push.clone()
    } else {
        info.source.chat.user.to_string()
    };
    let res = (|| -> Result<(usize, u64)> {
        let mut st = app.store.lock().unwrap();
        let c = st.chat_for(&chat, &chat_name)?;
        let s = if info.source.is_from_me {
            0
        } else {
            let name = if push.is_empty() { sender.clone() } else { push.clone() };
            st.sender_for(c, &info.source.sender.to_string(), &name)?
        };
        let (seq, _) = st.append_msg(c, s, info.timestamp.timestamp(), kind, &text, size)?;
        if let Some(m) = media {
            st.save_media_ref(seq, kind, &m)?;
        }
        Ok((c, st.head))
    })();
    let (c, head) = match res {
        Ok(r) => r,
        Err(e) => return log::error!("storing message: {e:#}"),
    };
    if info.source.is_from_me {
        return;
    }
    // notify the phone (push session) if WhatsApp would: not muted, or you are mentioned / replied to
    let own: Vec<String> = [ctx.client.pn(), ctx.client.lid()].into_iter().flatten().map(|j| j.user.to_string()).collect();
    let user_of = |jid: &str| jid.split('@').next().unwrap_or("").split(':').next().unwrap_or("").to_owned();
    let ci = ctx.message.context_info();
    let mentioned = ci.is_some_and(|c| c.mentioned_jid.iter().any(|j| own.contains(&user_of(j))));
    let replied = ci.and_then(|c| c.participant.as_deref()).is_some_and(|p| own.contains(&user_of(p)));
    let sender_name = if !info.source.is_group {
        String::new()
    } else if push.is_empty() {
        sender
    } else {
        push
    };
    let n = crate::notify::Arrived { service: SERVICE_WHATSAPP, jid: &chat, chat: c, seq: head, chat_name: &chat_name, sender: &sender_name, kind, text: &text };
    crate::notify::message_arrived(&app, &n, mentioned, replied);
}

/// WhatsApp's mute setting for a chat changed (or arrived with the first full sync): notifications
/// follow it.
fn on_mute(app: &App, ev: &Event) {
    let Event::MuteUpdate(m) = ev else { return };
    let until = match (m.action.muted, m.action.mute_end_timestamp) {
        (Some(true), Some(t)) if t > 0 => {
            if t > 100_000_000_000 { t / 1000 } else { t } // milliseconds or seconds
        }
        (Some(true), _) => -1,
        _ => 0,
    };
    let jid = m.jid.to_string();
    log::debug!("whatsapp: {jid} {}", match until { 0 => "unmuted".into(), -1 => "muted".into(), t => format!("muted until {t}") });
    app.mutes.lock().unwrap().set(&jid, until, &app.data);
}

/// Runs the WhatsApp client until the process exits. Failures only affect messaging.
pub async fn run(app: Arc<App>) -> Result<()> {
    client(app, false).await
}

/// `svpn init` / `svpn link`: prints pairing QR codes until WhatsApp is linked, then returns.
/// Messages arriving meanwhile are stored as usual.
pub async fn link(app: Arc<App>) -> Result<()> {
    client(app, true).await
}

async fn client(app: Arc<App>, link_only: bool) -> Result<()> {
    let store = SqliteStore::open(app.data.join("wa.db").to_string_lossy().as_ref()).await.map_err(|e| anyhow!("{e:?}"))?;
    let (a1, a2, a3, a4, a5) = (app.clone(), app.clone(), app.clone(), app.clone(), app.clone());
    let connected = Arc::new(tokio::sync::Notify::new());
    let qr_shown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (c2, q1, q2) = (connected.clone(), qr_shown.clone(), qr_shown.clone());
    let bot = Bot::builder()
        .with_backend(store)
        .skip_history_sync()
        .on_qr_code(move |code, timeout| {
            a1.wa_state.store(WA_NEEDS_PAIRING, Ordering::Relaxed);
            let first = !q1.swap(true, Ordering::Relaxed);
            async move {
                if first && !link_only {
                    log::warn!("whatsapp is not linked yet: scan the QR below (or stop and run `svpn link`)");
                }
                println!(
                    "\nLink WhatsApp: on your phone open WhatsApp > Settings > Linked devices > Link a device \
                     and scan this (valid {}s, a new one follows):",
                    timeout.as_secs()
                );
                if let Err(e) = qr2term::print_qr(&code) {
                    log::error!("printing QR: {e}");
                }
            }
        })
        .on_connected(move |_| {
            a2.wa_state.store(WA_CONNECTED, Ordering::Relaxed);
            c2.notify_one();
            let linked_now = q2.load(Ordering::Relaxed);
            async move { log::info!("whatsapp connected{}", if linked_now { " — linked" } else { "" }) }
        })
        .on_logged_out(move |info| {
            a3.wa_state.store(WA_LOGGED_OUT, Ordering::Relaxed);
            async move { log::error!("whatsapp logged out: {:?} — run `svpn link` to link it again", info.reason) }
        })
        .on_message(move |ctx| on_message(a4.clone(), ctx))
        .on_event_for(&[EventKind::MuteUpdate], move |ev, _| {
            on_mute(&a5, &ev);
            async {}
        })
        .build()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    *app.wa.write().unwrap() = Some(Arc::new(Wa(bot.client())));
    if link_only {
        tokio::select! {
            _ = bot.run() => anyhow::bail!("whatsapp client stopped before it was linked"),
            _ = connected.notified() => {}
        }
        // let the first session settle (key upload, queued messages) before the process exits
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        return Ok(());
    }
    bot.run().await;
    app.wa_state.store(WA_DISCONNECTED, Ordering::Relaxed);
    log::warn!("whatsapp client stopped");
    Ok(())
}
