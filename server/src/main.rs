// whatsapp-rust's instrumented async fns need a deeper recursion limit (see its examples/demo.rs).
#![recursion_limit = "512"]

mod activity;
mod app;
mod img;
mod keys;
mod mitm;
mod net;
mod notify;
mod provision;
mod proxy;
mod sig;
mod store;
mod tunnel;
mod wa;
mod wire;

#[cfg(test)]
mod itest;

use anyhow::{Result, bail};
use std::path::PathBuf;
use std::sync::Arc;

const USAGE: &str = "usage:
  svpn init --endpoint <public host/ip> [--port 51821] [--wg-port 51820] [--data ./data] [--no-whatsapp] [--no-signal]
                                   config + keys, links WhatsApp and Signal if you want them, prints the phone setup QR
  svpn link [whatsapp|signal] [--data ./data]
                                   link WhatsApp (default) or Signal (later, or again after being logged out;
                                   server stopped)
  svpn provision [--data ./data]   new messaging key + phone setup QR (server stopped)
  svpn run [--data ./data]
  svpn wirebench [--data ./data]   bytes per message for different compression setups";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();
    let data = PathBuf::from(arg(&args, "--data").unwrap_or_else(|| "data".into()));
    match args.get(1).map(String::as_str) {
        Some("init") => {
            let Some(endpoint) = arg(&args, "--endpoint") else { bail!("{USAGE}") };
            let port = arg(&args, "--port").map_or(Ok(51821), |p| p.parse())?;
            let wg_port = arg(&args, "--wg-port").map_or(Ok(51820), |p| p.parse())?;
            let setup = provision::init(&data, &endpoint, port, wg_port)?;
            // the HTTPS-interception CA is made now too, so the phone can fetch it right after setup
            mitm::Mitm::load_or_create(&data, mitm::web_roots())?;
            println!("\nStep 1 of 3: WhatsApp (optional)");
            if !args.iter().any(|a| a == "--no-whatsapp") && ask("Link WhatsApp now? `svpn link whatsapp` adds it later. [Y/n] ") {
                rt()?.block_on(link(data.clone(), false))?;
            } else {
                println!("WhatsApp skipped.");
            }
            println!("\nStep 2 of 3: Signal (optional)");
            if !args.iter().any(|a| a == "--no-signal") && ask("Link Signal now? `svpn link signal` adds it later. [Y/n] ") {
                rt()?.block_on(link(data.clone(), true))?;
            } else {
                println!("Signal skipped.");
            }
            println!("\nStep 3 of 3: set up the phone");
            provision::print_setup(&setup)?;
            println!("Then start the server with `svpn run` and finish setup in the app.");
            firewall_hint(&provision::load_config(&data)?);
            Ok(())
        }
        Some("link") => match args.get(2).map(String::as_str) {
            None | Some("whatsapp") => rt()?.block_on(link(data, false)),
            Some("signal") => rt()?.block_on(link(data, true)),
            Some(a) if a.starts_with("--") => rt()?.block_on(link(data, false)),
            Some(_) => bail!("{USAGE}"),
        },
        Some("provision") => provision::provision(&data),
        Some("run") => rt()?.block_on(run(data)),
        Some("wirebench") => wirebench(&data),
        _ => {
            eprintln!("{USAGE}");
            Ok(())
        }
    }
}

/// Yes/no question on the terminal; Enter (or no terminal) means yes.
fn ask(q: &str) -> bool {
    use std::io::Write;
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut a = String::new();
    let _ = std::io::stdin().read_line(&mut a);
    !a.trim().to_ascii_lowercase().starts_with('n')
}

/// WhatsApp is used once it was linked (`svpn link` / init created its database).
fn whatsapp_linked(data: &std::path::Path) -> bool {
    data.join("wa.db").exists()
}

/// Signal likewise (`svpn link signal`).
fn signal_linked(data: &std::path::Path) -> bool {
    data.join("signal.db").exists()
}

fn rt() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
}

fn open_app(data: &std::path::Path) -> Result<Arc<app::App>> {
    let store = store::Store::open(data)?;
    let keys = keys::Keys::load(&data.join("keys.bin"))?;
    Ok(Arc::new(app::App::new(data.to_path_buf(), store, keys)))
}

/// Links WhatsApp or Signal (QR codes in the terminal) and returns once it is linked.
async fn link(data: PathBuf, signal: bool) -> Result<()> {
    if signal {
        sig::link(open_app(&data)?).await?;
        println!("Signal is linked.");
    } else {
        wa::link(open_app(&data)?).await?;
        println!("WhatsApp is linked.");
    }
    Ok(())
}

fn firewall_hint(cfg: &provision::Config) {
    println!(
        "The phone must reach {} from the internet: open udp/{1} (messages), tcp/{1} (Sync) and udp/{2} (VPN) \
         in the server's firewall / the provider's panel.",
        cfg.endpoint, cfg.port, cfg.wg_port
    );
}

async fn run(data: PathBuf) -> Result<()> {
    let cfg = provision::load_config(&data)?;
    let app = open_app(&data)?;

    let udp = Arc::new(tokio::net::UdpSocket::bind(("0.0.0.0", cfg.port)).await?);
    let tcp = tokio::net::TcpListener::bind(("0.0.0.0", cfg.port)).await?;
    log::info!("messaging on udp/{0}, sync on tcp/{0}", cfg.port);
    tokio::spawn(net::serve_udp(app.clone(), udp));
    tokio::spawn(net::serve_sync(app.clone(), tcp));

    // VPN in userspace: no root, no TUN, no iptables
    let (wg_key, phone_key) = provision::wg_keys(&cfg)?;
    let wg = tokio::net::UdpSocket::bind(("0.0.0.0", cfg.wg_port)).await?;
    log::info!("wireguard on udp/{} (userspace, no root)", cfg.wg_port);
    let proxy = app.proxy.clone();
    let mitm = Arc::new(mitm::Mitm::load_or_create(&data, mitm::web_roots())?);
    let _ = app.ca.set(mitm.ca_der.clone());
    log::info!("https interception {}", if proxy.read().unwrap().https { "on" } else { "off (enable it in the app)" });
    tokio::spawn(async move {
        if let Err(e) = tunnel::serve(wg, wg_key, phone_key, proxy, Some(mitm), tunnel::public).await {
            log::error!("tunnel: {e:#}");
        }
    });

    if whatsapp_linked(&data) {
        log::info!("whatsapp: {} muted chats (notifications follow WhatsApp's mute settings)", app.mutes.lock().unwrap().len());
        let wa_app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = wa::run(wa_app).await {
                log::error!("whatsapp: {e:#}");
            }
        });
    } else {
        app.wa_state.store(wire::WA_OFF, std::sync::atomic::Ordering::Relaxed);
        log::info!("whatsapp: not used on this server (`svpn link` adds it, with the server stopped)");
    }
    if signal_linked(&data) {
        sig::start(app.clone());
    } else {
        app.sig_state.store(wire::WA_OFF, std::sync::atomic::Ordering::Relaxed);
        log::info!("signal: not used on this server (`svpn link signal` adds it, with the server stopped)");
    }

    log::info!(
        "phone connects to {}: udp/{1} + tcp/{1} + udp/{2} must be open to the internet (not just via another VPN)",
        cfg.endpoint, cfg.port, cfg.wg_port
    );
    activity::load(&data);
    tokio::spawn(activity::summary_task());
    log::info!("ready — what the phone does is logged below (RUST_LOG=debug for every request)");
    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");
    // State is persisted as it changes; exit right away (dropping open VPN flows can block).
    std::process::exit(0)
}

/// Bytes per message on the stored chats: plain vs zstd vs zstd+history vs zstd+trained dict+history.
/// The dictionary is trained on the older half of every chat and measured on the newer half.
fn wirebench(data: &std::path::Path) -> Result<()> {
    use wire::*;
    let st = store::Store::open(data)?;
    let split = |c: &store::Chat| c.index.len() / 2;
    let samples: Vec<&[u8]> = st
        .chats
        .iter()
        .flat_map(|c| {
            (0..split(c)).map(move |k| &c.stream[c.index[k].1..c.index.get(k + 1).map_or(c.stream.len(), |e| e.1)])
        })
        .collect();
    let trained = zstd::dict::from_samples(&samples, SYNC_DICT_SIZE).unwrap_or_default();
    let (mut n, mut raw, mut plain, mut hist, mut full) = (0usize, 0usize, 0usize, 0usize, 0usize);
    for c in &st.chats {
        for k in split(c)..c.index.len() {
            if !c.index[k].2 {
                continue;
            }
            let (s, e) = (c.index[k].1, c.index.get(k + 1).map_or(c.stream.len(), |e| e.1));
            let rec = &c.stream[s..e];
            n += 1;
            raw += rec.len();
            plain += pack(rec, &build_dict(b"", b"")).1.len();
            hist += pack(rec, &build_dict(b"", &c.stream[..s])).1.len();
            full += pack(rec, &build_dict(&trained, &c.stream[..s])).1.len();
        }
    }
    if n == 0 {
        println!("no messages stored yet (need real chats to measure)");
        return Ok(());
    }
    // per packet: 1 type byte + ~4 header bytes + 17 crypto + 28 IPv4/UDP
    let ovh = 1 + 4 + PACKET_OVERHEAD + 28;
    println!("{n} messages measured, trained dict {} bytes; average bytes per message (payload / on the wire):", trained.len());
    for (name, v) in [("canonical record", raw), ("zstd", plain), ("zstd + chat history", hist), ("zstd + dict + history", full)] {
        println!("  {name:24} {:7.1} / {:7.1}", v as f64 / n as f64, (v + n * ovh) as f64 / n as f64);
    }
    Ok(())
}
