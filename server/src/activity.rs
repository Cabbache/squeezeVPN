//! A readable log of what the phone does through the VPN: each site (at most once per 10 minutes),
//! each web page, each re-encoded image, and a one-line summary per minute with traffic.
//! Also the "Data usage" numbers for the app: bytes per site and kind of content (video, images, …)
//! and what shrinking saved, since the last reset (kept in `data/stats.bin`).
//! It is the user's browsing history, so it only goes to the terminal; hide it with
//! `RUST_LOG=info,svpn::activity=warn`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A site is logged again only after this long.
const SITE_QUIET: Duration = Duration::from_secs(600);

#[derive(Default)]
struct Activity {
    // this minute
    conns: AtomicU64,
    down: AtomicU64,
    up: AtomicU64,
    images: AtomicU64,
    img_before: AtomicU64,
    img_after: AtomicU64,
    sites_now: Mutex<HashSet<String>>,
    // host -> when it was last logged
    logged: Mutex<HashMap<String, Instant>>,
}

static ACT: LazyLock<Activity> = LazyLock::new(Activity::default);

/// Lifetime totals for the app's "Data saved" button, kept in `data/stats.bin`.
#[derive(Default)]
pub struct Totals {
    pub since: AtomicU64,
    pub web_down: AtomicU64,
    pub img_before: AtomicU64,
    pub img_after: AtomicU64,
    pub wa_before: AtomicU64,
    pub wa_after: AtomicU64,
    dirty: AtomicBool,
}

impl Totals {
    fn fields(&self) -> [&AtomicU64; 6] {
        [&self.since, &self.web_down, &self.img_before, &self.img_after, &self.wa_before, &self.wa_after]
    }

    fn add(&self, f: &AtomicU64, n: u64) {
        if n > 0 {
            f.fetch_add(n, Relaxed);
            self.dirty.store(true, Relaxed);
            let _ = self.since.compare_exchange(0, crate::app::now() as u64, Relaxed, Relaxed);
        }
    }

    /// Varints in field order (also the T_STATS_REPLY body).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        self.fields().iter().for_each(|f| crate::wire::put_uv(&mut b, f.load(Relaxed)));
        b
    }

    /// Reads the totals; returns what follows them.
    fn decode<'a>(&self, mut b: &'a [u8]) -> &'a [u8] {
        for f in self.fields() {
            match crate::wire::get_uv(&mut b) {
                Ok(v) => f.store(v, Relaxed),
                Err(_) => return &[],
            }
        }
        b
    }

    fn reset(&self) {
        self.fields().iter().for_each(|f| f.store(0, Relaxed));
        self.since.store(crate::app::now() as u64, Relaxed);
        self.dirty.store(true, Relaxed);
    }
}

pub static TOTALS: LazyLock<Totals> = LazyLock::new(Totals::default);
static STATS_FILE: OnceLock<PathBuf> = OnceLock::new();

/// Loads the lifetime totals from `data/stats.bin` (they are saved every minute by `summary_task`).
pub fn load(data: &Path) {
    let path = data.join("stats.bin");
    if let Ok(b) = std::fs::read(&path) {
        let mut rest = TOTALS.decode(&b);
        if let Ok(sites) = decode_sites(&mut rest) {
            SITES.lock().unwrap().sites = sites;
        }
    }
    let _ = STATS_FILE.set(path);
}

fn save() {
    if TOTALS.dirty.swap(false, Relaxed)
        && let Some(p) = STATS_FILE.get()
        && let Err(e) = std::fs::write(p, usage(usize::MAX))
    {
        log::warn!("saving {}: {e}", p.display());
    }
}

/// What kind of content bytes were (from the response's Content-Type, or the flow when it can't be seen).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Kind {
    Video,
    Audio,
    Images,
    Pages,
    Scripts,
    Styles,
    Fonts,
    Data,
    Other,
    Encrypted,
    Quic,
    Dns,
    Tcp,
    Udp,
}

const KINDS: usize = 14;
const ALL_KINDS: [Kind; KINDS] = [
    Kind::Video,
    Kind::Audio,
    Kind::Images,
    Kind::Pages,
    Kind::Scripts,
    Kind::Styles,
    Kind::Fonts,
    Kind::Data,
    Kind::Other,
    Kind::Encrypted,
    Kind::Quic,
    Kind::Dns,
    Kind::Tcp,
    Kind::Udp,
];

impl Kind {
    pub fn name(self) -> &'static str {
        ["video", "audio", "images", "pages", "scripts", "styles", "fonts", "data", "other", "encrypted", "quic", "dns", "tcp", "udp"]
            [self as usize]
    }
}

/// The kind of a response, from its Content-Type (and the path, for servers that say "octet-stream").
pub fn kind_of(content_type: &str, path: &str) -> Kind {
    let t = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let ext = path.split(['?', '#']).next().unwrap_or("").rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if t.starts_with("video/") || t.contains("mpegurl") || t == "application/dash+xml" || t.contains("mp2t")
        // a combined audio + video streaming format
        || t == "application/vnd.yt-ump"
    {
        Kind::Video
    } else if t.starts_with("audio/") {
        Kind::Audio
    } else if t.starts_with("image/") {
        Kind::Images
    } else if t == "text/html" || t == "application/xhtml+xml" {
        Kind::Pages
    } else if t.contains("javascript") || t.contains("ecmascript") || t == "application/wasm" {
        Kind::Scripts
    } else if t == "text/css" {
        Kind::Styles
    } else if t.starts_with("font/") || t.contains("font") {
        Kind::Fonts
    } else if t.contains("json") || t.contains("xml") || t.contains("protobuf") || t.contains("grpc") {
        Kind::Data
    } else if matches!(ext.as_str(), "mp4" | "m4s" | "ts" | "m3u8" | "mpd" | "webm") {
        Kind::Video
    } else if matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "webp" | "gif" | "avif") {
        Kind::Images
    } else {
        Kind::Other
    }
}

/// The site a host belongs to: `cdn.example.com` → `example.com`, `www.example.co.uk` → `example.co.uk`; IPs stay as they are.
pub fn domain(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = match h.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or("").to_owned(),
        None if h.matches(':').count() == 1 => h.split(':').next().unwrap_or("").to_owned(),
        None => h,
    };
    if h.parse::<IpAddr>().is_ok() {
        return h;
    }
    let l: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    let n = l.len();
    if n <= 2 {
        return l.join(".");
    }
    // second-level registries like co.uk, com.au, com.br
    let keep = if l[n - 1].len() == 2 && matches!(l[n - 2], "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "or" | "ne") { 3 } else { 2 };
    l[n - keep..].join(".")
}

/// One site's traffic since the last reset.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Site {
    pub streams: u64,
    pub bytes: [u64; KINDS],
    pub saved: [u64; KINDS],
}

impl Site {
    pub fn total(&self) -> u64 {
        self.bytes.iter().sum()
    }
}

#[derive(Default)]
struct Sites {
    sites: HashMap<String, Site>,
    /// this minute, for the log line: (site, kind) -> bytes
    minute: HashMap<(String, Kind), u64>,
}

static SITES: LazyLock<Mutex<Sites>> = LazyLock::new(Mutex::default);
/// Sites kept at most (the smallest are dropped).
const MAX_SITES: usize = 1000;

fn with_site(host: &str, f: impl FnOnce(&mut Site)) -> String {
    let name = domain(host);
    let mut s = SITES.lock().unwrap();
    if !s.sites.contains_key(&name)
        && s.sites.len() >= MAX_SITES
        && let Some(small) = s.sites.iter().min_by_key(|(_, v)| v.total()).map(|(k, _)| k.clone())
    {
        s.sites.remove(&small);
    }
    f(s.sites.entry(name.clone()).or_default());
    TOTALS.dirty.store(true, Relaxed);
    name
}

/// `bytes` of `kind` went to the phone from `host` (`saved`: what shrinking removed from them).
pub fn add(host: &str, kind: Kind, bytes: u64, saved: u64) {
    if bytes == 0 && saved == 0 {
        return;
    }
    let name = with_site(host, |s| {
        s.bytes[kind as usize] += bytes;
        s.saved[kind as usize] += saved;
    });
    *SITES.lock().unwrap().minute.entry((name, kind)).or_default() += bytes;
}

/// The phone opened a connection (TCP) or flow (UDP) to `host`.
pub fn stream(host: &str) {
    with_site(host, |s| s.streams += 1);
}

/// Totals and the `limit` biggest sites, as varints (the T_USAGE_REPLY body and `data/stats.bin`).
pub fn usage(limit: usize) -> Vec<u8> {
    use crate::wire::{put_bytes, put_uv};
    let mut b = TOTALS.encode();
    let s = SITES.lock().unwrap();
    let mut sites: Vec<(&String, &Site)> = s.sites.iter().collect();
    sites.sort_by_key(|(_, v)| std::cmp::Reverse(v.total()));
    sites.truncate(limit);
    put_uv(&mut b, sites.len() as u64);
    for (name, site) in sites {
        put_bytes(&mut b, name.as_bytes());
        put_uv(&mut b, site.streams);
        let kinds: Vec<Kind> = ALL_KINDS.into_iter().filter(|k| site.bytes[*k as usize] + site.saved[*k as usize] > 0).collect();
        put_uv(&mut b, kinds.len() as u64);
        for k in kinds {
            b.push(k as u8);
            put_uv(&mut b, site.bytes[k as usize]);
            put_uv(&mut b, site.saved[k as usize]);
        }
    }
    b
}

fn decode_sites(b: &mut &[u8]) -> anyhow::Result<HashMap<String, Site>> {
    use crate::wire::{get_bytes, get_u8, get_uv};
    let mut out = HashMap::new();
    for _ in 0..get_uv(b)? {
        let name = String::from_utf8_lossy(get_bytes(b)?).into_owned();
        let mut site = Site { streams: get_uv(b)?, ..Site::default() };
        for _ in 0..get_uv(b)? {
            let k = get_u8(b)? as usize;
            let (bytes, saved) = (get_uv(b)?, get_uv(b)?);
            if k < KINDS {
                site.bytes[k] = bytes;
                site.saved[k] = saved;
            }
        }
        out.insert(name, site);
    }
    Ok(out)
}

/// Tests that read the shared usage numbers hold this, so a test's reset can't clear another's sites.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Starts a new measurement: all sites and totals back to zero, "since" = now.
pub fn reset() {
    let mut s = SITES.lock().unwrap();
    s.sites.clear();
    s.minute.clear();
    TOTALS.reset();
}

/// A WhatsApp image shrunk before it went to the phone.
pub fn whatsapp_media(before: u64, after: u64) {
    TOTALS.add(&TOTALS.wa_before, before);
    TOTALS.add(&TOTALS.wa_after, after);
}

/// True if `host` should be logged at `now` (new, or last logged ≥ 10 min ago); records it.
fn due(logged: &mut HashMap<String, Instant>, host: &str, now: Instant) -> bool {
    logged.retain(|_, t| now.duration_since(*t) < SITE_QUIET);
    if logged.contains_key(host) {
        return false;
    }
    logged.insert(host.to_owned(), now);
    true
}

/// The phone reached `host` (`how`: http / https / https, decrypted / quic / tcp / udp).
pub fn site(host: &str, how: &str) {
    ACT.sites_now.lock().unwrap().insert(host.to_owned());
    if due(&mut ACT.logged.lock().unwrap(), host, Instant::now()) {
        log::info!("site {host} ({how})");
    }
}

/// A new TCP connection or UDP flow from the phone.
pub fn conn() {
    ACT.conns.fetch_add(1, Relaxed);
}

/// Bytes sent to (`down`) and received from (`up`) the phone.
pub fn bytes(down: u64, up: u64) {
    TOTALS.add(&TOTALS.web_down, down);
    ACT.down.fetch_add(down, Relaxed);
    ACT.up.fetch_add(up, Relaxed);
}

/// A web page (HTML) fetched for the phone.
pub fn page(method: &str, host: &str, path: &str, status: u16, len: Option<u64>) {
    let len = len.map_or_else(String::new, |n| format!(", {}", size(n)));
    log::info!("page {method} {host}{} → {status}{len}", short_path(path));
}

/// An image re-encoded for the phone.
pub fn image(host: &str, path: &str, from: &str, to: &str, before: u64, after: u64) {
    ACT.images.fetch_add(1, Relaxed);
    ACT.img_before.fetch_add(before, Relaxed);
    ACT.img_after.fetch_add(after, Relaxed);
    TOTALS.add(&TOTALS.img_before, before);
    TOTALS.add(&TOTALS.img_after, after);
    log::info!(
        "image {host}{}: {} {} → {} {} ({})",
        short_path(path),
        kind(from),
        size(before),
        kind(to),
        size(after),
        percent(before, after)
    );
}

/// Logs one summary line per minute, only for minutes with traffic.
pub async fn summary_task() {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Some(line) = take_minute() {
            log::info!("{line}");
        }
        save();
    }
}

fn take_minute() -> Option<String> {
    let a = &*ACT;
    let (conns, down, up) = (a.conns.swap(0, Relaxed), a.down.swap(0, Relaxed), a.up.swap(0, Relaxed));
    let (images, before, after) = (a.images.swap(0, Relaxed), a.img_before.swap(0, Relaxed), a.img_after.swap(0, Relaxed));
    let sites = std::mem::take(&mut *a.sites_now.lock().unwrap()).len();
    let minute = std::mem::take(&mut SITES.lock().unwrap().minute);
    if conns == 0 && down == 0 && up == 0 {
        return None;
    }
    let mut line = format!("last minute: {conns} connections, {sites} sites, ↓ {} ↑ {}", size(down), size(up));
    if images > 0 {
        line += &format!(", {images} images (−{})", size(before.saturating_sub(after)));
    }
    let mut top: Vec<_> = minute.into_iter().filter(|(_, n)| *n > 0).collect();
    top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    if !top.is_empty() {
        let t: Vec<String> = top.iter().take(3).map(|((site, k), n)| format!("{site} {} {}", k.name(), size(*n))).collect();
        line += &format!(" · top: {}", t.join(", "));
    }
    Some(line)
}

/// Path without query string or fragment, cut to 60 characters.
pub fn short_path(p: &str) -> String {
    let p = p.split(['?', '#']).next().unwrap_or("");
    if p.chars().count() > 60 { p.chars().take(59).chain(['…']).collect() } else { p.to_owned() }
}

/// "image/jpeg" → "jpeg"
fn kind(mime: &str) -> &str {
    mime.split(';').next().unwrap_or(mime).trim().rsplit('/').next().unwrap_or(mime)
}

pub fn size(n: u64) -> String {
    match n {
        0..1024 => format!("{n} B"),
        1024..1_048_576 => format!("{:.1} KB", n as f64 / 1024.0),
        _ => format!("{:.1} MB", n as f64 / 1_048_576.0),
    }
}

fn percent(before: u64, after: u64) -> String {
    if before == 0 {
        return "?".into();
    }
    let p = (after as f64 / before as f64 - 1.0) * 100.0;
    // one decimal near −100 %, so a 99.9 % saving doesn't read as "nothing left"
    let digits = if p.abs() >= 99.5 { 1 } else { 0 };
    if p < 0.0 { format!("−{:.*} %", digits, -p) } else { format!("+{p:.0} %") }
}

/// Wraps a site-side socket of a relayed (not decrypted) connection and counts what comes from the site.
pub struct Metered<S> {
    pub inner: S,
    pub host: String,
    pub kind: Kind,
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            add(&self.host, self.kind, n, 0);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps the phone's side of a connection and counts what passes through it.
pub struct Counted<S>(pub S);

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.0).poll_read(cx, buf);
        bytes(0, (buf.filled().len() - before) as u64);
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.0).poll_write(cx, b);
        if let Poll::Ready(Ok(n)) = r {
            bytes(n as u64, 0);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_are_logged_once_per_ten_minutes() {
        let mut m = HashMap::new();
        let t = Instant::now();
        assert!(due(&mut m, "a.com", t));
        assert!(!due(&mut m, "a.com", t + Duration::from_secs(300)));
        assert!(due(&mut m, "b.com", t + Duration::from_secs(300)));
        assert!(due(&mut m, "a.com", t + Duration::from_secs(601)));
    }

    #[test]
    fn kinds_and_domains() {
        assert_eq!(kind_of("video/mp4", "/x"), Kind::Video);
        assert_eq!(kind_of("application/vnd.apple.mpegURL", "/x"), Kind::Video);
        assert_eq!(kind_of("application/octet-stream", "/DASH_480.mp4?a=1"), Kind::Video);
        assert_eq!(kind_of("application/vnd.yt-ump", "/videoplayback?sabr=1"), Kind::Video);
        assert_eq!(kind_of("image/webp", "/"), Kind::Images);
        assert_eq!(kind_of("text/html; charset=utf-8", "/"), Kind::Pages);
        assert_eq!(kind_of("application/javascript", "/"), Kind::Scripts);
        assert_eq!(kind_of("font/woff2", "/"), Kind::Fonts);
        assert_eq!(kind_of("application/json", "/"), Kind::Data);
        assert_eq!(kind_of("", "/blob"), Kind::Other);
        assert_eq!(domain("cdn.example.com"), "example.com");
        assert_eq!(domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(domain("Old.Example.com:443"), "example.com");
        assert_eq!(domain("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(domain("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(domain("localhost"), "localhost");
    }

    #[test]
    fn usage_is_ranked_and_survives_a_restart() {
        let _l = TEST_LOCK.blocking_lock();
        add("v.usage-test.org", Kind::Video, 5 << 20, 0);
        add("i.usage-test.org", Kind::Images, 900 << 10, 3 << 20);
        stream("usage-test.org");
        add("small-usage-test.org", Kind::Scripts, 10, 0);
        let b = usage(usize::MAX);
        let mut rest = Totals::default().decode(&b);
        let sites = decode_sites(&mut rest).unwrap();
        let t = &sites["usage-test.org"];
        assert_eq!((t.bytes[Kind::Video as usize], t.saved[Kind::Images as usize], t.streams), (5 << 20, 3 << 20, 1));
        // ranked: the limit keeps the biggest
        let one = usage(1);
        let mut top = Totals::default().decode(&one);
        let top = decode_sites(&mut top).unwrap();
        assert_eq!(top.len(), 1);
        assert!(top.values().next().unwrap().total() >= t.total());
    }

    #[test]
    fn totals_add_up_and_survive_a_restart() {
        let t = Totals::default();
        t.add(&t.web_down, 5000);
        t.add(&t.img_before, 1000);
        t.add(&t.img_after, 100);
        assert!(t.since.load(Relaxed) > 0 && t.dirty.load(Relaxed));
        let again = Totals::default();
        again.decode(&t.encode());
        assert_eq!(again.encode(), t.encode());
        assert_eq!((again.web_down.load(Relaxed), again.img_before.load(Relaxed), again.img_after.load(Relaxed)), (5000, 1000, 100));
    }

    #[test]
    fn minute_summary() {
        conn();
        bytes(3 << 20, 2048);
        site("summary.test", "tcp");
        let line = take_minute().unwrap();
        assert!(line.starts_with("last minute: ") && line.contains("connections") && line.contains("sites"), "{line}");
    }

    #[test]
    fn formatting() {
        assert_eq!(short_path("/search?q=secret#x"), "/search");
        assert_eq!(short_path(&format!("/{}", "a".repeat(100))).chars().count(), 60);
        assert_eq!(kind("image/jpeg; charset=x"), "jpeg");
        assert_eq!((size(512), size(2048), size(3 << 20)), ("512 B".into(), "2.0 KB".into(), "3.0 MB".into()));
        assert_eq!(percent(1000, 50), "−95 %");
        assert_eq!(percent(100_000, 70), "−99.9 %");
        assert_eq!(percent(100, 120), "+20 %");
    }
}
