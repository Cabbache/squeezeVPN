//! Transparent HTTP proxy for the phone's web traffic: plain HTTP (port 80) and, for apps set to
//! decrypt, HTTPS (see `mitm.rs`). The upstream is always the address the phone was
//! connecting to (never the Host header, so the tunnel's destination filter can't be bypassed).
//! JPEG/PNG/WebP responses are re-encoded (lossy WebP if the client accepts it, see `img.rs`);
//! everything else is streamed through untouched.

use crate::app::ProxyCfg;
use bytes::Bytes;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{
    ACCEPT, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, COOKIE, ETAG, EXPIRES, HOST, HeaderMap,
    HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, TE, TRANSFER_ENCODING, UPGRADE,
};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type Body = BoxBody<Bytes, hyper::Error>;
const MAX_IMAGE: u64 = 8 << 20;
/// Idle upstream connections kept per phone connection.
const POOL: usize = 6;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn status(code: StatusCode) -> Response<Body> {
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = code;
    r
}

/// Where requests of one phone connection go: HTTP/1.1 to `addr`, optionally over verified TLS.
/// Keeps a few idle connections for reuse (an HTTP/2 phone connection can have many requests at once).
pub struct Upstream {
    addr: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    idle: Mutex<Vec<SendRequest<Incoming>>>,
}

impl Upstream {
    pub fn plain(addr: SocketAddr) -> Upstream {
        Upstream { addr, tls: None, idle: Mutex::default() }
    }

    pub fn tls(addr: SocketAddr, connector: TlsConnector, name: ServerName<'static>) -> Upstream {
        Upstream { addr, tls: Some((connector, name)), idle: Mutex::default() }
    }

    /// Opens a new connection; for TLS this verifies the server certificate (fails if invalid).
    pub async fn open(&self) -> anyhow::Result<SendRequest<Incoming>> {
        let tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(self.addr)).await??;
        match &self.tls {
            None => handshake(tcp).await,
            Some((c, name)) => handshake(c.connect(name.clone(), tcp).await?).await,
        }
    }

    async fn sender(&self) -> anyhow::Result<SendRequest<Incoming>> {
        {
            let mut idle = self.idle.lock().unwrap();
            idle.retain(|s| !s.is_closed());
            if let Some(i) = idle.iter().position(|s| s.is_ready()) {
                return Ok(idle.swap_remove(i));
            }
        }
        self.open().await
    }

    /// Returns a connection for reuse (it becomes ready again once its response body is done).
    pub fn give_back(&self, s: SendRequest<Incoming>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < POOL {
            idle.push(s);
        }
    }
}

async fn handshake<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I) -> anyhow::Result<SendRequest<Incoming>> {
    let (sender, conn) = hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender)
}

/// Serves one plain-HTTP connection from the phone to `upstream`.
pub async fn serve_conn<I>(io: I, upstream: SocketAddr, cfg: Arc<RwLock<ProxyCfg>>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve(io, Arc::new(Upstream::plain(upstream)), cfg, true).await;
}

/// Serves HTTP/1.1 or HTTP/2 (auto-detected) from the phone; returns the number of requests handled.
/// `count_stream`: count the connection for its site at the first request (plain HTTP; for HTTPS
/// `mitm.rs` already counted it from the TLS hello).
pub async fn serve<I>(io: I, up: Arc<Upstream>, cfg: Arc<RwLock<ProxyCfg>>, count_stream: bool) -> usize
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let n = Arc::new(AtomicUsize::new(0));
    let count = n.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        if count.fetch_add(1, Ordering::Relaxed) == 0 && count_stream {
            let host = req.headers().get(HOST).and_then(|h| h.to_str().ok()).or(req.uri().host()).unwrap_or("?");
            crate::activity::stream(host);
        }
        handle(req, up.clone(), cfg.clone())
    });
    let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    // HTTP/2 to the phone: read at most this far ahead of what the phone has taken, per request. hyper's
    // default (~400 KB) lets a cancelled video request download that much for nothing.
    b.http2().max_send_buf_size(SEND_AHEAD);
    // large cookies exceed hyper's 16 KB default, which answers "431 Request Header Fields Too Large"
    b.http2().max_header_list_size(MAX_HEADERS);
    if let Err(e) = b
        .serve_connection_with_upgrades(TokioIo::new(io), svc)
        .await
    {
        log::debug!("proxy conn: {e}");
    }
    n.load(Ordering::Relaxed)
}

/// Largest request header block accepted from the phone (sites allow far more than hyper's 16 KB).
const MAX_HEADERS: u32 = 256 * 1024;

/// How much of a response may wait in the HTTP/2 send buffer for the phone (see `serve`).
const SEND_AHEAD: usize = 64 * 1024;

/// HTTP/2 requests from the phone are sent upstream as HTTP/1.1.
fn to_http1(req: &mut Request<Incoming>) {
    if req.version() == Version::HTTP_2 {
        if let Some(a) = req.uri().authority().and_then(|a| HeaderValue::from_str(a.as_str()).ok()) {
            req.headers_mut().entry(HOST).or_insert(a);
        }
        // HTTP/2 may split cookies into several headers; HTTP/1.1 needs one (RFC 9113 8.2.3)
        let cookies: Vec<&str> = req.headers().get_all(COOKIE).iter().filter_map(|v| v.to_str().ok()).collect();
        if cookies.len() > 1
            && let Ok(v) = HeaderValue::from_str(&cookies.join("; "))
        {
            req.headers_mut().insert(COOKIE, v);
        }
        req.headers_mut().remove(TE);
        *req.version_mut() = Version::HTTP_11;
    }
    if let Some(pq) = req.uri().path_and_query().and_then(|p| p.as_str().parse().ok()) {
        *req.uri_mut() = pq;
    }
}

async fn handle(mut req: Request<Incoming>, up: Arc<Upstream>, cfg: Arc<RwLock<ProxyCfg>>) -> Result<Response<Body>, hyper::Error> {
    to_http1(&mut req);
    let host = req.headers().get(HOST).and_then(|h| h.to_str().ok()).unwrap_or("?").to_owned();
    let (method, path) = (req.method().to_string(), req.uri().to_string());
    crate::activity::site(&host, if up.tls.is_some() { "https, decrypted" } else { "http" });
    let now = *cfg.read().unwrap();
    // The browser re-checks an image we shrank: keep its copy if it is at least as good as the current
    // settings (asking the site whether the image changed), otherwise fetch it again in full.
    let mut keep: Option<HeaderValue> = None;
    if let Some(t) = req.headers().get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()).and_then(Tag::find) {
        let h = req.headers_mut();
        h.remove(IF_NONE_MATCH);
        h.remove(IF_MODIFIED_SINCE);
        if t.at_least(&now) {
            match t.orig {
                Some(Validator::Etag(e)) => h.insert(IF_NONE_MATCH, e),
                Some(Validator::Modified(m)) => h.insert(IF_MODIFIED_SINCE, m),
                None => return Ok(not_modified(t.raw)),
            };
            keep = Some(t.raw);
        }
    }
    let webp_ok = req.headers().get(ACCEPT).and_then(|a| a.to_str().ok()).is_some_and(|a| a.contains("image/webp"));
    // WebSocket and other HTTP/1.1 upgrades: hand both connections over to a raw relay
    let phone_upgrade = req.headers().contains_key(UPGRADE).then(|| hyper::upgrade::on(&mut req));
    let mut sender = match up.sender().await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("proxy upstream {host}: {e:#}");
            return Ok(status(StatusCode::BAD_GATEWAY));
        }
    };
    let mut resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            log::debug!("proxy request {host}: {e}");
            return Ok(status(StatusCode::BAD_GATEWAY));
        }
    };
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(phone) = phone_upgrade {
            let server = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(a), Ok(b)) = (phone.await, server.await) {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b)).await;
                }
            });
        }
        return Ok(resp.map(|b| b.boxed()));
    }
    up.give_back(sender);
    if resp.status() == StatusCode::NOT_MODIFIED
        && let Some(tag) = keep
    {
        log::debug!("{method} {host}{path} → 304, cached copy kept");
        return Ok(not_modified(tag));
    }
    for h in [CONNECTION, TRANSFER_ENCODING, UPGRADE] {
        resp.headers_mut().remove(h);
    }
    resp.headers_mut().remove("keep-alive");
    let ctype = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let len = resp.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    log::debug!("{method} {host}{path} → {} {ctype} {}", resp.status().as_u16(), len.map_or("?".into(), crate::activity::size));
    if ctype.starts_with("text/html") {
        crate::activity::page(&method, &host, &path, resp.status().as_u16(), len);
    }

    let kind = crate::activity::kind_of(&ctype, &path);
    let cfg = now;
    if !cfg.enabled || !eligible(&resp) {
        let pace = if kind == crate::activity::Kind::Video && cfg.video_kbps > 0 {
            log::debug!("video {host}{} limited to {} kbit/s", crate::activity::short_path(&path), cfg.video_kbps);
            cfg.video_kbps as u64 * 1000 / 8
        } else {
            0
        };
        return Ok(resp.map(|b| MeteredBody::new(b, host.clone(), kind, pace).boxed()));
    }
    let (mut parts, body) = resp.into_parts();
    let orig = match collect_upto(body, MAX_IMAGE).await {
        Ok(Ok(b)) => b,
        // bigger than we re-encode (only possible without Content-Length): pass it on untouched
        Ok(Err((read, rest))) => {
            let body = MeteredBody::new(Replay { pre: Some(read), rest }, host, kind, 0);
            return Ok(Response::from_parts(parts, body.boxed()));
        }
        Err(_) => return Ok(status(StatusCode::BAD_GATEWAY)),
    };
    let out = match crate::img::shrink_async(orig.to_vec(), cfg.max_dim, cfg.quality, webp_ok).await {
        Ok(Some((small, mime))) => {
            crate::activity::image(&host, &path, &ctype, mime, orig.len() as u64, small.len() as u64);
            crate::activity::add(&host, crate::activity::Kind::Images, small.len() as u64, (orig.len() - small.len()) as u64);
            parts.headers.insert(CONTENT_TYPE, HeaderValue::from_static(mime));
            // The browser keeps it but re-checks before each use, so new settings take effect (see Tag).
            parts.headers.insert(ETAG, Tag::make(cfg.quality, cfg.max_dim, &parts.headers));
            parts.headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
            parts.headers.remove(LAST_MODIFIED);
            parts.headers.remove(EXPIRES);
            Bytes::from(small)
        }
        _ => {
            crate::activity::add(&host, crate::activity::Kind::Images, orig.len() as u64, 0);
            orig
        }
    };
    parts.headers.insert(CONTENT_LENGTH, out.len().into());
    Ok(Response::from_parts(parts, full(out)))
}

fn not_modified(tag: HeaderValue) -> Response<Body> {
    let mut r = status(StatusCode::NOT_MODIFIED);
    r.headers_mut().insert(ETAG, tag);
    r.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    r
}

/// The site's own validator of an image we shrank, carried inside our tag.
#[derive(Debug, PartialEq)]
enum Validator {
    Etag(HeaderValue),
    Modified(HeaderValue),
}

/// Our ETag on shrunk images: `W/"svpn-q<quality>-d<max side>-<site validator>"`. It records how the
/// browser's copy was made, so a re-check can tell whether it is as good as the current settings.
#[derive(Debug)]
struct Tag {
    q: u8,
    d: u32,
    orig: Option<Validator>,
    raw: HeaderValue,
}

impl Tag {
    fn make(q: u8, d: u32, site: &HeaderMap) -> HeaderValue {
        let orig = match (site.get(ETAG), site.get(LAST_MODIFIED)) {
            (Some(e), _) => format!("e{}", B64.encode(e.as_bytes())),
            (None, Some(m)) => format!("m{}", B64.encode(m.as_bytes())),
            _ => String::new(),
        };
        HeaderValue::from_str(&format!("W/\"svpn-q{q}-d{d}-{orig}\"")).expect("ascii")
    }

    /// Finds our tag in an If-None-Match header (which may list several tags).
    fn find(h: &str) -> Option<Tag> {
        h.split(',').find_map(|t| {
            let t = t.trim();
            let inner = t.trim_start_matches("W/").strip_prefix("\"svpn-q")?.strip_suffix('"')?;
            let (q, rest) = inner.split_once("-d")?;
            let (d, orig) = rest.split_once('-')?;
            let val = |s: &str| HeaderValue::from_bytes(&B64.decode(s).ok()?).ok();
            let orig = match orig.split_at_checked(1) {
                Some(("e", v)) => Some(Validator::Etag(val(v)?)),
                Some(("m", v)) => Some(Validator::Modified(val(v)?)),
                _ => None,
            };
            Some(Tag { q: q.parse().ok()?, d: d.parse().ok()?, orig, raw: HeaderValue::from_str(t).ok()? })
        })
    }

    /// Is the browser's copy at least as good as what the current settings would give?
    /// Shrinking switched off counts as full quality at original size.
    fn at_least(&self, now: &ProxyCfg) -> bool {
        let (q, d) = if now.enabled { (now.quality, now.max_dim) } else { (100, 0) };
        self.q >= q && (self.d == 0 || (d != 0 && self.d >= d))
    }
}

/// Reads a body up to `limit` bytes: `Ok(Ok(all))` if it ended within the limit, otherwise
/// `Ok(Err((read so far, rest)))` so it can still be passed on untouched.
async fn collect_upto<B>(mut body: B, limit: u64) -> Result<Result<Bytes, (Bytes, B)>, B::Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            buf.extend_from_slice(&data);
            if buf.len() as u64 > limit {
                return Ok(Err((buf.into(), body)));
            }
        }
    }
    Ok(Ok(buf.into()))
}

/// A response body that counts what goes to the phone for (site, kind) as it streams, so a long video
/// shows up in the usage numbers while it plays. With `pace` set (video), it also limits the speed:
/// video players measure how fast data arrives and pick a lower quality by themselves.
struct MeteredBody<B> {
    inner: B,
    host: String,
    kind: crate::activity::Kind,
    /// Speed limit in bytes/s, shared by all video (0 = none).
    pace: u64,
    /// Read from the site, not yet sent.
    rest: Bytes,
    /// A piece waiting for its turn, and the timer it waits on.
    due: Option<(Bytes, Pin<Box<tokio::time::Sleep>>)>,
}

impl<B> MeteredBody<B> {
    fn new(inner: B, host: String, kind: crate::activity::Kind, pace: u64) -> Self {
        MeteredBody { inner, host, kind, pace, rest: Bytes::new(), due: None }
    }
}

/// Paced data goes out in pieces of at most this size, so arrival is smooth for the player's measurement.
const PIECE: usize = 16 * 1024;
/// When the next video piece may go out: one clock for all video, so parallel streams share the limit.
static VIDEO_NEXT: Mutex<Option<tokio::time::Instant>> = Mutex::new(None);

/// Books `len` bytes at `rate` bytes/s on the shared video clock; returns when they may go out.
fn video_slot(len: usize, rate: u64) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    let mut next = VIDEO_NEXT.lock().unwrap();
    let at = next.map_or(now, |n| n.max(now));
    *next = Some(at + Duration::from_secs_f64(len as f64 / rate as f64));
    at
}

impl<B: hyper::body::Body<Data = Bytes> + Unpin> hyper::body::Body for MeteredBody<B> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = &mut *self;
        let out = |this: &MeteredBody<B>, piece: Bytes| {
            crate::activity::add(&this.host, this.kind, piece.len() as u64, 0);
            Poll::Ready(Some(Ok(Frame::data(piece))))
        };
        loop {
            if let Some((_, sleep)) = &mut this.due {
                std::task::ready!(std::future::Future::poll(sleep.as_mut(), cx));
                let (piece, _) = this.due.take().unwrap();
                return out(this, piece);
            }
            if !this.rest.is_empty() {
                let piece = this.rest.split_to(this.rest.len().min(PIECE));
                let at = video_slot(piece.len(), this.pace);
                if at <= tokio::time::Instant::now() {
                    return out(this, piece);
                }
                this.due = Some((piece, Box::pin(tokio::time::sleep_until(at))));
                continue;
            }
            match std::task::ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(f)) if this.pace > 0 && f.is_data() => this.rest = f.into_data().unwrap_or_default(),
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        crate::activity::add(&this.host, this.kind, d.len() as u64, 0);
                    }
                    return Poll::Ready(Some(Ok(f)));
                }
                other => return Poll::Ready(other),
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.rest.is_empty() && self.due.is_none() && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        let held = (self.rest.len() + self.due.as_ref().map_or(0, |d| d.0.len())) as u64;
        let h = self.inner.size_hint();
        let mut out = hyper::body::SizeHint::new();
        out.set_lower(h.lower() + held);
        if let Some(u) = h.upper() {
            out.set_upper(u + held);
        }
        out
    }
}

/// A body that first plays back bytes already read, then the rest of the original body.
struct Replay<B> {
    pre: Option<Bytes>,
    rest: B,
}

impl<B: hyper::body::Body<Data = Bytes> + Unpin> hyper::body::Body for Replay<B> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        if let Some(b) = self.pre.take() {
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }
}

/// Only complete, uncompressed JPEG/PNG/WebP responses, of bounded size if the size is announced
/// (streamed images without Content-Length are read up to the limit, see `collect_upto`).
fn eligible(r: &Response<Incoming>) -> bool {
    let h = r.headers();
    let image = |v: &str| {
        let v = v.trim().to_ascii_lowercase();
        ["image/jpeg", "image/png", "image/webp"].iter().any(|t| v.starts_with(t))
    };
    r.status() == StatusCode::OK
        && h.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(image)
        && !h.contains_key(CONTENT_ENCODING)
        && !h.contains_key(CONTENT_RANGE)
        && match h.get(CONTENT_LENGTH) {
            Some(v) => v.to_str().ok().and_then(|v| v.parse::<u64>().ok()).is_some_and(|n| n > 0 && n <= MAX_IMAGE),
            None => true,
        }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hyper::server::conn::http1;
    use tokio::net::TcpListener;

    /// Version of `/e.jpg` (its ETag is `"v<n>"`).
    static E_VERSION: AtomicUsize = AtomicUsize::new(1);

    /// A body sent in pieces without a known size (like a streaming CDN).
    struct Chunks(std::collections::VecDeque<Bytes>);

    impl hyper::body::Body for Chunks {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
        }
    }

    fn chunks(b: Vec<u8>) -> Chunks {
        let half = b.len() / 2;
        Chunks([Bytes::copy_from_slice(&b[..half]), Bytes::copy_from_slice(&b[half..])].into())
    }

    /// Test origin: `/a.jpg` is a JPEG, anything else a short text. Serves on any accepted stream.
    /// `/chunked.jpg` has no Content-Length; `/e.jpg` has an ETag and answers 304 to a matching If-None-Match.
    pub async fn origin<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I) {
        let svc = service_fn(|req: Request<Incoming>| async move {
            if req.uri().path() == "/chunked.jpg" {
                let body = chunks(crate::img::tests::sample_jpeg()).map_err(|never| match never {}).boxed();
                return Ok::<_, hyper::Error>(Response::builder().header(CONTENT_TYPE, "image/jpeg").body(body).unwrap());
            }
            if req.uri().path() == "/v.mp4" {
                let body = chunks(vec![7u8; 300_000]).map_err(|never| match never {}).boxed();
                return Ok(Response::builder().header(CONTENT_TYPE, "video/mp4").body(body).unwrap());
            }
            if req.uri().path() == "/big.mp4" {
                let pieces = (0..192).map(|_| Bytes::from(vec![9u8; 16 * 1024])).collect();
                let body = Chunks(pieces).map_err(|never| match never {}).boxed();
                return Ok(Response::builder().header(CONTENT_TYPE, "video/mp4").body(body).unwrap());
            }
            if req.uri().path() == "/e.jpg" {
                let etag = format!("\"v{}\"", E_VERSION.load(Ordering::SeqCst));
                let r = Response::builder().header(ETAG, &etag).header(CACHE_CONTROL, "max-age=31536000");
                if req.headers().get(IF_NONE_MATCH).is_some_and(|v| v.as_bytes() == etag.as_bytes()) {
                    return Ok(r.status(StatusCode::NOT_MODIFIED).body(full(Bytes::new())).unwrap());
                }
                let body = crate::img::tests::sample_jpeg();
                return Ok(r.header(CONTENT_TYPE, "image/jpeg").header(CONTENT_LENGTH, body.len()).body(full(body)).unwrap());
            }
            let (ct, body) = match req.uri().path() {
                "/a.jpg" => ("image/jpeg", crate::img::tests::sample_jpeg()),
                "/a.png" => ("image/png", crate::img::tests::sample_png(false)),
                "/a.webp" => ("image/webp", crate::img::tests::sample_webp()),
                _ => ("text/plain", b"hello world, untouched".to_vec()),
            };
            Ok::<_, hyper::Error>(Response::builder().header(CONTENT_TYPE, ct).header(CONTENT_LENGTH, body.len()).body(full(body)).unwrap())
        });
        let _ = http1::Builder::new().serve_connection(TokioIo::new(io), svc).await;
    }

    async fn upstream() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(origin(s));
            }
        });
        addr
    }

    /// GET over an HTTP/1.1 connection made on `io` (no Accept header, like a JPEG-only client).
    pub async fn get<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I, host: &str, path: &str) -> (Response<()>, Bytes) {
        get_accept(io, host, path, "*/*").await
    }

    pub async fn get_accept<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I, host: &str, path: &str, accept: &str) -> (Response<()>, Bytes) {
        get_with(io, host, path, &[("accept", accept)]).await
    }

    async fn get_with<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I, host: &str, path: &str, headers: &[(&str, &str)]) -> (Response<()>, Bytes) {
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.unwrap();
        tokio::spawn(conn);
        let mut req = Request::get(path).header(HOST, host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req.body(Full::new(Bytes::new())).unwrap();
        let resp = tx.send_request(req).await.unwrap();
        let (p, b) = resp.into_parts();
        (Response::from_parts(p, ()), b.collect().await.unwrap().to_bytes())
    }

    #[tokio::test]
    async fn proxies_and_shrinks_jpeg() {
        let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Info).try_init(); // `cargo test -- --nocapture` shows the log
        let up = upstream().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = l.local_addr().unwrap();
        let cfg = Arc::new(RwLock::new(ProxyCfg { enabled: true, quality: 30, max_dim: 320, https: false, video_kbps: 0 }));
        let c = cfg.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(serve_conn(s, up, c.clone()));
            }
        });
        let conn = || async { TcpStream::connect(proxy).await.unwrap() };
        let host = up.to_string();

        let (r, body) = get(conn().await, &host, "/t.txt").await;
        assert_eq!(&body[..], b"hello world, untouched");
        assert_eq!(r.headers()[CONTENT_LENGTH], "22");

        let orig = crate::img::tests::sample_jpeg();
        let (r, body) = get(conn().await, &host, "/a.jpg").await;
        assert!(body.len() < orig.len(), "{} !< {}", body.len(), orig.len());
        assert_eq!(r.headers()[CONTENT_LENGTH], body.len().to_string().as_str());
        assert_eq!(r.headers()[CONTENT_TYPE], "image/jpeg");
        let img = image::load_from_memory(&body).unwrap();
        assert_eq!(img.width(), 320);

        // a browser accepting WebP gets WebP for JPEG, PNG and WebP originals
        let browser = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8";
        for (path, orig) in [("/a.jpg", orig.clone()), ("/a.png", crate::img::tests::sample_png(false)), ("/a.webp", crate::img::tests::sample_webp())] {
            let (r, body) = get_accept(conn().await, &host, path, browser).await;
            assert_eq!(r.headers()[CONTENT_TYPE], "image/webp", "{path}");
            assert_eq!(r.headers()[CONTENT_LENGTH], body.len().to_string().as_str());
            assert!(body.len() < orig.len(), "{path}");
            assert_eq!(image::load_from_memory_with_format(&body, image::ImageFormat::WebP).unwrap().width(), 320);
        }

        cfg.write().unwrap().enabled = false;
        let (_, body) = get(conn().await, &host, "/a.jpg").await;
        assert_eq!(body.len(), orig.len());
    }

    /// Starts the proxy in front of the test origin; returns (proxy address, origin host, settings).
    async fn proxy_with(quality: u8, max_dim: u32) -> (SocketAddr, String, Arc<RwLock<ProxyCfg>>) {
        let up = upstream().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = Arc::new(RwLock::new(ProxyCfg { enabled: true, quality, max_dim, https: false, video_kbps: 0 }));
        let c = cfg.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(serve_conn(s, up, c.clone()));
            }
        });
        (addr, up.to_string(), cfg)
    }

    #[tokio::test]
    async fn streamed_images_without_size_are_shrunk() {
        let (proxy, host, _) = proxy_with(30, 320).await;
        let browser = "image/avif,image/webp,image/*,*/*;q=0.8";
        let (r, body) = get_accept(TcpStream::connect(proxy).await.unwrap(), &host, "/chunked.jpg", browser).await;
        assert_eq!(r.headers()[CONTENT_TYPE], "image/webp");
        assert_eq!(r.headers()[CONTENT_LENGTH], body.len().to_string().as_str());
        assert!(body.len() < crate::img::tests::sample_jpeg().len());
    }

    #[tokio::test]
    async fn too_big_bodies_are_passed_on_untouched() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let Ok(Err((read, rest))) = collect_upto(chunks(data.clone()), 100).await else { panic!("limit not hit") };
        assert!(read.len() > 100);
        let all = Replay { pre: Some(read), rest }.collect().await.unwrap().to_bytes();
        assert_eq!(&all[..], &data[..]);
        let Ok(Ok(small)) = collect_upto(chunks(data.clone()), 1 << 20).await else { panic!("limit hit") };
        assert_eq!(&small[..], &data[..]);
    }

    #[tokio::test]
    async fn cached_images_follow_the_settings() {
        let (proxy, host, cfg) = proxy_with(35, 320).await;
        let conn = || async { TcpStream::connect(proxy).await.unwrap() };
        let jpeg = [("accept", "*/*")];

        // first load: shrunk, tagged with the settings, re-checked before reuse
        let (r, body) = get_with(conn().await, &host, "/e.jpg", &jpeg).await;
        let tag35 = r.headers()[ETAG].to_str().unwrap().to_owned();
        assert!(tag35.starts_with("W/\"svpn-q35-d320-e"), "{tag35}");
        assert_eq!(r.headers()[CACHE_CONTROL], "private, no-cache");
        assert!(!body.is_empty());

        // same settings: keep the copy (site asked with its own ETag, answers 304)
        let (r, body) = get_with(conn().await, &host, "/e.jpg", &[("accept", "*/*"), ("if-none-match", &tag35)]).await;
        assert_eq!((r.status(), body.len()), (StatusCode::NOT_MODIFIED, 0));
        assert_eq!(r.headers()[ETAG], tag35.as_str());

        // higher quality: the cached copy is worse, so a new image comes
        cfg.write().unwrap().quality = 50;
        let (r, body) = get_with(conn().await, &host, "/e.jpg", &[("accept", "*/*"), ("if-none-match", &tag35)]).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(!body.is_empty());
        let tag50 = r.headers()[ETAG].to_str().unwrap().to_owned();
        assert!(tag50.starts_with("W/\"svpn-q50-"), "{tag50}");

        // lower quality: the better cached copy is kept
        cfg.write().unwrap().quality = 20;
        let (r, _) = get_with(conn().await, &host, "/e.jpg", &[("accept", "*/*"), ("if-none-match", &tag50)]).await;
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);

        // the site changed the image: a new one comes despite the good cached copy
        E_VERSION.store(2, Ordering::SeqCst);
        let (r, body) = get_with(conn().await, &host, "/e.jpg", &[("accept", "*/*"), ("if-none-match", &tag50)]).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(!body.is_empty());
        assert!(r.headers()[ETAG].to_str().unwrap().starts_with("W/\"svpn-q20-"));

        // shrinking off: every shrunk copy is worse than the original
        cfg.write().unwrap().enabled = false;
        let (r, body) = get_with(conn().await, &host, "/e.jpg", &[("accept", "*/*"), ("if-none-match", &tag50)]).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body.len(), crate::img::tests::sample_jpeg().len());
        assert_eq!(r.headers()[ETAG], "\"v2\"");

        // an image that doesn't get smaller keeps the site's own headers
        *cfg.write().unwrap() = ProxyCfg { enabled: true, quality: 100, max_dim: 0, https: false, video_kbps: 0 };
        let (r, _) = get_with(conn().await, &host, "/e.jpg", &jpeg).await;
        assert_eq!(r.headers()[ETAG], "\"v2\"");
        assert_eq!(r.headers()[CACHE_CONTROL], "max-age=31536000");
    }

    #[tokio::test]
    async fn usage_counts_video_and_shrunk_images_per_site() {
        let _l = crate::activity::TEST_LOCK.lock().await;
        let (proxy, host, _) = proxy_with(30, 320).await;
        let site = |_: &[u8]| site_kinds("127.0.0.1");
        let before = site(&crate::activity::usage(usize::MAX));
        let (_, body) = get(TcpStream::connect(proxy).await.unwrap(), &host, "/v.mp4").await;
        assert_eq!(body.len(), 300_000);
        get(TcpStream::connect(proxy).await.unwrap(), &host, "/a.jpg").await;
        let after = site(&crate::activity::usage(usize::MAX));
        let of = |v: &Vec<(u8, u64, u64)>, k: crate::activity::Kind| v.iter().find(|x| x.0 == k as u8).map_or((0, 0), |x| (x.1, x.2));
        let (v0, v1) = (of(&before, crate::activity::Kind::Video), of(&after, crate::activity::Kind::Video));
        assert!(v1.0 - v0.0 >= 300_000, "video counted while streaming: {v0:?} -> {v1:?}");
        let (i0, i1) = (of(&before, crate::activity::Kind::Images), of(&after, crate::activity::Kind::Images));
        assert!(i1.1 > i0.1, "image savings counted: {i0:?} -> {i1:?}");
    }

    /// (kind, bytes, saved) counted for `name` so far.
    fn site_kinds(name: &str) -> Vec<(u8, u64, u64)> {
        let b = crate::activity::usage(usize::MAX);
        let mut rest = &b[..];
        (0..6).for_each(|_| {
            get_uv_t(&mut rest);
        });
        let mut found = None;
        for _ in 0..get_uv_t(&mut rest) {
            let n = crate::wire::get_bytes(&mut rest).unwrap().to_vec();
            get_uv_t(&mut rest);
            let mut kinds = Vec::new();
            for _ in 0..get_uv_t(&mut rest) {
                kinds.push((crate::wire::get_u8(&mut rest).unwrap(), get_uv_t(&mut rest), get_uv_t(&mut rest)));
            }
            if n == name.as_bytes() {
                found = Some(kinds);
            }
        }
        found.unwrap_or_default()
    }

    fn video_bytes(name: &str) -> u64 {
        site_kinds(name).iter().find(|k| k.0 == crate::activity::Kind::Video as u8).map_or(0, |k| k.1)
    }

    /// The phone's side of a connection over a slow link: counts what is written, and takes no more
    /// than `cap` bytes (then writes wait, as when the phone doesn't read).
    struct SlowPhone<S> {
        inner: S,
        written: Arc<std::sync::atomic::AtomicU64>,
        cap: u64,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for SlowPhone<S> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for SlowPhone<S> {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
            let done = self.written.load(Ordering::SeqCst);
            if done >= self.cap {
                return Poll::Pending; // never woken: this link is stuck for the rest of the test
            }
            let b = &b[..b.len().min((self.cap - done) as usize)];
            let r = Pin::new(&mut self.inner).poll_write(cx, b);
            if let Poll::Ready(Ok(n)) = r {
                self.written.fetch_add(n as u64, Ordering::SeqCst);
            }
            r
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A video player cancels an HTTP/2 request over a slow link: what the server read ahead from the
    /// site but never sent must not be counted as sent to the phone.
    #[tokio::test]
    async fn cancelled_http2_streams_count_only_what_was_sent() {
        let _l = crate::activity::TEST_LOCK.lock().await;
        let up = upstream().await;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let w = written.clone();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let cfg = Arc::new(RwLock::new(ProxyCfg { enabled: true, quality: 30, max_dim: 320, https: false, video_kbps: 0 }));
            serve_conn(SlowPhone { inner: s, written: w, cap: 200_000 }, up, cfg).await;
        });
        let before = video_bytes("cancel.test");
        let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
        let (mut tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get("http://cancel.test/big.mp4").body(Full::new(Bytes::new())).unwrap();
        let mut body = tx.send_request(req).await.unwrap().into_body();
        let mut got = 0;
        while got < 50_000 {
            match body.frame().await {
                Some(Ok(f)) => got += f.data_ref().map_or(0, |d| d.len()),
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(body); // the player moves on: the stream is reset
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (counted, sent) = (video_bytes("cancel.test") - before, written.load(Ordering::SeqCst));
        assert!(got > 0 && sent <= 200_000);
        assert!(counted <= sent + 128 * 1024, "counted {counted} B for the site, but only {sent} B went to the phone");
    }

    /// Video is limited to the set speed, all video together; other content isn't slowed.
    #[tokio::test]
    async fn video_is_paced_and_shares_one_limit() {
        let (proxy, host, cfg) = proxy_with(30, 320).await;
        cfg.write().unwrap().video_kbps = 2400; // 300 KB/s
        let h = host.clone();
        let video = move || {
            let host = h.clone();
            async move {
                let t = tokio::time::Instant::now();
                let (r, body) = get(TcpStream::connect(proxy).await.unwrap(), &host, "/v.mp4").await;
                assert_eq!((r.status(), body.len()), (StatusCode::OK, 300_000));
                t.elapsed()
            }
        };
        let one = video().await;
        assert!(one >= Duration::from_millis(800), "300 KB at 300 KB/s took {one:?}");

        let v = video.clone();
        let both = tokio::spawn(async move { tokio::join!(v(), v()) });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = tokio::time::Instant::now();
        let (_, body) = get(TcpStream::connect(proxy).await.unwrap(), &host, "/t.txt").await;
        assert_eq!(&body[..], b"hello world, untouched");
        assert!(t.elapsed() < Duration::from_millis(300), "a page isn't slowed by video: {:?}", t.elapsed());
        let (a, b) = both.await.unwrap();
        assert!(a.max(b) >= Duration::from_millis(1700), "two videos share the limit: {a:?} {b:?}");

        cfg.write().unwrap().video_kbps = 0;
        let free = video().await;
        assert!(free < Duration::from_millis(500), "no limit: {free:?}");
    }

    fn get_uv_t(b: &mut &[u8]) -> u64 {
        crate::wire::get_uv(b).unwrap()
    }

    #[test]
    fn tags_round_trip() {
        let mut site = HeaderMap::new();
        site.insert(ETAG, HeaderValue::from_static("\"abc-1\""));
        let t = Tag::make(40, 1280, &site);
        let p = Tag::find(&format!("\"other\", {}", t.to_str().unwrap())).unwrap();
        assert_eq!((p.q, p.d, p.orig), (40, 1280, Some(Validator::Etag(HeaderValue::from_static("\"abc-1\"")))));
        let cfg = |quality, max_dim| ProxyCfg { enabled: true, quality, max_dim, https: false, video_kbps: 0 };
        let t = Tag::find(t.to_str().unwrap()).unwrap();
        assert!(t.at_least(&cfg(40, 1280)) && t.at_least(&cfg(20, 800)));
        assert!(!t.at_least(&cfg(41, 1280)) && !t.at_least(&cfg(40, 2000)) && !t.at_least(&cfg(40, 0)));
        assert!(Tag::find("\"v1\"").is_none());
    }
}
