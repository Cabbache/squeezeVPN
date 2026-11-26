//! HTTPS interception, once the CA is installed on the phone, and only for apps set to decrypt (the
//! others are marked by the phone and relayed untouched, see `tunnel.rs`). For each TLS connection to port 443:
//!  1. read the phone's ClientHello (keeping the raw bytes);
//!  2. no SNI, not TLS, or host on the passthrough list → relay the bytes untouched;
//!  3. connect to the same destination and verify its certificate against the Mozilla roots; if that
//!     fails the connection is closed — nothing unverified is ever served;
//!  4. answer the phone with a certificate for the SNI signed by our CA, and proxy HTTP/1.1 or HTTP/2
//!     through `proxy.rs`, which recompresses images;
//!  5. if the phone rejects our certificate (pinning, or the app ignores user CAs), the host is passed
//!     through untouched for 24 h, so the app's retry works. Pinning is never bypassed.

use crate::app::ProxyCfg;
use crate::proxy::{self, Upstream};
use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber};
use rustls::crypto::ring as provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::Digest;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskCx, Poll};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PASSTHROUGH_FOR: Duration = Duration::from_secs(24 * 3600);
const LEAF_DAYS: i64 = 30;

pub struct Mitm {
    /// Our CA certificate, for the phone to install.
    pub ca_der: Vec<u8>,
    server: Arc<ServerConfig>,
    client: TlsConnector,
    passthrough: Mutex<HashMap<String, Instant>>,
}

/// The Mozilla root store: upstream certificates are always verified against it.
pub fn web_roots() -> RootCertStore {
    RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

fn ca_params(key: &KeyPair) -> CertificateParams {
    let id = sha2::Sha256::digest(key.public_key_raw());
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("squeezeVPN CA {:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]));
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(3650);
    p
}

fn serial() -> SerialNumber {
    let mut b: [u8; 16] = rand::random();
    b[0] &= 0x7f;
    SerialNumber::from(b.to_vec())
}

/// Issues (and caches) leaf certificates for whatever host name the phone asks for.
struct Leaves {
    issuer: Issuer<'static, KeyPair>,
    key: KeyPair,
    signer: Arc<dyn SigningKey>,
    cache: Mutex<HashMap<String, (Instant, Arc<CertifiedKey>)>>,
}

impl std::fmt::Debug for Leaves {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Leaves")
    }
}

impl Leaves {
    fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some((t, c)) = self.cache.lock().unwrap().get(host)
            && t.elapsed() < Duration::from_secs(7 * 24 * 3600)
        {
            return Some(c.clone());
        }
        let mut p = CertificateParams::new(vec![host.to_owned()]).ok()?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        p.not_after = now + time::Duration::days(LEAF_DAYS);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.serial_number = Some(serial());
        let cert = p.signed_by(&self.key, &self.issuer).ok()?;
        // leaf only: a few hundred bytes on the phone link instead of a full public chain
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone()], self.signer.clone()));
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= 1000 {
            cache.clear();
        }
        cache.insert(host.to_owned(), (Instant::now(), ck.clone()));
        Some(ck)
    }
}

impl ResolvesServerCert for Leaves {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.get(hello.server_name()?)
    }
}

impl Mitm {
    /// Loads the CA from `data/ca.key` + `data/ca.der`, creating it on first use.
    pub fn load_or_create(data: &Path, upstream_roots: RootCertStore) -> Result<Mitm> {
        let (key_path, der_path) = (data.join("ca.key"), data.join("ca.der"));
        let key = if key_path.exists() {
            KeyPair::try_from(std::fs::read(&key_path)?).context("ca.key")?
        } else {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let key = KeyPair::generate()?;
            let ca = ca_params(&key).self_signed(&key)?;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_path)?.write_all(&key.serialize_der())?;
            std::fs::write(&der_path, ca.der())?;
            log::info!("created HTTPS interception CA in {}", data.display());
            key
        };
        let ca_der = std::fs::read(&der_path).context("ca.der")?;
        // the issuer's name comes from the stored certificate, not from ca_params(): leaves must name the
        // CA exactly as the phone has it installed, even if the name in ca_params() changes
        let issuer = Issuer::from_ca_cert_der(&ca_der.as_slice().into(), key).context("ca.der")?;

        let leaf_key = KeyPair::generate()?;
        let signer = provider::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))?;
        let leaves = Arc::new(Leaves { issuer, key: leaf_key, signer, cache: Mutex::default() });

        let p = Arc::new(provider::default_provider());
        let mut server = ServerConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(leaves);
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server.ticketer = provider::Ticketer::new()?; // resumption: fewer handshake bytes on the phone link
        let mut client = ClientConfig::builder_with_provider(p).with_safe_default_protocol_versions()?.with_root_certificates(upstream_roots).with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Mitm { ca_der, server: Arc::new(server), client: TlsConnector::from(Arc::new(client)), passthrough: Mutex::default() })
    }

    fn passed_through(&self, host: &str) -> bool {
        let mut p = self.passthrough.lock().unwrap();
        p.retain(|_, t| t.elapsed() < PASSTHROUGH_FOR);
        p.contains_key(host)
    }

    fn pass(&self, host: &str, why: &str) {
        log::info!("https {host}: not intercepted for 24 h ({why})");
        self.passthrough.lock().unwrap().insert(host.to_owned(), Instant::now());
    }

    pub async fn serve_conn<S>(self: Arc<Self>, mut flow: S, dst: SocketAddr, cfg: Arc<RwLock<ProxyCfg>>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Ok((hello, sni)) = client_hello(&mut flow).await else { return };
        let flow = Prefixed::new(hello, flow);
        let host = sni.clone().unwrap_or_else(|| dst.ip().to_string());
        crate::activity::stream(&host);
        let Some((sni, name)) = sni.filter(|s| !self.passed_through(s)).and_then(|s| Some((s.clone(), ServerName::try_from(s).ok()?)))
        else {
            crate::activity::site(&host, "https");
            return relay(flow, dst, &host, crate::activity::Kind::Encrypted).await;
        };
        // logged as "https, decrypted" by the proxy at the first request, once decryption actually works
        let up = Arc::new(Upstream::tls(dst, self.client.clone(), name));
        match up.open().await {
            Ok(s) => up.give_back(s),
            Err(e) => {
                log::warn!("https {sni}: upstream not verified, connection closed ({e:#})");
                return;
            }
        }
        let started = Instant::now();
        let tls = match TlsAcceptor::from(self.server.clone()).accept(flow).await {
            Ok(t) => t,
            Err(e) => return self.pass(&sni, &format!("phone rejected the certificate: {e}")),
        };
        if proxy::serve(tls, up, cfg, false).await == 0 && started.elapsed() < Duration::from_secs(2) {
            self.pass(&sni, "closed right after the handshake, probably certificate pinning");
        }
    }
}

/// Reads until a complete ClientHello; returns the raw bytes and the SNI (None if not TLS).
pub(crate) async fn client_hello<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<(Vec<u8>, Option<String>)> {
    let (mut acc, mut all, mut buf) = (Acceptor::default(), Vec::new(), [0u8; 4096]);
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await??;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        all.extend_from_slice(&buf[..n]);
        let mut rd = &buf[..n];
        while !rd.is_empty() {
            if acc.read_tls(&mut rd).is_err() {
                return Ok((all, None));
            }
        }
        match acc.accept() {
            Ok(Some(a)) => {
                let sni = a.client_hello().server_name().map(str::to_owned);
                return Ok((all, sni));
            }
            Ok(None) if all.len() < 64 * 1024 => {}
            _ => return Ok((all, None)),
        }
    }
}

/// Relays a connection untouched; what comes from the site counts as `kind` for `host` in the usage numbers.
pub(crate) async fn relay<S: AsyncRead + AsyncWrite + Unpin>(mut flow: S, dst: SocketAddr, host: &str, kind: crate::activity::Kind) {
    match tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(dst)).await {
        Ok(Ok(up)) => match tokio::io::copy_bidirectional(&mut flow, &mut crate::activity::Metered { inner: up, host: host.to_owned(), kind }).await {
            Ok((sent, got)) => log::debug!(
                "tcp {dst} closed: ↓ {} ↑ {}",
                crate::activity::size(got),
                crate::activity::size(sent)
            ),
            Err(e) => log::debug!("tcp {dst}: {e}"),
        },
        _ => log::debug!("tcp {dst}: cannot connect"),
    }
}

/// A stream that first replays bytes already read from it.
pub(crate) struct Prefixed<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(pre: Vec<u8>, inner: S) -> Self {
        Prefixed { pre, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let pos = self.pos;
            buf.put_slice(&self.pre[pos..pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::net::TcpListener;

    /// A fake HTTPS origin for `hosts`, with its own root (returned so tests can choose to trust it).
    async fn origin(hosts: &[&str]) -> (SocketAddr, RootCertStore) {
        let root_key = KeyPair::generate().unwrap();
        let root = ca_params(&root_key).self_signed(&root_key).unwrap();
        let issuer = Issuer::new(ca_params(&root_key), root_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap().signed_by(&leaf_key, &issuer).unwrap();
        let cfg = ServerConfig::builder_with_provider(Arc::new(provider::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()))
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let a = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(t) = a.accept(s).await {
                        proxy::tests::origin(t).await;
                    }
                });
            }
        });
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        (addr, roots)
    }

    fn connector(roots: RootCertStore, alpn: &[u8]) -> TlsConnector {
        let mut c = ClientConfig::builder_with_provider(Arc::new(provider::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = vec![alpn.to_vec()];
        TlsConnector::from(Arc::new(c))
    }

    /// The phone's side of one tunnel flow that `serve_conn` handles.
    fn flow(m: &Arc<Mitm>, dst: SocketAddr) -> tokio::io::DuplexStream {
        let (phone, server) = tokio::io::duplex(1 << 16);
        let cfg = Arc::new(RwLock::new(ProxyCfg { enabled: true, quality: 30, max_dim: 320, https: true, video_kbps: 0 }));
        tokio::spawn(m.clone().serve_conn(server, dst, cfg));
        phone
    }

    /// A CA created under an older name still signs leaves the phone accepts.
    #[tokio::test]
    async fn leaves_name_the_stored_ca_even_after_a_rename() {
        let dir = crate::store::tests::tmpdir("mitm-rename");
        let key = KeyPair::generate().unwrap();
        let mut old = ca_params(&key);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "oldname CA 01020304");
        old.distinguished_name = dn;
        let ca = old.self_signed(&key).unwrap();
        std::fs::write(dir.join("ca.key"), key.serialize_der()).unwrap();
        std::fs::write(dir.join("ca.der"), ca.der()).unwrap();
        let m = Mitm::load_or_create(&dir, web_roots()).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let (phone, server) = tokio::io::duplex(1 << 16);
        let acceptor = TlsAcceptor::from(m.server.clone());
        tokio::spawn(async move {
            let _ = acceptor.accept(server).await;
        });
        let name = rustls::pki_types::ServerName::try_from("img.test").unwrap();
        connector(roots, b"http/1.1").connect(name, phone).await.expect("phone trusts the leaf");
    }

    #[tokio::test]
    async fn intercepts_verifies_and_passes_pinned_hosts_through() {
        let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Info).try_init(); // `cargo test -- --nocapture` shows the log
        let dir = crate::store::tests::tmpdir("mitm");
        let (good, good_roots) = origin(&["img.test", "pin.test"]).await;
        let (bad, bad_roots) = origin(&["bad.test"]).await;
        let m = Arc::new(Mitm::load_or_create(&dir, good_roots.clone()).unwrap());
        let mut ours = RootCertStore::empty();
        ours.add(m.ca_der.clone().into()).unwrap();
        let orig = crate::img::tests::sample_jpeg();
        let name = |s: &str| ServerName::try_from(s.to_owned()).unwrap();

        // HTTP/1.1: JPEG shrunk, text untouched, our leaf-only certificate
        let t = connector(ours.clone(), b"http/1.1").connect(name("img.test"), flow(&m, good)).await.unwrap();
        assert_eq!(t.get_ref().1.peer_certificates().unwrap().len(), 1);
        let (_, body) = proxy::tests::get(t, "img.test", "/a.jpg").await;
        assert!(body.len() < orig.len());
        assert_eq!(image::load_from_memory(&body).unwrap().width(), 320);
        let t = connector(ours.clone(), b"http/1.1").connect(name("img.test"), flow(&m, good)).await.unwrap();
        assert_eq!(&proxy::tests::get(t, "img.test", "/t.txt").await.1[..], b"hello world, untouched");

        // HTTP/2 from the phone (sent upstream as HTTP/1.1)
        let t = connector(ours.clone(), b"h2").connect(name("img.test"), flow(&m, good)).await.unwrap();
        assert_eq!(t.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(t)).await.unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("https://img.test/a.png").header("accept", "image/webp,*/*").body(Empty::<Bytes>::new()).unwrap();
        let resp = tx.send_request(req).await.unwrap();
        assert_eq!(resp.headers()["content-type"], "image/webp");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.len() < crate::img::tests::sample_png(false).len());
        assert_eq!(image::guess_format(&body).unwrap(), image::ImageFormat::WebP);

        // upstream certificate not trusted by us → the phone gets nothing
        let r = connector(ours.clone(), b"http/1.1").connect(name("bad.test"), flow(&m, bad)).await;
        assert!(r.is_err());
        let _ = bad_roots;

        // an app that only trusts the real certificate (pinning / ignores user CAs): first connection
        // fails, then the host is passed through untouched with the origin's own certificate
        assert!(connector(good_roots.clone(), b"http/1.1").connect(name("pin.test"), flow(&m, good)).await.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = connector(good_roots, b"http/1.1").connect(name("pin.test"), flow(&m, good)).await.unwrap();
        assert_eq!(proxy::tests::get(t, "pin.test", "/a.jpg").await.1.len(), orig.len());

        // the CA survives a restart
        assert_eq!(Mitm::load_or_create(&dir, web_roots()).unwrap().ca_der, m.ca_der);
    }
}
