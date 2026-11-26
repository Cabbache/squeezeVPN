//! Userspace VPN endpoint, no root needed: WireGuard is decrypted with boringtun, the phone's TCP/UDP
//! flows are terminated by a userspace TCP/IP stack (ipstack) and re-opened from ordinary sockets.
//! No TUN device, no iptables, no ip_forward. Plain-HTTP (port 80) flows go to the image proxy, and
//! HTTPS (port 443) to `mitm.rs` once the phone has the CA installed, for apps set to decrypt.

use crate::activity;
use crate::app::ProxyCfg;
use crate::mitm::Mitm;
use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackUdpStream, TcpConfig, TcpOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

/// The phone's address inside the tunnel (see the Android `Interface` config).
pub const PHONE_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
/// Connections of apps the user set to "untouched" come from this address instead (the phone's
/// WireGuard library marks them, android/tunnel/tools/libwg-go/mark): relayed as is, never decrypted.
pub const PHONE_IP_PLAIN: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 3);
/// wireguard-android's default tunnel MTU.
const MTU: u16 = 1280;
/// Big enough for any IP packet plus WireGuard's 32-byte overhead.
const BUF: usize = 65_600;

/// ipstack's "network device": one IP packet per read / write, backed by channels.
struct PacketDev {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for PacketDev {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                let n = p.len().min(buf.remaining());
                buf.put_slice(&p[..n]);
                Poll::Ready(Ok(()))
            }
            // the sender lives as long as `serve`, so this only happens on shutdown
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketDev {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let _ = self.tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Destinations the phone may reach: public IPv4 only. Keeps the server's own localhost and LAN
/// (and cloud metadata at 169.254.169.254) out of reach. The phone has no IPv6 address.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && o[1] & 0xc0 == 64)) // CGNAT 100.64/10
        }
        IpAddr::V6(_) => false,
    }
}

pub async fn serve(
    sock: UdpSocket,
    key: StaticSecret,
    phone: PublicKey,
    proxy: Arc<RwLock<ProxyCfg>>,
    mitm: Option<Arc<Mitm>>,
    allow: fn(IpAddr) -> bool,
) -> Result<()> {
    let sock = Arc::new(sock);
    // No persistent keepalive: idle tunnel = 0 bytes.
    let tunn = Arc::new(Mutex::new(Tunn::new(key, phone, None, None, 0, None)));
    // Where the phone was last seen (it roams between networks); set only by authenticated packets.
    let endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::default();

    let (to_stack, stack_rx) = mpsc::channel(1024);
    let (stack_tx, mut from_stack) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut cfg = IpStackConfig::default();
    cfg.mtu(MTU)?;
    let mut tcp = TcpConfig::default();
    tcp.timeout = Duration::from_secs(2 * 3600); // idle TCP connections, like a NAT table entry
    tcp.options = Some(vec![TcpOptions::MaximumSegmentSize(MTU - 40)]);
    // ipstack resends a lost segment only 3 times (1+2+4 s) and then drops it but keeps the connection:
    // on lossy Wi-Fi/mobile the page then hangs until the user reloads. 8 tries = about 4 min, like real TCP.
    tcp.max_retransmit_count = 8;
    cfg.with_tcp_config(tcp);
    cfg.udp_timeout(Duration::from_secs(180));
    let mut stack = IpStack::new(cfg, PacketDev { rx: stack_rx, tx: stack_tx });

    // phone -> stack
    let (s, t, ep) = (sock.clone(), tunn.clone(), endpoint.clone());
    tokio::spawn(async move {
        let (mut buf, mut out) = (vec![0u8; BUF], vec![0u8; BUF]);
        let mut last_err_log: Option<std::time::Instant> = None;
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else { continue };
            let mut replies = Vec::new();
            {
                let mut t = t.lock().unwrap();
                let mut input = &buf[..n];
                loop {
                    match t.decapsulate(Some(from.ip()), input, &mut out) {
                        // handshake response, then any queued packets
                        TunnResult::WriteToNetwork(p) => replies.push(p.to_vec()),
                        TunnResult::WriteToTunnelV4(p, src) => {
                            set_endpoint(&ep, from);
                            if (src == PHONE_IP || src == PHONE_IP_PLAIN) && !p.is_empty() {
                                let _ = to_stack.try_send(p.to_vec()); // full queue = dropped packet
                            }
                            break;
                        }
                        TunnResult::WriteToTunnelV6(..) => {
                            set_endpoint(&ep, from);
                            break;
                        }
                        TunnResult::Err(e) => {
                            // at most every 10 s: someone else / an old phone key / stray packets
                            if last_err_log.is_none_or(|t| t.elapsed().as_secs() >= 10) {
                                last_err_log = Some(std::time::Instant::now());
                                log::warn!("wireguard {from}: packet rejected ({e:?}) — phone set up with an older QR?");
                            }
                            break;
                        }
                        TunnResult::Done => break,
                    }
                    input = &[];
                }
            }
            for r in replies {
                let _ = s.send_to(&r, from).await;
            }
        }
    });

    // stack -> phone
    let (s, t, ep) = (sock.clone(), tunn.clone(), endpoint.clone());
    tokio::spawn(async move {
        let mut out = vec![0u8; BUF];
        while let Some(pkt) = from_stack.recv().await {
            let msg = match t.lock().unwrap().encapsulate(&pkt, &mut out) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            };
            let to = *ep.lock().unwrap();
            if let (Some(m), Some(to)) = (msg, to) {
                let _ = s.send_to(&m, to).await;
            }
        }
    });

    // WireGuard timers (handshake retries/expiry). Only sends when WireGuard itself requires it.
    let (s, t, ep) = (sock.clone(), tunn.clone(), endpoint.clone());
    tokio::spawn(async move {
        let mut out = vec![0u8; BUF];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let msg = match t.lock().unwrap().update_timers(&mut out) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            };
            let to = *ep.lock().unwrap();
            if let (Some(m), Some(to)) = (msg, to) {
                let _ = s.send_to(&m, to).await;
            }
        }
    });

    loop {
        match stack.accept().await? {
            IpStackStream::Tcp(flow) => {
                let dst = flow.peer_addr();
                if !allow(dst.ip()) {
                    log::debug!("tunnel: refused tcp to {dst}");
                    continue;
                }
                activity::conn();
                let plain = flow.local_addr().ip() == IpAddr::V4(PHONE_IP_PLAIN);
                let mut flow = activity::Counted(flow);
                let proxy = proxy.clone();
                let route = tcp_route(dst.port(), plain, proxy.read().unwrap().https, mitm.is_some());
                if route == TcpRoute::Mitm && let Some(m) = &mitm {
                    tokio::spawn(m.clone().serve_conn(flow, dst, proxy));
                    continue;
                }
                tokio::spawn(async move {
                    match route {
                        TcpRoute::HttpProxy => crate::proxy::serve_conn(flow, dst, proxy).await,
                        TcpRoute::TlsRelay => {
                            // not decrypted: read the TLS hello only to learn the site's name, then relay as is
                            let Ok((hello, sni)) = crate::mitm::client_hello(&mut flow).await else { return };
                            let host = sni.unwrap_or_else(|| dst.ip().to_string());
                            activity::site(&host, if plain { "https, untouched: app setting" } else { "https" });
                            activity::stream(&host);
                            let flow = crate::mitm::Prefixed::new(hello, flow);
                            crate::mitm::relay(flow, dst, &host, activity::Kind::Encrypted).await
                        }
                        _ => {
                            let host = dst.ip().to_string();
                            activity::site(&dst.to_string(), if plain { "tcp, untouched: app setting" } else { "tcp" });
                            activity::stream(&host);
                            crate::mitm::relay(flow, dst, &host, activity::Kind::Tcp).await
                        }
                    }
                });
            }
            IpStackStream::Udp(flow) => {
                let dst = flow.peer_addr();
                // HTTP/3 can't be intercepted: dropping it makes browsers fall back to HTTPS over TCP.
                // Apps left untouched keep it.
                let plain = flow.local_addr().ip() == IpAddr::V4(PHONE_IP_PLAIN);
                if dst.port() == 443 && !plain && proxy.read().unwrap().https && mitm.is_some() {
                    continue;
                }
                if allow(dst.ip()) {
                    activity::conn();
                    let (host, kind) = match dst.port() {
                        53 => ("dns".to_owned(), activity::Kind::Dns), // the sites show up when they are visited
                        443 => (dst.ip().to_string(), activity::Kind::Quic),
                        _ => (dst.ip().to_string(), activity::Kind::Udp),
                    };
                    if kind != activity::Kind::Dns {
                        activity::site(&dst.to_string(), kind.name());
                    }
                    activity::stream(&host);
                    tokio::spawn(relay_udp(flow, dst, host, kind));
                } else {
                    log::debug!("tunnel: refused udp to {dst}");
                }
            }
            _ => {} // ICMP and other protocols are not forwarded
        }
    }
}

/// What happens to a TCP connection from the phone.
#[derive(Debug, PartialEq, Clone, Copy)]
enum TcpRoute {
    /// HTTPS decrypted by `mitm.rs` (images shrunk, video paced)
    Mitm,
    /// plain HTTP through `proxy.rs`
    HttpProxy,
    /// HTTPS relayed as is (the TLS hello is read for the site's name only)
    TlsRelay,
    /// any other TCP, relayed as is
    Relay,
}

/// `plain`: the connection comes from an app the user set to "untouched" (PHONE_IP_PLAIN).
fn tcp_route(port: u16, plain: bool, https: bool, have_mitm: bool) -> TcpRoute {
    match port {
        443 if !plain && https && have_mitm => TcpRoute::Mitm,
        443 => TcpRoute::TlsRelay,
        80 if !plain => TcpRoute::HttpProxy,
        _ => TcpRoute::Relay,
    }
}

/// One UDP flow (DNS, QUIC, …) relayed through an ordinary socket until ipstack's idle timeout ends it.
async fn relay_udp(mut flow: IpStackUdpStream, dst: SocketAddr, host: String, kind: activity::Kind) {
    let Ok(up) = UdpSocket::bind(if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await else { return };
    if up.connect(dst).await.is_err() {
        return;
    }
    let (mut a, mut b) = (vec![0u8; 65_536], vec![0u8; 65_536]);
    let (mut sent, mut got) = (0u64, 0u64);
    loop {
        tokio::select! {
            r = flow.read(&mut a) => match r {
                Ok(n) if n > 0 => {
                    sent += n as u64;
                    activity::bytes(0, n as u64);
                    let _ = up.send(&a[..n]).await;
                }
                _ => break,
            },
            r = up.recv(&mut b) => {
                // errors here are e.g. ICMP "port unreachable" from a previous datagram: keep going
                if let Ok(n) = r {
                    got += n as u64;
                    activity::bytes(n as u64, 0);
                    activity::add(&host, kind, n as u64, 0);
                    if flow.write(&b[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    log::debug!("udp {dst} closed: ↓ {} ↑ {}", activity::size(got), activity::size(sent));
}

/// Remembers where the phone sends from (replies go there) and logs when that changes.
fn set_endpoint(ep: &Mutex<Option<SocketAddr>>, from: SocketAddr) {
    if ep.lock().unwrap().replace(from) != Some(from) {
        log::info!("wireguard: phone connected from {from}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

    /// The phone side: its own boringtun peer, talking to `serve` over localhost UDP.
    struct Phone {
        t: Tunn,
        sock: UdpSocket,
        server: SocketAddr,
    }

    impl Phone {
        async fn start(allow: fn(IpAddr) -> bool) -> Phone {
            let (sk, pk) = (StaticSecret::random_from_rng(rand::rngs::OsRng), StaticSecret::random_from_rng(rand::rngs::OsRng));
            let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = server_sock.local_addr().unwrap();
            let proxy = Arc::new(RwLock::new(ProxyCfg { enabled: false, quality: 35, max_dim: 1280, https: false, video_kbps: 0 }));
            tokio::spawn(serve(server_sock, sk.clone(), PublicKey::from(&pk), proxy, None, allow));
            let t = Tunn::new(pk, PublicKey::from(&sk), None, None, 1, None);
            Phone { t, sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(), server }
        }

        async fn send_ip(&mut self, pkt: &[u8]) {
            let mut out = vec![0u8; BUF];
            if let TunnResult::WriteToNetwork(p) = self.t.encapsulate(pkt, &mut out) {
                self.sock.send_to(p, self.server).await.unwrap();
            }
        }

        /// Next IP packet from the server, completing the handshake on the way. None after `wait`.
        async fn recv_ip(&mut self, wait: Duration) -> Option<Vec<u8>> {
            let (mut buf, mut out) = (vec![0u8; BUF], vec![0u8; BUF]);
            loop {
                let (n, _) = tokio::time::timeout(wait, self.sock.recv_from(&mut buf)).await.ok()?.unwrap();
                let mut input = &buf[..n];
                loop {
                    match self.t.decapsulate(None, input, &mut out) {
                        TunnResult::WriteToNetwork(p) => self.sock.send_to(p, self.server).await.unwrap(),
                        TunnResult::WriteToTunnelV4(p, _) if !p.is_empty() => return Some(p.to_vec()),
                        _ => break,
                    };
                    input = &[];
                }
            }
        }

        async fn recv_tcp_payload(&mut self) -> Vec<u8> {
            loop {
                let p = self.recv_ip(Duration::from_secs(5)).await.expect("tcp data");
                if let Some(TransportSlice::Tcp(t)) = SlicedPacket::from_ip(&p).unwrap().transport
                    && !t.payload().is_empty()
                {
                    return t.payload().to_vec();
                }
            }
        }
    }

    fn udp(dst: SocketAddr, data: &[u8]) -> Vec<u8> {
        let IpAddr::V4(d) = dst.ip() else { unreachable!() };
        let mut v = Vec::new();
        PacketBuilder::ipv4(PHONE_IP.octets(), d.octets(), 64).udp(40000, dst.port()).write(&mut v, data).unwrap();
        v
    }

    fn tcp(dst: SocketAddr, build: impl FnOnce(etherparse::PacketBuilderStep<etherparse::TcpHeader>) -> etherparse::PacketBuilderStep<etherparse::TcpHeader>, seq: u32, data: &[u8]) -> Vec<u8> {
        let IpAddr::V4(d) = dst.ip() else { unreachable!() };
        let mut v = Vec::new();
        build(PacketBuilder::ipv4(PHONE_IP.octets(), d.octets(), 64).tcp(40001, dst.port(), seq, 65535)).write(&mut v, data).unwrap();
        v
    }

    // multi-threaded: ipstack blocks (block_in_place) when a TCP flow is dropped
    #[tokio::test(flavor = "multi_thread")]
    async fn udp_and_tcp_through_userspace_wireguard() {
        let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Info).try_init(); // `cargo test -- --nocapture` shows the log
        // local echo servers standing in for the internet
        let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = echo_udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo_udp.recv_from(&mut b).await {
                let _ = echo_udp.send_to(&b[..n], from).await;
            }
        });
        let echo_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = echo_tcp.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_tcp.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let mut phone = Phone::start(|_| true).await;

        // UDP: first packet also triggers the WireGuard handshake
        phone.send_ip(&udp(udp_addr, b"ping over udp")).await;
        let p = phone.recv_ip(Duration::from_secs(5)).await.expect("udp echo");
        let Some(TransportSlice::Udp(u)) = SlicedPacket::from_ip(&p).unwrap().transport else { panic!("not udp") };
        assert_eq!(u.payload(), b"ping over udp");
        assert_eq!(u.source_port(), udp_addr.port());

        // TCP: SYN -> SYN-ACK -> ACK + data -> echoed data
        phone.send_ip(&tcp(tcp_addr, |b| b.syn(), 1000, b"")).await;
        let synack = loop {
            let p = phone.recv_ip(Duration::from_secs(5)).await.expect("syn-ack");
            if let Some(TransportSlice::Tcp(t)) = SlicedPacket::from_ip(&p).unwrap().transport
                && t.syn()
                && t.ack()
            {
                assert_eq!(t.acknowledgment_number(), 1001);
                break t.sequence_number();
            }
        };
        phone.send_ip(&tcp(tcp_addr, |b| b.ack(synack + 1), 1001, b"")).await;
        phone.send_ip(&tcp(tcp_addr, |b| b.ack(synack + 1).psh(), 1001, b"hello over tcp")).await;
        assert_eq!(phone.recv_tcp_payload().await, b"hello over tcp");
    }

    // multi-threaded: ipstack blocks (block_in_place) when a TCP flow is dropped
    #[tokio::test(flavor = "multi_thread")]
    async fn local_destinations_are_refused() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });
        let mut phone = Phone::start(public).await;
        phone.send_ip(&udp(addr, b"let me in")).await;
        assert!(phone.recv_ip(Duration::from_secs(1)).await.is_none());

        assert!(public("1.1.1.1".parse().unwrap()));
        for ip in ["127.0.0.1", "10.8.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1"] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn untouched_apps_are_never_decrypted_or_proxied() {
        use TcpRoute::*;
        assert_eq!(tcp_route(443, false, true, true), Mitm);
        assert_eq!(tcp_route(443, true, true, true), TlsRelay);
        assert_eq!(tcp_route(443, false, false, true), TlsRelay); // interception switched off
        assert_eq!(tcp_route(80, false, true, true), HttpProxy);
        assert_eq!(tcp_route(80, true, true, true), Relay);
        assert_eq!(tcp_route(5222, false, true, true), Relay);
    }

    // multi-threaded: ipstack blocks (block_in_place) when a TCP flow is dropped
    #[tokio::test(flavor = "multi_thread")]
    async fn marked_address_is_served_and_answered() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });
        let mut phone = Phone::start(|_| true).await;
        let IpAddr::V4(d) = addr.ip() else { unreachable!() };
        for (src, ok) in [(PHONE_IP_PLAIN, true), (Ipv4Addr::new(10, 8, 0, 9), false)] {
            let mut v = Vec::new();
            PacketBuilder::ipv4(src.octets(), d.octets(), 64).udp(40000, addr.port()).write(&mut v, b"marked").unwrap();
            phone.send_ip(&v).await;
            let reply = phone.recv_ip(Duration::from_secs(if ok { 5 } else { 1 })).await;
            match reply {
                Some(p) => {
                    assert!(ok, "{src} must be dropped");
                    let s = SlicedPacket::from_ip(&p).unwrap();
                    let Some(etherparse::NetSlice::Ipv4(ip)) = s.net else { panic!("not ipv4") };
                    assert_eq!(ip.header().destination_addr(), src); // the reply goes back to the marked address
                }
                None => assert!(!ok, "no reply for {src}"),
            }
        }
    }
}
