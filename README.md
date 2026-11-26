# squeezeVPN

Don't pay for what you don't need!
The purpose of this is to minimise the bandwidth of typical mobile subscriptions while keeping the essentials functioning.
Currently only android is supported as a client. It's entirely vibe coded and it works but don't count on this being secure.

## Messaging
- WhatsApp and Signal in one chat list: the server is a linked device and keeps your chats
- Custom UDP protocol: 17 bytes of overhead per packet, nothing sent unless you tap something
- Messages compressed with zstd against a dictionary trained on your chats plus the chat's recent history
- Media downloaded only on tap, recompressed on the server, with progress, opened in any app
- Sync over TCP when data is free (Wi-Fi): full history, new dictionary, key rotation
- Instant notifications while the VPN is on, muted chats stay silent

## VPN
- WireGuard, server side in userspace: no root, no TUN device, no iptables
- Choose which apps may use the network
- Per app: decrypt HTTPS to shrink it (🔓) or leave it untouched (🔒), so certificate-pinned apps keep working
- Images re-encoded as WebP, with sliders for quality and size and a live example picture
- Video speed limit, so adaptive players pick a lower quality
- Data usage per site and per kind of content, with what shrinking saved

## Build
- Server: `cd server && cargo build --release`, then `svpn init --endpoint <host>` and `svpn run`
- App: `cd android && ./gradlew assembleDebug`
