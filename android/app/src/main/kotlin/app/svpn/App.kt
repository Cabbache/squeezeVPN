package app.svpn

import android.app.Application
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import com.wireguard.crypto.Curve25519
import com.wireguard.crypto.KeyPair
import java.io.DataInputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors

/** Setup data from the server's provisioning QR: "svpn:" + base64url(...). */
class Provision(val host: String, val port: Int, val wgPort: Int, val clientWgPriv: ByteArray, val serverWgPub: ByteArray, val psk: ByteArray) {
    companion object {
        fun parse(text: String): Provision {
            val t = text.trim().removePrefix("svpn:")
            val rd = Rd(Base64.decode(t, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
            if (rd.u8() != 1) throw WireException("unknown provisioning format")
            val host = rd.str()
            val port = rd.uv().toInt()
            val wg = rd.uv().toInt()
            val b = rd.rest()
            if (b.size != 96) throw WireException("bad key material")
            return Provision(host, port, wg, b.copyOfRange(0, 32), b.copyOfRange(32, 64), b.copyOfRange(64, 96))
        }
    }
}

class App : Application() {
    companion object {
        lateinit var I: App
        private const val TX_BLOCK = 256L
        const val TAG = "svpn"
    }

    lateinit var prefs: SharedPreferences
    lateinit var store: PhoneStore
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    // counters shown in the UI (estimated on-the-wire bytes incl. 28 B IPv4/UDP headers)
    var bytesUp = 0L
    var bytesDown = 0L
    var waState = -1
    var sigState = -1
    var status = ""
    /** Did the server answer the last request? null = not tried yet. Drives the green/red "Server" pill. */
    var serverOk: Boolean? = null

    private var key = ByteArray(0)
    private var txNext = 0L
    private var txReserved = 0L
    private val rx = RxWindow()
    private var sock: DatagramSocket? = null

    override fun onCreate() {
        super.onCreate()
        I = this
        prefs = getSharedPreferences("svpn", MODE_PRIVATE)
        store = PhoneStore(filesDir)
        loadKeyState()
        bytesUp = prefs.getLong("bytes_up", 0)
        bytesDown = prefs.getLong("bytes_down", 0)
        store.chats.forEach { it.unread = prefs.getInt("unread_${it.idx}", 0) }
        // also when Android restarts the VPN in a new process without the app's screens
        Vpn.watchApps(this)
        // When no activity is visible, close the socket: no background traffic at all.
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            var started = 0
            override fun onActivityStarted(a: android.app.Activity) { started++ }
            override fun onActivityStopped(a: android.app.Activity) { if (--started == 0) closeSocket() }
            override fun onActivityCreated(a: android.app.Activity, b: android.os.Bundle?) {}
            override fun onActivityResumed(a: android.app.Activity) {}
            override fun onActivityPaused(a: android.app.Activity) {}
            override fun onActivitySaveInstanceState(a: android.app.Activity, b: android.os.Bundle) {}
            override fun onActivityDestroyed(a: android.app.Activity) {}
        })
    }

    val provisioned get() = prefs.contains("key")
    fun prov(): Provision = Provision.parse(prefs.getString("prov", "")!!)
    var dictId: Long
        get() = prefs.getLong("dict_id", 0)
        private set(v) { prefs.edit().putLong("dict_id", v).apply() }
    /** The Check cursor: the server's store head the phone has seen. */
    var since: Long
        get() = prefs.getLong("since", 0)
        private set(v) { prefs.edit().putLong("since", v).apply() }
    var autoRefreshSecs: Int
        get() = prefs.getInt("auto_refresh", 0)
        set(v) { prefs.edit().putInt("auto_refresh", v).apply() }
    var mediaMaxDim: Int
        get() = prefs.getInt("media_dim", 1280)
        set(v) { prefs.edit().putInt("media_dim", v).apply() }
    var mediaQuality: Int
        get() = prefs.getInt("media_q", 40)
        set(v) { prefs.edit().putInt("media_q", v).apply() }

    fun saveProvision(text: String) {
        val p = Provision.parse(text)
        prefs.edit()
            .putString("prov", text.trim())
            .putString("key", b64(p.psk))
            .putLong("tx_reserved", 0).putLong("rx_next", 0).putLong("rx_bitmap", 0)
            .putLong("dict_id", 0)
            .commit()
        loadKeyState()
    }

    /** "Remove server": disconnects the VPN and deletes the setup, keys, settings and downloaded chats.
     *  Runs on the network thread (via `bg`), which owns the socket. */
    fun forget() {
        if (Vpn.isUp) Vpn.down(this)
        sock?.close()
        sock = null
        prefs.edit().clear().commit()
        listOf("chats", "dicts", "media").forEach { File(filesDir, it).deleteRecursively() }
        filesDir.listFiles()?.filter { it.isFile }?.forEach { it.delete() }
        store = PhoneStore(filesDir)
        loadKeyState()
        bytesUp = 0
        bytesDown = 0
        waState = -1
        sigState = -1
        status = ""
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

    // The key state is shared by the UDP requests and the push session thread (Push.kt).
    @Synchronized
    private fun loadKeyState() {
        key = prefs.getString("key", null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: ByteArray(0)
        txReserved = prefs.getLong("tx_reserved", 0)
        txNext = txReserved // never reuse a packet number after a restart
        rx.next = prefs.getLong("rx_next", 0)
        rx.bitmap = prefs.getLong("rx_bitmap", 0)
    }

    @Synchronized
    private fun nextPn(): Long {
        if (txNext >= txReserved) {
            txReserved = txNext + TX_BLOCK
            prefs.edit().putLong("tx_reserved", txReserved).commit() // must hit disk before use
        }
        return txNext++
    }

    @Synchronized
    private fun seal(pt: ByteArray) = Crypto.seal(key, T.DIR_C2S, nextPn(), pt)

    @Synchronized
    private fun open(pkt: ByteArray): ByteArray? {
        val (pn, pt) = rx.open(key, T.DIR_S2C, pkt) ?: return null
        rx.accept(pn)
        prefs.edit().putLong("rx_next", rx.next).putLong("rx_bitmap", rx.bitmap).apply()
        return pt
    }

    // ------------------------------------------------------------ threading --

    /** Runs network work off the UI thread; `done` runs on the UI thread. */
    fun <R> bg(work: () -> R, done: (Result<R>) -> Unit) {
        io.execute {
            val r = runCatching(work)
            prefs.edit().putLong("bytes_up", bytesUp).putLong("bytes_down", bytesDown).apply()
            ui { done(r) }
        }
    }

    /** Media downloads in progress: seq -> percent. Kept here so a chat opened again still shows them. */
    val downloads = java.util.concurrent.ConcurrentHashMap<Long, Int>()
    /** Redraws the chat on show when a download moves on (set by ChatActivity while visible). */
    var onDownloads: (() -> Unit)? = null

    /** Runs [media] on its own thread; `done` runs on the UI thread. */
    fun bgMedia(seq: Long, done: (Result<File>) -> Unit) {
        downloads[seq] = 0
        Thread({
            val r = runCatching { media(seq) { p -> downloads[seq] = p; ui { onDownloads?.invoke() } } }
            downloads.remove(seq)
            prefs.edit().putLong("bytes_up", bytesUp).putLong("bytes_down", bytesDown).apply()
            ui { onDownloads?.invoke(); done(r) }
        }, "svpn-media").apply { isDaemon = true }.start()
    }

    /** Posts to the UI thread. A UI error must not crash the process: the VPN runs in it too. */
    private fun ui(block: () -> Unit) {
        main.post { try { block() } catch (e: Exception) { Log.w(TAG, "ui callback failed", e) } }
    }

    /** Closes the UDP socket (app left the foreground): nothing is sent until the user acts again. */
    fun closeSocket() = io.execute { sock?.close(); sock = null }

    // ------------------------------------------------------------- UDP core --

    private fun socket(): DatagramSocket = sock ?: DatagramSocket().also { sock = it }

    /**
     * Sends one request and feeds decrypted replies to `onReply` until it returns
     * true or no packet arrives for `quietMs`. Returns true if `onReply` finished.
     */
    private fun request(pt: ByteArray, quietMs: Int = 1500, onReply: (ByteArray) -> Boolean): Boolean {
        val p = prov()
        val s = socket()
        val buf = ByteArray(65536)
        // drop stale replies of earlier requests
        s.soTimeout = 1
        try { while (true) s.receive(DatagramPacket(buf, buf.size)) } catch (_: SocketTimeoutException) {}
        val pkt = seal(pt)
        s.send(DatagramPacket(pkt, pkt.size, InetSocketAddress(p.host, p.port)))
        bytesUp += pkt.size + 28
        Log.i(TAG, "-> type ${type(pt)}, ${pkt.size} B to ${p.host} udp/${p.port}")
        s.soTimeout = quietMs
        while (true) {
            val dp = DatagramPacket(buf, buf.size)
            try { s.receive(dp) } catch (_: SocketTimeoutException) {
                Log.w(TAG, "no reply within $quietMs ms")
                return false
            }
            bytesDown += dp.length + 28
            val r = open(buf.copyOf(dp.length))
            if (r == null) {
                Log.w(TAG, "<- ${dp.length} B that don't decrypt (server set up again? scan its new QR)")
                continue
            }
            Log.i(TAG, "<- type ${type(r)}, ${dp.length} B")
            serverOk = true
            if (onReply(r)) return true
        }
    }

    /** The error shown when the server stays silent: says where we sent to and what usually causes it. */
    private fun noAnswer(): WireException {
        serverOk = false
        val p = prov()
        return WireException(
            "no answer from ${p.host} (UDP port ${p.port}). Is `svpn run` running there, and is udp/${p.port} " +
                "open in the server's firewall? If the server was set up again, scan its new QR."
        )
    }

    private fun type(pt: ByteArray) = (pt[0].toInt() and 0xff) ushr 3
    private fun codec(pt: ByteArray) = pt[0].toInt() and 7

    private fun errText(code: Int) = when (code) {
        2 -> "media not available"
        3 -> "WhatsApp / Signal offline on the server"
        4 -> "server doesn't know our dictionary — run Sync"
        5 -> "unknown chat"
        else -> "bad request"
    }

    private fun synced(): ByteArray = store.dict(dictId) ?: ByteArray(0)

    // ----------------------------------------------------------- operations --

    /** CHECK: which chats have new messages. Returns chats with news. */
    fun check(): Int {
        val known = store.chats.size
        val q = Buf().u8(T.hdr(T.CHECK, 0)).uv(dictId).uv(since).uv(known).toBytes()
        repeat(3) {
            var news = -1
            var err: String? = null
            request(q) { r ->
                when (type(r)) {
                    T.SUMMARY -> {
                        val body = Z.unpack(codec(r), r.copyOfRange(1, r.size), Z.buildDict(synced(), store.namesTable(known)), 1 shl 20)
                        val rd = Rd(body)
                        val head = rd.uv()
                        setStates(rd.u8())
                        val n = rd.uv().toInt()
                        repeat(n) {
                            val chat = rd.uv().toInt()
                            val count = rd.uv().toInt()
                            if (chat >= known) store.setName(chat, rd.str(), rd.u8())
                            store.chats.getOrNull(chat)?.let { c -> c.unread += count; saveUnread(c) }
                        }
                        since = head
                        news = n
                        true
                    }
                    T.ERR -> { err = errText(Rd(r, 1).u8()); true }
                    else -> false
                }
            }
            err?.let { throw WireException(it) }
            if (news >= 0) return news
        }
        throw noAnswer()
    }

    /** WhatsApp's and Signal's state, from one byte (T.WA_*). */
    private fun setStates(b: Int) {
        val (wa, sig) = T.states(b)
        waState = wa
        sigState = sig
    }

    private fun saveUnread(c: PChat) = prefs.edit().putInt("unread_${c.idx}", c.unread).apply()

    /**
     * FETCH: new messages of one chat. Returns true if the server has more
     * (UI shows "Load more"). With `all`, keeps going until everything arrived.
     */
    fun fetch(c: PChat, all: Boolean = false): Boolean {
        var attempts = 0
        while (attempts < 4) {
            val q = Buf().u8(T.hdr(T.FETCH, 0)).uv(dictId).uv(c.idx).uv(c.pos.seq).toBytes()
            val pending = HashMap<Long, ByteArray>()
            var err: String? = null
            var finished = false
            var more = false
            val startSeq = c.pos.seq
            request(q) { r ->
                when (type(r)) {
                    T.RECORDS -> {
                        val rd = Rd(r, 1)
                        if (rd.uv().toInt() == c.idx) pending[rd.uv()] = r
                        // apply every packet whose predecessor we have
                        while (true) {
                            val p = pending.remove(c.pos.seq) ?: break
                            val prd = Rd(p, 1)
                            prd.uv(); prd.uv()
                            val flags = prd.u8()
                            val recs = Z.unpack(codec(p), prd.rest(), Z.buildDict(synced(), c.stream), 1 shl 22)
                            store.append(c, recs)
                            if (flags and 1 == 1) { finished = true; more = flags and 2 == 2 }
                        }
                        finished
                    }
                    T.ERR -> { err = errText(Rd(r, 1).u8()); true }
                    else -> false
                }
            }
            err?.let { throw WireException(it) }
            if (finished) {
                c.unread = 0
                saveUnread(c)
                if (more && all) { attempts = 0; continue }
                return more
            }
            if (c.pos.seq == startSeq) attempts++ // no progress: count as a failed try
        }
        throw WireException("fetch incomplete, try again")
    }

    /** SEND a text; the server's reply lets us append the record locally (no echo over the air). */
    fun send(c: PChat, text: String) {
        val cid = prefs.getLong("client_id", 0) + 1
        prefs.edit().putLong("client_id", cid).commit()
        val cursor = c.pos.seq
        val (codec, z) = Z.pack(text.toByteArray(), Z.buildDict(synced(), c.stream))
        val q = Buf().u8(T.hdr(T.SEND, codec)).uv(cid).uv(dictId).uv(c.idx).uv(cursor).raw(z).toBytes()
        repeat(4) {
            var err: String? = null
            var sent: LongArray? = null
            request(q, 3000) { r ->
                val rd = Rd(r, 1)
                when (type(r)) {
                    T.SENT -> if (rd.uv() == cid) { sent = longArrayOf(rd.uv(), rd.uv(), unzz(rd.uv())); true } else false
                    T.ERR -> { val code = rd.u8(); if (rd.uv() == cid || code == 1) { err = errText(code); true } else false }
                    else -> false
                }
            }
            err?.let { throw WireException(it) }
            sent?.let { (seq, prev, ts) ->
                if (prev == c.pos.seq) {
                    val b = Buf()
                    ChatPos(c.pos.seq, c.pos.ts, c.pos.senders).encode(Record.Msg(seq, 0, ts, T.KIND_TEXT, text, 0), b)
                    store.append(c, b.toBytes())
                }
                return
            }
        }
        throw noAnswer()
    }

    /**
     * MEDIA: downloads (recompressed) media in chunks, asking again for lost ones. Call it from its own
     * thread ([bgMedia]), not from `io`: each round is one task on `io`, so Check, Send and Data usage
     * get through between rounds of a long download.
     */
    fun media(seq: Long, progress: (Int) -> Unit = {}): File {
        val f = store.mediaFile(seq)
        if (f.exists()) return f
        val chunks = HashMap<Long, ByteArray>()
        var total = -1L
        var idle = 0
        var shown = -1
        while (total < 0 || chunks.size.toLong() < total) {
            val (from, count) = nextRange(chunks.keys, total)
            val q = Buf().u8(T.hdr(T.MEDIA, 0)).uv(seq).uv(mediaMaxDim).u8(mediaQuality).uv(from).uv(count).toBytes()
            val before = chunks.size
            var err: String? = null
            // the first reply waits for the server to fetch the file from WhatsApp/Signal; after that, a
            // round ends as soon as its chunks are in (a lost one ends it after 700 ms of quiet)
            try { io.submit {
                request(q, if (total < 0) 30_000 else 700) { r ->
                    val rd = Rd(r, 1)
                    when (type(r)) {
                        T.CHUNK -> if (rd.uv() == seq) {
                            val idx = rd.uv()
                            total = rd.uv()
                            chunks[idx] = rd.rest()
                            (from until from + count).all { it >= total || it in chunks }
                        } else false
                        T.ERR -> { val code = rd.u8(); if (rd.uv() == seq) { err = errText(code); true } else false }
                        else -> false
                    }
                }
            }.get() } catch (e: java.util.concurrent.ExecutionException) { throw e.cause ?: e }
            err?.let { throw WireException(it) }
            if (chunks.size == before) {
                if (total < 0 && ++idle >= 2) throw noAnswer()
                if (total >= 0 && ++idle >= 5) throw WireException("download stalled")
            } else idle = 0
            if (total > 0) {
                val pct = (chunks.size * 100 / total).toInt()
                if (pct != shown) { shown = pct; progress(pct) }
            }
        }
        val tmp = File(f.path + ".part")
        tmp.outputStream().use { o -> (0L until total).forEach { o.write(chunks[it]!!) } }
        tmp.renameTo(f)
        return f
    }

    /** PROXY_CFG: image settings of the server's web proxy; `https` = decrypt HTTPS (needed to shrink
     *  images and limit video there); `videoKbps` = video speed limit (0 = none). */
    fun proxyCfg(enabled: Boolean, quality: Int, maxDim: Int, https: Boolean, videoKbps: Int) {
        val cid = prefs.getLong("client_id", 0) + 1
        prefs.edit().putLong("client_id", cid).commit()
        val q = Buf().u8(T.hdr(T.PROXY_CFG, 0)).uv(cid).u8(if (enabled) 1 else 0).u8(quality).uv(maxDim)
            .u8(if (https) 1 else 0).uv(videoKbps).toBytes()
        repeat(3) {
            if (request(q) { r -> type(r) == T.ACK && Rd(r, 1).uv() == cid }) return
        }
        throw noAnswer()
    }

    /** Has the bell turned this chat's notifications off? */
    fun muted(c: PChat) = prefs.getBoolean("muted_${c.idx}", false)

    /** MUTE: the bell. The server keeps it, so muted chats don't send notifications at all. */
    fun mute(c: PChat, muted: Boolean) {
        val cid = prefs.getLong("client_id", 0) + 1
        prefs.edit().putLong("client_id", cid).commit()
        val q = Buf().u8(T.hdr(T.MUTE, 0)).uv(cid).uv(c.idx).u8(if (muted) 1 else 0).toBytes()
        repeat(3) {
            if (request(q) { r -> type(r) == T.ACK && Rd(r, 1).uv() == cid }) {
                prefs.edit().putBoolean("muted_${c.idx}", muted).apply()
                return
            }
        }
        throw noAnswer()
    }

    /** What one site sent to the phone since the last reset: bytes and shrinking savings per kind. */
    class SiteUse(val name: String, val streams: Long, val kinds: List<Triple<String, Long, Long>>) {
        val total get() = kinds.sumOf { it.second }
    }

    /** "Data usage": totals since the last reset (`since` in unix seconds) and the biggest sites. */
    class Usage(
        val since: Long, val webDown: Long, val imgBefore: Long, val imgAfter: Long, val waBefore: Long, val waAfter: Long,
        val sites: List<SiteUse>,
    ) {
        val saved get() = (imgBefore - imgAfter).coerceAtLeast(0) + (waBefore - waAfter).coerceAtLeast(0)
    }

    private val KIND_NAMES = arrayOf("video", "audio", "images", "pages", "scripts", "styles", "fonts", "data", "other",
        "encrypted", "quic", "dns", "tcp", "udp")

    /** USAGE: one small request; `reset` starts a new measurement after this reply. */
    fun usage(reset: Boolean): Usage {
        val q = Buf().u8(T.hdr(T.USAGE, 0)).u8(if (reset) 1 else 0).toBytes()
        var u: Usage? = null
        repeat(3) {
            if (request(q) { r ->
                    (type(r) == T.USAGE_REPLY).also {
                        if (!it) return@also
                        val body = Z.unpack(codec(r), r.copyOfRange(1, r.size), Z.buildDict(ByteArray(0), ByteArray(0)), 1 shl 20)
                        val rd = Rd(body)
                        val t = LongArray(6) { rd.uv() }
                        val sites = (0 until rd.uv()).map {
                            val name = rd.str()
                            val streams = rd.uv()
                            val kinds = (0 until rd.uv()).map {
                                val k = rd.u8()
                                Triple(KIND_NAMES.getOrElse(k) { "other" }, rd.uv(), rd.uv())
                            }
                            SiteUse(name, streams, kinds)
                        }
                        u = Usage(t[0], t[1], t[2], t[3], t[4], t[5], sites)
                    }
                }) return u!!
        }
        throw noAnswer()
    }

    /** CA: the server's HTTPS-interception CA certificate (DER), over the authenticated channel. */
    fun caCert(): ByteArray {
        var der: ByteArray? = null
        val q = Buf().u8(T.hdr(T.CA, 0)).toBytes()
        repeat(3) {
            if (request(q) { r -> (type(r) == T.CA_CERT).also { if (it) der = r.copyOfRange(1, r.size) } }) {
                prefs.edit().putString("ca_der", b64(der!!)).apply()
                return der!!
            }
        }
        throw noAnswer()
    }

    /** True if the user installed our CA (it shows up as a "user:" entry in Android's CA store). */
    fun caInstalled(): Boolean? {
        val der = prefs.getString("ca_der", null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        return try {
            val ks = java.security.KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            ks.aliases().toList().any { it.startsWith("user:") && ks.getCertificate(it)?.encoded?.contentEquals(der) == true }
        } catch (_: Exception) {
            false
        }
    }

    /** Adds to the ↑↓ counters from another thread (push session). */
    @Synchronized
    fun countBytes(up: Int, down: Int) {
        bytesUp += up
        bytesDown += down
    }

    // ------------------------------------------------------------ TCP frames --

    /** Sends one sealed frame (varint length + packet) on the TCP port (Sync, push sessions). */
    fun sendFrame(out: java.io.OutputStream, pt: ByteArray) {
        val pkt = seal(pt)
        synchronized(out) { out.write(Buf().uv(pkt.size).raw(pkt).toBytes()); out.flush() }
    }

    /** Reads and opens one frame from the TCP port. */
    fun recvFrame(input: DataInputStream): ByteArray {
        var len = 0L
        var shift = 0
        while (true) {
            val b = input.readUnsignedByte()
            len = len or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 35) throw WireException("bad frame length")
        }
        if (len > 32L shl 20) throw WireException("frame too large")
        val f = ByteArray(len.toInt())
        input.readFully(f)
        return open(f) ?: throw WireException("bad frame")
    }

    // ----------------------------------------------------------------- Sync --

    /**
     * Sync over TCP (for free data): rotate the key, receive the full history of
     * every chat and a dictionary trained on all chats. `progress` gets status lines.
     */
    fun sync(progress: (String) -> Unit) {
        val p = prov()
        Socket().use { s ->
            try {
                s.connect(InetSocketAddress(p.host, p.port), 10_000)
            } catch (e: java.io.IOException) {
                serverOk = false
                throw WireException("can't reach ${p.host} on TCP port ${p.port} for Sync (${e.message}). Is `svpn run` running, and is tcp/${p.port} open in the server's firewall?")
            }
            s.soTimeout = 120_000
            val input = DataInputStream(s.getInputStream().buffered())
            val out = s.getOutputStream()
            fun send(pt: ByteArray) = sendFrame(out, pt)
            fun recv(): ByteArray = recvFrame(input)

            progress("rotating key…")
            val kp = KeyPair()
            send(byteArrayOf(T.hdr(T.SYNC_HELLO, 0).toByte()) + kp.publicKey.bytes)
            val hello = recv()
            if (type(hello) != T.SYNC_HELLO || hello.size != 33) throw WireException("bad hello")
            val dh = ByteArray(32)
            Curve25519.eval(dh, 0, kp.privateKey.bytes, hello.copyOfRange(1, 33))
            val newKey = Crypto.rotate(key, dh)
            // persist the new key with fresh counters before using it
            prefs.edit().putString("key", b64(newKey)).putLong("tx_reserved", 0).putLong("rx_next", 0).putLong("rx_bitmap", 0).commit()
            loadKeyState()

            val cur = Buf().u8(T.hdr(T.SYNC_CURSORS, 0)).uv(store.chats.size)
            store.chats.forEach { cur.uv(it.idx).uv(it.pos.seq) }
            send(cur.toBytes())

            var newDict = dictId
            while (true) {
                val f = recv()
                val rd = Rd(f, 1)
                when (type(f)) {
                    T.SYNC_CHAT -> {
                        val idx = rd.uv().toInt()
                        val name = rd.str()
                        val service = rd.u8()
                        val base = rd.uv()
                        store.setName(idx, name, service)
                        val c = store.chats.getOrNull(idx) ?: continue
                        val recs = rd.rest()
                        if (base == 0L) store.replace(c, recs) else if (base == c.pos.seq) store.append(c, recs)
                        progress("chat ${idx + 1}: ${c.name} (${c.msgs.size} messages)")
                    }
                    T.SYNC_DICT -> {
                        newDict = rd.uv()
                        val d = rd.rest()
                        if (newDict != 0L && store.dict(newDict) == null) store.saveDict(newDict, d)
                        progress("dictionary v$newDict (${d.size / 1024} KiB)")
                    }
                    T.SYNC_DONE -> {
                        since = rd.uv()
                        setStates(rd.u8())
                        dictId = newDict
                        serverOk = true
                        store.chats.forEach { it.unread = 0; saveUnread(it) }
                        progress("synced ${store.chats.size} chats, dictionary v$newDict")
                        return
                    }
                    else -> throw WireException("unexpected sync frame")
                }
            }
        }
    }
}
