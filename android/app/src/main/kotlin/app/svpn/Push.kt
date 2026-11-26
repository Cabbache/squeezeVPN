package app.svpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Real-time message notifications while the VPN is on: one quiet TCP connection to the server (a push
 * session) for WhatsApp and Signal. The server writes a few bytes the moment a message arrives that
 * would notify (not in a chat muted in WhatsApp or with the bell in our app). Runs in the app process,
 * which Android keeps alive for the VPN, so there is no extra background service or permanent notification. A ping about every 9 minutes keeps the carrier's NAT
 * entry alive; Android lets that alarm fire even in deep sleep.
 */
object Push {
    private const val TAG = "svpn"
    private const val PING_EVERY = 9 * 60_000L
    private const val PONG_WAIT = 20_000L
    /** Estimated TCP/IP header bytes per frame, for the ↑↓ counters. */
    private const val TCP_OVERHEAD = 40

    /** Is the push session connected? Drives the green/red dot in VPN & settings. */
    @Volatile var connected = false
        private set
    @Volatile private var running = false
    @Volatile private var sock: Socket? = null
    @Volatile private var out: OutputStream? = null
    @Volatile private var lastPong = 0L
    /** The services the open session asked for (PUSH_HELLO bits). */
    @Volatile private var asked = 0
    private var net: Network? = null
    private var netCb: ConnectivityManager.NetworkCallback? = null
    private val wake = Object()
    private var kicked = false

    private fun pref(service: Int) = if (service == T.SERVICE_SIGNAL) "notify_signal" else "notify_whatsapp"

    /** The setting for one service (on by default). */
    fun enabled(service: Int) = App.I.prefs.getBoolean(pref(service), true)

    fun setEnabled(ctx: Context, service: Int, on: Boolean) {
        App.I.prefs.edit().putBoolean(pref(service), on).apply()
        update(ctx)
    }

    /** Is the service used on the server (state unknown counts as used)? */
    fun used(service: Int) = (if (service == T.SERVICE_SIGNAL) App.I.sigState else App.I.waState) != T.WA_OFF

    /** PUSH_HELLO bits: the services that are used and switched on. */
    private fun services() = listOf(T.SERVICE_WHATSAPP, T.SERVICE_SIGNAL).filter { used(it) && enabled(it) }.sumOf { 1 shl it }

    /** Starts or stops the session to match the VPN state and the settings. */
    @Synchronized
    fun update(ctx: Context) {
        val want = Vpn.isUp && App.I.provisioned && services() != 0
        if (want && !running) start(ctx.applicationContext)
        else if (!want && running) stop(ctx.applicationContext)
        else if (running && connected && asked != services()) kick() // reconnect asking for the new set
    }

    private fun start(ctx: Context) {
        running = true
        Thread({ loop(ctx) }, "svpn-push").apply { isDaemon = true; start() }
        // a new network (Wi-Fi <-> mobile) means a new address: reconnect right away
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) {
                val old = net
                net = n
                if (old != null && old != n) kick()
            }
        }
        try {
            ctx.getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(cb)
            netCb = cb
        } catch (e: Exception) {
            Log.w(TAG, "push: can't watch network changes (${e.message}); reconnects take longer")
        }
        schedulePing(ctx)
    }

    private fun stop(ctx: Context) {
        running = false
        kick()
        netCb?.let { ctx.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        netCb = null
        net = null
        ctx.getSystemService(AlarmManager::class.java).cancel(pingIntent(ctx))
        connected = false
    }

    /** Drops the connection (the loop reconnects at once, if still running). */
    private fun kick() {
        try { sock?.close() } catch (_: Exception) {}
        synchronized(wake) { kicked = true; wake.notifyAll() }
    }

    private fun loop(ctx: Context) {
        var backoff = 2_000L
        while (running) {
            val began = SystemClock.elapsedRealtime()
            try {
                session(ctx)
            } catch (e: Exception) {
                if (running) Log.i(TAG, "push: disconnected (${e.message})")
            }
            connected = false
            if (!running) break
            if (SystemClock.elapsedRealtime() - began > 60_000) backoff = 2_000L // it had been working
            synchronized(wake) {
                if (!kicked) wake.wait(backoff) else backoff = 2_000L
                kicked = false
            }
            backoff = (backoff * 2).coerceAtMost(5 * 60_000L)
        }
    }

    private fun session(ctx: Context) {
        val p = App.I.prov()
        Socket().use { s ->
            sock = s
            s.connect(InetSocketAddress(p.host, p.port), 10_000)
            val o = s.getOutputStream()
            out = o
            val input = DataInputStream(s.getInputStream().buffered())
            // ask for what we haven't seen: notifications missed while disconnected come first
            val since = maxOf(App.I.since, App.I.prefs.getLong("push_seq", 0))
            asked = services()
            send(o, Buf().u8(T.hdr(T.PUSH_HELLO, 0)).u8(asked).uv(since).toBytes())
            connected = true
            Log.i(TAG, "push: connected to ${p.host}:${p.port}")
            while (true) {
                val pt = App.I.recvFrame(input)
                App.I.countBytes(0, pt.size + 17 + 2 + TCP_OVERHEAD)
                when ((pt[0].toInt() and 0xff) ushr 3) {
                    T.PUSH -> onPush(ctx, PushMsg.decode(pt))
                    T.PONG -> lastPong = SystemClock.elapsedRealtime()
                }
            }
        }
    }

    private fun send(o: OutputStream, pt: ByteArray) {
        App.I.sendFrame(o, pt)
        App.I.countBytes(pt.size + 17 + 2 + TCP_OVERHEAD, 0)
    }

    private fun onPush(ctx: Context, m: PushMsg) {
        val prefs = App.I.prefs
        if (m.seq <= prefs.getLong("push_seq", 0)) return // already shown
        prefs.edit().putLong("push_seq", m.seq).apply()
        val wl = ctx.getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "svpn:push")
        wl.acquire(10_000)
        Log.i(TAG, "push: message in chat ${m.chat}")
        // one Check brings the unread counts and new chat names up to date, as in the app
        App.I.bg({ App.I.check() }) {
            val unread = App.I.store.chats.getOrNull(m.chat)?.unread ?: 0
            Notify.post(ctx, m, unread)
            if (wl.isHeld) wl.release()
        }
    }

    private fun pingIntent(ctx: Context) =
        PendingIntent.getBroadcast(ctx, 0, Intent(ctx, PingReceiver::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun schedulePing(ctx: Context) {
        ctx.getSystemService(AlarmManager::class.java)
            .setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + PING_EVERY, pingIntent(ctx))
    }

    /** Keepalive (from the alarm): ping, and reconnect if no pong comes back within 20 s. */
    fun ping(ctx: Context) {
        if (!running) return
        schedulePing(ctx)
        val o = out
        if (!connected || o == null) return kick()
        val wl = ctx.getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "svpn:ping")
        wl.acquire(PONG_WAIT + 5_000)
        Thread {
            val sent = SystemClock.elapsedRealtime()
            try {
                send(o, byteArrayOf(T.hdr(T.PING, 0).toByte()))
                while (lastPong < sent && SystemClock.elapsedRealtime() - sent < PONG_WAIT) Thread.sleep(250)
                if (lastPong < sent) {
                    Log.i(TAG, "push: no answer to ping, reconnecting")
                    kick()
                }
            } catch (e: Exception) {
                kick()
            } finally {
                if (wl.isHeld) wl.release()
            }
        }.start()
    }
}

/** The keepalive alarm. */
class PingReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) = Push.ping(ctx.applicationContext)
}
