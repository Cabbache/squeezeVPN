package app.svpn

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ListView
import android.widget.Switch

/** Chat list. Nothing goes over the network unless the user taps something
 *  (or explicitly set an auto-refresh interval in settings). */
class MainActivity : Activity() {
    private lateinit var adapter: ListAdapter<PChat>
    private val status by lazy { label() }
    private val serverDot by lazy { status("Server") }
    private val waDot by lazy { status("WhatsApp") }
    private val sigDot by lazy { status("Signal") }
    private val vpnDot by lazy { status("VPN") }
    private val empty by lazy { label("No chats yet — tap Check for new messages", 16f) }
    private lateinit var free: Switch
    private var bothServices = false
    private val handler = Handler(Looper.getMainLooper())
    private val autoCheck = object : Runnable {
        override fun run() {
            check(quiet = true)
            App.I.autoRefreshSecs.takeIf { it > 0 }?.let { handler.postDelayed(this, it * 1000L) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        adapter = ListAdapter(this, App.I.store.chats) { c ->
            val last = c.msgs.lastOrNull()?.let { m -> " — " + (m.text.ifEmpty { "[${T.KIND_NAMES.getOrElse(m.kind) { "media" }}]" }).take(40) } ?: ""
            val text = (if (c.unread > 0) "● ${c.name} (${c.unread} new)" else c.name) + last
            // with chats from both services, a small grey S or W tells them apart
            if (!bothServices) text else android.text.SpannableString((if (c.service == T.SERVICE_SIGNAL) "S  " else "W  ") + text).apply {
                setSpan(android.text.style.ForegroundColorSpan(0xFF9E9E9E.toInt()), 0, 1, 0)
            }
        }
        val list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            // the list is sorted newest first: open the chat by its own index, not the list position
            setOnItemClickListener { _, _, i, _ ->
                startActivity(Intent(this@MainActivity, ChatActivity::class.java).putExtra("chat", this@MainActivity.adapter.items[i].idx))
            }
        }
        free = Switch(this).apply {
            text = "Free data — Sync"
            isChecked = App.I.prefs.getBoolean("free", false)
            setOnCheckedChangeListener { _, on ->
                App.I.prefs.edit().putBoolean("free", on).apply()
                if (on) sync()
            }
        }
        show(vbox(
            row(serverDot, waDot, sigDot, vpnDot),
            status,
            hbox(button("Check for new messages") { check(quiet = false) }, button("VPN & settings") {
                startActivity(Intent(this, VpnActivity::class.java))
            }),
            button("Data usage") { startActivity(Intent(this, UsageActivity::class.java)) },
            free,
            empty,
            list.also { it.layoutParams = weight() },
        ))
    }

    override fun onResume() {
        super.onResume()
        if (!App.I.provisioned) {
            startActivity(Intent(this, SetupActivity::class.java))
            return
        }
        refresh()
        App.I.autoRefreshSecs.takeIf { it > 0 }?.let { handler.postDelayed(autoCheck, it * 1000L) }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(autoCheck)
    }

    private fun refresh() {
        val a = App.I
        serverDot.dot(a.serverOk?.let { if (it) Col.OK else Col.BAD })
        waDot.dot(if (a.waState < 0) null else if (a.waState == T.WA_CONNECTED) Col.OK else Col.BAD)
        waDot.visibility = if (a.waState == T.WA_OFF) android.view.View.GONE else android.view.View.VISIBLE
        sigDot.dot(if (a.sigState < 0) null else if (a.sigState == T.WA_CONNECTED) Col.OK else Col.BAD)
        // Signal appears once the server says it is used (WhatsApp shows until the server says it isn't)
        sigDot.visibility = if (a.sigState < 0 || a.sigState == T.WA_OFF) android.view.View.GONE else android.view.View.VISIBLE
        bothServices = a.store.chats.map { it.service }.distinct().size > 1
        vpnDot.dot(Vpn.state(this).first)
        status.text = "↑ ${fmtBytes(a.bytesUp)}  ↓ ${fmtBytes(a.bytesDown)}" + (if (a.status.isNotEmpty()) "  ·  ${a.status}" else "")
        adapter.items = a.store.chats.sortedByDescending { it.msgs.lastOrNull()?.seq ?: 0 }
        adapter.notifyDataSetChanged()
        empty.visibility = if (adapter.items.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
    }

    private fun check(quiet: Boolean) {
        App.I.bg({ App.I.check() }) { r ->
            r.onSuccess { n -> if (!quiet) toast(if (n == 0) "nothing new" else "$n chat(s) with new messages") }
            r.onFailure { if (!quiet) fail(it) }
            refresh()
        }
    }

    private fun sync() {
        App.I.status = "syncing…"
        refresh()
        App.I.bg({ App.I.sync { line -> runOnUiThread { App.I.status = line; refresh() } } }) { r ->
            r.onFailure {
                App.I.status = "sync failed: ${it.message}"
                free.isChecked = false // the switch shows a Sync in progress / free-data mode, not a failed one
                fail(it)
            }
            refresh()
        }
    }
}
