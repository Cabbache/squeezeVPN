package app.svpn

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Bundle
import android.widget.EditText
import android.widget.ImageView
import android.widget.ListView
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One conversation. "Fetch" pulls only this chat; media is downloaded only when tapped. */
class ChatActivity : Activity() {
    private lateinit var chat: PChat
    private lateinit var adapter: ListAdapter<Record.Msg>
    private lateinit var fetchBtn: android.widget.Button
    private val fmt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.ROOT)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        chat = App.I.store.chats[intent.getIntExtra("chat", 0)]
        title = chat.name
        adapter = ListAdapter(this, chat.msgs) { m ->
            val who = chat.senderName(m.sender)
            val body = if (m.kind == T.KIND_TEXT) m.text else {
                val have = App.I.store.mediaFile(m.seq).exists()
                "[${T.KIND_NAMES.getOrElse(m.kind) { "media" }} ${fmtBytes(m.mediaSize)}] ${m.text}" +
                    when {
                        have -> " — tap to open"
                        App.I.downloads.containsKey(m.seq) -> " — ${App.I.downloads[m.seq]}%"
                        else -> " — tap to download"
                    }
            }
            "${fmt.format(Date(m.ts * 1000))}  $who\n$body"
        }
        val list = ListView(this).apply {
            this.adapter = this@ChatActivity.adapter
            transcriptMode = ListView.TRANSCRIPT_MODE_NORMAL
            setOnItemClickListener { _, _, i, _ -> this@ChatActivity.adapter.items[i].takeIf { it.kind != T.KIND_TEXT }?.let(::download) }
        }
        val input = EditText(this).apply { hint = "message" }
        fetchBtn = button("") { fetch() }
        // the bell: this chat's notifications on/off (kept on the server)
        val bell = button(bellText()) {}
        bell.setOnClickListener {
            val muted = !App.I.muted(chat)
            bell.isEnabled = false
            App.I.bg({ App.I.mute(chat, muted) }) { r ->
                bell.isEnabled = true
                r.onFailure { toast("not changed: ${it.message}") }
                bell.text = bellText()
            }
        }
        show(vbox(
            android.widget.LinearLayout(this).apply {
                gravity = android.view.Gravity.CENTER_VERTICAL
                addView(label(chat.name, 20f).apply { setTypeface(typeface, android.graphics.Typeface.BOLD) }, android.widget.LinearLayout.LayoutParams(0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(bell)
            },
            fetchBtn,
            list.also { it.layoutParams = weight() },
            hbox(input, button("Send") {
                val text = input.text.toString().trim()
                if (text.isEmpty()) return@button
                App.I.bg({ App.I.send(chat, text) }) { r ->
                    r.onSuccess { input.setText("") }.onFailure { fail(it) }
                    refresh()
                }
            }),
        ))
        refresh()
        list.setSelection(adapter.count - 1)
    }

    private fun bellText() = if (App.I.muted(chat)) "🔕" else "🔔"

    override fun onResume() {
        super.onResume()
        Notify.visibleChat = chat.idx
        Notify.cancel(this, chat.idx)
        App.I.onDownloads = { adapter.notifyDataSetChanged() }
        adapter.notifyDataSetChanged() // a download may have moved on or finished while away
    }

    override fun onPause() {
        super.onPause()
        Notify.visibleChat = -1
        App.I.onDownloads = null
    }

    private fun refresh(more: Boolean = false) {
        fetchBtn.text = when {
            more -> "Load more"
            chat.unread > 0 -> "Fetch ${chat.unread} new message(s)"
            else -> "Fetch new messages"
        }
        adapter.items = chat.msgs
        adapter.notifyDataSetChanged()
    }

    private fun fetch() {
        val all = App.I.prefs.getBoolean("free", false)
        App.I.bg({ App.I.fetch(chat, all) }) { r ->
            r.onFailure { fail(it) }
            refresh(r.getOrDefault(false))
        }
    }

    private fun download(m: Record.Msg) {
        App.I.downloads[m.seq]?.let { return toast("downloading $it%") }
        if (!App.I.store.mediaFile(m.seq).exists()) toast("downloading…")
        App.I.bgMedia(m.seq) { r ->
            r.onFailure { fail(it) }
            r.onSuccess { f -> if (alive()) open(m, f) }
        }
        adapter.notifyDataSetChanged()
    }

    /** Images in a dialog; videos, audio and documents in the app Android picks for them. */
    private fun open(m: Record.Msg, f: File) {
        val bmp = if (m.kind == T.KIND_IMAGE || m.kind == 5) BitmapFactory.decodeFile(f.path) else null
        if (bmp != null) {
            AlertDialog.Builder(this).setView(ImageView(this).apply { setImageBitmap(bmp); adjustViewBounds = true })
                .setPositiveButton("Close", null).show()
            return
        }
        val type = when (m.kind) {
            2 -> "video/*"
            3 -> "audio/*"
            else -> android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(m.text.substringAfterLast('.', "").lowercase())
                ?: "application/octet-stream"
        }
        val uri = FileProvider.getUriForFile(this, "app.svpn.files", f)
        try {
            startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, type).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
        } catch (_: ActivityNotFoundException) {
            toast("no app to open this (${fmtBytes(f.length())})")
        }
    }
}
