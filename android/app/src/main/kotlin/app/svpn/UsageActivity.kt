package app.svpn

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.widget.ListView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** "Data usage": what each site sent to the phone since the last reset, by kind (video, images, …).
 *  Asks the server only when opened and on Refresh / Reset. */
class UsageActivity : Activity() {
    private val head by lazy { label(size = 16f) }
    private lateinit var adapter: ListAdapter<App.SiteUse>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        adapter = ListAdapter(this, emptyList()) { row(it) }
        show(vbox(
            head,
            hbox(button("Refresh") { load(reset = false) }, button("Reset") {
                AlertDialog.Builder(this).setMessage("Start a new measurement from zero?")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Reset") { _, _ -> load(reset = true) }
                    .show()
            }),
            ListView(this).apply { this.adapter = this@UsageActivity.adapter; layoutParams = weight() },
        ))
        load(reset = false)
    }

    private fun load(reset: Boolean) {
        App.I.bg({ App.I.usage(reset) }) { r ->
            r.onFailure { fail(it) }.onSuccess { u ->
                val since = if (u.since > 0) SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.ROOT).format(Date(u.since * 1000)) else "—"
                head.text = "Received ${fmtBytes(u.webDown)} · Saved ${fmtBytes(u.saved)}\nsince $since"
                adapter.items = if (reset) emptyList() else u.sites
                adapter.notifyDataSetChanged()
                if (reset) {
                    toast("new measurement started")
                    load(reset = false)
                }
            }
        }
    }

    /** "example.com   6.3 MB · 14 connections" in bold, then the kinds, largest first, smaller and grey. */
    private fun row(s: App.SiteUse): CharSequence {
        val b = SpannableStringBuilder()
        val start = b.length
        b.append("${s.name}   ${fmtBytes(s.total)} · ${s.streams} connections")
        b.setSpan(StyleSpan(android.graphics.Typeface.BOLD), start, b.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        val kinds = s.kinds.sortedByDescending { it.second }.joinToString(" · ") { (k, bytes, saved) ->
            "$k ${fmtBytes(bytes)}" + if (saved > 0) " (−${fmtBytes(saved)})" else ""
        }
        val k0 = b.length
        b.append("\n").append(kinds)
        b.setSpan(RelativeSizeSpan(0.85f), k0, b.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        b.setSpan(ForegroundColorSpan(0xFF9E9E9E.toInt()), k0, b.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        return b
    }
}
