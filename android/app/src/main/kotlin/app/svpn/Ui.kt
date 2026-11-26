package app.svpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/** Tiny helpers for building framework views in code (no XML, no AndroidX). */
fun Activity.dp(v: Int) = (v * resources.displayMetrics.density).toInt()

fun Activity.vbox(vararg views: View) = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    views.forEach { addView(it) }
}

/** setContentView that keeps the content out from under the title bar, status bar, navigation bar,
 *  camera cutout and keyboard (Android 15+ draws apps edge-to-edge). */
fun Activity.show(root: View) {
    val pad = dp(12)
    root.setOnApplyWindowInsetsListener { v, insets ->
        val i = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
        v.setPadding(i.left + pad, i.top + pad, i.right + pad, i.bottom + pad)
        WindowInsets.CONSUMED
    }
    setContentView(root)
}

fun Activity.hbox(vararg views: View) = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    views.forEach { addView(it, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)) }
}

fun Activity.button(text: String, onClick: () -> Unit) = Button(this).apply {
    this.text = text
    isAllCaps = false
    setOnClickListener { onClick() }
}

fun Activity.label(text: String = "", size: Float = 14f) = TextView(this).apply {
    this.text = text
    textSize = size
    setPadding(dp(4), dp(6), dp(4), dp(6))
}

/** A slider over `options` with its current value as the caption above it. Starts at `value` (or the
 *  nearest option); `onChange` runs for every new position while dragging. */
fun Activity.slider(options: List<Int>, value: Int, text: (Int) -> String, onChange: (Int) -> Unit): View {
    val caption = label("", 13f)
    val bar = android.widget.SeekBar(this).apply {
        max = options.size - 1
        progress = options.indexOf(value).takeIf { it >= 0 } ?: options.indices.minBy { kotlin.math.abs(options[it] - value) }
        caption.text = text(options[progress])
        setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(s: android.widget.SeekBar, p: Int, fromUser: Boolean) {
                caption.text = text(options[p])
                onChange(options[p])
            }
            override fun onStartTrackingTouch(s: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(s: android.widget.SeekBar) {}
        })
    }
    return vbox(caption, bar)
}

fun Activity.toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

/** Is the screen still shown? A dialog on a screen the user has left crashes the app (and the VPN with it). */
fun Activity.alive() = !isFinishing && !isDestroyed

fun Activity.fail(e: Throwable) {
    val msg = e.message ?: e.toString()
    if (alive()) AlertDialog.Builder(this).setMessage(msg).setPositiveButton("OK", null).show()
    else Toast.makeText(applicationContext, msg, Toast.LENGTH_LONG).show()
}

fun fmtBytes(n: Long) = when {
    n < 1024 -> "$n B"
    n < 1024 * 1024 -> "%.1f KB".format(n / 1024.0)
    else -> "%.1f MB".format(n / 1048576.0)
}

fun weight() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)

/** ListView adapter over a list, rendering each item with `render`. */
class ListAdapter<T>(private val act: Activity, var items: List<T>, private val render: (T) -> CharSequence) : BaseAdapter() {
    override fun getCount() = items.size
    override fun getItem(i: Int) = items[i]
    override fun getItemId(i: Int) = i.toLong()
    override fun getView(i: Int, convert: View?, parent: ViewGroup?): View =
        ((convert as? TextView) ?: act.label(size = 16f)).apply { text = render(items[i]) }
}

const val REQ_SAVE_CA = 2

/** Fetches the CA from the server first, then lets the user pick where to save it (no storage permission
 *  needed); the result arrives as REQ_SAVE_CA. Fetching first means a failed download never leaves an
 *  empty file behind. */
fun Activity.pickCaFile() = App.I.bg({ App.I.caCert() }) { r ->
    r.onSuccess {
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/x-x509-ca-cert").putExtra(Intent.EXTRA_TITLE, "squeezevpn-ca.crt"),
            REQ_SAVE_CA,
        )
    }.onFailure { fail(it) }
}

/** Writes the already fetched CA to the picked file. */
fun Activity.writeCa(uri: Uri, done: () -> Unit) = App.I.bg({
    val der = App.I.prefs.getString("ca_der", null)?.let { android.util.Base64.decode(it, android.util.Base64.NO_WRAP) }
        ?: error("certificate not fetched")
    contentResolver.openOutputStream(uri, "wt")!!.use { it.write(der) }
}) { r -> r.onSuccess { toast("saved — now tap Install it") }.onFailure { fail(it) }; done() }

/** Android 11+ doesn't let apps install CAs: open the screen where the user does it. */
fun Activity.openCaInstall() {
    toast("Encryption & credentials → Install a certificate → CA certificate → pick squeezevpn-ca.crt")
    startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
}

/** Status dot colours: green = working, red = not working. */
object Col {
    const val OK = 0xFF2E9D46.toInt()
    const val BAD = 0xFFD32F2F.toInt()
}

/** A small filled circle right before the text (`null` = no dot, state unknown). */
fun TextView.dot(color: Int?) {
    val d = color?.let {
        val size = (10 * resources.displayMetrics.density).toInt()
        GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(it); setSize(size, size); setBounds(0, 0, size, size) }
    }
    setCompoundDrawablesRelative(d, null, null, null)
    compoundDrawablePadding = (6 * resources.displayMetrics.density).toInt()
}

/** A plain label that carries a status dot. */
fun Activity.status(text: String) = label(text, 14f)

/** Labels side by side, each as wide as its text. */
fun Activity.row(vararg views: View) = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    views.forEach { addView(it, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(18) }) }
}
