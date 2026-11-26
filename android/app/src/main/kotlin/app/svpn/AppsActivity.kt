package app.svpn

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.CheckedTextView
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Which apps use the VPN, and per app whether the server decrypts its HTTPS (open lock: images
 *  shrunk, video limited) or leaves it untouched (closed lock: the app sees the real certificate, so
 *  it always works).
 *  Search box and buttons stay at the top; the list scrolls below them, so search results are never
 *  hidden behind the keyboard. */
class AppsActivity : Activity() {
    private lateinit var apps: List<Vpn.AppInfo>
    private lateinit var rows: List<CheckedTextView>
    private lateinit var locks: List<android.widget.ImageView>
    private lateinit var lines: List<LinearLayout>
    private var allowed: Set<String> = emptySet()
    private var decrypt: Set<String> = emptySet()
    private var browsers: Set<String> = emptySet()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        apps = Vpn.launchableApps(this)
        allowed = Vpn.allowed()
        decrypt = Vpn.decrypting(this)
        browsers = Vpn.browsers(this)
        rows = apps.map { app ->
            (layoutInflater.inflate(android.R.layout.simple_list_item_multiple_choice, null) as CheckedTextView).apply {
                text = app.label
                compoundDrawablePadding = dp(12)
                setOnClickListener { save(if (app.pkg in allowed) allowed - app.pkg else allowed + app.pkg) }
            }
        }
        locks = apps.map { app ->
            android.widget.ImageView(this).apply {
                setPadding(dp(12), dp(4), dp(12), dp(4))
                setOnClickListener { setDecrypt(if (app.pkg in decrypt) decrypt - app.pkg else decrypt + app.pkg) }
            }
        }
        lines = apps.indices.map { i ->
            LinearLayout(this).apply {
                gravity = android.view.Gravity.CENTER_VERTICAL
                addView(rows[i], LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                addView(locks[i], LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(12) })
            }
        }
        render()
        val search = EditText(this).apply {
            hint = "Search apps"
            isSingleLine = true
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable) = filter(s.toString().trim())
            })
        }
        show(vbox(
            label("Apps that can use network", 18f),
            search,
            hbox(button("Enable all") { setAll(true) }, button("Disable all") { setAll(false) }),
            ScrollView(this).apply { addView(vbox(*lines.toTypedArray())); layoutParams = weight() },
        ))
        // icons load in the background so the screen opens immediately
        Thread {
            val size = dp(36)
            apps.forEachIndexed { i, app ->
                val icon = runCatching { packageManager.getApplicationIcon(app.pkg) }.getOrNull()?.apply { setBounds(0, 0, size, size) }
                runOnUiThread { rows[i].setCompoundDrawablesRelative(icon, null, null, null) }
            }
        }.start()
    }

    private fun filter(q: String) {
        apps.forEachIndexed { i, app -> lines[i].visibility = if (app.label.contains(q, ignoreCase = true)) View.VISIBLE else View.GONE }
    }

    /** Enable / disable all apps currently shown (all, or those matching the search). */
    private fun setAll(on: Boolean) {
        val pkgs = apps.filterIndexed { i, _ -> lines[i].visibility == View.VISIBLE }.map { it.pkg }
        save(if (on) allowed + pkgs else allowed - pkgs.toSet())
    }

    private fun save(s: Set<String>) {
        // a newly enabled app starts decrypted if it is a browser, untouched otherwise
        val added = s - allowed
        allowed = s
        Vpn.setAllowed(s)
        if (added.isNotEmpty()) setDecrypt(decrypt - added + (added intersect browsers)) else render()
    }

    private fun setDecrypt(s: Set<String>) {
        decrypt = s
        Vpn.setDecrypting(s)
        render()
    }

    private fun render() = apps.forEachIndexed { i, app ->
        rows[i].isChecked = app.pkg in allowed
        locks[i].visibility = if (app.pkg in allowed) View.VISIBLE else View.INVISIBLE
        val open = app.pkg in decrypt
        locks[i].setImageResource(if (open) R.drawable.lock_open else R.drawable.lock_closed)
        locks[i].setColorFilter(if (open) 0xFF1E6FD9.toInt() else 0xFF8A8A8A.toInt())
        locks[i].contentDescription = if (open) "HTTPS decrypted" else "untouched"
    }
}
