package app.svpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.CheckBox
import android.widget.ScrollView

/** VPN on/off, which apps use it, blocking status, and settings. Phone-only settings apply as they
 *  change; the image and video settings go to the server with Save (enabled only when they differ). */
class VpnActivity : Activity() {
    private val status by lazy { label() }
    private val vpnBtn by lazy { button("") { toggle() } }
    private val lockDot by lazy { status("Other apps blocked") }
    private val caDot by lazy { status("Certificate installed") }
    private val certRow by lazy { hbox(button("Save certificate") { pickCaFile() }, button("Install it") { openCaInstall() }) }
    /** Notifications per service (push session while the VPN is on); the dot shows whether it is connected. */
    private fun notifyBox(service: Int, name: String) = CheckBox(this).apply {
        text = "$name notifications"
        isChecked = Push.enabled(service)
        setOnCheckedChangeListener { _, on ->
            Push.setEnabled(this@VpnActivity, service, on)
            if (on) askNotifications()
            refresh()
        }
    }
    private val notifyBoxes by lazy { mapOf(T.SERVICE_WHATSAPP to notifyBox(T.SERVICE_WHATSAPP, "WhatsApp"), T.SERVICE_SIGNAL to notifyBox(T.SERVICE_SIGNAL, "Signal")) }
    private val permRow by lazy {
        status("Notifications allowed").apply {
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }
        }
    }
    private val batteryRow by lazy {
        status("Battery unrestricted (tap)").apply {
            setOnClickListener {
                @Suppress("BatteryLife") // a messaging app's push connection is the intended use
                startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, android.net.Uri.parse("package:$packageName")))
            }
        }
    }
    private val appsBtn by lazy { button("") { startActivity(Intent(this, AppsActivity::class.java)) } }
    /** Sends the image and video settings; enabled only while they differ from what the server has. */
    private val saveBtn by lazy { button("Save") { save() } }
    private var saving = false
    private var fetchingCa = false

    /** Quality and size sliders with the example photo as it would arrive at those settings. */
    private fun imageBox(q: Int, dim: Int, setQ: (Int) -> Unit, setDim: (Int) -> Unit): android.view.View {
        val preview = Preview(this)
        var (cq, cd) = q to dim
        preview.show(cq, cd)
        return vbox(
            slider(QUALITIES, q, { "Quality $it" }) { cq = it; setQ(it); preview.show(cq, cd) },
            slider(DIMS, dim, { if (it == 0) "Size  as is" else "Size  up to $it px" }) { cd = it; setDim(it); preview.show(cq, cd) },
            preview.image, preview.size,
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "VPN & settings"
        val a = App.I
        val prefs = a.prefs
        val proxyOn = CheckBox(this).apply {
            text = "Shrink images on web pages"
            isChecked = prefs.getBoolean("proxy_on", true)
            setOnCheckedChangeListener { _, on -> prefs.edit().putBoolean("proxy_on", on).apply(); updateSave() }
        }
        val webImages = imageBox(prefs.getInt("proxy_q", 35), prefs.getInt("proxy_dim", 1280),
            { prefs.edit().putInt("proxy_q", it).apply(); updateSave() },
            { prefs.edit().putInt("proxy_dim", it).apply(); updateSave() })
        val video = slider(VIDEO, prefs.getInt("proxy_video", VIDEO_DEFAULT), { if (it == 0) "Video  no limit" else "Video  $it kbit/s" }) {
            prefs.edit().putInt("proxy_video", it).apply()
            updateSave()
        }
        val waImages = imageBox(a.mediaQuality, a.mediaMaxDim, { a.mediaQuality = it }, { a.mediaMaxDim = it })
        val auto = slider(AUTO, a.autoRefreshSecs, { "Auto-check  " + when { it == 0 -> "off"; it < 60 -> "every $it s"; else -> "every ${it / 60} min" } }) {
            a.autoRefreshSecs = it
        }

        val header = vbox(
            vpnBtn,
            lockDot,
            status,
            hbox(button("Android VPN settings") {
                startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
            }),
            appsBtn,
            label("Image shrinking"),
            proxyOn, webImages,
            video,
            caDot,
            certRow,
            saveBtn,
            label("WhatsApp images"),
            waImages,
            label("Messages"),
            notifyBoxes.getValue(T.SERVICE_WHATSAPP),
            notifyBoxes.getValue(T.SERVICE_SIGNAL),
            permRow,
            batteryRow,
            auto,
            button("Set up again (scan new server QR)") { startActivity(Intent(this, SetupActivity::class.java)) },
            button("Remove server") { confirmRemove() },
        )
        show(ScrollView(this).apply { addView(header) })
    }

    /** What the server should use. HTTPS interception only once the certificate is installed, otherwise
     *  every HTTPS site would fail in the browser. */
    private fun imageSettings(): List<Any> = App.I.prefs.let {
        val https = App.I.caInstalled() == true
        listOf(it.getBoolean("proxy_on", true), it.getInt("proxy_q", 35), it.getInt("proxy_dim", 1280), https,
            it.getInt("proxy_video", VIDEO_DEFAULT))
    }

    // Slider positions; 0 at the end means "no limit" / "as is" / "off" (first for auto-check).
    private companion object {
        const val VIDEO_DEFAULT = 400
        val QUALITIES = (1..9).toList() + (2..20).map { it * 5 } // fine steps at the low end
        val DIMS = listOf(80, 120, 160, 200, 240, 320, 480, 640, 800, 1024, 1280, 1600, 2048, 0)
        val VIDEO = (1..40).map { it * 50 } + 0
        val AUTO = listOf(0, 15, 30, 60, 120, 300, 600, 900, 1800, 3600)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    /** Settings as the server has them, from the last successful Save. */
    private fun savedKey() = App.I.prefs.getString("proxy_sent", null)

    private fun updateSave() {
        saveBtn.isEnabled = !saving && imageSettings().joinToString(",") != savedKey()
    }

    /** Save: one small request with the image and video settings. */
    private fun save() {
        val now = imageSettings()
        val (on, q, d, https, video) = now
        saving = true
        updateSave()
        App.I.bg({ App.I.proxyCfg(on as Boolean, q as Int, d as Int, https as Boolean, video as Int) }) { r ->
            saving = false
            r.onSuccess { App.I.prefs.edit().putString("proxy_sent", now.joinToString(",")).apply() }
                .onFailure { toast("not saved: ${it.message}") }
            updateSave()
        }
    }

    private fun refresh() {
        updateSave()
        for ((service, box) in notifyBoxes) {
            // Signal's row only once the server says Signal is used
            val shown = Push.used(service) && (service != T.SERVICE_SIGNAL || App.I.sigState >= 0)
            box.visibility = if (shown) View.VISIBLE else View.GONE
            // green: connected; red: should be connected (VPN on) but isn't; no dot while the VPN is off
            box.dot(if (!Push.enabled(service) || !Vpn.isUp) null else if (Push.connected) Col.OK else Col.BAD)
        }
        val notifying = notifyBoxes.any { (s, box) -> box.visibility == View.VISIBLE && Push.enabled(s) }
        permRow.dot(Col.BAD)
        permRow.visibility = if (notifying && !Notify.allowed(this)) View.VISIBLE else View.GONE
        batteryRow.dot(Col.BAD)
        val unrestricted = getSystemService(android.os.PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)
        batteryRow.visibility = if (notifying && !unrestricted) View.VISIBLE else View.GONE
        appsBtn.text = "Apps that can use network (${Vpn.allowed().size})"
        val (color, text) = Vpn.state(this)
        vpnBtn.text = text
        vpnBtn.dot(color)
        lockDot.dot(Vpn.lockdown(this)?.let { if (it) Col.OK else Col.BAD })
        lockDot.visibility = if (Vpn.isUp) View.VISIBLE else View.GONE
        val ca = App.I.caInstalled() == true
        // a fresh install doesn't know the server's certificate yet: fetch it (a few hundred bytes), so one
        // that is already installed on the phone is recognised without "Save certificate"
        if (App.I.caInstalled() == null && !fetchingCa) {
            fetchingCa = true
            App.I.bg({ App.I.caCert() }) { fetchingCa = false; if (alive()) refresh() }
        }
        // no certificate yet: show the two steps (the server only decrypts HTTPS once it is installed)
        certRow.visibility = if (!ca) View.VISIBLE else View.GONE
        caDot.dot(Col.OK)
        caDot.visibility = if (ca) View.VISIBLE else View.GONE
        status.text = Vpn.stats(this)?.let { (rx, tx) -> "↓ ${fmtBytes(rx)}  ↑ ${fmtBytes(tx)}" } ?: ""
        status.visibility = if (status.text.isEmpty()) View.GONE else View.VISIBLE
        // the VPN dot turns green once the server answers: refresh while this screen is open
        handler.removeCallbacks(tick)
        if (Vpn.isUp) handler.postDelayed(tick, 2000)
    }

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val tick = Runnable { refresh() }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }

    private fun toggle() {
        if (Vpn.isUp) {
            App.I.bg({ Vpn.down(this) }) { r -> r.onFailure { fail(it) }; refresh() }
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, 1) else connect()
    }

    @Deprecated("framework Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) connect()
        val uri = data?.data
        if (requestCode == REQ_SAVE_CA && resultCode == RESULT_OK && uri != null) writeCa(uri) { refresh() }
    }

    private fun confirmRemove() {
        android.app.AlertDialog.Builder(this)
            .setTitle("Remove server?")
            .setMessage("Disconnects the VPN and deletes this server's setup, keys and downloaded chats from this phone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Remove") { _, _ ->
                App.I.bg({ App.I.forget() }) { r ->
                    r.onFailure { fail(it) }.onSuccess {
                        toast("Server removed. Android keeps an empty VPN entry; delete it in Settings → Network → VPN → squeezeVPN → Forget")
                        startActivity(Intent(this, SetupActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                    }
                }
            }
            .show()
    }

    private fun connect() {
        if (notifyBoxes.any { (s, _) -> Push.used(s) && Push.enabled(s) }) askNotifications()
        App.I.bg({ Vpn.up(this) }) { r -> r.onFailure { fail(it) }; refresh() }
    }

    /** Android's notification permission, asked once (later: the red "Notifications allowed" row). */
    private fun askNotifications() {
        if (!Notify.allowed(this)) requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2)
    }
}
