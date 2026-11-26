package app.svpn

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import com.google.zxing.integration.android.IntentIntegrator

/** Phone setup: scan or paste the `svpn:` code printed by `svpn init` / `svpn provision`, then
 *  1. check that the server answers, 2. first Sync, 3. (optional) the certificate for HTTPS images.
 *  The server (`svpn run`) must be running for steps 1–3. */
class SetupActivity : Activity() {
    private val input by lazy { EditText(this).apply { hint = "svpn:…"; minLines = 3 } }
    private val steps by lazy { label(size = 16f) }
    private val certRow by lazy {
        hbox(button("Save certificate") { pickCaFile() }, button("Install it") { openCaInstall() }).apply { visibility = View.GONE }
    }
    private val retryBtn by lazy { button("Try again") { firstRun() }.apply { visibility = View.GONE } }
    private val doneBtn by lazy { button("Done") { done() }.apply { visibility = View.GONE } }

    /** Back to the chats (start them if setup was opened on its own, e.g. after "Remove server"). */
    private fun done() {
        if (isTaskRoot) startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Set up squeezeVPN"
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            onBackInvokedDispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT) { back() }
        }
        show(vbox(
            label("Set up", 20f),
            label("Scan the phone setup QR printed by `svpn init` on your server, or paste its text. Start `svpn run` on the server first."),
            button("Scan QR code") {
                IntentIntegrator(this).setPrompt("Scan the svpn setup QR").setBeepEnabled(false).setOrientationLocked(true).initiateScan()
            },
            input,
            button("Save") { save(input.text.toString()) },
            steps, retryBtn, certRow, doneBtn,
        ))
    }

    private fun save(text: String) {
        try {
            App.I.saveProvision(text)
        } catch (e: Exception) {
            fail(Exception("not a valid setup code: ${e.message}"))
            return
        }
        firstRun()
    }

    /** The server is already saved; these steps only check it and do the first Sync. Nothing here can
     *  undo the setup: Done is always offered. */
    private fun firstRun() {
        val saved = "✓ Server saved (${App.I.prov().host})\n"
        listOf(retryBtn, certRow).forEach { it.visibility = View.GONE }
        doneBtn.visibility = View.VISIBLE
        steps.text = saved + "Contacting the server…"
        App.I.bg({ App.I.check() }) { r ->
            r.onFailure {
                steps.text = saved + "Not reachable yet: ${it.message}\n\n" +
                    "You can continue: tap Done. The app connects when you tap Check, or tap Try again once the server runs."
                retryBtn.visibility = View.VISIBLE
                return@bg
            }
            val wa = T.WA_STATES.getOrNull(App.I.waState) ?: "unknown"
            val sig = T.WA_STATES.getOrNull(App.I.sigState) ?: "unknown"
            val one = saved + "✓ Server answers (WhatsApp: $wa, Signal: $sig)\n"
            steps.text = one + "First Sync…"
            App.I.bg({ App.I.sync { line -> runOnUiThread { steps.text = one + "Sync: $line" } } }) { r2 ->
                val two = r2.fold({ "✓ First Sync done\n" }, { e -> "✗ Sync failed: ${e.message}\n   (retry later with Free data — Sync)\n" })
                steps.text = one + two + "\nOptional — to shrink images on HTTPS sites: save the certificate, then install it."
                certRow.visibility = View.VISIBLE
            }
        }
    }

    /** Without a server there is nothing behind this screen: back closes the app instead of reopening setup. */
    private fun back() = if (App.I.provisioned) done() else finishAffinity()

    @Deprecated("framework Activity API (Android < 13)")
    override fun onBackPressed() = back()

    @Deprecated("framework Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val uri = data?.data
        if (requestCode == REQ_SAVE_CA) {
            if (resultCode == RESULT_OK && uri != null) writeCa(uri) {}
            return
        }
        val r = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (r?.contents != null) {
            input.setText(r.contents)
            save(r.contents)
        } else super.onActivityResult(requestCode, resultCode, data)
    }
}
