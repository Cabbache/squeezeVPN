package app.svpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Base64
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer

/** WireGuard tunnel for the apps the user allows. Our own app is never routed (its UDP goes direct). */
object Vpn {
    private class Tun : Tunnel {
        @Volatile var state = Tunnel.State.DOWN
        override fun getName() = "svpn"
        override fun onStateChange(newState: Tunnel.State) {
            state = newState
            // notifications run only while the VPN is on; a problem there must never fail the VPN itself
            try { Push.update(App.I) } catch (e: Exception) { android.util.Log.w("svpn", "push: ${e.message}") }
        }
    }

    private val tunnel = Tun()
    private var backend: GoBackend? = null
    private fun backend(ctx: Context) = backend ?: GoBackend(ctx.applicationContext).also { backend = it }

    val isUp get() = tunnel.state == Tunnel.State.UP

    data class AppInfo(val pkg: String, val label: String)

    /** Launchable apps (visible through the <queries> declaration), excluding ourselves. */
    fun launchableApps(ctx: Context): List<AppInfo> {
        val pm = ctx.packageManager
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(i, PackageManager.MATCH_ALL)
            .map { AppInfo(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
            .filter { it.pkg != ctx.packageName }
            .distinctBy { it.pkg }
            .sortedBy { it.label.lowercase() }
    }

    fun allowed(): Set<String> = App.I.prefs.getStringSet("vpn_apps", emptySet())!!
    fun setAllowed(s: Set<String>) {
        App.I.prefs.edit().putStringSet("vpn_apps", s).apply()
        untouchedByUid.clear()
    }

    /** Apps whose HTTPS the server decrypts (images shrunk, video limited). All others are left
     *  untouched: their connections are marked by our WireGuard fork (android/tunnel) and relayed as is.
     *  First use: the browsers among the allowed apps. */
    fun decrypting(ctx: Context): Set<String> =
        App.I.prefs.getStringSet("vpn_decrypt", null) ?: (allowed() intersect browsers(ctx)).also { setDecrypting(it) }

    fun setDecrypting(s: Set<String>) {
        App.I.prefs.edit().putStringSet("vpn_decrypt", s).apply()
        untouchedByUid.clear()
    }

    /** Apps that open web links (browsers): decrypted by default. */
    fun browsers(ctx: Context): Set<String> {
        val i = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)
        return ctx.packageManager.queryIntentActivities(i, PackageManager.MATCH_ALL).map { it.activityInfo.packageName }.toSet()
    }

    /** Untouched unless one of the uid's packages is set to be decrypted (unknown uid: untouched). */
    fun untouched(pkgs: Array<String>?, decrypt: Set<String>) = pkgs == null || pkgs.none { it in decrypt }

    private val untouchedByUid = java.util.concurrent.ConcurrentHashMap<Int, Boolean>()

    /** Tells the WireGuard fork which apps to leave untouched; asked once per new connection, on its packet thread. */
    fun watchApps(ctx: Context) {
        val app = ctx.applicationContext
        GoBackend.setUidFilter { uid ->
            untouchedByUid.getOrPut(uid) { untouched(app.packageManager.getPackagesForUid(uid), decrypting(app)) }
        }
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

    /** Call off the UI thread, after VpnService.prepare() was granted. */
    fun up(ctx: Context) {
        val apps = allowed()
        require(apps.isNotEmpty()) { "select at least one app to route through the VPN" }
        val p = App.I.prov()
        val host = if (p.host.contains(':')) "[${p.host}]" else p.host
        val iface = Interface.Builder()
            .parsePrivateKey(b64(p.clientWgPriv))
            .parseAddresses("10.8.0.2/32")
            .parseDnsServers("1.1.1.1")
            .includeApplications(apps)
            .build()
        // No persistent keepalive: the server never initiates traffic, so idle costs 0 bytes.
        val peer = Peer.Builder()
            .parsePublicKey(b64(p.serverWgPub))
            .parseEndpoint("$host:${p.wgPort}")
            .parseAllowedIPs("0.0.0.0/0, ::/0")
            .build()
        backend(ctx).setState(tunnel, Tunnel.State.UP, Config.Builder().setInterface(iface).addPeer(peer).build())
    }

    fun down(ctx: Context) {
        backend(ctx).setState(tunnel, Tunnel.State.DOWN, null)
    }

    /** (rx, tx) bytes of the tunnel, or null when down. */
    fun stats(ctx: Context): Pair<Long, Long>? =
        if (!isUp) null else backend(ctx).getStatistics(tunnel).let { it.totalRx() to it.totalTx() }

    /** The VPN as a status dot: green = on and the server answers, red = off or no answer. */
    fun state(ctx: Context): Pair<Int, String> {
        val st = stats(ctx) ?: return Col.BAD to "VPN off"
        return if (st.first > 0) Col.OK to "VPN on" else Col.BAD to "VPN: no answer"
    }

    /** Android "Block connections without VPN" state; null if unknown (tunnel down / old Android). */
    fun lockdown(ctx: Context): Boolean? = try {
        if (isUp) backend(ctx).isLockdownEnabled else null
    } catch (e: Exception) {
        null
    }
}
