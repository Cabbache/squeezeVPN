package app.svpn

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.widget.ImageView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

/** Shows the example photo as the server would send it: shrunk to fit `dim` (0 = as is) and re-encoded as
 *  WebP at `q`, the same encoder (libwebp) the server uses. The photo (res/raw/sample.jpg) is CC0, from
 *  Wikimedia Commons: "Mango stall with an 'Aceitamos vários cartões' sign at a feira livre, São Paulo". */
class Preview(act: Activity) {
    /** Always as wide as the screen, so a small image looks as blurry as it would when shown big. */
    val image = object : ImageView(act) {
        override fun onMeasure(w: Int, h: Int) {
            val width = MeasureSpec.getSize(w)
            setMeasuredDimension(width, width * SAMPLE_H / SAMPLE_W)
        }
    }.apply { scaleType = ImageView.ScaleType.FIT_XY }
    /** The example's size after shrinking, e.g. "Example: 84 KB". */
    val size = act.label("", 12f)
    private var want: Pair<Int, Int>? = null
    private var busy = false
    private val res = act.resources

    /** Latest-wins: while dragging, only the newest setting is encoded once the current one is done. */
    fun show(q: Int, dim: Int) {
        want = q to dim
        if (!busy) next()
    }

    private fun next() {
        val (q, dim) = want ?: return
        want = null
        busy = true
        worker.execute {
            val r = runCatching { encode(sample(), q, dim) }
            main.post {
                busy = false
                r.onSuccess { bytes ->
                    image.setImageBitmap(BitmapFactory.decodeByteArray(bytes, 0, bytes.size))
                    size.text = "Example: ${fmtBytes(bytes.size.toLong())}"
                }
                next()
            }
        }
    }

    private fun sample(): Bitmap = original ?: res.openRawResource(R.raw.sample).use { BitmapFactory.decodeStream(it) }
        .also { original = it }

    private companion object {
        const val SAMPLE_W = 2048
        const val SAMPLE_H = 1360
        val worker = Executors.newSingleThreadExecutor { Thread(it, "svpn-preview") }
        val main = Handler(Looper.getMainLooper())
        @Volatile var original: Bitmap? = null

        fun encode(src: Bitmap, q: Int, dim: Int): ByteArray {
            val scale = if (dim > 0) minOf(1.0, dim.toDouble() / maxOf(src.width, src.height)) else 1.0
            val bmp = if (scale < 1) Bitmap.createScaledBitmap(src, (src.width * scale).toInt().coerceAtLeast(1),
                (src.height * scale).toInt().coerceAtLeast(1), true) else src
            @Suppress("DEPRECATION") // WEBP is lossy WebP before Android 11
            val fmt = if (Build.VERSION.SDK_INT >= 30) Bitmap.CompressFormat.WEBP_LOSSY else Bitmap.CompressFormat.WEBP
            return ByteArrayOutputStream().also { bmp.compress(fmt, q, it) }.toByteArray()
        }
    }
}
