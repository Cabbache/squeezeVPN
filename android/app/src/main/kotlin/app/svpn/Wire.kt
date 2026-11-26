// Wire format — Kotlin mirror of server/src/wire.rs. Keep the two in sync;
// WireTest checks this file against server/testdata/golden.txt.
package app.svpn

import com.github.luben.zstd.ZstdCompressCtx
import com.github.luben.zstd.ZstdDecompressCtx
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object T {
    const val DIR_C2S = 0
    const val DIR_S2C = 1

    const val CHECK = 1
    const val FETCH = 2
    const val SEND = 3
    const val MEDIA = 4
    const val PROXY_CFG = 5
    const val CA = 6
    const val USAGE = 8
    const val PUSH_HELLO = 9
    const val PING = 10
    const val MUTE = 11
    const val SUMMARY = 16
    const val RECORDS = 17
    const val SENT = 18
    const val CHUNK = 19
    const val ERR = 20
    const val ACK = 21
    const val CA_CERT = 22
    const val SYNC_HELLO = 24
    const val SYNC_CURSORS = 25
    const val SYNC_CHAT = 26
    const val SYNC_DICT = 27
    const val SYNC_DONE = 28
    const val USAGE_REPLY = 29
    const val PUSH = 30
    const val PONG = 31

    // a chat's service (SUMMARY / SYNC_CHAT) and a notification's (PUSH); bit numbers in PUSH_HELLO
    const val SERVICE_WHATSAPP = 0
    const val SERVICE_SIGNAL = 1

    const val CODEC_RAW = 0
    const val CODEC_ZSTD = 1

    const val KIND_TEXT = 0
    const val KIND_IMAGE = 1

    val KIND_NAMES = arrayOf("text", "image", "video", "audio", "document", "sticker")
    val WA_STATES = arrayOf("starting", "needs pairing (scan QR on server)", "connected", "disconnected", "logged out", "not used")
    // indexes into WA_STATES (server wire.rs WA_*), for WhatsApp and Signal alike; SUMMARY and SYNC_DONE
    // carry both in one byte: WhatsApp in the low nibble, Signal in the high one
    const val WA_STARTING = 0
    const val WA_NEEDS_PAIRING = 1
    const val WA_CONNECTED = 2
    const val WA_DISCONNECTED = 3
    const val WA_LOGGED_OUT = 4
    const val WA_OFF = 5 // the service isn't linked on this server

    fun hdr(t: Int, codec: Int) = (t shl 3) or (codec and 7)

    /** The states byte of SUMMARY / SYNC_DONE: (WhatsApp, Signal). */
    fun states(b: Int) = Pair(b and 15, b shr 4)
}

class WireException(msg: String) : Exception(msg)

/** A notification from a push session (server wire.rs `push_frame`). */
data class PushMsg(val service: Int, val seq: Long, val chat: Int, val chatName: String, val sender: String, val kind: Int, val preview: String) {
    companion object {
        fun decode(pt: ByteArray): PushMsg {
            val rd = Rd(pt, 1)
            return PushMsg(rd.u8(), rd.uv(), rd.uv().toInt(), rd.str(), rd.str(), rd.u8(), rd.str())
        }
    }
}

class Buf {
    private val out = ByteArrayOutputStream()
    fun u8(v: Int) = apply { out.write(v) }
    fun uv(v: Long): Buf {
        var x = v
        while (true) {
            val b = (x and 0x7f).toInt()
            x = x ushr 7
            if (x == 0L) { out.write(b); return this }
            out.write(b or 0x80)
        }
    }
    fun uv(v: Int) = uv(v.toLong())
    fun bytes(b: ByteArray) = apply { uv(b.size.toLong()); out.write(b) }
    fun str(s: String) = bytes(s.toByteArray(Charsets.UTF_8))
    fun raw(b: ByteArray) = apply { out.write(b) }
    fun toBytes(): ByteArray = out.toByteArray()
}

class Rd(val b: ByteArray, var p: Int = 0, private val end: Int = b.size) {
    fun eof() = p >= end
    fun u8(): Int {
        if (p >= end) throw WireException("eof")
        return b[p++].toInt() and 0xff
    }
    fun uv(): Long {
        var v = 0L
        var shift = 0
        while (true) {
            if (shift >= 64) throw WireException("varint overflow")
            val x = u8()
            v = v or ((x and 0x7f).toLong() shl shift)
            if (x and 0x80 == 0) return v
            shift += 7
        }
    }
    fun bytes(): ByteArray {
        val n = uv()
        if (n < 0 || n > end - p) throw WireException("bytes eof")
        return b.copyOfRange(p, p + n.toInt()).also { p += n.toInt() }
    }
    fun str() = String(bytes(), Charsets.UTF_8)
    fun rest(): ByteArray = b.copyOfRange(p, end).also { p = end }
}

fun zz(v: Long) = (v shl 1) xor (v shr 63)
fun unzz(v: Long) = (v ushr 1) xor -(v and 1)

sealed class Record {
    abstract val seq: Long
    data class Sender(override val seq: Long, val name: String) : Record()
    data class Msg(
        override val seq: Long, val sender: Long, val ts: Long,
        val kind: Int, val text: String, val mediaSize: Long,
    ) : Record()
}

/** Position in a chat's canonical record stream (last seq, last message ts, senders seen). */
class ChatPos(var seq: Long = 0, var ts: Long = 0, var senders: Long = 0) {
    fun encode(r: Record, out: Buf) {
        when (r) {
            is Record.Sender -> {
                out.uv(((r.seq - seq) shl 1) or 1).str(r.name)
                seq = r.seq; senders++
            }
            is Record.Msg -> {
                out.uv((r.seq - seq) shl 1).uv(r.sender).uv(zz(r.ts - ts)).u8(r.kind).str(r.text)
                if (r.kind != T.KIND_TEXT) out.uv(r.mediaSize)
                seq = r.seq; ts = r.ts
            }
        }
    }

    fun decode(rd: Rd): Record {
        val head = rd.uv()
        val delta = head ushr 1
        if (delta == 0L) throw WireException("zero seq delta")
        val s = seq + delta
        val r = if (head and 1L == 1L) {
            senders++
            Record.Sender(s, rd.str())
        } else {
            val sender = rd.uv()
            val t = ts + unzz(rd.uv())
            val kind = rd.u8()
            val text = rd.str()
            val size = if (kind != T.KIND_TEXT) rd.uv() else 0
            ts = t
            Record.Msg(s, sender, t, kind, text, size)
        }
        seq = s
        return r
    }

    /** Decodes a whole canonical stream, advancing this position. */
    fun decodeAll(stream: ByteArray): List<Record> {
        val rd = Rd(stream)
        val out = ArrayList<Record>()
        while (!rd.eof()) out.add(decode(rd))
        return out
    }
}

object Z {
    private val MAGIC = byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte())
    const val HISTORY_TAIL = 32 * 1024

    /** 0x00 ‖ synced dict ‖ last 32 KiB of chat history — byte-identical to the server's. */
    fun buildDict(synced: ByteArray, history: ByteArray): ByteArray {
        val from = maxOf(0, history.size - HISTORY_TAIL)
        val d = ByteArray(1 + synced.size + history.size - from)
        System.arraycopy(synced, 0, d, 1, synced.size)
        System.arraycopy(history, from, d, 1 + synced.size, history.size - from)
        return d
    }

    fun compress(data: ByteArray, dict: ByteArray): ByteArray {
        ZstdCompressCtx().use { c ->
            c.setLevel(19)
            c.setContentSize(false)
            c.setChecksum(false)
            c.setDictID(false)
            c.setWindowLog(17)
            c.loadDict(dict)
            val out = c.compress(data)
            return out.copyOfRange(4, out.size) // strip magic
        }
    }

    fun decompress(data: ByteArray, dict: ByteArray, max: Int): ByteArray {
        ZstdDecompressCtx().use { d ->
            d.loadDict(dict)
            return d.decompress(MAGIC + data, max)
        }
    }

    /** (codec, payload): compressed only if that saves bytes. */
    fun pack(data: ByteArray, dict: ByteArray): Pair<Int, ByteArray> {
        val z = try { compress(data, dict) } catch (e: Exception) { null }
        return if (z != null && z.size < data.size) T.CODEC_ZSTD to z else T.CODEC_RAW to data
    }

    fun unpack(codec: Int, payload: ByteArray, dict: ByteArray, max: Int): ByteArray = when (codec) {
        T.CODEC_RAW -> payload
        T.CODEC_ZSTD -> decompress(payload, dict, max)
        else -> throw WireException("unknown codec $codec")
    }
}

object Crypto {
    private fun nonce(dir: Int, pn: Long): ByteArray {
        val n = ByteArray(12)
        n[0] = dir.toByte()
        for (i in 0 until 8) n[1 + i] = (pn ushr (8 * i)).toByte()
        return n
    }

    private fun cipher(mode: Int, key: ByteArray, dir: Int, pn: Long): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(dir, pn)))
            updateAAD(byteArrayOf(pn.toByte()))
        }

    fun seal(key: ByteArray, dir: Int, pn: Long, pt: ByteArray): ByteArray =
        byteArrayOf(pn.toByte()) + cipher(Cipher.ENCRYPT_MODE, key, dir, pn).doFinal(pt)

    fun tryOpen(key: ByteArray, dir: Int, pn: Long, pkt: ByteArray): ByteArray? = try {
        cipher(Cipher.DECRYPT_MODE, key, dir, pn).doFinal(pkt, 1, pkt.size - 1)
    } catch (e: Exception) {
        null
    }

    /** HKDF-SHA256(salt = old key, ikm = DH secret, info = "svpn-rotate"), 32 bytes. */
    fun rotate(oldKey: ByteArray, dh: ByteArray): ByteArray {
        val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(oldKey, "HmacSHA256")); doFinal(dh) }
        return Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(prk, "HmacSHA256"))
            doFinal("svpn-rotate".toByteArray() + byteArrayOf(1))
        }
    }
}

/** Reconstructs full packet numbers from their low byte and rejects replays. */
class RxWindow(var next: Long = 0, var bitmap: Long = 0) {
    fun candidate(lo: Int): Long {
        var c = (next and 0xff.toLong().inv()) or lo.toLong()
        if (c + 128 <= next) c += 256
        else if (c > next + 128 && c >= 256) c -= 256
        return c
    }

    private fun isReplay(pn: Long): Boolean {
        if (pn >= next) return false
        val age = next - 1 - pn
        return age >= 64 || (bitmap ushr age.toInt()) and 1L == 1L
    }

    fun accept(pn: Long) {
        if (pn >= next) {
            val shift = pn + 1 - next
            bitmap = if (shift >= 64) 0 else bitmap shl shift.toInt()
            bitmap = bitmap or 1
            next = pn + 1
        } else {
            bitmap = bitmap or (1L shl (next - 1 - pn).toInt())
        }
    }

    /** (pn, plaintext) without updating state; tries windows ahead after sender restarts. */
    fun open(key: ByteArray, dir: Int, pkt: ByteArray): Pair<Long, ByteArray>? {
        if (pkt.size < 17) return null
        val base = candidate(pkt[0].toInt() and 0xff)
        for (k in 0 until 64) {
            val pn = base + k * 256L
            if (isReplay(pn)) continue
            Crypto.tryOpen(key, dir, pn, pkt)?.let { return pn to it }
        }
        return null
    }
}
