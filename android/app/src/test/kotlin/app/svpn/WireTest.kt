package app.svpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** Cross-language check against vectors written by `cargo test` (server/testdata/golden.txt). */
class WireTest {
    private val g: Map<String, ByteArray> by lazy {
        val f = listOf("../../server/testdata/golden.txt", "../server/testdata/golden.txt").map(::File).first { it.exists() }
        f.readLines().filter { it.isNotBlank() }.associate { line ->
            val (k, v) = line.split(" ")
            k to v.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
    }

    @Test fun varints() {
        val b = Buf()
        listOf(0L, 1, 127, 128, 300, 16384, 0xffffffffL).forEach { b.uv(it) }
        assertArrayEquals(g["varints"], b.toBytes())
        val rd = Rd(b.toBytes())
        listOf(0L, 1, 127, 128, 300, 16384, 0xffffffffL).forEach { assertEquals(it, rd.uv()) }
        for (v in listOf(0L, 1, -1, 63, -64, Long.MIN_VALUE, Long.MAX_VALUE)) assertEquals(v, unzz(zz(v)))
    }

    @Test fun records() {
        val recs = ChatPos().decodeAll(g["records"]!!)
        assertEquals(Record.Sender(3, "Alex"), recs[0])
        assertEquals(Record.Msg(4, 1, 1_760_000_000, 0, "Are we still meeting?", 0), recs[1])
        assertEquals(Record.Msg(10, 1, 1_760_000_050, 1, "", 2_400_000), recs[3])
        val out = Buf()
        val pos = ChatPos()
        recs.forEach { pos.encode(it, out) }
        assertArrayEquals(g["records"], out.toBytes())
    }

    @Test fun packets() {
        val key = g["key"]!!
        val rx = RxWindow()
        val (pn, pt) = rx.open(key, T.DIR_S2C, g["packet_s2c_pn5"]!!)!!
        assertEquals(5L, pn)
        assertEquals("hello server", String(pt))
        assertArrayEquals(g["packet_c2s_pn300"], Crypto.seal(key, T.DIR_C2S, 300, "hello phone".toByteArray()))
        rx.accept(pn)
        assertEquals(null, rx.open(key, T.DIR_S2C, g["packet_s2c_pn5"]!!)) // replay
    }

    @Test fun compression() {
        val dict = Z.buildDict(g["synced"]!!, g["records"]!!)
        assertArrayEquals(g["dict"], dict)
        assertArrayEquals(g["plain"], Z.decompress(g["zstd"]!!, dict, 4096))
        assertArrayEquals(g["plain"], Z.decompress(g["zstd_nodict"]!!, Z.buildDict(ByteArray(0), ByteArray(0)), 4096))
        // our own compression must be decodable with the same dictionary
        val (codec, z) = Z.pack(g["plain"]!!, dict)
        assertEquals(T.CODEC_ZSTD, codec)
        assertArrayEquals(g["plain"], Z.unpack(codec, z, dict, 4096))
    }

    @Test fun push() {
        assertEquals(PushMsg(T.SERVICE_WHATSAPP, 300, 2, "Family", "Alex", T.KIND_IMAGE, "Look at this 📷"), PushMsg.decode(g["push"]!!))
        assertEquals(PushMsg(T.SERVICE_SIGNAL, 301, 3, "Sam", "", T.KIND_TEXT, "hi"), PushMsg.decode(g["push_signal"]!!))
    }

    @Test fun states() {
        assertEquals(Pair(T.WA_CONNECTED, T.WA_OFF), T.states(g["states_wa2_sig5"]!![0].toInt() and 0xff))
    }

    @Test fun rotation() {
        assertArrayEquals(g["rotated_dh5"], Crypto.rotate(g["key"]!!, ByteArray(32) { 5 }))
    }
}
