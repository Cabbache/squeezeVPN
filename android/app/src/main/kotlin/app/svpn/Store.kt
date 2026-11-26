package app.svpn

import java.io.File

/** One chat: the canonical record stream (byte-identical to the server's) plus decoded view. */
class PChat(val idx: Int, var name: String, var service: Int = T.SERVICE_WHATSAPP) {
    var stream = ByteArray(0)
    val pos = ChatPos()
    val senders = ArrayList<String>() // per-chat sender index i+1
    val msgs = ArrayList<Record.Msg>()
    var unread = 0

    fun senderName(i: Long) = if (i == 0L) "me" else senders.getOrNull(i.toInt() - 1) ?: "?"

    /** Appends canonical bytes (already validated by decoding). */
    fun absorb(recs: List<Record>) {
        for (r in recs) when (r) {
            is Record.Sender -> senders.add(r.name)
            is Record.Msg -> msgs.add(r)
        }
    }
}

/**
 * Local copy of the shared knowledge:
 *   files/chats/<idx>.bin  canonical record streams
 *   files/names.bin        chat-name table (same bytes as the server's names_table)
 *   files/services.bin     each chat's service, one byte per chat (missing = WhatsApp)
 *   files/dicts/<id>.bin   dictionaries received during Sync
 */
class PhoneStore(private val dir: File) {
    val chats = ArrayList<PChat>()
    private val dicts = HashMap<Long, ByteArray>()

    init {
        File(dir, "chats").mkdirs()
        File(dir, "dicts").mkdirs()
        File(dir, "media").mkdirs()
        val names = File(dir, "names.bin")
        val services = File(dir, "services.bin").takeIf { it.exists() }?.readBytes() ?: ByteArray(0)
        if (names.exists()) {
            val rd = Rd(names.readBytes())
            while (!rd.eof()) {
                val c = PChat(chats.size, rd.str(), services.getOrElse(chats.size) { 0 }.toInt())
                val f = chatFile(c.idx)
                if (f.exists()) {
                    val bytes = f.readBytes()
                    try {
                        c.absorb(c.pos.decodeAll(bytes))
                        c.stream = bytes
                    } catch (e: Exception) { // corrupt: start over for this chat
                        f.delete()
                        c.pos.seq = 0; c.pos.ts = 0; c.pos.senders = 0
                        c.senders.clear(); c.msgs.clear()
                    }
                }
                chats.add(c)
            }
        }
    }

    private fun chatFile(idx: Int) = File(dir, "chats/$idx.bin")
    fun mediaFile(seq: Long) = File(dir, "media/$seq")

    fun namesTable(n: Int): ByteArray {
        val b = Buf()
        chats.take(n).forEach { b.str(it.name) }
        return b.toBytes()
    }

    private fun saveNames() {
        File(dir, "names.bin").writeBytes(namesTable(chats.size))
        File(dir, "services.bin").writeBytes(ByteArray(chats.size) { chats[it].service.toByte() })
    }

    /** Learns chat names and services (SUMMARY / Sync). Indices must arrive contiguously. */
    fun setName(idx: Int, name: String, service: Int) {
        if (idx < chats.size) chats[idx].apply { this.name = name; this.service = service }
        else if (idx == chats.size) chats.add(PChat(idx, name, service))
        else return
        saveNames()
    }

    /** Appends canonical record bytes received for a chat (decoding validates them). */
    fun append(c: PChat, bytes: ByteArray) {
        if (bytes.isEmpty()) return
        val recs = c.pos.decodeAll(bytes)
        c.absorb(recs)
        c.stream += bytes
        chatFile(c.idx).appendBytes(bytes)
    }

    /** Replaces a chat's history from scratch (Sync with base 0). */
    fun replace(c: PChat, bytes: ByteArray) {
        val pos = ChatPos()
        val recs = pos.decodeAll(bytes)
        c.pos.seq = pos.seq; c.pos.ts = pos.ts; c.pos.senders = pos.senders
        c.senders.clear(); c.msgs.clear()
        c.absorb(recs)
        c.stream = bytes
        chatFile(c.idx).writeBytes(bytes)
    }

    fun dict(id: Long): ByteArray? = if (id == 0L) ByteArray(0) else dicts.getOrPut(id) {
        File(dir, "dicts/$id.bin").takeIf { it.exists() }?.readBytes() ?: return null
    }

    fun saveDict(id: Long, d: ByteArray) {
        File(dir, "dicts/$id.bin").writeBytes(d)
        dicts[id] = d
    }
}
