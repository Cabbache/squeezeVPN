package app.svpn

/** Chunks asked for per MEDIA request (the server sends at most 64). */
const val MEDIA_WINDOW = 64L

/**
 * The next MEDIA request (from, count): the first run of chunks we don't have, up to the next one we
 * do have, at most [MEDIA_WINDOW]. Lost chunks are asked for again without re-sending the others.
 * `total` < 0: not known yet (first request).
 */
fun nextRange(have: Set<Long>, total: Long): Pair<Long, Long> {
    if (total < 0) return 0L to MEDIA_WINDOW
    var from = 0L
    while (from < total && from in have) from++
    var end = from
    while (end < total && end - from < MEDIA_WINDOW && end !in have) end++
    return from to end - from
}
