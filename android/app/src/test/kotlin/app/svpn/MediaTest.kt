package app.svpn

import org.junit.Assert.assertEquals
import org.junit.Test

class MediaTest {
    @Test fun firstRequest() = assertEquals(0L to 64L, nextRange(emptySet(), -1))

    @Test fun freshStartAndSmallFile() {
        assertEquals(0L to 64L, nextRange(emptySet(), 1000))
        assertEquals(0L to 3L, nextRange(emptySet(), 3))
    }

    @Test fun asksOnlyForTheGap() {
        val have = (0L until 64).toSet() - setOf(10L, 11L)
        assertEquals(10L to 2L, nextRange(have, 1000))
    }

    @Test fun continuesAfterLastWindow() = assertEquals(64L to 64L, nextRange((0L until 64).toSet(), 1000))

    @Test fun lastPartialWindow() = assertEquals(960L to 40L, nextRange((0L until 960).toSet(), 1000))

    @Test fun noSizeLimit() {
        val total = 64L * 40 * 10 // ~29 MB
        assertEquals(total - 64 to 64L, nextRange((0L until total - 64).toSet(), total))
    }
}
