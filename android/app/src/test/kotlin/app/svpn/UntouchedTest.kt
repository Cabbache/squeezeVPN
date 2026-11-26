package app.svpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UntouchedTest {
    private val decrypt = setOf("com.example.browser")

    @Test fun browserIsDecrypted() = assertFalse(Vpn.untouched(arrayOf("com.example.browser"), decrypt))

    @Test fun otherAppsAreUntouched() = assertTrue(Vpn.untouched(arrayOf("com.bank.app"), decrypt))

    // apps sharing one uid: decrypted if any of them is set to be
    @Test fun sharedUid() = assertFalse(Vpn.untouched(arrayOf("com.bank.app", "com.example.browser"), decrypt))

    @Test fun unknownUidIsUntouched() = assertTrue(Vpn.untouched(null, decrypt))
}
