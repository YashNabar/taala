package taala.persistence.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.Key
import javax.crypto.AEADBadTagException
import javax.crypto.spec.SecretKeySpec

class EncryptionOperationsTest {

    private val password = "correct-horse-battery-staple".toCharArray()

    private fun testKey(): Key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")

    @Test
    fun `wrap generates salt and iv`() {
        val protected = EncryptionOperations.wrap(
            testKey(), password
        )

        assertEquals(16, protected.salt.size)
        assertEquals(12, protected.iv.size)
    }

    @Test
    fun `wrap produces encrypted key different from original key bytes`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        assertFalse(
            protected.wrappedKey.contentEquals(key.encoded)
        )
    }

    @Test
    fun `unwrap recovers original key bytes`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        val unwrapped = EncryptionOperations.unwrap(
            encrypted = protected.wrappedKey, salt = protected.salt, iv = protected.iv, password = password
        )

        assertArrayEquals(
            key.encoded, unwrapped
        )
    }

    @Test
    fun `unwrap fails with incorrect password`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        assertThrows<AEADBadTagException> {
            EncryptionOperations.unwrap(
                encrypted = protected.wrappedKey,
                salt = protected.salt,
                iv = protected.iv,
                password = "wrong-password".toCharArray()
            )
        }
    }

    @Test
    fun `unwrap fails when ciphertext is modified`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        val tampered = protected.wrappedKey.copyOf().apply {
            this[0] = (this[0].toInt() xor 1).toByte()
        }

        assertThrows<AEADBadTagException> {
            EncryptionOperations.unwrap(
                encrypted = tampered, salt = protected.salt, iv = protected.iv, password = password
            )
        }
    }

    @Test
    fun `unwrap fails when salt is modified`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        val tamperedSalt = protected.salt.copyOf().apply {
            this[0] = (this[0].toInt() xor 1).toByte()
        }

        assertThrows<AEADBadTagException> {
            EncryptionOperations.unwrap(
                encrypted = protected.wrappedKey, salt = tamperedSalt, iv = protected.iv, password = password
            )
        }
    }

    @Test
    fun `unwrap fails when iv is modified`() {
        val key = testKey()

        val protected = EncryptionOperations.wrap(
            key, password
        )

        val tamperedIv = protected.iv.copyOf().apply {
            this[0] = (this[0].toInt() xor 1).toByte()
        }

        assertThrows<AEADBadTagException> {
            EncryptionOperations.unwrap(
                encrypted = protected.wrappedKey, salt = protected.salt, iv = tamperedIv, password = password
            )
        }
    }

    @Test
    fun `wrapping same key twice produces different output`() {
        val key = testKey()

        val first = EncryptionOperations.wrap(
            key, password
        )

        val second = EncryptionOperations.wrap(
            key, password
        )

        assertFalse(
            first.wrappedKey.contentEquals(second.wrappedKey)
        )
    }
}
