package taala.persistence.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

class ProtectedKeyRecordTest {

    @Test
    fun `records with identical contents are equal and have same hash code`() {
        val first = ProtectedKeyRecord(
            wrappedKey = byteArrayOf(1, 2, 3),
            salt = byteArrayOf(4, 5, 6),
            iv = byteArrayOf(7, 8, 9),
        )

        val second = ProtectedKeyRecord(
            wrappedKey = byteArrayOf(1, 2, 3),
            salt = byteArrayOf(4, 5, 6),
            iv = byteArrayOf(7, 8, 9),
        )

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun `records with different contents are not equal`() {
        val first = ProtectedKeyRecord(
            wrappedKey = byteArrayOf(1, 2, 3),
            salt = byteArrayOf(4, 5, 6),
            iv = byteArrayOf(7, 8, 9),
        )

        assertNotEquals(
            first, first.copy(wrappedKey = byteArrayOf(9, 2, 3))
        )

        assertNotEquals(
            first, first.copy(salt = byteArrayOf(9, 5, 6))
        )

        assertNotEquals(
            first, first.copy(iv = byteArrayOf(9, 8, 9))
        )
    }
}
