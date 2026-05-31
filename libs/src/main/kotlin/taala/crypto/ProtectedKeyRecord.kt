package taala.crypto

data class ProtectedKeyRecord(
    val wrappedKey: ByteArray,
    val salt: ByteArray,
    val iv: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ProtectedKeyRecord

        if (!wrappedKey.contentEquals(other.wrappedKey)) return false
        if (!salt.contentEquals(other.salt)) return false
        if (!iv.contentEquals(other.iv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = wrappedKey.contentHashCode()
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }
}
