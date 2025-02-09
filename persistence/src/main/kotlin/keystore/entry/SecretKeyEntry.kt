package keystore.entry

import jakarta.persistence.Entity
import javax.crypto.SecretKey

@Entity
class SecretKeyEntry(
    alias: String,
    secretKey: SecretKey
) : KeyStoreEntry(alias, privateKey = null, chain = null, secretKey.encoded, secretKey.algorithm) {

    override fun equals(other: Any?): Boolean {
        if (other === this) return true
        if (other == null) return false
        if (other !is SecretKeyEntry) return false
        return other.alias == this.alias
                && other.secretKey.contentEquals(this.secretKey)
    }

    override fun hashCode(): Int {
        var result = alias.hashCode()
        result = 31 * result + secretKey!!.hashCode()
        return result
    }
}
