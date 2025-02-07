package keystore.entry

import javax.crypto.SecretKey
import javax.persistence.Entity
import keystore.entity.KeyStoreEntity

@Entity
class SecretKeyEntry(
    alias: String,
    secretKey: SecretKey
) : KeyStoreEntity(alias, privateKey = null, chain = null, secretKey, secretKey.algorithm) {

    override fun equals(other: Any?): Boolean {
        if (other === this) return true
        if (other == null) return false
        if (other !is SecretKeyEntry) return false
        return other.alias == this.alias
                && other.secretKey == this.secretKey
    }

    override fun hashCode(): Int {
        var result = alias.hashCode()
        result = 31 * result + secretKey!!.hashCode()
        return result
    }
}
