package keystore.entry

import java.security.PrivateKey
import java.security.cert.Certificate
import javax.persistence.Entity

@Entity
class PrivateKeyEntry(
    alias: String,
    privateKey: PrivateKey,
    chain: List<Certificate>
) : KeyStoreEntry(alias, privateKey, chain, secretKey = null, privateKey.algorithm) {

    override fun equals(other: Any?): Boolean {
        if (other === this) return true
        if (other == null) return false
        if (other !is PrivateKeyEntry) return false
        return other.alias == this.alias
                && other.privateKey == this.privateKey
                && other.chain == this.chain
    }

    override fun hashCode(): Int {
        var result = alias.hashCode()
        result = 31 * result + privateKey!!.hashCode()
        result = 31 * result + chain!!.hashCode()
        return result
    }
}
