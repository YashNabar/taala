package keystore.entry

import java.security.cert.Certificate
import javax.persistence.Entity
import keystore.entity.KeyStoreEntity

@Entity
class TrustedCertificateEntry(
    alias: String,
    certificate: List<Certificate>
) : KeyStoreEntity(alias, privateKey = null, certificate, secretKey = null, certificate.single().type) {

    override fun equals(other: Any?): Boolean {
        if (other === this) return true
        if (other == null) return false
        if (other !is TrustedCertificateEntry) return false
        return other.alias == this.alias
                && other.chain == this.chain
    }

    override fun hashCode(): Int {
        var result = alias.hashCode()
        result = 31 * result + chain!!.hashCode()
        return result
    }
}
