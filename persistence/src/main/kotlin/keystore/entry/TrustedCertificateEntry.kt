package keystore.entry

import jakarta.persistence.Entity
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

@Entity
class TrustedCertificateEntry(
    alias: String,
    certificate: Certificate
) : KeyStoreEntry(
    alias,
    privateKey = null,
    CertificateFactory.getInstance(certificate.type).generateCertPath(listOf(certificate)).encoded,
    secretKey = null,
    certificate.type
) {

    override fun equals(other: Any?): Boolean {
        if (other === this) return true
        if (other == null) return false
        if (other !is TrustedCertificateEntry) return false
        return other.alias == this.alias
                && other.chain.contentEquals(this.chain)
    }

    override fun hashCode(): Int {
        var result = alias.hashCode()
        result = 31 * result + chain!!.hashCode()
        return result
    }
}
