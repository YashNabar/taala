package taala.persistence.entry

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
    certificate.type,
    keyType = null,
)
