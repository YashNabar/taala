package taala.persistence.entry

import jakarta.persistence.Entity
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

@Entity
class PrivateKeyEntry(
    alias: String,
    privateKey: PrivateKey,
    chain: List<Certificate>
) : KeyStoreEntry(
    alias,
    privateKey.encoded,
    CertificateFactory.getInstance(chain.first().type).generateCertPath(chain).encoded,
    secretKey = null,
    privateKey.algorithm
)
