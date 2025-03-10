package taala.persistence.entry

import jakarta.persistence.Entity
import javax.crypto.SecretKey

@Entity
class SecretKeyEntry(
    alias: String,
    secretKey: SecretKey
) : KeyStoreEntry(alias, privateKey = null, chain = null, secretKey.encoded, certificateType = null, secretKey.algorithm)
