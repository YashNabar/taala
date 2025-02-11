package keystore.entry

import jakarta.persistence.Entity
import javax.crypto.SecretKey

@Entity
class SecretKeyEntry(
    alias: String,
    secretKey: SecretKey
) : KeyStoreEntry(alias, privateKey = null, chain = null, secretKey.encoded, secretKey.algorithm)
