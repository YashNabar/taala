package taala.persistence.entry

import jakarta.persistence.Entity
import taala.persistence.crypto.EncryptionOperations.unwrap
import taala.persistence.crypto.EncryptionOperations.wrap
import java.security.Key
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Entity
class SecretKeyEntry private constructor(
    alias: String,
    secretKey: ByteArray,
    algorithm: String,
    salt: ByteArray?,
    iv: ByteArray?,
) : KeyStoreEntry(
    alias = alias,
    privateKey = null,
    chain = null,
    secretKey = secretKey,
    certificateType = null,
    keyType = algorithm,
    salt = salt,
    iv = iv,
) {
    override fun retrieveKey(password: CharArray?): Key {
        val keyBytes = password?.let { unwrap(secretKey!!, salt!!, iv!!, password) } ?: secretKey
        return SecretKeySpec(keyBytes, keyType)
    }

    companion object {
        fun new(alias: String, secretKey: SecretKey, password: CharArray? = null): SecretKeyEntry {
            return if (password == null) {
                plain(alias, secretKey)
            } else {
                wrapped(alias, secretKey, password)
            }
        }

        private fun wrapped(
            alias: String,
            secretKey: SecretKey,
            password: CharArray,
        ): SecretKeyEntry {
            val wrapped = wrap(secretKey, password)
            return SecretKeyEntry(
                alias = alias,
                secretKey = wrapped.wrappedKey,
                algorithm = secretKey.algorithm,
                salt = wrapped.salt,
                iv = wrapped.iv,
            )
        }

        private fun plain(
            alias: String,
            secretKey: SecretKey,
        ): SecretKeyEntry = SecretKeyEntry(
            alias = alias,
            secretKey = secretKey.encoded,
            algorithm = secretKey.algorithm,
            salt = null,
            iv = null,
        )
    }
}

