package taala.persistence.entry

import jakarta.persistence.Entity
import taala.crypto.EncryptionOperations.unwrap
import taala.crypto.EncryptionOperations.wrap
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec

@Entity
@Suppress("LongParameterList")
class PrivateKeyEntry private constructor(
    alias: String,
    privateKey: ByteArray,
    chain: ByteArray,
    certificateType: String,
    algorithm: String,
    salt: ByteArray?,
    iv: ByteArray?,
) : KeyStoreEntry(
    alias = alias,
    privateKey = privateKey,
    chain = chain,
    secretKey = null,
    certificateType = certificateType,
    keyType = algorithm,
    salt = salt,
    iv = iv,
) {
    override fun retrieveKey(password: CharArray?): Key {
        val keyBytes = password?.let { unwrap(privateKey!!, salt!!, iv!!, password) } ?: privateKey
        return KeyFactory.getInstance(keyType).generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    companion object {
        fun new(alias: String, privateKey: PrivateKey, chain: List<Certificate>, password: CharArray? = null): PrivateKeyEntry {
            return if (password == null) {
                plain(alias, privateKey, chain)
            } else {
                wrapped(alias, privateKey, chain, password)
            }
        }

        private fun plain(
            alias: String,
            privateKey: PrivateKey,
            chain: List<Certificate>,
        ): PrivateKeyEntry {
            val certificateType = chain.first().type

            return PrivateKeyEntry(
                alias = alias,
                privateKey = privateKey.encoded,
                chain = CertificateFactory.getInstance(certificateType).generateCertPath(chain).encoded,
                certificateType = certificateType,
                algorithm = privateKey.algorithm,
                salt = null,
                iv = null,
            )
        }

        private fun wrapped(
            alias: String,
            privateKey: PrivateKey,
            chain: List<Certificate>,
            password: CharArray,
        ): PrivateKeyEntry {
            val protectedKey = wrap(privateKey, password)

            val certificateType = chain.first().type

            return PrivateKeyEntry(
                alias = alias,
                privateKey = protectedKey.wrappedKey,
                chain = CertificateFactory.getInstance(certificateType).generateCertPath(chain).encoded,
                certificateType = certificateType,
                algorithm = privateKey.algorithm,
                salt = protectedKey.salt,
                iv = protectedKey.iv,
            )
        }
    }
}
