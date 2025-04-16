package taala.keystore.provider

import java.security.Provider
import javax.sql.DataSource
import taala.keystore.KeyStoreImpl

/**
 * Taala is a custom [java.security.Provider] implementation that registers a
 * database-backed JCA [java.security.KeyStore] implementation.
 *
 * This provider enables Java applications to persist cryptographic material
 * — such as private keys, secret keys, and certificates — to a relational database,
 * as opposed to traditional file-based formats like JKS or PKCS12.
 *
 * Taala integrates with the standard JCA `KeyStore` API, allowing
 * applications to interact with it as they would with any other keystore type.
 *
 * Supported key and certificate types:
 * - X.509 Certificates
 * - RSA Private Keys
 * - AES Secret Keys
 *
 * Example usage:
 * ```
 * Taala provider = new Taala(myDataSource);
 * Security.addProvider(provider);
 *
 * KeyStore ks = KeyStore.getInstance("TaalaKeyStore", "Taala");
 * ks.load(null, null);
 * ```
 *
 * @param dataSource the [javax.sql.DataSource] to persist and retrieve key store entries from.
 */
class Taala(
    private val dataSource: DataSource
) : Provider(
    "Taala",
    "1.0.0",
    "A database-backed implementation provider of the Java cryptographic key store."
) {
    init {
        putService(object : Service(
            this,
            "KeyStore",
            "TaalaKeyStore",
            "taala.keystore.KeyStoreImpl",
            null,
            null
        ) {
            override fun newInstance(constructorParameter: Any?) = KeyStoreImpl(dataSource)
        })
    }
}
