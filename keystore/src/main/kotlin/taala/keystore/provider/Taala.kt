package taala.keystore.provider

import java.security.Provider
import javax.sql.DataSource
import taala.keystore.KeyStoreImpl

class Taala(
    private val dataSource: DataSource
) : Provider(
    "Taala",
    "0.1.0",
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
