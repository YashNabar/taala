package taala.e2eTest

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.assertj.core.api.SoftAssertions.assertSoftly
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.containers.JdbcDatabaseContainer
import taala.e2eTest.DatabaseTypes.cockroachVersions
import taala.e2eTest.DatabaseTypes.postgresVersions
import taala.keystore.provider.Taala
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.sql.DataSource

class KeyStoreE2ETest {
    @ParameterizedTest(name = "{0}")
    @MethodSource("getSupportedDatabases")
    fun `test keystore functionality against supported databases`(database: DatabaseTypes.TestDatabase) {
        init(database.containerProvider)

        logger.atInfo().log { "[${database}] Starting test: can store and retrieve certificate from key store" }
        `can store and retrieve certificate from key store`(alias = UUID.randomUUID().toString())

        logger.atInfo().log { "[${database}] Starting test: can store and retrieve private key from key store" }
        `can store and retrieve private key from key store`(alias = UUID.randomUUID().toString())

        logger.atInfo().log { "[${database}] Starting test: can store and retrieve secret key from key store" }
        `can store and retrieve secret key from key store`(alias = UUID.randomUUID().toString())

        logger.atInfo().log { "[${database}] Starting test: can delete all entry types from key store" }
        `can delete all entry types from key store`()

        logger.atInfo().log { "[${database}] Starting test: can check for and retrieve all aliases from key store" }
        `can check for and retrieve all aliases from key store`()
    }

    private fun `can store and retrieve certificate from key store`(alias: String) {
        keyStore.setCertificateEntry(alias, testCertificateB)
        val certificateFromKeyStore = keyStore.getCertificate(alias)

        assertSoftly { softly ->
            softly.assertThat(keyStore.isCertificateEntry(alias)).isTrue()
            softly.assertThat(certificateFromKeyStore).isEqualTo(testCertificateB)
        }
    }

    fun `can store and retrieve private key from key store`(alias: String) {
        val certificateChain = arrayOf(testCertificateA, testCertificateB)

        keyStore.setKeyEntry(alias, testPrivateKey, null, certificateChain)
        val privateKeyFromKeyStore = keyStore.getKey(alias, null)
        val certChainFromKeyStore = keyStore.getCertificateChain(alias)

        assertSoftly { softly ->
            softly.assertThat(keyStore.isKeyEntry(alias)).isTrue()
            softly.assertThat(privateKeyFromKeyStore).isEqualTo(testPrivateKey)
            softly.assertThat(certChainFromKeyStore).isEqualTo(certificateChain)
        }
    }

    fun `can store and retrieve secret key from key store`(alias: String) {
        keyStore.setKeyEntry(alias, testSecretKey, null, null)
        val secretKeyFromKeyStore = keyStore.getKey(alias, null)

        assertSoftly { softly ->
            softly.assertThat(keyStore.isKeyEntry(alias)).isTrue()
            softly.assertThat(secretKeyFromKeyStore).isEqualTo(testSecretKey)
        }
    }

    fun `can check for and retrieve all aliases from key store`() {
        val testAliases = listOf("alias-1", "alias-2", "alias-3")
        keyStore.setKeyEntry(testAliases[0], testSecretKey, null, null)
        keyStore.setKeyEntry(testAliases[1], testPrivateKey, null, arrayOf(testCertificateA))
        keyStore.setCertificateEntry(testAliases[2], testCertificateB)

        assertSoftly { softly ->
            softly.assertThat(keyStore.aliases().toList()).containsAll(testAliases)
            testAliases.forEach { testAlias ->
                softly.assertThat(keyStore.containsAlias(testAlias)).isTrue()
            }
        }
    }

    fun `can delete all entry types from key store`() {
        val testAliases = listOf("alias-A", "alias-B", "alias-C")
        keyStore.setKeyEntry(testAliases[0], testSecretKey, null, null)
        keyStore.setKeyEntry(testAliases[1], testPrivateKey, null, arrayOf(testCertificateA))
        keyStore.setCertificateEntry(testAliases[2], testCertificateB)

        testAliases.forEach { keyStore.deleteEntry(it) }

        assertSoftly { softly ->
            testAliases.forEach { testAlias ->
                softly.assertThat(keyStore.containsAlias(testAlias)).isFalse()
            }
        }
    }

    private fun init(databaseContainer: JdbcDatabaseContainer<*>) {
        databaseContainer.start()
        dataSource = HikariDataSource(
            HikariConfig().apply {
                jdbcUrl = databaseContainer.jdbcUrl
                username = databaseContainer.username
                password = databaseContainer.password
            }
        )
        val provider = Taala(dataSource)
        Security.addProvider(provider)
        keyStore = KeyStore.getInstance("TaalaKeyStore", "Taala")
        keyStore.load(null, null)
    }

    private companion object {
        const val CERTIFICATE_TYPE = "X.509"
        const val SECRET_KEY_TYPE = "AES"
        const val PRIVATE_KEY_TYPE = "RSA"

        lateinit var keyStore: KeyStore
        lateinit var dataSource: DataSource

        val logger: Logger = LoggerFactory.getLogger(this::class.java.enclosingClass)
        val databasesUnderTest = getSupportedDatabases()
        val certificateFactory: CertificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE)
        val secretKeyFactory: KeyGenerator = KeyGenerator.getInstance(SECRET_KEY_TYPE).also { it.init(256) }
        val privateKeyFactory: KeyPairGenerator = KeyPairGenerator.getInstance(PRIVATE_KEY_TYPE).also { it.initialize(2048) }
        val testCertificateA = readTestCertificate("test-certificate-1.pem")
        val testCertificateB = readTestCertificate("test-certificate-2.pem")
        val testSecretKey: SecretKey = secretKeyFactory.generateKey()
        val testPrivateKey: PrivateKey = privateKeyFactory.genKeyPair().private

        fun readTestCertificate(identifier: String): Certificate =
            certificateFactory.generateCertificate(
                ByteArrayInputStream(this::class.java.classLoader.getResource(identifier)!!.readBytes())
            )

        @JvmStatic
        fun getSupportedDatabases() =
            postgresVersions("9.6", "11", "12", "13", "14", "15", "16", "17") + cockroachVersions("v24.3.29", "v25.4.6")

        @AfterAll
        @JvmStatic
        fun tearDown() {
            databasesUnderTest.forEach {
                logger.atInfo().log { "Stopping container $it" }
                it.containerProvider.stop()
            }
        }
    }
}
