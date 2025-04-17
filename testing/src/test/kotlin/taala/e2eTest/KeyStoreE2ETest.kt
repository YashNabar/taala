package taala.e2eTest

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.SoftAssertions.assertSoftly
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import taala.keystore.provider.Taala

class KeyStoreE2ETest {
    @BeforeEach
    fun setUp() {
        alias = UUID.randomUUID().toString()
    }

    @Test
    fun `can store and retrieve certificate from key store`() {
        keyStore.setCertificateEntry(alias, testCertificateB)
        val certificateFromKeyStore = keyStore.getCertificate(alias)

        assertSoftly { softly ->
            softly.assertThat(keyStore.isCertificateEntry(alias)).isTrue()
            softly.assertThat(certificateFromKeyStore).isEqualTo(testCertificateB)
        }
    }

    @Test
    fun `can store and retrieve private key from key store`() {
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

    @Test
    fun `can store and retrieve secret key from key store`() {
        keyStore.setKeyEntry(alias, testSecretKey, null, null)
        val secretKeyFromKeyStore = keyStore.getKey(alias, null)

        assertSoftly { softly ->
            softly.assertThat(keyStore.isKeyEntry(alias)).isTrue()
            softly.assertThat(secretKeyFromKeyStore).isEqualTo(testSecretKey)
        }
    }

    @Test
    fun `can check for and retrieve all aliases from key store`() {
        val testAliases = setOf("one", "two", "three")
        testAliases.forEach { testAlias ->
            keyStore.setKeyEntry(testAlias, testSecretKey, null, null)
        }

        val result = keyStore.aliases()

        assertSoftly { softly ->
            softly.assertThat(result.toList()).containsExactlyInAnyOrderElementsOf(testAliases)
            testAliases.forEach { testAlias ->
                softly.assertThat(keyStore.containsAlias(testAlias)).isTrue()
            }
        }
    }

    private companion object {
        const val CERTIFICATE_TYPE = "X.509"
        const val SECRET_KEY_TYPE = "AES"
        const val PRIVATE_KEY_TYPE = "RSA"

        lateinit var keyStore: KeyStore
        lateinit var alias: String
        val database = PostgreSQLContainer(DockerImageName.parse("postgres:17"))
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
        @BeforeAll
        fun init() {
            database.start()
            val dataSource = HikariDataSource(
                HikariConfig().apply {
                    jdbcUrl = database.jdbcUrl
                    username = database.username
                    password = database.password
                }
            )
            val provider = Taala(dataSource)
            Security.addProvider(provider)
            keyStore = KeyStore.getInstance("TaalaKeyStore", "Taala")
            keyStore.load(null, null)
        }

        @AfterAll
        @JvmStatic
        fun tearDown() {
            database.stop()
        }
    }
}
