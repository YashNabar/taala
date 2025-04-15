package taala.keystore

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import taala.keystore.provider.Taala
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper
import taala.persistence.orm.HibernateHelper.withTransaction

class KeyStoreImplIntegrationTest {
    @BeforeEach
    fun setUp() {
        alias = UUID.randomUUID().toString()
    }

    @Test
    fun `given provider, when register provider and load keystore, then initializes keystore for use`() {
        val provider = Taala(dataSource)
        Security.addProvider(provider)

        val ks = KeyStore.getInstance("TaalaKeyStore", "Taala")
        ks.load(null, null)

        ks.setCertificateEntry(alias, testCertificateB)
        val result = ks.getCertificate(alias)
        assertThat(result).isEqualTo(testCertificateB)
    }

    @Nested
    inner class SetCertificateEntryTests {
        @Test
        fun `given certificate with new alias, when engineSetCertificateEntry, then assigns certificate to alias`() {
            keyStore.engineSetCertificateEntry(alias, testCertificateB)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(TrustedCertificateEntry::class.java, alias)
                CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertPath(ByteArrayInputStream(entity.chain))
                    .certificates.first()
            }

            assertThat(result).isEqualTo(testCertificateB)
        }

        @Test
        fun `given alias assigned to different entity, when engineSetCertificateEntry, then throws exception`() {
            val someKey = secretKeyFactory.generateKey()
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val transaction = session.beginTransaction()
                session.persist(SecretKeyEntry(alias, someKey))
                transaction.commit()
            }

            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetCertificateEntry(alias, testCertificateB)
            }

            assertThat(ex).hasMessageContaining("Failed to save certificate entry")
        }

        @Test
        fun `given certificate with alias exists, when engineSetCertificateEntry, then overwrites existing certificate`() {
            keyStore.engineSetCertificateEntry(alias, testCertificateA)

            keyStore.engineSetCertificateEntry(alias, testCertificateB)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(TrustedCertificateEntry::class.java, alias)
                CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertPath(ByteArrayInputStream(entity.chain))
                    .certificates.first()
            }
            assertThat(result).isEqualTo(testCertificateB)
        }
    }

    @Nested
    inner class GetCertificateTests {
        @Test
        fun `given certificate exists, when engineGetCertificate, then returns certificate`() {
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(TrustedCertificateEntry(alias, testCertificateB))
                tx.commit()
            }

            val result = keyStore.engineGetCertificate(alias)

            assertThat(result).isEqualTo(testCertificateB)
        }

        @Test
        fun `given certificate chain exists for private key, when engineGetCertificate, then returns first certificate`() {
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(PrivateKeyEntry(alias, privateKey = testPrivateKey, chain = listOf(testCertificateA, testCertificateB)))
                tx.commit()
            }

            val result = keyStore.engineGetCertificate(alias)

            assertThat(result).isEqualTo(testCertificateA)
        }
    }

    @Nested
    inner class GetCertificateChainTests {
        @Test
        fun `given certificate chain exists for private key, when engineGetCertificateChain, then returns certificate chain`() {
            val chain = listOf(testCertificateA, testCertificateB)
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(PrivateKeyEntry(alias, privateKey = testPrivateKey, chain = chain))
                tx.commit()
            }

            val result = keyStore.engineGetCertificateChain(alias)

            assertThat(result).isEqualTo(chain.toTypedArray())
        }
    }

    @Nested
    inner class IsCertificateEntryTests {
        @Test
        fun `given certificate exists for alias, when engineIsCertificateEntry, then returns true`() {
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(TrustedCertificateEntry(alias, testCertificateB))
                tx.commit()
            }

            val result = keyStore.engineIsCertificateEntry(alias)

            assertThat(result).isTrue()
        }

        @Test
        fun `given certificate does not exist for alias, when engineIsCertificateEntry, then returns false`() {
            val result = keyStore.engineIsCertificateEntry(alias = "non-existent")

            assertThat(result).isFalse()
        }
    }

    @Nested
    inner class SetKeyEntryTests {
        @Test
        fun `given secret key with new alias, when engineSetKeyEntry, then assigns secret key to alias`() {
            keyStore.engineSetKeyEntry(alias, testSecretKey, null, null)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(SecretKeyEntry::class.java, alias)
                SecretKeySpec(entity.secretKey, SECRET_KEY_TYPE)
            }

            assertThat(result).isEqualTo(testSecretKey)
        }

        @Test
        fun `given private key with new alias, when engineSetKeyEntry, then assigns private key to alias`() {
            keyStore.engineSetKeyEntry(alias, testPrivateKey, null, listOf(testCertificateB).toTypedArray())

            val (key, chain) = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(PrivateKeyEntry::class.java, alias)
                val key = KeyFactory.getInstance(PRIVATE_KEY_TYPE).generatePrivate(PKCS8EncodedKeySpec(entity.privateKey))
                val chain = certificateFactory.generateCertPath(ByteArrayInputStream(entity.chain)).certificates
                key to chain
            }

            assertThat(key).isEqualTo(testPrivateKey)
            assertThat(chain).isEqualTo(listOf(testCertificateB))
        }

        @Test
        fun `given alias assigned to different entity, when engineSetKeyEntry, then throws exception`() {
            HibernateHelper.buildSessionFactory(dataSource).withTransaction { session ->
                session.persist(TrustedCertificateEntry(alias, testCertificateA))
            }

            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetKeyEntry(alias, testSecretKey, null, null)
            }

            assertThat(ex).hasMessageContaining("Failed to save key entry")
        }

        @Test
        fun `given key with alias exists, when engineSetKeyEntry, then overwrites existing key`() {
            keyStore.engineSetKeyEntry(alias, testPrivateKey, null, listOf(testCertificateB).toTypedArray())

            keyStore.engineSetKeyEntry(alias, testSecretKey, null, null)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(SecretKeyEntry::class.java, alias)
                SecretKeySpec(entity.secretKey, SECRET_KEY_TYPE)
            }
            assertThat(result).isEqualTo(testSecretKey)
        }
    }

    @Nested
    inner class GetKeyTests {
        @Test
        fun `given secret key exists, when engineGetKey, then returns secret key`() {
            HibernateHelper.buildSessionFactory(dataSource).withTransaction { session ->
                session.persist(SecretKeyEntry(alias, testSecretKey))
            }

            val result = keyStore.engineGetKey(alias, null)

            assertThat(result).isEqualTo(testSecretKey)
        }

        @Test
        fun `given private key exists, when engineGetKey, then returns private key`() {
            HibernateHelper.buildSessionFactory(dataSource).withTransaction { session ->
                session.persist(PrivateKeyEntry(alias, testPrivateKey, listOf(testCertificateA)))
            }

            val result = keyStore.engineGetKey(alias, null)

            assertThat(result).isEqualTo(testPrivateKey)
        }
    }

    @Nested
    inner class IsKeyEntryTests {
        @Test
        fun `given secret key exists for alias, when engineIsKeyEntry, then returns true`() {
            HibernateHelper.buildSessionFactory(dataSource).withTransaction { session ->
                session.persist(SecretKeyEntry(alias, testSecretKey))
            }

            val result = keyStore.engineIsKeyEntry(alias)

            assertThat(result).isTrue()
        }

        @Test
        fun `given private key exists for alias, when engineIsKeyEntry, then returns true`() {
            HibernateHelper.buildSessionFactory(dataSource).withTransaction { session ->
                session.persist(PrivateKeyEntry(alias, testPrivateKey, listOf(testCertificateA)))
            }

            val result = keyStore.engineIsKeyEntry(alias)

            assertThat(result).isTrue()
        }

        @Test
        fun `given key does not exist for alias, when engineIsKeyEntry, then returns false`() {
            val result = keyStore.engineIsKeyEntry(alias = "non-existent")

            assertThat(result).isFalse()
        }
    }

    private companion object {
        const val CERTIFICATE_TYPE = "X.509"
        const val SECRET_KEY_TYPE = "AES"
        const val PRIVATE_KEY_TYPE = "RSA"

        lateinit var dataSource: DataSource
        lateinit var keyStore: KeyStoreImpl
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
            dataSource = HikariDataSource(
                HikariConfig().apply {
                    jdbcUrl = database.jdbcUrl
                    username = database.username
                    password = database.password
                }
            )
            keyStore = KeyStoreImpl(dataSource)
        }

        @AfterAll
        @JvmStatic
        fun tearDown() {
            database.stop()
        }
    }
}
