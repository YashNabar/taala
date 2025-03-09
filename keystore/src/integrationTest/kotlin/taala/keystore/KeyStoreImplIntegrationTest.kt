package taala.keystore

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.crypto.KeyGenerator
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
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper

class KeyStoreImplIntegrationTest {
    @BeforeEach
    fun setUp() {
        alias = UUID.randomUUID().toString()
    }

    @Nested
    inner class SetCertificateEntryTests {
        @Test
        fun `given certificate with new alias, when engineSetCertificateEntry, then assigns certificate to alias`() {
            keyStore.engineSetCertificateEntry(alias, newCertificate)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(TrustedCertificateEntry::class.java, alias)
                CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertPath(ByteArrayInputStream(entity.chain))
                    .certificates.first()
            }

            assertThat(result).isEqualTo(newCertificate)
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
                keyStore.engineSetCertificateEntry(alias, newCertificate)
            }

            assertThat(ex).hasMessageContaining("Failed to save certificate entry")
        }

        @Test
        fun `given certificate with alias exists, when engineSetCertificateEntry, then overwrites existing certificate`() {
            keyStore.engineSetCertificateEntry(alias, existingCertificate)

            keyStore.engineSetCertificateEntry(alias, newCertificate)

            val result = HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val entity = session.get(TrustedCertificateEntry::class.java, alias)
                CertificateFactory.getInstance(CERTIFICATE_TYPE)
                    .generateCertPath(ByteArrayInputStream(entity.chain))
                    .certificates.first()
            }
            assertThat(result).isEqualTo(newCertificate)
        }
    }

    @Nested
    inner class GetCertificateTests {
        @Test
        fun `given certificate exists, when engineGetCertificate, then returns certificate`() {
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(TrustedCertificateEntry(alias, newCertificate))
                tx.commit()
            }

            val result = keyStore.engineGetCertificate(alias)

            assertThat(result).isEqualTo(newCertificate)
        }

        @Test
        fun `given certificate chain exists for private key, when engineGetCertificate, then returns first certificate`() {
            val keyPair = privateKeyFactory.genKeyPair()
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(PrivateKeyEntry(alias, privateKey = keyPair.private, chain = listOf(existingCertificate, newCertificate)))
                tx.commit()
            }

            val result = keyStore.engineGetCertificate(alias)

            assertThat(result).isEqualTo(existingCertificate)
        }
    }

    @Nested
    inner class IsCertificateEntryTests {
        @Test
        fun `given certificate exists for alias, when engineIsCertificateEntry, then returns true`() {
            HibernateHelper.buildSessionFactory(dataSource).openSession().use { session ->
                val tx = session.beginTransaction()
                session.persist(TrustedCertificateEntry(alias, newCertificate))
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
        val existingCertificate = readTestCertificate("test-certificate-1.pem")
        val newCertificate = readTestCertificate("test-certificate-2.pem")

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