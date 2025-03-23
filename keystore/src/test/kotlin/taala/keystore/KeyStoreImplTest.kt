package taala.keystore

import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.ByteArrayInputStream
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import javax.sql.DataSource
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.SoftAssertions.assertSoftly
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.Transaction
import org.hibernate.exception.ConstraintViolationException
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import taala.persistence.entry.KeyStoreEntry
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper

class KeyStoreImplTest {

    @Nested
    inner class SetCertificateEntryTests {
        @BeforeEach
        fun setUpMocks() {
            every { session.persist(any()) } just Runs
        }

        @Test
        fun `given certificate with new alias, when engineSetCertificateEntry, then assigns certificate to alias`() {
            every { session.get(TrustedCertificateEntry::class.java, KNOWN_ALIAS) } returns null
            val entryCaptor = slot<TrustedCertificateEntry>()
            every { session.persist(capture(entryCaptor)) } just Runs

            keyStore.engineSetCertificateEntry(KNOWN_ALIAS, newCertificate)

            with(entryCaptor.captured) {
                assertSoftly { softly ->
                    softly.assertThat(this.alias).isEqualTo(KNOWN_ALIAS)
                    val certFromChain =
                        certificateFactory.generateCertPath(ByteArrayInputStream(this.chain)).certificates.single()
                    softly.assertThat(certFromChain).isEqualTo(newCertificate)
                    softly.assertThat(this.certificateType).isEqualTo(CERTIFICATE_TYPE)
                    softly.assertThat(this.secretKey).isNull()
                    softly.assertThat(this.privateKey).isNull()
                    softly.assertThat(this.keyType).isNull()
                }
            }
        }

        @Test
        fun `given certificate with alias exists, when engineSetCertificateEntry, then overwrites existing certificate`() {
            every { session.get(TrustedCertificateEntry::class.java, KNOWN_ALIAS) } returns TrustedCertificateEntry(
                KNOWN_ALIAS, existingCertificate
            )
            val entryCaptor = slot<TrustedCertificateEntry>()

            keyStore.engineSetCertificateEntry(KNOWN_ALIAS, newCertificate)

            verify { session.merge(capture(entryCaptor)) }
            with(entryCaptor.captured) {
                assertSoftly { softly ->
                    softly.assertThat(this.alias).isEqualTo(KNOWN_ALIAS)
                    val certFromChain =
                        certificateFactory.generateCertPath(ByteArrayInputStream(this.chain)).certificates.single()
                    softly.assertThat(certFromChain).isEqualTo(newCertificate)
                    softly.assertThat(this.certificateType).isEqualTo(CERTIFICATE_TYPE)
                    softly.assertThat(this.secretKey).isNull()
                    softly.assertThat(this.privateKey).isNull()
                    softly.assertThat(this.keyType).isNull()
                }
            }
        }

        @Test
        fun `given persistence fails, when engineSetCertificateEntry, then throws exception`() {
            val alias = "test"
            every { session.get(TrustedCertificateEntry::class.java, alias) } returns null
            every { session.persist(any()) } throws mockk<ConstraintViolationException>()

            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetCertificateEntry(alias, newCertificate)
            }
            assertSoftly { softly ->
                softly.assertThat(ex).hasMessageContaining("Operation failed")
                verify { tx.rollback() }
            }
        }

        @Test
        fun `given alias is null, when engineSetCertificateEntry, then throws exception`() {
            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetCertificateEntry(alias = null, newCertificate)
            }
            assertThat(ex).hasMessageContaining("Alias was null")
        }

        @Test
        fun `given certificate is null, when engineSetCertificateEntry, then throws exception`() {
            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetCertificateEntry(KNOWN_ALIAS, cert = null)
            }
            assertThat(ex).hasMessageContaining("Certificate was null")
        }
    }

    @Nested
    inner class GetCertificateTests {
        @Test
        fun `given certificate exists, when engineGetCertificate, then returns certificate`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns TrustedCertificateEntry(
                KNOWN_ALIAS, existingCertificate
            )

            val result = keyStore.engineGetCertificate(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(existingCertificate)
            }
        }

        @Test
        fun `given certificate chain exists for private key, when engineGetCertificate, then returns first certificate`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, mockk(relaxed = true), listOf(existingCertificate)
            )

            val result = keyStore.engineGetCertificate(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(existingCertificate)
            }
        }

        @Test
        fun `given alias is null, when engineGetCertificate, then returns null`() {
            val result = keyStore.engineGetCertificate(alias = null)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }
        }

        @Test
        fun `given alias does not exist, when engineGetCertificate, then returns null`() {
            val alias = "unknown"
            every { session.get(KeyStoreEntry::class.java, any()) } returns null

            val result = keyStore.engineGetCertificate(alias)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }
        }
    }

    @Nested
    inner class IsCertificateEntryTests {
        @Test
        fun `given certificate exists for alias, when engineIsCertificateEntry, then returns true`() {
            every { session.get(TrustedCertificateEntry::class.java, any()) } returns TrustedCertificateEntry(
                KNOWN_ALIAS, existingCertificate
            )

            val result = keyStore.engineIsCertificateEntry(KNOWN_ALIAS)

            assertThat(result).isTrue()
        }

        @Test
        fun `given certificate does not exist for alias, when engineIsCertificateEntry, then returns false`() {
            every { session.get(TrustedCertificateEntry::class.java, any()) } returns null

            val result = keyStore.engineIsCertificateEntry(KNOWN_ALIAS)

            assertThat(result).isFalse()
        }

        @Test
        fun `given a different entry exists for alias, when engineIsCertificateEntry, then returns false`() {
            every { session.get(TrustedCertificateEntry::class.java, any()) } returns null
            every { session.get(PrivateKeyEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, mockk(relaxed = true), listOf(existingCertificate)
            )

            val result = keyStore.engineIsCertificateEntry(KNOWN_ALIAS)

            assertThat(result).isFalse()
        }

        @Test
        fun `given alias is null, when engineIsCertificateEntry, then returns false`() {
            val result = keyStore.engineIsCertificateEntry(alias = null)

            assertThat(result).isFalse()
        }
    }

    private companion object {
        const val CERTIFICATE_TYPE = "X.509"
        const val KNOWN_ALIAS = "test-alias"

        val certificateFactory: CertificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE)
        val existingCertificate = readTestCertificate("test-certificate-1.pem")
        val newCertificate = readTestCertificate("test-certificate-2.pem")
        val tx = mockk<Transaction> {
            every { commit() } just Runs
            every { rollback() } just Runs
            every { isActive } returns true
        }
        val session = mockk<Session> {
            every { beginTransaction() } returns tx
            every { merge<TrustedCertificateEntry>(any()) } returns mockk()
            every { close() } just Runs
            every { isOpen } returns true
        }
        val sessionFactory = mockk<SessionFactory> {
            every { openSession() } returns session
        }
        val dataSource = mockk<DataSource>()
        lateinit var keyStore: KeyStoreImpl

        @JvmStatic
        @BeforeAll
        fun setUp() {
            keyStore = KeyStoreImpl(dataSource)
            mockkObject(HibernateHelper)
            every { HibernateHelper.buildSessionFactory(any()) } returns sessionFactory
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            unmockkAll()
        }

        fun readTestCertificate(identifier: String): Certificate =
            certificateFactory.generateCertificate(
                ByteArrayInputStream(this::class.java.classLoader.getResource(identifier)!!.readBytes())
            )
    }
}
