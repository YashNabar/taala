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
import java.sql.SQLException
import org.assertj.core.api.SoftAssertions.assertSoftly
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.Transaction
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper

class KeyStoreImplTest {
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
                val certFromChain = certificateFactory.generateCertPath(ByteArrayInputStream(this.chain)).certificates.single()
                softly.assertThat(certFromChain).isEqualTo(newCertificate)
                softly.assertThat(this.type).isEqualTo(CERTIFICATE_TYPE)
                softly.assertThat(this.secretKey).isNull()
                softly.assertThat(this.privateKey).isNull()
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
                val certFromChain = certificateFactory.generateCertPath(ByteArrayInputStream(this.chain)).certificates.single()
                softly.assertThat(certFromChain).isEqualTo(newCertificate)
                softly.assertThat(this.type).isEqualTo(CERTIFICATE_TYPE)
                softly.assertThat(this.secretKey).isNull()
                softly.assertThat(this.privateKey).isNull()
            }
        }
    }

    @Test
    fun `given persistence fails, when engineSetCertificateEntry, then throws exception`() {
        val alias = "test"
        every { session.get(TrustedCertificateEntry::class.java, alias) } returns null
        every { session.persist(any()) } throws SQLException()

        val ex = assertThrows<KeyStoreException> {
            keyStore.engineSetCertificateEntry(alias, newCertificate)
        }
        assertSoftly { softly ->
            softly.assertThat(ex).hasMessageContaining("Failed to save certificate entry")
            verify { tx.rollback() }
        }
    }

    @Test
    fun `given alias is null, when engineSetCertificateEntry, then throws exception`() {
        val ex = assertThrows<KeyStoreException> {
            keyStore.engineSetCertificateEntry(alias = null, newCertificate)
        }
        assertSoftly { softly ->
            softly.assertThat(ex).hasMessageContaining("Alias was null")
        }
    }

    @Test
    fun `given certificate is null, when engineSetCertificateEntry, then throws exception`() {
        val ex = assertThrows<KeyStoreException> {
            keyStore.engineSetCertificateEntry(KNOWN_ALIAS, cert = null)
        }
        assertSoftly { softly ->
            softly.assertThat(ex).hasMessageContaining("Certificate was null")
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
        }
        val session = mockk<Session> {
            every { beginTransaction() } returns tx
            every { merge<TrustedCertificateEntry>(any()) } returns mockk()
            every { close() } just Runs
        }
        val sessionFactory = mockk<SessionFactory> {
            every { openSession() } returns session
        }
        lateinit var keyStore: KeyStoreImpl

        @JvmStatic
        @BeforeAll
        fun setUp() {
            keyStore = KeyStoreImpl()
            mockkObject(HibernateHelper)
            every { HibernateHelper.sessionFactory } returns sessionFactory
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
