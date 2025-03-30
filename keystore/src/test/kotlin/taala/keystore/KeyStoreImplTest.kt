package taala.keystore

import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.unmockkStatic
import io.mockk.verify
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.SoftAssertions.assertSoftly
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.Transaction
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import taala.persistence.entry.KeyStoreEntry
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
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
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns null
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
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns TrustedCertificateEntry(
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
        fun `given key with alias exists, when engineSetCertificateEntry, then throws exception`() {
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns SecretKeyEntry(
                KNOWN_ALIAS, existingSecretKey
            )

            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetCertificateEntry(KNOWN_ALIAS, newCertificate)
            }
            assertSoftly { softly ->
                softly.assertThat(ex).hasMessageContaining("Failed to save certificate entry")
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
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )

            val result = keyStore.engineGetCertificate(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(existingCertificate)
            }
        }

        @Test
        fun `given unrecoverable certificate, when engineGetCertificate, then returns null`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )
            mockkStatic(CertificateFactory::class)

            val factory = mockk<CertificateFactory>()
            every { CertificateFactory.getInstance(CERTIFICATE_TYPE) } returns factory
            every { factory.generateCertPath(any<InputStream>()) } throws CertificateException()

            val result = keyStore.engineGetCertificate(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }

            unmockkStatic(CertificateFactory::class)
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
    inner class GetCertificateChainTests {
        @Test
        fun `given certificate chain exists for private key, when engineGetCertificateChain, then returns certificate chain`() {
            val chain = listOf(existingCertificate, newCertificate)
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, chain
            )

            val result = keyStore.engineGetCertificateChain(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(chain.toTypedArray())
            }
        }

        @Test
        fun `given unrecoverable certificate, when engineGetCertificateChain, then returns null`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )
            mockkStatic(CertificateFactory::class)

            val factory = mockk<CertificateFactory>()
            every { CertificateFactory.getInstance(CERTIFICATE_TYPE) } returns factory
            every { factory.generateCertPath(any<InputStream>()) } throws CertificateException()

            val result = keyStore.engineGetCertificateChain(KNOWN_ALIAS)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }

            unmockkStatic(CertificateFactory::class)
        }

        @Test
        fun `given alias is null, when engineGetCertificateChain, then returns null`() {
            val result = keyStore.engineGetCertificateChain(alias = null)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }
        }

        @Test
        fun `given alias does not exist, when engineGetCertificateChain, then returns null`() {
            val alias = "unknown"
            every { session.get(KeyStoreEntry::class.java, any()) } returns null

            val result = keyStore.engineGetCertificateChain(alias)

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

    @Nested
    inner class SetKeyEntryTests {
        @BeforeEach
        fun setUpMocks() {
            every { session.persist(any()) } just Runs
        }

        @Test
        fun `given secret key with new alias, when engineSetKeyEntry, then assigns secret key to alias`() {
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns null
            val entryCaptor = slot<SecretKeyEntry>()
            every { session.persist(capture(entryCaptor)) } just Runs

            keyStore.engineSetKeyEntry(KNOWN_ALIAS, newSecretKey, null, null)

            with(entryCaptor.captured) {
                assertSoftly { softly ->
                    softly.assertThat(this.alias).isEqualTo(KNOWN_ALIAS)
                    val key = SecretKeySpec(this.secretKey, SECRET_KEY_TYPE)
                    softly.assertThat(key).isEqualTo(newSecretKey)
                    softly.assertThat(this.keyType).isEqualTo(SECRET_KEY_TYPE)
                    softly.assertThat(this.chain).isNull()
                    softly.assertThat(this.certificateType).isNull()
                    softly.assertThat(this.privateKey).isNull()
                }
            }
        }

        @Test
        fun `given private key with new alias, when engineSetKeyEntry, then assigns private key to alias`() {
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns null
            val entryCaptor = slot<PrivateKeyEntry>()
            every { session.persist(capture(entryCaptor)) } just Runs
            val certChain = listOf(existingCertificate, newCertificate)

            keyStore.engineSetKeyEntry(KNOWN_ALIAS, newPrivateKey, null, certChain.toTypedArray())

            with(entryCaptor.captured) {
                assertSoftly { softly ->
                    softly.assertThat(this.alias).isEqualTo(KNOWN_ALIAS)
                    val capturedKey = KeyFactory.getInstance(PRIVATE_KEY_TYPE).generatePrivate(PKCS8EncodedKeySpec(this.privateKey))
                    softly.assertThat(capturedKey).isEqualTo(newPrivateKey)
                    softly.assertThat(this.keyType).isEqualTo(PRIVATE_KEY_TYPE)
                    val capturedChain = certificateFactory.generateCertPath(ByteArrayInputStream(this.chain)).certificates
                    softly.assertThat(capturedChain).isEqualTo(certChain)
                    softly.assertThat(this.certificateType).isEqualTo(existingCertificate.type)
                    softly.assertThat(this.secretKey).isNull()
                }
            }
        }

        @Test
        fun `given secret key but private key with alias exists, when engineSetKeyEntry, then overwrites existing private key`() {
            val existingEntry = PrivateKeyEntry(KNOWN_ALIAS, newPrivateKey, listOf(newCertificate))
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns existingEntry
            val entryCaptor = slot<SecretKeyEntry>()

            keyStore.engineSetKeyEntry(KNOWN_ALIAS, newSecretKey, null, null)

            verify { session.remove(existingEntry) }
            verify { session.merge(capture(entryCaptor)) }
            with(entryCaptor.captured) {
                assertSoftly { softly ->
                    softly.assertThat(this.alias).isEqualTo(KNOWN_ALIAS)
                    val key = SecretKeySpec(this.secretKey, SECRET_KEY_TYPE)
                    softly.assertThat(key).isEqualTo(newSecretKey)
                    softly.assertThat(this.keyType).isEqualTo(SECRET_KEY_TYPE)
                    softly.assertThat(this.chain).isNull()
                    softly.assertThat(this.privateKey).isNull()
                    softly.assertThat(this.certificateType).isNull()
                }
            }
        }

        @Test
        fun `given certificate with alias exists, when engineSetKeyEntry, then throws exception`() {
            every { session.get(KeyStoreEntry::class.java, KNOWN_ALIAS) } returns TrustedCertificateEntry(
                KNOWN_ALIAS, existingCertificate
            )

            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetKeyEntry(KNOWN_ALIAS, newSecretKey, null, null)
            }
            assertSoftly { softly ->
                softly.assertThat(ex).hasMessageContaining("Failed to save key entry")
            }
        }

        @Test
        fun `given alias is null, when engineSetKeyEntry, then throws exception`() {
            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetKeyEntry(alias = null, newSecretKey, null, null)
            }
            assertThat(ex).hasMessageContaining("Alias was null")
        }

        @Test
        fun `given key is null, when engineSetKeyEntry, then throws exception`() {
            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetKeyEntry(KNOWN_ALIAS, key = null, null, null)
            }
            assertThat(ex).hasMessageContaining("Key was null")
        }

        @Test
        fun `given private key and chain is null, when engineSetKeyEntry, then throws exception`() {
            val ex = assertThrows<KeyStoreException> {
                keyStore.engineSetKeyEntry(KNOWN_ALIAS, newPrivateKey, null, chain = null)
            }
            assertThat(ex).hasMessageContaining("Certificate chain was null")
        }
    }

    @Nested
    inner class GetKeyTests {
        @Test
        fun `given secret key exists, when engineGetKey, then returns secret key`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns SecretKeyEntry(
                KNOWN_ALIAS, existingSecretKey
            )

            val result = keyStore.engineGetKey(KNOWN_ALIAS, null)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(existingSecretKey)
            }
        }

        @Test
        fun `given private key exists, when engineGetKey, then returns private key`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )

            val result = keyStore.engineGetKey(KNOWN_ALIAS, null)

            assertSoftly { softly ->
                softly.assertThat(result).isEqualTo(newPrivateKey)
            }
        }

        @Test
        fun `given unrecoverable private key, when engineGetKey, then throws exception`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )
            mockkStatic(KeyFactory::class)

            val mockKeyFactory = mockk<KeyFactory>()
            every { KeyFactory.getInstance(PRIVATE_KEY_TYPE) } returns mockKeyFactory
            every { mockKeyFactory.generatePrivate(any()) } throws InvalidKeySpecException()

            val ex = assertThrows<UnrecoverableKeyException> {
                keyStore.engineGetKey(KNOWN_ALIAS, null)
            }

            assertSoftly { softly ->
                softly.assertThat(ex).hasMessageContaining("Failed to retrieve key")
            }

            unmockkStatic(KeyFactory::class)
        }

        @Test
        fun `given alias is null, when engineGetKey, then returns null`() {
            val result = keyStore.engineGetKey(alias = null, null)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }
        }

        @Test
        fun `given alias does not exist, when engineGetKey, then returns null`() {
            val alias = "unknown"
            every { session.get(KeyStoreEntry::class.java, any()) } returns null

            val result = keyStore.engineGetKey(alias, null)

            assertSoftly { softly ->
                softly.assertThat(result).isNull()
            }
        }
    }

    @Nested
    inner class IsKeyEntryTests {
        @Test
        fun `given secret key exists for alias, when engineIsKeyEntry, then returns true`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns SecretKeyEntry(
                KNOWN_ALIAS, existingSecretKey
            )

            val result = keyStore.engineIsKeyEntry(KNOWN_ALIAS)

            assertThat(result).isTrue()
        }

        @Test
        fun `given private key exists for alias, when engineIsKeyEntry, then returns true`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns PrivateKeyEntry(
                KNOWN_ALIAS, newPrivateKey, listOf(existingCertificate)
            )

            val result = keyStore.engineIsKeyEntry(KNOWN_ALIAS)

            assertThat(result).isTrue()
        }

        @Test
        fun `given key does not exist for alias, when engineIsKeyEntry, then returns false`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns null

            val result = keyStore.engineIsKeyEntry(KNOWN_ALIAS)

            assertThat(result).isFalse()
        }

        @Test
        fun `given a different entry exists for alias, when engineIsKeyEntry, then returns false`() {
            every { session.get(KeyStoreEntry::class.java, any()) } returns TrustedCertificateEntry(
                KNOWN_ALIAS, existingCertificate
            )

            val result = keyStore.engineIsKeyEntry(KNOWN_ALIAS)

            assertThat(result).isFalse()
        }

        @Test
        fun `given alias is null, when engineIsKeyEntry, then returns false`() {
            val result = keyStore.engineIsKeyEntry(alias = null)

            assertThat(result).isFalse()
        }
    }

    private companion object {
        const val CERTIFICATE_TYPE = "X.509"
        const val SECRET_KEY_TYPE = "AES"
        const val PRIVATE_KEY_TYPE = "RSA"
        const val KNOWN_ALIAS = "test-alias"

        val certificateFactory: CertificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE)
        val existingCertificate = readTestCertificate("test-certificate-1.pem")
        val newCertificate = readTestCertificate("test-certificate-2.pem")
        val secretKeyFactory: KeyGenerator = KeyGenerator.getInstance(SECRET_KEY_TYPE).also { it.init(256) }
        val existingSecretKey: SecretKey = secretKeyFactory.generateKey()
        val newSecretKey: SecretKey = secretKeyFactory.generateKey()
        val privateKeyFactory: KeyPairGenerator = KeyPairGenerator.getInstance(PRIVATE_KEY_TYPE).also { it.initialize(2048) }
        val newPrivateKey: PrivateKey = privateKeyFactory.genKeyPair().private
        val tx = mockk<Transaction> {
            every { commit() } just Runs
            every { rollback() } just Runs
            every { isActive } returns true
        }
        val session = mockk<Session> {
            every { beginTransaction() } returns tx
            every { merge<KeyStoreEntry>(any()) } returns mockk()
            every { remove(any()) } just Runs
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
