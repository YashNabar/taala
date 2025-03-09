package taala.keystore

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreException
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.util.Date
import java.util.Enumeration
import javax.sql.DataSource
import org.hibernate.exception.ConstraintViolationException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper

@Suppress("TooManyFunctions")
class KeyStoreImpl(dataSource: DataSource) : KeyStoreSpi() {
    private val sessionFactory by lazy {
        HibernateHelper.buildSessionFactory(dataSource)
    }

    override fun engineGetKey(alias: String?, password: CharArray?): Key {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificateChain(alias: String?): Array<Certificate> {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificate(alias: String?): Certificate? {
        if (alias == null) return null
        return try {
            sessionFactory.openSession().use { session ->
                val entry = session.get(TrustedCertificateEntry::class.java, alias) ?: session.get(PrivateKeyEntry::class.java, alias)
                entry?.let {
                    CertificateFactory.getInstance(it.certificateType).generateCertPath(ByteArrayInputStream(it.chain)).certificates.first()
                }
            }
        } catch (e: CertificateException) {
            logger.atError().log { "Failed to retrieve certificate with alias '$alias'. Cause: ${e.message}" }
            null
        }
    }

    override fun engineGetCreationDate(alias: String?): Date {
        throw UnsupportedOperationException()
    }

    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    @Suppress("TooGenericExceptionCaught")
    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {
        requireNotNull(alias) { throw KeyStoreException("Alias was null. Certificate entry was not saved.") }
        requireNotNull(cert) { throw KeyStoreException("Certificate was null. Certificate entry was not saved.") }

        val entry = TrustedCertificateEntry(alias, cert)
        sessionFactory.openSession().use { session ->
            val transaction = session.beginTransaction()
            try {
                if (session.get(TrustedCertificateEntry::class.java, alias) == null) {
                    logger.atDebug().log { "Adding new certificate entry to key store under alias '$alias'." }
                    session.persist(entry)
                } else {
                    logger.atDebug().log { "Overwriting existing certificate entry in key store under alias '$alias'." }
                    session.merge(entry)
                }
                transaction.commit()
                logger.atInfo().log { "Saved certificate using alias '$alias'." }
            } catch (e: ConstraintViolationException) {
                transaction.rollback()
                throw KeyStoreException("Failed to save certificate entry. Cause: Alias '$alias' already exists.")
            } catch (e: Exception) {
                transaction.rollback()
                throw KeyStoreException(
                    "An unexpected error occurred while attempting to save certificate entry. Check logs for more information."
                )
            }
        }
    }

    override fun engineDeleteEntry(alias: String?) {
        throw UnsupportedOperationException()
    }

    override fun engineAliases(): Enumeration<String> {
        throw UnsupportedOperationException()
    }

    override fun engineContainsAlias(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineSize(): Int {
        throw UnsupportedOperationException()
    }

    override fun engineIsKeyEntry(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineIsCertificateEntry(alias: String?): Boolean {
        if (alias == null) return false
        val entry = sessionFactory.openSession().use { session ->
            session.get(TrustedCertificateEntry::class.java, alias)
        }
        return entry != null
    }

    override fun engineGetCertificateAlias(cert: Certificate?): String {
        throw UnsupportedOperationException()
    }

    override fun engineStore(stream: OutputStream?, password: CharArray?) {
        throw UnsupportedOperationException()
    }

    override fun engineLoad(stream: InputStream?, password: CharArray?) {
        throw UnsupportedOperationException()
    }

    private companion object {
        val logger: Logger = LoggerFactory.getLogger(this::class.java.enclosingClass)
    }
}