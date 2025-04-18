package taala.keystore

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyFactory
import java.security.KeyStoreException
import java.security.KeyStoreSpi
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.sql.DataSource
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import taala.persistence.entry.KeyStoreEntry
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import taala.persistence.orm.HibernateHelper
import taala.persistence.orm.HibernateHelper.withTransaction

@Suppress("TooManyFunctions")
class KeyStoreImpl(dataSource: DataSource) : KeyStoreSpi() {
    private val sessionFactory = HibernateHelper.buildSessionFactory(dataSource)

    override fun engineGetKey(alias: String?, password: CharArray?): Key? {
        if (alias == null) return null
        return sessionFactory.openSession().use { session ->
            when (val entry = session.get(KeyStoreEntry::class.java, alias)) {
                is SecretKeyEntry -> SecretKeySpec(entry.secretKey, entry.keyType)
                is PrivateKeyEntry -> try {
                    KeyFactory.getInstance(entry.keyType).generatePrivate(PKCS8EncodedKeySpec(entry.privateKey))
                } catch (e: InvalidKeySpecException) {
                    logger.atError().log { "Failed to retrieve key with alias '$alias'. Cause: ${e.message}" }
                    throw UnrecoverableKeyException("Failed to retrieve key with alias '$alias'.")
                }

                else -> null
            }
        }
    }

    override fun engineGetCertificateChain(alias: String?): Array<Certificate>? {
        if (alias == null) return null
        return try {
            sessionFactory.openSession().use { session ->
                when (val entry = session.get(KeyStoreEntry::class.java, alias)) {
                    is PrivateKeyEntry -> {
                        CertificateFactory.getInstance(entry.certificateType)
                            .generateCertPath(ByteArrayInputStream(entry.chain))
                            .certificates.toTypedArray()
                    }

                    else -> null
                }
            }
        } catch (e: CertificateException) {
            logger.atError().log { "Failed to retrieve certificate chain with alias '$alias'. Cause: ${e.message}" }
            null
        }
    }

    override fun engineGetCertificate(alias: String?): Certificate? {
        if (alias == null) return null
        return try {
            sessionFactory.openSession().use { session ->
                when (val entry = session.get(KeyStoreEntry::class.java, alias)) {
                    is TrustedCertificateEntry, is PrivateKeyEntry -> {
                        CertificateFactory.getInstance(entry.certificateType)
                            .generateCertPath(ByteArrayInputStream(entry.chain))
                            .certificates.first()
                    }

                    else -> null
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
        requireNotNull(alias) { throw KeyStoreException("Alias was null. Key entry was not saved.") }
        requireNotNull(key) { throw KeyStoreException("Key was null. Key entry was not saved.") }
        password?.let {
            logger.atWarn().log {
                "Password protection is not currently supported. Key entry with alias '$alias' will not be password-protected."
            }
        }

        val newEntry = when (key) {
            is SecretKey -> SecretKeyEntry(alias, key)
            is PrivateKey -> {
                requireNotNull(chain) { throw KeyStoreException("Certificate chain was null. Private key entry was not saved.") }
                PrivateKeyEntry(alias, key, chain.toList())
            }
            else -> throw UnsupportedOperationException()
        }
        sessionFactory.withTransaction { session ->
            when (val existingEntry = session.get(KeyStoreEntry::class.java, alias)) {
                is SecretKeyEntry, is PrivateKeyEntry -> {
                    logger.atDebug().log { "Overwriting existing key entry in key store under alias '$alias'." }
                    session.remove(existingEntry)
                    session.merge(newEntry)
                }

                null -> {
                    logger.atDebug().log { "Adding new key entry to key store under alias '$alias'." }
                    session.persist(newEntry)
                }

                else -> {
                    throw KeyStoreException("Failed to save key entry. Cause: Alias '$alias' already exists.")
                }
            }
        }
    }

    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {
        requireNotNull(alias) { throw KeyStoreException("Alias was null. Certificate entry was not saved.") }
        requireNotNull(cert) { throw KeyStoreException("Certificate was null. Certificate entry was not saved.") }

        val newEntry = TrustedCertificateEntry(alias, cert)
        sessionFactory.withTransaction { session ->
            when (session.get(KeyStoreEntry::class.java, alias)) {
                is TrustedCertificateEntry -> {
                    logger.atDebug().log { "Overwriting existing certificate entry in key store under alias '$alias'." }
                    session.merge(newEntry)
                }

                null -> {
                    logger.atDebug().log { "Adding new certificate entry to key store under alias '$alias'." }
                    session.persist(newEntry)
                }

                else -> {
                    throw KeyStoreException("Failed to save certificate entry. Cause: Alias '$alias' already exists.")
                }
            }
        }
    }

    override fun engineDeleteEntry(alias: String?) {
        throw UnsupportedOperationException()
    }

    override fun engineAliases(): Enumeration<String> {
        return sessionFactory.openSession().use { session ->
            val cb = session.criteriaBuilder
            val query = cb.createQuery(String::class.java)
            val root = query.from(KeyStoreEntry::class.java)
            query.select(root.get("alias"))

            val aliases = session.createQuery(query).resultList
            Collections.enumeration(aliases)
        }
    }

    override fun engineContainsAlias(alias: String?): Boolean {
        if (alias == null) return false
        val entry = sessionFactory.openSession().use { session ->
            session.get(KeyStoreEntry::class.java, alias)
        }
        return when (entry) {
            is SecretKeyEntry, is PrivateKeyEntry, is TrustedCertificateEntry -> true
            else -> false
        }
    }

    override fun engineSize(): Int {
        return engineAliases().toList().size
    }

    override fun engineIsKeyEntry(alias: String?): Boolean {
        if (alias == null) return false
        val entry = sessionFactory.openSession().use { session ->
            session.get(KeyStoreEntry::class.java, alias)
        }
        return when (entry) {
            is SecretKeyEntry, is PrivateKeyEntry -> true
            else -> false
        }
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
        logger.atDebug().log { "Initialized key store." }
    }

    private companion object {
        val logger: Logger = LoggerFactory.getLogger(this::class.java.enclosingClass)
    }
}
