package taala.persistence.orm

import java.security.KeyStoreException
import javax.sql.DataSource
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.boot.registry.StandardServiceRegistryBuilder
import org.hibernate.cfg.Configuration
import org.slf4j.LoggerFactory
import taala.persistence.entry.KeyStoreEntry
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
import taala.persistence.entry.TrustedCertificateEntry

object HibernateHelper {
    fun buildSessionFactory(datasource: DataSource): SessionFactory {
        return StandardServiceRegistryBuilder().applySettings(getDbProperties(datasource)).build().run {
            Configuration()
                .addAnnotatedClass(KeyStoreEntry::class.java)
                .addAnnotatedClass(PrivateKeyEntry::class.java)
                .addAnnotatedClass(SecretKeyEntry::class.java)
                .addAnnotatedClass(TrustedCertificateEntry::class.java)
                .buildSessionFactory(this)
        }
    }

    /**
     * Executes the specified [block] within a database transaction.
     * Commits the transaction upon successful completion, then closes the connection.
     *
     * If an error occurs during the execution of [block], the transaction is rolled back
     * instead of being committed.
     *
     * @return The result of executing [block].
     */
    @Suppress("TooGenericExceptionCaught")
    fun <T> SessionFactory.withTransaction(block: (Session) -> T): T {
        val session = openSession()
        val transaction = session.beginTransaction()
        return try {
            val result = block(session)
            transaction.commit()
            result
        } catch (e: KeyStoreException) {
            logger.atError().log { "Operation failed. Cause: $e" }
            if (transaction.isActive) {
                logger.atTrace().log { "Rolling back transaction." }
                transaction.rollback()
            }
            throw e
        } catch (e: Throwable) {
            logger.atError().log { "Operation failed due to an unexpected error. Cause: $e" }
            if (transaction.isActive) {
                logger.atTrace().log { "Rolling back transaction." }
                transaction.rollback()
            }
            throw KeyStoreException("Operation failed due to an unexpected error. Check logs for more information.")
        } finally {
            if (session.isOpen) {
                session.close()
            }
        }
    }

    private fun getDbProperties(datasource: DataSource) = mapOf(
        "hibernate.connection.datasource" to datasource,
        "hibernate.hbm2ddl.auto" to "update"
    )

    private val logger = LoggerFactory.getLogger("taala.persistence.orm.HibernateHelper")
}
