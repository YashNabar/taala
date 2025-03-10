package taala.persistence.orm

import javax.sql.DataSource
import org.hibernate.SessionFactory
import org.hibernate.boot.registry.StandardServiceRegistryBuilder
import org.hibernate.cfg.Configuration
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

    private fun getDbProperties(datasource: DataSource) = mapOf(
        "hibernate.connection.datasource" to datasource,
        "hibernate.hbm2ddl.auto" to "update"
    )
}
