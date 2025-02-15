package taala.persistence.orm

import java.util.Properties
import taala.persistence.entry.KeyStoreEntry
import taala.persistence.entry.PrivateKeyEntry
import taala.persistence.entry.SecretKeyEntry
import taala.persistence.entry.TrustedCertificateEntry
import org.hibernate.SessionFactory
import org.hibernate.boot.registry.StandardServiceRegistryBuilder
import org.hibernate.cfg.Configuration

internal object HibernateHelper {
    val sessionFactory: SessionFactory by lazy {
        StandardServiceRegistryBuilder().applySettings(getDbProperties()).build().run {
            Configuration()
                .addAnnotatedClass(KeyStoreEntry::class.java)
                .addAnnotatedClass(PrivateKeyEntry::class.java)
                .addAnnotatedClass(SecretKeyEntry::class.java)
                .addAnnotatedClass(TrustedCertificateEntry::class.java)
                .buildSessionFactory(this)
        }
    }

    private fun getDbProperties() = Properties().apply {
        setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect")
        setProperty("hibernate.connection.driver_class", "org.h2.Driver")
        setProperty("hibernate.connection.url", "jdbc:h2:mem:keystore")
        setProperty("hibernate.connection.username", "sa")
        setProperty("hibernate.connection.password", "")
        setProperty("hibernate.hbm2ddl.auto", "update")
    }
}
