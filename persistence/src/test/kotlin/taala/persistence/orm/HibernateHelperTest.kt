package taala.persistence.orm

import org.assertj.core.api.Assertions.assertThat
import org.hibernate.SessionFactory
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test

class HibernateHelperTest {

    @Test
    fun `session factory can open a session`() {
        sessionFactory.openSession().use { session ->
            assertThat(session.isOpen).isTrue()
        }
    }

    private companion object {
        lateinit var sessionFactory: SessionFactory

        @JvmStatic
        @BeforeAll
        fun setUp() {
            sessionFactory = HibernateHelper.sessionFactory
        }
    }
}
