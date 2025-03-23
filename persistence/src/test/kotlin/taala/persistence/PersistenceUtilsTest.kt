package taala.persistence

import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import io.mockk.verifyOrder
import java.security.KeyStoreException
import java.sql.SQLException
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.Transaction
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import taala.persistence.orm.HibernateHelper.withTransaction

class PersistenceUtilsTest {
    private val tx = mockk<Transaction> {
        every { commit() } just Runs
        every { rollback() } just Runs
        every { isActive } returns true
    }
    private val session = mockk<Session> {
        every { beginTransaction() } returns tx
        every { close() } just Runs
        every { isOpen } returns true
    }
    private val sessionFactory = mockk<SessionFactory> {
        every { openSession() } returns session
    }

    @Nested
    inner class BlockWithExceptionTests {
        private fun error(): Nothing = throw SQLException("test")

        @Test
        fun `withTransaction rolls back and correctly closes connection`() {
            try {
                sessionFactory.withTransaction { error() }
            } catch (_: Exception) {}

            verify(exactly = 0) { tx.commit() }
            verifyOrder {
                tx.rollback()
                session.close()
            }
        }

        @Test
        fun `withTransaction wraps caught exception in KeyStoreException`() {
            assertThrows<KeyStoreException> {
                sessionFactory.withTransaction { error() }
            }
        }

        @Test
        fun `withTransaction doesn't roll back if the transaction is not active`() {
            every { tx.isActive } returns false

            try {
                sessionFactory.withTransaction { error() }
            } catch (_: Exception) {}

            verify(exactly = 0) { tx.rollback() }
        }
    }

    @Nested
    inner class BlockWithoutExceptionTests {
        @Test
        fun `withTransaction correctly opens transaction and commits after block runs`() {
            val block: () -> Unit = mockk()
            every { block.invoke() } just Runs

            sessionFactory.withTransaction { block() }

            verifyOrder {
                session.beginTransaction()
                block.invoke()
                tx.commit()
            }
        }

        @Test
        fun `withTransaction correctly closes session`() {
            sessionFactory.withTransaction {}

            verifyOrder {
                session.close()
            }
        }

        @Test
        fun `withTransaction doesn't close session if already closed`() {
            every { session.isOpen } returns false

            sessionFactory.withTransaction {}

            verify(exactly = 0) { session.close() }
        }
    }
}
