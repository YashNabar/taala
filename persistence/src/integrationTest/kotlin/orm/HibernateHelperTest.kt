package orm

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import taala.persistence.orm.HibernateHelper

class HibernateHelperTest {

    @Test
    fun `given postgres datasource, when buildSessionFactory, then returns session factory`() {
        val sessionFactory = HibernateHelper.buildSessionFactory(
            HikariDataSource(
                HikariConfig().apply {
                    jdbcUrl = database.jdbcUrl
                    username = database.username
                    password = database.password
                }
            )
        )

        sessionFactory.openSession().use { session ->
            assertThat(session.isOpen).isTrue()
        }
    }

    private companion object {
        val database = PostgreSQLContainer(DockerImageName.parse("postgres:17"))

        @JvmStatic
        @BeforeAll
        fun setUp() {
            database.start()
        }

        @AfterAll
        @JvmStatic
        fun tearDown() {
            database.stop()
        }
    }
}
