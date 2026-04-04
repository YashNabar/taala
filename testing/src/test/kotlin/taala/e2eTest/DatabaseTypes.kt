package taala.e2eTest

import org.testcontainers.cockroachdb.CockroachContainer
import org.testcontainers.containers.JdbcDatabaseContainer
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName

object DatabaseTypes {
    data class TestDatabase(
        val name: String,
        val version: String,
        val containerProvider: JdbcDatabaseContainer<*>
    ) {
        override fun toString(): String = "$name:$version"
    }

    internal fun postgresVersions(vararg versions: String) =
        versions.map {
            TestDatabase(
                name = "Postgres",
                version = it,
                containerProvider = PostgreSQLContainer(DockerImageName.parse("postgres:$it"))
            )
        }

    internal fun cockroachVersions(vararg versions: String) =
        versions.map {
            TestDatabase(
                name = "Cockroach",
                version = it,
                containerProvider = CockroachContainer("cockroachdb/cockroach:$it")
            )
        }
}
