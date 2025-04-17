plugins {
    id("taala-conventions")
    id("integration-test")
    id("maven-publish")
}

description = "Keystore implementation"
version = rootProject.version

dependencies {
    compileOnly(project(":persistence"))
    implementation(libs.jakarta)
    implementation(libs.hibernate)
    implementation(libs.slf4j.api)

    runtimeOnly(libs.log4j.slf4j)

    testImplementation(project(":persistence"))
    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.engine)
    integrationTestImplementation(libs.bundles.integration.test)
    integrationTestRuntimeOnly(libs.junit.engine)
    integrationTestRuntimeOnly(libs.postgres.driver)
}

tasks.jar {
    from(project(":persistence").sourceSets["main"].output)
}

publishing {
    publications {
        create<MavenPublication>("mavenKotlin") {
            from(components["java"])

            groupId = "taala.keystore"
            artifactId = "taala"
            version = project.version.toString()

            pom {
                name.set("Taala")
                url.set("https://github.com/YashNabar/taala")

                licenses {
                    license {
                        name.set("GNU General Public License v3.0")
                        url.set("https://www.gnu.org/licenses/gpl-3.0.en.html")
                    }
                }
            }
        }
    }

    repositories {
        mavenLocal()
    }
}
