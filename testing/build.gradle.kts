plugins {
    id("taala-conventions")
}

description = "End-to-end tests"
version = rootProject.version

dependencies {
    // Dependency on published artifact
    testImplementation("taala.keystore:taala:$version")
    testImplementation(libs.bundles.integration.test)
    testImplementation(libs.bundles.test)

    testRuntimeOnly(libs.junit.engine)
    testRuntimeOnly(libs.log4j.slf4j)
    testRuntimeOnly(libs.postgres.driver)
}
