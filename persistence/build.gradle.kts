plugins {
    id("taala-conventions")
    id("integration-test")
    alias(libs.plugins.allopen)
    alias(libs.plugins.noarg)
}

description = "Keystore persistence"
version = rootProject.version

dependencies {
    compileOnly(project(":libs"))
    implementation(libs.jakarta)
    implementation(libs.hibernate)
    implementation(libs.slf4j.api)

    runtimeOnly(libs.log4j.slf4j)

    testImplementation(project(":libs"))
    testImplementation(libs.bundles.test)
    integrationTestImplementation(libs.bundles.test)
    integrationTestImplementation(libs.bundles.integration.test)
    integrationTestRuntimeOnly(libs.junit.engine)
    integrationTestRuntimeOnly(libs.postgres.driver)
}

allOpen {
    annotations("jakarta.persistence.Entity")
}

noArg {
    annotations("jakarta.persistence.Entity")
}
