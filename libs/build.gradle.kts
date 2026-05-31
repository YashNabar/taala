plugins {
    id("taala-conventions")
}

description = "Keystore implementation"
version = rootProject.version

dependencies {
    implementation(libs.slf4j.api)

    runtimeOnly(libs.log4j.slf4j)

    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.engine)
}
