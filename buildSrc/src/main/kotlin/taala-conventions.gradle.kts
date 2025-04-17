import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("io.gitlab.arturbosch.detekt")
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(17))
    withSourcesJar()
}

tasks.withType<KotlinJvmCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
        languageVersion.set(KotlinVersion.KOTLIN_2_1)
        apiVersion.set(KotlinVersion.KOTLIN_2_1)
        javaParameters.set(true)
        freeCompilerArgs.addAll(
            "-java-parameters",
            "-Xjvm-default=all"
        )
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        excludeTags = if (project.hasProperty("runUnstableTests")) {
            setOf("runAllTestsNoExclusions")
        } else {
            setOf("Unstable")
        }
    }

    doFirst {
        systemProperty("java.io.tmpdir", layout.buildDirectory.get().asFile.absolutePath)
    }
}

tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
    val baselineFile = file("$projectDir/detekt-baseline.xml")
    if (baselineFile.exists()) {
        baseline.set(baselineFile)
    }

    config.setFrom(files("$rootDir/detekt-config.yml"))
    parallel = true
    reports {
        xml.required.set(true)
        xml.outputLocation.set(layout.buildDirectory.file("reports/detekt/report.xml"))
        txt.required.set(false)
        sarif.required.set(false)
        html.required.set(false)
    }
}
