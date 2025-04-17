val javaExtension = extensions.getByType<JavaPluginExtension>()
val mainSourceSet: SourceSet = javaExtension.sourceSets.named("main").get()
val testSourceSet: SourceSet = javaExtension.sourceSets.named("test").get()

val integrationTestSourceSet: SourceSet = javaExtension.sourceSets.create("integrationTest").apply {
    java.srcDir("src/integrationTest/kotlin")
    resources.srcDir("src/integrationTest/resources")
    compileClasspath += mainSourceSet.output + testSourceSet.output
    runtimeClasspath += mainSourceSet.output + testSourceSet.output
}

configurations.named("integrationTestImplementation") {
    extendsFrom(configurations.named("testImplementation").get())
}
configurations.named("integrationTestRuntimeOnly") {
    extendsFrom(configurations.named("testRuntimeOnly").get())
}
configurations.findByName("testApi")?.let { testApi ->
    configurations.findByName("integrationTestApi")?.extendsFrom(testApi)
}

tasks.register<Test>("integrationTest") {
    description = "Runs integration tests."
    group = "verification"
    testClassesDirs = integrationTestSourceSet.output.classesDirs
    classpath = integrationTestSourceSet.runtimeClasspath
    shouldRunAfter(tasks.named("test"))
    useJUnitPlatform()
}

project.tasks.withType<ProcessResources>().configureEach {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
