
val kotlin_version: String by project
val logback_version: String by project

plugins {
    kotlin("jvm") version "2.0.0"
    id("io.ktor.plugin") version "2.3.12"
}

group = "example.com"
version = "0.0.1"

application {
//    mainClass.set("io.ktor.server.cio.EngineMain")

    mainClass.set("dev.pythonplayer123.kotlindns.CombinedKt")


    val isDevelopment: Boolean = project.ext.has("development")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=$isDevelopment")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-network")
    implementation("io.ktor:ktor-server-netty")
    implementation("io.ktor:ktor-server-html-builder")
    implementation("ch.qos.logback:logback-classic:$logback_version")
    implementation("io.ktor:ktor-server-config-yaml")
    implementation("com.google.guava:guava:33.2.1-jre")
    implementation(kotlin("reflect"))
    testImplementation("io.ktor:ktor-server-tests-jvm")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlin_version")
    implementation(kotlin("stdlib-jdk8"))
}
kotlin {
    jvmToolchain(19)
}
