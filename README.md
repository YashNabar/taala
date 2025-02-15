# Taala

[![Gradle Build](https://github.com/YashNabar/database-keystore/actions/workflows/gradle.yml/badge.svg?branch=master)](https://github.com/YashNabar/database-keystore/actions/workflows/gradle.yml)

Taala is a Java library written in Kotlin that provides a database-backed cryptographic key store.    
The standard Java `KeyStore` instances are typically written to JKS files. This library enables you to create a
database-backed implementation of `KeyStore` which can be interacted with using the standard `JavaSpi` interface.
