# database-keystore

This is a Java library written in Kotlin that provides database-backed cryptographic key stores.    
The standard Java `KeyStore` instances are typically written to JKS files. This library enables you to create a
database-backed implementation of `KeyStore` which can be interacted with using the standard `JavaSpi` interface.
