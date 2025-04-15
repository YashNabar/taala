# Taala

[![Gradle Build](https://github.com/YashNabar/database-keystore/actions/workflows/gradle.yml/badge.svg?branch=master)](https://github.com/YashNabar/database-keystore/actions/workflows/gradle.yml)

Taala is a database-backed implementation of the Java Cryptographic Architecture (JCA) KeyStore.
It provides a custom implementation of `KeyStoreSpi`, allowing Java applications to store cryptographic keys and certificates in a relational database, rather than using traditional file-based formats such as JKS or PKCS12.

Applications can interact with the Taala key store seamlessly through Java’s standard KeyStore interface.

#### Supported Types

Taala currently supports the following key and certificate types:
- X.509 Certificates
- RSA Private Keys
- AES Secret Keys

## How To Use The Provider
Java applications can register the provider and obtain an instance of `KeyStore` as shown below.

```java
Taala provider = new Taala(myDataSource);
Security.addProvider(provider);

KeyStore ks = KeyStore.getInstance("TaalaKeyStore", "Taala");
ks.load(null, null);
```
