# Taala

[![Gradle Build](https://github.com/YashNabar/taala/actions/workflows/gradle.yml/badge.svg?branch=master)](https://github.com/YashNabar/taala/actions/workflows/gradle.yml) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Taala is a database-backed implementation provider of the Java Cryptographic Architecture (JCA) KeyStore.
It provides a custom implementation of `KeyStoreSpi`, enabling Java applications to persist cryptographic material — such as private keys, secret keys, and certificates — to a relational database, as opposed to traditional file-based formats like JKS or PKCS12.

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
