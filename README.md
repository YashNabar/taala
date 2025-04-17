# Taala

[![Build](https://github.com/YashNabar/taala/actions/workflows/gradle.yml/badge.svg?branch=master)](https://github.com/YashNabar/taala/actions/workflows/gradle.yml) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Taala is a database-backed implementation provider of the Java Cryptographic Architecture (JCA) KeyStore.

Taala provides a custom implementation of `KeyStoreSpi`, enabling Java applications to persist cryptographic material — such as private keys, secret keys, and certificates — to a relational database of their choice, as opposed to traditional file-based formats like JKS or PKCS12.
It allows applications to supply their own `DataSource` and creates the required tables in the provided database instance.
This gives applications full control over connection pooling, credentials, and advanced database settings through their own `DataSource` setup.

Applications can interact with the Taala key store seamlessly through Java’s standard KeyStore interface.

#### Supported Types

Taala currently supports the following key and certificate types:
- X.509 Certificates
- RSA Private Keys
- AES Secret Keys

Taala currently supports the following databases:
- PostgreSQL: 9.6, 11, 12, 13, 14, 15, 16, 17

## How To Use The Provider
Java applications can register the provider and obtain an instance of `KeyStore` as shown below.

```java
Taala provider = new Taala(myDataSource);
Security.addProvider(provider);

KeyStore ks = KeyStore.getInstance("TaalaKeyStore", "Taala");
ks.load(null, null);
```
