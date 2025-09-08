# crypt-card proto server

![kotlin](https://img.shields.io/badge/kotlin-1.9-blue.svg)
![gradle](https://img.shields.io/badge/gradle-8.3-green.svg)
![jdk](https://img.shields.io/badge/jdk-17+-orange.svg)
![license](https://img.shields.io/badge/license-MIT-lightgrey.svg)

this is a kotlin project implementing a secure async client-server communication using noise protocol (xx handshake) and ed25519 signatures. the server and client communicate over tcp with replay protection, session management and aes-gcm encrypted storage for keys.

## features

- noise xx handshake (ed25519 + chachapoly + sha256)
- replay protection and sequence numbers
- session management with ttl and max messages
- aes-gcm encrypted storage for server private key
- async client/server using coroutines
- configurable max message size and handshake limits
- easy to run and extend

## technologies

- kotlin
- gradle
- jdk 17+
- noise protocol library (`com.southernstorm.noise`)
- coroutines (`kotlinx.coroutines`)
- bouncycastle (ed25519 + crypto)
