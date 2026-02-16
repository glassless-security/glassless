<p align="center">
  <img src="docs/img/glassless.png" alt="GlaSSLess Logo" width="400">
</p>

<p align="center">
  <a href="https://central.sonatype.com/artifact/net.glassless/glassless-provider"><img src="https://img.shields.io/maven-central/v/net.glassless/glassless-provider?label=Maven%20Central" alt="Maven Central"></a>
  <a href="https://openjdk.org/"><img src="https://img.shields.io/badge/Java-25%2B-blue?logo=openjdk" alt="Java Version"></a>
  <a href="https://github.com/glassless-security/glassless/commits/main"><img src="https://img.shields.io/github/last-commit/glassless-security/glassless" alt="GitHub last commit"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg" alt="License"></a>
</p>

GlaSSLess is a Java Cryptography Architecture (JCA) provider that wraps a system-installed OpenSSL library to provide a comprehensive suite of cryptographic algorithms. It uses Java's Foreign Function & Memory (FFM) API for native interoperability, requiring no JNI code or native compilation.

## Features

- **Native OpenSSL Performance**: Leverages OpenSSL's optimized implementations
- **No Native Compilation**: Uses Java's FFM API (no JNI required)
- **FIPS Mode Support**: Automatically detects and respects OpenSSL FIPS mode
- **Comprehensive Algorithm Coverage**: 370+ algorithm implementations
- **Post-Quantum Cryptography**: ML-KEM, ML-DSA, SLH-DSA, and hybrid key exchange (OpenSSL 3.5+)
- **Drop-in Replacement**: Standard JCA provider interface

## Requirements

- **Java**: 25 or later (with `--enable-native-access` flag)
- **OpenSSL**: 3.0 or later (`libcrypto.so.3`)

## Quick Start

### Maven

```xml
<dependency>
   <groupId>net.glassless</groupId>
   <artifactId>glassless-provider</artifactId>
   <version>0.3-SNAPSHOT</version>
</dependency>
```

### Gradle

```groovy
implementation 'net.glassless:glassless-provider:0.3-SNAPSHOT'
```

### JVM Arguments

```bash
java --enable-native-access=ALL-UNNAMED -jar your-app.jar
```

### Basic Usage

```java
import java.security.Security;
import java.security.MessageDigest;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
byte[] hash = md.digest("Hello, World!".getBytes());
```

## FIPS Mode

GlaSSLess automatically detects OpenSSL FIPS mode and excludes non-approved algorithms:

```java
GlaSSLessProvider provider = new GlaSSLessProvider();
System.out.println("FIPS Mode: " + provider.isFIPSMode());
```

## Documentation

Comprehensive documentation is available in the `docs` classifier JAR and in `src/main/asciidoc/`:

| Document | Description |
|----------|-------------|
| [Installation Guide](src/main/asciidoc/installation.adoc) | Setup, configuration, and provider registration |
| [Usage Guide](src/main/asciidoc/usage.adoc) | Code examples for all supported operations |
| [Supported Algorithms](src/main/asciidoc/algorithms.adoc) | Complete list of 370+ algorithms |
| [Post-Quantum Cryptography](src/main/asciidoc/pqc.adoc) | ML-KEM, ML-DSA, SLH-DSA, and hybrid KEMs |
| [Performance](src/main/asciidoc/performance.adoc) | Benchmark results and optimization guidance |
| [Development](src/main/asciidoc/development.adoc) | Contributing and architecture guide |

## Supported Algorithms

GlaSSLess provides 370+ cryptographic algorithms:

| Category | Count | Examples |
|----------|-------|----------|
| Message Digests | 18 | SHA-256, SHA-512, SHA3-256, BLAKE2b-512 |
| Ciphers | 143 | AES-GCM, ChaCha20-Poly1305, Camellia |
| MACs | 20 | HMAC-SHA256, KMAC256, Poly1305 |
| Signatures | 48 | ECDSA, EdDSA, RSA-PSS, ML-DSA, SLH-DSA |
| KEMs | 6 | ML-KEM-768, X25519MLKEM768 |
| KDFs | 14 | HKDF, PBKDF2, TLS13-KDF, Argon2 |
| Key Agreement | 5 | ECDH, X25519, X448 |

See [Supported Algorithms](src/main/asciidoc/algorithms.adoc) for the complete list.

## Post-Quantum Cryptography

GlaSSLess supports NIST-standardized post-quantum algorithms (requires OpenSSL 3.5+):

| Standard | Algorithm | Type |
|----------|-----------|------|
| FIPS 203 | ML-KEM-512/768/1024 | Key Encapsulation |
| FIPS 204 | ML-DSA-44/65/87 | Digital Signature |
| FIPS 205 | SLH-DSA (12 variants) | Digital Signature |

**Hybrid KEMs** (X25519MLKEM768, X448MLKEM1024) combine classical and post-quantum cryptography for defense-in-depth.

See [Post-Quantum Cryptography](src/main/asciidoc/pqc.adoc) for details, including JEP 527 roadmap and TLS 1.3 integration.

## Performance

GlaSSLess excels at asymmetric cryptography:

| Operation | vs JDK |
|-----------|--------|
| ECDH Key Agreement | ~6x faster |
| EC Key Generation | ~2x faster |
| SecureRandom (large buffers) | ~10-25x faster |

JDK excels at small-data symmetric operations due to HotSpot intrinsics.

See [Performance](src/main/asciidoc/performance.adoc) for detailed benchmarks.

## Building

```bash
# Build
mvn clean package

# Run tests
mvn test

# Run benchmarks
mvn test -Pbenchmarks
```

## License

Apache License, Version 2.0. See [LICENSE.md](LICENSE.md).

## Contributing

Contributions welcome! See [Development Guide](src/main/asciidoc/development.adoc) for guidelines.
