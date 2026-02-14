<p align="center">
  <img src="docs/img/glassless.png" alt="GlaSSLess Logo" width="400">
</p>

<p align="center">
  <a href="https://central.sonatype.com/artifact/net.glassless/glassless-provider"><img src="https://img.shields.io/maven-central/v/net.glassless/glassless-provider?label=Maven%20Central" alt="Maven Central"></a>
  <a href="https://openjdk.org/"><img src="https://img.shields.io/badge/Java-21%2B-blue?logo=openjdk" alt="Java Version"></a>
  <a href="https://github.com/glassless-security/glassless/commits/main"><img src="https://img.shields.io/github/last-commit/glassless-security/glassless" alt="GitHub last commit"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg" alt="License"></a>
</p>

GlaSSLess is a Java Cryptography Architecture (JCA) provider that wraps a system-installed OpenSSL library to provide a comprehensive suite of cryptographic algorithms. It uses Java's Foreign Function & Memory (FFM) API for native interoperability, requiring no JNI code or native compilation.

## Features

- **Native OpenSSL Performance**: Leverages OpenSSL's optimized implementations
- **No Native Compilation**: Uses Java's FFM API (no JNI required)
- **FIPS Mode Support**: Automatically detects and respects OpenSSL FIPS mode
- **Comprehensive Algorithm Coverage**: 275+ algorithm implementations
- **Drop-in Replacement**: Standard JCA provider interface

## Requirements

- **Java**: 21 or later (with `--enable-native-access` flag)
- **OpenSSL**: 3.0 or later (`libcrypto.so.3`)

### OpenSSL Version Compatibility

| OpenSSL Version | Status | Notes |
|-----------------|--------|-------|
| 3.0.x | Supported | Base algorithms |
| 3.1.x | Supported | Full support |
| 3.2.x | Supported | Adds Argon2 KDFs |
| 3.3.x+ | Supported | Latest features |

## Building

```bash
# Clone the repository
git clone https://github.com/glassless-security/glassless.git
cd glassless

# Build with Maven
mvn clean package

# Run tests
mvn test

# Check code formatting
mvn spotless:check

# Apply code formatting
mvn spotless:apply
```

## Installation

### Maven

```xml
<dependency>
   <groupId>net.glassless</groupId>
   <artifactId>glassless-provider</artifactId>
   <version>1.0-SNAPSHOT</version>
</dependency>
```

### JVM Arguments

The provider requires native access permissions:

```bash
java --enable-native-access=ALL-UNNAMED -jar your-app.jar
```

Or in `JAVA_TOOL_OPTIONS`:

```bash
export JAVA_TOOL_OPTIONS="--enable-native-access=ALL-UNNAMED"
```

## Usage

### Registering the Provider Programmatically

```java
import java.security.Security;
import net.glassless.provider.GlaSSLessProvider;

// Option 1: Add provider programmatically
Security.addProvider(new GlaSSLessProvider());

// Option 2: Insert at highest priority
Security.insertProviderAt(new GlaSSLessProvider(), 1);
```

### Configuring in java.security

For system-wide installation, add GlaSSLess to the `java.security` file located at `$JAVA_HOME/conf/security/java.security`.

#### Finding the Configuration File

```bash
# Find java.security location
java -XshowSettings:all 2>&1 | grep java.home
# Then look in: <java.home>/conf/security/java.security
```

#### Adding the Provider

Providers are listed with numeric priorities (lower numbers = higher priority). Add GlaSSLess to the provider list:

```properties
# Existing providers (example)
security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.3=SunEC
security.provider.4=SunJSSE
security.provider.5=SunJCE
security.provider.6=SunJGSS
security.provider.7=SunSASL
security.provider.8=XMLDSig
security.provider.9=SunPCSC
security.provider.10=JdkLDAP
security.provider.11=JdkSASL
security.provider.12=SunPKCS11

# Add GlaSSLess
security.provider.13=net.glassless.provider.GlaSSLessProvider
```

#### Best Practices

**1. Provider Priority Positioning**

| Position | Use Case | Recommendation |
|----------|----------|----------------|
| Low priority (e.g., 13) | Explicit use only | Use `getInstance("ALG", "GlaSSLess")` to select |
| Mid priority (e.g., 5-6) | Preferred for specific algorithms | GlaSSLess used when JDK doesn't provide algorithm |
| High priority (e.g., 1-2) | Default for all operations | All crypto uses GlaSSLess unless unavailable |

**2. Recommended: Low Priority with Explicit Selection**

For most applications, add GlaSSLess at low priority and explicitly request it when needed:

```properties
# Add GlaSSLess at low priority
security.provider.13=net.glassless.provider.GlaSSLessProvider
```

```java
// Explicitly request GlaSSLess for performance-critical operations
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "GlaSSLess");
Signature sig = Signature.getInstance("Ed25519", "GlaSSLess");
```

This approach:
- Maintains JDK behavior by default
- Allows selective use of GlaSSLess where beneficial
- Avoids unexpected behavior changes

**3. High Priority for OpenSSL-First Strategy**

If you want all cryptographic operations to use OpenSSL by default:

```properties
# Insert GlaSSLess at high priority
security.provider.1=net.glassless.provider.GlaSSLessProvider
security.provider.2=SUN
security.provider.3=SunRsaSign
# ... remaining providers renumbered
```

> **Warning**: High priority positioning changes default behavior for all applications using this JVM. Test thoroughly before deploying.

**4. FIPS Mode Considerations**

When OpenSSL is in FIPS mode, GlaSSLess automatically excludes non-approved algorithms. For FIPS-compliant deployments:

```properties
# Place GlaSSLess at high priority to ensure FIPS-approved algorithms are used
security.provider.1=net.glassless.provider.GlaSSLessProvider
security.provider.2=SunJSSE
# ... other providers
```

**5. TLS/SSL Configuration**

For TLS connections to use GlaSSLess algorithms, ensure the provider is available before `SunJSSE`:

```properties
security.provider.1=net.glassless.provider.GlaSSLessProvider
security.provider.2=SunJSSE
# ... remaining providers
```

The JSSE implementation will automatically use GlaSSLess for underlying cryptographic operations.

**6. Alternative: Security Properties File Override**

Instead of modifying the system `java.security`, create a custom properties file:

```properties
# custom-security.properties
security.provider.1=net.glassless.provider.GlaSSLessProvider
security.provider.2=SUN
# ... etc
```

Then specify it at runtime:

```bash
java -Djava.security.properties=/path/to/custom-security.properties \
     --enable-native-access=ALL-UNNAMED \
     -jar your-app.jar
```

**7. Module Path Configuration**

When using the module path, ensure GlaSSLess is accessible:

```bash
java --module-path /path/to/glassless-provider.jar \
     --add-modules net.glassless.provider \
     --enable-native-access=net.glassless.provider \
     -jar your-app.jar
```

### Basic Examples

#### Message Digest (Hashing)

```java
import java.security.MessageDigest;
import java.security.Security;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

MessageDigest md = MessageDigest.getInstance("SHA-256", "GlaSSLess");
byte[] hash = md.digest("Hello, World!".getBytes());
```

#### Symmetric Encryption (AES-GCM)

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.security.Security;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

// Generate a key
KeyGenerator keyGen = KeyGenerator.getInstance("AES", "GlaSSLess");
keyGen.init(256);
SecretKey key = keyGen.generateKey();

// Generate IV
byte[] iv = new byte[12];
SecureRandom random = SecureRandom.getInstance("NativePRNG", "GlaSSLess");
random.nextBytes(iv);

// Encrypt
Cipher cipher = Cipher.getInstance("AES_256/GCM/NoPadding", "GlaSSLess");
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal("Secret message".getBytes());

// Decrypt
cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] plaintext = cipher.doFinal(ciphertext);
```

#### Digital Signatures (ECDSA)

```java
import java.security.*;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

// Generate key pair
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "GlaSSLess");
keyPairGen.initialize(256);
KeyPair keyPair = keyPairGen.generateKeyPair();

// Sign
Signature signer = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
signer.initSign(keyPair.getPrivate());
signer.update("Data to sign".getBytes());
byte[] signature = signer.sign();

// Verify
Signature verifier = Signature.getInstance("SHA256withECDSA", "GlaSSLess");
verifier.initVerify(keyPair.getPublic());
verifier.update("Data to sign".getBytes());
boolean valid = verifier.verify(signature);
```

#### Key Derivation (HKDF)

```java
import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

// Input keying material
byte[] ikm = "input-key-material".getBytes();
byte[] salt = "salt-value".getBytes();
byte[] info = "context-info".getBytes();

KDF hkdf = KDF.getInstance("HKDF-SHA256", "GlaSSLess");
SecretKey derived = hkdf.deriveKey("AES",
    HKDFParameterSpec.expandOnly(new SecretKeySpec(ikm, "HKDF"), info, 32));
```

#### HMAC

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import net.glassless.provider.GlaSSLessProvider;

Security.addProvider(new GlaSSLessProvider());

byte[] key = "secret-key".getBytes();
SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");

Mac mac = Mac.getInstance("HmacSHA256", "GlaSSLess");
mac.init(keySpec);
byte[] hmac = mac.doFinal("Message".getBytes());
```

## Supported Algorithms

### Message Digests (18)

| Algorithm | FIPS Approved |
|-----------|---------------|
| SHA-224, SHA-256, SHA-384, SHA-512 | Yes |
| SHA-512/224, SHA-512/256 | Yes |
| SHA3-224, SHA3-256, SHA3-384, SHA3-512 | Yes |
| SHAKE128, SHAKE256 | Yes |
| BLAKE2b-512, BLAKE2s-256 | Yes |
| MD5, SHA-1 | No |
| SM3, RIPEMD160 | No |

### Ciphers (143)

| Algorithm | Key Sizes | Modes | FIPS Approved |
|-----------|-----------|-------|---------------|
| AES | 128, 192, 256 | ECB, CBC, CFB, CTR, OFB, GCM, CCM, XTS | Yes |
| AES Key Wrap | 128, 192, 256 | KW, KWP | Yes |
| Camellia | 128, 192, 256 | ECB, CBC, CFB, CTR, OFB | No |
| ARIA | 128, 192, 256 | ECB, CBC, CFB, CTR, OFB, GCM | No |
| SM4 | 128 | ECB, CBC, CFB, CTR, OFB | No |
| ChaCha20 | 256 | Stream | No |
| ChaCha20-Poly1305 | 256 | AEAD | No |
| DESede (3DES) | 168 | ECB, CBC | No |
| RSA | 1024-8192 | ECB with PKCS1/OAEP | Yes |

### MACs (20)

| Algorithm | FIPS Approved |
|-----------|---------------|
| HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512 | Yes |
| HmacSHA3-224, HmacSHA3-256, HmacSHA3-384, HmacSHA3-512 | Yes |
| AESCMAC, AESGMAC | Yes |
| KMAC128, KMAC256 | Yes |
| HmacSHA1 | No |
| Poly1305, SipHash | No |

### Signatures (31)

| Algorithm | FIPS Approved |
|-----------|---------------|
| SHA256withRSA, SHA384withRSA, SHA512withRSA | Yes |
| SHA256withRSAandMGF1 (RSA-PSS) | Yes |
| SHA256withECDSA, SHA384withECDSA, SHA512withECDSA | Yes |
| SHA3-256withECDSA, SHA3-384withECDSA, SHA3-512withECDSA | Yes |
| SHA256withDSA, SHA384withDSA, SHA512withDSA | Yes |
| Ed25519, Ed448, EdDSA | Yes |
| SHA1withRSA, SHA1withECDSA, SHA1withDSA | No |

### Key Agreement (5)

| Algorithm | FIPS Approved |
|-----------|---------------|
| ECDH, DH | Yes |
| X25519, X448, XDH | Yes |

### Key Derivation Functions (5)

| Algorithm | FIPS Approved |
|-----------|---------------|
| HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 | Yes |
| HKDF-SHA224 | Yes |
| HKDF-SHA1 | No |

### Secret Key Factories (32)

| Algorithm | FIPS Approved |
|-----------|---------------|
| PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512 | Yes |
| PBKDF2WithHmacSHA3-256, PBKDF2WithHmacSHA3-384, PBKDF2WithHmacSHA3-512 | Yes |
| PBKDF2WithHmacSHA1 | No |
| SCRYPT | No |

### Secure Random (3)

| Algorithm | FIPS Approved |
|-----------|---------------|
| NativePRNG, DRBG | Yes |
| SHA1PRNG | No |

## FIPS Mode

When OpenSSL is configured with FIPS mode enabled, GlaSSLess automatically detects this and excludes non-FIPS-approved algorithms from registration.

```java
GlaSSLessProvider provider = new GlaSSLessProvider();
boolean fipsMode = provider.isFIPSMode();
System.out.println("FIPS Mode: " + (fipsMode ? "ENABLED" : "DISABLED"));
```

## Command-Line Tool

Display provider information:

```bash
java --enable-native-access=ALL-UNNAMED -jar glassless-provider-1.0-SNAPSHOT.jar

# Verbose mode (list all algorithms)
java --enable-native-access=ALL-UNNAMED -jar glassless-provider-1.0-SNAPSHOT.jar --verbose
```

## Performance

GlaSSLess provides significant performance advantages for asymmetric cryptography operations while JDK implementations excel at small-data symmetric operations due to HotSpot intrinsics.

### Where GlaSSLess Excels

| Operation | Typical Speedup |
|-----------|-----------------|
| ECDH Key Agreement | ~6x faster |
| Ed25519 Signing | ~8x faster |
| Ed25519 Verification | ~5-6x faster |
| EC Key Generation (P-256/P-384) | ~2-3x faster |
| Ed25519/X25519 Key Generation | ~2-5x faster |
| SecureRandom (large buffers) | ~10-25x faster |
| SHA3/SHAKE (large data) | ~1.5-2x faster |

### Where JDK Excels

| Operation | JDK Advantage |
|-----------|---------------|
| SHA-256/SHA-512 (small data <1KB) | ~4-6x faster |
| HMAC (small data <1KB) | ~4-8x faster |
| SecureRandom (small buffers <64B) | ~2x faster |

> **Note**: For large data (16KB+), symmetric operation performance converges between implementations.

For detailed benchmark results on your system, run:

```bash
mvn test -Pbenchmarks
./scripts/generate-performance-report.sh
```

This generates `PERFORMANCE.md` with full benchmark data for your environment.

## Benchmarks

JMH microbenchmarks compare performance between JDK and GlaSSLess implementations. Benchmarks are activated via a Maven profile:

```bash
# Run all benchmarks (~12 minutes)
mvn test -Pbenchmarks

# Generate detailed performance report
./scripts/generate-performance-report.sh

# Run specific benchmark class
mvn test -Pbenchmarks -Dexec.args=".*MessageDigestBenchmark.*"
```

### Benchmark Categories

| Benchmark | Algorithms | Data Sizes |
|-----------|------------|------------|
| MessageDigestBenchmark | SHA-256, SHA-512, SHA3-256 | 64B, 1KB, 16KB, 1MB |
| CipherBenchmark | AES/GCM, AES/CBC, ChaCha20-Poly1305 | 64B, 1KB, 16KB, 1MB |
| MacBenchmark | HmacSHA256, HmacSHA512, HmacSHA3-256 | 64B, 1KB, 16KB, 1MB |
| SignatureBenchmark | SHA256withECDSA, SHA384withECDSA, Ed25519 | - |
| KeyAgreementBenchmark | ECDH, X25519 | - |
| KeyPairGeneratorBenchmark | EC P-256/P-384, RSA-2048/4096, Ed25519, X25519 | - |
| SecureRandomBenchmark | NativePRNG | 16B to 4KB |

Results are saved to `target/jmh-results.json`.

## Development

### Code Style

The project uses [Spotless](https://github.com/diffplug/spotless) for code formatting:

- 3-space indentation for Java and XML
- Import ordering: `java`, `javax`, `org`, `com`, `net`
- UTF-8 encoding, Unix line endings

```bash
# Check formatting
mvn spotless:check

# Apply formatting
mvn spotless:apply
```

### Project Structure

```
src/main/java/net/glassless/provider/
├── GlaSSLessProvider.java       # Main provider class
├── FIPSStatus.java              # FIPS mode detection
└── internal/
    ├── OpenSSLCrypto.java       # FFM bindings to OpenSSL
    ├── cipher/                  # Cipher implementations
    ├── digest/                  # MessageDigest implementations
    ├── mac/                     # MAC implementations
    ├── signature/               # Signature implementations
    ├── kdf/                     # KDF implementations
    ├── keygen/                  # KeyGenerator implementations
    ├── keypairgen/              # KeyPairGenerator implementations
    ├── keyfactory/              # KeyFactory implementations
    ├── keyagreement/            # KeyAgreement implementations
    ├── securerandom/            # SecureRandom implementations
    └── ...
```

## License

This project is licensed under the **Apache License, Version 2.0**.

You may obtain a copy of the License at: http://www.apache.org/licenses/LICENSE-2.0

```
Copyright 2026

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

See [LICENSE.md](LICENSE.md) for the full license text.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Ensure code follows the project style (`mvn spotless:apply`)
4. Add tests for new functionality
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/my-feature`)
7. Open a Pull Request

Please ensure all tests pass before submitting:

```bash
mvn test
```
