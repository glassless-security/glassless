# GlaSSLess Performance Report

This report compares the performance of multiple JCA cryptographic providers:

- **GlaSSLess** - OpenSSL-based provider using FFM (Foreign Function & Memory API)
- **JDK** - Standard JDK provider with HotSpot intrinsics
- **BC FIPS** - Bouncy Castle FIPS certified provider
- **NSS** - Mozilla NSS via SunPKCS11 (when available)

> **Note**: These benchmarks measure throughput (operations per millisecond). Higher is better.
> Results vary by hardware, JVM version, and library versions.

## Test Environment

| Property | Value |
|----------|-------|
| Date | 2026-02-14T18:40:40+01:00 |
| Host | jakku |
| CPU | AMD Ryzen 9 9900X 12-Core Processor |
| Java | openjdk version "25.0.2" 2026-01-20 |
| OpenSSL | OpenSSL 3.5.3 16 Sep 2025 (Library: OpenSSL 3.5.3 16 Sep 2025) |
| NSS | Unknown |

## Performance Summary

Benchmarks include the following providers: bcFips, glassless, jdk, nss

### Key Operations Comparison

| Category | Operation | GlaSSLess | JDK | BC FIPS | NSS |
|----------|-----------|----------:|----:|--------:|----:|
| Key Agreement | ECDH | 19.09 | 3.06 | 4.13 | - |
| Key Agreement | X25519 | - | - | - | - |
| Key Encapsulation | ML-KEM-768 Encaps | 37.14 | - | - | - |
| Key Encapsulation | ML-KEM-768 Decaps | 20.59 | - | - | - |
| Key Generation | ML-KEM-768 | 23.84 | - | - | - |
| Key Generation | Ed25519 | - | - | - | - |
| Key Generation | EC P-256 | 33.15 | 17.81 | 2.26 | 17.73 |
| Signature | Ed25519 Sign | - | - | - | - |
| Signature | Ed25519 Verify | - | - | - | - |
| Digest | SHA-256 (64B) | 2614.14 | 15116.36 | 8169.17 | - |
| MAC | HMAC-SHA256 (64B) | 797.98 | 6137.97 | 2417.73 | - |

_Scores in ops/ms. Higher is better. "-" indicates no data available._

### GlaSSLess vs JDK Speedups

| Category | Operation | Speedup |
|----------|-----------|--------:|
| Key Agreement | ECDH | 6.2x faster |
| Key Agreement | X25519 | - |
| Key Generation | Ed25519 | - |
| Key Generation | EC P-256 | 1.9x faster |
| Signature | Ed25519 Sign | - |
| Signature | Ed25519 Verify | - |
| Digest | SHA-256 (64B) | 5x slower |

## MessageDigest Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Digest | algorithm=SHA-256, dataSize=1024 | 1999.11 | ±45.94 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=1048576 | 2.43 | ±0.03 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=16384 | 152.92 | ±1 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=64 | 8169.17 | ±148.05 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1024 | 471.96 | ±5.35 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1048576 | 0.54 | ±0.01 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=16384 | 33.75 | ±0.23 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=64 | 3678.73 | ±129.54 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1024 | 1057.93 | ±220.85 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1048576 | 1.88 | ±0.06 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=16384 | 111.29 | ±11.77 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=64 | 2614.14 | ±1053.5 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1024 | 760.58 | ±92.48 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1048576 | 1.23 | ±0.02 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=16384 | 75.02 | ±2.39 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=64 | 2131.86 | ±374.72 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1024 | 2405.29 | ±38.27 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1048576 | 2.61 | ±0.02 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=16384 | 166.06 | ±0.79 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=64 | 15116.36 | ±232.77 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1024 | 1132.96 | ±18.72 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1048576 | 1.31 | ±0.01 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=16384 | 82.5 | ±1.03 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=64 | 8538.47 | ±370.52 | ops/ms |

## Cipher Benchmarks

_No data available for this benchmark._

## MAC Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1024 | 1189.83 | ±7.01 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.43 | ±0.03 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=16384 | 146.21 | ±4.28 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=64 | 2417.73 | ±77.45 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1024 | 368.14 | ±3.95 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1048576 | 0.55 | ±0 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=16384 | 33.2 | ±0.61 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=64 | 1230.29 | ±15.54 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1024 | 585.9 | ±155.05 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.47 | ±0.01 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=16384 | 131.9 | ±28.35 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=64 | 797.98 | ±219.39 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1024 | 395.19 | ±85.44 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.46 | ±0.01 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=16384 | 81.85 | ±13.8 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=64 | 551.14 | ±150.16 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1024 | 1950.5 | ±38.3 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.61 | ±0.02 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=16384 | 163.07 | ±1.17 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=64 | 6137.97 | ±180.96 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1024 | 831.75 | ±29.32 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.3 | ±0 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=16384 | 80.13 | ±0.51 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=64 | 2239.36 | ±69.65 | ops/ms |

## Signature Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Sign | algorithm=SHA256withECDSA | 3.1 | ±0.15 | ops/ms |
| bcFips | Sign | algorithm=SHA384withECDSA | 3.61 | ±0.2 | ops/ms |
| bcFips | Verify | algorithm=SHA256withECDSA | 6.61 | ±0.1 | ops/ms |
| bcFips | Verify | algorithm=SHA384withECDSA | 2.51 | ±0.03 | ops/ms |
| glassless | Verify | algorithm=SHA256withECDSA | 22.35 | ±0.3 | ops/ms |
| glassless | Verify | algorithm=SHA384withECDSA | 3.46 | ±0.02 | ops/ms |
| jdk | Sign | algorithm=SHA256withECDSA | 13.53 | ±0.31 | ops/ms |
| jdk | Sign | algorithm=SHA384withECDSA | 1.82 | ±0.03 | ops/ms |
| jdk | Verify | algorithm=SHA256withECDSA | 4.34 | ±0.06 | ops/ms |
| jdk | Verify | algorithm=SHA384withECDSA | 1 | ±0.02 | ops/ms |

## Key Agreement Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | KeyAgreement | algorithm=ECDH | 4.13 | ±0.07 | ops/ms |
| glassless | KeyAgreement | algorithm=ECDH | 19.09 | ±0.26 | ops/ms |
| jdk | KeyAgreement | algorithm=ECDH | 3.06 | ±0.07 | ops/ms |

## Key Encapsulation (ML-KEM) Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| glassless | Decapsulate | algorithm=ML-KEM-1024 | 15.05 | ±0.22 | ops/ms |
| glassless | Decapsulate | algorithm=ML-KEM-512 | 29.63 | ±0.82 | ops/ms |
| glassless | Decapsulate | algorithm=ML-KEM-768 | 20.59 | ±0.55 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-1024 | 26.53 | ±0.28 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-512 | 53.86 | ±2.55 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-768 | 37.14 | ±0.54 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-1024 | 18.16 | ±0.42 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-512 | 31.84 | ±0.75 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-768 | 23.84 | ±0.65 | ops/ms |

## Key Pair Generator Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | GenerateKeyPair | algorithm=EC-P256 | 2.26 | ±0.13 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=EC-P384 | 0.97 | ±0.05 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-2048 | 0.01 | ±0 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P256 | 33.15 | ±1.03 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P384 | 6.47 | ±0.17 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-2048 | 0.04 | ±0.02 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P256 | 17.81 | ±0.47 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P384 | 2.04 | ±0.03 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P256 | 17.73 | ±0.57 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P384 | 2.02 | ±0.04 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |

## SecureRandom Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | NextBytes | byteCount=1024 | 3.43 | ±0.32 | ops/ms |
| bcFips | NextBytes | byteCount=16 | 2.81 | ±0.03 | ops/ms |
| bcFips | NextBytes | byteCount=256 | 2.9 | ±0.05 | ops/ms |
| bcFips | NextBytes | byteCount=32 | 2.82 | ±0.03 | ops/ms |
| bcFips | NextBytes | byteCount=4096 | 3.17 | ±0.12 | ops/ms |
| bcFips | NextBytes | byteCount=64 | 2.77 | ±0.06 | ops/ms |
| glassless | NextBytes | byteCount=1024 | 3059.63 | ±135.61 | ops/ms |
| glassless | NextBytes | byteCount=16 | 4465.85 | ±148.99 | ops/ms |
| glassless | NextBytes | byteCount=256 | 4141.75 | ±58.45 | ops/ms |
| glassless | NextBytes | byteCount=32 | 4876.37 | ±89.96 | ops/ms |
| glassless | NextBytes | byteCount=4096 | 1381.7 | ±79.15 | ops/ms |
| glassless | NextBytes | byteCount=64 | 4715.64 | ±84.39 | ops/ms |
| jdk | NextBytes | byteCount=1024 | 241.54 | ±12.34 | ops/ms |
| jdk | NextBytes | byteCount=16 | 8647.78 | ±168.26 | ops/ms |
| jdk | NextBytes | byteCount=256 | 979.87 | ±24.51 | ops/ms |
| jdk | NextBytes | byteCount=32 | 6283.81 | ±53.42 | ops/ms |
| jdk | NextBytes | byteCount=4096 | 60.46 | ±5.03 | ops/ms |
| jdk | NextBytes | byteCount=64 | 3525.31 | ±59.95 | ops/ms |
| nss | NextBytes | byteCount=1024 | 194.32 | ±7.79 | ops/ms |
| nss | NextBytes | byteCount=16 | 10061.26 | ±620.68 | ops/ms |
| nss | NextBytes | byteCount=256 | 968.05 | ±42.3 | ops/ms |
| nss | NextBytes | byteCount=32 | 5668.33 | ±515 | ops/ms |
| nss | NextBytes | byteCount=4096 | 49.98 | ±1.21 | ops/ms |
| nss | NextBytes | byteCount=64 | 3549.5 | ±82.84 | ops/ms |

## Notes

- **Throughput** is measured in operations per millisecond (ops/ms). Higher is better.
- **Error** shows the 99.9% confidence interval.
- **Provider characteristics**:
  - **JDK**: Benefits from HotSpot intrinsics for SHA-256, SHA-512, AES, and other common algorithms
  - **GlaSSLess (OpenSSL)**: Excels at asymmetric cryptography; FFM call overhead affects small-data operations
  - **BC FIPS**: FIPS 140-2 certified; pure Java implementation with some native acceleration
  - **NSS**: Mozilla's Network Security Services via SunPKCS11; requires system NSS libraries
- **Post-Quantum Cryptography** (ML-KEM, ML-DSA, SLH-DSA) requires OpenSSL 3.5+ and is currently only available in GlaSSLess.
- For large data sizes (16KB+), performance typically converges between implementations.
- Missing data ("-") indicates the benchmark was not run or the provider was unavailable.

## Reproducing Results

```bash
# Run all benchmarks
mvn test -Pbenchmarks

# Generate this report
./scripts/generate-performance-report.sh

# Run specific benchmark
mvn test -Pbenchmarks -Dexec.args=".*MessageDigestBenchmark.*"
```
