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
| Date | 2026-02-15T10:46:57+01:00 |
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
| Key Agreement | ECDH | 19.25 | 3.07 | 4.12 | - |
| Key Agreement | X25519 | - | - | - | - |
| Key Encapsulation | ML-KEM-768 Encaps | 37.13 | 59.06 | - | - |
| Key Encapsulation | ML-KEM-768 Decaps | 20.83 | 51.49 | - | - |
| Key Generation | ML-KEM-768 | 24.24 | 52.08 | - | - |
| Key Generation | Ed25519 | - | - | - | - |
| Key Generation | EC P-256 | 33.29 | 17.74 | 2.33 | 17.86 |
| Signature | Ed25519 Sign | - | - | - | - |
| Signature | Ed25519 Verify | - | - | - | - |
| Digest | SHA-256 (64B) | 2616.48 | 15118.94 | 8237.58 | - |
| MAC | HMAC-SHA256 (64B) | 797.36 | 6214.14 | 2444.02 | - |

_Scores in ops/ms. Higher is better. "-" indicates no data available._

### GlaSSLess vs JDK Speedups

| Category | Operation | Speedup |
|----------|-----------|--------:|
| Key Agreement | ECDH | 6.3x faster |
| Key Agreement | X25519 | - |
| Key Encapsulation | ML-KEM-768 Encaps | 1.7x slower |
| Key Encapsulation | ML-KEM-768 Decaps | 2.5x slower |
| Key Generation | ML-KEM-768 | 2x slower |
| Key Generation | Ed25519 | - |
| Key Generation | EC P-256 | 1.9x faster |
| Signature | Ed25519 Sign | - |
| Signature | Ed25519 Verify | - |
| Digest | SHA-256 (64B) | 5x slower |

## MessageDigest Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Digest | algorithm=SHA-256, dataSize=1024 | 2011.03 | ±35.39 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=1048576 | 2.45 | ±0.01 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=16384 | 154.4 | ±0.68 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=64 | 8237.58 | ±215.35 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1024 | 478.26 | ±1.12 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1048576 | 0.55 | ±0 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=16384 | 33.59 | ±0.3 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=64 | 3698.45 | ±117.77 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1024 | 1065.44 | ±166.27 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1048576 | 1.9 | ±0.03 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=16384 | 114.13 | ±6.65 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=64 | 2616.48 | ±977.59 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1024 | 739.14 | ±48.94 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1048576 | 1.24 | ±0.02 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=16384 | 74.75 | ±1.12 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=64 | 2115.62 | ±339.52 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1024 | 2406.57 | ±35.21 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1048576 | 2.62 | ±0 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=16384 | 166.43 | ±0.06 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=64 | 15118.94 | ±1105.4 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1024 | 1117.76 | ±24.99 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1048576 | 1.31 | ±0.01 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=16384 | 82.83 | ±0.35 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=64 | 8508.64 | ±127.14 | ops/ms |

## Cipher Benchmarks

_No data available for this benchmark._

## MAC Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1024 | 1276.26 | ±39.57 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.44 | ±0.02 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=16384 | 147.15 | ±2.4 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=64 | 2444.02 | ±20.41 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1024 | 382.04 | ±1.51 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1048576 | 0.53 | ±0.01 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=16384 | 33.38 | ±0.62 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=64 | 1252.33 | ±20.1 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1024 | 587.1 | ±152.72 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.48 | ±0 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=16384 | 132.58 | ±28.12 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=64 | 797.36 | ±223.32 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1024 | 394.95 | ±70.05 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.46 | ±0.01 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=16384 | 82.13 | ±13.22 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=64 | 554.12 | ±142.57 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1024 | 1956.72 | ±33.97 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.62 | ±0.03 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=16384 | 163.57 | ±2.75 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=64 | 6214.14 | ±150.03 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1024 | 829.08 | ±17.48 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.31 | ±0.01 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=16384 | 80.44 | ±0.29 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=64 | 2223.51 | ±33.06 | ops/ms |

## Signature Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Sign | algorithm=SHA256withECDSA | 3.06 | ±0.1 | ops/ms |
| bcFips | Sign | algorithm=SHA384withECDSA | 3.42 | ±0.41 | ops/ms |
| bcFips | Verify | algorithm=SHA256withECDSA | 6.64 | ±0.03 | ops/ms |
| bcFips | Verify | algorithm=SHA384withECDSA | 2.44 | ±0.05 | ops/ms |
| glassless | Verify | algorithm=SHA256withECDSA | 22.33 | ±0.18 | ops/ms |
| glassless | Verify | algorithm=SHA384withECDSA | 3.45 | ±0.07 | ops/ms |
| jdk | Sign | algorithm=SHA256withECDSA | 13.6 | ±0.3 | ops/ms |
| jdk | Sign | algorithm=SHA384withECDSA | 1.83 | ±0.02 | ops/ms |
| jdk | Verify | algorithm=SHA256withECDSA | 4.28 | ±0.05 | ops/ms |
| jdk | Verify | algorithm=SHA384withECDSA | 1 | ±0.01 | ops/ms |

## Key Agreement Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | KeyAgreement | algorithm=ECDH | 4.12 | ±0.04 | ops/ms |
| glassless | KeyAgreement | algorithm=ECDH | 19.25 | ±0.16 | ops/ms |
| jdk | KeyAgreement | algorithm=ECDH | 3.07 | ±0.04 | ops/ms |

## Key Encapsulation (ML-KEM) Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| glassless | Decapsulate | algorithm=ML-KEM-1024 | 15.16 | ±0.11 | ops/ms |
| glassless | Decapsulate | algorithm=ML-KEM-512 | 29.95 | ±0.19 | ops/ms |
| glassless | Decapsulate | algorithm=ML-KEM-768 | 20.83 | ±0.24 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-1024 | 26.74 | ±0.52 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-512 | 54.36 | ±1.02 | ops/ms |
| glassless | Encapsulate | algorithm=ML-KEM-768 | 37.13 | ±0.92 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-1024 | 18.32 | ±0.4 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-512 | 31.86 | ±0.54 | ops/ms |
| glassless | KeyGen | algorithm=ML-KEM-768 | 24.24 | ±0.46 | ops/ms |
| jdk | Decapsulate | algorithm=ML-KEM-1024 | 33.47 | ±0.3 | ops/ms |
| jdk | Decapsulate | algorithm=ML-KEM-512 | 77.8 | ±1.23 | ops/ms |
| jdk | Decapsulate | algorithm=ML-KEM-768 | 51.49 | ±0.49 | ops/ms |
| jdk | Encapsulate | algorithm=ML-KEM-1024 | 39.04 | ±0.25 | ops/ms |
| jdk | Encapsulate | algorithm=ML-KEM-512 | 92.6 | ±0.94 | ops/ms |
| jdk | Encapsulate | algorithm=ML-KEM-768 | 59.06 | ±0.4 | ops/ms |
| jdk | KeyGen | algorithm=ML-KEM-1024 | 33.39 | ±0.23 | ops/ms |
| jdk | KeyGen | algorithm=ML-KEM-512 | 84.08 | ±0.96 | ops/ms |
| jdk | KeyGen | algorithm=ML-KEM-768 | 52.08 | ±0.26 | ops/ms |

## Key Pair Generator Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | GenerateKeyPair | algorithm=EC-P256 | 2.33 | ±0.11 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=EC-P384 | 0.95 | ±0.04 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-2048 | 0.01 | ±0 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P256 | 33.29 | ±1.02 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P384 | 6.49 | ±0.1 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-2048 | 0.04 | ±0.01 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P256 | 17.74 | ±0.56 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P384 | 2.03 | ±0.05 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P256 | 17.86 | ±0.49 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P384 | 2.06 | ±0.03 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |

## SecureRandom Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | NextBytes | byteCount=1024 | 3.64 | ±0.05 | ops/ms |
| bcFips | NextBytes | byteCount=16 | 2.82 | ±0.03 | ops/ms |
| bcFips | NextBytes | byteCount=256 | 2.9 | ±0.02 | ops/ms |
| bcFips | NextBytes | byteCount=32 | 2.81 | ±0.04 | ops/ms |
| bcFips | NextBytes | byteCount=4096 | 3.11 | ±0.11 | ops/ms |
| bcFips | NextBytes | byteCount=64 | 2.77 | ±0.02 | ops/ms |
| glassless | NextBytes | byteCount=1024 | 3015.69 | ±69.48 | ops/ms |
| glassless | NextBytes | byteCount=16 | 4799.25 | ±223.6 | ops/ms |
| glassless | NextBytes | byteCount=256 | 4224.07 | ±109.92 | ops/ms |
| glassless | NextBytes | byteCount=32 | 4746.28 | ±93.23 | ops/ms |
| glassless | NextBytes | byteCount=4096 | 1361.17 | ±20.29 | ops/ms |
| glassless | NextBytes | byteCount=64 | 4774.94 | ±102.42 | ops/ms |
| jdk | NextBytes | byteCount=1024 | 236.17 | ±24.84 | ops/ms |
| jdk | NextBytes | byteCount=16 | 10422.74 | ±197.27 | ops/ms |
| jdk | NextBytes | byteCount=256 | 982.28 | ±5.14 | ops/ms |
| jdk | NextBytes | byteCount=32 | 6325.02 | ±333.98 | ops/ms |
| jdk | NextBytes | byteCount=4096 | 60.98 | ±5.27 | ops/ms |
| jdk | NextBytes | byteCount=64 | 3520.35 | ±128.75 | ops/ms |
| nss | NextBytes | byteCount=1024 | 243.93 | ±5.74 | ops/ms |
| nss | NextBytes | byteCount=16 | 10391.94 | ±119.75 | ops/ms |
| nss | NextBytes | byteCount=256 | 980.59 | ±8.92 | ops/ms |
| nss | NextBytes | byteCount=32 | 6411.93 | ±295.97 | ops/ms |
| nss | NextBytes | byteCount=4096 | 61.08 | ±1.41 | ops/ms |
| nss | NextBytes | byteCount=64 | 3505.04 | ±183.46 | ops/ms |

## Notes

- **Throughput** is measured in operations per millisecond (ops/ms). Higher is better.
- **Error** shows the 99.9% confidence interval.
- **Provider characteristics**:
  - **JDK**: Benefits from HotSpot intrinsics for SHA-256, SHA-512, AES, and other common algorithms
  - **GlaSSLess (OpenSSL)**: Excels at asymmetric cryptography; FFM call overhead affects small-data operations
  - **BC FIPS**: FIPS 140-2 certified; pure Java implementation with some native acceleration
  - **NSS**: Mozilla's Network Security Services via SunPKCS11; requires system NSS libraries
- **Post-Quantum Cryptography**: ML-KEM is available in both JDK 24+ and GlaSSLess (OpenSSL 3.5+). ML-DSA and SLH-DSA require OpenSSL 3.5+ and are currently only available in GlaSSLess.
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
