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
| Date | 2026-02-14T14:38:05+01:00 |
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
| Key Agreement | ECDH | 19.23 | 3.09 | 4.14 | - |
| Key Agreement | X25519 | - | - | - | - |
| Key Generation | Ed25519 | - | - | - | - |
| Key Generation | EC P-256 | 33.05 | 17.81 | 2.32 | 17.78 |
| Signature | Ed25519 Sign | - | - | - | - |
| Signature | Ed25519 Verify | - | - | - | - |
| Digest | SHA-256 (64B) | 2592.21 | 15081.45 | 8024.14 | - |
| MAC | HMAC-SHA256 (64B) | 771.83 | 6162.4 | 2424.12 | - |

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
| bcFips | Digest | algorithm=SHA-256, dataSize=1024 | 2012.99 | ±62.72 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=1048576 | 2.45 | ±0.01 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=16384 | 154.21 | ±1.32 | ops/ms |
| bcFips | Digest | algorithm=SHA-256, dataSize=64 | 8024.14 | ±258.66 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1024 | 474.87 | ±3.65 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=1048576 | 0.55 | ±0 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=16384 | 33.76 | ±0.23 | ops/ms |
| bcFips | Digest | algorithm=SHA-512, dataSize=64 | 3705.31 | ±123.13 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1024 | 1051.66 | ±166.92 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=1048576 | 1.88 | ±0.03 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=16384 | 112.7 | ±4.52 | ops/ms |
| glassless | Digest | algorithm=SHA-256, dataSize=64 | 2592.21 | ±1031.7 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1024 | 743.29 | ±59.72 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=1048576 | 1.23 | ±0.03 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=16384 | 74.4 | ±1.55 | ops/ms |
| glassless | Digest | algorithm=SHA-512, dataSize=64 | 2062.09 | ±437.42 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1024 | 2406.89 | ±38.14 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=1048576 | 2.62 | ±0.01 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=16384 | 166.61 | ±0.56 | ops/ms |
| jdk | Digest | algorithm=SHA-256, dataSize=64 | 15081.45 | ±260.35 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1024 | 1153.62 | ±20.58 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=1048576 | 1.31 | ±0.01 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=16384 | 82.76 | ±0.6 | ops/ms |
| jdk | Digest | algorithm=SHA-512, dataSize=64 | 8380.67 | ±286.47 | ops/ms |

## Cipher Benchmarks

_No data available for this benchmark._

## MAC Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1024 | 1272.28 | ±26.51 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.45 | ±0 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=16384 | 147.38 | ±1.89 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA256, dataSize=64 | 2424.12 | ±43.37 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1024 | 385.21 | ±0.82 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=1048576 | 0.54 | ±0 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=16384 | 33.32 | ±0.12 | ops/ms |
| bcFips | Mac | algorithm=HmacSHA512, dataSize=64 | 1278.88 | ±24.17 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1024 | 584.25 | ±161.92 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.48 | ±0 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=16384 | 132.15 | ±28.83 | ops/ms |
| glassless | Mac | algorithm=HmacSHA256, dataSize=64 | 771.83 | ±594.03 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1024 | 395.19 | ±93.22 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.47 | ±0 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=16384 | 82.22 | ±14.63 | ops/ms |
| glassless | Mac | algorithm=HmacSHA512, dataSize=64 | 550.65 | ±156.27 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1024 | 1954.14 | ±35.67 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=1048576 | 2.62 | ±0 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=16384 | 163.93 | ±0.25 | ops/ms |
| jdk | Mac | algorithm=HmacSHA256, dataSize=64 | 6162.4 | ±174.29 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1024 | 832.2 | ±13.31 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=1048576 | 1.31 | ±0.01 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=16384 | 80.54 | ±0.61 | ops/ms |
| jdk | Mac | algorithm=HmacSHA512, dataSize=64 | 2235.06 | ±45.02 | ops/ms |

## Signature Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | Sign | algorithm=SHA256withECDSA | 3.09 | ±0.09 | ops/ms |
| bcFips | Sign | algorithm=SHA384withECDSA | 3.4 | ±0.37 | ops/ms |
| bcFips | Verify | algorithm=SHA256withECDSA | 6.51 | ±0.1 | ops/ms |
| bcFips | Verify | algorithm=SHA384withECDSA | 2.46 | ±0.05 | ops/ms |
| glassless | Verify | algorithm=SHA256withECDSA | 22.46 | ±0.51 | ops/ms |
| glassless | Verify | algorithm=SHA384withECDSA | 3.45 | ±0.04 | ops/ms |
| jdk | Sign | algorithm=SHA256withECDSA | 13.61 | ±0.4 | ops/ms |
| jdk | Sign | algorithm=SHA384withECDSA | 1.81 | ±0.04 | ops/ms |
| jdk | Verify | algorithm=SHA256withECDSA | 4.34 | ±0.08 | ops/ms |
| jdk | Verify | algorithm=SHA384withECDSA | 1.01 | ±0.02 | ops/ms |

## Key Agreement Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | KeyAgreement | algorithm=ECDH | 4.14 | ±0.03 | ops/ms |
| glassless | KeyAgreement | algorithm=ECDH | 19.23 | ±0.25 | ops/ms |
| jdk | KeyAgreement | algorithm=ECDH | 3.09 | ±0.08 | ops/ms |

## Key Pair Generator Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | GenerateKeyPair | algorithm=EC-P256 | 2.32 | ±0.04 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=EC-P384 | 0.97 | ±0.04 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-2048 | 0.01 | ±0.01 | ops/ms |
| bcFips | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P256 | 33.05 | ±0.91 | ops/ms |
| glassless | GenerateKeyPair | algorithm=EC-P384 | 6.47 | ±0.15 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-2048 | 0.04 | ±0.01 | ops/ms |
| glassless | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P256 | 17.81 | ±0.49 | ops/ms |
| jdk | GenerateKeyPair | algorithm=EC-P384 | 2.05 | ±0.03 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| jdk | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P256 | 17.78 | ±0.47 | ops/ms |
| nss | GenerateKeyPair | algorithm=EC-P384 | 2.06 | ±0.06 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| nss | GenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |

## SecureRandom Benchmarks

| Provider | Operation | Parameters | Score | Error | Unit |
|----------|-----------|------------|------:|------:|------|
| bcFips | NextBytes | byteCount=1024 | 3.61 | ±0.18 | ops/ms |
| bcFips | NextBytes | byteCount=16 | 2.82 | ±0.03 | ops/ms |
| bcFips | NextBytes | byteCount=256 | 2.88 | ±0.02 | ops/ms |
| bcFips | NextBytes | byteCount=32 | 2.83 | ±0.01 | ops/ms |
| bcFips | NextBytes | byteCount=4096 | 2.94 | ±0.03 | ops/ms |
| bcFips | NextBytes | byteCount=64 | 2.76 | ±0.03 | ops/ms |
| glassless | NextBytes | byteCount=1024 | 2894.44 | ±91.32 | ops/ms |
| glassless | NextBytes | byteCount=16 | 4909.66 | ±88.88 | ops/ms |
| glassless | NextBytes | byteCount=256 | 4187.15 | ±274.78 | ops/ms |
| glassless | NextBytes | byteCount=32 | 4873.44 | ±154.28 | ops/ms |
| glassless | NextBytes | byteCount=4096 | 1369.09 | ±55.88 | ops/ms |
| glassless | NextBytes | byteCount=64 | 4783.15 | ±89.24 | ops/ms |
| jdk | NextBytes | byteCount=1024 | 243.85 | ±8.58 | ops/ms |
| jdk | NextBytes | byteCount=16 | 10270.84 | ±503.77 | ops/ms |
| jdk | NextBytes | byteCount=256 | 983.03 | ±47.6 | ops/ms |
| jdk | NextBytes | byteCount=32 | 6405.95 | ±94.34 | ops/ms |
| jdk | NextBytes | byteCount=4096 | 60.57 | ±0.93 | ops/ms |
| jdk | NextBytes | byteCount=64 | 3486.85 | ±40.55 | ops/ms |
| nss | NextBytes | byteCount=1024 | 239.73 | ±10.66 | ops/ms |
| nss | NextBytes | byteCount=16 | 10363.95 | ±482.1 | ops/ms |
| nss | NextBytes | byteCount=256 | 985.02 | ±65.95 | ops/ms |
| nss | NextBytes | byteCount=32 | 6211.59 | ±177.05 | ops/ms |
| nss | NextBytes | byteCount=4096 | 60.78 | ±1.83 | ops/ms |
| nss | NextBytes | byteCount=64 | 3498.13 | ±83.33 | ops/ms |

## Notes

- **Throughput** is measured in operations per millisecond (ops/ms). Higher is better.
- **Error** shows the 99.9% confidence interval.
- **Provider characteristics**:
  - **JDK**: Benefits from HotSpot intrinsics for SHA-256, SHA-512, AES, and other common algorithms
  - **GlaSSLess (OpenSSL)**: Excels at asymmetric cryptography; FFM call overhead affects small-data operations
  - **BC FIPS**: FIPS 140-2 certified; pure Java implementation with some native acceleration
  - **NSS**: Mozilla's Network Security Services via SunPKCS11; requires system NSS libraries
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
