# Glassless Performance Report

This report compares the performance of Glassless (OpenSSL) vs JDK cryptographic implementations.

> **Note**: These benchmarks measure throughput (operations per millisecond). Higher is better.
> Results vary by hardware, JVM version, and OpenSSL version.

## Test Environment

| Property | Value |
|----------|-------|
| Date | 2026-02-14T10:19:36+01:00 |
| Host | jakku |
| CPU | AMD Ryzen 9 9900X 12-Core Processor |
| Java | openjdk version "25.0.2" 2026-01-20 |
| OpenSSL | OpenSSL 3.5.3 16 Sep 2025 (Library: OpenSSL 3.5.3 16 Sep 2025) |

## Performance Summary

### Glassless Advantages (OpenSSL faster)

| Category | Operation | Speedup |
|----------|-----------|--------:|
| Key Agreement | ECDH | 6.3x |
| Key Agreement | X25519 | 1.7x |
| Key Generation | Ed25519 | 4.8x |
| Key Generation | EC P-256 | 1.9x |
| Signature | Ed25519 Sign | 8.4x |
| Signature | Ed25519 Verify | 5.7x |

### JDK Advantages (JDK intrinsics faster for small data)

| Category | Operation | JDK Speedup |
|----------|-----------|------------:|
| MessageDigest | SHA-256 (64B) | 6.3x |
| MAC | HmacSHA256 (64B) | 8.5x |

## MessageDigest Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessDigest | algorithm=SHA-256, dataSize=64 | 2373.03 | ±448.5 | ops/ms |
| glasslessDigest | algorithm=SHA-256, dataSize=1024 | 989.24 | ±308.4 | ops/ms |
| glasslessDigest | algorithm=SHA-256, dataSize=16384 | 110.85 | ±7.76 | ops/ms |
| glasslessDigest | algorithm=SHA-256, dataSize=1048576 | 1.87 | ±0.09 | ops/ms |
| glasslessDigest | algorithm=SHA-512, dataSize=64 | 1984.94 | ±139.38 | ops/ms |
| glasslessDigest | algorithm=SHA-512, dataSize=1024 | 702.3 | ±56.65 | ops/ms |
| glasslessDigest | algorithm=SHA-512, dataSize=16384 | 74.63 | ±1.66 | ops/ms |
| glasslessDigest | algorithm=SHA-512, dataSize=1048576 | 1.21 | ±0.05 | ops/ms |
| glasslessDigest | algorithm=SHA3-256, dataSize=64 | 1679.5 | ±225.6 | ops/ms |
| glasslessDigest | algorithm=SHA3-256, dataSize=1024 | 502.89 | ±63.83 | ops/ms |
| glasslessDigest | algorithm=SHA3-256, dataSize=16384 | 42.27 | ±0.43 | ops/ms |
| glasslessDigest | algorithm=SHA3-256, dataSize=1048576 | 0.69 | ±0.03 | ops/ms |
| jdkDigest | algorithm=SHA-256, dataSize=64 | 15001.57 | ±236.5 | ops/ms |
| jdkDigest | algorithm=SHA-256, dataSize=1024 | 2375.98 | ±68.09 | ops/ms |
| jdkDigest | algorithm=SHA-256, dataSize=16384 | 162.18 | ±15.31 | ops/ms |
| jdkDigest | algorithm=SHA-256, dataSize=1048576 | 2.59 | ±0.12 | ops/ms |
| jdkDigest | algorithm=SHA-512, dataSize=64 | 8386.72 | ±738.02 | ops/ms |
| jdkDigest | algorithm=SHA-512, dataSize=1024 | 1122.09 | ±45.88 | ops/ms |
| jdkDigest | algorithm=SHA-512, dataSize=16384 | 82.15 | ±0.46 | ops/ms |
| jdkDigest | algorithm=SHA-512, dataSize=1048576 | 1.25 | ±0.08 | ops/ms |
| jdkDigest | algorithm=SHA3-256, dataSize=64 | 2736.27 | ±61.37 | ops/ms |
| jdkDigest | algorithm=SHA3-256, dataSize=1024 | 356.74 | ±2.36 | ops/ms |
| jdkDigest | algorithm=SHA3-256, dataSize=16384 | 23.83 | ±0.07 | ops/ms |
| jdkDigest | algorithm=SHA3-256, dataSize=1048576 | 0.37 | ±0.01 | ops/ms |

## Cipher Benchmarks

_No data available for this benchmark._

## MAC Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessMac | algorithm=HmacSHA256, dataSize=64 | 727.66 | ±528.48 | ops/ms |
| glasslessMac | algorithm=HmacSHA256, dataSize=1024 | 582.62 | ±220 | ops/ms |
| glasslessMac | algorithm=HmacSHA256, dataSize=16384 | 132.25 | ±30.76 | ops/ms |
| glasslessMac | algorithm=HmacSHA256, dataSize=1048576 | 2.45 | ±0.07 | ops/ms |
| glasslessMac | algorithm=HmacSHA512, dataSize=64 | 561.65 | ±144.63 | ops/ms |
| glasslessMac | algorithm=HmacSHA512, dataSize=1024 | 397.64 | ±99.5 | ops/ms |
| glasslessMac | algorithm=HmacSHA512, dataSize=16384 | 80.01 | ±18.46 | ops/ms |
| glasslessMac | algorithm=HmacSHA512, dataSize=1048576 | 1.46 | ±0.01 | ops/ms |
| glasslessMac | algorithm=HmacSHA3-256, dataSize=64 | 431.97 | ±93.77 | ops/ms |
| glasslessMac | algorithm=HmacSHA3-256, dataSize=1024 | 279.78 | ±81.68 | ops/ms |
| glasslessMac | algorithm=HmacSHA3-256, dataSize=16384 | 43.46 | ±6.21 | ops/ms |
| glasslessMac | algorithm=HmacSHA3-256, dataSize=1048576 | 0.76 | ±0 | ops/ms |
| jdkMac | algorithm=HmacSHA256, dataSize=64 | 6214.72 | ±135.71 | ops/ms |
| jdkMac | algorithm=HmacSHA256, dataSize=1024 | 1936.63 | ±73.6 | ops/ms |
| jdkMac | algorithm=HmacSHA256, dataSize=16384 | 162.56 | ±3.34 | ops/ms |
| jdkMac | algorithm=HmacSHA256, dataSize=1048576 | 2.6 | ±0.03 | ops/ms |
| jdkMac | algorithm=HmacSHA512, dataSize=64 | 2214.18 | ±58.73 | ops/ms |
| jdkMac | algorithm=HmacSHA512, dataSize=1024 | 796.33 | ±23.93 | ops/ms |
| jdkMac | algorithm=HmacSHA512, dataSize=16384 | 79.13 | ±0.83 | ops/ms |
| jdkMac | algorithm=HmacSHA512, dataSize=1048576 | 1.29 | ±0.02 | ops/ms |
| jdkMac | algorithm=HmacSHA3-256, dataSize=64 | 690.44 | ±2.1 | ops/ms |
| jdkMac | algorithm=HmacSHA3-256, dataSize=1024 | 254.64 | ±15.28 | ops/ms |
| jdkMac | algorithm=HmacSHA3-256, dataSize=16384 | 23.23 | ±0.06 | ops/ms |
| jdkMac | algorithm=HmacSHA3-256, dataSize=1048576 | 0.37 | ±0.01 | ops/ms |

## Signature Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessSign | algorithm=Ed25519 | 27.4 | ±0.89 | ops/ms |
| glasslessVerify | algorithm=Ed25519 | 19.76 | ±0.27 | ops/ms |
| jdkSign | algorithm=SHA256withECDSA | 13.43 | ±0.29 | ops/ms |
| jdkSign | algorithm=SHA384withECDSA | 1.78 | ±0.04 | ops/ms |
| jdkSign | algorithm=Ed25519 | 3.25 | ±0.15 | ops/ms |
| jdkVerify | algorithm=SHA256withECDSA | 4.24 | ±0.11 | ops/ms |
| jdkVerify | algorithm=SHA384withECDSA | 0.98 | ±0.01 | ops/ms |
| jdkVerify | algorithm=Ed25519 | 3.5 | ±0.17 | ops/ms |

## Key Agreement Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessKeyAgreement | algorithm=ECDH | 19.03 | ±0.31 | ops/ms |
| glasslessKeyAgreement | algorithm=X25519 | 24.94 | ±0.49 | ops/ms |
| jdkKeyAgreement | algorithm=ECDH | 3.04 | ±0.08 | ops/ms |
| jdkKeyAgreement | algorithm=X25519 | 14.26 | ±0.06 | ops/ms |

## Key Pair Generator Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessGenerateKeyPair | algorithm=EC-P256 | 33.09 | ±0.7 | ops/ms |
| glasslessGenerateKeyPair | algorithm=EC-P384 | 6.4 | ±0.24 | ops/ms |
| glasslessGenerateKeyPair | algorithm=RSA-2048 | 0.04 | ±0.01 | ops/ms |
| glasslessGenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| glasslessGenerateKeyPair | algorithm=Ed25519 | 32.63 | ±0.37 | ops/ms |
| glasslessGenerateKeyPair | algorithm=X25519 | 32.23 | ±0.96 | ops/ms |
| jdkGenerateKeyPair | algorithm=EC-P256 | 17.58 | ±0.48 | ops/ms |
| jdkGenerateKeyPair | algorithm=EC-P384 | 2.04 | ±0.03 | ops/ms |
| jdkGenerateKeyPair | algorithm=RSA-2048 | 0.02 | ±0.01 | ops/ms |
| jdkGenerateKeyPair | algorithm=RSA-4096 | 0 | ±0 | ops/ms |
| jdkGenerateKeyPair | algorithm=Ed25519 | 6.86 | ±0.16 | ops/ms |
| jdkGenerateKeyPair | algorithm=X25519 | 14.13 | ±0.18 | ops/ms |

## SecureRandom Benchmarks

| Operation | Parameters | Score | Error | Unit |
|-----------|------------|------:|------:|------|
| glasslessNextBytes | byteCount=16 | 4587.41 | ±180.45 | ops/ms |
| glasslessNextBytes | byteCount=32 | 4527.16 | ±18.61 | ops/ms |
| glasslessNextBytes | byteCount=64 | 4540.2 | ±214.86 | ops/ms |
| glasslessNextBytes | byteCount=256 | 4063.2 | ±228.17 | ops/ms |
| glasslessNextBytes | byteCount=1024 | 2974.63 | ±110.59 | ops/ms |
| glasslessNextBytes | byteCount=4096 | 1304.24 | ±7.02 | ops/ms |
| jdkNextBytes | byteCount=16 | 10322.94 | ±999.26 | ops/ms |
| jdkNextBytes | byteCount=32 | 6390.07 | ±510.76 | ops/ms |
| jdkNextBytes | byteCount=64 | 3497.82 | ±173.68 | ops/ms |
| jdkNextBytes | byteCount=256 | 983.3 | ±24.48 | ops/ms |
| jdkNextBytes | byteCount=1024 | 239.03 | ±4.24 | ops/ms |
| jdkNextBytes | byteCount=4096 | 49.34 | ±1.14 | ops/ms |

## Notes

- **Throughput** is measured in operations per millisecond (ops/ms). Higher is better.
- **Error** shows the 99.9% confidence interval.
- JDK implementations benefit from HotSpot intrinsics for common algorithms like SHA-256.
- Glassless/OpenSSL excels at asymmetric cryptography (key generation, key agreement, signatures).
- For large data sizes (16KB+), performance typically converges between implementations.
- FFM call overhead affects small-data operations more significantly.

## Reproducing Results

```bash
# Run all benchmarks
mvn test -Pbenchmarks

# Generate this report
./scripts/generate-performance-report.sh

# Run specific benchmark
mvn test -Pbenchmarks -Dexec.args=".*MessageDigestBenchmark.*"
```
