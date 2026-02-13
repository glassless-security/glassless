#!/bin/bash
#
# Generate PERFORMANCE.md from JMH benchmark results
#
# Usage: ./scripts/generate-performance-report.sh [jmh-results.json]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INPUT_FILE="${1:-$PROJECT_DIR/target/jmh-results.json}"
OUTPUT_FILE="$PROJECT_DIR/PERFORMANCE.md"

if [ ! -f "$INPUT_FILE" ]; then
   echo "Error: JMH results file not found: $INPUT_FILE"
   echo "Run benchmarks first: mvn test -Pbenchmarks"
   exit 1
fi

# Check for jq
if ! command -v jq &> /dev/null; then
   echo "Error: jq is required but not installed."
   echo "Install with: sudo apt install jq"
   exit 1
fi

# Get system info
JAVA_VERSION=$(java -version 2>&1 | head -1)
OPENSSL_VERSION=$(openssl version 2>/dev/null || echo "Unknown")
HOSTNAME=$(hostname)
DATE=$(date -Iseconds)
CPU_MODEL=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unknown")

cat > "$OUTPUT_FILE" << 'HEADER'
# Glassless Performance Report

This report compares the performance of Glassless (OpenSSL) vs JDK cryptographic implementations.

> **Note**: These benchmarks measure throughput (operations per millisecond). Higher is better.
> Results vary by hardware, JVM version, and OpenSSL version.

HEADER

cat >> "$OUTPUT_FILE" << EOF
## Test Environment

| Property | Value |
|----------|-------|
| Date | $DATE |
| Host | $HOSTNAME |
| CPU | $CPU_MODEL |
| Java | $JAVA_VERSION |
| OpenSSL | $OPENSSL_VERSION |

EOF

# Function to extract and format benchmark data
generate_table() {
   local benchmark_prefix="$1"
   local title="$2"

   echo "## $title" >> "$OUTPUT_FILE"
   echo "" >> "$OUTPUT_FILE"

   # Get unique parameter combinations
   jq -r --arg prefix "$benchmark_prefix" '
      .[] | select(.benchmark | startswith($prefix)) |
      {
         benchmark: (.benchmark | split(".") | last),
         params: (.params // {}),
         score: .primaryMetric.score,
         error: .primaryMetric.scoreError,
         unit: .primaryMetric.scoreUnit
      }
   ' "$INPUT_FILE" | jq -s '.' > /tmp/benchmarks.json

   # Check if we have data
   if [ "$(jq 'length' /tmp/benchmarks.json)" -eq 0 ]; then
      echo "_No data available for this benchmark._" >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
      return
   fi

   # Detect parameters
   local params=$(jq -r '.[0].params | keys[]' /tmp/benchmarks.json 2>/dev/null | head -1)

   if [ -n "$params" ] && [ "$params" != "null" ]; then
      echo "| Operation | Parameters | Score | Error | Unit |" >> "$OUTPUT_FILE"
      echo "|-----------|------------|------:|------:|------|" >> "$OUTPUT_FILE"
      jq -r '.[] | "| \(.benchmark) | \(.params | to_entries | map("\(.key)=\(.value)") | join(", ")) | \(.score | . * 100 | round / 100) | ±\(.error | . * 100 | round / 100) | \(.unit) |"' /tmp/benchmarks.json >> "$OUTPUT_FILE"
   else
      echo "| Operation | Score | Error | Unit |" >> "$OUTPUT_FILE"
      echo "|-----------|------:|------:|------|" >> "$OUTPUT_FILE"
      jq -r '.[] | "| \(.benchmark) | \(.score | . * 100 | round / 100) | ±\(.error | . * 100 | round / 100) | \(.unit) |"' /tmp/benchmarks.json >> "$OUTPUT_FILE"
   fi

   echo "" >> "$OUTPUT_FILE"
}

# Generate comparison summary
echo "## Performance Summary" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "### Glassless Advantages (OpenSSL faster)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "| Category | Operation | Speedup |" >> "$OUTPUT_FILE"
echo "|----------|-----------|--------:|" >> "$OUTPUT_FILE"

# Calculate speedups for key operations
jq -r '
   def get_score(name; params):
      [.[] | select(.benchmark | endswith(name)) | select(if params then (.params | to_entries | all(. as $e | params | has($e.key) and .[$e.key] == $e.value)) else true end)] | .[0].primaryMetric.score // 0;

   # Key Agreement
   (get_score("glasslessKeyAgreement"; {algorithm: "ECDH"})) as $gl_ecdh |
   (get_score("jdkKeyAgreement"; {algorithm: "ECDH"})) as $jdk_ecdh |
   (get_score("glasslessKeyAgreement"; {algorithm: "X25519"})) as $gl_x25519 |
   (get_score("jdkKeyAgreement"; {algorithm: "X25519"})) as $jdk_x25519 |

   # Key Generation
   (get_score("glasslessGenerateKeyPair"; {algorithm: "Ed25519"})) as $gl_ed25519_gen |
   (get_score("jdkGenerateKeyPair"; {algorithm: "Ed25519"})) as $jdk_ed25519_gen |
   (get_score("glasslessGenerateKeyPair"; {algorithm: "EC-P256"})) as $gl_ec256_gen |
   (get_score("jdkGenerateKeyPair"; {algorithm: "EC-P256"})) as $jdk_ec256_gen |

   # Signatures
   (get_score("glasslessSign"; {algorithm: "Ed25519"})) as $gl_ed_sign |
   (get_score("jdkSign"; {algorithm: "Ed25519"})) as $jdk_ed_sign |
   (get_score("glasslessVerify"; {algorithm: "Ed25519"})) as $gl_ed_verify |
   (get_score("jdkVerify"; {algorithm: "Ed25519"})) as $jdk_ed_verify |

   if $jdk_ecdh > 0 then "| Key Agreement | ECDH | \(($gl_ecdh / $jdk_ecdh * 10 | round / 10))x |" else empty end,
   if $jdk_x25519 > 0 then "| Key Agreement | X25519 | \(($gl_x25519 / $jdk_x25519 * 10 | round / 10))x |" else empty end,
   if $jdk_ed25519_gen > 0 then "| Key Generation | Ed25519 | \(($gl_ed25519_gen / $jdk_ed25519_gen * 10 | round / 10))x |" else empty end,
   if $jdk_ec256_gen > 0 then "| Key Generation | EC P-256 | \(($gl_ec256_gen / $jdk_ec256_gen * 10 | round / 10))x |" else empty end,
   if $jdk_ed_sign > 0 then "| Signature | Ed25519 Sign | \(($gl_ed_sign / $jdk_ed_sign * 10 | round / 10))x |" else empty end,
   if $jdk_ed_verify > 0 then "| Signature | Ed25519 Verify | \(($gl_ed_verify / $jdk_ed_verify * 10 | round / 10))x |" else empty end
' "$INPUT_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "### JDK Advantages (JDK intrinsics faster for small data)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "| Category | Operation | JDK Speedup |" >> "$OUTPUT_FILE"
echo "|----------|-----------|------------:|" >> "$OUTPUT_FILE"

jq -r '
   def get_score(name; params):
      [.[] | select(.benchmark | endswith(name)) | select(if params then (.params | to_entries | all(. as $e | params | has($e.key) and .[$e.key] == $e.value)) else true end)] | .[0].primaryMetric.score // 0;

   # Small data hashing
   (get_score("glasslessDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $gl_sha256 |
   (get_score("jdkDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $jdk_sha256 |
   (get_score("glasslessMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $gl_hmac |
   (get_score("jdkMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $jdk_hmac |

   if $gl_sha256 > 0 then "| MessageDigest | SHA-256 (64B) | \(($jdk_sha256 / $gl_sha256 * 10 | round / 10))x |" else empty end,
   if $gl_hmac > 0 then "| MAC | HmacSHA256 (64B) | \(($jdk_hmac / $gl_hmac * 10 | round / 10))x |" else empty end
' "$INPUT_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# Generate detailed tables
generate_table "net.glassless.provider.benchmark.MessageDigestBenchmark" "MessageDigest Benchmarks"
generate_table "net.glassless.provider.benchmark.CipherBenchmark" "Cipher Benchmarks"
generate_table "net.glassless.provider.benchmark.MacBenchmark" "MAC Benchmarks"
generate_table "net.glassless.provider.benchmark.SignatureBenchmark" "Signature Benchmarks"
generate_table "net.glassless.provider.benchmark.KeyAgreementBenchmark" "Key Agreement Benchmarks"
generate_table "net.glassless.provider.benchmark.KeyPairGeneratorBenchmark" "Key Pair Generator Benchmarks"
generate_table "net.glassless.provider.benchmark.SecureRandomBenchmark" "SecureRandom Benchmarks"

# Add notes
cat >> "$OUTPUT_FILE" << 'FOOTER'
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
FOOTER

echo "Generated: $OUTPUT_FILE"
