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
NSS_VERSION=$(nss-config --version 2>/dev/null || pkg-config nss --modversion 2>/dev/null || echo "Unknown")
HOSTNAME=$(hostname)
DATE=$(date -Iseconds)
CPU_MODEL=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "Unknown")

cat > "$OUTPUT_FILE" << 'HEADER'
# GlaSSLess Performance Report

This report compares the performance of multiple JCA cryptographic providers:

- **GlaSSLess** - OpenSSL-based provider using FFM (Foreign Function & Memory API)
- **JDK** - Standard JDK provider with HotSpot intrinsics
- **BC FIPS** - Bouncy Castle FIPS certified provider
- **NSS** - Mozilla NSS via SunPKCS11 (when available)

> **Note**: These benchmarks measure throughput (operations per millisecond). Higher is better.
> Results vary by hardware, JVM version, and library versions.

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
| NSS | $NSS_VERSION |

EOF

# Function to extract and format benchmark data
generate_table() {
   local benchmark_prefix="$1"
   local title="$2"

   echo "## $title" >> "$OUTPUT_FILE"
   echo "" >> "$OUTPUT_FILE"

   # Get unique parameter combinations with provider extracted
   jq -r --arg prefix "$benchmark_prefix" '
      .[] | select(.benchmark | startswith($prefix)) |
      (.benchmark | split(".") | last) as $method |
      ($method | capture("^(?<provider>glassless|jdk|bcFips|nss)(?<op>.*)$") // {provider: "unknown", op: $method}) as $parsed |
      {
         provider: $parsed.provider,
         operation: $parsed.op,
         params: (.params // {}),
         score: .primaryMetric.score,
         error: .primaryMetric.scoreError,
         unit: .primaryMetric.scoreUnit
      }
   ' "$INPUT_FILE" | jq -s 'sort_by(.provider, .operation, (.params | to_entries | map(.value) | join(",")))' > /tmp/benchmarks.json

   # Check if we have data
   if [ "$(jq 'length' /tmp/benchmarks.json)" -eq 0 ]; then
      echo "_No data available for this benchmark._" >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
      return
   fi

   # Detect parameters
   local params=$(jq -r '.[0].params | keys[]' /tmp/benchmarks.json 2>/dev/null | head -1)

   if [ -n "$params" ] && [ "$params" != "null" ]; then
      echo "| Provider | Operation | Parameters | Score | Error | Unit |" >> "$OUTPUT_FILE"
      echo "|----------|-----------|------------|------:|------:|------|" >> "$OUTPUT_FILE"
      jq -r '.[] | "| \(.provider) | \(.operation) | \(.params | to_entries | map("\(.key)=\(.value)") | join(", ")) | \(.score | . * 100 | round / 100) | ±\(.error | . * 100 | round / 100) | \(.unit) |"' /tmp/benchmarks.json >> "$OUTPUT_FILE"
   else
      echo "| Provider | Operation | Score | Error | Unit |" >> "$OUTPUT_FILE"
      echo "|----------|-----------|------:|------:|------|" >> "$OUTPUT_FILE"
      jq -r '.[] | "| \(.provider) | \(.operation) | \(.score | . * 100 | round / 100) | ±\(.error | . * 100 | round / 100) | \(.unit) |"' /tmp/benchmarks.json >> "$OUTPUT_FILE"
   fi

   echo "" >> "$OUTPUT_FILE"
}

# Generate comparison summary
echo "## Performance Summary" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Detect available providers from the benchmark results
PROVIDERS=$(jq -r '[.[].benchmark | split(".") | last | capture("^(?<provider>glassless|jdk|bcFips|nss)") | .provider] | unique | .[]' "$INPUT_FILE" 2>/dev/null | sort -u)

echo "Benchmarks include the following providers: $(echo $PROVIDERS | tr '\n' ' ' | sed 's/ /, /g' | sed 's/, $//')" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Generate comprehensive comparison table for key operations
echo "### Key Operations Comparison" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "| Category | Operation | GlaSSLess | JDK | BC FIPS | NSS |" >> "$OUTPUT_FILE"
echo "|----------|-----------|----------:|----:|--------:|----:|" >> "$OUTPUT_FILE"

jq -r '
   def get_score(name; params):
      [.[] | select(.benchmark | endswith(name)) | select(if params then (.params | to_entries | all(. as $e | params | has($e.key) and .[$e.key] == $e.value)) else true end)] | .[0].primaryMetric.score // null;

   def format_score(s):
      if s == null then "-" else (s * 100 | round / 100 | tostring) end;

   # Key Agreement
   (get_score("glasslessKeyAgreement"; {algorithm: "ECDH"})) as $gl_ecdh |
   (get_score("jdkKeyAgreement"; {algorithm: "ECDH"})) as $jdk_ecdh |
   (get_score("bcFipsKeyAgreement"; {algorithm: "ECDH"})) as $bc_ecdh |
   (get_score("nssKeyAgreement"; {algorithm: "ECDH"})) as $nss_ecdh |

   (get_score("glasslessKeyAgreement"; {algorithm: "X25519"})) as $gl_x25519 |
   (get_score("jdkKeyAgreement"; {algorithm: "X25519"})) as $jdk_x25519 |
   (get_score("bcFipsKeyAgreement"; {algorithm: "X25519"})) as $bc_x25519 |
   (get_score("nssKeyAgreement"; {algorithm: "X25519"})) as $nss_x25519 |

   # Key Generation
   (get_score("glasslessGenerateKeyPair"; {algorithm: "Ed25519"})) as $gl_ed25519_gen |
   (get_score("jdkGenerateKeyPair"; {algorithm: "Ed25519"})) as $jdk_ed25519_gen |
   (get_score("bcFipsGenerateKeyPair"; {algorithm: "Ed25519"})) as $bc_ed25519_gen |
   (get_score("nssGenerateKeyPair"; {algorithm: "Ed25519"})) as $nss_ed25519_gen |

   (get_score("glasslessGenerateKeyPair"; {algorithm: "EC-P256"})) as $gl_ec256_gen |
   (get_score("jdkGenerateKeyPair"; {algorithm: "EC-P256"})) as $jdk_ec256_gen |
   (get_score("bcFipsGenerateKeyPair"; {algorithm: "EC-P256"})) as $bc_ec256_gen |
   (get_score("nssGenerateKeyPair"; {algorithm: "EC-P256"})) as $nss_ec256_gen |

   # Signatures
   (get_score("glasslessSign"; {algorithm: "Ed25519"})) as $gl_ed_sign |
   (get_score("jdkSign"; {algorithm: "Ed25519"})) as $jdk_ed_sign |
   (get_score("bcFipsSign"; {algorithm: "Ed25519"})) as $bc_ed_sign |
   (get_score("nssSign"; {algorithm: "Ed25519"})) as $nss_ed_sign |

   (get_score("glasslessVerify"; {algorithm: "Ed25519"})) as $gl_ed_verify |
   (get_score("jdkVerify"; {algorithm: "Ed25519"})) as $jdk_ed_verify |
   (get_score("bcFipsVerify"; {algorithm: "Ed25519"})) as $bc_ed_verify |
   (get_score("nssVerify"; {algorithm: "Ed25519"})) as $nss_ed_verify |

   # Small data hashing
   (get_score("glasslessDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $gl_sha256 |
   (get_score("jdkDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $jdk_sha256 |
   (get_score("bcFipsDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $bc_sha256 |
   (get_score("nssDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $nss_sha256 |

   (get_score("glasslessMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $gl_hmac |
   (get_score("jdkMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $jdk_hmac |
   (get_score("bcFipsMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $bc_hmac |
   (get_score("nssMac"; {algorithm: "HmacSHA256", dataSize: "64"})) as $nss_hmac |

   "| Key Agreement | ECDH | \(format_score($gl_ecdh)) | \(format_score($jdk_ecdh)) | \(format_score($bc_ecdh)) | \(format_score($nss_ecdh)) |",
   "| Key Agreement | X25519 | \(format_score($gl_x25519)) | \(format_score($jdk_x25519)) | \(format_score($bc_x25519)) | \(format_score($nss_x25519)) |",
   "| Key Generation | Ed25519 | \(format_score($gl_ed25519_gen)) | \(format_score($jdk_ed25519_gen)) | \(format_score($bc_ed25519_gen)) | \(format_score($nss_ed25519_gen)) |",
   "| Key Generation | EC P-256 | \(format_score($gl_ec256_gen)) | \(format_score($jdk_ec256_gen)) | \(format_score($bc_ec256_gen)) | \(format_score($nss_ec256_gen)) |",
   "| Signature | Ed25519 Sign | \(format_score($gl_ed_sign)) | \(format_score($jdk_ed_sign)) | \(format_score($bc_ed_sign)) | \(format_score($nss_ed_sign)) |",
   "| Signature | Ed25519 Verify | \(format_score($gl_ed_verify)) | \(format_score($jdk_ed_verify)) | \(format_score($bc_ed_verify)) | \(format_score($nss_ed_verify)) |",
   "| Digest | SHA-256 (64B) | \(format_score($gl_sha256)) | \(format_score($jdk_sha256)) | \(format_score($bc_sha256)) | \(format_score($nss_sha256)) |",
   "| MAC | HMAC-SHA256 (64B) | \(format_score($gl_hmac)) | \(format_score($jdk_hmac)) | \(format_score($bc_hmac)) | \(format_score($nss_hmac)) |"
' "$INPUT_FILE" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"
echo "_Scores in ops/ms. Higher is better. \"-\" indicates no data available._" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Generate speedup comparison (GlaSSLess vs others)
echo "### GlaSSLess vs JDK Speedups" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "| Category | Operation | Speedup |" >> "$OUTPUT_FILE"
echo "|----------|-----------|--------:|" >> "$OUTPUT_FILE"

jq -r '
   def get_score(name; params):
      [.[] | select(.benchmark | endswith(name)) | select(if params then (.params | to_entries | all(. as $e | params | has($e.key) and .[$e.key] == $e.value)) else true end)] | .[0].primaryMetric.score // 0;

   def speedup(gl; other):
      if other > 0 and gl > 0 then
         (gl / other * 10 | round / 10) as $s |
         if $s >= 1 then "\($s)x faster" else "\((1 / $s * 10 | round / 10))x slower" end
      else "-" end;

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

   # Small data hashing
   (get_score("glasslessDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $gl_sha256 |
   (get_score("jdkDigest"; {algorithm: "SHA-256", dataSize: "64"})) as $jdk_sha256 |

   "| Key Agreement | ECDH | \(speedup($gl_ecdh; $jdk_ecdh)) |",
   "| Key Agreement | X25519 | \(speedup($gl_x25519; $jdk_x25519)) |",
   "| Key Generation | Ed25519 | \(speedup($gl_ed25519_gen; $jdk_ed25519_gen)) |",
   "| Key Generation | EC P-256 | \(speedup($gl_ec256_gen; $jdk_ec256_gen)) |",
   "| Signature | Ed25519 Sign | \(speedup($gl_ed_sign; $jdk_ed_sign)) |",
   "| Signature | Ed25519 Verify | \(speedup($gl_ed_verify; $jdk_ed_verify)) |",
   "| Digest | SHA-256 (64B) | \(speedup($gl_sha256; $jdk_sha256)) |"
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
FOOTER

echo "Generated: $OUTPUT_FILE"
