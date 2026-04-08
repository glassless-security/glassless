#!/bin/bash
# Run OpenJDK jtreg crypto tests against GlaSSLess provider.
#
# Prerequisites:
#   - JDK 25+ (JAVA_HOME must be set or java must be on PATH)
#   - GlaSSLess provider JAR (built via: ./mvnw package -DskipTests)
#   - OpenJDK submodule initialized (git submodule update --init)
#
# Usage:
#   ./scripts/run-jtreg.sh [test-dir...]
#
# Examples:
#   ./scripts/run-jtreg.sh                                    # Run all crypto tests
#   ./scripts/run-jtreg.sh test/jdk/javax/crypto              # Cipher/Mac/KA tests only
#   ./scripts/run-jtreg.sh test/jdk/sun/security/pkcs12       # PKCS12 tests only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
JTREG_VERSION="8.2.1+1"
JTREG_DIR="$PROJECT_DIR/target/jtreg"
JTREG_HOME="$JTREG_DIR/jtreg"
OPENJDK_DIR="$PROJECT_DIR/openjdk-jdk"

# --- Resolve JAVA_HOME ---
if [ -z "${JAVA_HOME:-}" ]; then
   JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
fi
echo "Using JAVA_HOME=$JAVA_HOME"

# --- Check submodule ---
if [ ! -f "$OPENJDK_DIR/test/jdk/TEST.ROOT" ]; then
   echo "Initializing OpenJDK submodule..."
   cd "$PROJECT_DIR"
   git submodule update --init --depth 1
   cd "$OPENJDK_DIR"
   git sparse-checkout init --cone
   git sparse-checkout set \
      test/jdk/java/security \
      test/jdk/javax/crypto \
      test/jdk/javax/net/ssl \
      test/jdk/sun/security/pkcs12 \
      test/jdk/sun/security/provider \
      test/jdk/sun/security/ssl \
      test/lib
fi

# --- Find GlaSSLess JAR ---
GLASSLESS_JAR="$(find "$PROJECT_DIR/target" -maxdepth 1 -name 'glassless-provider-*.jar' \
   -not -name '*-sources.jar' -not -name '*-javadoc.jar' -not -name '*-docs.jar' -not -name '*-asciidoc.jar' | head -1)"
if [ -z "$GLASSLESS_JAR" ]; then
   echo "GlaSSLess JAR not found. Building..."
   cd "$PROJECT_DIR"
   ./mvnw -B package -DskipTests -q
   GLASSLESS_JAR="$(find "$PROJECT_DIR/target" -maxdepth 1 -name 'glassless-provider-*.jar' \
      -not -name '*-sources.jar' -not -name '*-javadoc.jar' -not -name '*-docs.jar' | head -1)"
fi
echo "Using GlaSSLess JAR: $GLASSLESS_JAR"

# --- Download jtreg ---
if [ ! -x "$JTREG_HOME/bin/jtreg" ]; then
   echo "Downloading jtreg $JTREG_VERSION..."
   mkdir -p "$JTREG_DIR"

   # Try Adoptium CI build first, fall back to building from source
   JTREG_URL="https://ci.adoptium.net/view/Dependencies/job/dependency_pipeline/lastSuccessfulBuild/artifact/jtreg/jtreg-${JTREG_VERSION}.tar.gz"
   if curl -fsSL --head "$JTREG_URL" >/dev/null 2>&1; then
      curl -fsSL "$JTREG_URL" | tar xz -C "$JTREG_DIR"
   else
      echo "Adoptium build not available, building jtreg from source..."
      JTREG_SRC="$JTREG_DIR/jtreg-src"
      if [ ! -d "$JTREG_SRC" ]; then
         git clone --depth 1 https://github.com/openjdk/jtreg.git "$JTREG_SRC"
      fi
      cd "$JTREG_SRC"
      bash make/build.sh --jdk "$JAVA_HOME"
      mv build/images/jtreg "$JTREG_HOME"
   fi
fi

if [ ! -x "$JTREG_HOME/bin/jtreg" ]; then
   echo "ERROR: jtreg not found at $JTREG_HOME/bin/jtreg"
   exit 1
fi
echo "Using jtreg: $JTREG_HOME"

# --- Create security properties file ---
# Insert GlaSSLess at position 1, shifting all existing providers down by 1.
# Uses == (override mode) to replace the entire provider list.
SECURITY_PROPS="$JTREG_DIR/glassless-security.properties"
{
   echo "# GlaSSLess as highest-priority provider (auto-generated)"
   echo "security.provider.1=net.glassless.provider.GlaSSLessProvider"
   grep "^security\.provider\." "$JAVA_HOME/conf/security/java.security" \
      | sort -t. -k3 -n \
      | while IFS='=' read -r key value; do
         num="${key##*.}"
         echo "security.provider.$((num + 1))=$value"
      done
} > "$SECURITY_PROPS"
echo "Security properties: $SECURITY_PROPS"

# --- Determine test directories ---
if [ $# -gt 0 ]; then
   TEST_DIRS=("$@")
else
   TEST_DIRS=(
      test/jdk/java/security
      test/jdk/javax/crypto
      test/jdk/javax/net/ssl
      test/jdk/sun/security/pkcs12
      test/jdk/sun/security/ssl
   )
fi

# Convert relative paths to absolute
ABSOLUTE_TEST_DIRS=()
for dir in "${TEST_DIRS[@]}"; do
   if [[ "$dir" = /* ]]; then
      ABSOLUTE_TEST_DIRS+=("$dir")
   else
      ABSOLUTE_TEST_DIRS+=("$OPENJDK_DIR/$dir")
   fi
done

# --- Patch TEST.ROOT for sparse checkout ---
# TEST.groups references directories not in our sparse checkout, causing
# group validation errors. Remove the groups reference since we run
# specific test directories, not test groups.
TEST_ROOT="$OPENJDK_DIR/test/jdk/TEST.ROOT"
if grep -q "^groups=" "$TEST_ROOT" 2>/dev/null; then
   sed -i 's/^groups=/#groups=/' "$TEST_ROOT"
fi

# --- Run jtreg ---
echo ""
echo "Running jtreg tests..."
echo "Test directories: ${ABSOLUTE_TEST_DIRS[*]}"
echo ""

cd "$OPENJDK_DIR"

"$JTREG_HOME/bin/jtreg" \
   -jdk:"$JAVA_HOME" \
   -agentvm \
   -conc:auto \
   -verbose:summary \
   -w "$JTREG_DIR/work" \
   -r "$JTREG_DIR/report" \
   -timeout:4 \
   -vmoptions:"--enable-native-access=ALL-UNNAMED --module-path=$GLASSLESS_JAR --add-modules=net.glassless.provider -Djava.security.properties=$SECURITY_PROPS" \
   "${ABSOLUTE_TEST_DIRS[@]}" \
   || true

# --- Summary ---
echo ""
echo "========================================="
echo "jtreg results:"
echo "  Work directory: $JTREG_DIR/work"
echo "  HTML report:    $JTREG_DIR/report/index.html"
echo "========================================="

# Print summary if available
SUMMARY_FILE="$JTREG_DIR/report/text/summary.txt"
if [ -f "$SUMMARY_FILE" ]; then
   TOTAL=$(wc -l < "$SUMMARY_FILE")
   PASSED=$(grep -c "^Passed" "$SUMMARY_FILE" || true)
   FAILED=$(grep -c "^Failed\|^FAILED" "$SUMMARY_FILE" || true)
   ERRORS=$(grep -c "^Error" "$SUMMARY_FILE" || true)
   echo ""
   echo "Total: $TOTAL  Passed: $PASSED  Failed: $FAILED  Errors: $ERRORS"
   if [ "$FAILED" -gt 0 ] || [ "$ERRORS" -gt 0 ]; then
      echo ""
      echo "Failed/Error tests:"
      grep "^Failed\|^FAILED\|^Error" "$SUMMARY_FILE" || true
   fi
fi
