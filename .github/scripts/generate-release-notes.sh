#!/bin/bash
# Generate release notes from git commit history
# Usage: generate-release-notes.sh <version> [previous-tag]

set -e

VERSION="${1:?Version required}"
PREVIOUS_TAG="${2:-}"

# Determine the target ref (use version tag if exists, otherwise HEAD)
TARGET_REF="v${VERSION}"
if ! git rev-parse "$TARGET_REF" &>/dev/null; then
    TARGET_REF="HEAD"
fi

# Find the previous tag if not provided
if [ -z "$PREVIOUS_TAG" ]; then
    # Get the most recent tag before TARGET_REF
    PREVIOUS_TAG=$(git tag --sort=-version:refname --merged "$TARGET_REF" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | grep -v "^v${VERSION}$" | head -1)
fi

echo "Generating release notes for $VERSION (since $PREVIOUS_TAG)" >&2

# Get commits between previous tag and target (excluding release/prepare commits)
COMMITS=$(git log "${PREVIOUS_TAG}..${TARGET_REF}" --pretty=format:"%s|%h" 2>/dev/null | \
    grep -v "^Release " | \
    grep -v "^Prepare for next development" || true)

# Categorize commits
declare -a FEATURES
declare -a FIXES
declare -a PERFORMANCE
declare -a DOCS
declare -a SECURITY
declare -a OTHER

while IFS='|' read -r message hash; do
    [ -z "$message" ] && continue

    # Categorize based on commit message patterns
    lower_msg=$(echo "$message" | tr '[:upper:]' '[:lower:]')

    if [[ "$lower_msg" =~ ^add|^implement|^support|^enable|^introduce ]]; then
        FEATURES+=("$message")
    elif [[ "$lower_msg" =~ ^fix|^resolve|^correct|^repair ]]; then
        FIXES+=("$message")
    elif [[ "$lower_msg" =~ performance|benchmark|optimize|speed|fast ]]; then
        PERFORMANCE+=("$message")
    elif [[ "$lower_msg" =~ ^doc|documentation|readme|asciidoc ]]; then
        DOCS+=("$message")
    elif [[ "$lower_msg" =~ security|fips|vulnerability|cve ]]; then
        SECURITY+=("$message")
    elif [[ "$lower_msg" =~ ^update|^improve|^enhance|^refactor ]]; then
        FEATURES+=("$message")
    else
        OTHER+=("$message")
    fi
done <<< "$COMMITS"

# Generate the release notes
cat << 'HEADER'
## Installation

### Maven
```xml
<dependency>
   <groupId>net.glassless</groupId>
   <artifactId>glassless-provider</artifactId>
HEADER

echo "   <version>${VERSION}</version>"

cat << 'HEADER2'
</dependency>
```

### Gradle
```groovy
HEADER2

echo "implementation 'net.glassless:glassless-provider:${VERSION}'"

cat << 'HEADER3'
```

HEADER3

# Output highlights section with the most significant change
echo "## Highlights"
echo ""

# Try to identify the main feature
if [ ${#FEATURES[@]} -gt 0 ]; then
    MAIN_FEATURE="${FEATURES[0]}"
    # Create a title from the commit message
    TITLE=$(echo "$MAIN_FEATURE" | sed 's/^Add //' | sed 's/^Implement //' | sed 's/^Support //')
    echo "### ${TITLE}"
    echo ""
    echo "${MAIN_FEATURE}"
    echo ""
fi

# What's Changed section
echo "## What's Changed"
echo ""

# Features
if [ ${#FEATURES[@]} -gt 0 ]; then
    echo "### New Features"
    for item in "${FEATURES[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Fixes
if [ ${#FIXES[@]} -gt 0 ]; then
    echo "### Bug Fixes"
    for item in "${FIXES[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Performance
if [ ${#PERFORMANCE[@]} -gt 0 ]; then
    echo "### Performance"
    for item in "${PERFORMANCE[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Security
if [ ${#SECURITY[@]} -gt 0 ]; then
    echo "### Security"
    for item in "${SECURITY[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Documentation
if [ ${#DOCS[@]} -gt 0 ]; then
    echo "### Documentation"
    for item in "${DOCS[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Other changes
if [ ${#OTHER[@]} -gt 0 ]; then
    echo "### Other Changes"
    for item in "${OTHER[@]}"; do
        echo "- ${item}"
    done
    echo ""
fi

# Footer
echo "---"
echo ""
echo "**Full Changelog**: https://github.com/glassless-security/glassless/compare/${PREVIOUS_TAG}...v${VERSION}"
