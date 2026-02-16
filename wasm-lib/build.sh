#!/bin/bash
set -euo pipefail

# =============================================================================
# Build script for the OpenSSL WASM module used by Glassless.
#
# This script compiles openssl_wrapper.c and links it against the
# pre-compiled WASM static libraries of OpenSSL to produce a single
# libcrypto.wasm module that exposes all needed crypto functions.
#
# Prerequisites:
#   - WASI SDK (https://github.com/aspect-build/aspect-wasi-sdk/releases)
#   - Pre-compiled OpenSSL for wasm32-wasi (libcrypto.a + headers)
#
# Usage:
#   ./build.sh
#
# Environment variables (all optional, with sensible defaults):
#   WASI_SDK_PATH  - Path to the WASI SDK installation
#   OPENSSL_PATH   - Path to the pre-compiled OpenSSL (with include/ and lib/)
# https://github.com/jedisct1/openssl-wasm
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Configuration -----------------------------------------------------------

# WASI SDK path: use env var, or look for a local copy, or the sqlite4j one
WASI_SDK_PATH="${WASI_SDK_PATH:-}"
if [ -z "$WASI_SDK_PATH" ]; then
    if [ -d "$SCRIPT_DIR/wasi-sdk" ]; then
        WASI_SDK_PATH="$SCRIPT_DIR/wasi-sdk"
    elif [ -d "$SCRIPT_DIR/../wasi-sdk" ]; then
        WASI_SDK_PATH="$SCRIPT_DIR/../wasi-sdk"
    else
        echo "ERROR: WASI SDK not found. Set WASI_SDK_PATH or place it in $SCRIPT_DIR/wasi-sdk"
        exit 1
    fi
fi

# OpenSSL pre-compiled path
OPENSSL_PATH="${OPENSSL_PATH:-/${PWD}/../openssl-wasm/precompiled}"

# Verify paths
if [ ! -f "$WASI_SDK_PATH/bin/clang" ]; then
    echo "ERROR: clang not found at $WASI_SDK_PATH/bin/clang"
    exit 1
fi
if [ ! -f "$OPENSSL_PATH/lib/libcrypto.a" ]; then
    echo "ERROR: libcrypto.a not found at $OPENSSL_PATH/lib/libcrypto.a"
    exit 1
fi
if [ ! -d "$OPENSSL_PATH/include/openssl" ]; then
    echo "ERROR: OpenSSL headers not found at $OPENSSL_PATH/include/openssl/"
    exit 1
fi

# Output
OUTPUT="$SCRIPT_DIR/libcrypto.wasm"

echo "=== Glassless OpenSSL WASM Build ==="
echo "  WASI SDK:     $WASI_SDK_PATH"
echo "  OpenSSL:      $OPENSSL_PATH"
echo "  Output:       $OUTPUT"
echo ""

# --- Compile and Link --------------------------------------------------------

echo "Compiling and linking..."

# --- Explicit exports (only the symbols needed by the Java side) --------------
# Using explicit --export= flags instead of --export-all to keep the export
# count manageable (Chicory's annotation processor hits JVM "code too large"
# limits when there are thousands of exports).

EXPORTS=(
    # Memory management
    malloc free

    # Message Digest
    EVP_MD_CTX_new EVP_MD_CTX_free EVP_get_digestbyname
    EVP_DigestInit_ex EVP_DigestUpdate EVP_DigestFinal_ex EVP_MD_get_size

    # Cipher
    EVP_CIPHER_CTX_new EVP_CIPHER_CTX_free
    EVP_EncryptInit_ex EVP_EncryptUpdate EVP_EncryptFinal_ex
    EVP_DecryptInit_ex EVP_DecryptUpdate EVP_DecryptFinal_ex
    EVP_get_cipherbyname EVP_CIPHER_CTX_ctrl
    EVP_CIPHER_get_iv_length EVP_CIPHER_get_key_length EVP_CIPHER_get_block_size

    # PBKDF2
    PKCS5_PBKDF2_HMAC

    # EVP_PKEY (RSA, EC, etc.)
    EVP_PKEY_CTX_new_from_pkey EVP_PKEY_CTX_free
    EVP_PKEY_encrypt_init EVP_PKEY_encrypt
    EVP_PKEY_decrypt_init EVP_PKEY_decrypt
    EVP_PKEY_CTX_set_rsa_padding
    EVP_PKEY_CTX_set_rsa_oaep_md EVP_PKEY_CTX_set_rsa_mgf1_md
    d2i_PrivateKey d2i_PUBKEY EVP_PKEY_free EVP_PKEY_get_size

    # EVP_MAC (HMAC)
    EVP_MAC_fetch EVP_MAC_free EVP_MAC_CTX_new EVP_MAC_CTX_free
    EVP_MAC_init EVP_MAC_update EVP_MAC_final EVP_MAC_CTX_get_mac_size

    # OSSL_PARAM (original + glassless wrappers)
    OSSL_PARAM_construct_utf8_string OSSL_PARAM_construct_end
    OSSL_PARAM_construct_octet_string
    glassless_OSSL_PARAM_construct_utf8_string glassless_OSSL_PARAM_construct_end
    glassless_OSSL_PARAM_construct_octet_string glassless_OSSL_PARAM_construct_uint
    glassless_sizeof_OSSL_PARAM

    # Secure random
    RAND_bytes RAND_seed

    # Signatures
    EVP_DigestSignInit EVP_DigestSignFinal EVP_DigestSign
    EVP_DigestVerifyInit EVP_DigestVerifyFinal EVP_DigestVerify
    EVP_PKEY_CTX_set_rsa_pss_saltlen
    d2i_PrivateKey_ex d2i_PUBKEY_ex

    # Key pair generation
    EVP_PKEY_CTX_new_from_name EVP_PKEY_keygen_init EVP_PKEY_keygen
    EVP_PKEY_CTX_set_rsa_keygen_bits EVP_PKEY_CTX_set_ec_paramgen_curve_nid
    i2d_PrivateKey i2d_PUBKEY OBJ_txt2nid OBJ_sn2nid
    EVP_PKEY2PKCS8 PKCS8_PRIV_KEY_INFO_free i2d_PKCS8_PRIV_KEY_INFO

    # Key agreement
    EVP_PKEY_derive_init EVP_PKEY_derive_set_peer EVP_PKEY_derive

    # DSA/DH key generation
    EVP_PKEY_CTX_set_dsa_paramgen_bits EVP_PKEY_CTX_set_dsa_paramgen_q_bits
    EVP_PKEY_CTX_set_dh_paramgen_prime_len EVP_PKEY_CTX_set_dh_paramgen_generator
    EVP_PKEY_paramgen_init EVP_PKEY_paramgen
    EVP_PKEY_get_bn_param BN_bn2bin BN_num_bits BN_free

    # EVP_KDF (HKDF)
    EVP_KDF_fetch EVP_KDF_free EVP_KDF_CTX_new EVP_KDF_CTX_free EVP_KDF_derive

    # FIPS detection
    EVP_default_properties_is_fips_enabled OSSL_PROVIDER_available

    # Version info
    OpenSSL_version

    # KEM (Key Encapsulation Mechanism)
    EVP_PKEY_encapsulate_init EVP_PKEY_encapsulate
    EVP_PKEY_decapsulate_init EVP_PKEY_decapsulate
    EVP_KEYMGMT_fetch EVP_KEYMGMT_free

    # Raw key export/import
    EVP_PKEY_get_raw_public_key EVP_PKEY_get_raw_private_key
    EVP_PKEY_new_raw_public_key_ex EVP_PKEY_new_raw_private_key_ex

    # OpenSSL init
    OPENSSL_init_crypto

    # Memory (OpenSSL)
    CRYPTO_malloc CRYPTO_free
)

EXPORT_FLAGS=""
for sym in "${EXPORTS[@]}"; do
    EXPORT_FLAGS="$EXPORT_FLAGS -Wl,--export=$sym"
done

${WASI_SDK_PATH}/bin/clang \
    --sysroot=${WASI_SDK_PATH}/share/wasi-sysroot \
    --target=wasm32-wasi \
    -o "$OUTPUT" \
    "$SCRIPT_DIR/openssl_wrapper.c" \
    -I "${OPENSSL_PATH}/include" \
    -L "${OPENSSL_PATH}/lib" \
    -lcrypto \
    \
    $EXPORT_FLAGS \
    -Wl,--no-entry \
    -Wl,--import-undefined \
    -Wl,--initial-memory=67108864 \
    -Wl,--stack-first \
    -Wl,--strip-debug \
    \
    -mnontrapping-fptoint \
    -msign-ext \
    -mmutable-globals \
    -mbulk-memory \
    -mexec-model=reactor \
    \
    -fno-stack-protector \
    -fno-stack-clash-protection \
    -g0 -Oz

echo ""
echo "Build complete: $OUTPUT"
ls -lh "$OUTPUT"

# --- Optional: Optimize with wasm-opt (Binaryen) ----------------------------

WASM_OPT=""
if [ -x "$SCRIPT_DIR/binaryen/bin/wasm-opt" ]; then
    WASM_OPT="$SCRIPT_DIR/binaryen/bin/wasm-opt"
elif command -v wasm-opt &> /dev/null; then
    WASM_OPT="wasm-opt"
fi

if [ -n "$WASM_OPT" ]; then
    echo ""
    echo "Optimizing with wasm-opt..."
    "$WASM_OPT" -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals \
        --enable-nontrapping-float-to-int \
        "$OUTPUT" -o "$OUTPUT.opt"
    mv "$OUTPUT.opt" "$OUTPUT"
    echo "Optimized: $OUTPUT"
    ls -lh "$OUTPUT"
fi

echo ""
echo "Done."
