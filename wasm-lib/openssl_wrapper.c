/*
 * OpenSSL WASM wrapper for Glassless
 *
 * This file provides a thin wrapper around OpenSSL functions needed by the
 * Glassless Java crypto provider. It is compiled to WebAssembly and linked
 * against a WASI-targeted static build of OpenSSL (libcrypto.a).
 *
 * All standard OpenSSL functions are exported directly via --export-all.
 * Helper wrapper functions (prefixed with glassless_) are provided for
 * functions that return structs by value, since the WASM ABI transforms
 * these to use an sret (hidden first pointer) parameter.
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

/* ========================================================================
 * Reactor model initialization
 * Called automatically when the WASM module is instantiated.
 * ======================================================================== */

__attribute__((constructor))
static void glassless_init(void) {
    OPENSSL_init_crypto(
        OPENSSL_INIT_ADD_ALL_CIPHERS |
        OPENSSL_INIT_ADD_ALL_DIGESTS,
        NULL
    );
}

/* ========================================================================
 * Force the linker to pull in all required symbols from libcrypto.a.
 *
 * When linking against a static archive, only object files that satisfy
 * undefined references are included. This array ensures all the OpenSSL
 * functions needed by the Java side are linked into the WASM module.
 * Combined with --export-all, they become available as WASM exports.
 * ======================================================================== */

__attribute__((used))
static volatile const void *glassless_required_symbols[] = {
    /* Message Digest */
    (const void *)EVP_MD_CTX_new,
    (const void *)EVP_MD_CTX_free,
    (const void *)EVP_get_digestbyname,
    (const void *)EVP_DigestInit_ex,
    (const void *)EVP_DigestUpdate,
    (const void *)EVP_DigestFinal_ex,
    (const void *)EVP_MD_get_size,

    /* Cipher */
    (const void *)EVP_CIPHER_CTX_new,
    (const void *)EVP_CIPHER_CTX_free,
    (const void *)EVP_EncryptInit_ex,
    (const void *)EVP_EncryptUpdate,
    (const void *)EVP_EncryptFinal_ex,
    (const void *)EVP_DecryptInit_ex,
    (const void *)EVP_DecryptUpdate,
    (const void *)EVP_DecryptFinal_ex,
    (const void *)EVP_get_cipherbyname,
    (const void *)EVP_CIPHER_CTX_ctrl,
    (const void *)EVP_CIPHER_get_iv_length,
    (const void *)EVP_CIPHER_get_key_length,
    (const void *)EVP_CIPHER_get_block_size,

    /* PBKDF2 */
    (const void *)PKCS5_PBKDF2_HMAC,

    /* EVP_PKEY (RSA, EC, etc.) */
    (const void *)EVP_PKEY_CTX_new_from_pkey,
    (const void *)EVP_PKEY_CTX_free,
    (const void *)EVP_PKEY_encrypt_init,
    (const void *)EVP_PKEY_encrypt,
    (const void *)EVP_PKEY_decrypt_init,
    (const void *)EVP_PKEY_decrypt,
    (const void *)EVP_PKEY_CTX_set_rsa_padding,
    (const void *)EVP_PKEY_CTX_set_rsa_oaep_md,
    (const void *)EVP_PKEY_CTX_set_rsa_mgf1_md,
    (const void *)d2i_PrivateKey,
    (const void *)d2i_PUBKEY,
    (const void *)EVP_PKEY_free,
    (const void *)EVP_PKEY_get_size,

    /* EVP_MAC (HMAC) */
    (const void *)EVP_MAC_fetch,
    (const void *)EVP_MAC_free,
    (const void *)EVP_MAC_CTX_new,
    (const void *)EVP_MAC_CTX_free,
    (const void *)EVP_MAC_init,
    (const void *)EVP_MAC_update,
    (const void *)EVP_MAC_final,
    (const void *)EVP_MAC_CTX_get_mac_size,

    /* OSSL_PARAM construction */
    (const void *)OSSL_PARAM_construct_utf8_string,
    (const void *)OSSL_PARAM_construct_end,

    /* Secure random */
    (const void *)RAND_bytes,
    (const void *)RAND_seed,

    /* Signatures (EVP_DigestSign/Verify) */
    (const void *)EVP_DigestSignInit,
    (const void *)EVP_DigestSignFinal,
    (const void *)EVP_DigestSign,
    (const void *)EVP_DigestVerifyInit,
    (const void *)EVP_DigestVerifyFinal,
    (const void *)EVP_DigestVerify,
    (const void *)EVP_PKEY_CTX_set_rsa_pss_saltlen,
    (const void *)d2i_PrivateKey_ex,
    (const void *)d2i_PUBKEY_ex,

    /* Key pair generation */
    (const void *)EVP_PKEY_CTX_new_from_name,
    (const void *)EVP_PKEY_keygen_init,
    (const void *)EVP_PKEY_keygen,
    (const void *)EVP_PKEY_CTX_set_rsa_keygen_bits,
    (const void *)EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
    (const void *)i2d_PrivateKey,
    (const void *)i2d_PUBKEY,
    (const void *)OBJ_txt2nid,
    (const void *)OBJ_sn2nid,
    (const void *)EVP_PKEY2PKCS8,
    (const void *)PKCS8_PRIV_KEY_INFO_free,
    (const void *)i2d_PKCS8_PRIV_KEY_INFO,

    /* Key agreement (ECDH, X25519, etc.) */
    (const void *)EVP_PKEY_derive_init,
    (const void *)EVP_PKEY_derive_set_peer,
    (const void *)EVP_PKEY_derive,

    /* DSA/DH key generation */
    (const void *)EVP_PKEY_CTX_set_dsa_paramgen_bits,
    (const void *)EVP_PKEY_CTX_set_dsa_paramgen_q_bits,
    (const void *)EVP_PKEY_CTX_set_dh_paramgen_prime_len,
    (const void *)EVP_PKEY_CTX_set_dh_paramgen_generator,
    (const void *)EVP_PKEY_paramgen_init,
    (const void *)EVP_PKEY_paramgen,
    (const void *)EVP_PKEY_get_bn_param,
    (const void *)BN_bn2bin,
    (const void *)BN_num_bits,
    (const void *)BN_free,

    /* EVP_KDF (HKDF) */
    (const void *)EVP_KDF_fetch,
    (const void *)EVP_KDF_free,
    (const void *)EVP_KDF_CTX_new,
    (const void *)EVP_KDF_CTX_free,
    (const void *)EVP_KDF_derive,

    /* FIPS detection */
    (const void *)EVP_default_properties_is_fips_enabled,
    (const void *)OSSL_PROVIDER_available,

    /* Version info */
    (const void *)OpenSSL_version,

    /* KEM (Key Encapsulation Mechanism) */
    (const void *)EVP_PKEY_encapsulate_init,
    (const void *)EVP_PKEY_encapsulate,
    (const void *)EVP_PKEY_decapsulate_init,
    (const void *)EVP_PKEY_decapsulate,
    (const void *)EVP_KEYMGMT_fetch,
    (const void *)EVP_KEYMGMT_free,

    /* Raw key export/import (for hybrid KEMs) */
    (const void *)EVP_PKEY_get_raw_public_key,
    (const void *)EVP_PKEY_get_raw_private_key,
    (const void *)EVP_PKEY_new_raw_public_key_ex,
    (const void *)EVP_PKEY_new_raw_private_key_ex,

    /* Memory management (needed by Java side for WASM linear memory) */
    (const void *)CRYPTO_malloc,
    (const void *)CRYPTO_free,
};

/* ========================================================================
 * Helper wrappers for functions that return structs by value.
 *
 * In the WASM ABI, functions returning structs larger than a register
 * use an sret (struct return) convention: the caller passes a pointer
 * to the output location as a hidden first parameter. These wrappers
 * make the contract explicit for the Java WASM runtime caller.
 * ======================================================================== */

/**
 * Constructs an OSSL_PARAM for a UTF-8 string and writes it to *out.
 * Wraps OSSL_PARAM_construct_utf8_string which returns OSSL_PARAM by value.
 */
void glassless_OSSL_PARAM_construct_utf8_string(
    OSSL_PARAM *out, const char *key, char *buf, size_t bsize)
{
    *out = OSSL_PARAM_construct_utf8_string(key, buf, bsize);
}

/**
 * Constructs an OSSL_PARAM end marker and writes it to *out.
 * Wraps OSSL_PARAM_construct_end which returns OSSL_PARAM by value.
 */
void glassless_OSSL_PARAM_construct_end(OSSL_PARAM *out)
{
    *out = OSSL_PARAM_construct_end();
}

/**
 * Constructs an OSSL_PARAM for an octet string and writes it to *out.
 * Useful for HKDF salt, key, and info parameters.
 */
void glassless_OSSL_PARAM_construct_octet_string(
    OSSL_PARAM *out, const char *key, void *buf, size_t bsize)
{
    *out = OSSL_PARAM_construct_octet_string(key, buf, bsize);
}

/**
 * Constructs an OSSL_PARAM for an unsigned integer and writes it to *out.
 * Useful for HKDF mode parameter.
 */
void glassless_OSSL_PARAM_construct_uint(
    OSSL_PARAM *out, const char *key, unsigned int *val)
{
    *out = OSSL_PARAM_construct_uint(key, val);
}

/**
 * Returns the size of OSSL_PARAM struct on this platform (wasm32).
 * Useful for the Java side to know how much memory to allocate per param entry.
 */
unsigned int glassless_sizeof_OSSL_PARAM(void)
{
    return (unsigned int)sizeof(OSSL_PARAM);
}
