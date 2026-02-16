package net.glassless.provider.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.NoSuchElementException;

public class OpenSSLCrypto {

   private static final String LIBCRYPTO_NAME = "crypto";
   public static final String LIBCRYPTO_SO_3 = "libcrypto.so.3";

   // Method handles for OpenSSL functions
   private static MethodHandle EVP_MD_CTX_new;
   private static MethodHandle EVP_MD_CTX_free;
   private static MethodHandle EVP_get_digestbyname;
   private static MethodHandle EVP_DigestInit_ex;
   private static MethodHandle EVP_DigestUpdate;
   private static MethodHandle EVP_DigestFinal_ex;
   private static MethodHandle EVP_MD_size;

   // Method handles for OpenSSL cipher functions
   private static MethodHandle EVP_CIPHER_CTX_new;
   private static MethodHandle EVP_CIPHER_CTX_free;
   private static MethodHandle EVP_EncryptInit_ex;
   private static MethodHandle EVP_EncryptUpdate;
   private static MethodHandle EVP_EncryptFinal_ex;
   private static MethodHandle EVP_DecryptInit_ex;
   private static MethodHandle EVP_DecryptUpdate;
   private static MethodHandle EVP_DecryptFinal_ex;
   private static MethodHandle EVP_get_cipherbyname;
   private static MethodHandle EVP_CIPHER_CTX_ctrl;
   private static MethodHandle EVP_CIPHER_get_iv_length;
   private static MethodHandle EVP_CIPHER_get_key_length;
   private static MethodHandle EVP_CIPHER_get_block_size;

   // Method handles for PBKDF2
   private static MethodHandle PKCS5_PBKDF2_HMAC;

   // Method handles for RSA (EVP_PKEY API)
   private static MethodHandle EVP_PKEY_CTX_new_from_pkey;
   private static MethodHandle EVP_PKEY_CTX_free;
   private static MethodHandle EVP_PKEY_encrypt_init;
   private static MethodHandle EVP_PKEY_encrypt;
   private static MethodHandle EVP_PKEY_decrypt_init;
   private static MethodHandle EVP_PKEY_decrypt;
   private static MethodHandle EVP_PKEY_CTX_set_rsa_padding;
   private static MethodHandle EVP_PKEY_CTX_set_rsa_oaep_md;
   private static MethodHandle EVP_PKEY_CTX_set_rsa_mgf1_md;
   private static MethodHandle d2i_PrivateKey;
   private static MethodHandle d2i_PUBKEY;
   private static MethodHandle EVP_PKEY_free;
   private static MethodHandle EVP_PKEY_get_size;

   // Method handles for EVP_MAC (HMAC)
   private static MethodHandle EVP_MAC_fetch;
   private static MethodHandle EVP_MAC_free;
   private static MethodHandle EVP_MAC_CTX_new;
   private static MethodHandle EVP_MAC_CTX_free;
   private static MethodHandle EVP_MAC_init;
   private static MethodHandle EVP_MAC_update;
   private static MethodHandle EVP_MAC_final;
   private static MethodHandle EVP_MAC_CTX_get_mac_size;
   private static MethodHandle OSSL_PARAM_construct_utf8_string;
   private static MethodHandle OSSL_PARAM_construct_end;

   // Method handles for secure random
   private static MethodHandle RAND_bytes;
   private static MethodHandle RAND_seed;

   // Method handles for signatures (EVP_DigestSign/Verify API)
   private static MethodHandle EVP_DigestSignInit;
   private static MethodHandle EVP_DigestSignUpdate;
   private static MethodHandle EVP_DigestSignFinal;
   private static MethodHandle EVP_DigestSign;  // Single-shot for EdDSA
   private static MethodHandle EVP_DigestVerifyInit;
   private static MethodHandle EVP_DigestVerifyUpdate;
   private static MethodHandle EVP_DigestVerifyFinal;
   private static MethodHandle EVP_DigestVerify;  // Single-shot for EdDSA
   private static MethodHandle EVP_PKEY_CTX_set_rsa_pss_saltlen;
   private static MethodHandle d2i_PrivateKey_ex;
   private static MethodHandle d2i_PUBKEY_ex;

   // Method handles for key pair generation
   private static MethodHandle EVP_PKEY_CTX_new_from_name;
   private static MethodHandle EVP_PKEY_keygen_init;
   private static MethodHandle EVP_PKEY_keygen;
   private static MethodHandle EVP_PKEY_CTX_set_rsa_keygen_bits;
   private static MethodHandle EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
   private static MethodHandle i2d_PrivateKey;
   private static MethodHandle i2d_PUBKEY;
   private static MethodHandle OBJ_txt2nid;
   private static MethodHandle OBJ_sn2nid;
   private static MethodHandle EVP_PKEY2PKCS8;
   private static MethodHandle PKCS8_PRIV_KEY_INFO_free;
   private static MethodHandle i2d_PKCS8_PRIV_KEY_INFO;

   // Method handles for key agreement (EVP_PKEY_derive API)
   private static MethodHandle EVP_PKEY_derive_init;
   private static MethodHandle EVP_PKEY_derive_set_peer;
   private static MethodHandle EVP_PKEY_derive;

   // Method handles for DSA/DH key generation
   private static MethodHandle EVP_PKEY_CTX_set_dsa_paramgen_bits;
   private static MethodHandle EVP_PKEY_CTX_set_dsa_paramgen_q_bits;
   private static MethodHandle EVP_PKEY_CTX_set_dh_paramgen_prime_len;
   private static MethodHandle EVP_PKEY_CTX_set_dh_paramgen_generator;
   private static MethodHandle EVP_PKEY_paramgen_init;
   private static MethodHandle EVP_PKEY_paramgen;
   private static MethodHandle EVP_PKEY_get_bn_param;
   private static MethodHandle BN_bn2bin;
   private static MethodHandle BN_num_bytes;
   private static MethodHandle BN_free;

   // Method handles for EVP_KDF (HKDF)
   private static MethodHandle EVP_KDF_fetch;
   private static MethodHandle EVP_KDF_free;
   private static MethodHandle EVP_KDF_CTX_new;
   private static MethodHandle EVP_KDF_CTX_free;
   private static MethodHandle EVP_KDF_derive;

   // Method handles for FIPS detection
   private static MethodHandle EVP_default_properties_is_fips_enabled;
   private static MethodHandle OSSL_PROVIDER_available;

   // Method handles for version info
   private static MethodHandle OpenSSL_version;

   // Method handles for KEM (Key Encapsulation Mechanism) - OpenSSL 3.2+
   private static MethodHandle EVP_PKEY_encapsulate_init;
   private static MethodHandle EVP_PKEY_encapsulate;
   private static MethodHandle EVP_PKEY_decapsulate_init;
   private static MethodHandle EVP_PKEY_decapsulate;
   private static MethodHandle EVP_KEYMGMT_fetch;
   private static MethodHandle EVP_KEYMGMT_free;

   // Method handles for raw key export/import (for hybrid KEMs)
   private static MethodHandle EVP_PKEY_get_raw_public_key;
   private static MethodHandle EVP_PKEY_get_raw_private_key;
   private static MethodHandle EVP_PKEY_new_raw_public_key_ex;
   private static MethodHandle EVP_PKEY_new_raw_private_key_ex;

   static {
      initFFM();
   }

   private static void initFFM() {
      Linker linker = Linker.nativeLinker();
      SymbolLookup libcrypto;
      try {
         // Use the full path to the library
         libcrypto = SymbolLookup.libraryLookup(LIBCRYPTO_SO_3, Arena.global());
      } catch (IllegalArgumentException e) {
         throw new IllegalStateException("Could not find OpenSSL crypto library at specified path", e);
      }

      try {
         // MessageDigest functions
         EVP_MD_CTX_new = linker.downcallHandle(
            libcrypto.find("EVP_MD_CTX_new").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS)
         );
         EVP_MD_CTX_free = linker.downcallHandle(
            libcrypto.find("EVP_MD_CTX_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         EVP_get_digestbyname = linker.downcallHandle(
            libcrypto.find("EVP_get_digestbyname").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_DigestInit_ex = linker.downcallHandle(
            libcrypto.find("EVP_DigestInit_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_DigestUpdate = linker.downcallHandle(
            libcrypto.find("EVP_DigestUpdate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         EVP_DigestFinal_ex = linker.downcallHandle(
            libcrypto.find("EVP_DigestFinal_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_MD_size = linker.downcallHandle(
            libcrypto.find("EVP_MD_get_size").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );

         // Cipher functions
         EVP_CIPHER_CTX_new = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_CTX_new").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS)
         );
         EVP_CIPHER_CTX_free = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_CTX_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         EVP_EncryptInit_ex = linker.downcallHandle(
            libcrypto.find("EVP_EncryptInit_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_EncryptUpdate = linker.downcallHandle(
            libcrypto.find("EVP_EncryptUpdate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         EVP_EncryptFinal_ex = linker.downcallHandle(
            libcrypto.find("EVP_EncryptFinal_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_DecryptInit_ex = linker.downcallHandle(
            libcrypto.find("EVP_DecryptInit_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_DecryptUpdate = linker.downcallHandle(
            libcrypto.find("EVP_DecryptUpdate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         EVP_DecryptFinal_ex = linker.downcallHandle(
            libcrypto.find("EVP_DecryptFinal_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_get_cipherbyname = linker.downcallHandle(
            libcrypto.find("EVP_get_cipherbyname").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_CIPHER_CTX_ctrl = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_CTX_ctrl").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         EVP_CIPHER_get_iv_length = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_get_iv_length").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         EVP_CIPHER_get_key_length = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_get_key_length").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         EVP_CIPHER_get_block_size = linker.downcallHandle(
            libcrypto.find("EVP_CIPHER_get_block_size").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );

         // PBKDF2 function
         // int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen,
         //                       int iter, const EVP_MD *digest, int keylen, unsigned char *out);
         PKCS5_PBKDF2_HMAC = linker.downcallHandle(
            libcrypto.find("PKCS5_PBKDF2_HMAC").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
               ValueLayout.ADDRESS,  // pass
               ValueLayout.JAVA_INT, // passlen
               ValueLayout.ADDRESS,  // salt
               ValueLayout.JAVA_INT, // saltlen
               ValueLayout.JAVA_INT, // iter
               ValueLayout.ADDRESS,  // digest (EVP_MD*)
               ValueLayout.JAVA_INT, // keylen
               ValueLayout.ADDRESS)  // out
         );

         // RSA/EVP_PKEY functions
         EVP_PKEY_CTX_new_from_pkey = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_new_from_pkey").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_PKEY_CTX_free = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         EVP_PKEY_encrypt_init = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_encrypt_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         EVP_PKEY_encrypt = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_encrypt").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         EVP_PKEY_decrypt_init = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_decrypt_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         EVP_PKEY_decrypt = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_decrypt").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         EVP_PKEY_CTX_set_rsa_padding = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_rsa_padding").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         EVP_PKEY_CTX_set_rsa_oaep_md = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_rsa_oaep_md").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_PKEY_CTX_set_rsa_mgf1_md = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_rsa_mgf1_md").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length)
         d2i_PrivateKey = linker.downcallHandle(
            libcrypto.find("d2i_PrivateKey").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)
         d2i_PUBKEY = linker.downcallHandle(
            libcrypto.find("d2i_PUBKEY").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         EVP_PKEY_free = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         EVP_PKEY_get_size = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_get_size").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );

         // EVP_MAC functions for HMAC
         // EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties)
         EVP_MAC_fetch = linker.downcallHandle(
            libcrypto.find("EVP_MAC_fetch").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_MAC_free = linker.downcallHandle(
            libcrypto.find("EVP_MAC_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         // EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac)
         EVP_MAC_CTX_new = linker.downcallHandle(
            libcrypto.find("EVP_MAC_CTX_new").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         EVP_MAC_CTX_free = linker.downcallHandle(
            libcrypto.find("EVP_MAC_CTX_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         // int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[])
         EVP_MAC_init = linker.downcallHandle(
            libcrypto.find("EVP_MAC_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS)
         );
         // int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)
         EVP_MAC_update = linker.downcallHandle(
            libcrypto.find("EVP_MAC_update").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)
         EVP_MAC_final = linker.downcallHandle(
            libcrypto.find("EVP_MAC_final").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx)
         EVP_MAC_CTX_get_mac_size = linker.downcallHandle(
            libcrypto.find("EVP_MAC_CTX_get_mac_size").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS)
         );
         // OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize)
         OSSL_PARAM_construct_utf8_string = linker.downcallHandle(
            libcrypto.find("OSSL_PARAM_construct_utf8_string").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // OSSL_PARAM OSSL_PARAM_construct_end(void)
         OSSL_PARAM_construct_end = linker.downcallHandle(
            libcrypto.find("OSSL_PARAM_construct_end").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS)
         );

         // int RAND_bytes(unsigned char *buf, int num)
         RAND_bytes = linker.downcallHandle(
            libcrypto.find("RAND_bytes").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );

         // void RAND_seed(const void *buf, int num)
         RAND_seed = linker.downcallHandle(
            libcrypto.find("RAND_seed").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );

         // Signature functions (EVP_DigestSign/Verify API)
         // int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
         EVP_DigestSignInit = linker.downcallHandle(
            libcrypto.find("EVP_DigestSignInit").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
         // This is actually a macro that calls EVP_DigestUpdate in OpenSSL 3.x
         EVP_DigestSignUpdate = linker.downcallHandle(
            libcrypto.find("EVP_DigestUpdate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen)
         EVP_DigestSignFinal = linker.downcallHandle(
            libcrypto.find("EVP_DigestSignFinal").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
         // Single-shot signing for algorithms like EdDSA
         EVP_DigestSign = linker.downcallHandle(
            libcrypto.find("EVP_DigestSign").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
         EVP_DigestVerifyInit = linker.downcallHandle(
            libcrypto.find("EVP_DigestVerifyInit").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
         // This is actually a macro that calls EVP_DigestUpdate in OpenSSL 3.x
         EVP_DigestVerifyUpdate = linker.downcallHandle(
            libcrypto.find("EVP_DigestUpdate").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
         EVP_DigestVerifyFinal = linker.downcallHandle(
            libcrypto.find("EVP_DigestVerifyFinal").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
         // Single-shot verification for algorithms like EdDSA
         EVP_DigestVerify = linker.downcallHandle(
            libcrypto.find("EVP_DigestVerify").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
         );
         // int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len)
         EVP_PKEY_CTX_set_rsa_pss_saltlen = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_rsa_pss_saltlen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         // EVP_PKEY *d2i_PrivateKey_ex(int type, EVP_PKEY **a, const unsigned char **pp, long length, OSSL_LIB_CTX *libctx, const char *propq)
         d2i_PrivateKey_ex = linker.downcallHandle(
            libcrypto.find("d2i_PrivateKey_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // EVP_PKEY *d2i_PUBKEY_ex(EVP_PKEY **a, const unsigned char **pp, long length, OSSL_LIB_CTX *libctx, const char *propq)
         d2i_PUBKEY_ex = linker.downcallHandle(
            libcrypto.find("d2i_PUBKEY_ex").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // Key pair generation functions
         // EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name, const char *propquery)
         EVP_PKEY_CTX_new_from_name = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_new_from_name").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
         EVP_PKEY_keygen_init = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_keygen_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
         EVP_PKEY_keygen = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_keygen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits)
         EVP_PKEY_CTX_set_rsa_keygen_bits = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_rsa_keygen_bits").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         // int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
         EVP_PKEY_CTX_set_ec_paramgen_curve_nid = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_ec_paramgen_curve_nid").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         // int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp)
         i2d_PrivateKey = linker.downcallHandle(
            libcrypto.find("i2d_PrivateKey").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **pp)
         i2d_PUBKEY = linker.downcallHandle(
            libcrypto.find("i2d_PUBKEY").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int OBJ_txt2nid(const char *s)
         OBJ_txt2nid = linker.downcallHandle(
            libcrypto.find("OBJ_txt2nid").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // int OBJ_sn2nid(const char *s)
         OBJ_sn2nid = linker.downcallHandle(
            libcrypto.find("OBJ_sn2nid").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(const EVP_PKEY *pkey)
         EVP_PKEY2PKCS8 = linker.downcallHandle(
            libcrypto.find("EVP_PKEY2PKCS8").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *p8)
         PKCS8_PRIV_KEY_INFO_free = linker.downcallHandle(
            libcrypto.find("PKCS8_PRIV_KEY_INFO_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         // int i2d_PKCS8_PRIV_KEY_INFO(const PKCS8_PRIV_KEY_INFO *p8, unsigned char **pp)
         i2d_PKCS8_PRIV_KEY_INFO = linker.downcallHandle(
            libcrypto.find("i2d_PKCS8_PRIV_KEY_INFO").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // Key agreement functions (EVP_PKEY_derive API)
         // int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
         EVP_PKEY_derive_init = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_derive_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
         EVP_PKEY_derive_set_peer = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_derive_set_peer").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
         EVP_PKEY_derive = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_derive").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // DSA/DH key generation functions
         // int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits)
         EVP_PKEY_CTX_set_dsa_paramgen_bits = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_dsa_paramgen_bits").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         // int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int len)
         EVP_PKEY_CTX_set_dh_paramgen_prime_len = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_dh_paramgen_prime_len").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );
         // int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
         EVP_PKEY_paramgen_init = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_paramgen_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
         EVP_PKEY_paramgen = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_paramgen").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(EVP_PKEY_CTX *ctx, int qbits)
         EVP_PKEY_CTX_set_dsa_paramgen_q_bits = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_dsa_paramgen_q_bits").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );

         // int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen)
         EVP_PKEY_CTX_set_dh_paramgen_generator = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_CTX_set_dh_paramgen_generator").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );

         // int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn)
         EVP_PKEY_get_bn_param = linker.downcallHandle(
            libcrypto.find("EVP_PKEY_get_bn_param").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // int BN_bn2bin(const BIGNUM *a, unsigned char *to)
         BN_bn2bin = linker.downcallHandle(
            libcrypto.find("BN_bn2bin").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // int BN_num_bytes(const BIGNUM *a) - actually a macro, use BN_num_bits and divide
         BN_num_bytes = linker.downcallHandle(
            libcrypto.find("BN_num_bits").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );

         // void BN_free(BIGNUM *a)
         BN_free = linker.downcallHandle(
            libcrypto.find("BN_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );

         // EVP_KDF functions for HKDF
         // EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties)
         EVP_KDF_fetch = linker.downcallHandle(
            libcrypto.find("EVP_KDF_fetch").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // void EVP_KDF_free(EVP_KDF *kdf)
         EVP_KDF_free = linker.downcallHandle(
            libcrypto.find("EVP_KDF_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         // EVP_KDF_CTX *EVP_KDF_CTX_new(const EVP_KDF *kdf)
         EVP_KDF_CTX_new = linker.downcallHandle(
            libcrypto.find("EVP_KDF_CTX_new").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );
         // void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)
         EVP_KDF_CTX_free = linker.downcallHandle(
            libcrypto.find("EVP_KDF_CTX_free").orElseThrow(),
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
         );
         // int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
         EVP_KDF_derive = linker.downcallHandle(
            libcrypto.find("EVP_KDF_derive").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS)
         );

         // FIPS detection functions
         // int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *libctx)
         EVP_default_properties_is_fips_enabled = linker.downcallHandle(
            libcrypto.find("EVP_default_properties_is_fips_enabled").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)
         );
         // int OSSL_PROVIDER_available(OSSL_LIB_CTX *libctx, const char *name)
         OSSL_PROVIDER_available = linker.downcallHandle(
            libcrypto.find("OSSL_PROVIDER_available").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
         );

         // const char *OpenSSL_version(int type)
         OpenSSL_version = linker.downcallHandle(
            libcrypto.find("OpenSSL_version").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
         );

         // KEM (Key Encapsulation Mechanism) functions - OpenSSL 3.2+
         // These may not exist on older OpenSSL versions, so we handle them gracefully
         try {
            // int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])
            EVP_PKEY_encapsulate_init = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_encapsulate_init").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen,
            //                         unsigned char *genkey, size_t *genkeylen)
            EVP_PKEY_encapsulate = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_encapsulate").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                  ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])
            EVP_PKEY_decapsulate_init = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_decapsulate_init").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *unwrapped, size_t *unwrappedlen,
            //                         const unsigned char *wrapped, size_t wrappedlen)
            EVP_PKEY_decapsulate = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_decapsulate").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                  ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
            );
         } catch (NoSuchElementException e) {
            // KEM functions not available on this OpenSSL version
            EVP_PKEY_encapsulate_init = null;
            EVP_PKEY_encapsulate = null;
            EVP_PKEY_decapsulate_init = null;
            EVP_PKEY_decapsulate = null;
         }

         // EVP_KEYMGMT functions for checking algorithm availability
         try {
            // EVP_KEYMGMT *EVP_KEYMGMT_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
            EVP_KEYMGMT_fetch = linker.downcallHandle(
               libcrypto.find("EVP_KEYMGMT_fetch").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // void EVP_KEYMGMT_free(EVP_KEYMGMT *keymgmt)
            EVP_KEYMGMT_free = linker.downcallHandle(
               libcrypto.find("EVP_KEYMGMT_free").orElseThrow(),
               FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
            );
         } catch (NoSuchElementException e) {
            EVP_KEYMGMT_fetch = null;
            EVP_KEYMGMT_free = null;
         }

         // Raw key export/import functions (for hybrid KEMs which don't have ASN.1 encoders)
         try {
            // int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len)
            EVP_PKEY_get_raw_public_key = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_get_raw_public_key").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len)
            EVP_PKEY_get_raw_private_key = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_get_raw_private_key").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)
            );
            // EVP_PKEY *EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
            //                                          const char *propq, const unsigned char *pub, size_t len)
            EVP_PKEY_new_raw_public_key_ex = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_new_raw_public_key_ex").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                  ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
            );
            // EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
            //                                           const char *propq, const unsigned char *priv, size_t len)
            EVP_PKEY_new_raw_private_key_ex = linker.downcallHandle(
               libcrypto.find("EVP_PKEY_new_raw_private_key_ex").orElseThrow(),
               FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                  ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
            );
         } catch (NoSuchElementException e) {
            EVP_PKEY_get_raw_public_key = null;
            EVP_PKEY_get_raw_private_key = null;
            EVP_PKEY_new_raw_public_key_ex = null;
            EVP_PKEY_new_raw_private_key_ex = null;
         }

      } catch (NoSuchMethodError | Exception e) {
         System.err.println("Error initializing OpenSSL FFM: " + e.getMessage());
         throw new IllegalStateException("Failed to initialize OpenSSL FFM", e);
      }
   }

   public static MemorySegment getDigestHandle(String algorithmName, Arena arena) throws Throwable {
      byte[] algorithmNameBytes = algorithmName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment algorithmNameSegment = arena.allocate(algorithmNameBytes.length + 1); // +1 for null terminator
      algorithmNameSegment.asByteBuffer().put(algorithmNameBytes).put((byte) 0); // Copy bytes and add null terminator
      return (MemorySegment) EVP_get_digestbyname.invokeExact(algorithmNameSegment);
   }

   public static MemorySegment EVP_MD_CTX_new() throws Throwable {
      return (MemorySegment) EVP_MD_CTX_new.invokeExact();
   }

   public static void EVP_MD_CTX_free(MemorySegment ctx) throws Throwable {
      EVP_MD_CTX_free.invokeExact(ctx);
   }

   public static int EVP_DigestInit_ex(MemorySegment ctx, MemorySegment type) throws Throwable {
      return (int) EVP_DigestInit_ex.invokeExact(ctx, type, MemorySegment.NULL);
   }

   public static int EVP_DigestUpdate(MemorySegment ctx, MemorySegment d, long cnt) throws Throwable {
      return (int) EVP_DigestUpdate.invokeExact(ctx, d, cnt);
   }

   public static int EVP_DigestFinal_ex(MemorySegment ctx, MemorySegment md, MemorySegment s) throws Throwable {
      return (int) EVP_DigestFinal_ex.invokeExact(ctx, md, s);
   }

   public static int EVP_MD_size(MemorySegment md) throws Throwable {
      return (int) EVP_MD_size.invokeExact(md);
   }

   // Cipher functions wrappers
   public static MemorySegment EVP_CIPHER_CTX_new() throws Throwable {
      return (MemorySegment) EVP_CIPHER_CTX_new.invokeExact();
   }

   public static void EVP_CIPHER_CTX_free(MemorySegment ctx) throws Throwable {
      EVP_CIPHER_CTX_free.invokeExact(ctx);
   }

   public static int EVP_EncryptInit_ex(MemorySegment ctx, MemorySegment type, MemorySegment impl, MemorySegment key, MemorySegment iv) throws Throwable {
      return (int) EVP_EncryptInit_ex.invokeExact(ctx, type, impl, key, iv);
   }

   public static int EVP_EncryptUpdate(MemorySegment ctx, MemorySegment out, MemorySegment outlen, MemorySegment in, int inlen) throws Throwable {
      return (int) EVP_EncryptUpdate.invokeExact(ctx, out, outlen, in, inlen);
   }

   public static int EVP_EncryptFinal_ex(MemorySegment ctx, MemorySegment out, MemorySegment outlen) throws Throwable {
      return (int) EVP_EncryptFinal_ex.invokeExact(ctx, out, outlen);
   }

   public static int EVP_DecryptInit_ex(MemorySegment ctx, MemorySegment type, MemorySegment impl, MemorySegment key, MemorySegment iv) throws Throwable {
      return (int) EVP_DecryptInit_ex.invokeExact(ctx, type, impl, key, iv);
   }

   public static int EVP_DecryptUpdate(MemorySegment ctx, MemorySegment out, MemorySegment outlen, MemorySegment in, int inlen) throws Throwable {
      return (int) EVP_DecryptUpdate.invokeExact(ctx, out, outlen, in, inlen);
   }

   public static int EVP_DecryptFinal_ex(MemorySegment ctx, MemorySegment out, MemorySegment outlen) throws Throwable {
      return (int) EVP_DecryptFinal_ex.invokeExact(ctx, out, outlen);
   }

   public static MemorySegment EVP_get_cipherbyname(String cipherName, Arena arena) throws Throwable {
      byte[] cipherNameBytes = cipherName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment cipherNameSegment = arena.allocate(cipherNameBytes.length + 1); // +1 for null terminator
      cipherNameSegment.asByteBuffer().put(cipherNameBytes).put((byte) 0); // Copy bytes and add null terminator
      return (MemorySegment) EVP_get_cipherbyname.invokeExact(cipherNameSegment);
   }

   public static int EVP_CIPHER_CTX_ctrl(MemorySegment ctx, int cmd, int larg, MemorySegment parg) throws Throwable {
      return (int) EVP_CIPHER_CTX_ctrl.invokeExact(ctx, cmd, larg, parg);
   }

   public static int EVP_CIPHER_CTX_set_padding(MemorySegment ctx, int padding) throws Throwable {
      // EVP_CTRL_SET_PADDING is 9 (defined in openssl/evp.h)
      return EVP_CIPHER_CTX_ctrl(ctx, 9, padding, MemorySegment.NULL);
   }

   public static int EVP_CIPHER_get_iv_length(MemorySegment cipher) throws Throwable {
      return (int) EVP_CIPHER_get_iv_length.invokeExact(cipher);
   }

   public static int EVP_CIPHER_get_key_length(MemorySegment cipher) throws Throwable {
      return (int) EVP_CIPHER_get_key_length.invokeExact(cipher);
   }

   public static int EVP_CIPHER_get_block_size(MemorySegment cipher) throws Throwable {
      return (int) EVP_CIPHER_get_block_size.invokeExact(cipher);
   }

   /**
    * Derives a key using PKCS5 PBKDF2 HMAC.
    *
    * @param password the password
    * @param salt the salt
    * @param iterationCount the iteration count
    * @param digestName the digest algorithm name (e.g., "SHA256", "SHA1")
    * @param keyLength the desired key length in bytes
    * @param arena the arena for memory allocation
    * @return the derived key bytes
    * @throws Throwable if key derivation fails
    */
   public static byte[] PKCS5_PBKDF2_HMAC(char[] password, byte[] salt, int iterationCount,
                                          String digestName, int keyLength, Arena arena) throws Throwable {
      // Get the digest handle
      MemorySegment digestHandle = getDigestHandle(digestName, arena);
      if (digestHandle.equals(MemorySegment.NULL)) {
         throw new IllegalArgumentException("Unknown digest: " + digestName);
      }

      // Convert password to bytes (UTF-8)
      byte[] passwordBytes = new String(password).getBytes(java.nio.charset.StandardCharsets.UTF_8);

      // Allocate memory segments
      MemorySegment passSegment = arena.allocate(ValueLayout.JAVA_BYTE, passwordBytes.length);
      passSegment.asByteBuffer().put(passwordBytes);

      MemorySegment saltSegment = arena.allocate(ValueLayout.JAVA_BYTE, salt.length);
      saltSegment.asByteBuffer().put(salt);

      MemorySegment outSegment = arena.allocate(ValueLayout.JAVA_BYTE, keyLength);

      // Call PKCS5_PBKDF2_HMAC
      int result = (int) PKCS5_PBKDF2_HMAC.invokeExact(
         passSegment,
         passwordBytes.length,
         saltSegment,
         salt.length,
         iterationCount,
         digestHandle,
         keyLength,
         outSegment
      );

      if (result != 1) {
         throw new IllegalStateException("PKCS5_PBKDF2_HMAC failed");
      }

      // Extract the derived key
      byte[] derivedKey = new byte[keyLength];
      outSegment.asByteBuffer().get(derivedKey);

      // Clear sensitive data
      java.util.Arrays.fill(passwordBytes, (byte) 0);

      return derivedKey;
   }

   /**
    * Derives a key using PKCS5 PBKDF2 HMAC with pre-encoded password bytes.
    *
    * @param passwordBytes the password as bytes (already encoded)
    * @param salt the salt
    * @param iterationCount the iteration count
    * @param digestName the digest algorithm name (e.g., "SHA256", "SHA1")
    * @param keyLength the desired key length in bytes
    * @param arena the arena for memory allocation
    * @return the derived key bytes
    * @throws Throwable if key derivation fails
    */
   public static byte[] PKCS5_PBKDF2_HMAC(byte[] passwordBytes, byte[] salt, int iterationCount,
                                          String digestName, int keyLength, Arena arena) throws Throwable {
      // Get the digest handle
      MemorySegment digestHandle = getDigestHandle(digestName, arena);
      if (digestHandle.equals(MemorySegment.NULL)) {
         throw new IllegalArgumentException("Unknown digest: " + digestName);
      }

      // Allocate memory segments
      MemorySegment passSegment = arena.allocate(ValueLayout.JAVA_BYTE, passwordBytes.length);
      passSegment.asByteBuffer().put(passwordBytes);

      MemorySegment saltSegment = arena.allocate(ValueLayout.JAVA_BYTE, salt.length);
      saltSegment.asByteBuffer().put(salt);

      MemorySegment outSegment = arena.allocate(ValueLayout.JAVA_BYTE, keyLength);

      // Call PKCS5_PBKDF2_HMAC
      int result = (int) PKCS5_PBKDF2_HMAC.invokeExact(
         passSegment,
         passwordBytes.length,
         saltSegment,
         salt.length,
         iterationCount,
         digestHandle,
         keyLength,
         outSegment
      );

      if (result != 1) {
         throw new IllegalStateException("PKCS5_PBKDF2_HMAC failed");
      }

      // Extract the derived key
      byte[] derivedKey = new byte[keyLength];
      outSegment.asByteBuffer().get(derivedKey);

      return derivedKey;
   }

   // RSA constants
   public static final int RSA_PKCS1_PADDING = 1;
   public static final int RSA_NO_PADDING = 3;
   public static final int RSA_PKCS1_OAEP_PADDING = 4;
   public static final int RSA_PKCS1_PSS_PADDING = 6;
   public static final int EVP_PKEY_RSA = 6;

   public static MemorySegment EVP_PKEY_CTX_new_from_pkey(MemorySegment libctx, MemorySegment pkey, MemorySegment propq) throws Throwable {
      return (MemorySegment) EVP_PKEY_CTX_new_from_pkey.invokeExact(libctx, pkey, propq);
   }

   public static void EVP_PKEY_CTX_free(MemorySegment ctx) throws Throwable {
      EVP_PKEY_CTX_free.invokeExact(ctx);
   }

   public static int EVP_PKEY_encrypt_init(MemorySegment ctx) throws Throwable {
      return (int) EVP_PKEY_encrypt_init.invokeExact(ctx);
   }

   public static int EVP_PKEY_encrypt(MemorySegment ctx, MemorySegment out, MemorySegment outlen, MemorySegment in, long inlen) throws Throwable {
      return (int) EVP_PKEY_encrypt.invokeExact(ctx, out, outlen, in, inlen);
   }

   public static int EVP_PKEY_decrypt_init(MemorySegment ctx) throws Throwable {
      return (int) EVP_PKEY_decrypt_init.invokeExact(ctx);
   }

   public static int EVP_PKEY_decrypt(MemorySegment ctx, MemorySegment out, MemorySegment outlen, MemorySegment in, long inlen) throws Throwable {
      return (int) EVP_PKEY_decrypt.invokeExact(ctx, out, outlen, in, inlen);
   }

   public static int EVP_PKEY_CTX_set_rsa_padding(MemorySegment ctx, int padding) throws Throwable {
      return (int) EVP_PKEY_CTX_set_rsa_padding.invokeExact(ctx, padding);
   }

   public static int EVP_PKEY_CTX_set_rsa_oaep_md(MemorySegment ctx, MemorySegment md) throws Throwable {
      return (int) EVP_PKEY_CTX_set_rsa_oaep_md.invokeExact(ctx, md);
   }

   public static int EVP_PKEY_CTX_set_rsa_mgf1_md(MemorySegment ctx, MemorySegment md) throws Throwable {
      return (int) EVP_PKEY_CTX_set_rsa_mgf1_md.invokeExact(ctx, md);
   }

   public static MemorySegment d2i_PrivateKey(int type, MemorySegment a, MemorySegment pp, long length) throws Throwable {
      return (MemorySegment) d2i_PrivateKey.invokeExact(type, a, pp, length);
   }

   public static MemorySegment d2i_PUBKEY(MemorySegment a, MemorySegment pp, long length) throws Throwable {
      return (MemorySegment) d2i_PUBKEY.invokeExact(a, pp, length);
   }

   public static void EVP_PKEY_free(MemorySegment pkey) throws Throwable {
      EVP_PKEY_free.invokeExact(pkey);
   }

   public static int EVP_PKEY_get_size(MemorySegment pkey) throws Throwable {
      return (int) EVP_PKEY_get_size.invokeExact(pkey);
   }

   // EVP_MAC wrapper methods
   public static MemorySegment EVP_MAC_fetch(MemorySegment libctx, String algorithm, MemorySegment properties, Arena arena) throws Throwable {
      byte[] algBytes = algorithm.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment algSegment = arena.allocate(algBytes.length + 1);
      algSegment.asByteBuffer().put(algBytes).put((byte) 0);
      return (MemorySegment) EVP_MAC_fetch.invokeExact(libctx, algSegment, properties);
   }

   public static void EVP_MAC_free(MemorySegment mac) throws Throwable {
      EVP_MAC_free.invokeExact(mac);
   }

   public static MemorySegment EVP_MAC_CTX_new(MemorySegment mac) throws Throwable {
      return (MemorySegment) EVP_MAC_CTX_new.invokeExact(mac);
   }

   public static void EVP_MAC_CTX_free(MemorySegment ctx) throws Throwable {
      EVP_MAC_CTX_free.invokeExact(ctx);
   }

   public static int EVP_MAC_init(MemorySegment ctx, MemorySegment key, long keylen, MemorySegment params) throws Throwable {
      return (int) EVP_MAC_init.invokeExact(ctx, key, keylen, params);
   }

   public static int EVP_MAC_update(MemorySegment ctx, MemorySegment data, long datalen) throws Throwable {
      return (int) EVP_MAC_update.invokeExact(ctx, data, datalen);
   }

   public static int EVP_MAC_final(MemorySegment ctx, MemorySegment out, MemorySegment outl, long outsize) throws Throwable {
      return (int) EVP_MAC_final.invokeExact(ctx, out, outl, outsize);
   }

   public static long EVP_MAC_CTX_get_mac_size(MemorySegment ctx) throws Throwable {
      return (long) EVP_MAC_CTX_get_mac_size.invokeExact(ctx);
   }

   // OSSL_PARAM size (on 64-bit: key(8) + data_type(4) + padding(4) + data(8) + data_size(8) + return_size(8) = 40 bytes)
   public static final long OSSL_PARAM_SIZE = 40;
   public static final int OSSL_PARAM_UTF8_STRING = 4;

   /**
    * Creates an OSSL_PARAM array with a single utf8 string parameter for the digest algorithm,
    * followed by an end marker.
    */
   public static MemorySegment createDigestParams(String digestName, Arena arena) {
      // Allocate space for 2 OSSL_PARAM entries (one for digest, one for end marker)
      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * 2);

      // Create the key string "digest"
      byte[] keyBytes = "digest".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment keySegment = arena.allocate(keyBytes.length + 1);
      keySegment.asByteBuffer().put(keyBytes).put((byte) 0);

      // Create the value string (digest name)
      byte[] valueBytes = digestName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment valueSegment = arena.allocate(valueBytes.length + 1);
      valueSegment.asByteBuffer().put(valueBytes).put((byte) 0);

      // Fill in first OSSL_PARAM entry
      // key (offset 0)
      params.set(ValueLayout.ADDRESS, 0, keySegment);
      // data_type (offset 8)
      params.set(ValueLayout.JAVA_INT, 8, OSSL_PARAM_UTF8_STRING);
      // data (offset 16)
      params.set(ValueLayout.ADDRESS, 16, valueSegment);
      // data_size (offset 24)
      params.set(ValueLayout.JAVA_LONG, 24, valueBytes.length);
      // return_size (offset 32)
      params.set(ValueLayout.JAVA_LONG, 32, 0L);

      // Fill in end marker (second OSSL_PARAM entry with NULL key)
      params.set(ValueLayout.ADDRESS, OSSL_PARAM_SIZE, MemorySegment.NULL);

      return params;
   }

   /**
    * Generates cryptographically secure random bytes using OpenSSL's RAND_bytes.
    *
    * @param length the number of random bytes to generate
    * @return the random bytes
    * @throws Throwable if random generation fails
    */
   public static byte[] RAND_bytes(int length) throws Throwable {
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, length);
         int result = (int) RAND_bytes.invokeExact(buffer, length);
         if (result != 1) {
            throw new IllegalStateException("RAND_bytes failed");
         }
         byte[] bytes = new byte[length];
         buffer.asByteBuffer().get(bytes);
         return bytes;
      }
   }

   /**
    * Seeds the OpenSSL random number generator with additional entropy.
    *
    * @param seed the seed bytes
    * @throws Throwable if seeding fails
    */
   public static void RAND_seed(byte[] seed) throws Throwable {
      if (seed == null || seed.length == 0) {
         return;
      }
      try (Arena arena = Arena.ofConfined()) {
         MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, seed.length);
         buffer.asByteBuffer().put(seed);
         RAND_seed.invokeExact(buffer, seed.length);
      }
   }

   // Signature wrapper methods
   public static int EVP_DigestSignInit(MemorySegment ctx, MemorySegment pctx, MemorySegment type, MemorySegment engine, MemorySegment pkey) throws Throwable {
      return (int) EVP_DigestSignInit.invokeExact(ctx, pctx, type, engine, pkey);
   }

   public static int EVP_DigestSignUpdate(MemorySegment ctx, MemorySegment data, long datalen) throws Throwable {
      return (int) EVP_DigestSignUpdate.invokeExact(ctx, data, datalen);
   }

   public static int EVP_DigestSignFinal(MemorySegment ctx, MemorySegment sig, MemorySegment siglen) throws Throwable {
      return (int) EVP_DigestSignFinal.invokeExact(ctx, sig, siglen);
   }

   /**
    * Single-shot signing function for algorithms like EdDSA.
    */
   public static int EVP_DigestSign(MemorySegment ctx, MemorySegment sig, MemorySegment siglen, MemorySegment tbs, long tbslen) throws Throwable {
      return (int) EVP_DigestSign.invokeExact(ctx, sig, siglen, tbs, tbslen);
   }

   public static int EVP_DigestVerifyInit(MemorySegment ctx, MemorySegment pctx, MemorySegment type, MemorySegment engine, MemorySegment pkey) throws Throwable {
      return (int) EVP_DigestVerifyInit.invokeExact(ctx, pctx, type, engine, pkey);
   }

   public static int EVP_DigestVerifyUpdate(MemorySegment ctx, MemorySegment data, long datalen) throws Throwable {
      return (int) EVP_DigestVerifyUpdate.invokeExact(ctx, data, datalen);
   }

   public static int EVP_DigestVerifyFinal(MemorySegment ctx, MemorySegment sig, long siglen) throws Throwable {
      return (int) EVP_DigestVerifyFinal.invokeExact(ctx, sig, siglen);
   }

   /**
    * Single-shot verification function for algorithms like EdDSA.
    */
   public static int EVP_DigestVerify(MemorySegment ctx, MemorySegment sig, long siglen, MemorySegment tbs, long tbslen) throws Throwable {
      return (int) EVP_DigestVerify.invokeExact(ctx, sig, siglen, tbs, tbslen);
   }

   public static int EVP_PKEY_CTX_set_rsa_pss_saltlen(MemorySegment ctx, int len) throws Throwable {
      return (int) EVP_PKEY_CTX_set_rsa_pss_saltlen.invokeExact(ctx, len);
   }

   // Constants for RSA-PSS salt length
   public static final int RSA_PSS_SALTLEN_DIGEST = -1;  // Use digest length
   public static final int RSA_PSS_SALTLEN_MAX = -2;     // Use maximum
   public static final int RSA_PSS_SALTLEN_AUTO = -3;    // Auto-detect on verify

   // Key type constants
   public static final int EVP_PKEY_EC = 408;

   /**
    * Loads a private key from DER-encoded bytes.
    * For EC keys, use type=0 to auto-detect.
    */
   public static MemorySegment loadPrivateKey(int type, byte[] keyBytes, Arena arena) throws Throwable {
      MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
      keySegment.asByteBuffer().put(keyBytes);

      MemorySegment keyPtrSegment = arena.allocate(ValueLayout.ADDRESS);
      keyPtrSegment.set(ValueLayout.ADDRESS, 0, keySegment);

      // Use d2i_PrivateKey_ex with type=0 for auto-detection (works for both RSA and EC)
      MemorySegment pkey = (MemorySegment) d2i_PrivateKey_ex.invokeExact(type, MemorySegment.NULL, keyPtrSegment, (long) keyBytes.length, MemorySegment.NULL, MemorySegment.NULL);
      return pkey;
   }

   /**
    * Loads a public key from DER-encoded bytes (SubjectPublicKeyInfo format).
    */
   public static MemorySegment loadPublicKey(byte[] keyBytes, Arena arena) throws Throwable {
      MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
      keySegment.asByteBuffer().put(keyBytes);

      MemorySegment keyPtrSegment = arena.allocate(ValueLayout.ADDRESS);
      keyPtrSegment.set(ValueLayout.ADDRESS, 0, keySegment);

      MemorySegment pkey = (MemorySegment) d2i_PUBKEY_ex.invokeExact(MemorySegment.NULL, keyPtrSegment, (long) keyBytes.length, MemorySegment.NULL, MemorySegment.NULL);
      return pkey;
   }

   // Key pair generation wrapper methods
   public static MemorySegment EVP_PKEY_CTX_new_from_name(MemorySegment libctx, String name, MemorySegment propquery, Arena arena) throws Throwable {
      byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment nameSegment = arena.allocate(nameBytes.length + 1);
      nameSegment.asByteBuffer().put(nameBytes).put((byte) 0);
      return (MemorySegment) EVP_PKEY_CTX_new_from_name.invokeExact(libctx, nameSegment, propquery);
   }

   public static int EVP_PKEY_keygen_init(MemorySegment ctx) throws Throwable {
      return (int) EVP_PKEY_keygen_init.invokeExact(ctx);
   }

   public static int EVP_PKEY_keygen(MemorySegment ctx, MemorySegment ppkey) throws Throwable {
      return (int) EVP_PKEY_keygen.invokeExact(ctx, ppkey);
   }

   public static int EVP_PKEY_CTX_set_rsa_keygen_bits(MemorySegment ctx, int bits) throws Throwable {
      return (int) EVP_PKEY_CTX_set_rsa_keygen_bits.invokeExact(ctx, bits);
   }

   public static int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(MemorySegment ctx, int nid) throws Throwable {
      return (int) EVP_PKEY_CTX_set_ec_paramgen_curve_nid.invokeExact(ctx, nid);
   }

   public static int i2d_PrivateKey(MemorySegment pkey, MemorySegment pp) throws Throwable {
      return (int) i2d_PrivateKey.invokeExact(pkey, pp);
   }

   public static int i2d_PUBKEY(MemorySegment pkey, MemorySegment pp) throws Throwable {
      return (int) i2d_PUBKEY.invokeExact(pkey, pp);
   }

   public static int OBJ_txt2nid(String txt, Arena arena) throws Throwable {
      byte[] txtBytes = txt.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment txtSegment = arena.allocate(txtBytes.length + 1);
      txtSegment.asByteBuffer().put(txtBytes).put((byte) 0);
      return (int) OBJ_txt2nid.invokeExact(txtSegment);
   }

   public static int OBJ_sn2nid(String sn, Arena arena) throws Throwable {
      byte[] snBytes = sn.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment snSegment = arena.allocate(snBytes.length + 1);
      snSegment.asByteBuffer().put(snBytes).put((byte) 0);
      return (int) OBJ_sn2nid.invokeExact(snSegment);
   }

   // Common EC curve NIDs
   public static final int NID_X9_62_prime256v1 = 415;  // P-256 / secp256r1
   public static final int NID_secp384r1 = 715;         // P-384
   public static final int NID_secp521r1 = 716;         // P-521
   public static final int NID_secp256k1 = 714;         // Bitcoin curve

   public static MemorySegment EVP_PKEY2PKCS8(MemorySegment pkey) throws Throwable {
      return (MemorySegment) EVP_PKEY2PKCS8.invokeExact(pkey);
   }

   public static void PKCS8_PRIV_KEY_INFO_free(MemorySegment p8) throws Throwable {
      PKCS8_PRIV_KEY_INFO_free.invokeExact(p8);
   }

   public static int i2d_PKCS8_PRIV_KEY_INFO(MemorySegment p8, MemorySegment pp) throws Throwable {
      return (int) i2d_PKCS8_PRIV_KEY_INFO.invokeExact(p8, pp);
   }

   /**
    * Exports an EVP_PKEY to DER-encoded PKCS#8 private key bytes.
    */
   public static byte[] exportPrivateKey(MemorySegment pkey, Arena arena) throws Throwable {
      // Convert to PKCS8 format
      MemorySegment p8 = EVP_PKEY2PKCS8(pkey);
      if (p8.equals(MemorySegment.NULL)) {
         throw new IllegalStateException("Failed to convert private key to PKCS8");
      }

      try {
         // First call to get the length
         int len = i2d_PKCS8_PRIV_KEY_INFO(p8, MemorySegment.NULL);
         if (len <= 0) {
            throw new IllegalStateException("Failed to get PKCS8 private key length");
         }

         // Allocate buffer and export
         MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, len);
         MemorySegment bufferPtr = arena.allocate(ValueLayout.ADDRESS);
         bufferPtr.set(ValueLayout.ADDRESS, 0, buffer);

         int written = i2d_PKCS8_PRIV_KEY_INFO(p8, bufferPtr);
         if (written <= 0) {
            throw new IllegalStateException("Failed to export PKCS8 private key");
         }

         byte[] result = new byte[written];
         buffer.asByteBuffer().get(result);
         return result;
      } finally {
         PKCS8_PRIV_KEY_INFO_free(p8);
      }
   }

   /**
    * Exports an EVP_PKEY to DER-encoded public key bytes (SubjectPublicKeyInfo format).
    */
   public static byte[] exportPublicKey(MemorySegment pkey, Arena arena) throws Throwable {
      // First call to get the length
      int len = i2d_PUBKEY(pkey, MemorySegment.NULL);
      if (len <= 0) {
         throw new IllegalStateException("Failed to get public key length");
      }

      // Allocate buffer and export
      MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, len);
      MemorySegment bufferPtr = arena.allocate(ValueLayout.ADDRESS);
      bufferPtr.set(ValueLayout.ADDRESS, 0, buffer);

      int written = i2d_PUBKEY(pkey, bufferPtr);
      if (written <= 0) {
         throw new IllegalStateException("Failed to export public key");
      }

      byte[] result = new byte[written];
      buffer.asByteBuffer().get(result);
      return result;
   }

   /**
    * Exports an EVP_PKEY to raw public key bytes.
    * Used for hybrid KEMs which don't have standard ASN.1 encoders.
    */
   public static byte[] exportRawPublicKey(MemorySegment pkey, Arena arena) throws Throwable {
      if (EVP_PKEY_get_raw_public_key == null) {
         throw new IllegalStateException("Raw key export not available on this OpenSSL version");
      }

      // First call to get the length
      MemorySegment lenPtr = arena.allocate(ValueLayout.JAVA_LONG);
      int result = (int) EVP_PKEY_get_raw_public_key.invokeExact(pkey, MemorySegment.NULL, lenPtr);
      if (result != 1) {
         throw new IllegalStateException("Failed to get raw public key length");
      }

      long len = lenPtr.get(ValueLayout.JAVA_LONG, 0);
      MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, len);

      result = (int) EVP_PKEY_get_raw_public_key.invokeExact(pkey, buffer, lenPtr);
      if (result != 1) {
         throw new IllegalStateException("Failed to export raw public key");
      }

      byte[] keyBytes = new byte[toIntSize(lenPtr.get(ValueLayout.JAVA_LONG, 0))];
      buffer.asByteBuffer().get(keyBytes);
      return keyBytes;
   }

   /**
    * Exports an EVP_PKEY to raw private key bytes.
    * Used for hybrid KEMs which don't have standard ASN.1 encoders.
    */
   public static byte[] exportRawPrivateKey(MemorySegment pkey, Arena arena) throws Throwable {
      if (EVP_PKEY_get_raw_private_key == null) {
         throw new IllegalStateException("Raw key export not available on this OpenSSL version");
      }

      // First call to get the length
      MemorySegment lenPtr = arena.allocate(ValueLayout.JAVA_LONG);
      int result = (int) EVP_PKEY_get_raw_private_key.invokeExact(pkey, MemorySegment.NULL, lenPtr);
      if (result != 1) {
         throw new IllegalStateException("Failed to get raw private key length");
      }

      long len = lenPtr.get(ValueLayout.JAVA_LONG, 0);
      MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, len);

      result = (int) EVP_PKEY_get_raw_private_key.invokeExact(pkey, buffer, lenPtr);
      if (result != 1) {
         throw new IllegalStateException("Failed to export raw private key");
      }

      byte[] keyBytes = new byte[toIntSize(lenPtr.get(ValueLayout.JAVA_LONG, 0))];
      buffer.asByteBuffer().get(keyBytes);
      return keyBytes;
   }

   /**
    * Loads a raw public key from bytes.
    * Used for hybrid KEMs which don't have standard ASN.1 encoders.
    *
    * @param keytype the OpenSSL key type name (e.g., "X25519MLKEM768")
    * @param keyBytes the raw public key bytes
    * @param arena the memory arena
    * @return the EVP_PKEY handle
    */
   public static MemorySegment loadRawPublicKey(String keytype, byte[] keyBytes, Arena arena) throws Throwable {
      if (EVP_PKEY_new_raw_public_key_ex == null) {
         throw new IllegalStateException("Raw key import not available on this OpenSSL version");
      }

      MemorySegment keytypeSegment = arena.allocateFrom(keytype);
      MemorySegment keyBuffer = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
      keyBuffer.asByteBuffer().put(keyBytes);

      MemorySegment pkey = (MemorySegment) EVP_PKEY_new_raw_public_key_ex.invokeExact(
         MemorySegment.NULL, keytypeSegment, MemorySegment.NULL, keyBuffer, (long) keyBytes.length);

      if (pkey.equals(MemorySegment.NULL)) {
         throw new IllegalStateException("Failed to load raw public key for " + keytype);
      }

      return pkey;
   }

   /**
    * Loads a raw private key from bytes.
    * Used for hybrid KEMs which don't have standard ASN.1 encoders.
    *
    * @param keytype the OpenSSL key type name (e.g., "X25519MLKEM768")
    * @param keyBytes the raw private key bytes
    * @param arena the memory arena
    * @return the EVP_PKEY handle
    */
   public static MemorySegment loadRawPrivateKey(String keytype, byte[] keyBytes, Arena arena) throws Throwable {
      if (EVP_PKEY_new_raw_private_key_ex == null) {
         throw new IllegalStateException("Raw key import not available on this OpenSSL version");
      }

      MemorySegment keytypeSegment = arena.allocateFrom(keytype);
      MemorySegment keyBuffer = arena.allocate(ValueLayout.JAVA_BYTE, keyBytes.length);
      keyBuffer.asByteBuffer().put(keyBytes);

      MemorySegment pkey = (MemorySegment) EVP_PKEY_new_raw_private_key_ex.invokeExact(
         MemorySegment.NULL, keytypeSegment, MemorySegment.NULL, keyBuffer, (long) keyBytes.length);

      if (pkey.equals(MemorySegment.NULL)) {
         throw new IllegalStateException("Failed to load raw private key for " + keytype);
      }

      return pkey;
   }

   /**
    * Checks if raw key functions are available.
    */
   public static boolean isRawKeyAvailable() {
      return EVP_PKEY_get_raw_public_key != null && EVP_PKEY_new_raw_public_key_ex != null;
   }

   // Key agreement wrapper methods
   public static int EVP_PKEY_derive_init(MemorySegment ctx) throws Throwable {
      return (int) EVP_PKEY_derive_init.invokeExact(ctx);
   }

   public static int EVP_PKEY_derive_set_peer(MemorySegment ctx, MemorySegment peer) throws Throwable {
      return (int) EVP_PKEY_derive_set_peer.invokeExact(ctx, peer);
   }

   public static int EVP_PKEY_derive(MemorySegment ctx, MemorySegment key, MemorySegment keylen) throws Throwable {
      return (int) EVP_PKEY_derive.invokeExact(ctx, key, keylen);
   }

   /**
    * Derives a shared secret using ECDH key agreement.
    *
    * @param privateKey the local private key (EVP_PKEY)
    * @param publicKey the peer's public key (EVP_PKEY)
    * @param arena the arena for memory allocation
    * @return the derived shared secret bytes
    * @throws Throwable if key agreement fails
    */
   public static byte[] deriveSharedSecret(MemorySegment privateKey, MemorySegment publicKey, Arena arena) throws Throwable {
      // Create context from private key
      MemorySegment ctx = EVP_PKEY_CTX_new_from_pkey(MemorySegment.NULL, privateKey, MemorySegment.NULL);
      if (ctx.equals(MemorySegment.NULL)) {
         throw new IllegalStateException("Failed to create EVP_PKEY_CTX for key agreement");
      }

      try {
         // Initialize for derivation
         int result = EVP_PKEY_derive_init(ctx);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive_init failed");
         }

         // Set peer's public key
         result = EVP_PKEY_derive_set_peer(ctx, publicKey);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive_set_peer failed");
         }

         // Get the required buffer length
         MemorySegment secretLenPtr = arena.allocate(ValueLayout.JAVA_LONG);
         result = EVP_PKEY_derive(ctx, MemorySegment.NULL, secretLenPtr);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive (get length) failed");
         }

         long secretLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);

         // Allocate buffer and derive the secret
         MemorySegment secretBuffer = arena.allocate(ValueLayout.JAVA_BYTE, secretLen);
         result = EVP_PKEY_derive(ctx, secretBuffer, secretLenPtr);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive failed");
         }

         // Get the actual derived length (may be different)
         long actualLen = secretLenPtr.get(ValueLayout.JAVA_LONG, 0);

         byte[] secret = new byte[(int) actualLen];
         secretBuffer.asByteBuffer().get(secret);
         return secret;
      } finally {
         EVP_PKEY_CTX_free(ctx);
      }
   }

   // DSA/DH key generation wrapper methods
   public static int EVP_PKEY_CTX_set_dsa_paramgen_bits(MemorySegment ctx, int bits) throws Throwable {
      return (int) EVP_PKEY_CTX_set_dsa_paramgen_bits.invokeExact(ctx, bits);
   }

   public static int EVP_PKEY_CTX_set_dh_paramgen_prime_len(MemorySegment ctx, int len) throws Throwable {
      return (int) EVP_PKEY_CTX_set_dh_paramgen_prime_len.invokeExact(ctx, len);
   }

   public static int EVP_PKEY_paramgen_init(MemorySegment ctx) throws Throwable {
      return (int) EVP_PKEY_paramgen_init.invokeExact(ctx);
   }

   public static int EVP_PKEY_paramgen(MemorySegment ctx, MemorySegment ppkey) throws Throwable {
      return (int) EVP_PKEY_paramgen.invokeExact(ctx, ppkey);
   }

   public static int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(MemorySegment ctx, int qbits) throws Throwable {
      return (int) EVP_PKEY_CTX_set_dsa_paramgen_q_bits.invokeExact(ctx, qbits);
   }

   public static int EVP_PKEY_CTX_set_dh_paramgen_generator(MemorySegment ctx, int gen) throws Throwable {
      return (int) EVP_PKEY_CTX_set_dh_paramgen_generator.invokeExact(ctx, gen);
   }

   /**
    * Extracts a BigInteger parameter from an EVP_PKEY.
    *
    * @param pkey the EVP_PKEY
    * @param paramName the parameter name (e.g., "p", "q", "g", "pub", "priv")
    * @param arena the arena for memory allocation
    * @return the BigInteger value
    * @throws Throwable if extraction fails
    */
   public static java.math.BigInteger EVP_PKEY_get_bn_param(MemorySegment pkey, String paramName, Arena arena) throws Throwable {
      // Allocate pointer for BIGNUM
      MemorySegment bnPtr = arena.allocate(ValueLayout.ADDRESS);

      // Create parameter name string
      MemorySegment nameSegment = arena.allocateFrom(paramName);

      // Get the BIGNUM parameter
      int result = (int) EVP_PKEY_get_bn_param.invokeExact(pkey, nameSegment, bnPtr);
      if (result != 1) {
         throw new IllegalStateException("EVP_PKEY_get_bn_param failed for: " + paramName);
      }

      MemorySegment bn = bnPtr.get(ValueLayout.ADDRESS, 0);
      if (bn.equals(MemorySegment.NULL)) {
         throw new IllegalStateException("BIGNUM is null for: " + paramName);
      }

      try {
         // Get the number of bits (BN_num_bits)
         int numBits = (int) BN_num_bytes.invokeExact(bn);
         int numBytes = (numBits + 7) / 8;

         if (numBytes == 0) {
            return java.math.BigInteger.ZERO;
         }

         // Allocate buffer for the binary representation
         MemorySegment buffer = arena.allocate(ValueLayout.JAVA_BYTE, numBytes);

         // Convert BIGNUM to binary
         int written = (int) BN_bn2bin.invokeExact(bn, buffer);
         if (written != numBytes) {
            throw new IllegalStateException("BN_bn2bin returned unexpected length");
         }

         // Convert to BigInteger (unsigned)
         byte[] bytes = new byte[numBytes];
         buffer.asByteBuffer().get(bytes);

         // BN_bn2bin produces unsigned big-endian bytes
         // BigInteger expects a sign-magnitude representation
         // For positive numbers, we may need to prepend a zero byte if high bit is set
         if (bytes.length > 0 && (bytes[0] & 0x80) != 0) {
            byte[] tmp = new byte[bytes.length + 1];
            System.arraycopy(bytes, 0, tmp, 1, bytes.length);
            bytes = tmp;
         }

         return new java.math.BigInteger(bytes);
      } finally {
         // Free the BIGNUM
         BN_free.invokeExact(bn);
      }
   }

   public static void BN_free(MemorySegment bn) throws Throwable {
      BN_free.invokeExact(bn);
   }

   // EVP_KDF wrapper methods
   public static MemorySegment EVP_KDF_fetch(MemorySegment libctx, String algorithm, MemorySegment properties, Arena arena) throws Throwable {
      byte[] algBytes = algorithm.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment algSegment = arena.allocate(algBytes.length + 1);
      algSegment.asByteBuffer().put(algBytes).put((byte) 0);
      return (MemorySegment) EVP_KDF_fetch.invokeExact(libctx, algSegment, properties);
   }

   public static void EVP_KDF_free(MemorySegment kdf) throws Throwable {
      EVP_KDF_free.invokeExact(kdf);
   }

   public static MemorySegment EVP_KDF_CTX_new(MemorySegment kdf) throws Throwable {
      return (MemorySegment) EVP_KDF_CTX_new.invokeExact(kdf);
   }

   public static void EVP_KDF_CTX_free(MemorySegment ctx) throws Throwable {
      EVP_KDF_CTX_free.invokeExact(ctx);
   }

   public static int EVP_KDF_derive(MemorySegment ctx, MemorySegment key, long keylen, MemorySegment params) throws Throwable {
      return (int) EVP_KDF_derive.invokeExact(ctx, key, keylen, params);
   }

   // FIPS detection methods

   /**
    * Checks if FIPS mode is enabled as the default property in OpenSSL.
    *
    * @return true if FIPS mode is enabled, false otherwise
    */
   public static boolean isFIPSEnabled() {
      try {
         int result = (int) EVP_default_properties_is_fips_enabled.invokeExact(MemorySegment.NULL);
         return result == 1;
      } catch (Throwable e) {
         return false;
      }
   }

   /**
    * Checks if a specific OpenSSL provider is available.
    *
    * @param providerName the name of the provider (e.g., "fips", "default")
    * @return true if the provider is available, false otherwise
    */
   public static boolean isProviderAvailable(String providerName) {
      try (Arena arena = Arena.ofConfined()) {
         byte[] nameBytes = providerName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
         MemorySegment nameSegment = arena.allocate(nameBytes.length + 1);
         nameSegment.asByteBuffer().put(nameBytes).put((byte) 0);
         int result = (int) OSSL_PROVIDER_available.invokeExact(MemorySegment.NULL, nameSegment);
         return result == 1;
      } catch (Throwable e) {
         return false;
      }
   }

   /**
    * Checks if the FIPS provider is available in OpenSSL.
    *
    * @return true if the FIPS provider is available, false otherwise
    */
   public static boolean isFIPSProviderAvailable() {
      return isProviderAvailable("fips");
   }

   // OpenSSL version type constants
   private static final int OPENSSL_VERSION = 0;

   /**
    * Checks if a specific algorithm is available in OpenSSL.
    *
    * @param type the algorithm type: "MD" (digest), "CIPHER", "MAC", "KDF", or "KEYMGMT"
    * @param name the algorithm name (e.g., "blake2b512", "aes-256-ccm", "KMAC128", "mlkem768")
    * @return true if the algorithm is available, false otherwise
    */
   public static boolean isAlgorithmAvailable(String type, String name) {
      try (Arena arena = Arena.ofConfined()) {
         return switch (type.toUpperCase()) {
            case "MD", "DIGEST" -> {
               MemorySegment md = getDigestHandle(name, arena);
               yield !md.equals(MemorySegment.NULL);
            }
            case "CIPHER" -> {
               MemorySegment cipher = EVP_get_cipherbyname(name, arena);
               yield !cipher.equals(MemorySegment.NULL);
            }
            case "MAC" -> {
               MemorySegment mac = EVP_MAC_fetch(MemorySegment.NULL, name, MemorySegment.NULL, arena);
               if (!mac.equals(MemorySegment.NULL)) {
                  EVP_MAC_free(mac);
                  yield true;
               }
               yield false;
            }
            case "KDF" -> {
               MemorySegment kdf = EVP_KDF_fetch(MemorySegment.NULL, name, MemorySegment.NULL, arena);
               if (!kdf.equals(MemorySegment.NULL)) {
                  EVP_KDF_free(kdf);
                  yield true;
               }
               yield false;
            }
            case "KEYMGMT" -> {
               // Check for key management algorithms (PQC algorithms like ML-KEM, ML-DSA, SLH-DSA)
               if (EVP_KEYMGMT_fetch == null) {
                  yield false;
               }
               MemorySegment keymgmt = EVP_KEYMGMT_fetch(MemorySegment.NULL, name, MemorySegment.NULL, arena);
               if (!keymgmt.equals(MemorySegment.NULL)) {
                  EVP_KEYMGMT_free(keymgmt);
                  yield true;
               }
               yield false;
            }
            default -> false;
         };
      } catch (Throwable e) {
         return false;
      }
   }

   // KEM (Key Encapsulation Mechanism) wrapper methods

   /**
    * Checks if KEM operations are available on this OpenSSL version.
    *
    * @return true if KEM operations are supported
    */
   public static boolean isKEMAvailable() {
      return EVP_PKEY_encapsulate_init != null && EVP_PKEY_encapsulate != null
          && EVP_PKEY_decapsulate_init != null && EVP_PKEY_decapsulate != null;
   }

   public static int EVP_PKEY_encapsulate_init(MemorySegment ctx, MemorySegment params) throws Throwable {
      if (EVP_PKEY_encapsulate_init == null) {
         throw new UnsupportedOperationException("KEM not supported on this OpenSSL version");
      }
      return (int) EVP_PKEY_encapsulate_init.invokeExact(ctx, params);
   }

   public static int EVP_PKEY_encapsulate(MemorySegment ctx, MemorySegment wrappedKey, MemorySegment wrappedKeyLen,
                                          MemorySegment genKey, MemorySegment genKeyLen) throws Throwable {
      if (EVP_PKEY_encapsulate == null) {
         throw new UnsupportedOperationException("KEM not supported on this OpenSSL version");
      }
      return (int) EVP_PKEY_encapsulate.invokeExact(ctx, wrappedKey, wrappedKeyLen, genKey, genKeyLen);
   }

   public static int EVP_PKEY_decapsulate_init(MemorySegment ctx, MemorySegment params) throws Throwable {
      if (EVP_PKEY_decapsulate_init == null) {
         throw new UnsupportedOperationException("KEM not supported on this OpenSSL version");
      }
      return (int) EVP_PKEY_decapsulate_init.invokeExact(ctx, params);
   }

   public static int EVP_PKEY_decapsulate(MemorySegment ctx, MemorySegment unwrapped, MemorySegment unwrappedLen,
                                          MemorySegment wrapped, long wrappedLen) throws Throwable {
      if (EVP_PKEY_decapsulate == null) {
         throw new UnsupportedOperationException("KEM not supported on this OpenSSL version");
      }
      return (int) EVP_PKEY_decapsulate.invokeExact(ctx, unwrapped, unwrappedLen, wrapped, wrappedLen);
   }

   public static MemorySegment EVP_KEYMGMT_fetch(MemorySegment libctx, String algorithm,
                                                  MemorySegment properties, Arena arena) throws Throwable {
      if (EVP_KEYMGMT_fetch == null) {
         return MemorySegment.NULL;
      }
      byte[] algBytes = algorithm.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment algSegment = arena.allocate(algBytes.length + 1);
      algSegment.asByteBuffer().put(algBytes).put((byte) 0);
      return (MemorySegment) EVP_KEYMGMT_fetch.invokeExact(libctx, algSegment, properties);
   }

   public static void EVP_KEYMGMT_free(MemorySegment keymgmt) throws Throwable {
      if (EVP_KEYMGMT_free != null && !keymgmt.equals(MemorySegment.NULL)) {
         EVP_KEYMGMT_free.invokeExact(keymgmt);
      }
   }

   /**
    * Returns the OpenSSL version string.
    *
    * @return the OpenSSL version string
    */
   public static String getOpenSSLVersion() {
      try {
         MemorySegment result = (MemorySegment) OpenSSL_version.invokeExact(OPENSSL_VERSION);
         if (result.equals(MemorySegment.NULL)) {
            return "Unknown";
         }
         return result.reinterpret(256).getString(0);
      } catch (Throwable e) {
         return "Unknown";
      }
   }

   // HKDF mode constants (from openssl/kdf.h)
   public static final int HKDF_MODE_EXTRACT_AND_EXPAND = 0;
   public static final int HKDF_MODE_EXTRACT_ONLY = 1;
   public static final int HKDF_MODE_EXPAND_ONLY = 2;

   // OSSL_PARAM types
   public static final int OSSL_PARAM_OCTET_STRING = 5;
   public static final int OSSL_PARAM_UNSIGNED_INTEGER = 1;

   /**
    * Creates an OSSL_PARAM array for HKDF operations.
    *
    * @param digestName the digest algorithm name (e.g., "SHA256")
    * @param mode the HKDF mode (extract, expand, or both)
    * @param salt the salt (can be null for expand mode)
    * @param key the input key material or PRK
    * @param info the info/context (can be null for extract mode)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createHKDFParams(String digestName, int mode, byte[] salt, byte[] key, byte[] info, Arena arena) {
      // Count number of parameters needed
      int numParams = 3;  // digest, mode, key are always required
      if (salt != null && salt.length > 0) numParams++;
      if (info != null && info.length > 0) numParams++;
      numParams++;  // end marker

      // Allocate space for OSSL_PARAM entries
      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Digest parameter
      byte[] digestKeyBytes = "digest".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment digestKeySegment = arena.allocate(digestKeyBytes.length + 1);
      digestKeySegment.asByteBuffer().put(digestKeyBytes).put((byte) 0);

      byte[] digestValueBytes = digestName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment digestValueSegment = arena.allocate(digestValueBytes.length + 1);
      digestValueSegment.asByteBuffer().put(digestValueBytes).put((byte) 0);

      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, digestKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UTF8_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, digestValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, digestValueBytes.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 2. Mode parameter
      byte[] modeKeyBytes = "mode".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment modeKeySegment = arena.allocate(modeKeyBytes.length + 1);
      modeKeySegment.asByteBuffer().put(modeKeyBytes).put((byte) 0);

      MemorySegment modeValueSegment = arena.allocate(ValueLayout.JAVA_INT);
      modeValueSegment.set(ValueLayout.JAVA_INT, 0, mode);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, modeKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UNSIGNED_INTEGER);
      params.set(ValueLayout.ADDRESS, offset + 16, modeValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, 4L);  // sizeof(int)
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 3. Key parameter
      byte[] keyKeyBytes = "key".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment keyKeySegment = arena.allocate(keyKeyBytes.length + 1);
      keyKeySegment.asByteBuffer().put(keyKeyBytes).put((byte) 0);

      MemorySegment keyValueSegment = arena.allocate(ValueLayout.JAVA_BYTE, key.length);
      keyValueSegment.asByteBuffer().put(key);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, keyKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, keyValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, (long) key.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 4. Salt parameter (optional)
      if (salt != null && salt.length > 0) {
         byte[] saltKeyBytes = "salt".getBytes(java.nio.charset.StandardCharsets.UTF_8);
         MemorySegment saltKeySegment = arena.allocate(saltKeyBytes.length + 1);
         saltKeySegment.asByteBuffer().put(saltKeyBytes).put((byte) 0);

         MemorySegment saltValueSegment = arena.allocate(ValueLayout.JAVA_BYTE, salt.length);
         saltValueSegment.asByteBuffer().put(salt);

         offset = paramIndex * OSSL_PARAM_SIZE;
         params.set(ValueLayout.ADDRESS, offset, saltKeySegment);
         params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
         params.set(ValueLayout.ADDRESS, offset + 16, saltValueSegment);
         params.set(ValueLayout.JAVA_LONG, offset + 24, (long) salt.length);
         params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
         paramIndex++;
      }

      // 5. Info parameter (optional)
      if (info != null && info.length > 0) {
         byte[] infoKeyBytes = "info".getBytes(java.nio.charset.StandardCharsets.UTF_8);
         MemorySegment infoKeySegment = arena.allocate(infoKeyBytes.length + 1);
         infoKeySegment.asByteBuffer().put(infoKeyBytes).put((byte) 0);

         MemorySegment infoValueSegment = arena.allocate(ValueLayout.JAVA_BYTE, info.length);
         infoValueSegment.asByteBuffer().put(info);

         offset = paramIndex * OSSL_PARAM_SIZE;
         params.set(ValueLayout.ADDRESS, offset, infoKeySegment);
         params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
         params.set(ValueLayout.ADDRESS, offset + 16, infoValueSegment);
         params.set(ValueLayout.JAVA_LONG, offset + 24, (long) info.length);
         params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
         paramIndex++;
      }

      // 6. End marker
      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for SCRYPT operations.
    *
    * @param password the password
    * @param salt the salt
    * @param n the CPU/memory cost parameter
    * @param r the block size parameter
    * @param p the parallelization parameter
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createScryptParams(byte[] password, byte[] salt, long n, int r, int p, Arena arena) {
      // 5 parameters + end marker
      int numParams = 6;

      // Allocate space for OSSL_PARAM entries
      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Password parameter ("pass")
      byte[] passKeyBytes = "pass".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment passKeySegment = arena.allocate(passKeyBytes.length + 1);
      passKeySegment.asByteBuffer().put(passKeyBytes).put((byte) 0);

      MemorySegment passValueSegment = arena.allocate(ValueLayout.JAVA_BYTE, password.length);
      passValueSegment.asByteBuffer().put(password);

      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, passKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, passValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, (long) password.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 2. Salt parameter
      byte[] saltKeyBytes = "salt".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment saltKeySegment = arena.allocate(saltKeyBytes.length + 1);
      saltKeySegment.asByteBuffer().put(saltKeyBytes).put((byte) 0);

      MemorySegment saltValueSegment = arena.allocate(ValueLayout.JAVA_BYTE, salt.length);
      saltValueSegment.asByteBuffer().put(salt);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, saltKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, saltValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, (long) salt.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 3. N parameter (cost)
      byte[] nKeyBytes = "n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment nKeySegment = arena.allocate(nKeyBytes.length + 1);
      nKeySegment.asByteBuffer().put(nKeyBytes).put((byte) 0);

      MemorySegment nValueSegment = arena.allocate(ValueLayout.JAVA_LONG);
      nValueSegment.set(ValueLayout.JAVA_LONG, 0, n);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, nKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UNSIGNED_INTEGER);
      params.set(ValueLayout.ADDRESS, offset + 16, nValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, 8L);  // sizeof(uint64)
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 4. r parameter (block size)
      byte[] rKeyBytes = "r".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment rKeySegment = arena.allocate(rKeyBytes.length + 1);
      rKeySegment.asByteBuffer().put(rKeyBytes).put((byte) 0);

      MemorySegment rValueSegment = arena.allocate(ValueLayout.JAVA_INT);
      rValueSegment.set(ValueLayout.JAVA_INT, 0, r);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, rKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UNSIGNED_INTEGER);
      params.set(ValueLayout.ADDRESS, offset + 16, rValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, 4L);  // sizeof(uint32)
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 5. p parameter (parallelization)
      byte[] pKeyBytes = "p".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment pKeySegment = arena.allocate(pKeyBytes.length + 1);
      pKeySegment.asByteBuffer().put(pKeyBytes).put((byte) 0);

      MemorySegment pValueSegment = arena.allocate(ValueLayout.JAVA_INT);
      pValueSegment.set(ValueLayout.JAVA_INT, 0, p);

      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, pKeySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UNSIGNED_INTEGER);
      params.set(ValueLayout.ADDRESS, offset + 16, pValueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, 4L);  // sizeof(uint32)
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);
      paramIndex++;

      // 6. End marker
      offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for Argon2 operations.
    *
    * @param password the password
    * @param salt the salt
    * @param iterations the number of iterations (t_cost)
    * @param memoryKB the memory in KB (m_cost)
    * @param parallelism the parallelism (p)
    * @param ad optional associated data (can be null)
    * @param secret optional secret (can be null)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createArgon2Params(byte[] password, byte[] salt, int iterations,
         int memoryKB, int parallelism, byte[] ad, byte[] secret, Arena arena) {
      int numParams = 5;  // pass, salt, iter, memcost, lanes
      if (ad != null && ad.length > 0) numParams++;
      if (secret != null && secret.length > 0) numParams++;
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Password parameter ("pass")
      paramIndex = addOctetParam(params, paramIndex, "pass", password, arena);

      // 2. Salt parameter
      paramIndex = addOctetParam(params, paramIndex, "salt", salt, arena);

      // 3. Iterations parameter ("iter")
      paramIndex = addUIntParam(params, paramIndex, "iter", iterations, arena);

      // 4. Memory cost parameter ("memcost")
      paramIndex = addUIntParam(params, paramIndex, "memcost", memoryKB, arena);

      // 5. Parallelism parameter ("lanes")
      paramIndex = addUIntParam(params, paramIndex, "lanes", parallelism, arena);

      // 6. Associated data (optional)
      if (ad != null && ad.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "ad", ad, arena);
      }

      // 7. Secret (optional)
      if (secret != null && secret.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "secret", secret, arena);
      }

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for X9.63 KDF operations.
    *
    * @param digestName the digest algorithm name
    * @param secret the shared secret
    * @param info the shared info (can be null)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createX963KDFParams(String digestName, byte[] secret, byte[] info, Arena arena) {
      int numParams = 2;  // digest, key
      if (info != null && info.length > 0) numParams++;
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Digest parameter
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName, arena);

      // 2. Key/secret parameter
      paramIndex = addOctetParam(params, paramIndex, "key", secret, arena);

      // 3. Info parameter (optional)
      if (info != null && info.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "info", info, arena);
      }

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for SSH KDF operations.
    *
    * @param digestName the digest algorithm name
    * @param key the shared secret (K)
    * @param xcghash the exchange hash (H)
    * @param sessionId the session ID
    * @param keyType the key type character (A-F)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createSSHKDFParams(String digestName, byte[] key, byte[] xcghash,
         byte[] sessionId, char keyType, Arena arena) {
      int numParams = 5;  // digest, key, xcghash, session_id, type
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Digest parameter
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName, arena);

      // 2. Key parameter
      paramIndex = addOctetParam(params, paramIndex, "key", key, arena);

      // 3. Exchange hash parameter
      paramIndex = addOctetParam(params, paramIndex, "xcghash", xcghash, arena);

      // 4. Session ID parameter
      paramIndex = addOctetParam(params, paramIndex, "session_id", sessionId, arena);

      // 5. Key type parameter (single character as UTF8)
      paramIndex = addUtf8Param(params, paramIndex, "type", String.valueOf(keyType), arena);

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for KBKDF (SP 800-108) operations.
    *
    * @param macName the MAC algorithm name (e.g., "HMAC")
    * @param digestName the digest algorithm name (e.g., "SHA256")
    * @param key the input key
    * @param salt the salt/label
    * @param info the context/info
    * @param mode the KDF mode ("counter", "feedback", or "pipeline")
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createKBKDFParams(String macName, String digestName, byte[] key,
         byte[] salt, byte[] info, String mode, Arena arena) {
      int numParams = 4;  // mac, digest, key, mode
      if (salt != null && salt.length > 0) numParams++;
      if (info != null && info.length > 0) numParams++;
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. MAC parameter
      paramIndex = addUtf8Param(params, paramIndex, "mac", macName, arena);

      // 2. Digest parameter
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName, arena);

      // 3. Key parameter
      paramIndex = addOctetParam(params, paramIndex, "key", key, arena);

      // 4. Mode parameter
      paramIndex = addUtf8Param(params, paramIndex, "mode", mode, arena);

      // 5. Salt/label parameter (optional)
      if (salt != null && salt.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "salt", salt, arena);
      }

      // 6. Info/context parameter (optional)
      if (info != null && info.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "info", info, arena);
      }

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for TLS1-PRF operations.
    *
    * @param digestName the digest algorithm name
    * @param secret the secret
    * @param seed the seed (label + seed concatenated)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createTLSPRFParams(String digestName, byte[] secret, byte[] seed, Arena arena) {
      int numParams = 3;  // digest, secret, seed
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Digest parameter
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName, arena);

      // 2. Secret parameter
      paramIndex = addOctetParam(params, paramIndex, "secret", secret, arena);

      // 3. Seed parameter
      paramIndex = addOctetParam(params, paramIndex, "seed", seed, arena);

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   /**
    * Creates an OSSL_PARAM array for TLS 1.3 KDF operations.
    *
    * @param digestName the digest algorithm name (SHA256 or SHA384)
    * @param mode the mode string ("EXTRACT_ONLY" or "EXPAND_ONLY")
    * @param key the input key material (for extract) or PRK (for expand)
    * @param salt the salt (for extract mode, can be null)
    * @param prefix the label prefix (typically "tls13 ")
    * @param label the label (for expand mode)
    * @param data the context data (for expand mode)
    * @param arena the arena for memory allocation
    * @return the OSSL_PARAM array
    */
   public static MemorySegment createTLS13KDFParams(String digestName, String mode,
         byte[] key, byte[] salt, byte[] prefix, byte[] label, byte[] data, Arena arena) {
      // Count number of parameters needed
      int numParams = 3;  // digest, mode, key are always required
      if (salt != null && salt.length > 0) numParams++;
      if (prefix != null && prefix.length > 0) numParams++;
      if (label != null && label.length > 0) numParams++;
      if (data != null) numParams++;  // data can be empty but present
      numParams++;  // end marker

      MemorySegment params = arena.allocate(OSSL_PARAM_SIZE * numParams);
      int paramIndex = 0;

      // 1. Digest parameter
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName, arena);

      // 2. Mode parameter (UTF8 string for TLS13-KDF)
      paramIndex = addUtf8Param(params, paramIndex, "mode", mode, arena);

      // 3. Key parameter
      paramIndex = addOctetParam(params, paramIndex, "key", key, arena);

      // 4. Salt parameter (optional, for extract mode)
      if (salt != null && salt.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "salt", salt, arena);
      }

      // 5. Prefix parameter (optional, typically "tls13 ")
      if (prefix != null && prefix.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "prefix", prefix, arena);
      }

      // 6. Label parameter (for expand mode)
      if (label != null && label.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "label", label, arena);
      }

      // 7. Data parameter (context, for expand mode - can be empty)
      if (data != null) {
         paramIndex = addOctetParam(params, paramIndex, "data", data, arena);
      }

      // End marker
      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, MemorySegment.NULL);

      return params;
   }

   // Helper methods for building OSSL_PARAM entries

   private static int addUtf8Param(MemorySegment params, int paramIndex, String key, String value, Arena arena) {
      byte[] keyBytes = key.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment keySegment = arena.allocate(keyBytes.length + 1);
      keySegment.asByteBuffer().put(keyBytes).put((byte) 0);

      byte[] valueBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment valueSegment = arena.allocate(valueBytes.length + 1);
      valueSegment.asByteBuffer().put(valueBytes).put((byte) 0);

      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, keySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UTF8_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, valueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, (long) valueBytes.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);

      return paramIndex + 1;
   }

   private static int addOctetParam(MemorySegment params, int paramIndex, String key, byte[] value, Arena arena) {
      byte[] keyBytes = key.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment keySegment = arena.allocate(keyBytes.length + 1);
      keySegment.asByteBuffer().put(keyBytes).put((byte) 0);

      MemorySegment valueSegment = arena.allocate(ValueLayout.JAVA_BYTE, value.length);
      valueSegment.asByteBuffer().put(value);

      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, keySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_OCTET_STRING);
      params.set(ValueLayout.ADDRESS, offset + 16, valueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, (long) value.length);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);

      return paramIndex + 1;
   }

   /**
    * Safely converts a size_t value (represented as long) to int.
    * Throws ArithmeticException if the value overflows int range.
    * This is used when allocating arrays from native size values.
    *
    * @param size the size value from native code (size_t as long)
    * @return the size as int
    * @throws ArithmeticException if size exceeds Integer.MAX_VALUE
    */
   public static int toIntSize(long size) {
      if (size < 0 || size > Integer.MAX_VALUE) {
         throw new ArithmeticException("Size value " + size + " exceeds int range");
      }
      return (int) size;
   }

   private static int addUIntParam(MemorySegment params, int paramIndex, String key, int value, Arena arena) {
      byte[] keyBytes = key.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      MemorySegment keySegment = arena.allocate(keyBytes.length + 1);
      keySegment.asByteBuffer().put(keyBytes).put((byte) 0);

      MemorySegment valueSegment = arena.allocate(ValueLayout.JAVA_INT);
      valueSegment.set(ValueLayout.JAVA_INT, 0, value);

      long offset = paramIndex * OSSL_PARAM_SIZE;
      params.set(ValueLayout.ADDRESS, offset, keySegment);
      params.set(ValueLayout.JAVA_INT, offset + 8, OSSL_PARAM_UNSIGNED_INTEGER);
      params.set(ValueLayout.ADDRESS, offset + 16, valueSegment);
      params.set(ValueLayout.JAVA_LONG, offset + 24, 4L);
      params.set(ValueLayout.JAVA_LONG, offset + 32, 0L);

      return paramIndex + 1;
   }
}
