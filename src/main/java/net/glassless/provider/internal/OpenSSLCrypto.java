package net.glassless.provider.internal;

import java.nio.charset.StandardCharsets;

import com.dylibso.chicory.runtime.Memory;

public class OpenSSLCrypto {

   private static OpenSSLCryptoModule_ModuleExports exports() {
      return OpenSSLCryptoModule.getInstance().exports();
   }

   public static Memory memory() {
      return OpenSSLCryptoModule.getInstance().memory();
   }

   // Memory management utilities

   public static int malloc(int size) {
      return exports().malloc(size);
   }

   public static void free(int ptr) {
      if (ptr != 0) {
         exports().free(ptr);
      }
   }

   public static int allocCString(String s) {
      byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
      int ptr = malloc(bytes.length + 1);
      memory().write(ptr, bytes);
      memory().writeByte(ptr + bytes.length, (byte) 0);
      return ptr;
   }

   public static int allocBytes(byte[] data) {
      int ptr = malloc(data.length);
      memory().write(ptr, data);
      return ptr;
   }

   // MessageDigest functions

   public static int getDigestHandle(String algorithmName) {
      int namePtr = allocCString(algorithmName);
      try {
         return exports().EVPGetDigestbyname(namePtr);
      } finally {
         free(namePtr);
      }
   }

   public static int EVP_MD_CTX_new() {
      return exports().EVPMDCTXNew();
   }

   public static void EVP_MD_CTX_free(int ctx) {
      exports().EVPMDCTXFree(ctx);
   }

   public static int EVP_DigestInit_ex(int ctx, int type) {
      return exports().EVPDigestInitEx(ctx, type, 0);
   }

   public static int EVP_DigestUpdate(int ctx, int d, int cnt) {
      return exports().EVPDigestUpdate(ctx, d, cnt);
   }

   public static int EVP_DigestFinal_ex(int ctx, int md, int s) {
      return exports().EVPDigestFinalEx(ctx, md, s);
   }

   public static int EVP_MD_size(int md) {
      return exports().EVPMDGetSize(md);
   }

   // Cipher functions

   public static int EVP_CIPHER_CTX_new() {
      return exports().EVPCIPHERCTXNew();
   }

   public static void EVP_CIPHER_CTX_free(int ctx) {
      exports().EVPCIPHERCTXFree(ctx);
   }

   public static int EVP_EncryptInit_ex(int ctx, int type, int impl, int key, int iv) {
      return exports().EVPEncryptInitEx(ctx, type, impl, key, iv);
   }

   public static int EVP_EncryptUpdate(int ctx, int out, int outlen, int in, int inlen) {
      return exports().EVPEncryptUpdate(ctx, out, outlen, in, inlen);
   }

   public static int EVP_EncryptFinal_ex(int ctx, int out, int outlen) {
      return exports().EVPEncryptFinalEx(ctx, out, outlen);
   }

   public static int EVP_DecryptInit_ex(int ctx, int type, int impl, int key, int iv) {
      return exports().EVPDecryptInitEx(ctx, type, impl, key, iv);
   }

   public static int EVP_DecryptUpdate(int ctx, int out, int outlen, int in, int inlen) {
      return exports().EVPDecryptUpdate(ctx, out, outlen, in, inlen);
   }

   public static int EVP_DecryptFinal_ex(int ctx, int out, int outlen) {
      return exports().EVPDecryptFinalEx(ctx, out, outlen);
   }

   public static int EVP_get_cipherbyname(String cipherName) {
      int namePtr = allocCString(cipherName);
      try {
         return exports().EVPGetCipherbyname(namePtr);
      } finally {
         free(namePtr);
      }
   }

   public static int EVP_CIPHER_CTX_ctrl(int ctx, int cmd, int larg, int parg) {
      return exports().EVPCIPHERCTXCtrl(ctx, cmd, larg, parg);
   }

   public static int EVP_CIPHER_CTX_set_padding(int ctx, int padding) {
      return EVP_CIPHER_CTX_ctrl(ctx, 9, padding, 0);
   }

   public static int EVP_CIPHER_get_iv_length(int cipher) {
      return exports().EVPCIPHERGetIvLength(cipher);
   }

   public static int EVP_CIPHER_get_key_length(int cipher) {
      return exports().EVPCIPHERGetKeyLength(cipher);
   }

   public static int EVP_CIPHER_get_block_size(int cipher) {
      return exports().EVPCIPHERGetBlockSize(cipher);
   }

   // PBKDF2

   public static byte[] PKCS5_PBKDF2_HMAC(char[] password, byte[] salt, int iterationCount,
                                           String digestName, int keyLength) {
      byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
      try {
         return PKCS5_PBKDF2_HMAC(passwordBytes, salt, iterationCount, digestName, keyLength);
      } finally {
         java.util.Arrays.fill(passwordBytes, (byte) 0);
      }
   }

   public static byte[] PKCS5_PBKDF2_HMAC(byte[] passwordBytes, byte[] salt, int iterationCount,
                                           String digestName, int keyLength) {
      int digestHandle = getDigestHandle(digestName);
      if (digestHandle == 0) {
         throw new IllegalArgumentException("Unknown digest: " + digestName);
      }

      int passPtr = allocBytes(passwordBytes);
      int saltPtr = allocBytes(salt);
      int outPtr = malloc(keyLength);
      try {
         int result = exports().PKCS5PBKDF2HMAC(passPtr, passwordBytes.length, saltPtr, salt.length,
               iterationCount, digestHandle, keyLength, outPtr);
         if (result != 1) {
            throw new IllegalStateException("PKCS5_PBKDF2_HMAC failed");
         }
         return memory().readBytes(outPtr, keyLength);
      } finally {
         free(passPtr);
         free(saltPtr);
         free(outPtr);
      }
   }

   // RSA constants
   public static final int RSA_PKCS1_PADDING = 1;
   public static final int RSA_NO_PADDING = 3;
   public static final int RSA_PKCS1_OAEP_PADDING = 4;
   public static final int RSA_PKCS1_PSS_PADDING = 6;
   public static final int EVP_PKEY_RSA = 6;

   public static int EVP_PKEY_CTX_new_from_pkey(int libctx, int pkey, int propq) {
      return exports().EVPPKEYCTXNewFromPkey(libctx, pkey, propq);
   }

   public static void EVP_PKEY_CTX_free(int ctx) {
      exports().EVPPKEYCTXFree(ctx);
   }

   public static int EVP_PKEY_encrypt_init(int ctx) {
      return exports().EVPPKEYEncryptInit(ctx);
   }

   public static int EVP_PKEY_encrypt(int ctx, int out, int outlen, int in, int inlen) {
      return exports().EVPPKEYEncrypt(ctx, out, outlen, in, inlen);
   }

   public static int EVP_PKEY_decrypt_init(int ctx) {
      return exports().EVPPKEYDecryptInit(ctx);
   }

   public static int EVP_PKEY_decrypt(int ctx, int out, int outlen, int in, int inlen) {
      return exports().EVPPKEYDecrypt(ctx, out, outlen, in, inlen);
   }

   public static int EVP_PKEY_CTX_set_rsa_padding(int ctx, int padding) {
      return exports().EVPPKEYCTXSetRsaPadding(ctx, padding);
   }

   public static int EVP_PKEY_CTX_set_rsa_oaep_md(int ctx, int md) {
      return exports().EVPPKEYCTXSetRsaOaepMd(ctx, md);
   }

   public static int EVP_PKEY_CTX_set_rsa_mgf1_md(int ctx, int md) {
      return exports().EVPPKEYCTXSetRsaMgf1Md(ctx, md);
   }

   public static int d2i_PrivateKey(int type, int a, int pp, int length) {
      return exports().d2iPrivateKey(type, a, pp, length);
   }

   public static int d2i_PUBKEY(int a, int pp, int length) {
      return exports().d2iPUBKEY(a, pp, length);
   }

   public static void EVP_PKEY_free(int pkey) {
      exports().EVPPKEYFree(pkey);
   }

   public static int EVP_PKEY_get_size(int pkey) {
      return exports().EVPPKEYGetSize(pkey);
   }

   // EVP_MAC wrapper methods

   public static int EVP_MAC_fetch(int libctx, String algorithm, int properties) {
      int algPtr = allocCString(algorithm);
      try {
         return exports().EVPMACFetch(libctx, algPtr, properties);
      } finally {
         free(algPtr);
      }
   }

   public static void EVP_MAC_free(int mac) {
      exports().EVPMACFree(mac);
   }

   public static int EVP_MAC_CTX_new(int mac) {
      return exports().EVPMACCTXNew(mac);
   }

   public static void EVP_MAC_CTX_free(int ctx) {
      exports().EVPMACCTXFree(ctx);
   }

   public static int EVP_MAC_init(int ctx, int key, int keylen, int params) {
      return exports().EVPMACInit(ctx, key, keylen, params);
   }

   public static int EVP_MAC_update(int ctx, int data, int datalen) {
      return exports().EVPMACUpdate(ctx, data, datalen);
   }

   public static int EVP_MAC_final(int ctx, int out, int outl, int outsize) {
      return exports().EVPMACFinal(ctx, out, outl, outsize);
   }

   public static int EVP_MAC_CTX_get_mac_size(int ctx) {
      return exports().EVPMACCTXGetMacSize(ctx);
   }

   // OSSL_PARAM construction using glassless wrappers

   public static int glasslessSizeofOSSLPARAM() {
      return exports().glasslessSizeofOSSLPARAM();
   }

   public static int createDigestParams(String digestName) {
      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * 2);
      int keyPtr = allocCString("digest");
      int valPtr = allocCString(digestName);
      exports().glasslessOSSLPARAMConstructUtf8String(params, keyPtr, valPtr, digestName.length());
      exports().glasslessOSSLPARAMConstructEnd(params + paramSize);
      return params;
      // Note: caller should free params, but keyPtr and valPtr must remain valid while params is in use
   }

   public static int createCipherParams(String cipherName) {
      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * 2);
      int keyPtr = allocCString("cipher");
      int valPtr = allocCString(cipherName);
      exports().glasslessOSSLPARAMConstructUtf8String(params, keyPtr, valPtr, cipherName.length());
      exports().glasslessOSSLPARAMConstructEnd(params + paramSize);
      return params;
      // Note: caller should free params, but keyPtr and valPtr must remain valid while params is in use
   }

   // Secure random

   public static byte[] RAND_bytes(int length) {
      int bufPtr = malloc(length);
      try {
         int result = exports().RANDBytes(bufPtr, length);
         if (result != 1) {
            throw new IllegalStateException("RAND_bytes failed");
         }
         return memory().readBytes(bufPtr, length);
      } finally {
         free(bufPtr);
      }
   }

   public static void RAND_seed(byte[] seed) {
      if (seed == null || seed.length == 0) {
         return;
      }
      int bufPtr = allocBytes(seed);
      try {
         exports().RANDSeed(bufPtr, seed.length);
      } finally {
         free(bufPtr);
      }
   }

   // Signature wrapper methods

   public static int EVP_DigestSignInit(int ctx, int pctx, int type, int engine, int pkey) {
      return exports().EVPDigestSignInit(ctx, pctx, type, engine, pkey);
   }

   public static int EVP_DigestSignUpdate(int ctx, int data, int datalen) {
      // EVP_DigestSignUpdate is a macro for EVP_DigestUpdate in OpenSSL 3.x
      return exports().EVPDigestUpdate(ctx, data, datalen);
   }

   public static int EVP_DigestSignFinal(int ctx, int sig, int siglen) {
      return exports().EVPDigestSignFinal(ctx, sig, siglen);
   }

   public static int EVP_DigestSign(int ctx, int sig, int siglen, int tbs, int tbslen) {
      return exports().EVPDigestSign(ctx, sig, siglen, tbs, tbslen);
   }

   public static int EVP_DigestVerifyInit(int ctx, int pctx, int type, int engine, int pkey) {
      return exports().EVPDigestVerifyInit(ctx, pctx, type, engine, pkey);
   }

   public static int EVP_DigestVerifyUpdate(int ctx, int data, int datalen) {
      // EVP_DigestVerifyUpdate is a macro for EVP_DigestUpdate in OpenSSL 3.x
      return exports().EVPDigestUpdate(ctx, data, datalen);
   }

   public static int EVP_DigestVerifyFinal(int ctx, int sig, int siglen) {
      return exports().EVPDigestVerifyFinal(ctx, sig, siglen);
   }

   public static int EVP_DigestVerify(int ctx, int sig, int siglen, int tbs, int tbslen) {
      return exports().EVPDigestVerify(ctx, sig, siglen, tbs, tbslen);
   }

   public static int EVP_PKEY_CTX_set_rsa_pss_saltlen(int ctx, int len) {
      return exports().EVPPKEYCTXSetRsaPssSaltlen(ctx, len);
   }

   // Constants for RSA-PSS salt length
   public static final int RSA_PSS_SALTLEN_DIGEST = -1;
   public static final int RSA_PSS_SALTLEN_MAX = -2;
   public static final int RSA_PSS_SALTLEN_AUTO = -3;

   // Key type constants
   public static final int EVP_PKEY_EC = 408;

   /**
    * Loads a private key from DER-encoded bytes.
    */
   public static int loadPrivateKey(int type, byte[] keyBytes) {
      int keyDataPtr = allocBytes(keyBytes);
      int keyPtrPtr = malloc(4);
      memory().writeI32(keyPtrPtr, keyDataPtr);
      try {
         int pkey = exports().d2iPrivateKeyEx(type, 0, keyPtrPtr, keyBytes.length, 0, 0);
         return pkey;
      } finally {
         free(keyPtrPtr);
         free(keyDataPtr);
      }
   }

   /**
    * Loads a public key from DER-encoded bytes (SubjectPublicKeyInfo format).
    */
   public static int loadPublicKey(byte[] keyBytes) {
      int keyDataPtr = allocBytes(keyBytes);
      int keyPtrPtr = malloc(4);
      memory().writeI32(keyPtrPtr, keyDataPtr);
      try {
         int pkey = exports().d2iPUBKEYEx(0, keyPtrPtr, keyBytes.length, 0, 0);
         return pkey;
      } finally {
         free(keyPtrPtr);
         free(keyDataPtr);
      }
   }

   // Key pair generation

   public static int EVP_PKEY_CTX_new_from_name(int libctx, String name, int propquery) {
      int namePtr = allocCString(name);
      try {
         return exports().EVPPKEYCTXNewFromName(libctx, namePtr, propquery);
      } finally {
         free(namePtr);
      }
   }

   public static int EVP_PKEY_keygen_init(int ctx) {
      return exports().EVPPKEYKeygenInit(ctx);
   }

   public static int EVP_PKEY_keygen(int ctx, int ppkey) {
      return exports().EVPPKEYKeygen(ctx, ppkey);
   }

   public static int EVP_PKEY_CTX_set_rsa_keygen_bits(int ctx, int bits) {
      return exports().EVPPKEYCTXSetRsaKeygenBits(ctx, bits);
   }

   public static int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(int ctx, int nid) {
      return exports().EVPPKEYCTXSetEcParamgenCurveNid(ctx, nid);
   }

   public static int i2d_PrivateKey(int pkey, int pp) {
      return exports().i2dPrivateKey(pkey, pp);
   }

   public static int i2d_PUBKEY(int pkey, int pp) {
      return exports().i2dPUBKEY(pkey, pp);
   }

   public static int OBJ_txt2nid(String txt) {
      int txtPtr = allocCString(txt);
      try {
         return exports().OBJTxt2nid(txtPtr);
      } finally {
         free(txtPtr);
      }
   }

   public static int OBJ_sn2nid(String sn) {
      int snPtr = allocCString(sn);
      try {
         return exports().OBJSn2nid(snPtr);
      } finally {
         free(snPtr);
      }
   }

   // Common EC curve NIDs
   public static final int NID_X9_62_prime256v1 = 415;
   public static final int NID_secp384r1 = 715;
   public static final int NID_secp521r1 = 716;
   public static final int NID_secp256k1 = 714;

   public static int EVP_PKEY2PKCS8(int pkey) {
      return exports().EVPPKEY2PKCS8(pkey);
   }

   public static void PKCS8_PRIV_KEY_INFO_free(int p8) {
      exports().PKCS8PRIVKEYINFOFree(p8);
   }

   public static int i2d_PKCS8_PRIV_KEY_INFO(int p8, int pp) {
      return exports().i2dPKCS8PRIVKEYINFO(p8, pp);
   }

   /**
    * Exports an EVP_PKEY to DER-encoded PKCS#8 private key bytes.
    */
   public static byte[] exportPrivateKey(int pkey) {
      int p8 = EVP_PKEY2PKCS8(pkey);
      if (p8 == 0) {
         throw new IllegalStateException("Failed to convert private key to PKCS8");
      }

      try {
         int len = i2d_PKCS8_PRIV_KEY_INFO(p8, 0);
         if (len <= 0) {
            throw new IllegalStateException("Failed to get PKCS8 private key length");
         }

         int buffer = malloc(len);
         int bufferPtr = malloc(4);
         memory().writeI32(bufferPtr, buffer);
         try {
            int written = i2d_PKCS8_PRIV_KEY_INFO(p8, bufferPtr);
            if (written <= 0) {
               throw new IllegalStateException("Failed to export PKCS8 private key");
            }
            return memory().readBytes(buffer, written);
         } finally {
            free(buffer);
            free(bufferPtr);
         }
      } finally {
         PKCS8_PRIV_KEY_INFO_free(p8);
      }
   }

   /**
    * Exports an EVP_PKEY to DER-encoded public key bytes (SubjectPublicKeyInfo format).
    */
   public static byte[] exportPublicKey(int pkey) {
      int len = i2d_PUBKEY(pkey, 0);
      if (len <= 0) {
         throw new IllegalStateException("Failed to get public key length");
      }

      int buffer = malloc(len);
      int bufferPtr = malloc(4);
      memory().writeI32(bufferPtr, buffer);
      try {
         int written = i2d_PUBKEY(pkey, bufferPtr);
         if (written <= 0) {
            throw new IllegalStateException("Failed to export public key");
         }
         return memory().readBytes(buffer, written);
      } finally {
         free(buffer);
         free(bufferPtr);
      }
   }

   /**
    * Exports an EVP_PKEY to raw public key bytes.
    */
   public static byte[] exportRawPublicKey(int pkey) {
      // First call to get the length
      int lenPtr = malloc(4);
      try {
         memory().writeI32(lenPtr, 0);
         int result = exports().EVPPKEYGetRawPublicKey(pkey, 0, lenPtr);
         if (result != 1) {
            throw new IllegalStateException("Failed to get raw public key length");
         }

         int len = memory().readInt(lenPtr);
         int buffer = malloc(len);
         try {
            memory().writeI32(lenPtr, len);
            result = exports().EVPPKEYGetRawPublicKey(pkey, buffer, lenPtr);
            if (result != 1) {
               throw new IllegalStateException("Failed to export raw public key");
            }
            int actualLen = memory().readInt(lenPtr);
            return memory().readBytes(buffer, actualLen);
         } finally {
            free(buffer);
         }
      } finally {
         free(lenPtr);
      }
   }

   /**
    * Exports an EVP_PKEY to raw private key bytes.
    */
   public static byte[] exportRawPrivateKey(int pkey) {
      int lenPtr = malloc(4);
      try {
         memory().writeI32(lenPtr, 0);
         int result = exports().EVPPKEYGetRawPrivateKey(pkey, 0, lenPtr);
         if (result != 1) {
            throw new IllegalStateException("Failed to get raw private key length");
         }

         int len = memory().readInt(lenPtr);
         int buffer = malloc(len);
         try {
            memory().writeI32(lenPtr, len);
            result = exports().EVPPKEYGetRawPrivateKey(pkey, buffer, lenPtr);
            if (result != 1) {
               throw new IllegalStateException("Failed to export raw private key");
            }
            int actualLen = memory().readInt(lenPtr);
            return memory().readBytes(buffer, actualLen);
         } finally {
            free(buffer);
         }
      } finally {
         free(lenPtr);
      }
   }

   /**
    * Loads a raw public key from bytes.
    */
   public static int loadRawPublicKey(String keytype, byte[] keyBytes) {
      int keytypePtr = allocCString(keytype);
      int keyBuffer = allocBytes(keyBytes);
      try {
         int pkey = exports().EVPPKEYNewRawPublicKeyEx(0, keytypePtr, 0, keyBuffer, keyBytes.length);
         if (pkey == 0) {
            throw new IllegalStateException("Failed to load raw public key for " + keytype);
         }
         return pkey;
      } finally {
         free(keytypePtr);
         free(keyBuffer);
      }
   }

   /**
    * Loads a raw private key from bytes.
    */
   public static int loadRawPrivateKey(String keytype, byte[] keyBytes) {
      int keytypePtr = allocCString(keytype);
      int keyBuffer = allocBytes(keyBytes);
      try {
         int pkey = exports().EVPPKEYNewRawPrivateKeyEx(0, keytypePtr, 0, keyBuffer, keyBytes.length);
         if (pkey == 0) {
            throw new IllegalStateException("Failed to load raw private key for " + keytype);
         }
         return pkey;
      } finally {
         free(keytypePtr);
         free(keyBuffer);
      }
   }

   public static boolean isRawKeyAvailable() {
      return true; // always available in WASM build
   }

   // Key agreement wrapper methods

   public static int EVP_PKEY_derive_init(int ctx) {
      return exports().EVPPKEYDeriveInit(ctx);
   }

   public static int EVP_PKEY_derive_set_peer(int ctx, int peer) {
      return exports().EVPPKEYDeriveSetPeer(ctx, peer);
   }

   public static int EVP_PKEY_derive(int ctx, int key, int keylen) {
      return exports().EVPPKEYDerive(ctx, key, keylen);
   }

   /**
    * Derives a shared secret using key agreement.
    */
   public static byte[] deriveSharedSecret(int privateKey, int publicKey) {
      int ctx = EVP_PKEY_CTX_new_from_pkey(0, privateKey, 0);
      if (ctx == 0) {
         throw new IllegalStateException("Failed to create EVP_PKEY_CTX for key agreement");
      }

      try {
         int result = EVP_PKEY_derive_init(ctx);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive_init failed");
         }

         result = EVP_PKEY_derive_set_peer(ctx, publicKey);
         if (result <= 0) {
            throw new IllegalStateException("EVP_PKEY_derive_set_peer failed");
         }

         // Get the required buffer length
         int secretLenPtr = malloc(4);
         try {
            memory().writeI32(secretLenPtr, 0);
            result = EVP_PKEY_derive(ctx, 0, secretLenPtr);
            if (result <= 0) {
               throw new IllegalStateException("EVP_PKEY_derive (get length) failed");
            }

            int secretLen = memory().readInt(secretLenPtr);
            int secretBuffer = malloc(secretLen);
            try {
               memory().writeI32(secretLenPtr, secretLen);
               result = EVP_PKEY_derive(ctx, secretBuffer, secretLenPtr);
               if (result <= 0) {
                  throw new IllegalStateException("EVP_PKEY_derive failed");
               }
               int actualLen = memory().readInt(secretLenPtr);
               return memory().readBytes(secretBuffer, actualLen);
            } finally {
               free(secretBuffer);
            }
         } finally {
            free(secretLenPtr);
         }
      } finally {
         EVP_PKEY_CTX_free(ctx);
      }
   }

   // DSA/DH key generation

   public static int EVP_PKEY_CTX_set_dsa_paramgen_bits(int ctx, int bits) {
      return exports().EVPPKEYCTXSetDsaParamgenBits(ctx, bits);
   }

   public static int EVP_PKEY_CTX_set_dh_paramgen_prime_len(int ctx, int len) {
      return exports().EVPPKEYCTXSetDhParamgenPrimeLen(ctx, len);
   }

   public static int EVP_PKEY_paramgen_init(int ctx) {
      return exports().EVPPKEYParamgenInit(ctx);
   }

   public static int EVP_PKEY_paramgen(int ctx, int ppkey) {
      return exports().EVPPKEYParamgen(ctx, ppkey);
   }

   public static int EVP_PKEY_CTX_set_dsa_paramgen_q_bits(int ctx, int qbits) {
      return exports().EVPPKEYCTXSetDsaParamgenQBits(ctx, qbits);
   }

   public static int EVP_PKEY_CTX_set_dh_paramgen_generator(int ctx, int gen) {
      return exports().EVPPKEYCTXSetDhParamgenGenerator(ctx, gen);
   }

   /**
    * Extracts a BigInteger parameter from an EVP_PKEY.
    */
   public static java.math.BigInteger EVP_PKEY_get_bn_param(int pkey, String paramName) {
      int bnPtr = malloc(4);
      int namePtr = allocCString(paramName);
      try {
         memory().writeI32(bnPtr, 0);
         int result = exports().EVPPKEYGetBnParam(pkey, namePtr, bnPtr);
         if (result != 1) {
            throw new IllegalStateException("EVP_PKEY_get_bn_param failed for: " + paramName);
         }

         int bn = memory().readInt(bnPtr);
         if (bn == 0) {
            throw new IllegalStateException("BIGNUM is null for: " + paramName);
         }

         try {
            int numBits = exports().BNNumBits(bn);
            int numBytes = (numBits + 7) / 8;

            if (numBytes == 0) {
               return java.math.BigInteger.ZERO;
            }

            int buffer = malloc(numBytes);
            try {
               int written = exports().BNBn2bin(bn, buffer);
               if (written != numBytes) {
                  throw new IllegalStateException("BN_bn2bin returned unexpected length");
               }

               byte[] bytes = memory().readBytes(buffer, numBytes);
               if (bytes.length > 0 && (bytes[0] & 0x80) != 0) {
                  byte[] tmp = new byte[bytes.length + 1];
                  System.arraycopy(bytes, 0, tmp, 1, bytes.length);
                  bytes = tmp;
               }
               return new java.math.BigInteger(bytes);
            } finally {
               free(buffer);
            }
         } finally {
            exports().BNFree(bn);
         }
      } finally {
         free(bnPtr);
         free(namePtr);
      }
   }

   public static void BN_free(int bn) {
      exports().BNFree(bn);
   }

   // EVP_KDF wrapper methods

   public static int EVP_KDF_fetch(int libctx, String algorithm, int properties) {
      int algPtr = allocCString(algorithm);
      try {
         return exports().EVPKDFFetch(libctx, algPtr, properties);
      } finally {
         free(algPtr);
      }
   }

   public static void EVP_KDF_free(int kdf) {
      exports().EVPKDFFree(kdf);
   }

   public static int EVP_KDF_CTX_new(int kdf) {
      return exports().EVPKDFCTXNew(kdf);
   }

   public static void EVP_KDF_CTX_free(int ctx) {
      exports().EVPKDFCTXFree(ctx);
   }

   public static int EVP_KDF_derive(int ctx, int key, int keylen, int params) {
      return exports().EVPKDFDerive(ctx, key, keylen, params);
   }

   // FIPS detection

   public static boolean isFIPSEnabled() {
      try {
         int result = exports().EVPDefaultPropertiesIsFipsEnabled(0);
         return result == 1;
      } catch (Exception e) {
         return false;
      }
   }

   public static boolean isProviderAvailable(String providerName) {
      int namePtr = allocCString(providerName);
      try {
         int result = exports().OSSLPROVIDERAvailable(0, namePtr);
         return result == 1;
      } catch (Exception e) {
         return false;
      } finally {
         free(namePtr);
      }
   }

   public static boolean isFIPSProviderAvailable() {
      return isProviderAvailable("fips");
   }

   // OpenSSL version
   private static final int OPENSSL_VERSION = 0;

   public static boolean isAlgorithmAvailable(String type, String name) {
      try {
         return switch (type.toUpperCase()) {
            case "MD", "DIGEST" -> {
               int md = getDigestHandle(name);
               yield md != 0;
            }
            case "CIPHER" -> {
               int cipher = EVP_get_cipherbyname(name);
               yield cipher != 0;
            }
            case "MAC" -> {
               int mac = EVP_MAC_fetch(0, name, 0);
               if (mac != 0) {
                  EVP_MAC_free(mac);
                  yield true;
               }
               yield false;
            }
            case "KDF" -> {
               int kdf = EVP_KDF_fetch(0, name, 0);
               if (kdf != 0) {
                  EVP_KDF_free(kdf);
                  yield true;
               }
               yield false;
            }
            case "KEYMGMT" -> {
               int keymgmt = EVP_KEYMGMT_fetch(0, name, 0);
               if (keymgmt != 0) {
                  EVP_KEYMGMT_free(keymgmt);
                  yield true;
               }
               yield false;
            }
            default -> false;
         };
      } catch (Exception e) {
         return false;
      }
   }

   // KEM wrapper methods

   public static boolean isKEMAvailable() {
      return true; // always available in WASM build
   }

   public static int EVP_PKEY_encapsulate_init(int ctx, int params) {
      return exports().EVPPKEYEncapsulateInit(ctx, params);
   }

   public static int EVP_PKEY_encapsulate(int ctx, int wrappedKey, int wrappedKeyLen,
                                          int genKey, int genKeyLen) {
      return exports().EVPPKEYEncapsulate(ctx, wrappedKey, wrappedKeyLen, genKey, genKeyLen);
   }

   public static int EVP_PKEY_decapsulate_init(int ctx, int params) {
      return exports().EVPPKEYDecapsulateInit(ctx, params);
   }

   public static int EVP_PKEY_decapsulate(int ctx, int unwrapped, int unwrappedLen,
                                          int wrapped, int wrappedLen) {
      return exports().EVPPKEYDecapsulate(ctx, unwrapped, unwrappedLen, wrapped, wrappedLen);
   }

   public static int EVP_KEYMGMT_fetch(int libctx, String algorithm, int properties) {
      int algPtr = allocCString(algorithm);
      try {
         return exports().EVPKEYMGMTFetch(libctx, algPtr, properties);
      } finally {
         free(algPtr);
      }
   }

   public static void EVP_KEYMGMT_free(int keymgmt) {
      if (keymgmt != 0) {
         exports().EVPKEYMGMTFree(keymgmt);
      }
   }

   public static String getOpenSSLVersion() {
      try {
         int resultPtr = exports().OpenSSLVersion(OPENSSL_VERSION);
         if (resultPtr == 0) {
            return "Unknown";
         }
         // Read null-terminated C string from WASM memory
         byte[] buf = memory().readBytes(resultPtr, 256);
         int len = 0;
         while (len < buf.length && buf[len] != 0) len++;
         return new String(buf, 0, len, StandardCharsets.UTF_8);
      } catch (Exception e) {
         return "Unknown";
      }
   }

   // HKDF mode constants
   public static final int HKDF_MODE_EXTRACT_AND_EXPAND = 0;
   public static final int HKDF_MODE_EXTRACT_ONLY = 1;
   public static final int HKDF_MODE_EXPAND_ONLY = 2;

   // OSSL_PARAM types
   public static final int OSSL_PARAM_OCTET_STRING = 5;
   public static final int OSSL_PARAM_UNSIGNED_INTEGER = 1;
   public static final int OSSL_PARAM_UTF8_STRING = 4;

   // OSSL_PARAM construction helpers using glassless wrappers

   private static int addUtf8Param(int params, int paramIndex, String key, String value) {
      int paramSize = glasslessSizeofOSSLPARAM();
      int keyPtr = allocCString(key);
      int valPtr = allocCString(value);
      exports().glasslessOSSLPARAMConstructUtf8String(params + paramIndex * paramSize, keyPtr, valPtr, value.length());
      return paramIndex + 1;
      // Note: keyPtr and valPtr must remain valid while params is in use
   }

   private static int addOctetParam(int params, int paramIndex, String key, byte[] value) {
      int paramSize = glasslessSizeofOSSLPARAM();
      int keyPtr = allocCString(key);
      int valPtr = allocBytes(value);
      exports().glasslessOSSLPARAMConstructOctetString(params + paramIndex * paramSize, keyPtr, valPtr, value.length);
      return paramIndex + 1;
   }

   private static int addUIntParam(int params, int paramIndex, String key, int value) {
      int paramSize = glasslessSizeofOSSLPARAM();
      int keyPtr = allocCString(key);
      int valPtr = malloc(4);
      memory().writeI32(valPtr, value);
      exports().glasslessOSSLPARAMConstructUint(params + paramIndex * paramSize, keyPtr, valPtr);
      return paramIndex + 1;
   }

   private static void addEndParam(int params, int paramIndex) {
      int paramSize = glasslessSizeofOSSLPARAM();
      exports().glasslessOSSLPARAMConstructEnd(params + paramIndex * paramSize);
   }

   /**
    * Creates an OSSL_PARAM array for HKDF operations.
    */
   public static int createHKDFParams(String digestName, int mode, byte[] salt, byte[] key, byte[] info) {
      int numParams = 3;
      if (salt != null && salt.length > 0) numParams++;
      if (info != null && info.length > 0) numParams++;
      numParams++;

      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addUIntParam(params, paramIndex, "mode", mode);
      paramIndex = addOctetParam(params, paramIndex, "key", key);

      if (salt != null && salt.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "salt", salt);
      }

      if (info != null && info.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "info", info);
      }

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for SCRYPT operations.
    */
   public static int createScryptParams(byte[] password, byte[] salt, long n, int r, int p) {
      int numParams = 6;
      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addOctetParam(params, paramIndex, "pass", password);
      paramIndex = addOctetParam(params, paramIndex, "salt", salt);
      paramIndex = addUIntParam(params, paramIndex, "n", (int) n);
      paramIndex = addUIntParam(params, paramIndex, "r", r);
      paramIndex = addUIntParam(params, paramIndex, "p", p);

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for Argon2 operations.
    */
   public static int createArgon2Params(byte[] password, byte[] salt, int iterations,
         int memoryKB, int parallelism, byte[] ad, byte[] secret) {
      int numParams = 5;
      if (ad != null && ad.length > 0) numParams++;
      if (secret != null && secret.length > 0) numParams++;
      numParams++;

      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addOctetParam(params, paramIndex, "pass", password);
      paramIndex = addOctetParam(params, paramIndex, "salt", salt);
      paramIndex = addUIntParam(params, paramIndex, "iter", iterations);
      paramIndex = addUIntParam(params, paramIndex, "memcost", memoryKB);
      paramIndex = addUIntParam(params, paramIndex, "lanes", parallelism);

      if (ad != null && ad.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "ad", ad);
      }

      if (secret != null && secret.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "secret", secret);
      }

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for X9.63 KDF operations.
    */
   public static int createX963KDFParams(String digestName, byte[] secret, byte[] info) {
      int numParams = 2;
      if (info != null && info.length > 0) numParams++;
      numParams++;

      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addOctetParam(params, paramIndex, "key", secret);

      if (info != null && info.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "info", info);
      }

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for SSH KDF operations.
    */
   public static int createSSHKDFParams(String digestName, byte[] key, byte[] xcghash,
         byte[] sessionId, char keyType) {
      int numParams = 6;
      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addOctetParam(params, paramIndex, "key", key);
      paramIndex = addOctetParam(params, paramIndex, "xcghash", xcghash);
      paramIndex = addOctetParam(params, paramIndex, "session_id", sessionId);
      paramIndex = addUtf8Param(params, paramIndex, "type", String.valueOf(keyType));

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for KBKDF (SP 800-108) operations.
    */
   public static int createKBKDFParams(String macName, String digestName, byte[] key,
         byte[] salt, byte[] info, String mode) {
      int numParams = 4;
      if (salt != null && salt.length > 0) numParams++;
      if (info != null && info.length > 0) numParams++;
      numParams++;

      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "mac", macName);
      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addOctetParam(params, paramIndex, "key", key);
      paramIndex = addUtf8Param(params, paramIndex, "mode", mode);

      if (salt != null && salt.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "salt", salt);
      }

      if (info != null && info.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "info", info);
      }

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for TLS1-PRF operations.
    */
   public static int createTLSPRFParams(String digestName, byte[] secret, byte[] seed) {
      int numParams = 4;
      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addOctetParam(params, paramIndex, "secret", secret);
      paramIndex = addOctetParam(params, paramIndex, "seed", seed);

      addEndParam(params, paramIndex);
      return params;
   }

   /**
    * Creates an OSSL_PARAM array for TLS 1.3 KDF operations.
    */
   public static int createTLS13KDFParams(String digestName, String mode,
         byte[] key, byte[] salt, byte[] prefix, byte[] label, byte[] data) {
      int numParams = 3;
      if (salt != null && salt.length > 0) numParams++;
      if (prefix != null && prefix.length > 0) numParams++;
      if (label != null && label.length > 0) numParams++;
      if (data != null) numParams++;
      numParams++;

      int paramSize = glasslessSizeofOSSLPARAM();
      int params = malloc(paramSize * numParams);
      int paramIndex = 0;

      paramIndex = addUtf8Param(params, paramIndex, "digest", digestName);
      paramIndex = addUtf8Param(params, paramIndex, "mode", mode);
      paramIndex = addOctetParam(params, paramIndex, "key", key);

      if (salt != null && salt.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "salt", salt);
      }

      if (prefix != null && prefix.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "prefix", prefix);
      }

      if (label != null && label.length > 0) {
         paramIndex = addOctetParam(params, paramIndex, "label", label);
      }

      if (data != null) {
         paramIndex = addOctetParam(params, paramIndex, "data", data);
      }

      addEndParam(params, paramIndex);
      return params;
   }
}
