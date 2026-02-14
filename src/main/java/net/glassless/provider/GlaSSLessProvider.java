package net.glassless.provider;

import java.security.Provider;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import net.glassless.provider.internal.OpenSSLCrypto;
import net.glassless.provider.internal.cipher.*;
import net.glassless.provider.internal.digest.*;
import net.glassless.provider.internal.keyagreement.*;
import net.glassless.provider.internal.keyfactory.*;
import net.glassless.provider.internal.keygen.*;
import net.glassless.provider.internal.keypairgen.*;
import net.glassless.provider.internal.mac.*;
import net.glassless.provider.internal.mldsa.*;
import net.glassless.provider.internal.mlkem.*;
import net.glassless.provider.internal.secretkeyfactory.*;
import net.glassless.provider.internal.signature.*;
import net.glassless.provider.internal.slhdsa.*;

/**
 * OpenSSL-based JCA Provider using Java's Foreign Function &amp; Memory API.
 *
 * <p>When FIPS mode is detected (via {@link FIPSStatus}), only FIPS 140-2/140-3
 * approved algorithms are registered. Non-approved algorithms such as MD5,
 * DES/3DES, ChaCha20-Poly1305, and SCRYPT are excluded in FIPS mode.
 *
 * <p>Note that some algorithms may have runtime restrictions in FIPS mode
 * (e.g., minimum RSA key sizes) that are enforced by OpenSSL.
 */
public class GlaSSLessProvider extends Provider {

   public static final String PROVIDER_NAME = "GlaSSLess";

   public static final String MESSAGE_DIGEST = "MessageDigest";
   public static final String CIPHER = "Cipher";
   public static final String KEY_FACTORY = "KeyFactory";
   public static final String SIGNATURE = "Signature";
   public static final String MAC = "Mac";
   public static final String KEY_GENERATOR = "KeyGenerator";
   public static final String ALGORITHM_PARAMETERS = "AlgorithmParameters";
   public static final String KEY_PAIR_GENERATOR = "KeyPairGenerator";
   public static final String SECRET_KEY_FACTORY = "SecretKeyFactory";
   public static final String ALGORITHM_PARAMETER_GENERATOR = "AlgorithmParameterGenerator";
   public static final String KEY_AGREEMENT = "KeyAgreement";
   public static final String SECURE_RANDOM = "SecureRandom";
   public static final String KDF = "KDF";
   public static final String KEM = "KEM";

   private final boolean fipsMode;

   public GlaSSLessProvider() {
      super(PROVIDER_NAME, "0.1", "OpenSSL Native Provider using FFM API");

      this.fipsMode = FIPSStatus.isFIPSEnabled();

      registerMessageDigestServices();
      registerCipherServices();
      registerMacServices();
      registerKeyGeneratorServices();
      registerSignatureServices();
      registerKeyPairGeneratorServices();
      registerSecretKeyFactoryServices();
      registerKeyFactoryServices();
      registerKeyAgreementServices();
      registerAlgorithmParametersServices();
      registerSecureRandomServices();
      registerAlgorithmParameterGeneratorServices();
      registerKDFServices();
      registerKEMServices();
   }

   /**
    * Returns whether this provider instance is running in FIPS mode.
    *
    * @return true if FIPS mode is enabled
    */
   public boolean isFIPSMode() {
      return fipsMode;
   }

   private void registerMessageDigestServices() {
      // FIPS-approved: SHA-2 family, SHA-3 family
      // NOT FIPS-approved: MD5, SHA-1 (deprecated for most uses)

      if (!fipsMode) {
         // MD5 - NOT FIPS approved
         putService(new Service(this, MESSAGE_DIGEST, "MD5", MD5Digest.class.getName(),
            List.of("OID.1.2.840.113549.2.5", "1.2.840.113549.2.5"), null));
         // SHA-1 - Deprecated in FIPS, allowed only for legacy compatibility
         putService(new Service(this, MESSAGE_DIGEST, "SHA-1", SHA1Digest.class.getName(),
            List.of("SHA1", "OID.1.3.14.3.2.26", "1.3.14.3.2.26"), null));
      }

      // SHA-2 family - FIPS approved
      putService(new Service(this, MESSAGE_DIGEST, "SHA-224", SHA_224Digest.class.getName(),
         List.of("SHA224", "OID.2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA-256", SHA_256Digest.class.getName(),
         List.of("SHA256", "OID.2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.1"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA-384", SHA_384Digest.class.getName(),
         List.of("SHA384", "OID.2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.2"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA-512", SHA_512Digest.class.getName(),
         List.of("SHA512", "OID.2.16.840.1.101.3.4.2.3", "2.16.840.1.101.3.4.2.3"), null));

      // SHA-3 family - FIPS approved
      putService(new Service(this, MESSAGE_DIGEST, "SHA3-224", SHA3_224Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.7"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA3-256", SHA3_256Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.8"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA3-384", SHA3_384Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.9"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA3-512", SHA3_512Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.2.10"), null));

      // SHA-512 truncated variants - FIPS approved
      putService(new Service(this, MESSAGE_DIGEST, "SHA-512/224", SHA512_224Digest.class.getName(),
         List.of("SHA512/224", "OID.2.16.840.1.101.3.4.2.5", "2.16.840.1.101.3.4.2.5"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHA-512/256", SHA512_256Digest.class.getName(),
         List.of("SHA512/256", "OID.2.16.840.1.101.3.4.2.6", "2.16.840.1.101.3.4.2.6"), null));

      // SHAKE XOFs - FIPS approved
      putService(new Service(this, MESSAGE_DIGEST, "SHAKE128", SHAKE128Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.11", "2.16.840.1.101.3.4.2.11"), null));
      putService(new Service(this, MESSAGE_DIGEST, "SHAKE256", SHAKE256Digest.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.12", "2.16.840.1.101.3.4.2.12"), null));

      // BLAKE2 - FIPS approved (in some contexts)
      if (OpenSSLCrypto.isAlgorithmAvailable("MD", "blake2b512")) {
         putService(new Service(this, MESSAGE_DIGEST, "BLAKE2b-512", BLAKE2b512Digest.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("MD", "blake2s256")) {
         putService(new Service(this, MESSAGE_DIGEST, "BLAKE2s-256", BLAKE2s256Digest.class.getName(), null, null));
      }

      if (!fipsMode) {
         // SM3 - Chinese standard, NOT FIPS approved
         if (OpenSSLCrypto.isAlgorithmAvailable("MD", "sm3")) {
            putService(new Service(this, MESSAGE_DIGEST, "SM3", SM3Digest.class.getName(),
               List.of("OID.1.2.156.10197.1.401", "1.2.156.10197.1.401"), null));
         }
         // RIPEMD-160 - NOT FIPS approved
         if (OpenSSLCrypto.isAlgorithmAvailable("MD", "ripemd160")) {
            putService(new Service(this, MESSAGE_DIGEST, "RIPEMD160", RIPEMD160Digest.class.getName(),
               List.of("RIPEMD-160", "OID.1.3.36.3.2.1", "1.3.36.3.2.1"), null));
         }
      }
   }

   private void registerCipherServices() {
      // FIPS-approved: AES (all key sizes), RSA
      // NOT FIPS-approved: DESede (3DES), ChaCha20-Poly1305

      // AES-128 - FIPS approved
      putService(new Service(this, CIPHER, "AES_128/ECB/NoPadding", AES_128EcbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.1", "2.16.840.1.101.3.4.1.1"), null));
      putService(new Service(this, CIPHER, "AES_128/ECB/PKCS5Padding", AES_128EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/CBC/NoPadding", AES_128CbcNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2"), null));
      putService(new Service(this, CIPHER, "AES_128/CBC/PKCS5Padding", AES_128CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/CFB/NoPadding", AES_128CfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4"), null));
      putService(new Service(this, CIPHER, "AES_128/CFB/PKCS5Padding", AES_128CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/CTR/NoPadding", AES_128CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/CTR/PKCS5Padding", AES_128CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/GCM/NoPadding", AES_128GcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6"), null));
      putService(new Service(this, CIPHER, "AES_128/GCM/PKCS5Padding", AES_128GcmPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_128/OFB/NoPadding", AES_128OfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3"), null));
      putService(new Service(this, CIPHER, "AES_128/OFB/PKCS5Padding", AES_128OfbPKCS5PaddingCipher.class.getName(), null, null));

      // AES-192 - FIPS approved
      putService(new Service(this, CIPHER, "AES_192/ECB/NoPadding", AES_192EcbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.21", "2.16.840.1.101.3.4.1.21"), null));
      putService(new Service(this, CIPHER, "AES_192/ECB/PKCS5Padding", AES_192EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/CBC/NoPadding", AES_192CbcNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22"), null));
      putService(new Service(this, CIPHER, "AES_192/CBC/PKCS5Padding", AES_192CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/CFB/NoPadding", AES_192CfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24"), null));
      putService(new Service(this, CIPHER, "AES_192/CFB/PKCS5Padding", AES_192CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/CTR/NoPadding", AES_192CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/CTR/PKCS5Padding", AES_192CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/GCM/NoPadding", AES_192GcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26"), null));
      putService(new Service(this, CIPHER, "AES_192/GCM/PKCS5Padding", AES_192GcmPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_192/OFB/NoPadding", AES_192OfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23"), null));
      putService(new Service(this, CIPHER, "AES_192/OFB/PKCS5Padding", AES_192OfbPKCS5PaddingCipher.class.getName(), null, null));

      // AES-256 - FIPS approved
      putService(new Service(this, CIPHER, "AES_256/ECB/NoPadding", AES_256EcbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.41", "2.16.840.1.101.3.4.1.41"), null));
      putService(new Service(this, CIPHER, "AES_256/ECB/PKCS5Padding", AES_256EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/CBC/NoPadding", AES_256CbcNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42"), null));
      putService(new Service(this, CIPHER, "AES_256/CBC/PKCS5Padding", AES_256CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/CFB/NoPadding", AES_256CfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44"), null));
      putService(new Service(this, CIPHER, "AES_256/CFB/PKCS5Padding", AES_256CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/CTR/NoPadding", AES_256CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/CTR/PKCS5Padding", AES_256CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/GCM/NoPadding", AES_256GcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46"), null));
      putService(new Service(this, CIPHER, "AES_256/GCM/PKCS5Padding", AES_256GcmPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "AES_256/OFB/NoPadding", AES_256OfbNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43"), null));
      putService(new Service(this, CIPHER, "AES_256/OFB/PKCS5Padding", AES_256OfbPKCS5PaddingCipher.class.getName(), null, null));

      // AES-CCM - FIPS approved
      putService(new Service(this, CIPHER, "AES_128/CCM/NoPadding", AES_128CcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.7", "2.16.840.1.101.3.4.1.7"), null));
      putService(new Service(this, CIPHER, "AES_192/CCM/NoPadding", AES_192CcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.27", "2.16.840.1.101.3.4.1.27"), null));
      putService(new Service(this, CIPHER, "AES_256/CCM/NoPadding", AES_256CcmNoPaddingCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.47", "2.16.840.1.101.3.4.1.47"), null));

      // AES-XTS - FIPS approved (for storage encryption)
      putService(new Service(this, CIPHER, "AES_128/XTS/NoPadding", AES_128XtsNoPaddingCipher.class.getName(),
         List.of("OID.1.3.111.2.1619.0.1.1", "1.3.111.2.1619.0.1.1"), null));
      putService(new Service(this, CIPHER, "AES_256/XTS/NoPadding", AES_256XtsNoPaddingCipher.class.getName(),
         List.of("OID.1.3.111.2.1619.0.1.2", "1.3.111.2.1619.0.1.2"), null));

      // AES Key Wrap - FIPS approved
      putService(new Service(this, CIPHER, "AESWrap_128", AES_128WrapCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.5"), null));
      putService(new Service(this, CIPHER, "AESWrap_192", AES_192WrapCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.25"), null));
      putService(new Service(this, CIPHER, "AESWrap_256", AES_256WrapCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.45", "2.16.840.1.101.3.4.1.45"), null));
      putService(new Service(this, CIPHER, "AESWrapPad_128", AES_128WrapPadCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.8", "2.16.840.1.101.3.4.1.8"), null));
      putService(new Service(this, CIPHER, "AESWrapPad_192", AES_192WrapPadCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.28", "2.16.840.1.101.3.4.1.28"), null));
      putService(new Service(this, CIPHER, "AESWrapPad_256", AES_256WrapPadCipher.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.1.48", "2.16.840.1.101.3.4.1.48"), null));

      // PBE Ciphers - FIPS approved (uses PBKDF2 + AES)
      // Note: SHA-1 based PBE not FIPS approved
      if (!fipsMode) {
         putService(new Service(this, CIPHER, "PBEWithHmacSHA1AndAES_128", PBEWithHmacSHA1AndAES_128Cipher.class.getName(), null, null));
         putService(new Service(this, CIPHER, "PBEWithHmacSHA1AndAES_256", PBEWithHmacSHA1AndAES_256Cipher.class.getName(), null, null));
      }
      putService(new Service(this, CIPHER, "PBEWithHmacSHA224AndAES_128", PBEWithHmacSHA224AndAES_128Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA224AndAES_256", PBEWithHmacSHA224AndAES_256Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA256AndAES_128", PBEWithHmacSHA256AndAES_128Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA256AndAES_256", PBEWithHmacSHA256AndAES_256Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA384AndAES_128", PBEWithHmacSHA384AndAES_128Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA384AndAES_256", PBEWithHmacSHA384AndAES_256Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA512AndAES_128", PBEWithHmacSHA512AndAES_128Cipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "PBEWithHmacSHA512AndAES_256", PBEWithHmacSHA512AndAES_256Cipher.class.getName(), null, null));

      if (!fipsMode) {
         // DESede (Triple DES) - NOT FIPS approved (deprecated)
         putService(new Service(this, CIPHER, "DESede/ECB/NoPadding", DESedeEcbNoPaddingCipher.class.getName(),
            List.of("TripleDES/ECB/NoPadding"), null));
         putService(new Service(this, CIPHER, "DESede/ECB/PKCS5Padding", DESedeEcbPKCS5PaddingCipher.class.getName(),
            List.of("TripleDES/ECB/PKCS5Padding"), null));
         putService(new Service(this, CIPHER, "DESede/CBC/NoPadding", DESedeCbcNoPaddingCipher.class.getName(),
            List.of("TripleDES/CBC/NoPadding", "OID.1.2.840.113549.3.7", "1.2.840.113549.3.7"), null));
         putService(new Service(this, CIPHER, "DESede/CBC/PKCS5Padding", DESedeCbcPKCS5PaddingCipher.class.getName(),
            List.of("TripleDES/CBC/PKCS5Padding"), null));

         // ChaCha20-Poly1305 - NOT FIPS approved
         putService(new Service(this, CIPHER, "ChaCha20-Poly1305", ChaCha20Poly1305Cipher.class.getName(),
            List.of("ChaCha20-Poly1305/None/NoPadding"), null));
      }

      // RSA Ciphers - FIPS approved (with key size restrictions enforced at runtime)
      // Note: OAEP with SHA-1 deprecated in FIPS
      putService(new Service(this, CIPHER, "RSA/ECB/PKCS1Padding", RSAEcbPKCS1PaddingCipher.class.getName(),
         List.of("RSA", "OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1"), null));
      putService(new Service(this, CIPHER, "RSA/ECB/NoPadding", RSAEcbNoPaddingCipher.class.getName(), null, null));
      if (!fipsMode) {
         putService(new Service(this, CIPHER, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
            RSAEcbOAEPWithSHA1AndMGF1PaddingCipher.class.getName(),
            List.of("RSA/ECB/OAEPWithSHA1AndMGF1Padding"), null));
      }
      putService(new Service(this, CIPHER, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
         RSAEcbOAEPWithSHA256AndMGF1PaddingCipher.class.getName(),
         List.of("RSA/ECB/OAEPWithSHA256AndMGF1Padding", "OID.1.2.840.113549.1.1.7", "1.2.840.113549.1.1.7"), null));

      if (!fipsMode) {
         // Camellia - NOT FIPS approved (Japanese standard)
         registerCamelliaCiphers();
         // ARIA - NOT FIPS approved (Korean standard)
         registerARIACiphers();
         // SM4 - NOT FIPS approved (Chinese standard)
         registerSM4Ciphers();
         // ChaCha20 (stream cipher) - NOT FIPS approved
         putService(new Service(this, CIPHER, "ChaCha20", ChaCha20Cipher.class.getName(), null, null));
      }
   }

   private void registerCamelliaCiphers() {
      // Camellia-128
      putService(new Service(this, CIPHER, "Camellia_128/ECB/NoPadding", Camellia_128EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/ECB/PKCS5Padding", Camellia_128EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CBC/NoPadding", Camellia_128CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CBC/PKCS5Padding", Camellia_128CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CFB/NoPadding", Camellia_128CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CFB/PKCS5Padding", Camellia_128CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CTR/NoPadding", Camellia_128CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/CTR/PKCS5Padding", Camellia_128CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/OFB/NoPadding", Camellia_128OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_128/OFB/PKCS5Padding", Camellia_128OfbPKCS5PaddingCipher.class.getName(), null, null));
      // Camellia-192
      putService(new Service(this, CIPHER, "Camellia_192/ECB/NoPadding", Camellia_192EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/ECB/PKCS5Padding", Camellia_192EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CBC/NoPadding", Camellia_192CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CBC/PKCS5Padding", Camellia_192CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CFB/NoPadding", Camellia_192CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CFB/PKCS5Padding", Camellia_192CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CTR/NoPadding", Camellia_192CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/CTR/PKCS5Padding", Camellia_192CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/OFB/NoPadding", Camellia_192OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_192/OFB/PKCS5Padding", Camellia_192OfbPKCS5PaddingCipher.class.getName(), null, null));
      // Camellia-256
      putService(new Service(this, CIPHER, "Camellia_256/ECB/NoPadding", Camellia_256EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/ECB/PKCS5Padding", Camellia_256EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CBC/NoPadding", Camellia_256CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CBC/PKCS5Padding", Camellia_256CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CFB/NoPadding", Camellia_256CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CFB/PKCS5Padding", Camellia_256CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CTR/NoPadding", Camellia_256CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/CTR/PKCS5Padding", Camellia_256CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/OFB/NoPadding", Camellia_256OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "Camellia_256/OFB/PKCS5Padding", Camellia_256OfbPKCS5PaddingCipher.class.getName(), null, null));
   }

   private void registerARIACiphers() {
      // ARIA-128
      putService(new Service(this, CIPHER, "ARIA_128/ECB/NoPadding", ARIA_128EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/ECB/PKCS5Padding", ARIA_128EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CBC/NoPadding", ARIA_128CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CBC/PKCS5Padding", ARIA_128CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CFB/NoPadding", ARIA_128CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CFB/PKCS5Padding", ARIA_128CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CTR/NoPadding", ARIA_128CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/CTR/PKCS5Padding", ARIA_128CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/OFB/NoPadding", ARIA_128OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/OFB/PKCS5Padding", ARIA_128OfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/GCM/NoPadding", ARIA_128GcmNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_128/GCM/PKCS5Padding", ARIA_128GcmPKCS5PaddingCipher.class.getName(), null, null));
      // ARIA-192
      putService(new Service(this, CIPHER, "ARIA_192/ECB/NoPadding", ARIA_192EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/ECB/PKCS5Padding", ARIA_192EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CBC/NoPadding", ARIA_192CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CBC/PKCS5Padding", ARIA_192CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CFB/NoPadding", ARIA_192CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CFB/PKCS5Padding", ARIA_192CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CTR/NoPadding", ARIA_192CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/CTR/PKCS5Padding", ARIA_192CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/OFB/NoPadding", ARIA_192OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/OFB/PKCS5Padding", ARIA_192OfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/GCM/NoPadding", ARIA_192GcmNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_192/GCM/PKCS5Padding", ARIA_192GcmPKCS5PaddingCipher.class.getName(), null, null));
      // ARIA-256
      putService(new Service(this, CIPHER, "ARIA_256/ECB/NoPadding", ARIA_256EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/ECB/PKCS5Padding", ARIA_256EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CBC/NoPadding", ARIA_256CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CBC/PKCS5Padding", ARIA_256CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CFB/NoPadding", ARIA_256CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CFB/PKCS5Padding", ARIA_256CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CTR/NoPadding", ARIA_256CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/CTR/PKCS5Padding", ARIA_256CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/OFB/NoPadding", ARIA_256OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/OFB/PKCS5Padding", ARIA_256OfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/GCM/NoPadding", ARIA_256GcmNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "ARIA_256/GCM/PKCS5Padding", ARIA_256GcmPKCS5PaddingCipher.class.getName(), null, null));
   }

   private void registerSM4Ciphers() {
      putService(new Service(this, CIPHER, "SM4/ECB/NoPadding", SM4EcbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/ECB/PKCS5Padding", SM4EcbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CBC/NoPadding", SM4CbcNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CBC/PKCS5Padding", SM4CbcPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CFB/NoPadding", SM4CfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CFB/PKCS5Padding", SM4CfbPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CTR/NoPadding", SM4CtrNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/CTR/PKCS5Padding", SM4CtrPKCS5PaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/OFB/NoPadding", SM4OfbNoPaddingCipher.class.getName(), null, null));
      putService(new Service(this, CIPHER, "SM4/OFB/PKCS5Padding", SM4OfbPKCS5PaddingCipher.class.getName(), null, null));
   }

   private void registerMacServices() {
      // FIPS-approved: HMAC with SHA-2, SHA-3
      // NOT FIPS-approved: HmacSHA1 (deprecated)

      if (!fipsMode) {
         putService(new Service(this, MAC, "HmacSHA1", HmacSHA1.class.getName(),
            List.of("OID.1.2.840.113549.2.7", "1.2.840.113549.2.7"), null));
      }

      // HMAC with SHA-2 - FIPS approved
      putService(new Service(this, MAC, "HmacSHA224", HmacSHA224.class.getName(),
         List.of("OID.1.2.840.113549.2.8", "1.2.840.113549.2.8"), null));
      putService(new Service(this, MAC, "HmacSHA256", HmacSHA256.class.getName(),
         List.of("OID.1.2.840.113549.2.9", "1.2.840.113549.2.9"), null));
      putService(new Service(this, MAC, "HmacSHA384", HmacSHA384.class.getName(),
         List.of("OID.1.2.840.113549.2.10", "1.2.840.113549.2.10"), null));
      putService(new Service(this, MAC, "HmacSHA512", HmacSHA512.class.getName(),
         List.of("OID.1.2.840.113549.2.11", "1.2.840.113549.2.11"), null));

      // HMAC with SHA-3 - FIPS approved
      putService(new Service(this, MAC, "HmacSHA3-224", HmacSHA3_224.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.13", "2.16.840.1.101.3.4.2.13"), null));
      putService(new Service(this, MAC, "HmacSHA3-256", HmacSHA3_256.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.14", "2.16.840.1.101.3.4.2.14"), null));
      putService(new Service(this, MAC, "HmacSHA3-384", HmacSHA3_384.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.15", "2.16.840.1.101.3.4.2.15"), null));
      putService(new Service(this, MAC, "HmacSHA3-512", HmacSHA3_512.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.2.16", "2.16.840.1.101.3.4.2.16"), null));

      // HmacPBE services
      if (!fipsMode) {
         putService(new Service(this, MAC, "HmacPBESHA1", HmacPBESHA1.class.getName(), null, null));
      }
      putService(new Service(this, MAC, "HmacPBESHA224", HmacPBESHA224.class.getName(), null, null));
      putService(new Service(this, MAC, "HmacPBESHA256", HmacPBESHA256.class.getName(), null, null));
      putService(new Service(this, MAC, "HmacPBESHA384", HmacPBESHA384.class.getName(), null, null));
      putService(new Service(this, MAC, "HmacPBESHA512", HmacPBESHA512.class.getName(), null, null));

      // CMAC and GMAC - FIPS approved
      putService(new Service(this, MAC, "AESCMAC", AESCMACMac.class.getName(),
         List.of("AES-CMAC"), null));
      putService(new Service(this, MAC, "AESGMAC", AESGMACMac.class.getName(),
         List.of("AES-GMAC"), null));

      // KMAC - FIPS approved (NIST SP 800-185)
      if (OpenSSLCrypto.isAlgorithmAvailable("MAC", "KMAC128")) {
         putService(new Service(this, MAC, "KMAC128", KMAC128Mac.class.getName(),
            List.of("OID.2.16.840.1.101.3.4.2.19", "2.16.840.1.101.3.4.2.19"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("MAC", "KMAC256")) {
         putService(new Service(this, MAC, "KMAC256", KMAC256Mac.class.getName(),
            List.of("OID.2.16.840.1.101.3.4.2.20", "2.16.840.1.101.3.4.2.20"), null));
      }

      if (!fipsMode) {
         // Poly1305 - NOT FIPS approved
         if (OpenSSLCrypto.isAlgorithmAvailable("MAC", "Poly1305")) {
            putService(new Service(this, MAC, "Poly1305", Poly1305Mac.class.getName(), null, null));
         }
         // SipHash - NOT FIPS approved
         if (OpenSSLCrypto.isAlgorithmAvailable("MAC", "SIPHASH")) {
            putService(new Service(this, MAC, "SipHash", SipHashMac.class.getName(), null, null));
         }
      }
   }

   private void registerKeyGeneratorServices() {
      // AES - FIPS approved
      putService(new Service(this, KEY_GENERATOR, "AES", AESKeyGenerator.class.getName(), null, null));

      if (!fipsMode) {
         // DESede - NOT FIPS approved
         putService(new Service(this, KEY_GENERATOR, "DESede", DESedeKeyGenerator.class.getName(),
            List.of("TripleDES"), null));
         putService(new Service(this, KEY_GENERATOR, "HmacSHA1", HmacSHA1KeyGenerator.class.getName(), null, null));
      }

      // HMAC key generators - FIPS approved (SHA-2, SHA-3)
      putService(new Service(this, KEY_GENERATOR, "HmacSHA224", HmacSHA224KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA256", HmacSHA256KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA384", HmacSHA384KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA512", HmacSHA512KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA3-224", HmacSHA3_224KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA3-256", HmacSHA3_256KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA3-384", HmacSHA3_384KeyGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_GENERATOR, "HmacSHA3-512", HmacSHA3_512KeyGenerator.class.getName(), null, null));
   }

   private void registerSignatureServices() {
      // FIPS-approved: RSA/ECDSA/DSA with SHA-2/SHA-3, EdDSA
      // Note: SHA-1 based signatures deprecated in FIPS

      if (!fipsMode) {
         // SHA-1 based signatures - NOT FIPS approved (deprecated)
         putService(new Service(this, SIGNATURE, "SHA1withRSA", SHA1withRSASignature.class.getName(),
            List.of("OID.1.2.840.113549.1.1.5", "1.2.840.113549.1.1.5"), null));
         putService(new Service(this, SIGNATURE, "SHA1withECDSA", SHA1withECDSASignature.class.getName(),
            List.of("OID.1.2.840.10045.4.1", "1.2.840.10045.4.1"), null));
         putService(new Service(this, SIGNATURE, "SHA1withDSA", SHA1withDSASignature.class.getName(),
            List.of("OID.1.2.840.10040.4.3", "1.2.840.10040.4.3", "DSS"), null));
         putService(new Service(this, SIGNATURE, "SHA1withRSAandMGF1", SHA1withRSAandMGF1Signature.class.getName(), null, null));
      }

      // RSA PKCS#1 v1.5 with SHA-2 - FIPS approved
      putService(new Service(this, SIGNATURE, "SHA224withRSA", SHA224withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.14", "1.2.840.113549.1.1.14"), null));
      putService(new Service(this, SIGNATURE, "SHA256withRSA", SHA256withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.11", "1.2.840.113549.1.1.11"), null));
      putService(new Service(this, SIGNATURE, "SHA384withRSA", SHA384withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.12", "1.2.840.113549.1.1.12"), null));
      putService(new Service(this, SIGNATURE, "SHA512withRSA", SHA512withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.13", "1.2.840.113549.1.1.13"), null));

      // ECDSA with SHA-2 - FIPS approved
      putService(new Service(this, SIGNATURE, "SHA224withECDSA", SHA224withECDSASignature.class.getName(),
         List.of("OID.1.2.840.10045.4.3.1", "1.2.840.10045.4.3.1"), null));
      putService(new Service(this, SIGNATURE, "SHA256withECDSA", SHA256withECDSASignature.class.getName(),
         List.of("OID.1.2.840.10045.4.3.2", "1.2.840.10045.4.3.2"), null));
      putService(new Service(this, SIGNATURE, "SHA384withECDSA", SHA384withECDSASignature.class.getName(),
         List.of("OID.1.2.840.10045.4.3.3", "1.2.840.10045.4.3.3"), null));
      putService(new Service(this, SIGNATURE, "SHA512withECDSA", SHA512withECDSASignature.class.getName(),
         List.of("OID.1.2.840.10045.4.3.4", "1.2.840.10045.4.3.4"), null));

      // ECDSA with SHA-3 - FIPS approved
      putService(new Service(this, SIGNATURE, "SHA3-224withECDSA", SHA3_224withECDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.9", "2.16.840.1.101.3.4.3.9"), null));
      putService(new Service(this, SIGNATURE, "SHA3-256withECDSA", SHA3_256withECDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.10", "2.16.840.1.101.3.4.3.10"), null));
      putService(new Service(this, SIGNATURE, "SHA3-384withECDSA", SHA3_384withECDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.11", "2.16.840.1.101.3.4.3.11"), null));
      putService(new Service(this, SIGNATURE, "SHA3-512withECDSA", SHA3_512withECDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.12", "2.16.840.1.101.3.4.3.12"), null));

      // RSA with SHA-512 truncated - FIPS approved
      putService(new Service(this, SIGNATURE, "SHA512/224withRSA", SHA512_224withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.15", "1.2.840.113549.1.1.15"), null));
      putService(new Service(this, SIGNATURE, "SHA512/256withRSA", SHA512_256withRSASignature.class.getName(),
         List.of("OID.1.2.840.113549.1.1.16", "1.2.840.113549.1.1.16"), null));

      // RSA-PSS with SHA-2 - FIPS approved (OID 1.2.840.113549.1.1.10 is the generic RSASSA-PSS OID)
      putService(new Service(this, SIGNATURE, "SHA224withRSAandMGF1", SHA224withRSAandMGF1Signature.class.getName(),
         List.of("RSASSA-PSS", "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10"), null));
      putService(new Service(this, SIGNATURE, "SHA256withRSAandMGF1", SHA256withRSAandMGF1Signature.class.getName(), null, null));
      putService(new Service(this, SIGNATURE, "SHA384withRSAandMGF1", SHA384withRSAandMGF1Signature.class.getName(), null, null));
      putService(new Service(this, SIGNATURE, "SHA512withRSAandMGF1", SHA512withRSAandMGF1Signature.class.getName(), null, null));
      putService(new Service(this, SIGNATURE, "SHA512/224withRSAandMGF1", SHA512_224withRSAandMGF1Signature.class.getName(), null, null));
      putService(new Service(this, SIGNATURE, "SHA512/256withRSAandMGF1", SHA512_256withRSAandMGF1Signature.class.getName(), null, null));

      // DSA with SHA-2 - FIPS approved
      putService(new Service(this, SIGNATURE, "SHA224withDSA", SHA224withDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.1", "2.16.840.1.101.3.4.3.1"), null));
      putService(new Service(this, SIGNATURE, "SHA256withDSA", SHA256withDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.2", "2.16.840.1.101.3.4.3.2"), null));
      putService(new Service(this, SIGNATURE, "SHA384withDSA", SHA384withDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.3", "2.16.840.1.101.3.4.3.3"), null));
      putService(new Service(this, SIGNATURE, "SHA512withDSA", SHA512withDSASignature.class.getName(),
         List.of("OID.2.16.840.1.101.3.4.3.4", "2.16.840.1.101.3.4.3.4"), null));

      // EdDSA - FIPS approved (FIPS 186-5)
      putService(new Service(this, SIGNATURE, "EdDSA",
         net.glassless.provider.internal.eddsa.EdDSASignature.class.getName(), null, null));
      putService(new Service(this, SIGNATURE, "Ed25519",
         net.glassless.provider.internal.eddsa.Ed25519Signature.class.getName(),
         List.of("OID.1.3.101.112", "1.3.101.112"), null));
      putService(new Service(this, SIGNATURE, "Ed448",
         net.glassless.provider.internal.eddsa.Ed448Signature.class.getName(),
         List.of("OID.1.3.101.113", "1.3.101.113"), null));

      // Post-Quantum Signatures - FIPS 204, 205 (requires OpenSSL 3.5+)
      registerPQCSignatureServices();
   }

   private void registerPQCSignatureServices() {
      // ML-DSA (FIPS 204) - Module-Lattice Digital Signature Algorithm
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa44")) {
         putService(new Service(this, SIGNATURE, "ML-DSA-44",
            MLDSA44Signature.class.getName(),
            List.of("MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa65")) {
         putService(new Service(this, SIGNATURE, "ML-DSA-65",
            MLDSA65Signature.class.getName(),
            List.of("MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18"), null));
         // Register generic ML-DSA signature
         putService(new Service(this, SIGNATURE, "ML-DSA",
            MLDSASignature.class.getName(), List.of("MLDSA"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa87")) {
         putService(new Service(this, SIGNATURE, "ML-DSA-87",
            MLDSA87Signature.class.getName(),
            List.of("MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"), null));
      }

      // SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm
      // SHA-2 variants
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-128s",
            SLHDSA_SHA2_128sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-128f",
            SLHDSA_SHA2_128fSignature.class.getName(), null, null));
         // Register generic SLH-DSA signature
         putService(new Service(this, SIGNATURE, "SLH-DSA",
            SLHDSASignature.class.getName(), List.of("SLHDSA"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-192s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-192s",
            SLHDSA_SHA2_192sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-192f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-192f",
            SLHDSA_SHA2_192fSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-256s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-256s",
            SLHDSA_SHA2_256sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-256f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHA2-256f",
            SLHDSA_SHA2_256fSignature.class.getName(), null, null));
      }
      // SHAKE variants
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-128s",
            SLHDSA_SHAKE_128sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-128f",
            SLHDSA_SHAKE_128fSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-192s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-192s",
            SLHDSA_SHAKE_192sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-192f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-192f",
            SLHDSA_SHAKE_192fSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-256s")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-256s",
            SLHDSA_SHAKE_256sSignature.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-256f")) {
         putService(new Service(this, SIGNATURE, "SLH-DSA-SHAKE-256f",
            SLHDSA_SHAKE_256fSignature.class.getName(), null, null));
      }
   }

   private void registerKeyPairGeneratorServices() {
      // All key pair generators are FIPS approved (with key size restrictions at runtime)
      putService(new Service(this, KEY_PAIR_GENERATOR, "RSA", RSAKeyPairGenerator.class.getName(),
         List.of("OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "EC", ECKeyPairGenerator.class.getName(),
         List.of("EllipticCurve", "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "DSA", DSAKeyPairGenerator.class.getName(),
         List.of("OID.1.2.840.10040.4.1", "1.2.840.10040.4.1"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "DH", DHKeyPairGenerator.class.getName(),
         List.of("DiffieHellman", "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "EdDSA",
         net.glassless.provider.internal.eddsa.EdDSAKeyPairGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "Ed25519",
         net.glassless.provider.internal.eddsa.Ed25519KeyPairGenerator.class.getName(),
         List.of("OID.1.3.101.112", "1.3.101.112"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "Ed448",
         net.glassless.provider.internal.eddsa.Ed448KeyPairGenerator.class.getName(),
         List.of("OID.1.3.101.113", "1.3.101.113"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "XDH",
         net.glassless.provider.internal.xdh.XDHKeyPairGenerator.class.getName(), null, null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "X25519",
         net.glassless.provider.internal.xdh.X25519KeyPairGenerator.class.getName(),
         List.of("OID.1.3.101.110", "1.3.101.110"), null));
      putService(new Service(this, KEY_PAIR_GENERATOR, "X448",
         net.glassless.provider.internal.xdh.X448KeyPairGenerator.class.getName(),
         List.of("OID.1.3.101.111", "1.3.101.111"), null));

      // Post-Quantum Cryptography - FIPS 203, 204, 205 (requires OpenSSL 3.5+)
      registerPQCKeyPairGeneratorServices();
   }

   private void registerPQCKeyPairGeneratorServices() {
      // ML-KEM (FIPS 203) - Key Encapsulation Mechanism
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem512")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-KEM-512",
            MLKEM512KeyPairGenerator.class.getName(),
            List.of("MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem768")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-KEM-768",
            MLKEM768KeyPairGenerator.class.getName(),
            List.of("MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2"), null));
         // Register generic ML-KEM pointing to the most common variant
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-KEM",
            MLKEMKeyPairGenerator.class.getName(), List.of("MLKEM"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem1024")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-KEM-1024",
            MLKEM1024KeyPairGenerator.class.getName(),
            List.of("MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3"), null));
      }

      // ML-DSA (FIPS 204) - Digital Signature Algorithm
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa44")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-DSA-44",
            MLDSA44KeyPairGenerator.class.getName(),
            List.of("MLDSA44", "OID.2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa65")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-DSA-65",
            MLDSA65KeyPairGenerator.class.getName(),
            List.of("MLDSA65", "OID.2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18"), null));
         // Register generic ML-DSA pointing to the most common variant
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-DSA",
            MLDSAKeyPairGenerator.class.getName(), List.of("MLDSA"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa87")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "ML-DSA-87",
            MLDSA87KeyPairGenerator.class.getName(),
            List.of("MLDSA87", "OID.2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19"), null));
      }

      // SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm
      // SHA-2 variants
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-128s",
            SLHDSA_SHA2_128sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-128f",
            SLHDSA_SHA2_128fKeyPairGenerator.class.getName(), null, null));
         // Register generic SLH-DSA pointing to a common variant
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA",
            SLHDSAKeyPairGenerator.class.getName(), List.of("SLHDSA"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-192s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-192s",
            SLHDSA_SHA2_192sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-192f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-192f",
            SLHDSA_SHA2_192fKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-256s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-256s",
            SLHDSA_SHA2_256sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-256f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHA2-256f",
            SLHDSA_SHA2_256fKeyPairGenerator.class.getName(), null, null));
      }
      // SHAKE variants
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-128s",
            SLHDSA_SHAKE_128sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-128f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-128f",
            SLHDSA_SHAKE_128fKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-192s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-192s",
            SLHDSA_SHAKE_192sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-192f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-192f",
            SLHDSA_SHAKE_192fKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-256s")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-256s",
            SLHDSA_SHAKE_256sKeyPairGenerator.class.getName(), null, null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHAKE-256f")) {
         putService(new Service(this, KEY_PAIR_GENERATOR, "SLH-DSA-SHAKE-256f",
            SLHDSA_SHAKE_256fKeyPairGenerator.class.getName(), null, null));
      }
   }

   private void registerSecretKeyFactoryServices() {
      // FIPS-approved: PBKDF2
      // NOT FIPS-approved: SCRYPT

      if (!fipsMode) {
         // PBKDF2 with SHA-1 - deprecated in FIPS
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA1",
            PBKDF2WithHmacSHA1.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA1And8BIT",
            PBKDF2WithHmacSHA1And8BIT.class.getName(), null, null));
      }

      // PBKDF2 with SHA-2 - FIPS approved
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA224",
         PBKDF2WithHmacSHA224.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA256",
         PBKDF2WithHmacSHA256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA384",
         PBKDF2WithHmacSHA384.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA512",
         PBKDF2WithHmacSHA512.class.getName(), null, null));

      if (!fipsMode) {
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA224And8BIT",
            PBKDF2WithHmacSHA224And8BIT.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA256And8BIT",
            PBKDF2WithHmacSHA256And8BIT.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA384And8BIT",
            PBKDF2WithHmacSHA384And8BIT.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA512And8BIT",
            PBKDF2WithHmacSHA512And8BIT.class.getName(), null, null));
      }

      // PBKDF2 with SHA-3 - FIPS approved
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA3-224",
         PBKDF2WithHmacSHA3_224.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA3-256",
         PBKDF2WithHmacSHA3_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA3-384",
         PBKDF2WithHmacSHA3_384.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBKDF2WithHmacSHA3-512",
         PBKDF2WithHmacSHA3_512.class.getName(), null, null));

      // PBE, AES, DESede SecretKeyFactory
      if (!fipsMode) {
         putService(new Service(this, SECRET_KEY_FACTORY, "PBE", PBESecretKeyFactory.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "DESede", DESedeSecretKeyFactory.class.getName(),
            List.of("TripleDES"), null));
         // SCRYPT - NOT FIPS approved
         putService(new Service(this, SECRET_KEY_FACTORY, "SCRYPT", ScryptSecretKeyFactory.class.getName(), null, null));

         // Argon2 - NOT FIPS approved, requires OpenSSL 3.2+
         if (OpenSSLCrypto.isAlgorithmAvailable("KDF", "ARGON2ID")) {
            putService(new Service(this, SECRET_KEY_FACTORY, "Argon2id",
               net.glassless.provider.internal.secretkeyfactory.Argon2idSecretKeyFactory.class.getName(), null, null));
            putService(new Service(this, SECRET_KEY_FACTORY, "Argon2i",
               net.glassless.provider.internal.secretkeyfactory.Argon2iSecretKeyFactory.class.getName(), null, null));
            putService(new Service(this, SECRET_KEY_FACTORY, "Argon2d",
               net.glassless.provider.internal.secretkeyfactory.Argon2dSecretKeyFactory.class.getName(), null, null));
         }
      }
      putService(new Service(this, SECRET_KEY_FACTORY, "AES", AESSecretKeyFactory.class.getName(), null, null));

      // PBES2 SecretKeyFactory
      if (!fipsMode) {
         putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA1AndAES_128",
            PBEWithHmacSHA1AndAES_128.class.getName(), null, null));
         putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA1AndAES_256",
            PBEWithHmacSHA1AndAES_256.class.getName(), null, null));
      }
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA224AndAES_128",
         PBEWithHmacSHA224AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA224AndAES_256",
         PBEWithHmacSHA224AndAES_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA256AndAES_128",
         PBEWithHmacSHA256AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA256AndAES_256",
         PBEWithHmacSHA256AndAES_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA384AndAES_128",
         PBEWithHmacSHA384AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA384AndAES_256",
         PBEWithHmacSHA384AndAES_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512AndAES_128",
         PBEWithHmacSHA512AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512AndAES_256",
         PBEWithHmacSHA512AndAES_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512/224AndAES_128",
         PBEWithHmacSHA512_224AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512/224AndAES_256",
         PBEWithHmacSHA512_224AndAES_256.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512/256AndAES_128",
         PBEWithHmacSHA512_256AndAES_128.class.getName(), null, null));
      putService(new Service(this, SECRET_KEY_FACTORY, "PBEWithHmacSHA512/256AndAES_256",
         PBEWithHmacSHA512_256AndAES_256.class.getName(), null, null));
   }

   private void registerKeyFactoryServices() {
      // All key factories are FIPS approved
      putService(new Service(this, KEY_FACTORY, "RSA", RSAKeyFactory.class.getName(),
         List.of("OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1"), null));
      putService(new Service(this, KEY_FACTORY, "EC", ECKeyFactory.class.getName(),
         List.of("EllipticCurve", "ECDSA", "ECDH", "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"), null));
      putService(new Service(this, KEY_FACTORY, "DSA", DSAKeyFactory.class.getName(),
         List.of("OID.1.2.840.10040.4.1", "1.2.840.10040.4.1"), null));
      putService(new Service(this, KEY_FACTORY, "DH", DHKeyFactory.class.getName(),
         List.of("DiffieHellman", "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1"), null));
      putService(new Service(this, KEY_FACTORY, "EdDSA",
         net.glassless.provider.internal.eddsa.EdDSAKeyFactory.class.getName(),
         List.of("Ed25519", "Ed448", "OID.1.3.101.112", "1.3.101.112", "OID.1.3.101.113", "1.3.101.113"), null));
      putService(new Service(this, KEY_FACTORY, "XDH",
         net.glassless.provider.internal.xdh.XDHKeyFactory.class.getName(),
         List.of("X25519", "X448", "OID.1.3.101.110", "1.3.101.110", "OID.1.3.101.111", "1.3.101.111"), null));

      // Post-Quantum Key Factories (requires OpenSSL 3.5+)
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem768")) {
         putService(new Service(this, KEY_FACTORY, "ML-KEM",
            MLKEMKeyFactory.class.getName(),
            List.of("MLKEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
               "OID.2.16.840.1.101.3.4.4.1", "OID.2.16.840.1.101.3.4.4.2", "OID.2.16.840.1.101.3.4.4.3"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mldsa65")) {
         putService(new Service(this, KEY_FACTORY, "ML-DSA",
            MLDSAKeyFactory.class.getName(),
            List.of("MLDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
               "OID.2.16.840.1.101.3.4.3.17", "OID.2.16.840.1.101.3.4.3.18", "OID.2.16.840.1.101.3.4.3.19"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "SLH-DSA-SHA2-128f")) {
         putService(new Service(this, KEY_FACTORY, "SLH-DSA",
            SLHDSAKeyFactory.class.getName(),
            List.of("SLHDSA", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
               "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
               "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"), null));
      }
   }

   private void registerKeyAgreementServices() {
      // All key agreement algorithms are FIPS approved
      putService(new Service(this, KEY_AGREEMENT, "ECDH", ECDHKeyAgreement.class.getName(),
         List.of("EllipticCurveDiffieHellman", "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"), null));
      putService(new Service(this, KEY_AGREEMENT, "DH", DHKeyAgreement.class.getName(),
         List.of("DiffieHellman", "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1"), null));
      putService(new Service(this, KEY_AGREEMENT, "XDH",
         net.glassless.provider.internal.xdh.XDHKeyAgreement.class.getName(), null, null));
      putService(new Service(this, KEY_AGREEMENT, "X25519",
         net.glassless.provider.internal.xdh.X25519KeyAgreement.class.getName(),
         List.of("OID.1.3.101.110", "1.3.101.110"), null));
      putService(new Service(this, KEY_AGREEMENT, "X448",
         net.glassless.provider.internal.xdh.X448KeyAgreement.class.getName(),
         List.of("OID.1.3.101.111", "1.3.101.111"), null));
   }

   private void registerAlgorithmParametersServices() {
      // Most AlgorithmParameters are FIPS approved
      putService(new Service(this, ALGORITHM_PARAMETERS, "EC",
         net.glassless.provider.internal.algparams.ECParameters.class.getName(),
         List.of("EllipticCurve"), null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "DSA",
         net.glassless.provider.internal.algparams.DSAParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "DH",
         net.glassless.provider.internal.algparams.DHParameters.class.getName(),
         List.of("DiffieHellman"), null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "AES",
         net.glassless.provider.internal.algparams.AESParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "GCM",
         net.glassless.provider.internal.algparams.GCMParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "OAEP",
         net.glassless.provider.internal.algparams.OAEPParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "RSASSA-PSS",
         net.glassless.provider.internal.algparams.PSSParameters.class.getName(),
         List.of("PSS"), null));

      if (!fipsMode) {
         putService(new Service(this, ALGORITHM_PARAMETERS, "DESede",
            net.glassless.provider.internal.algparams.DESedeParameters.class.getName(),
            List.of("TripleDES"), null));
      }

      // PBE AlgorithmParameters
      if (!fipsMode) {
         putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA1AndAES_128",
            net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
         putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA1AndAES_256",
            net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      }
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA224AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA224AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA256AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA256AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA384AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA384AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512/224AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512/224AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512/256AndAES_128",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBEWithHmacSHA512/256AndAES_256",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETERS, "PBES2",
         net.glassless.provider.internal.algparams.PBEParameters.class.getName(), null, null));
   }

   private void registerSecureRandomServices() {
      // FIPS-approved: DRBG, NativePRNG
      // NOT FIPS-approved: SHA1PRNG (deprecated)
      // All implementations use OpenSSL's thread-safe RAND_bytes()
      Map<String, String> threadSafeAttr = Map.of("ThreadSafe", "true");

      putService(new Service(this, SECURE_RANDOM, "NativePRNG",
         net.glassless.provider.internal.securerandom.NativePRNG.class.getName(),
         List.of("NativePRNGBlocking", "NativePRNGNonBlocking"), threadSafeAttr));
      putService(new Service(this, SECURE_RANDOM, "DRBG",
         net.glassless.provider.internal.securerandom.DRBG.class.getName(), null, threadSafeAttr));

      if (!fipsMode) {
         putService(new Service(this, SECURE_RANDOM, "SHA1PRNG",
            net.glassless.provider.internal.securerandom.SHA1PRNG.class.getName(), null, threadSafeAttr));
      }
   }

   private void registerAlgorithmParameterGeneratorServices() {
      // All parameter generators are FIPS approved
      putService(new Service(this, ALGORITHM_PARAMETER_GENERATOR, "DSA",
         net.glassless.provider.internal.algparamgen.DSAParameterGenerator.class.getName(), null, null));
      putService(new Service(this, ALGORITHM_PARAMETER_GENERATOR, "DH",
         net.glassless.provider.internal.algparamgen.DHParameterGenerator.class.getName(),
         List.of("DiffieHellman"), null));
   }

   private void registerKDFServices() {
      // HKDF - FIPS approved
      if (!fipsMode) {
         // HKDF-SHA1 - deprecated in FIPS
         putService(new Service(this, KDF, "HKDF-SHA1",
            net.glassless.provider.internal.kdf.HKDF_SHA1.class.getName(), null, null));
      }
      putService(new Service(this, KDF, "HKDF-SHA224",
         net.glassless.provider.internal.kdf.HKDF_SHA224.class.getName(), null, null));
      putService(new Service(this, KDF, "HKDF-SHA256",
         net.glassless.provider.internal.kdf.HKDF_SHA256.class.getName(), null, null));
      putService(new Service(this, KDF, "HKDF-SHA384",
         net.glassless.provider.internal.kdf.HKDF_SHA384.class.getName(), null, null));
      putService(new Service(this, KDF, "HKDF-SHA512",
         net.glassless.provider.internal.kdf.HKDF_SHA512.class.getName(), null, null));

      // X9.63 KDF - FIPS approved
      putService(new Service(this, KDF, "X963KDF-SHA256",
         net.glassless.provider.internal.kdf.X963KDF_SHA256.class.getName(), null, null));
      putService(new Service(this, KDF, "X963KDF-SHA384",
         net.glassless.provider.internal.kdf.X963KDF_SHA384.class.getName(), null, null));
      putService(new Service(this, KDF, "X963KDF-SHA512",
         net.glassless.provider.internal.kdf.X963KDF_SHA512.class.getName(), null, null));

      // SSH KDF - FIPS approved
      putService(new Service(this, KDF, "SSHKDF-SHA256",
         net.glassless.provider.internal.kdf.SSHKDF_SHA256.class.getName(), null, null));

      // KBKDF (SP 800-108) - FIPS approved
      putService(new Service(this, KDF, "KBKDF-HMAC-SHA256",
         net.glassless.provider.internal.kdf.KBKDF_HMAC_SHA256.class.getName(), null, null));

      // TLS 1.2 PRF - FIPS approved
      putService(new Service(this, KDF, "TLS1-PRF-SHA256",
         net.glassless.provider.internal.kdf.TLS1PRF_SHA256.class.getName(), null, null));
      putService(new Service(this, KDF, "TLS1-PRF-SHA384",
         net.glassless.provider.internal.kdf.TLS1PRF_SHA384.class.getName(), null, null));
   }

   private void registerKEMServices() {
      // ML-KEM (FIPS 203) - Key Encapsulation Mechanism (requires OpenSSL 3.5+)
      if (!OpenSSLCrypto.isKEMAvailable()) {
         return;  // KEM operations not supported on this OpenSSL version
      }

      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem512")) {
         putService(new Service(this, KEM, "ML-KEM-512",
            MLKEM512.class.getName(),
            List.of("MLKEM512", "OID.2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem768")) {
         putService(new Service(this, KEM, "ML-KEM-768",
            MLKEM768.class.getName(),
            List.of("MLKEM768", "OID.2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2"), null));
         // Register generic ML-KEM pointing to the most common variant
         putService(new Service(this, KEM, "ML-KEM",
            MLKEM.class.getName(), List.of("MLKEM"), null));
      }
      if (OpenSSLCrypto.isAlgorithmAvailable("KEYMGMT", "mlkem1024")) {
         putService(new Service(this, KEM, "ML-KEM-1024",
            MLKEM1024.class.getName(),
            List.of("MLKEM1024", "OID.2.16.840.1.101.3.4.4.3", "2.16.840.1.101.3.4.4.3"), null));
      }
   }

   /**
    * Main method to display provider information.
    *
    * @param args command line arguments. Use "--verbose" or "-v" to list all algorithms.
    */
   public static void main(String[] args) {
      boolean verbose = false;
      for (String arg : args) {
         if ("--verbose".equals(arg) || "-v".equals(arg)) {
            verbose = true;
            break;
         }
      }

      GlaSSLessProvider provider = new GlaSSLessProvider();

      System.out.println("GlaSSLess Provider Information");
      System.out.println("==============================");
      System.out.println();
      System.out.println("Provider: " + provider.getName() + " v" + provider.getVersionStr());
      System.out.println("Description: " + provider.getInfo());
      System.out.println();
      System.out.println("OpenSSL: " + net.glassless.provider.internal.OpenSSLCrypto.getOpenSSLVersion());
      System.out.println();
      System.out.println("FIPS Status");
      System.out.println("-----------");
      System.out.println("FIPS Mode: " + (provider.isFIPSMode() ? "ENABLED" : "DISABLED"));
      System.out.println("FIPS Provider Available: " + FIPSStatus.isFIPSProviderAvailable());
      System.out.println("OpenSSL FIPS Enabled: " + net.glassless.provider.internal.OpenSSLCrypto.isFIPSEnabled());

      if (verbose) {
         System.out.println();
         System.out.println("Available Algorithms");
         System.out.println("--------------------");

         // Group services by type
         Map<String, TreeSet<String>> servicesByType = new TreeMap<>();
         for (Service service : provider.getServices()) {
            servicesByType
               .computeIfAbsent(service.getType(), k -> new TreeSet<>())
               .add(service.getAlgorithm());
         }

         for (Map.Entry<String, TreeSet<String>> entry : servicesByType.entrySet()) {
            System.out.println();
            System.out.println(entry.getKey() + " (" + entry.getValue().size() + "):");
            for (String algorithm : entry.getValue()) {
               System.out.println("  " + algorithm);
            }
         }
      } else {
         System.out.println();
         System.out.println("Use --verbose or -v to list all available algorithms.");
      }
   }
}
