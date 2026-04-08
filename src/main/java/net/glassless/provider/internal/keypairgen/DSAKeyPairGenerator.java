package net.glassless.provider.internal.keypairgen;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import net.glassless.provider.FIPSStatus;
import net.glassless.provider.internal.GlaSSLessLog;
import net.glassless.provider.internal.OpenSSLCrypto;
import net.glassless.provider.internal.keyfactory.DSAKeyFactory;
import net.glassless.provider.internal.keyfactory.GlaSSLessDSAPublicKey;

/**
 * DSA KeyPairGenerator using OpenSSL.
 * DSA key generation requires a two-step process:
 * 1. Generate DSA parameters (p, q, g)
 * 2. Generate the key pair from those parameters
 */
public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {

   private static final System.Logger LOG = GlaSSLessLog.KEY_PAIR_GEN;
   private static final int DEFAULT_KEY_SIZE = 2048;
   private static final int MIN_KEY_SIZE = 512;
   private static final int FIPS_MIN_KEY_SIZE = 2048;
   private static final int MAX_KEY_SIZE = 3072;

   private int keySize = DEFAULT_KEY_SIZE;

   private int getMinKeySize() {
      return FIPSStatus.isFIPSEnabled() ? FIPS_MIN_KEY_SIZE : MIN_KEY_SIZE;
   }

   @Override
   public void initialize(int keysize, SecureRandom random) {
      int minSize = getMinKeySize();
      if (keysize < minSize || keysize > MAX_KEY_SIZE) {
         throw new InvalidParameterException("Key size must be between " + minSize + " and " + MAX_KEY_SIZE + " bits");
      }
      // DSA key sizes should be multiples of 64
      if (keysize % 64 != 0) {
         throw new InvalidParameterException("DSA key size must be a multiple of 64");
      }
      this.keySize = keysize;

   }

   @Override
   public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
      if (params instanceof DSAParameterSpec dsaParams) {
         // Extract key size from the P parameter
         int pBitLength = dsaParams.getP().bitLength();
         int minSize = getMinKeySize();
         if (pBitLength < minSize || pBitLength > MAX_KEY_SIZE) {
            throw new InvalidAlgorithmParameterException("Key size must be between " + minSize + " and " + MAX_KEY_SIZE + " bits");
         }
         this.keySize = pBitLength;

      } else if (params != null) {
         throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params.getClass().getName());
      }
   }

   @Override
   public KeyPair generateKeyPair() {
      try (Arena arena = Arena.ofConfined()) {
         // Step 1: Generate DSA parameters
         MemorySegment paramCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_name(MemorySegment.NULL, "DSA", MemorySegment.NULL, arena);
         if (paramCtx.equals(MemorySegment.NULL)) {
            throw new ProviderException("Failed to create EVP_PKEY_CTX for DSA parameter generation");
         }

         MemorySegment dsaParams;
         try {
            int result = OpenSSLCrypto.EVP_PKEY_paramgen_init(paramCtx);
            if (result <= 0) {
               throw new ProviderException("EVP_PKEY_paramgen_init failed");
            }

            result = OpenSSLCrypto.EVP_PKEY_CTX_set_dsa_paramgen_bits(paramCtx, keySize);
            if (result <= 0) {
               throw new ProviderException("EVP_PKEY_CTX_set_dsa_paramgen_bits failed");
            }

            MemorySegment paramsPtr = arena.allocate(ValueLayout.ADDRESS);
            result = OpenSSLCrypto.EVP_PKEY_paramgen(paramCtx, paramsPtr);
            if (result <= 0) {
               throw new ProviderException("EVP_PKEY_paramgen failed");
            }

            dsaParams = paramsPtr.get(ValueLayout.ADDRESS, 0);
            if (dsaParams.equals(MemorySegment.NULL)) {
               throw new ProviderException("Generated DSA parameters are null");
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_CTX_free(paramCtx);
         }

         // Step 2: Generate the key pair from parameters
         try {
            MemorySegment keyCtx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(MemorySegment.NULL, dsaParams, MemorySegment.NULL);
            if (keyCtx.equals(MemorySegment.NULL)) {
               throw new ProviderException("Failed to create EVP_PKEY_CTX for DSA key generation");
            }

            try {
               int result = OpenSSLCrypto.EVP_PKEY_keygen_init(keyCtx);
               if (result <= 0) {
                  throw new ProviderException("EVP_PKEY_keygen_init failed");
               }

               MemorySegment pkeyPtr = arena.allocate(ValueLayout.ADDRESS);
               result = OpenSSLCrypto.EVP_PKEY_keygen(keyCtx, pkeyPtr);
               if (result <= 0) {
                  throw new ProviderException("EVP_PKEY_keygen failed");
               }

               MemorySegment pkey = pkeyPtr.get(ValueLayout.ADDRESS, 0);
               if (pkey.equals(MemorySegment.NULL)) {
                  throw new ProviderException("Generated key is null");
               }

               try {
                  byte[] privateKeyBytes = OpenSSLCrypto.exportPrivateKey(pkey, arena);
                  byte[] publicKeyBytes = OpenSSLCrypto.exportPublicKey(pkey, arena);

                  DSAParameterSpec params = DSAKeyFactory.extractDSAParams(pkey, arena);
                  BigInteger y = OpenSSLCrypto.EVP_PKEY_get_bn_param(pkey, "pub", arena);

                  LOG.log(System.Logger.Level.DEBUG, "DSA, {0} bits", keySize);
                  return new KeyPair(
                     new GlaSSLessDSAPublicKey(y, params, publicKeyBytes),
                     DSAKeyFactory.extractDSAPrivateKey(pkey, arena, privateKeyBytes));

               } finally {
                  OpenSSLCrypto.EVP_PKEY_free(pkey);
               }

            } finally {
               OpenSSLCrypto.EVP_PKEY_CTX_free(keyCtx);
            }
         } finally {
            OpenSSLCrypto.EVP_PKEY_free(dsaParams);
         }

      } catch (ProviderException e) {
         throw e;
      } catch (Throwable e) {
         throw new ProviderException("Error generating DSA key pair", e);
      }
   }
}
