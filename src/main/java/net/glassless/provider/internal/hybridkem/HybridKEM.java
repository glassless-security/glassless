package net.glassless.provider.internal.hybridkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Base KEMSpi implementation for hybrid KEM algorithms.
 * Supports X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
 */
public class HybridKEM implements KEMSpi {

   protected final String opensslName;
   protected final String jcaAlgorithm;
   protected final int sharedSecretSize;

   public HybridKEM() {
      this("X25519MLKEM768", "X25519MLKEM768", 64);
   }

   protected HybridKEM(String opensslName, String jcaAlgorithm, int sharedSecretSize) {
      this.opensslName = opensslName;
      this.jcaAlgorithm = jcaAlgorithm;
      this.sharedSecretSize = sharedSecretSize;
   }

   @Override
   public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                                                 SecureRandom secureRandom)
         throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (publicKey == null) {
         throw new InvalidKeyException("Public key cannot be null");
      }
      if (spec != null) {
         throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for hybrid KEM");
      }

      if (publicKey instanceof GlaSSLessHybridKEMPublicKey hybridKey) {
         return new HybridKEMEncapsulator(hybridKey.getOpenSSLName(), hybridKey.getRawKey(), sharedSecretSize);
      }

      throw new InvalidKeyException("Unsupported public key type: " + publicKey.getClass().getName() +
         ". Expected GlaSSLessHybridKEMPublicKey");
   }

   @Override
   public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
         throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (privateKey == null) {
         throw new InvalidKeyException("Private key cannot be null");
      }
      if (spec != null) {
         throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not supported for hybrid KEM");
      }

      if (privateKey instanceof GlaSSLessHybridKEMPrivateKey hybridKey) {
         return new HybridKEMDecapsulator(hybridKey.getOpenSSLName(), hybridKey.getRawKey(), sharedSecretSize);
      }

      throw new InvalidKeyException("Unsupported private key type: " + privateKey.getClass().getName() +
         ". Expected GlaSSLessHybridKEMPrivateKey");
   }

   /**
    * Encapsulator implementation for hybrid KEM.
    */
   private static class HybridKEMEncapsulator implements EncapsulatorSpi {
      private final String opensslName;
      private final byte[] rawPublicKey;
      private final int sharedSecretSize;
      private int encapsulationSize = -1;

      HybridKEMEncapsulator(String opensslName, byte[] rawPublicKey, int sharedSecretSize) {
         this.opensslName = opensslName;
         this.rawPublicKey = rawPublicKey;
         this.sharedSecretSize = sharedSecretSize;
      }

      @Override
      public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
         if (from < 0 || from > to || to > sharedSecretSize) {
            throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
         }

         try {
            // Load the public key using raw key format
            int pkey = OpenSSLCrypto.loadRawPublicKey(opensslName, rawPublicKey);
            if (pkey == 0) {
               throw new ProviderException("Failed to load public key");
            }

            try {
               // Create context for encapsulation
               int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                  0, pkey, 0);
               if (ctx == 0) {
                  throw new ProviderException("Failed to create EVP_PKEY_CTX");
               }

               try {
                  // Initialize for encapsulation
                  int result = OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, 0);
                  if (result != 1) {
                     throw new ProviderException("EVP_PKEY_encapsulate_init failed");
                  }

                  // Get required sizes
                  int wrappedLenPtr = OpenSSLCrypto.malloc(4);
                  int secretLenPtr = OpenSSLCrypto.malloc(4);
                  try {
                     OpenSSLCrypto.memory().writeI32(wrappedLenPtr, 0);
                     OpenSSLCrypto.memory().writeI32(secretLenPtr, 0);

                     result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, 0, wrappedLenPtr,
                        0, secretLenPtr);
                     if (result != 1) {
                        throw new ProviderException("EVP_PKEY_encapsulate (get size) failed");
                     }

                     int wrappedLen = OpenSSLCrypto.memory().readInt(wrappedLenPtr);
                     int secretLen = OpenSSLCrypto.memory().readInt(secretLenPtr);

                     // Allocate buffers
                     int wrappedBuffer = OpenSSLCrypto.malloc(wrappedLen);
                     int secretBuffer = OpenSSLCrypto.malloc(secretLen);
                     try {
                        // Perform encapsulation
                        result = OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, wrappedBuffer, wrappedLenPtr,
                           secretBuffer, secretLenPtr);
                        if (result != 1) {
                           throw new ProviderException("EVP_PKEY_encapsulate failed");
                        }

                        // Extract results
                        int actualWrappedLen = OpenSSLCrypto.memory().readInt(wrappedLenPtr);
                        byte[] ciphertext = OpenSSLCrypto.memory().readBytes(wrappedBuffer, actualWrappedLen);

                        int actualSecretLen = OpenSSLCrypto.memory().readInt(secretLenPtr);
                        byte[] fullSecret = OpenSSLCrypto.memory().readBytes(secretBuffer, actualSecretLen);

                        // Create secret key from specified range
                        byte[] keyBytes = new byte[to - from];
                        System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
                        String keyAlgorithm = algorithm != null ? algorithm : "Generic";
                        SecretKey secretKey = new SecretKeySpec(keyBytes, keyAlgorithm);

                        // Store encapsulation size
                        encapsulationSize = ciphertext.length;

                        return new KEM.Encapsulated(secretKey, ciphertext, null);
                     } finally {
                        OpenSSLCrypto.free(wrappedBuffer);
                        OpenSSLCrypto.free(secretBuffer);
                     }
                  } finally {
                     OpenSSLCrypto.free(wrappedLenPtr);
                     OpenSSLCrypto.free(secretLenPtr);
                  }
               } finally {
                  OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
               }
            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
         } catch (ProviderException e) {
            throw e;
         } catch (Throwable e) {
            throw new ProviderException("Hybrid KEM encapsulation failed", e);
         }
      }

      @Override
      public int engineSecretSize() {
         return sharedSecretSize;
      }

      @Override
      public int engineEncapsulationSize() {
         if (encapsulationSize < 0) {
            // Calculate by doing a dummy encapsulation to get the size
            try {
               int pkey = OpenSSLCrypto.loadRawPublicKey(opensslName, rawPublicKey);
               if (pkey != 0) {
                  try {
                     int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                        0, pkey, 0);
                     if (ctx != 0) {
                        try {
                           if (OpenSSLCrypto.EVP_PKEY_encapsulate_init(ctx, 0) == 1) {
                              int wrappedLenPtr = OpenSSLCrypto.malloc(4);
                              int secretLenPtr = OpenSSLCrypto.malloc(4);
                              try {
                                 OpenSSLCrypto.memory().writeI32(wrappedLenPtr, 0);
                                 OpenSSLCrypto.memory().writeI32(secretLenPtr, 0);
                                 if (OpenSSLCrypto.EVP_PKEY_encapsulate(ctx, 0, wrappedLenPtr,
                                    0, secretLenPtr) == 1) {
                                    encapsulationSize = OpenSSLCrypto.memory().readInt(wrappedLenPtr);
                                 }
                              } finally {
                                 OpenSSLCrypto.free(wrappedLenPtr);
                                 OpenSSLCrypto.free(secretLenPtr);
                              }
                           }
                        } finally {
                           OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
                        }
                     }
                  } finally {
                     OpenSSLCrypto.EVP_PKEY_free(pkey);
                  }
               }
            } catch (Throwable e) {
               // Ignore
            }
         }
         return encapsulationSize > 0 ? encapsulationSize : 0;
      }
   }

   /**
    * Decapsulator implementation for hybrid KEM.
    */
   private static class HybridKEMDecapsulator implements DecapsulatorSpi {
      private final String opensslName;
      private final byte[] rawPrivateKey;
      private final int sharedSecretSize;
      private int encapsulationSize = -1;

      HybridKEMDecapsulator(String opensslName, byte[] rawPrivateKey, int sharedSecretSize) {
         this.opensslName = opensslName;
         this.rawPrivateKey = rawPrivateKey;
         this.sharedSecretSize = sharedSecretSize;
      }

      @Override
      public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
            throws DecapsulateException {
         if (encapsulation == null) {
            throw new DecapsulateException("Encapsulation cannot be null");
         }
         if (from < 0 || from > to || to > sharedSecretSize) {
            throw new IllegalArgumentException("Invalid range: from=" + from + ", to=" + to);
         }

         try {
            // Load the private key using raw key format
            int pkey = OpenSSLCrypto.loadRawPrivateKey(opensslName, rawPrivateKey);
            if (pkey == 0) {
               throw new DecapsulateException("Failed to load private key");
            }

            try {
               // Create context for decapsulation
               int ctx = OpenSSLCrypto.EVP_PKEY_CTX_new_from_pkey(
                  0, pkey, 0);
               if (ctx == 0) {
                  throw new DecapsulateException("Failed to create EVP_PKEY_CTX");
               }

               try {
                  // Initialize for decapsulation
                  int result = OpenSSLCrypto.EVP_PKEY_decapsulate_init(ctx, 0);
                  if (result != 1) {
                     throw new DecapsulateException("EVP_PKEY_decapsulate_init failed");
                  }

                  // Prepare encapsulation buffer
                  int wrappedBuffer = OpenSSLCrypto.malloc(encapsulation.length);
                  try {
                     OpenSSLCrypto.memory().write(wrappedBuffer, encapsulation);

                     // Get required size
                     int secretLenPtr = OpenSSLCrypto.malloc(4);
                     try {
                        OpenSSLCrypto.memory().writeI32(secretLenPtr, 0);
                        result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, 0, secretLenPtr,
                           wrappedBuffer, encapsulation.length);
                        if (result != 1) {
                           throw new DecapsulateException("EVP_PKEY_decapsulate (get size) failed");
                        }

                        int secretLen = OpenSSLCrypto.memory().readInt(secretLenPtr);
                        int secretBuffer = OpenSSLCrypto.malloc(secretLen);
                        try {
                           // Perform decapsulation
                           result = OpenSSLCrypto.EVP_PKEY_decapsulate(ctx, secretBuffer, secretLenPtr,
                              wrappedBuffer, encapsulation.length);
                           if (result != 1) {
                              throw new DecapsulateException("EVP_PKEY_decapsulate failed");
                           }

                           // Extract result
                           int actualSecretLen = OpenSSLCrypto.memory().readInt(secretLenPtr);
                           byte[] fullSecret = OpenSSLCrypto.memory().readBytes(secretBuffer, actualSecretLen);

                           // Create secret key from specified range
                           byte[] keyBytes = new byte[to - from];
                           System.arraycopy(fullSecret, from, keyBytes, 0, keyBytes.length);
                           String keyAlgorithm = algorithm != null ? algorithm : "Generic";
                           return new SecretKeySpec(keyBytes, keyAlgorithm);
                        } finally {
                           OpenSSLCrypto.free(secretBuffer);
                        }
                     } finally {
                        OpenSSLCrypto.free(secretLenPtr);
                     }
                  } finally {
                     OpenSSLCrypto.free(wrappedBuffer);
                  }
               } finally {
                  OpenSSLCrypto.EVP_PKEY_CTX_free(ctx);
               }
            } finally {
               OpenSSLCrypto.EVP_PKEY_free(pkey);
            }
         } catch (DecapsulateException e) {
            throw e;
         } catch (Throwable e) {
            throw new DecapsulateException("Hybrid KEM decapsulation failed", e);
         }
      }

      @Override
      public int engineSecretSize() {
         return sharedSecretSize;
      }

      @Override
      public int engineEncapsulationSize() {
         // Default encapsulation sizes for hybrid KEMs
         // X25519MLKEM768: 1120 bytes (32 + 1088)
         // X448MLKEM1024: 1624 bytes (56 + 1568)
         // SecP256r1MLKEM768: ~1153 bytes (65 + 1088)
         // SecP384r1MLKEM1024: ~1665 bytes (97 + 1568)
         return encapsulationSize > 0 ? encapsulationSize : 1120;
      }
   }
}
