package net.glassless.provider.internal.hybridkem;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
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

import net.glassless.provider.internal.GlaSSLessLog;
import net.glassless.provider.internal.KEMUtils;
import net.glassless.provider.internal.OpenSSLCrypto;

/**
 * Base KEMSpi implementation for hybrid KEM algorithms.
 * Supports X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
 */
public class HybridKEM implements KEMSpi {

   private static final System.Logger LOG = GlaSSLessLog.KEM;

   protected final int sharedSecretSize;

   public HybridKEM() {
      this(64);
   }

   protected HybridKEM(int sharedSecretSize) {
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
         LOG.log(System.Logger.Level.DEBUG, "newEncapsulator: {0}", hybridKey.getAlgorithm());
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
         LOG.log(System.Logger.Level.DEBUG, "newDecapsulator: {0}", hybridKey.getAlgorithm());
         return new HybridKEMDecapsulator(hybridKey.getOpenSSLName(), hybridKey.getRawKey(), sharedSecretSize);
      }

      throw new InvalidKeyException("Unsupported private key type: " + privateKey.getClass().getName() +
         ". Expected GlaSSLessHybridKEMPrivateKey");
   }

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
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadRawPublicKey(opensslName, rawPublicKey, arena);
            if (pkey.equals(MemorySegment.NULL)) {
               throw new ProviderException("Failed to load public key");
            }
            try {
               KEMUtils.EncapsulateResult result = KEMUtils.encapsulate(pkey, from, to, algorithm, sharedSecretSize, arena);
               encapsulationSize = result.encapsulationSize();
               return result.encapsulated();
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
            try (Arena arena = Arena.ofConfined()) {
               MemorySegment pkey = OpenSSLCrypto.loadRawPublicKey(opensslName, rawPublicKey, arena);
               if (!pkey.equals(MemorySegment.NULL)) {
                  try {
                     encapsulationSize = KEMUtils.queryEncapsulationSize(pkey, arena);
                  } finally {
                     OpenSSLCrypto.EVP_PKEY_free(pkey);
                  }
               }
            } catch (Throwable e) {
               // Ignore
            }
         }
         return Math.max(encapsulationSize, 0);
      }
   }

   private static class HybridKEMDecapsulator implements DecapsulatorSpi {
      private final String opensslName;
      private final byte[] rawPrivateKey;
      private final int sharedSecretSize;
      private final int encapsulationSize;

      HybridKEMDecapsulator(String opensslName, byte[] rawPrivateKey, int sharedSecretSize) {
         this.opensslName = opensslName;
         this.rawPrivateKey = rawPrivateKey;
         this.sharedSecretSize = sharedSecretSize;
         this.encapsulationSize = queryEncapsulationSize();
      }

      @Override
      public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
         throws DecapsulateException {
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadRawPrivateKey(opensslName, rawPrivateKey, arena);
            if (pkey.equals(MemorySegment.NULL)) {
               throw new DecapsulateException("Failed to load private key");
            }
            try {
               return KEMUtils.decapsulate(pkey, encapsulation, from, to, algorithm, sharedSecretSize, arena);
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
         return encapsulationSize;
      }

      private int queryEncapsulationSize() {
         try (Arena arena = Arena.ofConfined()) {
            MemorySegment pkey = OpenSSLCrypto.loadRawPrivateKey(opensslName, rawPrivateKey, arena);
            if (!pkey.equals(MemorySegment.NULL)) {
               try {
                  int size = KEMUtils.queryEncapsulationSize(pkey, arena);
                  if (size > 0) {
                     return size;
                  }
               } finally {
                  OpenSSLCrypto.EVP_PKEY_free(pkey);
               }
            }
         } catch (Throwable e) {
            // Ignore
         }
         return 0;
      }
   }
}
